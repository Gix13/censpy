#!/usr/bin/env python3
"""
nrich_nmap_orchestrator.py

One row per IP (exactly 3 columns):
  ip, ports/protocol, dns

- All port/protocol pairs combined into a single column (comma-separated)
- Deduplicated pairs; sorted by port then protocol
- Port-only scans (TCP: -sS if root else -sT; UDP: -sU; also -n -Pn)
- Minimal flags: input method, output format/path, tool paths, --verbose
- Domain from nrich if available; otherwise best-effort reverse DNS (PTR)

Examples:
  ./nrich_nmap_orchestrator.py \
    --targets "192.0.2.10, 198.51.100.20" \
    --nrich-bin /path/to/nrich \
    --output-format xlsx \
    --output-path results.xlsx \
    --verbose

  ./nrich_nmap_orchestrator.py \
    --targets-file targets.txt \
    --output-format csv \
    --output-path results.csv
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Set, Tuple

# ----------------------------- CLI & Utils -----------------------------

def run_cmd(cmd: List[str], verbose: bool = False) -> Tuple[int, str, str]:
    if verbose:
        print(f"[VERBOSE] exec: {' '.join(cmd)}")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    if verbose and err.strip():
        print(f"[VERBOSE] stderr: {err.strip()}")
    return p.returncode, out, err

def ensure_tool_exists(path_or_name: str):
    # If given a full path, check it; else search PATH
    if os.path.sep in path_or_name:
        if not (os.path.isfile(path_or_name) and os.access(path_or_name, os.X_OK)):
            sys.exit(f"ERROR: '{path_or_name}' is not an executable file.")
    else:
        if shutil.which(path_or_name) is None:
            sys.exit(f"ERROR: '{path_or_name}' not found in PATH. Please install it and try again.")

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def write_temp_targets(targets: List[str]) -> str:
    tf = NamedTemporaryFile("w", delete=False)
    try:
        for t in targets:
            s = t.strip()
            if s:
                tf.write(s + "\n")
        tf.flush()
        return tf.name
    finally:
        tf.close()

def load_targets(args) -> List[str]:
    if args.targets_file and args.targets:
        sys.exit("Provide either --targets-file or --targets, not both.")
    if not args.targets_file and not args.targets:
        sys.exit("You must provide one of --targets-file or --targets.")
    targets: List[str] = []
    if args.targets_file:
        with open(args.targets_file, "r") as f:
            targets = [l.strip() for l in f if l.strip()]
    else:
        raw = args.targets.replace(",", " ")
        targets = [t for t in raw.split() if t.strip()]
    if not targets:
        sys.exit("No targets found.")
    return targets

# ----------------------------- Data model ------------------------------

@dataclass
class HostFinding:
    ip: str
    ports_tcp: Set[int] = field(default_factory=set)
    ports_udp: Set[int] = field(default_factory=set)
    domain: Optional[str] = None  # best-effort

# ----------------------------- NRICH handling --------------------------

def parse_nrich_json(nrich_json_text: str, verbose: bool = False) -> Dict[str, HostFinding]:
    try:
        data = json.loads(nrich_json_text)
    except json.JSONDecodeError:
        sys.exit("ERROR: nrich did not return JSON. Ensure a recent nrich; this script calls: nrich <file> --output json")

    if isinstance(data, list):
        hosts = data
    elif isinstance(data, dict) and isinstance(data.get("results"), list):
        hosts = data["results"]
    elif isinstance(data, dict):
        hosts = [data]
    else:
        sys.exit("ERROR: Unrecognized nrich JSON structure.")

    findings: Dict[str, HostFinding] = {}

    def get_first_hostname(h: dict) -> Optional[str]:
        for key in ("hostnames", "domains", "names"):
            if key in h and isinstance(h[key], list) and h[key]:
                return str(h[key][0])
        for key in ("hostname", "domain", "name"):
            if key in h and isinstance(h[key], str) and h[key]:
                return h[key]
        return None

    for h in hosts:
        ip = h.get("ip") or h.get("host") or h.get("address")
        if not ip:
            continue
        hf = findings.setdefault(ip, HostFinding(ip=ip))
        hn = get_first_hostname(h)
        if hn and not hf.domain:
            hf.domain = hn

        # Collect candidate ports (protocol decided later by nmap)
        if isinstance(h.get("ports"), list):
            for p in h["ports"]:
                try:
                    hf.ports_tcp.add(int(p))  # temp bucket
                except Exception:
                    pass
        for key in ("data", "services", "open_ports", "exposed"):
            if isinstance(h.get(key), list):
                for item in h[key]:
                    if isinstance(item, dict) and "port" in item:
                        try:
                            hf.ports_tcp.add(int(item["port"]))
                        except Exception:
                            pass
                    elif isinstance(item, int):
                        hf.ports_tcp.add(item)
                    else:
                        try:
                            hf.ports_tcp.add(int(item))
                        except Exception:
                            pass

    cleaned = {ip: f for ip, f in findings.items() if (f.ports_tcp or f.ports_udp)}
    if verbose:
        print(f"[VERBOSE] nrich parsed hosts: {len(cleaned)}")
    return cleaned

# ----------------------------- Nmap handling ---------------------------

def parse_nmap_grepable(output: str) -> Dict[str, Dict[str, List[int]]]:
    """
    Parse 'nmap -oG -' output.
    Returns {ip: {"tcp":[open ports], "udp":[open ports]}}.
    (Counts only definitive 'open' states.)
    """
    result: Dict[str, Dict[str, List[int]]] = {}
    for line in output.splitlines():
        if not line.startswith("Host: "):
            continue
        m_ip = re.match(r"Host:\s+(\S+)", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)

        m_ports = re.search(r"Ports:\s+(.*)", line)
        if not m_ports:
            result.setdefault(ip, {"tcp": [], "udp": []})
            continue

        entries = [e.strip() for e in m_ports.group(1).split(",")]
        tcp_open, udp_open = [], []
        for e in entries:
            parts = e.split("/")
            if len(parts) < 3:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            state = parts[1]
            proto = parts[2].lower()
            if state == "open":
                if proto == "tcp":
                    tcp_open.append(port)
                elif proto == "udp":
                    udp_open.append(port)

        result.setdefault(ip, {"tcp": [], "udp": []})
        if tcp_open:
            result[ip]["tcp"].extend(sorted(set(tcp_open)))
        if udp_open:
            result[ip]["udp"].extend(sorted(set(udp_open)))
    return result

def run_nmap_on_ports(ip: str, ports: Set[int], scan_type: str, nmap_bin: str, verbose: bool = False) -> Tuple[str, str]:
    if not ports:
        return "", ""
    port_arg = ",".join(str(p) for p in sorted(ports))
    if scan_type == "tcp":
        tcp_flag = "-sS" if is_root() else "-sT"
        cmd = [nmap_bin, "-n", "-Pn", tcp_flag, "-p", port_arg, "-oG", "-", ip]
    elif scan_type == "udp":
        cmd = [nmap_bin, "-n", "-Pn", "-sU", "-p", port_arg, "-oG", "-", ip]
    else:
        raise ValueError("scan_type must be 'tcp' or 'udp'")
    rc, out, err = run_cmd(cmd, verbose=verbose)
    if rc != 0 and verbose:
        print(f"[VERBOSE] nmap {scan_type} scan non-zero exit ({rc}) for {ip}.")
    return out, err

# ----------------------------- Domain enrichment -----------------------

def best_effort_reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

# ----------------------------- Output builders -------------------------

def build_rows_single_cell(report: Dict[str, HostFinding]) -> List[Dict[str, str]]:
    """
    Build rows for CSV/XLSX with EXACTLY THREE COLUMNS:
    ip, ports/protocol, dns
    """
    rows: List[Dict[str, str]] = []
    for ip in sorted(report.keys()):
        hf = report[ip]
        # dedupe + sort by (port, protocol)
        pairs = sorted(
            {*( (p, 'tcp') for p in hf.ports_tcp ),
             *( (p, 'udp') for p in hf.ports_udp )},
            key=lambda x: (x[0], x[1])
        )
        pairs_str = ", ".join(f"{p}/{proto}" for p, proto in pairs)
        rows.append({
            "ip": ip,
            "ports/protocol": pairs_str,
            "dns": hf.domain or ""
        })
    return rows

def print_text_summary(report: Dict[str, HostFinding]):
    print("\n================= SUMMARY (Port-only verification) =================")
    if not is_root():
        print("[NOTE] Not running as root: used -sT for TCP. Use sudo for SYN (-sS).")
    print("No service/version/OS detection was performed.\n")

    for ip, hf in sorted(report.items(), key=lambda x: x[0]):
        pairs = sorted({*( (p, 'tcp') for p in hf.ports_tcp ),
                        *( (p, 'udp') for p in hf.ports_udp )}, key=lambda x: (x[0], x[1]))
        if not pairs:
            print(f"{ip}: No open ports confirmed by nmap among those suggested by nrich.")
            continue
        pairs_str = ", ".join(f"{p}/{proto}" for p, proto in pairs)
        print(f"{ip}  {pairs_str}  {hf.domain or 'no-domain'}")
    print("====================================================================\n")

def write_json(path: str, report: Dict[str, HostFinding]):
    out = {
        ip: {
            "dns": hf.domain,
            "pairs": [f"{p}/tcp" for p in sorted(hf.ports_tcp)]
                     + [f"{p}/udp" for p in sorted(hf.ports_udp)]
        } for ip, hf in report.items()
    }
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[OK] Wrote JSON: {path}")

def write_csv(path: str, rows: List[Dict[str, str]]):
    import csv
    headers = ["ip", "ports/protocol", "dns"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[OK] Wrote CSV: {path}")

def write_xlsx(path: str, rows: List[Dict[str, str]]):
    try:
        import pandas as pd
    except ImportError:
        sys.exit("ERROR: pandas is required for --output-format xlsx. Install with `pip install pandas openpyxl`.")
    headers = ["ip", "ports/protocol", "dns"]
    df = pd.DataFrame(rows, columns=headers)
    df.to_excel(path, index=False)
    print(f"[OK] Wrote XLSX: {path}")

# ----------------------------- Main flow -------------------------------

def main():
    ap = argparse.ArgumentParser(description="Use nrich + nmap to verify ports (TCP/UDP) and output one row per IP with 'ports/protocol' in a single column and DNS. Port-only scans.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--targets-file", help="File with one IP or CIDR per line")
    src.add_argument("--targets", help="Comma/space-separated IPs/CIDRs (e.g., '192.0.2.10,198.51.100.0/24')")

    ap.add_argument("--nrich-bin", default="nrich", help="Path to nrich binary (default: nrich)")
    ap.add_argument("--nmap-bin", default="nmap", help="Path to nmap binary (default: nmap)")
    ap.add_argument("--output-format", choices=["text", "json", "csv", "xlsx"], default="text",
                    help="Output format. For CSV/XLSX, columns are: ip, ports/protocol, dns.")
    ap.add_argument("--output-path", help="Output file path (required for json/csv/xlsx). Ignored for text.")
    ap.add_argument("--verbose", action="store_true", help="Verbose progress and command logging")

    args = ap.parse_args()

    # tools check
    ensure_tool_exists(args.nrich_bin)
    ensure_tool_exists(args.nmap_bin)

    # targets
    targets = load_targets(args)
    temp_targets = write_temp_targets(targets)

    # Run nrich (JSON), then remove the temporary target list even on failure.
    try:
        rc, nrich_out, nrich_err = run_cmd(
            [args.nrich_bin, temp_targets, "--output", "json"],
            verbose=args.verbose,
        )
    finally:
        try:
            os.unlink(temp_targets)
        except OSError:
            pass

    if rc != 0:
        sys.exit(f"ERROR running nrich (code {rc}).\n{nrich_err}")

    # parse nrich
    report = parse_nrich_json(nrich_out, verbose=args.verbose)
    if not report:
        sys.exit("No candidate ports found by nrich.")

    # nmap verify per host (port-only)
    for ip, hf in report.items():
        candidate_ports = hf.ports_tcp | hf.ports_udp  # candidates from nrich
        # TCP
        out_tcp, _ = run_nmap_on_ports(ip, candidate_ports, "tcp", args.nmap_bin, verbose=args.verbose)
        parsed_tcpudp = parse_nmap_grepable(out_tcp)
        hf.ports_tcp = set(parsed_tcpudp.get(ip, {}).get("tcp", []))
        # UDP
        out_udp, _ = run_nmap_on_ports(ip, candidate_ports, "udp", args.nmap_bin, verbose=args.verbose)
        parsed_tcpudp = parse_nmap_grepable(out_udp)
        hf.ports_udp = set(parsed_tcpudp.get(ip, {}).get("udp", []))
        # domain fallback (PTR) if missing
        if not hf.domain:
            hf.domain = best_effort_reverse_dns(ip)

    # produce output
    if args.output_format == "text":
        print_text_summary(report)
    else:
        if not args.output_path:
            sys.exit("ERROR: --output-path is required when --output-format is json/csv/xlsx.")
        if args.output_format == "json":
            write_json(args.output_path, report)
        else:
            rows = build_rows_single_cell(report)
            if args.output_format == "csv":
                write_csv(args.output_path, rows)
            elif args.output_format == "xlsx":
                write_xlsx(args.output_path, rows)

    if args.verbose:
        print("[VERBOSE] Done.")

if __name__ == "__main__":
    print("⚠️  Only scan systems you own or have explicit permission to test.", file=sys.stderr)
    main()
