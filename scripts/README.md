# nrich/Nmap Orchestrator

This component asks `nrich` for candidate ports and host metadata, then verifies those candidate ports with Nmap. It produces one record per IP with three fields: `ip`, `ports/protocol`, and `dns`.

## Requirements

- Python 3.9 or newer
- `nrich` in `PATH`, or passed with `--nrich-bin`
- Nmap in `PATH`, or passed with `--nmap-bin`
- `pandas` and `openpyxl` only when XLSX output is requested

## Examples

Use a file containing one authorized IP or CIDR per line:

```bash
python scripts/nrich_nmap_orchestrator.py \
  --targets-file ips.txt \
  --output-format csv \
  --output-path results.csv
```

Or pass documentation-only addresses directly:

```bash
python scripts/nrich_nmap_orchestrator.py \
  --targets "192.0.2.10,198.51.100.20" \
  --output-format text \
  --verbose
```

Supported output formats are `text`, `json`, `csv`, and `xlsx`. Run `python scripts/nrich_nmap_orchestrator.py --help` for every option.

TCP verification uses a SYN scan when run as root and a connect scan otherwise. UDP verification may require elevated privileges and can take substantially longer.

Only scan systems you own or have explicit permission to test.
