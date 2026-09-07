#!/usr/bin/env python3
# human_login_multiacct.py
# Drop-in replacement implementing account rotation, persistent request counts,
# IPs list processing, and run-folder output. Uses patchright (Playwright-like API).
# NOTE: Only change from your previous version is user-data directories now live under user_profiles/<email_tag>/
# PLUS: expand Forward DNS (if present) right before taking each results screenshot.
# PLUS: image-to-text (OCR) + Excel results (ip | ports/protocol | DNS) appended per IP.
# PLUS: **Network JSON harvesting** for exact ports/protocols and DNS (preferred over OCR/DOM).
# --- SPEED: Faster post-login start, faster DNS checks, shorter scroll/idle, smarter waits.

import os
import re
import time
import json
import random
import traceback
import tempfile
import shutil
import importlib.metadata as m
from typing import Optional, Tuple, List, Dict
from datetime import datetime, timezone

from patchright.sync_api import sync_playwright

# ---------- NEW: optional deps for Excel + OCR ----------
try:
    from openpyxl import Workbook, load_workbook
    _HAVE_XLSX = True
except Exception:
    _HAVE_XLSX = False

try:
    import pytesseract
    from PIL import Image
    _HAVE_OCR = True
except Exception:
    _HAVE_OCR = False

# Simple patterns to pull out domains and ports/protocol from text (fallback paths)
_DOMAIN_RE = re.compile(r"\b(?:(?:[a-z0-9-]{1,63}\.)+[a-z]{2,})(?:\.)?\b", re.I)
_PORT_PROTO_RE = re.compile(r"\b(\d{1,5})/(?:[a-z0-9][a-z0-9+.-]*)\b", re.I)
_PORT_ALTS = [
    re.compile(r"\b(\d{1,5})\s*\(\s*([a-z0-9+.-]+)\s*\)", re.I),  # "443 (https)"
    re.compile(r"\b(?:tcp|udp)\s*/\s*(\d{1,5})\b", re.I),         # "tcp/443"
]
# --------------------------------------------------------

# ---------- Config ----------
URL = "https://accounts.censys.io/login?flow=ca546e13-44f6-43ea-b2fc-df7c6d753b"
CHANNEL = "chromium"   # use 'chromium' on your platform
ACCOUNTS_FILE = "accounts.txt"   # email:password:requests per line
IPS_FILE = "ips.txt"             # one IP per line
RUNS_DIR = "runs"                # parent directory for timestamped runs

# All per-account profiles stored neatly here
USER_PROFILES_DIR = "user_profiles"
os.makedirs(USER_PROFILES_DIR, exist_ok=True)

# request retries on transient search failure before giving up (no decrement)
SEARCH_RETRIES = 2
# login retries per account before skipping
LOGIN_RETRIES = 2

# ---------- Utilities ----------
def human_sleep(a=0.25, b=0.9):
    time.sleep(random.uniform(a, b))

def tiny_sleep(a=0.06, b=0.14):  # --- SPEED: small jitter helper where user can't see the pause
    time.sleep(random.uniform(a, b))

def human_type(locator, text, per_char_ms=(60, 180)):
    try:
        locator.click()
    except Exception:
        pass
    for ch in text:
        try:
            locator.type(ch, delay=random.randint(*per_char_ms))
        except Exception:
            # fallback: fill everything at once
            try:
                locator.fill(text)
                break
            except Exception:
                pass
        time.sleep(random.uniform(0.01, 0.06))
    human_sleep(0.25, 0.7)

def safe_email_tag(email: str) -> str:
    return re.sub(r'[^A-Za-z0-9_.-]', '_', email)

def atomic_write(path: str, text: str) -> None:
    dirn = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", delete=False, dir=dirn) as tf:
        tf.write(text)
        tmp = tf.name
    os.replace(tmp, path)

# ---------- Account file handling ----------
def load_accounts(path: str) -> List[Dict]:
    accounts = []
    if not os.path.exists(path):
        return accounts
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            parts = ln.split(":")
            if len(parts) < 3:
                continue
            email = parts[0].strip()
            password = parts[1]
            try:
                reqs = int(parts[2])
            except Exception:
                reqs = 0
            accounts.append({"email": email, "password": password, "requests": reqs})
    return accounts

def save_accounts(path: str, accounts: List[Dict]) -> None:
    lines = []
    for a in accounts:
        lines.append(f"{a['email']}:{a['password']}:{a['requests']}")
    atomic_write(path, "\n".join(lines) + "\n")

def find_first_available_account(accounts: List[Dict]) -> Optional[int]:
    for i, a in enumerate(accounts):
        try:
            if int(a.get("requests", 0)) > 0:
                return i
        except Exception:
            continue
    return None

# ---------- SPEED HELPERS ----------
def _race_ready_for_search(page, timeout_ms=3000):
    """
    --- SPEED: After login, don't wait on a long URL/locator chain.
    Race: either we are on search.censys.io or the global search box exists.
    """
    try:
        page.wait_for_function(
            r"""
            () => {
              const href = (location && location.href) || '';
              if (/https:\/\/(search|platform)\.censys\.io\//.test(href) && !/home/i.test(href)) return true;
              const q = document.querySelector('[aria-label="Global Search Bar"], [role="combobox"][aria-label="Global Search Bar"]');
              return !!q;
            }
            """,
            timeout=timeout_ms
        )
    except Exception:
        pass

def _fast_focus_global_search(page):
    """
    --- SPEED: Reuse a quick selector path to grab and focus Global Search Bar.
    Returns locator or None.
    """
    sel = '[aria-label="Global Search Bar"], [role="combobox"][aria-label="Global Search Bar"]'
    try:
        # Quick probe
        found = page.locator(sel).first
        if found.count() > 0:
            try:
                found.focus()
            except Exception:
                try:
                    found.click()
                except Exception:
                    pass
            tiny_sleep()
            return found
    except Exception:
        pass
    # Fallbacks
    try:
        found = page.get_by_role("combobox", name="Global Search Bar")
        found.wait_for(timeout=1500)
        try:
            found.focus()
        except Exception:
            try:
                found.click()
            except Exception:
                pass
        tiny_sleep()
        return found
    except Exception:
        return None

def _has_forward_dns_fast(page) -> bool:
    """
    --- SPEED: Cheap pre-check for 'Forward DNS' presence to skip expansion work when absent.
    """
    try:
        return bool(page.evaluate(
            r"""
            () => {
              const els = Array.from(document.querySelectorAll('*'));
              return els.some(el => /forward\s*dns/i.test((el.textContent || '')));
            }
            """
        ))
    except Exception:
        return False

def _data_ready_race(page, max_ms=1200):
    """
    --- SPEED: Instead of waiting long 'networkidle', wait briefly for actual data,
    with a firm cap to keep moving.
    """
    t0 = time.time()
    while (time.time() - t0) * 1000 < max_ms:
        try:
            # Any JSON-harvested ports already?
            if _JSON_HARVEST.get("ports"):
                return
            # Any services/ports containers visible?
            has_ports_dom = page.evaluate(
                r"""
                () => {
                  const txt = (document.body && document.body.innerText) || '';
                  if (/open\s+port|services|total\s+services/i.test(txt)) return true;
                  return !!document.querySelector('[data-testid*="service"], [data-testid*="port"], [class*="service"], [class*="port"]');
                }
                """
            )
            if has_ports_dom:
                return
        except Exception:
            pass
        tiny_sleep(0.05, 0.11)

# ---------- Playwright helpers (login/search) ----------
def find_fields_in_target(target) -> Optional[Tuple[object, object]]:
    candidates = [
        lambda t: (t.get_by_role("textbox", name=re.compile(r"email", re.I)),
                   t.get_by_role("textbox", name=re.compile(r"password", re.I))),
        lambda t: (t.get_by_label(re.compile(r"email", re.I)),
                   t.get_by_label(re.compile(r"password", re.I))),
        lambda t: (t.get_by_placeholder(re.compile(r"email|name@|user", re.I)),
                   t.get_by_placeholder(re.compile(r"password|pass", re.I))),
        lambda t: (t.locator('input[type="email"], input[name*="email" i], input[id*="email" i]'),
                   t.locator('input[type="password"], input[name*="pass" i], input[id*="pass" i]')),
    ]
    for strat in candidates:
        try:
            e, p = strat(target)
            e.first.wait_for(timeout=3000)
            p.first.wait_for(timeout=3000)
            return e.first, p.first
        except Exception:
            pass
    return None

def find_submit_in_same_form(field_locator, scope_target):
    try:
        form = field_locator.locator("xpath=ancestor::form[1]")
        form.wait_for(timeout=3000)
        btn = form.locator('button[type="submit"], input[type="submit"]').first
        btn.wait_for(timeout=3000)
        return btn
    except Exception:
        pass
    try:
        btn = scope_target.get_by_role("button", name=re.compile(r"^\s*log\s*in\s*$", re.I))
        btn.wait_for(timeout=3000)
        return btn
    except Exception:
        pass
    return scope_target.locator('button[type="submit"], input[type="submit"], button:has-text("Log in")').first

def perform_login(page, email: str, password: str) -> bool:
    try:
        page.goto(URL, timeout=45000)
        page.wait_for_load_state("domcontentloaded", timeout=15000)
        human_sleep(0.5, 1.2)

        fields = find_fields_in_target(page)
        used_target = "main-page"
        email_loc = pwd_loc = None

        if not fields:
            frames = page.frames
            preferred = sorted(frames, key=lambda fr: (0 if re.search(r'login|account|auth|censys|ory|kratos', fr.url, re.I) else 1))
            for fr in preferred:
                try:
                    res = find_fields_in_target(fr)
                    if res:
                        email_loc, pwd_loc = res
                        used_target = f"iframe:{fr.url}"
                        break
                except Exception:
                    continue

            if not (email_loc and pwd_loc):
                fl_try = [
                    'iframe[src*="account"], iframe[src*="login"], iframe[src*="censys"], iframe[src*="ory"], iframe',
                    'iframe'
                ]
                for expr in fl_try:
                    try:
                        fl = page.frame_locator(expr).first
                        el = fl.get_by_role("textbox", name=re.compile(r"email", re.I))
                        el.wait_for(timeout=4000)
                        pl = fl.get_by_role("textbox", name=re.compile(r"password", re.I))
                        pl.wait_for(timeout=4000)
                        email_loc, pwd_loc = el, pl
                        used_target = f"frame_locator:{expr}"
                        break
                    except Exception:
                        try:
                            el = fl.locator('input[type="email"], input[name*="email" i], input[id*="email" i]').first
                            el.wait_for(timeout=3000)
                            pl = fl.locator('input[type="password"], input[name*="pass" i], input[id*="pass" i]').first
                            pl.wait_for(timeout=3000)
                            email_loc, pwd_loc = el, pl
                            used_target = f"frame_locator:{expr}"
                            break
                        except Exception:
                            pass

            if not (email_loc and pwd_loc):
                raise RuntimeError("Could not locate Email/Password fields on page or any iframe.")

            human_type(email_loc, email)
            tiny_sleep(0.1, 0.25)
            human_type(pwd_loc, password)

            if "frame_locator" in used_target:
                expr = used_target.split(":", 1)[1]
                scope = page.frame_locator(expr).first
                btn = find_submit_in_same_form(email_loc, scope)
            elif used_target.startswith("iframe:"):
                target_url = used_target.split(":", 1)[1]
                target_frame = next(fr for fr in page.frames if fr.url == target_url)
                btn = find_submit_in_same_form(email_loc, target_frame)
            else:
                btn = find_submit_in_same_form(email_loc, page)

            try:
                btn.scroll_into_view_if_needed()
            except Exception:
                pass
            tiny_sleep(0.05, 0.2)
            try:
                btn.click()
            except Exception:
                try:
                    btn.evaluate("el => el.click()")
                except Exception:
                    pass
            human_sleep(0.3, 1.0)
        else:
            email_loc, pwd_loc = fields
            human_type(email_loc, email)
            human_type(pwd_loc, password)
            btn = find_submit_in_same_form(email_loc, page)
            try:
                btn.scroll_into_view_if_needed()
            except Exception:
                pass
            tiny_sleep(0.05, 0.2)
            try:
                btn.click()
            except Exception:
                try:
                    btn.evaluate("el => el.click()")
                except Exception:
                    pass
            human_sleep(0.3, 1.0)

        # --- SPEED: race for ready-to-search instead of long URL wait
        _race_ready_for_search(page, timeout_ms=3000)

        # Also try to ensure the search box is interactable ASAP
        try:
            _fast_focus_global_search(page)
        except Exception:
            pass

        # Keep legacy success heuristics (no behavior change)
        try:
            page.get_by_role("combobox", name="Global Search Bar").wait_for(timeout=8000)
            return True
        except Exception:
            try:
                if page.locator("text=Search").count() > 0:
                    return True
            except Exception:
                pass

        return False

    except Exception:
        traceback.print_exc()
        return False

# --- expand Forward DNS (if present) just before screenshot ---
def _expand_forward_dns_if_available(page):
    try:
        # --- SAFETY FIX: disable pointer events on all WAF badges globally ---
        try:
            page.evaluate("""
                () => {
                    const wafs = Array.from(document.querySelectorAll('*')).filter(
                        el => (el.textContent || '').trim() === 'WAF'
                    );
                    for (const el of wafs) {
                        el.style.pointerEvents = 'none';
                        el.style.userSelect = 'none';
                    }
                }
            """)
        except Exception:
            pass
        # --------------------------------------------------------------------

        # --- SPEED: quick pre-check to skip whole block if absent
        if not _has_forward_dns_fast(page):
            return

        try:
            page.get_by_role("cell", name=re.compile(r"^\s*Forward\s+DNS\s*$", re.I)).first.scroll_into_view_if_needed()
            tiny_sleep(0.08, 0.18)
        except Exception:
            pass

        candidates = [
            page.locator("[data-testid*='expandable']:has-text('Forward DNS')"),
            page.locator("section:has-text('Forward DNS')"),
            page.locator("div:has-text('Forward DNS')").filter(
                has=page.get_by_test_id("expandable-list-control-button")
            ),
        ]

        deadline = time.time() + 0.30  # --- SPEED: hard budget ~300ms
        for c in candidates:
            if time.time() > deadline:
                break
            try:
                if c.count() > 0:
                    btn = c.get_by_test_id("expandable-list-control-button").first
                    try:
                        btn.wait_for(timeout=300)  # shorter
                    except Exception:
                        pass
                    try:
                        aria = btn.get_attribute("aria-expanded")
                    except Exception:
                        aria = None
                    if aria is None or str(aria).lower() == "false":
                        # --- SAFE CLICK (ignore overlay issues)
                        try:
                            bbox = btn.bounding_box()
                            if bbox:
                                page.mouse.move(bbox["x"] + bbox["width"]/2, bbox["y"] + bbox["height"]/2)
                                page.mouse.click(bbox["x"] + bbox["width"]/2, bbox["y"] + bbox["height"]/2)
                            else:
                                btn.click()
                            tiny_sleep(0.05, 0.12)
                        except Exception:
                            try:
                                btn.evaluate("el => el.click()")
                            except Exception:
                                pass
                    return
            except Exception:
                continue

        # last try with a generic button (short)
        try:
            if time.time() <= deadline:
                btn = page.get_by_test_id("expandable-list-control-button").first
                btn.wait_for(timeout=250)
                try:
                    aria = btn.get_attribute("aria-expanded")
                except Exception:
                    aria = None
                if aria is None or str(aria).lower() == "false":
                    try:
                        bbox = btn.bounding_box()
                        if bbox:
                            page.mouse.move(bbox["x"] + bbox["width"]/2, bbox["y"] + bbox["height"]/2)
                            page.mouse.click(bbox["x"] + bbox["width"]/2, bbox["y"] + bbox["height"]/2)
                        else:
                            btn.click()
                    except Exception:
                        try:
                            btn.evaluate("el => el.click()")
                        except Exception:
                            pass
        except Exception:
            pass
    except Exception:
        pass


# ---------- JSON harvester for exact data (preferred) ----------
_JSON_HARVEST: Dict[str, List[str]] = {"ports": [], "dns": []}

def _wire_json_harvest(page, target_ip: str):
    """
    Attach a response listener to collect ports/protocols and DNS from JSON payloads.
    Kept minimal and non-invasive; runs alongside existing logic.
    """
    if getattr(page, "_json_harvester_attached", False):
        # Clear previous stash for a new IP
        _JSON_HARVEST["ports"].clear()
        _JSON_HARVEST["dns"].clear()
        return

    def _on_response(resp):
        try:
            url = getattr(resp, "url", "") or ""
            if not any(k in url for k in ("/api/", "graphql", "/hosts", "/search", "/assets")):
                return
            headers = getattr(resp, "headers", {}) or {}
            ctype = headers.get("content-type", headers.get("Content-Type", ""))
            if "application/json" not in (ctype or ""):
                return

            try:
                text = resp.text()
            except Exception:
                return
            if not text or "{" not in text:
                return

            # Not all payloads echo the IP; we parse regardless.
            data = json.loads(text)

            ports, dns = set(), set()

            def walk(x):
                if isinstance(x, dict):
                    # Common service shapes
                    if "port" in x and isinstance(x["port"], int):
                        proto = (x.get("transport_protocol")
                                 or x.get("protocol")
                                 or x.get("service_name")
                                 or "").strip().lower()
                        if proto:
                            ports.add(f"{x['port']}/{proto}")
                        else:
                            # Assume TCP when missing (matches many UIs)
                            ports.add(f"{x['port']}/tcp")

                    if "protocols" in x and isinstance(x["protocols"], list):
                        for p in x["protocols"]:
                            if isinstance(p, str) and "/" in p:
                                ports.add(p.strip().lower())

                    # Services arrays
                    if "services" in x and isinstance(x["services"], list):
                        for s in x["services"]:
                            walk(s)

                    # DNS-ish keys
                    for k in ("names", "hostnames", "dns_names", "domain_names", "reverse_dns", "records"):
                        v = x.get(k)
                        if isinstance(v, list):
                            for n in v:
                                if isinstance(n, str):
                                    dns.add(n.strip().strip("."))
                                elif isinstance(n, dict):
                                    nm = n.get("name")
                                    if isinstance(nm, str):
                                        dns.add(nm.strip().strip("."))

                    # Recurse dict
                    for v in x.values():
                        walk(v)

                elif isinstance(x, list):
                    for v in x:
                        walk(v)

            # Some APIs wrap in { "result": {...} }
            walk(data.get("result", data))

            if ports or dns:
                _JSON_HARVEST["ports"] = sorted(ports)
                _JSON_HARVEST["dns"] = sorted({d for d in dns if d})
        except Exception:
            # best-effort; never break navigation
            pass

    try:
        page.on("response", _on_response)
        page._json_harvester_attached = True  # type: ignore[attr-defined]
        _JSON_HARVEST["ports"].clear()
        _JSON_HARVEST["dns"].clear()
    except Exception:
        pass

def _drain_json_harvest() -> Tuple[List[str], List[str]]:
    ports = list(_JSON_HARVEST.get("ports", []))
    dns = list(_JSON_HARVEST.get("dns", []))
    _JSON_HARVEST["ports"].clear()
    _JSON_HARVEST["dns"].clear()
    return ports, dns

# ---------- OCR + Excel helpers (DOM-first, OCR fallback) ----------
def _ocr_text_from_locator(locator) -> str:
    if not _HAVE_OCR:
        return ""
    try:
        tmp_png = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
        locator.screenshot(path=tmp_png)
        try:
            txt = pytesseract.image_to_string(Image.open(tmp_png))
        finally:
            try:
                os.remove(tmp_png)
            except Exception:
                pass
        return txt or ""
    except Exception:
        return ""

def _parse_dns(text: str) -> List[str]:
    if not text:
        return []
    hits = _DOMAIN_RE.findall(text)
    blacklist = {"censys.io", "platform.censys.io"}
    out, seen = [], set()
    for h in hits:
        hb = h.lower().strip(".")
        if hb in blacklist:
            continue
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out

def _parse_ports(text: str) -> List[str]:
    if not text:
        return []
    out = [f"{p}/{proto}" for (p, proto) in _PORT_PROTO_RE.findall(text)]
    if not out:
        for rx in _PORT_ALTS:
            for m in rx.findall(text):
                if isinstance(m, tuple):
                    out.append(f"{m[0]}/{m[1]}")
    # de-dupe preserve order
    seen, uniq = set(), []
    for v in out:
        v = v.lower()
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq

def _inner_text(locator) -> str:
    try:
        return locator.evaluate("el => el.innerText || ''") or ""
    except Exception:
        return ""

def _append_results_row(run_dir: str, ip: str, ports: List[str], dns: List[str]) -> None:
    if _HAVE_XLSX:
        xlsx = os.path.join(run_dir, "results_censys.xlsx")
        if os.path.exists(xlsx):
            wb = load_workbook(xlsx)
            ws = wb.active
        else:
            wb = Workbook()
            ws = wb.active
            ws.append(["ip", "ports/protocol", "DNS"])
        ws.append([ip, "; ".join(ports) if ports else "", "; ".join(dns) if dns else ""])
        wb.save(xlsx)
    else:
        csvp = os.path.join(run_dir, "results_censys.csv")
        header = not os.path.exists(csvp)
        with open(csvp, "a", encoding="utf-8") as f:
            if header:
                f.write("ip,ports/protocol,DNS\n")
            def esc(s): return '"' + s.replace('"', '""') + '"'
            f.write(",".join([
                esc(ip),
                esc("; ".join(ports) if ports else ""),
                esc("; ".join(dns) if dns else "")
            ]) + "\n")

def _extract_dns_from_forward_chPAX(page):
    """
    Collect Forward DNS names from rows with class 'chPAX' (or classes containing 'chPAX'),
    including items that load lazily as you scroll. Searches the main page and then frames
    only if main page yields nothing. All with tight caps.
    """
    try:
        try:
            _expand_forward_dns_if_available(page)
        except Exception:
            pass

        def _scan_ctx(ctx, max_scrolls=8, idle_repeats_to_stop=2):
            try:
                return ctx.evaluate(
                    fr"""
                    async () => {{
                      const sleep = ms => new Promise(r => setTimeout(r, ms));

                      // Find any element that contains "Forward DNS"
                      const els = Array.from(document.querySelectorAll('*'));
                      const headers = els.filter(el => /forward\s*dns/i.test(el.textContent || ''));
                      if (!headers.length) return [];

                      const header = headers[headers.length - 1];
                      let root = header.closest('section, div, main, article, tbody, ul, ol') || header;

                      // Choose the descendant that currently contains the MOST rows
                      const candidates = [root, ...root.querySelectorAll('section, div, main, article, tbody, ul, ol')];
                      let target = root, max = 0;
                      for (const c of candidates) {{
                        const count = c.querySelectorAll('.chPAX, [class*="chPAX"]').length;
                        if (count > max) {{ max = count; target = c; }}
                      }}

                      const scrollables = [target, ...target.querySelectorAll('*')].filter(n => {{
                        const s = getComputedStyle(n);
                        return (s.overflowY === 'auto' || s.overflowY === 'scroll') && (n.scrollHeight - n.clientHeight > 8);
                      }});
                      const sc = scrollables[0] || document.scrollingElement || document.documentElement || document.body;

                      // Scroll to force lazy render (tight loop + early exit)
                      let prev = -1, stable = 0;
                      for (let i = 0; i < {max_scrolls}; i++) {{
                        const cnt = target.querySelectorAll('.chPAX, [class*="chPAX"]').length;
                        if (cnt === prev) stable++; else stable = 0;
                        prev = cnt;
                        if (stable >= {idle_repeats_to_stop}) break;
                        sc.scrollTop = sc.scrollHeight;
                        window.scrollTo(0, document.body.scrollHeight);
                        await sleep(70);
                      }}

                      const out = [];
                      const seen = new Set();
                      const rows = target.querySelectorAll('.chPAX, [class*="chPAX"]');
                      for (const el of rows) {{
                        let t = (el.textContent || '').trim();
                        if (!t) continue;
                        t = t.replace(/[\u200B-\u200D\uFEFF]/g, '');
                        if (!/^(?:\*\.)?(?:[A-Za-z0-9-]{{1,63}}\.)+[A-Za-z]{{2,}}$/.test(t)) continue;
                        t = t.replace(/\.$/, '');
                        if (!seen.has(t)) {{ seen.add(t); out.push(t); }}
                      }}
                      return out;
                    }}
                    """
                )
            except Exception:
                return []

        # Main page first (fast)
        names = _scan_ctx(page, max_scrolls=6, idle_repeats_to_stop=1)
        if names:
            # de-dupe preserving order
            seen, uniq = set(), []
            for n in names:
                if n not in seen:
                    seen.add(n)
                    uniq.append(n)
            return uniq

        # If nothing, try frames quickly (tight cap)
        all_names = []
        t0 = time.time()
        for fr in page.frames:
            if time.time() - t0 > 0.7:  # --- SPEED: cap frame sweep ~700ms
                break
            try:
                fr_names = _scan_ctx(fr, max_scrolls=4, idle_repeats_to_stop=1)
                if fr_names:
                    all_names.extend(fr_names)
            except Exception:
                continue

        seen, uniq = set(), []
        for n in all_names:
            if n not in seen:
                seen.add(n)
                uniq.append(n)
        return uniq
    except Exception:
        return []

def _extract_summary_to_excel(page, ip: str, run_dir: str) -> None:
    """
    Prefer network JSON harvested values, with DOM/OCR as fallback.
    """
    # Use harvester ONLY for ports. Ignore harvester DNS to avoid extras.
    ports_list, _ = _drain_json_harvest()

    # Forward DNS: read strictly from the Forward DNS panel (.chPAX rows)
    dns_list = _extract_dns_from_forward_chPAX(page)

    # ---------- Ports/Protocols (DOM/OCR fallback) ----------
    if not ports_list:
        try:
            ports_candidates = [
                page.locator("xpath=(//*[self::section or self::div or self::li or self::tr or self::td]"
                             "[.//text()[contains(translate(., 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'TOTAL SERVICES')]])[1]").first,
                page.locator("xpath=(//*[self::section or self::div or self::li or self::tr or self::td]"
                             "[.//text()[contains(translate(., 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'SERVICES')]])[1]").first,
                page.locator("xpath=(//*[self::section or self::div or self::li or self::tr or self::td]"
                             "[.//text()[contains(translate(., 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'OPEN PORT')]])[1]").first,
                page.locator("xpath=(//*[self::section or self::div or self::li or self::tr or self::td]"
                             "[.//text()[contains(translate(., 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'PORTS')]])[1]").first,
                page.locator("xpath=(//*[self::section or self::div or self::li or self::tr or self::td]"
                             "[.//text()[contains(translate(., 'abcdefghijklmnopqrstuvwxyz','ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'PROTOCOL')]])[1]").first,
            ]
            for cand in ports_candidates:
                try:
                    cand.wait_for(timeout=700)  # --- SPEED: shorter per-candidate wait
                    txt_dom = _inner_text(cand)
                    ports_list = _parse_ports(txt_dom)
                    if ports_list:
                        break
                except Exception:
                    continue
        except Exception:
            pass

        if not ports_list:
            try:
                whole = page.evaluate("() => document.body && (document.body.innerText || '')") or ""
                ports_list = _parse_ports(whole)
            except Exception:
                pass

        # --- SPEED: keep OCR but never do full-page OCR (too slow)
        if not ports_list and _HAVE_OCR:
            try:
                for cand in ports_candidates if 'ports_candidates' in locals() else []:
                    try:
                        cand.wait_for(timeout=500)
                        txt_ocr = _ocr_text_from_locator(cand)
                        ports_list = _parse_ports(txt_ocr)
                        if ports_list:
                            break
                    except Exception:
                        continue
            except Exception:
                pass
            # No full-page OCR fallback (avoid multi-second stall)

    # Trim sizes
    ports_list = (ports_list or [])[:25]
    dns_list = dns_list or []

    _append_results_row(run_dir, ip, ports_list, dns_list)

# ------------------------------------------------------

def do_search_and_screenshot(page, IP: str, outdir: str) -> bool:
    try:
        _wire_json_harvest(page, IP)  # attach JSON harvester (idempotent)
        print(f"[info] Searching for {IP}…")

        # --- SPEED: instant focus path for search box
        sb = _fast_focus_global_search(page)
        if sb:
            # keep human typing pattern
            try:
                sb.click()
                sb.press("Control+A")
                sb.press("Backspace")
                tiny_sleep(0.1, 0.2)
            except Exception:
                pass
            for ch in IP:
                try:
                    sb.type(ch, delay=random.randint(20, 60))
                except Exception:
                    pass
                time.sleep(random.uniform(0.01, 0.06))
            try:
                sb.press("Enter")
            except Exception:
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
        else:
            # fallback path
            try:
                page.keyboard.type(IP, delay=35)
                page.keyboard.press("Enter")
            except Exception:
                pass

        def url_is_results(u: str) -> bool:
            return bool(re.search(r"https://(search|platform)\.censys\.io/", u)) and ("home" not in u.lower())

        nav_ok = False
        try:
            page.wait_for_url(lambda u: url_is_results(u), timeout=4000)  # --- SPEED: slightly shorter
            nav_ok = True
        except Exception:
            pass

        if not nav_ok:
            try:
                page.keyboard.press("ArrowDown")
                tiny_sleep(0.05, 0.12)
                page.keyboard.press("Enter")
                page.wait_for_url(lambda u: url_is_results(u), timeout=3500)
                nav_ok = True
            except Exception:
                pass

        # --- SPEED: Wait briefly for data instead of long 'networkidle'
        _data_ready_race(page, max_ms=1200)

        tiny_sleep(0.08, 0.18)

        # expand Forward DNS if present (fast)
        _expand_forward_dns_if_available(page)
        # Disable WAF badges AGAIN after search, because they reload dynamically
        try:
            page.evaluate("""
                () => {
                    const wafs = Array.from(document.querySelectorAll('*')).filter(
                        el => (el.textContent || '').trim() === 'WAF'
                    );
                    for (const el of wafs) {
                        el.style.pointerEvents = 'none';
                        el.style.userSelect = 'none';
                    }
                }
            """)
        except Exception:
            pass

        IP_SAFE = IP.replace(":", "_").replace("/", "_")
        pics_dir = os.path.join(outdir, "pics")
        os.makedirs(pics_dir, exist_ok=True)
        out_path = os.path.join(pics_dir, f"search_{IP_SAFE}.png")

        try:
            # --- SPEED: fewer scroll iterations with early exit
            page.evaluate("""
                (async () => {
                  const delay = ms => new Promise(r => setTimeout(r, ms));
                  let lastH = 0;
                  for (let i = 0; i < 6; i++) {
                    const h0 = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                    window.scrollTo(0, document.body.scrollHeight);
                    await delay(80);
                    const h1 = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                    if (Math.abs(h1 - h0) < 3) break;
                    lastH = h1;
                  }
                  window.scrollTo(0, 0);
                })();
            """)
        except Exception:
            pass

        # --- SPEED: only touch iframes if we actually detect content there
        target_frame = None
        try:
            for fr in page.frames:
                if fr == page.main_frame:
                    continue
                try:
                    if fr.locator(f"text={IP}").first.count() > 0:
                        target_frame = fr
                        break
                    if fr.locator("[data-testid='search-results'], .search-results, .results, .result").first.count() > 0:
                        target_frame = fr
                        break
                except Exception:
                    continue

            if target_frame is not None:
                content_h = target_frame.evaluate("Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)")
                fr_url = target_frame.url
                page.evaluate("""
                    (u, h) => {
                      for (const el of document.querySelectorAll('iframe')) {
                        try {
                          if (el.src && el.src.indexOf(u) !== -1) {
                            el.style.height = (h + 120) + 'px';
                            el.style.minHeight = (h + 120) + 'px';
                            el.style.overflow = 'visible';
                          }
                        } catch (e) {}
                      }
                    }
                """, fr_url, int(content_h))
                # Tighten iframe lazy scroll
                target_frame.evaluate("""
                    (async () => {
                      const delay = ms => new Promise(r => setTimeout(r, ms));
                      for (let i = 0; i < 5; i++) {
                        const h0 = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                        window.scrollTo(0, document.body.scrollHeight);
                        await delay(70);
                        const h1 = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                        if (Math.abs(h1 - h0) < 3) break;
                      }
                      window.scrollTo(0, 0);
                    })();
                """)
                tiny_sleep(0.1, 0.18)
        except Exception:
            pass

        try:
            handle = page.evaluate_handle(f"""
                (ip) => {{
                  const roots = Array.from(document.querySelectorAll(
                    'main, [role="main"], [data-testid], .content, .container, .layout, .results, .search-results'
                  ));
                  const hasIP = (el) => {{
                    try {{ return (el.innerText && el.innerText.includes(ip)); }} catch {{ return false; }}
                  }};
                  let target = null;
                  const all = [...roots, document.body];
                  for (const el of all) {{
                    if (!el) continue;
                    const sh = el.scrollHeight || 0;
                    const ch = el.clientHeight || 0;
                    const scrollable = sh > ch + 20;
                    if (scrollable && (hasIP(el) || el.querySelector('*'))) {{
                      if (!target || el.clientWidth < target.clientWidth) {{
                        target = el;
                      }}
                    }}
                  }}
                  return target || document.body;
                }}
            """, IP)

            # Expand the target box so the screenshot sees everything
            page.evaluate("""
                (el) => {
                  el.__origStyle = {
                    height: el.style.height,
                    minHeight: el.style.minHeight,
                    overflow: el.style.overflow,
                    maxHeight: el.style.maxHeight
                  };
                  const full = Math.max(el.scrollHeight, el.clientHeight, 2000);
                  el.style.height = (full + 200) + 'px';
                  el.style.minHeight = (full + 200) + 'px';
                  el.style.maxHeight = 'none';
                  el.style.overflow = 'visible';
                  let p = el.parentElement;
                  while (p && p !== document.body) {
                    if (getComputedStyle(p).overflow !== 'visible') {
                      if (!p.__origStyle) p.__origStyle = {};
                      p.__origStyle.overflow = p.style.overflow;
                      p.style.overflow = 'visible';
                    }
                    p = p.parentElement;
                  }
                }
            """, handle)

            # 🔸 Tiny delay to reduce chance of blank screenshots
            tiny_sleep(0.4, 0.7)

            element = handle.as_element()
            element.screenshot(path=out_path)
            print(f"[ok] Saved FULL results screenshot to {out_path}")

            # --- Extract summary -> Excel (JSON preferred; DOM/OCR fallback) ---
            _extract_summary_to_excel(page, IP, outdir)
            # ----------------------------------------------------------

            page.evaluate("""
                (el) => {
                  if (el.__origStyle) {
                    el.style.height = el.__origStyle.height || '';
                    el.style.minHeight = el.__origStyle.minHeight || '';
                    el.style.maxHeight = el.__origStyle.maxHeight || '';
                    el.style.overflow = el.__origStyle.overflow || '';
                  }
                  let p = el.parentElement;
                  while (p && p !== document.body) {
                    if (p.__origStyle && 'overflow' in p.__origStyle) {
                      p.style.overflow = p.__origStyle.overflow || '';
                    }
                    p = p.parentElement;
                  }
                }
            """, element)

            return True
        except Exception:
            try:
                # tiny sleep before fallback full_page shot as well
                tiny_sleep(0.4, 0.7)
                page.screenshot(path=out_path, full_page=True)
                print(f"[ok] Saved fallback full_page screenshot to {out_path}")
                # --- Extract summary -> Excel (JSON preferred; DOM/OCR fallback) ---
                _extract_summary_to_excel(page, IP, outdir)
                # ----------------------------------------------------------
                return True
            except Exception as ee:
                print("[err] Screenshot failed:", ee)
                return False

    except Exception:
        traceback.print_exc()
        return False

# ---------- Orchestration ----------
def run_all():
    accounts = load_accounts(ACCOUNTS_FILE)
    if not accounts:
        print(f"[err] No accounts found in {ACCOUNTS_FILE}.")
        return

    ips = []
    if not os.path.exists(IPS_FILE):
        print(f"[err] No ips file found ({IPS_FILE}). Create the file with one IP per line.")
        return
    with open(IPS_FILE, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            ips.append(ln)

    if not ips:
        print("[err] No IPs to search in ips.txt.")
        return

    # Example: 2025-10-28__14-33-05__UTC (Windows-safe, clearly readable)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d__%H-%M-%S__UTC")
    run_dir = os.path.join(RUNS_DIR, now)
    os.makedirs(run_dir, exist_ok=True)

    # Create pics/ inside the run folder
    pics_dir = os.path.join(run_dir, "pics")
    os.makedirs(pics_dir, exist_ok=True)

    print(f"[info] Run folder: {run_dir}")

    idx = find_first_available_account(accounts)
    if idx is None:
        print("[err] No authorized account has a remaining request allowance.")
        return

    try:
        ver = m.version("patchright")
    except Exception:
        ver = "unknown"
    print(f"[info] Using patchright {ver}")

    with sync_playwright() as p:
        ctx = None
        page = None
        current_account_idx = idx

        def open_context_for_account(account_idx: int):
            nonlocal ctx, page
            a = accounts[account_idx]
            tag = safe_email_tag(a["email"])
            user_dir = os.path.join(USER_PROFILES_DIR, tag)
            os.makedirs(user_dir, exist_ok=True)
            try:
                if ctx:
                    try:
                        ctx.close()
                    except Exception:
                        pass
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=user_dir,
                    channel=CHANNEL,
                    headless=False,
                    no_viewport=True,
                )
                page = ctx.new_page()
                return True
            except Exception:
                traceback.print_exc()
                ctx = None
                page = None
                return False

        if not open_context_for_account(current_account_idx):
            print("[err] Failed to open browser context for the initial account.")
            return

        def ensure_logged_in_for_account(account_idx: int) -> bool:
            nonlocal page
            a = accounts[account_idx]
            for attempt in range(1, LOGIN_RETRIES + 1):
                print(f"[info] Logging in as {a['email']} (attempt {attempt})")
                ok = perform_login(page, a["email"], a["password"])
                if ok:
                    print(f"[ok] Logged in as {a['email']}")
                    return True
                else:
                    print(f"[warn] Login attempt {attempt} failed for {a['email']}")
                    human_sleep(0.8, 1.6)
            print(f"[warn] Skipping account {a['email']} due to login failures.")
            return False

        started = False
        checked = 0
        total_accounts = len(accounts)
        while checked < total_accounts:
            if accounts[current_account_idx]["requests"] <= 0:
                current_account_idx = (current_account_idx + 1) % total_accounts
                checked += 1
                continue
            if ensure_logged_in_for_account(current_account_idx):
                started = True
                break
            else:
                current_account_idx = (current_account_idx + 1) % total_accounts
                if not open_context_for_account(current_account_idx):
                    print(f"[err] Failed to open context for {accounts[current_account_idx]['email']}.")
                    checked += 1
                    continue
                checked += 1

        if not started:
            print("[err] No authorized account has a remaining request allowance.")
            try:
                if ctx:
                    ctx.close()
            except Exception:
                pass
            return

        for ip in ips:
            acct_idx = find_first_available_account(accounts)
            if acct_idx is None:
                print("[err] No authorized account has a remaining request allowance.")
                break

            if accounts[current_account_idx]["requests"] <= 0:
                current_account_idx = acct_idx
                if not open_context_for_account(current_account_idx):
                    print(f"[err] Unable to open context for {accounts[current_account_idx]['email']}. Searching next.")
                    accounts[current_account_idx]["requests"] = 0
                    save_accounts(ACCOUNTS_FILE, accounts)
                    continue
                if not ensure_logged_in_for_account(current_account_idx):
                    accounts[current_account_idx]["requests"] = 0
                    save_accounts(ACCOUNTS_FILE, accounts)
                    continue

            success = False
            for attempt in range(1, SEARCH_RETRIES + 2):
                print(f"[info] ({attempt}) Searching {ip} with account {accounts[current_account_idx]['email']}")
                ok = do_search_and_screenshot(page, ip, run_dir)
                if ok:
                    success = True
                    break
                else:
                    print(f"[warn] Search attempt {attempt} failed for {ip}. Retrying shortly...")
                    human_sleep(0.8, 1.6)

            if success:
                try:
                    accounts[current_account_idx]["requests"] = int(accounts[current_account_idx]["requests"]) - 1
                    if accounts[current_account_idx]["requests"] < 0:
                        accounts[current_account_idx]["requests"] = 0
                    save_accounts(ACCOUNTS_FILE, accounts)
                    print(f"[info] Decremented requests for {accounts[current_account_idx]['email']} -> {accounts[current_account_idx]['requests']}")
                except Exception:
                    print("[err] Failed to update accounts file after successful search.")
            else:
                print(f"[err] All attempts failed for {ip}. Skipping to next IP.")

            if accounts[current_account_idx]["requests"] <= 0:
                print(f"[info] Account {accounts[current_account_idx]['email']} exhausted; switching.")
                next_idx = find_first_available_account(accounts)
                if next_idx is None:
                    print("[err] No authorized account has a remaining request allowance.")
                    break
                current_account_idx = next_idx
                if not open_context_for_account(current_account_idx):
                    print(f"[err] Failed to open context for {accounts[current_account_idx]['email']} after rotation.")
                    accounts[current_account_idx]["requests"] = 0
                    save_accounts(ACCOUNTS_FILE, accounts)
                    continue
                if not ensure_logged_in_for_account(current_account_idx):
                    accounts[current_account_idx]["requests"] = 0
                    save_accounts(ACCOUNTS_FILE, accounts)
                    continue

        try:
            if ctx:
                ctx.close()
        except Exception:
            pass

            print("[done] Run complete.")

    # ================= NRICH PHASE ADDITION (minimal and isolated) =================
    import subprocess
    import sys  # <-- needed for sys.executable

    # ---------- NRICH binary resolver (for portability) ----------
    def resolve_nrich_path() -> str:
        """
        Find the nrich binary in a portable way.

        Search order:
          1. Environment variable NRICH_BIN
          2. Found in PATH
          3. Common local or build paths (including your known one)
        """
        import shutil
        home = os.path.expanduser("~")

        # 1. Explicit override
        env_path = os.environ.get("NRICH_BIN")
        if env_path and os.path.isfile(env_path) and os.access(env_path, os.X_OK):
            return env_path

        # 2. PATH
        found = shutil.which("nrich")
        if found:
            return found

        # 3. Known build and system paths
        candidates = [
            os.path.join(home, "Desktop", "Mada", "MadaxNrich", "test", "nrich-0.4.2", "target", "release", "nrich"),
            "/usr/local/bin/nrich",
            "/usr/bin/nrich",
        ]
        for p in candidates:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p

        raise FileNotFoundError(
            "nrich binary not found. "
            "Install it, add it to PATH, or set NRICH_BIN=/path/to/nrich"
        )

    def run_nrich_phase(ips_file: str, run_dir: str):
        """
        Run nrich orchestrator script and save results_nrich.xlsx in the same run folder.
        """
        try:
            nrich_script = os.path.expanduser("./scripts/nrich_nmap_orchestrator.py")
            out_path = os.path.join(run_dir, "results_nrich.xlsx")

            print("[stage] Censys run finished. Starting NRICH phase...")

            NRICH_BIN = resolve_nrich_path()  # auto-detect nrich binary

            cmd = [
                sys.executable,
                nrich_script,
                "--nrich-bin", NRICH_BIN,
                "--targets-file", ips_file,
                "--output-format", "xlsx",
                "--output-path", out_path,
            ]
            print(f"[info] Running nrich: {' '.join(cmd)}")
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                print("[err] nrich returned non-zero exit code.")
                if proc.stderr.strip():
                    print(f"[nrich stderr] {proc.stderr.strip()}")
            else:
                print(f"[ok] nrich results saved to {out_path}")

        except Exception as e:
            print(f"[err] NRICH phase failed: {e}")

    def merge_censys_nrich(run_dir: str):
        """
        Merge results_censys.xlsx + results_nrich.xlsx -> merged.xlsx
        One row per IP. Dedupes ports and DNS.
        """
        censys_path = os.path.join(run_dir, "results_censys.xlsx")
        nrich_path = os.path.join(run_dir, "results_nrich.xlsx")
        merged_path = os.path.join(run_dir, "merged.xlsx")

        if not os.path.exists(censys_path):
            print("[warn] censys results not found; skipping merge.")
            return
        if not os.path.exists(nrich_path):
            print("[warn] nrich results not found; skipping merge.")
            return

        # Lazy-import pandas so lack of it doesn't crash the main script
        try:
            import pandas as pd
        except ImportError:
            print("[warn] pandas not available; cannot produce merged.xlsx. Install pandas & openpyxl to enable merging.")
            return

        try:
            df_c = pd.read_excel(censys_path)
            df_n = pd.read_excel(nrich_path)
        except Exception as e:
            print(f"[err] Failed reading Excel files: {e}")
            return

        def norm(val):
            if pd.isna(val):
                return set()
            s = str(val)
            parts = re.split(r"[;,]", s)
            return {p.strip() for p in parts if p.strip()}

        merged = {}
        for _, row in df_c.iterrows():
            ip = str(row.get("ip", "")).strip()
            if not ip:
                continue
            merged[ip] = {
                "ports": norm(row.get("ports/protocol")),
                "dns": norm(row.get("DNS")),
            }
        for _, row in df_n.iterrows():
            ip = str(row.get("ip", "")).strip()
            if not ip:
                continue
            if ip not in merged:
                merged[ip] = {"ports": set(), "dns": set()}
            merged[ip]["ports"].update(norm(row.get("ports/protocol")))
            merged[ip]["dns"].update(norm(row.get("dns")) or norm(row.get("DNS")))

        rows = []
        for ip, d in sorted(merged.items()):
            ports_sorted = sorted(
                d["ports"],
                key=lambda x: (int(x.split("/")[0]) if x.split("/")[0].isdigit() else 99999, x),
            )
            dns_sorted = sorted(d["dns"])
            rows.append({
                "ip": ip,
                "ports/protocol": "; ".join(ports_sorted),
                "DNS": "; ".join(dns_sorted),
            })

        try:
            pd.DataFrame(rows).to_excel(merged_path, index=False)
            print(f"[ok] merged.xlsx written to {merged_path}")
        except Exception as e:
            print(f"[err] Failed writing merged.xlsx: {e}")

    # --- Execute the new post-run phases ---
    try:
        run_nrich_phase(IPS_FILE, run_dir)
    except Exception as e:
        print(f"[err] Failed running nrich: {e}")

    try:
        print("[stage] NRICH finished (if available). Merging results...")
        merge_censys_nrich(run_dir)
    except Exception as e:
        print(f"[err] Merge failed: {e}")
    # ==========================================================================
if __name__ == "__main__":
    run_all()
