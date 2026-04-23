#!/usr/bin/env python3
"""
DeepProbe Volatility Analysis Runner

Tested with: Volatility 3 (2.26.x). Python 3.10+.

Usage:
  python runner.py --image memory.raw --case case1 \
    --detections detections.yaml --baseline detections.yaml --outdir out \
    --api-key YOUR_IP_ENRICHMENT_API_KEY

Notes:
- Keeps stdout very chatty so you can see exactly what runs.
- Handles Win7 limitations gracefully (skips unsupported plugins).
- Places “-r csv” BEFORE plugin name when format=csv (Vol3 quirk).
"""

import argparse, json, os, re, shutil, subprocess, sys, time, textwrap
from pathlib import Path
from datetime import datetime, UTC
from typing import Dict, List, Any, Tuple
import requests
import ipaddress
from io import StringIO
import traceback

print("[DEBUG] runner.py has started. All imports successful.")

try:
    import yaml
except Exception as e:
    print("Please: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# ---------------------------
# Helpers
# ---------------------------

def sh(cmd: List[str], capture=True, cwd=None) -> Tuple[int, str]:
    """Run a shell command. Returns (rc, output)."""
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            cwd=cwd,
            text=True
        )
        return proc.returncode, (proc.stdout or "")
    except FileNotFoundError:
        return 127, f"[ENOENT] {cmd[0]} not found on PATH"
    except Exception as e:
        return 1, f"[ERROR] {' '.join(cmd)} :: {e}"


def find_vol_binary(prefer_list: List[str]) -> str:
    for name in prefer_list:
        rc, _ = sh(["which", name])
        if rc == 0:
            return name
    return ""


def ensure_dirs(outdir: Path):
    print(f"[DEBUG] Ensuring output directories exist at: {outdir}")
    (outdir / "artifacts").mkdir(parents=True, exist_ok=True)
    (outdir / "logs").mkdir(exist_ok=True)
    print(f"[DEBUG] Directories created/exist.")


def write_file(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8", errors="ignore")


def now_iso() -> str:
    return datetime.now(UTC).isoformat() + "Z"


def compile_any_contains_to_regex(parts: List[str]) -> re.Pattern:
    escaped = []
    for p in parts:
        escaped.append(re.escape(p))
    regex = "(" + "|".join(escaped) + ")"
    return re.compile(regex, re.IGNORECASE)


def in_cidrs(ip: str, cidrs: List[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for block in cidrs:
            if addr in ipaddress.ip_network(block, strict=False):
                return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Free OSINT IP reputation feeds  (no API key required)
# ---------------------------------------------------------------------------
# Three sources are used:
#   Feodo Tracker  — C2 botnet IPs (Dridex, Emotet, TrickBot, etc.)
#   SSLBL          — IPs hosting malicious SSL certificates
#   ThreatFox      — IOC feed (malware, C2, stealers)
#
# Feeds are downloaded once and cached in memory for FEED_TTL seconds.
# A lookup returns a scoring dict compatible with the existing get_ip_info()
# output format.  Scores are additive — an IP can appear in multiple feeds.
# ---------------------------------------------------------------------------

_FEED_URLS = {
    "feodo":     "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "sslbl":     "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    "threatfox": "https://threatfox.abuse.ch/export/json/recent/",
}
_FEED_SCORES = {"feodo": 10, "sslbl": 8, "threatfox": 8}
FEED_TTL = 6 * 3600   # 6 hours between refreshes

# Disk cache path — lives next to the script so it survives container restarts
# as long as the ./out volume is mounted.  Falls back to /tmp if that dir is
# not writable (e.g. read-only container filesystem).
_FEED_DISK_CACHE = Path(__file__).parent / "out" / ".osint_feed_cache.json"

_feed_cache: Dict[str, set]  = {}   # source_name -> set of IP strings
_feed_last_updated: float    = 0.0  # unix timestamp of last successful refresh


def _load_feed_cache_from_disk() -> bool:
    """
    Try to load the OSINT feed cache from the on-disk JSON file.
    Returns True if the cache was loaded and is still fresh enough to use.
    """
    global _feed_cache, _feed_last_updated
    try:
        if not _FEED_DISK_CACHE.exists():
            return False
        with _FEED_DISK_CACHE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        saved_ts = float(data.get("timestamp", 0))
        if (time.time() - saved_ts) >= FEED_TTL:
            print("[i] Disk OSINT cache exists but is expired — will re-download")
            return False
        feeds = data.get("feeds", {})
        _feed_cache = {k: set(v) for k, v in feeds.items()}
        _feed_last_updated = saved_ts
        total = sum(len(s) for s in _feed_cache.values())
        print(f"[i] Loaded OSINT feed cache from disk — {total} IPs, age {int(time.time()-saved_ts)}s")
        return True
    except Exception as e:
        print(f"[warn] Could not load OSINT disk cache: {e}", file=sys.stderr)
        return False


def _save_feed_cache_to_disk() -> None:
    """Persist the in-memory feed cache to disk for use across restarts."""
    try:
        _FEED_DISK_CACHE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "timestamp": _feed_last_updated,
            "feeds": {k: sorted(v) for k, v in _feed_cache.items()},
        }
        tmp = _FEED_DISK_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
        tmp.replace(_FEED_DISK_CACHE)   # atomic replace
        print(f"[i] OSINT cache persisted to disk: {_FEED_DISK_CACHE}")
    except Exception as e:
        print(f"[warn] Could not save OSINT disk cache: {e}", file=sys.stderr)


def _refresh_osint_feeds(force: bool = False) -> None:
    """
    Download/refresh the three OSINT feeds.  Thread-safe enough for the
    single-process runner (no locking needed).  Silently tolerates network
    failures — if a feed can't be fetched the cache entry stays empty.
    """
    global _feed_last_updated

    # ── Short-circuit 1: in-memory cache is still fresh ─────────────────────
    if not force and (time.time() - _feed_last_updated) < FEED_TTL:
        return

    # ── Short-circuit 2: try loading from disk before hitting the network ───
    if not force and _load_feed_cache_from_disk():
        return   # disk cache was fresh enough

    print("[i] Refreshing OSINT reputation feeds …")
    new_cache: Dict[str, set] = {"feodo": set(), "sslbl": set(), "threatfox": set()}
    ip_re     = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    any_downloaded = False

    # ── Feodo Tracker & SSLBL (CSV / plain-text) ────────────────────────────
    for name in ("feodo", "sslbl"):
        try:
            r = requests.get(_FEED_URLS[name], timeout=15)
            r.raise_for_status()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Feodo CSV: "dst_ip,dst_port,date_added,…"   SSLBL: "IP,Port,…"
                m = ip_re.search(line)
                if m:
                    try:
                        ipaddress.ip_address(m.group(1))  # validate
                        new_cache[name].add(m.group(1))
                    except ValueError:
                        pass
            print(f"[i]   {name}: {len(new_cache[name])} IPs loaded")
            any_downloaded = True
        except Exception as e:
            print(f"[warn] OSINT feed '{name}' unavailable: {e}", file=sys.stderr)
            # Keep existing in-memory data for this source if available
            if name in _feed_cache:
                new_cache[name] = _feed_cache[name]
                print(f"[i]   {name}: using stale in-memory cache ({len(new_cache[name])} IPs)")

    # ── ThreatFox (JSON) ────────────────────────────────────────────────────
    try:
        r = requests.get(_FEED_URLS["threatfox"], timeout=20)
        r.raise_for_status()
        payload = r.json()
        # Response is {"query_status": "ok", "data": [{"ioc": "1.2.3.4:PORT", ...}, …]}
        data = payload.get("data") or []
        if isinstance(data, dict):
            data = list(data.values())   # older API returned dict keyed by id
        for item in (data if isinstance(data, list) else []):
            ioc = item.get("ioc", "") if isinstance(item, dict) else str(item)
            # IOC may be "1.2.3.4" or "1.2.3.4:4444"
            m = ip_re.search(ioc)
            if m:
                try:
                    ipaddress.ip_address(m.group(1))
                    new_cache["threatfox"].add(m.group(1))
                except ValueError:
                    pass
        print(f"[i]   threatfox: {len(new_cache['threatfox'])} IPs loaded")
        any_downloaded = True
    except Exception as e:
        print(f"[warn] OSINT feed 'threatfox' unavailable: {e}", file=sys.stderr)
        if "threatfox" in _feed_cache:
            new_cache["threatfox"] = _feed_cache["threatfox"]
            print(f"[i]   threatfox: using stale in-memory cache ({len(new_cache['threatfox'])} IPs)")

    _feed_cache.update(new_cache)
    _feed_last_updated = time.time()
    total = sum(len(s) for s in _feed_cache.values())
    print(f"[i] OSINT feeds ready — {total} total IPs across all sources")

    # Persist to disk only when we actually downloaded fresh data
    if any_downloaded:
        _save_feed_cache_to_disk()


def osint_lookup(ip: str) -> Dict[str, Any]:
    """
    Look up an IP against the cached OSINT feeds.

    Returns a dict:
      {
        "reputation": "Malicious" | "Suspicious" | "Unknown",
        "osint_score": <int>,
        "osint_sources": ["feodo", …]
      }

    Never treats missing data as 'safe' — Unknown is the default.
    Results are deterministic: same IP always gets the same score for a
    given cache snapshot.
    """
    _refresh_osint_feeds()           # no-op if cache is fresh

    score   = 0
    sources = []

    for name, ip_set in _feed_cache.items():
        if ip in ip_set:
            score   += _FEED_SCORES[name]
            sources.append(name)

    if score >= 10:
        reputation = "Malicious"
    elif score >= 5:
        reputation = "Suspicious"
    else:
        reputation = "Unknown"

    return {
        "reputation":   reputation,
        "osint_score":  score,
        "osint_sources": sources,
    }


def get_ip_info(ip: str, api_key: str) -> Dict[str, str]:
    # ── Step 1: free OSINT lookup (always runs, no key needed) ──────────────
    osint   = osint_lookup(ip)
    info    = {
        "country":      "N/A",
        "isp":          "N/A",
        "reputation":   osint["reputation"],
        "osint_score":  osint["osint_score"],
        "osint_sources": ", ".join(osint["osint_sources"]) if osint["osint_sources"] else "none",
    }

    # ── Step 2: enrich with AbuseIPDB if a key was provided ─────────────────
    if not api_key:
        # No API key — augment with ipinfo.io geo data only, keep OSINT reputation
        geo = _ipinfo_fallback(ip)
        info["country"] = geo.get("country", "N/A")
        info["isp"]     = geo.get("isp", "N/A")
        # Keep OSINT reputation — don't downgrade to "Unknown"
        if info["reputation"] == "Unknown":
            info["reputation"] = geo.get("reputation", "Unknown")
        return info

    abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': api_key,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90
    }

    try:
        print(f"[info] Querying AbuseIPDB for IP: {ip}…")
        response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=5)
        response.raise_for_status()

        data = response.json().get("data", {})
        info["country"]      = data.get("countryCode", "N/A")
        info["isp"]          = data.get("isp", "N/A")
        info["abuse_reports"] = data.get("totalReports", 0)
        info["last_reported"] = data.get("lastReportedAt", "N/A")

        # Merge AbuseIPDB confidence score with OSINT score
        # AbuseIPDB score is 0-100; map it to the same 0-26 range so both
        # sources contribute proportionally.
        abuse_conf = data.get("abuseConfidenceScore", 0)
        combined_score = osint["osint_score"] + round(abuse_conf * 26 / 100)

        if combined_score >= 10 or abuse_conf > 60:
            info["reputation"] = "Malicious"
        elif combined_score >= 5 or abuse_conf > 20:
            info["reputation"] = "Suspicious"
        elif osint["osint_score"] == 0:
            info["reputation"] = "Clean"
        # else keep OSINT reputation (e.g. Malicious from OSINT even if AbuseIPDB shows low score)

        print(
            f"[info] {ip}: country={info['country']}, osint={osint['osint_score']} "
            f"(sources: {osint['osint_sources']}), abuse={abuse_conf}% → {info['reputation']}",
            file=sys.stderr
        )

    except requests.exceptions.HTTPError as e:
        print(f"[WARN] AbuseIPDB HTTP {e.response.status_code} for {ip} — geo fallback (OSINT score kept)", file=sys.stderr)
        geo = _ipinfo_fallback(ip)
        info["country"] = geo.get("country", "N/A")
        info["isp"]     = geo.get("isp", "N/A")
    except requests.exceptions.ConnectionError:
        print(f"[WARN] AbuseIPDB unreachable for {ip} — geo fallback (OSINT score kept)", file=sys.stderr)
        geo = _ipinfo_fallback(ip)
        info["country"] = geo.get("country", "N/A")
        info["isp"]     = geo.get("isp", "N/A")
    except requests.exceptions.Timeout:
        print(f"[WARN] AbuseIPDB timed out for {ip} — geo fallback (OSINT score kept)", file=sys.stderr)
        geo = _ipinfo_fallback(ip)
        info["country"] = geo.get("country", "N/A")
        info["isp"]     = geo.get("isp", "N/A")
    except Exception as e:
        print(f"[WARN] AbuseIPDB error for {ip}: {e} — geo fallback (OSINT score kept)", file=sys.stderr)
        geo = _ipinfo_fallback(ip)
        info["country"] = geo.get("country", "N/A")
        info["isp"]     = geo.get("isp", "N/A")

    return info


def _ipinfo_fallback(ip: str) -> Dict[str, str]:
    """Fallback IP enrichment using ipinfo.io (free tier, no reputation scoring)."""
    info = {"country": "N/A", "isp": "N/A", "reputation": "Unknown (AbuseIPDB failed — ipinfo.io fallback)"}
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            info["country"] = data.get("country", "N/A")
            info["isp"] = data.get("org", "N/A")
            info["reputation"] = "Unknown (ipinfo.io fallback — no AbuseIPDB key or API failed)"
    except Exception as e:
        print(f"[warn] ipinfo.io fallback also failed for {ip}: {e}", file=sys.stderr)
    return info


# ---------------------------
# Volatility Runner
# ---------------------------

def run_plugin(vol: str, image: str, plugin: str, fmt: str, outdir: Path) -> str:
    base = [vol, "-f", image, "--quiet"]
    if fmt == "csv":
        cmd = base + ["-r", "csv", plugin]
    else:
        cmd = base + [plugin]

    safe_plugin_name = plugin.replace(".", "_")
    ext = "csv" if fmt == "csv" else "txt"
    raw_path = outdir / "artifacts" / f"{safe_plugin_name}.{ext}"

    print(f"[DEBUG] Attempting to run Volatility command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
            errors="replace"
        )
        out = proc.stdout
        print(f"[DEBUG] Raw output from {plugin} (first 500 chars):\n{out[:500]}...")
        write_file(raw_path, out)
        return out
    except subprocess.CalledProcessError as e:
        error_message = f"[ERROR] Plugin '{plugin}' failed with exit code {e.returncode}. Output:\n{e.stdout}"
        print(error_message, file=sys.stderr)
        return error_message
    except Exception as e:
        error_message = f"[ERROR] Plugin '{plugin}' failed unexpectedly: {e}"
        print(error_message, file=sys.stderr)
        return error_message


def try_plugin_with_fallbacks(vol: str, image: str, name: str, fmt: str, fallbacks: List[str], outdir: Path) -> Tuple[str, str]:
    content = run_plugin(vol, image, name, fmt, outdir)
    if "invalid choice" in content or "not supported" in content or "Traceback" in content or "Unsatisfied requirement" in content:
        print(f"[DEBUG] Plugin {name} failed or gave invalid output. Trying fallbacks: {fallbacks}")
        for alt in fallbacks or []:
            alt_content = run_plugin(vol, image, alt, fmt, outdir)
            if "invalid choice" not in alt_content and "Traceback" not in alt_content and "Unsatisfied requirement" not in alt_content:
                print(f"[DEBUG] Fallback {alt} successful.")
                return alt, alt_content
    return name, content


def detect_os(info_text: str) -> str:
    if "NtSystemRoot" in info_text or "IsPAE" in info_text:
        return "windows"
    if "Linux" in info_text or "linux" in info_text:
        return "linux"
    if "Darwin" in info_text or "Mac" in info_text:
        return "macos"
    return "windows"


# ---------------------------
# Parsers
# ---------------------------

def parse_csv(text: str) -> List[Dict[str, str]]:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        print("[DEBUG] parse_csv received empty text or only whitespace lines.")
        return []
    header_idx = 0
    for i, l in enumerate(lines[:10]):
        if "," in l and not l.lower().startswith("volatility 3"):
            header_idx = i
            break
    hdr = [h.strip() for h in lines[header_idx].split(",")]
    rows = []
    for l in lines[header_idx+1:]:
        parts = l.split(",", len(hdr)-1)
        parts += [""] * (len(hdr)-len(parts))
        rows.append({hdr[i]: parts[i].strip() for i in range(len(hdr))})
    print(f"[DEBUG] parse_csv parsed {len(rows)} rows with headers: {hdr}")
    return rows


def kv_parse(text: str) -> Dict[str, str]:
    d = {}
    for line in text.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            d[k.strip()] = v.strip()
        elif ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


# ---------------------------
# Engines
# ---------------------------
def eng_process_pid_match(pslist_rows: List[Dict[str, str]], target_pid: int):
    findings = []
    for r in pslist_rows:
        try:
            if int(r.get("PID","")) == target_pid:
                findings.append({"pid": target_pid, "name": r.get("ImageFileName","") or r.get("Name","")})
                break
        except (ValueError, TypeError):
            continue
    return findings

def eng_unknown_process_name(pslist_rows, baseline, oskey="windows"):
    wl = set((baseline.get("process_whitelist", {}).get(oskey, [])) or [])
    findings = []
    for r in pslist_rows:
        name = r.get("ImageFileName", "") or r.get("Name", "")
        pid  = r.get("PID", "")
        if name and (name.lower() not in [n.lower() for n in wl]):
            findings.append({"pid": pid, "name": name, "path": r.get("Path","")})
    return findings

def eng_psxview_hidden(rows):
    findings = []
    for r in rows:
        try:
            if r.get("pslist","").lower() == "false" and (
                r.get("psscan","").lower() == "true" or
                r.get("thrdscan","").lower() == "true" or
                r.get("csrss","").lower() == "true"
            ):
                findings.append({
                    "pid": r.get("PID",""),
                    "name": r.get("Name",""),
                    "pslist_present": r.get("pslist",""),
                    "psscan_present": r.get("psscan",""),
                    "thrdscan_present": r.get("thrdscan",""),
                    "csrss_present": r.get("csrss",""),
                })
        except:
            pass
    return findings

def eng_suspicious_connection(rows, baseline):
    print(f"[DEBUG] eng_suspicious_connection: Received {len(rows)} rows.")
    allow_cidrs = baseline.get("network", {}).get("allow_cidrs", []) or []
    allow_ports = set(str(p) for p in (baseline.get("network", {}).get("allow_ports", []) or []))
    findings = []
    for r in rows:
        faddr = r.get("ForeignAddr","") or r.get("ForeignIP","")
        fport = r.get("ForeignPort","") or r.get("ForeignPortNumber","")
        if not faddr or faddr in ("0.0.0.0","::","*"):
            continue
        ok_cidr = in_cidrs(faddr, allow_cidrs)
        ok_port = str(fport) in allow_ports
        print(f"[DEBUG] Suspicious_connection check for {faddr}:{fport}. OK CIDR: {ok_cidr}, OK Port: {ok_port}")
        if not (ok_cidr or ok_port):
            findings.append({
                "pid": r.get("PID",""),
                "owner": r.get("Owner","") or r.get("Process",""),
                "ForeignAddr": faddr,
                "ForeignPort": fport,
                "LocalAddr": r.get("LocalAddr",""),
                "LocalPort": r.get("LocalPort",""),
                "State": r.get("State",""),
            })
    print(f"[DEBUG] eng_suspicious_connection: Found {len(findings)} findings.")
    return findings

def eng_network_enrichment_master(netstat_rows: List[Dict[str, Any]], detection_rules: List[Dict[str, Any]], baseline: Dict[str, Any], api_key: str) -> List[Dict[str, Any]]:
    findings = []
    processed_ips = {}
    if not netstat_rows:
        print("[DEBUG] eng_network_enrichment_master: Received no rows.")
        return findings
    print("[info] Running network enrichment master engine...")
    allow_cidrs = baseline.get("network", {}).get("allow_cidrs", []) or []
    unique_ips_to_process = set()
    for row in netstat_rows:
        foreign_ip = row.get("ForeignAddr", "").strip()
        try:
            ip_obj = ipaddress.ip_address(foreign_ip)
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_private:
                continue
            if not in_cidrs(foreign_ip, allow_cidrs):
                unique_ips_to_process.add(foreign_ip)
        except ValueError:
            continue
    print(f"[DEBUG] eng_network_enrichment_master: Unique IPs to process: {unique_ips_to_process}")
    for ip in unique_ips_to_process:
        if ip in processed_ips:
            enriched_data = processed_ips[ip]
        else:
            print(f"[info] Fetching enrichment for IP: {ip}")
            enriched_data = get_ip_info(ip, api_key)
            processed_ips[ip] = enriched_data
        
    for ip, enriched_data in processed_ips.items():
        for detection_rule in detection_rules:
            if detection_rule.get('engine') != 'network_enrichment':
                continue
            is_suspicious_for_this_rule = False
            reasons = []
            rules_logic = detection_rule.get("logic", [])
            for logic_rule in rules_logic:
                rule_matched_locally = True
                for match_criteria in logic_rule.get("match", []):
                    field = match_criteria.get("field")
                    value = match_criteria.get("value")
                    operator = match_criteria.get("operator", "==")
                    if field in enriched_data:
                        data_val = enriched_data[field]
                        if operator == "==":
                            if not (str(data_val).lower() == str(value).lower()):
                                rule_matched_locally = False
                                break
                        elif operator == "<":
                            try:
                                if not (float(data_val) < float(value)):
                                    rule_matched_locally = False
                                    break
                            except ValueError:
                                rule_matched_locally = False
                                break
                if rule_matched_locally:
                    is_suspicious_for_this_rule = True
                    for match_criteria in logic_rule.get("match", []):
                        field = match_criteria.get("field")
                        if field in enriched_data:
                            reasons.append(f"Field '{field}' ({enriched_data[field]}) matches condition '{match_criteria.get('value')}'")
                    break
            if is_suspicious_for_this_rule:
                associated_connections = [conn for conn in netstat_rows if (conn.get("ForeignAddr", "") or conn.get("ForeignIP", "")) == ip]
                pids = list(set([c.get("Pid", c.get("PID", "N/A")) for c in associated_connections]))
                owners = list(set([c.get("Owner", c.get("Process", "N/A")) for c in associated_connections]))
                pids_display = ", ".join(p for p in pids if p and p != "N/A") or "N/A"
                owners_display = ", ".join(o for o in owners if o and o != "N/A") or "N/A"
                finding_evidence = {
                    "pid": pids_display, "owner": owners_display, "ip": ip,
                    "country": enriched_data.get("country", "N/A"), "isp": enriched_data.get("isp", "N/A"),
                    "reputation": enriched_data.get("reputation", "N/A"), "notes": "; ".join(reasons)
                }
                findings.append({
                    "id": detection_rule["id"], "title": detection_rule["title"], "narrative": detection_rule["narrative"],
                    "mitre": detection_rule.get("mitre", []), "weight": detection_rule["weight"],
                    "evidence": [finding_evidence]
                })
    return findings


def eng_suspicious_port_activity(rows, suspicious_ports: List[int]):
    findings = []
    susp_ports = {str(p) for p in suspicious_ports}
    for r in rows:
        local_port = r.get("LocalPort", "")
        foreign_port = r.get("ForeignPort", "")
        if (local_port and str(local_port).strip() != '0' and local_port in susp_ports) or \
           (foreign_port and str(foreign_port).strip() != '0' and foreign_port in susp_ports):
            findings.append({
                "pid": r.get("PID",""), "owner": r.get("Owner","") or r.get("Process",""),
                "Proto": r.get("Proto",""), "LocalPort": local_port,
                "ForeignPort": foreign_port, "Notes": "Connection found on a known suspicious port."
            })
    return findings

def _ev_pid(ev: Dict[str, Any]) -> str:
    """
    Normalise the PID out of an evidence dict.

    Different engine functions store the PID under different key names:
      - 'pid'           — most process-centric engines (lowercase)
      - 'Pid'           — eng_services_suspicious (mixed-case from svcscan CSV)
      - 'requestor_pid' — eng_handles_general (the handle-holder PID)
    Returns a stripped string, or "" if none found.
    """
    raw = ev.get("pid") or ev.get("Pid") or ev.get("requestor_pid") or ""
    return str(raw).strip() if raw and str(raw).strip() not in ("", "N/A", "None") else ""


def eng_correlated_findings(all_findings: List[Dict[str, Any]], correlation_pairs: List[Dict[str, Any]]):
    """
    Correlate findings that share a common process PID.

    Two categories of evidence:
      • PID-bearing  — evidence items that contain a process PID (most engine outputs).
      • System-wide  — evidence items with NO PID (e.g. scheduled-task lines, file-scan
                        paths, registry key values).  These are attached as context to
                        every chain that fires, because they represent host-wide
                        persistence/execution indicators that are relevant regardless of
                        which process triggered the chain.

    A correlation chain is only emitted when at least one PID appears in BOTH the
    primary finding set AND the secondary finding set.  Empty chains (where PID
    normalisation failed for every evidence item) are never emitted.
    """
    results = []

    # ── Pre-pass: build a global PID → PPID map from ALL findings ────────────
    # Findings from eng_unusual_parent_child and eng_wmi_suspicious_spawn carry
    # "parent_pid" / "ppid" in their evidence items, letting us detect
    # parent→child process relationships across the whole image.
    pid_to_ppid: Dict[str, str] = {}
    for f in all_findings:
        for ev in f.get("evidence", []):
            child_pid  = _ev_pid(ev)
            parent_pid = str(
                ev.get("parent_pid") or ev.get("ppid") or ev.get("PPID") or
                ev.get("ParentPID") or ""
            ).strip()
            if (child_pid and parent_pid
                    and parent_pid not in ("", "N/A", "None", "0", "nan")):
                pid_to_ppid[child_pid] = parent_pid

    for pair in correlation_pairs:
        primary_ids   = set(pair.get("primary_ids", []))
        secondary_ids = set(pair.get("secondary_ids", []))
        all_ids       = primary_ids | secondary_ids

        # ── Step 1: classify each referenced finding as PID-bearing or system-wide ──
        pid_bearing: Dict[str, List[Dict]] = {}   # finding_id -> list of evidence items with a PID
        system_wide: List[Dict]            = []   # evidence items from PID-less findings (all IDs combined)

        for f in all_findings:
            if f["id"] not in all_ids:
                continue
            ev_with_pid = [ev for ev in f.get("evidence", []) if _ev_pid(ev)]
            ev_no_pid   = [ev for ev in f.get("evidence", []) if not _ev_pid(ev)]

            if ev_with_pid:
                pid_bearing[f["id"]] = ev_with_pid
            elif ev_no_pid:
                system_wide.append({
                    "finding_id": f["id"],
                    "title":      f.get("title", f["id"]),
                    "evidence":   ev_no_pid[:5],
                    "time_utc":   f.get("time_utc", "unknown"),
                })

        # ── Step 2: build PID sets for primary and secondary ──
        def _pids_for(ids):
            s = set()
            for fid in ids:
                for ev in pid_bearing.get(fid, []):
                    p = _ev_pid(ev)
                    if p:
                        s.add(p)
            return s

        primary_pids    = _pids_for(primary_ids)
        secondary_pids  = _pids_for(secondary_ids)
        correlated_pids = primary_pids & secondary_pids

        pair_results: List[Dict] = []   # chains produced for this pair

        # ── Step 3 (STRONG): same PID in both primary and secondary ──────────
        for pid in sorted(correlated_pids):
            chain = []
            for f in all_findings:
                if f["id"] not in all_ids:
                    continue
                pid_ev = [ev for ev in pid_bearing.get(f["id"], []) if _ev_pid(ev) == pid]
                if pid_ev:
                    chain.append({
                        "finding_id": f["id"],
                        "title":      f.get("title", f["id"]),
                        "evidence":   pid_ev,
                        "time_utc":   f.get("time_utc", "unknown"),
                    })
            chain.extend(system_wide)
            if chain:
                pair_results.append({
                    "correlated_pid":      pid,
                    "correlated_findings": chain,
                    "correlated_rule_ids": list(all_ids),
                    "confidence":          "strong",
                    "correlation_type":    "same_pid",
                })

        # ── Step 4 (MEDIUM): parent-child PID relationship ───────────────────
        # Primary finding's PID is a parent (or child) of a secondary PID.
        # Uses the pid_to_ppid map built from parent_pid / ppid evidence fields.
        if not pair_results:
            pc_seen: set = set()   # avoid duplicate chains for the same pair
            for p_pid in sorted(primary_pids):
                for s_pid in sorted(secondary_pids):
                    # Direct parent → child or child → parent
                    is_p_parent = pid_to_ppid.get(s_pid) == p_pid
                    is_s_parent = pid_to_ppid.get(p_pid) == s_pid
                    if not (is_p_parent or is_s_parent):
                        continue
                    pair_key = (min(p_pid, s_pid), max(p_pid, s_pid))
                    if pair_key in pc_seen:
                        continue
                    pc_seen.add(pair_key)

                    parent_pid_label = p_pid if is_p_parent else s_pid
                    child_pid_label  = s_pid if is_p_parent else p_pid
                    chain = []
                    for f in all_findings:
                        if f["id"] not in all_ids:
                            continue
                        for target_pid in (p_pid, s_pid):
                            pid_ev = [
                                ev for ev in pid_bearing.get(f["id"], [])
                                if _ev_pid(ev) == target_pid
                            ]
                            if pid_ev:
                                chain.append({
                                    "finding_id":   f["id"],
                                    "title":        f.get("title", f["id"]),
                                    "evidence":     pid_ev,
                                    "time_utc":     f.get("time_utc", "unknown"),
                                    "process_role": (
                                        "parent" if target_pid == parent_pid_label
                                        else "child"
                                    ),
                                })
                    chain.extend(system_wide)
                    if chain:
                        pair_results.append({
                            "correlated_pid":      parent_pid_label,
                            "correlated_findings": chain,
                            "correlated_rule_ids": list(all_ids),
                            "confidence":          "medium",
                            "correlation_type":    "parent_child",
                            "note": (
                                f"Parent-child correlation: PID {parent_pid_label} "
                                f"spawned PID {child_pid_label}. "
                                "Suspicious activity spans a process spawn boundary."
                            ),
                        })

        # ── Step 5 (WEAK): behavioral co-presence fallback ───────────────────
        # Both primary AND secondary findings exist in the image but share no
        # PID or parent-child link.  Still meaningful — co-occurring indicators
        # suggest a multi-stage attack even when individual stages used separate
        # processes (e.g. certutil download finished before netstat snapshot).
        if not pair_results:
            secondary_present = any(
                f["id"] in secondary_ids and f.get("evidence")
                for f in all_findings
            )
            if secondary_present and primary_pids:
                for pid in sorted(primary_pids):
                    chain = []
                    for f in all_findings:
                        if f["id"] not in primary_ids:
                            continue
                        pid_ev = [ev for ev in pid_bearing.get(f["id"], []) if _ev_pid(ev) == pid]
                        if pid_ev:
                            chain.append({
                                "finding_id": f["id"],
                                "title":      f.get("title", f["id"]),
                                "evidence":   pid_ev,
                                "time_utc":   f.get("time_utc", "unknown"),
                            })
                    for f in all_findings:
                        if f["id"] not in secondary_ids or not f.get("evidence"):
                            continue
                        chain.append({
                            "finding_id":  f["id"],
                            "title":       f.get("title", f["id"]),
                            "evidence":    f.get("evidence", [])[:5],
                            "time_utc":    f.get("time_utc", "unknown"),
                            "co_presence": True,
                        })
                    chain.extend(system_wide)
                    if chain:
                        pair_results.append({
                            "correlated_pid":      pid,
                            "correlated_findings": chain,
                            "correlated_rule_ids": list(all_ids),
                            "confidence":          "weak",
                            "correlation_type":    "co_presence",
                            "note": (
                                "Behavioral co-presence: primary and secondary findings "
                                "both detected in this image with no shared PID or "
                                "process-spawn relationship. Indicates a multi-stage "
                                "pattern across separate processes."
                            ),
                        })

        results.extend(pair_results)

    return results


def eng_malfind_injection(text, keywords: List[str]):
    findings = []
    if not text.strip(): return findings
    blocks = text.splitlines()
    acc = []
    for line in blocks:
        if line.strip(): acc.append(line)
    if not acc: return findings
    blob = "\n".join(acc)
    matches = re.finditer(r"^PID:\s*(\d+).*?Process:\s*([^\s]+).*?Start:\s*([0-9xa-fA-F]+).*?Protection:\s*([^\r\n]+)", blob, re.I|re.M|re.S)
    for m in matches:
        item = {
            "pid": m.group(1), "process": m.group(2), "Start": m.group(3),
            "Protection": m.group(4).strip(), "PrivateMemory": "", "Notes": ""
        }
        if keywords:
            kblob = blob[max(0, m.start()-400): m.end()+400]
            for kw in keywords:
                if re.search(kw, kblob, re.I):
                    item["Notes"] = f"Keyword hit: {kw}"
                    break
        findings.append(item)
    return findings

def eng_hollowed_process(text, keywords: List[str]):
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Hollowed" in line or "hollow" in line.lower():
            row = {"Details": line.strip()}
            if keywords:
                for kw in keywords:
                    if re.search(kw, line, re.I):
                        row["Details"] += f" [kw:{kw}]"
                        break
            findings.append(row)
    return findings

def eng_ldr_unlinked_module(text, temp_like_paths: List[str]):
    findings = []
    if not text.strip(): return findings
    rx_temp = compile_any_contains_to_regex(temp_like_paths) if temp_like_paths else None
    for line in text.splitlines():
        low = line.lower()
        flag = ("false" in low and ("inload" in low or "ininit" in low or "inmem" in low))
        if not flag and rx_temp:
            flag = bool(rx_temp.search(low))
        if flag:
            findings.append({"Details": line.strip()})
    return findings

def eng_handles_general(text, access_regex: str, target_regex: str = None, lsass_special=False):
    findings = []
    if not text.strip(): return findings
    re_access = re.compile(access_regex, re.I) if access_regex else None
    re_target = re.compile(target_regex, re.I) if target_regex else None
    for line in text.splitlines():
        low = line.lower()
        if re_access and not re_access.search(low): continue
        if re_target and not re_target.search(low): continue
        m = re.search(r"(?i)PID\s+(\d+).*?(?i)Process\s+([^\s]+)", line)
        req_pid = m.group(1) if m else ""
        req_name = m.group(2) if m else ""
        tgt = ""
        if "lsass" in low: tgt = "lsass.exe"
        findings.append({
            "requestor_pid": req_pid, "requestor_name": req_name, "target_pid": "",
            "target_name": tgt, "GrantedAccess": line.strip()
        })
    return findings

def eng_services_suspicious(rows: List[Dict[str, str]], temp_like_paths: List[str], baseline) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not temp_like_paths:
        return findings

    rx = compile_any_contains_to_regex(temp_like_paths)
    allowlist = baseline.get('service_path_allowlist', [])
    
    for r in rows:
        image_path = r.get("ImagePath", "")
        service_name = r.get("ServiceName", "")
        
        is_allowed = False
        for entry in allowlist:
            if entry.get('service_name') == service_name:
                regex = entry.get('image_path_regex')
                if regex and re.search(regex, image_path, re.I):
                    is_allowed = True
                    break
        
        if not is_allowed and image_path and rx.search(image_path.lower()):
            findings.append({
                "ServiceName": service_name, "ServiceType": r.get("Type", "N/A"),
                "ImagePath": image_path, "Start": r.get("Start", "N/A"), "Pid": r.get("Pid", "N/A")
            })
    return findings

def eng_scheduled_tasks(text, temp_like_paths: List[str], risky_exts: List[str]):
    findings = []
    if not text.strip(): return findings
    rx_path = compile_any_contains_to_regex(temp_like_paths) if temp_like_paths else None
    rx_ext  = re.compile(r"\.(" + "|".join([re.escape(e) for e in risky_exts]) + r")(\.|$)", re.I) if risky_exts else None
    for line in text.splitlines():
        low = line.lower()
        if (rx_path and rx_path.search(low)) or (rx_ext and rx_ext.search(low)):
            findings.append({"TaskLine": line.strip()})
    return findings

def eng_filescan_path_match(text, any_path_contains: List[str], any_file_ext: List[str], any_name_contains: List[str], baseline: Dict[str, Any]):
    findings = []
    if not text.strip(): return findings
    rx_path = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    rx_names = compile_any_contains_to_regex(any_name_contains) if any_name_contains else None
    rx_ext = None
    if any_file_ext:
        rx_ext = re.compile(r"\.(" + "|".join([re.escape(e) for e in any_file_ext]) + r")(\.|$)", re.I)

    allowlist = baseline.get('file_path_allowlist', [])

    for line in text.splitlines():
        low = line.lower()
        hit = False
        is_allowed = False
        
        m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(.*)$", line.strip())
        path = m.group(2) if m else line.strip()
        
        for entry in allowlist:
            regex = entry.get('path_regex')
            if regex and re.search(regex, path, re.I):
                is_allowed = True
                break
        
        if not is_allowed:
            if rx_path and rx_path.search(low): hit = True
            if rx_names and rx_names.search(low): hit = True
            if rx_ext and rx_ext.search(low): hit = True

        if hit:
            findings.append({"Offset": m.group(1) if m else "", "Path": path})
    return findings


def eng_registry_printkey_matches(vol, image, outdir, keys: List[str], value_regex: str, baseline: Dict[str, Any]):
    findings = []
    rx = re.compile(value_regex, re.I) if value_regex else None
    
    # We don't have a specific registry allowlist, so we just run the check.

    for key in keys:
        plugin_name = "windows.registry.printkey"
        cmd_args = [vol, "-f", image, "--quiet", plugin_name, "--key", key]
        rc, out = sh(cmd_args)

        safe_key_name = re.sub(r"[^A-Za-z0-9]+", "_", key)
        artifact_path = outdir / "artifacts" / f"{plugin_name.replace('.', '_')}_{safe_key_name}.txt"
        write_file(artifact_path, out)

        if not rx or not out.strip():
            continue
        for line in out.splitlines():
            if rx.search(line):
                m = re.match(r'^\s*([0-9a-fA-F]+)\s+(\w+)\s+([^\s]+)\s+(.*)$', line.strip())
                if m:
                    offset, name, type_val, decoded = m.groups()
                    findings.append({
                        "Key": key, "Name": name.strip(), "Type": type_val.strip(),
                        "Decoded": decoded.strip()
                    })
                else:
                    findings.append({"Key": key, "Name": "", "Decoded": line.strip()})
    return findings


def eng_userassist_suspicious(text, any_path_contains: List[str]):
    findings = []
    if not text.strip(): return findings
    rx = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    for line in text.splitlines():
        low = line.lower()
        if rx and rx.search(low):
            path_match = re.search(r'\\??\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)
            guid_path_match = re.search(r'\{[0-9A-F-]+\}\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)
            extracted_path = ""
            if path_match: extracted_path = path_match.group(1).strip()
            elif guid_path_match: extracted_path = guid_path_match.group(1).strip()
            count_match = re.search(r'Count:\s*(\d+)', line)
            last_updated_match = re.search(r'Last Updated:\s*(.*)', line)
            findings.append({
                "Path": extracted_path if extracted_path else line.strip(),
                "Count": count_match.group(1) if count_match else "",
                "LastUpdated": last_updated_match.group(1) if last_updated_match else ""
            })
    return findings

def eng_unusual_parent_child(pslist_rows, detections_params, baseline):
    bypid = {r.get("PID",""): {"name": r.get("ImageFileName","") or r.get("Name",""), "path": r.get("Path","")} for r in pslist_rows}
    findings = []
    known_good_parents = set(detections_params.get("known_good_parents", []))
    child_process_name = detections_params.get("child_process")
    
    allowlist = baseline.get('parent_child_allowlist', [])

    for r in pslist_rows:
        pid = r.get("PID","")
        name = r.get("ImageFileName","") or r.get("Name","")
        ppid = r.get("PPID","")
        parent_info = bypid.get(ppid, {})
        parent_name = parent_info.get("name", "")
        
        if name.lower() == child_process_name.lower():
            if parent_name.lower() not in [p.lower() for p in known_good_parents]:
                
                is_allowed = False
                for entry in allowlist:
                    p_regex = entry.get('parent_process_regex')
                    p_name = entry.get('parent_process_name')
                    c_regex = entry.get('child_process_regex')
                    c_name = entry.get('child_process_name')
                    
                    if p_regex and re.search(p_regex, parent_name, re.I) and c_regex and re.search(c_regex, name, re.I):
                        is_allowed = True
                        break
                    if p_name and p_name.lower() == parent_name.lower() and c_name and c_name.lower() == name.lower():
                        is_allowed = True
                        break

                if not is_allowed:
                    findings.append({
                        "parent_name": parent_name, "parent_pid": ppid,
                        "child_name": name, "child_pid": pid,
                        "command_line": r.get("CommandLine", "") # pslist might not have this, cmdline does
                    })
    return findings

def eng_sessions_anomalous(rows, ignore_users: List[str], suspicious_auth_packages: List[str]):
    findings = []
    ign = set([u.lower() for u in ignore_users or []])
    sap = [s.lower() for s in suspicious_auth_packages or []]
    for r in rows:
        user = (r.get("User","") or r.get("Username","")).lower()
        if user and user not in ign:
            auth = (r.get("AuthPackage","") or r.get("AuthenticationPackage","")).lower()
            if auth in sap:
                findings.append({
                    "SessionId": r.get("SessionId",""), "User": r.get("User",""),
                    "AuthPackage": r.get("AuthPackage",""), "LogonType": r.get("LogonType",""),
                    "Pid": r.get("Pid","") or r.get("PID",""), "Process": r.get("Process","") or r.get("ImageFileName",""),
                })
    return findings

def eng_suspicious_cmdline(cmdline_rows: List[Dict[str, str]], suspicious_keywords: List[str], baseline: Dict[str, Any]):
    findings = []
    if not cmdline_rows or not suspicious_keywords: return findings
    rx = compile_any_contains_to_regex(suspicious_keywords)
    allowlist = baseline.get('command_line_allowlist', [])

    for r in cmdline_rows:
        pid = r.get("PID", "")
        name = r.get("ImageFileName", "")
        cmdline = r.get("CommandLine", "")

        is_allowed = False
        for entry in allowlist:
            if 'regex' in entry and re.search(entry['regex'], cmdline, re.I):
                is_allowed = True
                break
            if 'exact' in entry and entry['exact'] == cmdline:
                is_allowed = True
                break
            if 'process_name' in entry and entry['process_name'].lower() == name.lower() and \
               'contains' in entry and entry['contains'].lower() in cmdline.lower():
                is_allowed = True
                break
        
        if not is_allowed and cmdline and rx.search(cmdline):
            findings.append({"pid": pid, "name": name, "command_line": cmdline})
    return findings

def eng_bash_history_grep(text: str, suspicious_keywords: List[str]):
    findings = []
    if not text.strip() or not suspicious_keywords: return findings
    rx = compile_any_contains_to_regex(suspicious_keywords)
    current_user = "Unknown"
    for line in text.splitlines():
        user_match = re.match(r'^\s*User:\s*(.+)$', line, re.IGNORECASE)
        if user_match:
            current_user = user_match.group(1).strip()
            continue
        command_match = re.match(r'^\s*Command:\s*(.+)$', line, re.IGNORECASE)
        if command_match: command = command_match.group(1).strip()
        else: command = line.strip()
        if command and rx.search(command):
            findings.append({"User": current_user, "Command": command})
    return findings

def eng_exec_from_tmp(pslist_rows: List[Dict[str, str]], temp_paths: List[str]) -> List[Dict[str, Any]]:
    """Detect processes running from temporary/user-writable directories."""
    findings = []
    if not pslist_rows or not temp_paths:
        return findings
    rx = compile_any_contains_to_regex(temp_paths)
    for r in pslist_rows:
        path = r.get("ImageFilePath", "") or r.get("Path", "") or ""
        name = r.get("ImageFileName", "") or r.get("Name", "") or ""
        pid  = r.get("PID", "")
        if not path:
            continue
        if rx.search(path.lower()):
            findings.append({"pid": pid, "name": name, "path": path})
    return findings


def eng_lsass_credential_dump(cmdline_rows: List[Dict[str, str]], malfind_text: str) -> List[Dict[str, Any]]:
    """Detect LSASS credential dump via cmdline patterns and malfind memory strings."""
    findings = []
    cred_tools = re.compile(
        r"(?i)(procdump|mimikatz|comsvcs\.dll|minidump|out-minidump|lsadump|sekurlsa|wce\.exe|"
        r"fgdump|pwdumpx|ntdsutil|ntdsgrab|lazagne|safetykatz)", re.I
    )
    lsass_target = re.compile(r"(?i)(lsass|\.dmp.*lsass|lsass.*\.dmp)", re.I)
    for r in cmdline_rows:
        cmdline = r.get("CommandLine", "") or ""
        if cred_tools.search(cmdline) or lsass_target.search(cmdline):
            findings.append({
                "pid": r.get("PID", ""), "name": r.get("ImageFileName", ""),
                "command_line": cmdline,
                "Notes": "Credential dumping tool or LSASS dump command detected."
            })
    # Check malfind for MiniDumpWriteDump / comsvcs indicators
    if re.search(r"(?i)(MiniDumpWriteDump|comsvcs|RtlReportSilentProcessExit)", malfind_text):
        findings.append({
            "pid": "injected", "name": "malfind",
            "command_line": "MiniDumpWriteDump / comsvcs found in injected memory",
            "Notes": "LSASS dump API/DLL detected in injected memory region."
        })
    return findings


def eng_entropy_anomaly(vadinfo_text: str, threshold: float = 7.0) -> List[Dict[str, Any]]:
    """Detect high-entropy private executable memory regions (packed/encrypted shellcode)."""
    import math
    findings = []
    if not vadinfo_text.strip():
        return findings
    current_pid = None
    current_proc = None
    block_info: Dict[str, Any] = {}
    current_bytes: List[int] = []

    for line in vadinfo_text.splitlines():
        pid_match = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+)', line, re.I)
        if pid_match:
            current_pid = pid_match.group(1)
            current_proc = pid_match.group(2)
            block_info = {}
            current_bytes = []
            continue
        vad_match = re.search(
            r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+).*?(PAGE_EXECUTE[_A-Z]*|RWX|RX).*?(Private|Image)',
            line, re.I
        )
        if vad_match:
            # Evaluate entropy for previous block if it exists
            if current_bytes and len(current_bytes) >= 64 and block_info:
                freq: Dict[int, int] = {}
                for b in current_bytes:
                    freq[b] = freq.get(b, 0) + 1
                entropy = -sum((c / len(current_bytes)) * math.log2(c / len(current_bytes))
                               for c in freq.values() if c > 0)
                if entropy >= threshold:
                    finding = dict(block_info)
                    finding["Entropy"] = f"{entropy:.2f}"
                    finding["SampleBytes"] = len(current_bytes)
                    finding["Notes"] = f"High entropy ({entropy:.2f}/8.0) in executable memory — possible packed/encrypted shellcode."
                    findings.append(finding)
            block_info = {
                "pid": current_pid, "process": current_proc,
                "Start": vad_match.group(1), "End": vad_match.group(2),
                "Protection": vad_match.group(3), "Type": vad_match.group(4)
            }
            current_bytes = []
            continue
        hex_match = re.match(r'\s*[0-9a-fA-F]+:\s+([0-9a-fA-F ]+)', line)
        if hex_match and block_info:
            current_bytes.extend(int(b, 16) for b in re.findall(r'[0-9a-fA-F]{2}', hex_match.group(1)))
    return findings[:25]  # Cap to avoid noise


def eng_linux_ldpreload(envars_text: str) -> List[Dict[str, Any]]:
    """Detect LD_PRELOAD / LD_LIBRARY_PATH hijacking in Linux process environments."""
    findings = []
    if not envars_text.strip():
        return findings
    current_pid = None
    current_proc = None
    for line in envars_text.splitlines():
        pid_match = re.search(r'PID\s*[:\s]+(\d+).*?(?:Process|Comm)\s*[:\s]+([^\s]+)', line, re.I)
        if pid_match:
            current_pid = pid_match.group(1)
            current_proc = pid_match.group(2)
            continue
        val_match = re.search(r'(LD_(?:PRELOAD|LIBRARY_PATH))\s*[=:]\s*(.+)', line)
        if val_match:
            findings.append({
                "pid": current_pid or "N/A",
                "process": current_proc or "N/A",
                "Variable": val_match.group(1),
                "Value": val_match.group(2).strip(),
                "Notes": "LD_PRELOAD/LD_LIBRARY_PATH set — potential shared library hijacking."
            })
    return findings


def eng_linux_cron_persistence(bash_text: str, lsof_text: str) -> List[Dict[str, Any]]:
    """Detect cron-based persistence via bash history commands and open file handles."""
    findings = []
    cron_rx = re.compile(
        r"(?i)(crontab\s+(-[eilr]|--[a-z]+)|"
        r"echo.+\|.+crontab|"
        r"/etc/cron\b|/var/spool/cron|"
        r"cron\.(d|daily|hourly|weekly|monthly)/|"
        r"\bat\s+\d+|\batd\b)",
        re.I
    )
    for line in bash_text.splitlines():
        if cron_rx.search(line):
            findings.append({
                "source": "bash_history",
                "Command": line.strip(),
                "Notes": "Cron/at persistence pattern found in bash history."
            })
    for line in lsof_text.splitlines():
        if re.search(r'(?i)/etc/cron|/var/spool/cron|cron\.d/', line):
            findings.append({
                "source": "open_file_handle",
                "Command": line.strip(),
                "Notes": "Cron config file held open — possible persistence write in progress."
            })
    return findings[:15]


def eng_linux_hidden_process(pslist_rows: List[Dict], psscan_rows: List[Dict]) -> List[Dict[str, Any]]:
    """Detect hidden Linux processes by comparing pslist vs psscan."""
    pslist_pids = {r.get("PID", "") for r in pslist_rows}
    findings = []
    for r in psscan_rows:
        pid = r.get("PID", "")
        if pid and pid not in pslist_pids:
            findings.append({
                "pid": pid,
                "name": r.get("ImageFileName", "") or r.get("Name", ""),
                "pslist_present": "False",
                "psscan_present": "True",
                "Notes": "Process found by psscan but absent from pslist — rootkit hiding suspected."
            })
    return findings


def eng_linux_syscall_hooks(check_syscall_text: str) -> List[Dict[str, Any]]:
    """Detect Linux syscall table entries pointing outside kernel modules."""
    findings = []
    if not check_syscall_text.strip():
        return findings
    for line in check_syscall_text.splitlines():
        if re.search(r'(?i)(hooked|not in|outside|unknown module|suspicious)', line):
            m = re.search(r'(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(\S+)', line)
            if m:
                findings.append({
                    "Syscall": m.group(1), "Name": m.group(2),
                    "Address": m.group(3), "HookOwner": m.group(4),
                    "Notes": "Syscall entry points outside expected kernel module."
                })
            else:
                findings.append({"Details": line.strip(), "Notes": "Potential syscall hook."})
    return findings


def eng_linux_unsigned_module(check_modules_text: str) -> List[Dict[str, Any]]:
    """Detect suspicious/unsigned Linux kernel modules."""
    findings = []
    if not check_modules_text.strip():
        return findings
    for line in check_modules_text.splitlines():
        if re.search(r'(?i)(unknown|unsigned|suspicious|not found|hidden|tainted)', line):
            m = re.search(r'(\S+\.ko|\bmod\s+\S+)', line, re.I)
            findings.append({
                "module": m.group(1) if m else "unknown",
                "Details": line.strip(),
                "reason": "Module flagged as unsigned, unknown, or hidden."
            })
    return findings


def eng_lsof_suspicious_open(lsof_text: str, any_path_contains: List[str], any_name_contains: List[str]) -> List[Dict[str, Any]]:
    """Detect suspicious open file handles (deleted files, temp paths)."""
    findings = []
    if not lsof_text.strip():
        return findings
    rx_path = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    rx_name = compile_any_contains_to_regex(any_name_contains) if any_name_contains else None
    for line in lsof_text.splitlines():
        low = line.lower()
        hit = (rx_path and rx_path.search(low)) or (rx_name and rx_name.search(low))
        if hit:
            parts = re.split(r'\s+', line.strip())
            findings.append({
                "pid": parts[1] if len(parts) > 1 else "",
                "comm": parts[0] if parts else "",
                "fd": parts[3] if len(parts) > 3 else "",
                "type": parts[4] if len(parts) > 4 else "",
                "path": parts[-1] if parts else "",
                "cmdline": line.strip()
            })
    return findings[:25]


def eng_windows_ssdt_hooks(text, allowed_modules_regex: str):
    findings = []
    if not text.strip(): return findings
    rx_allowed = re.compile(allowed_modules_regex, re.I)
    for line in text.splitlines():
        if "Hooked" in line and not rx_allowed.search(line):
            m = re.search(r"Owner:\s*([^\s]+)", line)
            owner = m.group(1) if m else "unknown"
            findings.append({"Details": line.strip(), "OwnerModule": owner, "Notes": "SSDT Hook detected outside of allowed kernel modules."})
    return findings

def eng_windows_callbacks_suspicious(text, known_good_modules_regex: str):
    findings = []
    if not text.strip(): return findings
    rx_known_good = re.compile(known_good_modules_regex, re.I)
    for line in text.splitlines():
        if "Callback" in line and not rx_known_good.search(line):
            m = re.search(r"Owner:\s*([^\s]+)", line)
            owner = m.group(1) if m else "unknown"
            findings.append({"Details": line.strip(), "OwnerModule": owner, "Notes": "Unexpected callback owner detected."})
    return findings

def eng_iat_redirection(text: str) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip():
        return findings
    for line in text.splitlines():
        if "Non-Module" in line or "Private" in line or "Heap" in line:
            m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?Function:\s*([^\s]+).*?Resolved To:\s*(.*)', line, re.I)
            if m:
                pid, proc, func, resolved = m.groups()
                findings.append({
                    "pid": pid, "process": proc, "Function": func,
                    "ResolvedTo": resolved, "Notes": "IAT entry points to non-module memory."
                })
    return findings

def eng_vad_private_rx(text: str, require_executable: bool) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip():
        return findings
    for line in text.splitlines():
        if "RWX" in line or "RX" in line or "EXECUTE" in line:
            if require_executable:
                if "Private" in line or "Image" not in line:
                    m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?Start:\s*([^\s]+).*?Protection:\s*([^\s]+).*?Tag:\s*([^\s]+)', line, re.I)
                    if m:
                        pid, proc, start, prot, tag = m.groups()
                        findings.append({
                            "pid": pid, "process": proc, "Start": start, "Protection": prot, "Tag": tag, "Notes": "VAD region with executable permissions detected."
                        })
    return findings

def eng_threads_start_outside_module(text: str) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Start address outside module" in line:
            m = re.search(r'PID:\s*(\d+)\s+Process:\s*([^\s]+).*?TID:\s*(\d+).*?Start:\s*([^\s]+).*?Module:\s*([^\r\n]+)', line, re.I)
            if m:
                pid, proc, tid, start_addr, module = m.groups()
                findings.append({
                    "pid": pid, "process": proc, "ThreadId": tid,
                    "StartAddress": start_addr, "ModuleAtStart": module.strip(), "Notes": "Thread starts in unmapped memory or outside a known module."
                })
    return findings

def eng_netscan_beacon_like(rows: List[Dict[str, str]], suspicious_process_regex: str) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not suspicious_process_regex: return findings
    rx_proc = re.compile(suspicious_process_regex, re.I)
    for r in rows:
        owner = r.get("Owner", "") or r.get("Process", "")
        faddr = r.get("ForeignAddr", "")
        fport = r.get("ForeignPort", "")
        state = r.get("State", "")
        if rx_proc.search(owner) and faddr not in ["127.0.0.1", "0.0.0.0"] and state == "ESTABLISHED":
            findings.append({
                "pid": r.get("PID", ""), "owner": owner, "LocalAddr": r.get("LocalAddr", ""),
                "LocalPort": r.get("LocalPort", ""), "ForeignAddr": faddr, "ForeignPort": fport,
                "State": state, "Notes": "Beacon-like connection from a suspicious process."
            })
    return findings

def eng_verinfo_mismatch(rows: List[Dict[str, str]], system_dir_regex: str) -> List[Dict[str, Any]]:
    findings = []
    if not rows or not system_dir_regex: return findings
    rx_sysdir = re.compile(system_dir_regex, re.I)
    for r in rows:
        path = r.get("Path", "")
        name = r.get("FileDescription", "") or r.get("ProductName", "")
        if rx_sysdir.search(path) and not name:
            findings.append({
                "pid": r.get("PID", ""), "process": r.get("ImageFileName", ""),
                "Path": path, "Notes": "System file with missing version info."
            })
        if name and not re.search(re.escape(name), path, re.I):
            findings.append({
                "pid": r.get("PID", ""), "process": r.get("ImageFileName", ""),
                "Path": path, "CompanyName": r.get("CompanyName", ""),
                "ProductName": r.get("ProductName", ""), "FileDescription": r.get("FileDescription", ""),
                "Notes": "Version info and file path mismatch."
            })
    return findings

def eng_strings_ioc_match(text: str, patterns: List[str]) -> List[Dict[str, Any]]:
    findings = []
    if not text.strip() or not patterns: return findings
    
    current_pid = None
    current_process = None
    
    for line in text.splitlines():
        pid_match = re.match(r'^-+ PID: (\d+), Process: (.+)$', line)
        if pid_match:
            current_pid = pid_match.group(1)
            current_process = pid_match.group(2)
            continue
        
        for pattern in patterns:
            if re.search(pattern, line):
                findings.append({
                    "pid": current_pid, "process": current_process,
                    "Offset": "unknown", "String": line.strip()
                })
                break
    return findings

def eng_modules_vs_modscan_diff(modules_text: str, modscan_text: str):
    findings = []
    if not modules_text.strip() or not modscan_text.strip(): return findings
    modules_info = {}
    for line in modules_text.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 2:
            modules_info[parts[1].lower()] = {"Base": parts[0]}

    modscan_info = {}
    for line in modscan_text.splitlines():
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 2:
            modscan_info[parts[1].lower()] = {"Base": parts[0]}

    hidden = modscan_info.keys() - modules_info.keys()

    for h in hidden:
        findings.append({
            "Module": h, "Base": modscan_info[h]["Base"], "Notes": "Hidden kernel module detected by modscan."
        })
    return findings

def eng_registry_getcellroutine_hook(text: str):
    findings = []
    if not text.strip(): return findings
    for line in text.splitlines():
        if "Hooked" in line:
            m = re.search(r"Owner:\s*([^\s]+)", line)
            hook_target = m.group(1).strip() if m else "unknown"
            m = re.search(r'Hive:\s*([^\s]+)', line)
            hive = m.group(1).strip() if m else "unknown"
            findings.append({
                "Hive": hive, "Status": "Hooked", "HookTarget": hook_target, "Notes": "Registry hive's GetCellRoutine is hooked."
            })
    return findings

def eng_registry_orphan_hives(hivelist_text: str, hivescan_text: str):
    findings = []
    if not hivelist_text.strip() or not hivescan_text.strip(): return findings
    hivelist = {re.split(r'\s+', l.strip())[-1].lower() for l in hivelist_text.splitlines() if l.strip()}
    hivescan = {re.split(r'\s+', l.strip())[-1].lower() for l in hivescan_text.splitlines() if l.strip()}
    orphans = hivescan - hivelist
    for o in orphans:
        findings.append({"HivePath": o, "PresentInList": "False", "Notes": "Orphaned registry hive detected."})
    return findings

def eng_statistics_baseline_anomaly(text: str, baseline: Dict[str, Any]):
    findings = []
    if not text.strip(): return findings
    stats = kv_parse(text)
    expected_ranges = baseline.get("statistics_ranges", {})
    for metric, value in stats.items():
        if metric in expected_ranges:
            try:
                val = int(value)
                min_val, max_val = expected_ranges[metric]['min'], expected_ranges[metric]['max']
                if not (min_val <= val <= max_val):
                    findings.append({
                        "Metric": metric, "Value": value,
                        "ExpectedRange": f"{min_val}-{max_val}",
                        "Notes": "Metric value outside of expected baseline range."
                    })
            except (ValueError, TypeError):
                continue
    return findings


# ---------------------------------------------------------------------------
# New detection engines — modern attack technique coverage
# ---------------------------------------------------------------------------

# ── 1. AMSI / Windows Defender bypass ──────────────────────────────────────
_AMSI_BYPASS_RX = re.compile(
    r"(?i)("
    r"amsiScanBuffer|amsiContext|amsiInitFailed|AmsiUtils"
    r"|amsiBypass|amsi\.dll"
    r"|\[Runtime\.InteropServices\.Marshal\]::WriteByte"
    r"|\[Ref\]\.Assembly\.GetType[^;]*AMSI"
    r"|Set-MpPreference\s+-Disable(Realtime|Behavior|IOAVProtection|ScriptScanning)"
    r"|Add-MpPreference\s+-ExclusionPath"
    r"|DisableAntiSpyware.*1"
    r")",
    re.I,
)

def eng_amsi_bypass(cmdline_rows: List[Dict], malfind_text: str) -> List[Dict]:
    """
    Detect AMSI bypass attempts via:
    - Cmdline: reflection-based patches, Defender disablement, amsiInitFailed pattern
    - Malfind: AMSI-related strings in injected executable memory
    Each evidence item includes a pid field for correlation chain compatibility.
    """
    findings = []
    for r in cmdline_rows:
        cl = r.get("Args", "") or r.get("CommandLine", "") or ""
        if _AMSI_BYPASS_RX.search(cl):
            m = _AMSI_BYPASS_RX.search(cl)
            findings.append({
                "pid":          r.get("PID", ""),
                "name":         r.get("Process", "") or r.get("ImageFileName", ""),
                "command_line": cl[:300],
                "pattern":      m.group(1) if m else "matched",
                "Notes":        "AMSI bypass pattern detected in command line.",
            })
    # Also scan malfind output for AMSI strings in injected regions
    if malfind_text:
        current_pid, current_proc = "", ""
        for line in malfind_text.splitlines():
            pid_m = re.search(r"Process:\s*(\S+)\s+Pid:\s*(\d+)", line, re.I)
            if pid_m:
                current_proc, current_pid = pid_m.group(1), pid_m.group(2)
            if _AMSI_BYPASS_RX.search(line):
                findings.append({
                    "pid":   current_pid,
                    "name":  current_proc,
                    "Notes": f"AMSI bypass string in injected memory: {line.strip()[:120]}",
                })
    return findings


# ── 2. ETW / audit log disablement ─────────────────────────────────────────
_ETW_PATCH_RX = re.compile(
    r"(?i)("
    r"EtwEventWrite|NtTraceControl|EtwpCreateEtwThread"
    r"|EventProvider"
    r"|wevtutil\s+(cl|clear-log|sl\b[^;]*\/e:false)"
    r"|auditpol\s+/set.*no auditing"
    r"|Set-ItemProperty[^;]*DisableRealtimeMonitoring"
    r"|DisableEventLog"
    r"|Stop-Service.*EventLog"
    r")",
    re.I,
)

def eng_etw_patching(cmdline_rows: List[Dict]) -> List[Dict]:
    """
    Detect ETW/event-log patching via cmdline:
    - wevtutil clear-log / disable
    - auditpol / disable auditing
    - EtwEventWrite / NtTraceControl patching strings (appear in encoded payloads)
    """
    findings = []
    for r in cmdline_rows:
        cl = r.get("Args", "") or r.get("CommandLine", "") or ""
        m = _ETW_PATCH_RX.search(cl)
        if m:
            findings.append({
                "pid":          r.get("PID", ""),
                "name":         r.get("Process", "") or r.get("ImageFileName", ""),
                "command_line": cl[:300],
                "pattern":      m.group(1),
                "Notes":        "ETW/audit-log patching or disablement pattern detected.",
            })
    return findings


# ── 3. Token impersonation / privilege theft ────────────────────────────────
_TOKEN_HANDLE_RX = re.compile(
    r"(?i)\bToken\b",
)
# Impersonate (0x4), Duplicate (0x2), AssignPrimary (0x1) — any combo above 0x3
_TOKEN_SUSPICIOUS_ACCESS = re.compile(
    r"(?i)0x[0-9a-f]*[3-9a-f][0-9a-f]{2,}|0x[0-9a-f]{5,}",
)
# Processes that are expected to hold token handles legitimately
_TOKEN_WHITELIST_RX = re.compile(
    r"(?i)^(lsass|services|winlogon|wininit|csrss|svchost|spoolsv|"
    r"System|smss|taskmgr|explorer|VaultSvc)\\.exe$"
)

def eng_token_impersonation(handles_text: str) -> List[Dict]:
    """
    Detect token handle access with impersonation/duplication rights.
    Parses windows.handles text output; flags non-system processes holding
    Token handles with elevated access masks (>= TOKEN_DUPLICATE | TOKEN_IMPERSONATE).
    """
    findings = []
    if not handles_text.strip():
        return findings

    current_pid, current_proc = "", ""
    for line in handles_text.splitlines():
        # Try to detect PID/Process header lines from volatility3 handles output
        pid_m = re.search(r"^\s*(\d+)\s+(\S+\.exe)\b", line, re.I)
        if pid_m:
            current_pid, current_proc = pid_m.group(1), pid_m.group(2)
            continue

        # Format: Offset  PID  Process  HandleValue  Type  GrantedAccess  Name
        parts = line.split()
        if len(parts) < 6:
            continue
        # Detect "Token" in type column (column index 4 in typical Volatility3 output)
        type_idx = next((i for i, p in enumerate(parts) if p.lower() == "token"), None)
        if type_idx is None:
            continue

        # Extract PID from the line itself if available
        for i, p in enumerate(parts):
            if p.isdigit() and i < 4:
                current_pid = p
                break

        # Extract access mask (comes after "Token")
        if type_idx + 1 < len(parts):
            access_str = parts[type_idx + 1]
        else:
            continue

        # Skip whitelisted processes
        if _TOKEN_WHITELIST_RX.search(current_proc):
            continue

        # Flag if access mask has impersonation or duplication rights
        try:
            access_int = int(access_str, 16)
            # TOKEN_DUPLICATE=0x2 or TOKEN_IMPERSONATE=0x4 or TOKEN_ASSIGN_PRIMARY=0x1
            if access_int & 0x7:   # any of the three low bits
                findings.append({
                    "pid":          current_pid,
                    "name":         current_proc,
                    "access_mask":  access_str,
                    "Notes":        f"Token handle with impersonation/duplication rights (access={access_str}). "
                                    f"Non-system process may be performing privilege theft.",
                })
        except ValueError:
            continue

    # Deduplicate by pid+access
    seen = set()
    unique = []
    for f in findings:
        key = (f["pid"], f["access_mask"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ── 4. Lateral movement network ports ──────────────────────────────────────
_LATERAL_PORTS = {
    "445":  "SMB — file share / Pass-the-Hash",
    "5985": "WinRM HTTP — remote management",
    "5986": "WinRM HTTPS — remote management",
    "135":  "RPC / DCOM — WMI remote execution",
    "4899": "RAdmin — remote admin tool",
    "3389": "RDP — unexpected outbound",
}
_LATERAL_PROC_WHITELIST = re.compile(
    r"(?i)^(System|smss|wininit|services|svchost|lsass|csrss|winlogon|"
    r"mstsc|MSDTC|DfsC|iexplore|firefox|chrome|edge)\\.exe$"
)

def eng_lateral_movement_ports(netscan_rows: List[Dict]) -> List[Dict]:
    """
    Detect lateral movement by flagging outbound connections to well-known
    lateral movement ports (SMB/445, WinRM/5985-5986, RPC/135) from
    unexpected (non-system) processes.
    """
    findings = []
    for r in netscan_rows:
        state  = r.get("State", "").upper()
        fport  = str(r.get("ForeignPort", "") or r.get("ForeignPortNumber", ""))
        faddr  = r.get("ForeignAddr", "") or r.get("ForeignIP", "")
        proc   = r.get("Owner", "") or r.get("Process", "") or r.get("ImageFileName", "")
        pid    = str(r.get("PID", "") or r.get("Pid", ""))

        if not fport or not faddr or faddr in ("0.0.0.0", "::", "*", "127.0.0.1"):
            continue
        if fport not in _LATERAL_PORTS:
            continue
        if _LATERAL_PROC_WHITELIST.search(proc):
            continue

        findings.append({
            "pid":         pid,
            "name":        proc,
            "ForeignAddr": faddr,
            "ForeignPort": fport,
            "State":       state,
            "Notes":       f"Outbound lateral movement port {fport} ({_LATERAL_PORTS[fport]}) "
                           f"from non-standard process '{proc}'.",
        })
    return findings


# ── 5. WMI suspicious process spawn ────────────────────────────────────────
_WMI_PARENTS = re.compile(
    r"(?i)^(WmiPrvSE|wmiprvse|wmic|mmc)\\.exe$"
)
_WMI_SUSPICIOUS_CHILDREN = re.compile(
    r"(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|"
    r"msiexec|cmstp|odbcconf|regasm|regsvcs|installutil|sdbinst)\\.exe$"
)

def eng_wmi_suspicious_spawn(pslist_rows: List[Dict]) -> List[Dict]:
    """
    Detect WMI or MMC spawning command shells and script interpreters.
    This is a common technique for remote execution (T1047) and LOLBin abuse (T1218).
    Builds a PID→process map from pslist, then finds parent-child matches.
    """
    findings = []
    if not pslist_rows:
        return findings

    pid_map = {}   # pid -> {"name": ..., "ppid": ...}
    for r in pslist_rows:
        pid  = str(r.get("PID", "") or r.get("Pid", ""))
        ppid = str(r.get("PPID", "") or r.get("ParentPid", "") or "")
        name = r.get("ImageFileName", "") or r.get("Name", "")
        if pid:
            pid_map[pid] = {"name": name, "ppid": ppid}

    for pid, info in pid_map.items():
        child_name = info["name"]
        if not _WMI_SUSPICIOUS_CHILDREN.search(child_name):
            continue
        parent_info = pid_map.get(info["ppid"], {})
        parent_name = parent_info.get("name", "")
        if _WMI_PARENTS.search(parent_name):
            findings.append({
                "pid":         pid,
                "name":        child_name,
                "parent_pid":  info["ppid"],
                "parent_name": parent_name,
                "Notes":       f"'{parent_name}' (WMI/MMC) spawned '{child_name}' — "
                               f"common indicator of remote code execution via WMI (T1047).",
            })
    return findings


# ── 6. Enhanced LOLBin detection ────────────────────────────────────────────
_LOLBIN_PATTERNS: List[tuple] = [
    # (regex_pattern, short_name, mitre_note)
    (re.compile(r"(?i)certutil\s+(-urlcache|-decode|-f)\s", re.I),      "certutil_download_decode",  "certutil used as download cradle or base64 decoder (T1105/T1140)"),
    (re.compile(r"(?i)mshta\s+https?://",                   re.I),      "mshta_remote_url",          "mshta executing remote HTA (T1218.005)"),
    (re.compile(r"(?i)rundll32\s+.*javascript:",            re.I),      "rundll32_javascript",        "rundll32 running JScript — DotNetToJScript / Squiblydoo variant (T1218.011)"),
    (re.compile(r"(?i)wmic\s+.*/node:",                     re.I),      "wmic_remote_node",           "wmic /node: — remote WMI execution (T1047)"),
    (re.compile(r"(?i)msiexec\s+.*(https?://|/i\s+http)",  re.I),      "msiexec_remote_install",     "msiexec installing remote MSI (T1218.007)"),
    (re.compile(r"(?i)regsvr32\s+.*(/s|/u|/i:)\s*https?:", re.I),      "regsvr32_remote_scriptlet",  "regsvr32 Squiblydoo — remote scriptlet execution (T1218.010)"),
    (re.compile(r"(?i)cmstp\s+.*/s\s+.*(inf|dll)",         re.I),      "cmstp_uac_bypass",           "cmstp UAC bypass / DLL loading (T1218.003)"),
    (re.compile(r"(?i)odbcconf\s+.*REGSVR",                 re.I),      "odbcconf_regsvr",            "odbcconf proxy DLL execution (T1218.008)"),
    (re.compile(r"(?i)(installutil|regasm|regsvcs)\s+.*(https?://|\.dll\b)", re.I), "dotnet_proxy_exec", ".NET proxy execution via installutil/regasm/regsvcs (T1218)"),
]

def eng_lolbin_enhanced(cmdline_rows: List[Dict]) -> List[Dict]:
    """
    Targeted LOLBin detection going beyond keyword matching.
    Focuses on specific attack patterns (download cradles, remote execution,
    UAC bypasses) that are distinct from generic suspicious cmdline patterns.
    Does NOT re-flag items already caught by eng_suspicious_cmdline.
    """
    findings = []
    for r in cmdline_rows:
        cl = r.get("Args", "") or r.get("CommandLine", "") or ""
        if not cl:
            continue
        for rx, lolbin_id, note in _LOLBIN_PATTERNS:
            if rx.search(cl):
                findings.append({
                    "pid":          r.get("PID", ""),
                    "name":         r.get("Process", "") or r.get("ImageFileName", ""),
                    "command_line": cl[:300],
                    "lolbin":       lolbin_id,
                    "Notes":        note,
                })
                break   # one match per process line is enough
    return findings


# ── 7. Archive file staging (pre-exfiltration) ─────────────────────────────
_ARCHIVE_EXT_RX = re.compile(
    r"(?i)\.(zip|rar|7z|tar|tar\.gz|tgz|gz|bz2|cab|iso|arj)\b"
)
_ARCHIVE_SUSPICIOUS_PATH_RX = re.compile(
    r"(?i)("
    r"\\\\temp\\\\|\\\\appdata\\\\|\\\\users\\\\[^\\\\]+\\\\(desktop|downloads|documents)\\\\"
    r"|\\\\programdata\\\\|\\\\public\\\\"
    r"|/tmp/|/home/[^/]+/|/var/tmp/"
    r")"
)

def eng_archive_staging(filescan_text: str) -> List[Dict]:
    """
    Detect archive files (zip/rar/7z/tar) in user-writable or suspicious paths.
    These may indicate pre-exfiltration staging (T1560.001) or tool delivery (T1074).
    """
    findings = []
    if not filescan_text.strip():
        return findings
    for line in filescan_text.splitlines():
        if not _ARCHIVE_EXT_RX.search(line):
            continue
        if not _ARCHIVE_SUSPICIOUS_PATH_RX.search(line):
            continue
        m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(.+)$", line.strip())
        offset = m.group(1) if m else ""
        path   = m.group(2).strip() if m else line.strip()
        findings.append({
            "Offset": offset,
            "Path":   path,
            "Notes":  "Archive file in suspicious/user-writable path — possible staging for exfiltration.",
        })
    return findings


# ── 8. High-volume outbound connections (data exfiltration indicator) ───────
_EXFIL_PROC_WHITELIST = re.compile(
    r"(?i)^(svchost|System|MsMpEng|SearchProtocol|WmiPrvSE|WindowsAzure|"
    r"iexplore|firefox|chrome|edge|msedge|opera)\\.exe$"
)
_EXFIL_MIN_CONNECTIONS = 5   # alert when a single process has ≥ this many ESTABLISHED outbound

def eng_exfil_connections(netscan_rows: List[Dict]) -> List[Dict]:
    """
    Flag processes with an unusual number of ESTABLISHED outbound connections.
    A single process with ≥5 simultaneous established outbound connections to
    external IPs is abnormal for most processes except web browsers and cloud agents.
    """
    from collections import Counter
    outbound: Dict[str, Dict] = {}   # pid -> {name, ips: set, count: int}

    for r in netscan_rows:
        state  = r.get("State", "").upper()
        if "ESTABLISHED" not in state and "CLOSE_WAIT" not in state:
            continue
        faddr  = r.get("ForeignAddr", "") or r.get("ForeignIP", "")
        if not faddr or faddr in ("0.0.0.0", "::", "*", "127.0.0.1", "::1"):
            continue
        # Skip RFC1918 / private addresses (internal lateral movement handled separately)
        try:
            if ipaddress.ip_address(faddr).is_private:
                continue
        except ValueError:
            pass

        proc = r.get("Owner", "") or r.get("Process", "") or r.get("ImageFileName", "")
        pid  = str(r.get("PID", "") or r.get("Pid", ""))
        if _EXFIL_PROC_WHITELIST.search(proc):
            continue

        key = f"{pid}:{proc}"
        if key not in outbound:
            outbound[key] = {"pid": pid, "name": proc, "ips": set(), "count": 0}
        outbound[key]["ips"].add(faddr)
        outbound[key]["count"] += 1

    findings = []
    for key, info in outbound.items():
        if info["count"] >= _EXFIL_MIN_CONNECTIONS:
            findings.append({
                "pid":          info["pid"],
                "name":         info["name"],
                "connection_count": info["count"],
                "unique_ips":   len(info["ips"]),
                "sample_ips":   ", ".join(sorted(info["ips"])[:5]),
                "Notes":        f"Process '{info['name']}' has {info['count']} simultaneous established "
                                f"outbound connections to {len(info['ips'])} unique external IPs — "
                                f"possible data exfiltration (T1041).",
            })
    return findings


# ---------------------------
# HTML report
# ---------------------------

def html_escape(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def render_html_evidence(finding_id: str, evidence: List[Dict[str, Any]]) -> str:
    if not evidence: return "No key evidence."
    if finding_id == "suspicious_cmdline_args":
        display_items = [f"PID **{html_escape(r['pid'])}**: `{html_escape(r['command_line'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "registry_run_key_persistence":
        display_items = []
        for r in evidence[:3]:
            key_name = r.get("Key", "N/A").split("\\")[-1]
            entry_name = r.get("Name", "N/A")
            decoded_val = r.get("Decoded", "N/A")
            display_items.append(f"Key: **{html_escape(key_name)}** - Entry: `{html_escape(entry_name)}` - Value: `{html_escape(decoded_val)}`")
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious Run Key entries:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "unknown_process_name":
        display_items = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])}" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "unusual_parent_child":
        display_items = [f"Child: `{html_escape(r['child_name'])}` (PID: {html_escape(r['child_pid'])}) spawned by Parent: `{html_escape(r['parent_name'])}` (PPID: {html_escape(r['parent_pid'])})" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Unusual parent-child process chains:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "services_suspicious":
        display_items = [f"Service: `{html_escape(r['ServiceName'])}` (Type: {html_escape(r.get('ServiceType', 'N/A'))}) running from `{html_escape(r['ImagePath'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious services detected:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "scheduled_tasks_suspicious":
        display_items = [f"Task: `{html_escape(r['TaskLine'])}`" for r in evidence[:3]]
        if len(evidence) > 3: display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious scheduled tasks:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id == "psxview_hidden":
        critical_processes = ["lsass.exe", "services.exe", "winlogon.exe"]
        critical_evidence = [r for r in evidence if r.get('name') in critical_processes]
        lines = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])} (pslist: {html_escape(r.get('pslist_present',''))}, psscan: {html_escape(r.get('psscan_present',''))})" for r in critical_evidence]
        if len(lines) > 0:
            summary = f"<p>Total **{len(evidence)}** hidden processes. Examples showing process list mismatches (found by DeepProbe):</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
        else:
            summary = f"<p>Total **{len(evidence)}** hidden processes identified, showing discrepancies across process lists (found by DeepProbe).</p>"
        return summary
    if finding_id == "filescan_suspicious_names":
        relevant_paths = []
        for r in evidence:
            path = r.get('Path', '').lower()
            if "demon.py.txt" in path or "dumpit.exe" in path:
                relevant_paths.append(r.get('Path'))
            elif "catroot" not in path and "system32" not in path and "program files" not in path:
                relevant_paths.append(r.get('Path'))
        unique_paths = list(set(relevant_paths))
        deleted_paths = [p for p in unique_paths if "(deleted)" in p.lower()]
        other_paths = [p for p in unique_paths if "(deleted)" not in p.lower()]
        display_lines = []
        if deleted_paths:
            display_lines.append(f"<b>Deleted files still in memory:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in deleted_paths[:2]])
        if other_paths and len(display_lines) < 3:
            display_lines.append(f"<b>Other suspicious paths:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in other_paths[:(3 - len(display_lines))]])
        if len(unique_paths) > 3:
            display_lines.append(f"...and {len(unique_paths)-len(display_lines) + (2 if deleted_paths else 0)} more.")
        if not display_lines: return f"<p>Suspicious files found: See full details in raw artifacts.</p>"
        return f"<p>Suspicious files found:</p><ul>{''.join(f'<li>{item}</li>' for item in display_lines)}</ul>"
    if finding_id == "registry_recentdocs_py_exe":
        decoded_paths = []
        for r in evidence:
            if r.get('Decoded'):
                decoded_paths.append(r['Decoded'])
        lines = [f"File: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3: lines.append(f"...and {len(decoded_paths)-3} more.")
        return f"<p>Accessed files:</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
    if finding_id == "userassist_suspicious":
        # FIX: The display_items variable needs to be initialized here.
        display_items = []
        decoded_paths = []
        for r in evidence:
            clean_path = Path(r.get('Path', '')).name
            if clean_path: decoded_paths.append(clean_path)
        lines = [f"Program: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3: lines.append(f"...and {len(decoded_paths)-3} more.")
        return f"<p>GUI-launched programs:</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"
    if finding_id == "ldr_unlinked_module":
        details = evidence[0].get("Details", "")
        m = re.search(r"(\d+)\s+([^\s]+)\s+.*?(True|False)\s+(True|False)\s+(True|False)\s+(.*)", details)
        if m:
            pid, name, inload, ininit, inmem, path = m.groups()
            return f"<p>Process: **{html_escape(name)}** (PID: {html_escape(pid)})<br>Path: `{html_escape(path)}`<br>InLoad: {html_escape(inload)}, InInit: {html_escape(ininit)}, InMem: {html_escape(inmem)}</p>"
        return f"<pre style=\"white-space:pre-wrap;margin:0\">{html_escape(json.dumps(evidence[0], ensure_ascii=False, indent=2))}</pre>"
    if finding_id == "suspicious_network_enrichment":
        table_rows = ""
        network_evidence_list = evidence 
        for r in network_evidence_list:
            reputation_color = "#EF4444" if r.get('reputation') == "Malicious" else \
                               "#F59E0B" if r.get('reputation') == "Suspicious" else \
                               "#34D399" if r.get('reputation') == "Clean" else "#9CA3AF"
            table_rows += f"""
<tr>
  <td>{html_escape(r.get('pid', 'N/A'))}</td>
  <td>{html_escape(r.get('owner', 'N/A'))}</td>
  <td>{html_escape(r.get('ip', 'N/A'))}</td>
  <td>{html_escape(r.get('country', 'N/A'))}</td>
  <td>{html_escape(r.get('isp', 'N/A'))}</td>
  <td style="color: {reputation_color}; font-weight: bold;">{html_escape(r.get('reputation', 'N/A'))}</td>
</tr>"""
        return f"""
<p>Malicious IPs identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">PID</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Owner</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">IP</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Country</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">ISP</th><th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Reputation</th></tr>
  {table_rows}
</table>"""
    if finding_id == "suspicious_port_activity":
        table_rows = ""
        for r in evidence:
            local_port_display = html_escape(r['LocalPort']) if r.get('LocalPort') and str(r['LocalPort']).strip() != '0' else 'N/A'
            foreign_port_display = html_escape(r['ForeignPort']) if r.get('ForeignPort') and str(r['ForeignPort']).strip() != '0' else 'N/A'
            table_rows += f"""
<tr>
  <td>{html_escape(r['pid'])}</td>
  <td>{html_escape(r['owner'])}</td>
  <td>{html_escape(r['Proto'])}</td>
  <td>{local_port_display}</td>
  <td>{foreign_port_display}</td>
</tr>"""
        return f"""
<p>Connections on suspicious ports identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>PID</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Owner</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Proto</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Local Port</th><th style='padding:4px 6px; border-bottom: 1px solid #1f2937;'>Foreign Port</th></tr>
  {table_rows}
</table>"""
    if finding_id == "bash_history_suspicious":
        display_items = [f"User: **{html_escape(r['User'])}** - Command: `{html_escape(r['Command'])}`" for r in evidence[:5]]
        if len(evidence) > 5: display_items.append(f"...and {len(evidence)-5} more.")
        return f"<p>Suspicious commands found in Bash history:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"
    if finding_id.startswith("correlation"):
        # evidence is unused for correlation findings — caller should pass correlated_chains instead
        # but render_html_evidence is called with fnd.get("evidence", []) generically;
        # gracefully handle the empty case.
        if not evidence:
            return "<p>See correlated chain details in the attack graph.</p>"
        chain0 = evidence[0] if isinstance(evidence[0], dict) else {}
        correlated_pid  = html_escape(str(chain0.get("correlated_pid", "N/A")))
        correlated_info = chain0.get("correlated_findings", [])
        details_html = ""
        for info in correlated_info:
            details_html += (
                f"<li><b>{html_escape(str(info.get('title', '')))}</b>: "
                f"{html_escape(json.dumps(info.get('evidence', [])[:2], ensure_ascii=False))}</li>"
            )
        return f"<p>Correlated PID: <b>{correlated_pid}</b></p><ul>{details_html}</ul>"
    if finding_id == "dumpit_present":
        paths = [r.get('Path', 'N/A') for r in evidence]
        unique_paths = list(set(paths))
        if unique_paths:
            return f"<p>Acquisition tool(s) found: <ul>{''.join([f'<li>`{html_escape(p)}`</li>' for p in unique_paths[:3]])}</ul></p>"
        else:
            return f"<p>Memory acquisition tool present in memory. See raw artifacts for details.</p>"
    if finding_id == "kernel_callbacks_suspicious":
        return f"<p>Found **{len(evidence)}** suspicious kernel callbacks. See raw artifacts for details.</p>"
    if finding_id == "modules_hidden_vs_modscan":
        return f"<p>Found **{len(evidence)}** hidden kernel modules. See raw artifacts for details.</p>"
    if finding_id == "registry_orphan_hives":
        return f"<p>Found **{len(evidence)}** orphaned registry hives. See raw artifacts for details.</p>"

    # ── New modern detection evidence renderers ─────────────────────────────
    if finding_id == "amsi_bypass":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> <code>{html_escape(r.get('name','?'))}</code>: "
                 f"<code>{html_escape(r.get('command_line',r.get('Notes',''))[:120])}</code>" for r in evidence[:4]]
        return f"<p>AMSI bypass patterns detected:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "etw_patching":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> {html_escape(r.get('name','?'))}: "
                 f"<code>{html_escape(r.get('command_line','')[:120])}</code> "
                 f"[pattern: {html_escape(r.get('pattern',''))}]" for r in evidence[:3]]
        return f"<p>ETW/audit-log patching patterns:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "token_impersonation":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> {html_escape(r.get('name','?'))}: "
                 f"access={html_escape(r.get('access_mask','?'))} — {html_escape(r.get('Notes',''))}" for r in evidence[:4]]
        return f"<p>Token impersonation handles:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "lateral_movement_ports":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> {html_escape(r.get('name','?'))}: "
                 f"{html_escape(r.get('ForeignAddr',''))}:{html_escape(str(r.get('ForeignPort','')))} ({html_escape(r.get('State',''))})" for r in evidence[:4]]
        return f"<p>Lateral movement port connections:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "wmi_suspicious_spawn":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> <code>{html_escape(r.get('name','?'))}</code> "
                 f"← {html_escape(r.get('parent_name','?'))} (PID {html_escape(r.get('parent_pid','?'))})" for r in evidence[:4]]
        return f"<p>WMI spawned suspicious children:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "lolbin_enhanced":
        items = [f"<b>{html_escape(r.get('lolbin','?'))}</b> — PID {html_escape(r.get('pid','?'))} "
                 f"<code>{html_escape(r.get('command_line','')[:120])}</code>" for r in evidence[:4]]
        return f"<p>Enhanced LOLBin patterns:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"
    if finding_id == "archive_staging":
        paths = [html_escape(r.get('Path','')) for r in evidence[:5]]
        return f"<p>Archive files staged in suspicious locations:</p><ul>{''.join(f'<li><code>{p}</code></li>' for p in paths)}</ul>"
    if finding_id == "exfil_connections":
        items = [f"PID <b>{html_escape(r.get('pid','?'))}</b> {html_escape(r.get('name','?'))}: "
                 f"{html_escape(str(r.get('connection_count','?')))} connections to "
                 f"{html_escape(str(r.get('unique_ips','?')))} IPs ({html_escape(r.get('sample_ips','')[:80])})" for r in evidence[:3]]
        return f"<p>High-volume outbound connections:</p><ul>{''.join(f'<li>{i}</li>' for i in items)}</ul>"

    if len(evidence) == 1:
        return f"<pre style='white-space:pre-wrap;margin:0'>{html_escape(json.dumps(evidence[0], ensure_ascii=False, indent=2))}</pre>"
    else:
        return f"<p>Multiple evidence items. See raw artifacts for full details.</p>"


def render_html_explanation(finding_id: str, finding: Dict[str, Any], detections_config: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    original_narrative = "No specific narrative available for this finding."
    for os_profile in detections_config.get('os_profiles', {}).values():
        for rule in os_profile.get('detections', []):
            if rule.get('id') == finding_id:
                original_narrative = rule.get('narrative', original_narrative)
                break
        if original_narrative != "No specific narrative available for this finding.": break
    if finding_id == "suspicious_port_activity":
        is_local_only = True
        allow_cidrs = baseline_config.get("network", {}).get("allow_cidrs", []) or []
        for ev_item in finding.get('evidence', []):
            foreign_addr = ev_item.get('ForeignAddr', '').strip() or ev_item.get('ip', '').strip()
            if foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                is_local_only = False
                break
            if (foreign_addr in ["0.0.0.0", "127.0.0.1", "::"] or in_cidrs(foreign_addr, allow_cidrs)) and not ev_item.get('ForeignPort'):
                 is_local_only = True
            if ev_item.get('LocalPort') and ev_item.get('ForeignPort') and foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                 is_local_only = False
                 break
        if is_local_only:
            return "A process was observed communicating or listening on a port that is commonly associated with unusual internal services or local debugging activity. While unusual, this does not directly indicate external command and control (C2) communication unless coupled with further evidence of external connections."
    return original_narrative

# ---------------------------------------------------------------------------
# PDF Report Generator
# ---------------------------------------------------------------------------
def generate_pdf_report(
    out_path: Path,
    case: str,
    profile: str,
    score_sum: int,
    band: str,
    findings: List[Dict[str, Any]],
    detections_config: Dict[str, Any],
    artifacts_dir: Path,
) -> None:
    """
    Generate a professional PDF report from analysis findings using reportlab.
    Sections:
      1. Cover / Verdict
      2. Executive Summary (counts + risk score)
      3. High-Severity Findings (Critical + High)
      4. Correlated Attack Chains
      5. Timeline Events (if available)
      6. All Findings Reference Table
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether,
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.units import mm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        print("[WARN] reportlab not installed — skipping PDF report generation.")
        return

    PAGE_W, PAGE_H = A4
    MARGIN = 18 * mm

    # ── Colour palette ─────────────────────────────────────────────────────
    C_GREEN   = colors.HexColor("#2ecc71")
    C_DARK    = colors.HexColor("#0d1117")
    C_PANEL   = colors.HexColor("#161b22")
    C_BORDER  = colors.HexColor("#30363d")
    C_TEXT    = colors.HexColor("#c9d1d9")
    C_MUTED   = colors.HexColor("#8b949e")
    C_RED     = colors.HexColor("#e74c3c")
    C_ORANGE  = colors.HexColor("#e67e22")
    C_YELLOW  = colors.HexColor("#f1c40f")
    C_BLUE    = colors.HexColor("#3498db")
    C_WHITE   = colors.white

    SEVERITY_COLORS = {
        "Critical": C_RED,
        "High":     C_ORANGE,
        "Medium":   C_YELLOW,
        "Low":      C_BLUE,
    }

    # ── Styles ──────────────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def _s(name, parent="Normal", **kw):
        return ParagraphStyle(name, parent=base[parent], **kw)

    sTitle     = _s("DPTitle",   "Title",   fontSize=28, textColor=C_GREEN,
                    fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4)
    sSubtitle  = _s("DPSub",     fontSize=12, textColor=C_MUTED,
                    fontName="Helvetica", alignment=TA_CENTER, spaceAfter=2)
    sH1        = _s("DPH1",      fontSize=16, textColor=C_GREEN,
                    fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    sH2        = _s("DPH2",      fontSize=12, textColor=C_GREEN,
                    fontName="Helvetica-Bold", spaceBefore=6, spaceAfter=3)
    sBody      = _s("DPBody",    fontSize=9,  textColor=C_TEXT,
                    fontName="Helvetica", leading=13, spaceAfter=3)
    sBodySmall = _s("DPSmall",   fontSize=8,  textColor=C_MUTED,
                    fontName="Helvetica", leading=11)
    sTag       = _s("DPTag",     fontSize=7.5, textColor=C_MUTED,
                    fontName="Helvetica-Oblique")
    sVerdict   = _s("DPVerdict", fontSize=20, textColor=C_WHITE,
                    fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4)
    sVSub      = _s("DPVSub",    fontSize=10, textColor=C_WHITE,
                    fontName="Helvetica", alignment=TA_CENTER)

    def _hr():
        return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4, spaceBefore=4)

    # ── Helpers ─────────────────────────────────────────────────────────────
    # Build a flat id→rule lookup across all os_profiles.
    # Previously used detections_config.get("detections") which is the wrong key
    # (the YAML has os_profiles.{os}.detections) so _det_map was always empty.
    _det_map: dict = {}
    for os_data in detections_config.get("os_profiles", {}).values():
        for rule in os_data.get("detections", []):
            if isinstance(rule, dict) and "id" in rule:
                _det_map[rule["id"]] = rule

    # Static narratives for programmatically-generated correlation IDs not in YAML
    _CORR_NARRATIVES: dict = {
        "correlation_system_wide": (
            "High-severity indicators were detected simultaneously across multiple forensic "
            "layers (process, kernel, network, and/or system artifacts). This multi-layer "
            "co-presence is characteristic of a coordinated, active intrusion rather than "
            "isolated anomalies."
        ),
        "correlation_evasion_priv_esc": (
            "Evasion techniques (AMSI bypass, ETW patching) were detected alongside privilege "
            "escalation indicators (token impersonation, code injection). This combination "
            "suggests active defense suppression while elevating access level."
        ),
        "correlation_lolbin_chain": (
            "Living-off-the-land binaries or WMI were detected alongside network activity "
            "or persistence mechanisms, indicating abuse of built-in tools to blend with "
            "normal activity."
        ),
        "correlation_exfil_chain": (
            "Archive staging artifacts were detected alongside outbound connections, "
            "consistent with the Collection and Exfiltration phases of MITRE ATT&CK."
        ),
    }

    def _weight_to_severity(w: int) -> str:
        if w >= 10: return "Critical"
        if w >= 7:  return "High"
        if w >= 4:  return "Medium"
        return "Low"

    def _narrative(fid: str, finding: dict = None) -> str:
        # 1. YAML lookup (works for all regular detection rules)
        rule = _det_map.get(fid, {})
        if rule.get("narrative") or rule.get("description"):
            return rule.get("narrative") or rule["description"]
        # 2. Static fallback for programmatically-generated correlation IDs
        if fid in _CORR_NARRATIVES:
            return _CORR_NARRATIVES[fid]
        # 3. Generic fallback
        return fid.replace("_", " ").title()

    def _safe(v) -> str:
        if v is None: return "—"
        s = str(v).strip()
        return s if s not in ("None", "nan", "N/A", "") else "—"

    def _table_style(header_bg=C_PANEL, stripe=None):
        cmds = [
            ("BACKGROUND",    (0, 0), (-1, 0),  header_bg),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  C_GREEN),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0),  8),
            ("BOTTOMPADDING", (0, 0), (-1, 0),  5),
            ("TOPPADDING",    (0, 0), (-1, 0),  5),
            ("BACKGROUND",    (0, 1), (-1, -1), C_DARK),
            ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
            ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",      (0, 1), (-1, -1), 7.5),
            ("TOPPADDING",    (0, 1), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 1), (-1, -1), 4),
            ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_DARK, C_PANEL]),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP",      (0, 0), (-1, -1), True),
        ]
        return TableStyle(cmds)

    # ── Build story ─────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title=f"DeepProbe Report — {case}",
        author="DeepProbe Memory Forensics",
    )
    story = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    regular_findings    = [f for f in findings if not f.get("id", "").startswith("correlation_")]
    correlated_findings = [f for f in findings if     f.get("id", "").startswith("correlation_")]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in regular_findings:
        sev = _weight_to_severity(f.get("weight", 0))
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # ── 1. Cover ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20 * mm))
    story.append(Paragraph("DeepProbe", sTitle))
    story.append(Paragraph("Memory Forensics Report", sSubtitle))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(f"Case: {case}  |  Profile: {profile}  |  Generated: {now_str}", sSubtitle))
    story.append(Spacer(1, 8 * mm))
    _hr_thick = HRFlowable(width="100%", thickness=1.5, color=C_GREEN, spaceAfter=6, spaceBefore=6)
    story.append(_hr_thick)

    verdict_color = {
        "Critical": C_RED, "High": C_ORANGE, "Medium": C_YELLOW, "Low": C_BLUE,
    }.get(band, C_MUTED)
    verdict_msgs = {
        "Critical": "MALWARE: HIGHLY LIKELY — IMMEDIATE ACTION REQUIRED",
        "High":     "HIGH SUSPICION — INVESTIGATE NOW",
        "Medium":   "UNUSUAL ACTIVITY DETECTED — REVIEW REQUIRED",
        "Low":      "LOW-LEVEL ANOMALIES — INFORMATIONAL REVIEW",
        "Informational": "NO SIGNIFICANT THREATS DETECTED",
    }
    verdict_text = verdict_msgs.get(band, band.upper())

    verdict_table = Table(
        [[Paragraph(verdict_text, sVerdict)],
         [Paragraph(f"Overall Risk Score: {score_sum}", sVSub)]],
        colWidths=[PAGE_W - 2 * MARGIN],
    )
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), verdict_color),
        ("ROUNDEDCORNERS",(0, 0), (-1, -1), [5, 5, 5, 5]),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 6 * mm))
    story.append(_hr_thick)
    story.append(PageBreak())

    # ── 2. Executive Summary ─────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", sH1))
    story.append(_hr())

    col_w = (PAGE_W - 2 * MARGIN) / 5
    summary_data = [
        ["Total Findings", "Critical", "High", "Medium", "Risk Score"],
        [
            str(len(findings)),
            str(sev_counts["Critical"]),
            str(sev_counts["High"]),
            str(sev_counts["Medium"]),
            str(score_sum),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[col_w] * 5)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_PANEL),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_GREEN),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("BACKGROUND",    (0, 1), (-1, 1), C_DARK),
        ("TEXTCOLOR",     (0, 1), (-1, 1), C_WHITE),
        ("FONTNAME",      (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1, 1), 18),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        # Colour-code the count cells
        ("TEXTCOLOR",     (1, 1), (1, 1), C_RED    if sev_counts["Critical"] else C_WHITE),
        ("TEXTCOLOR",     (2, 1), (2, 1), C_ORANGE if sev_counts["High"]     else C_WHITE),
        ("TEXTCOLOR",     (3, 1), (3, 1), C_YELLOW if sev_counts["Medium"]   else C_WHITE),
        ("TEXTCOLOR",     (4, 1), (4, 1), C_GREEN),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 4 * mm))

    # Brief narrative
    story.append(Paragraph(
        f"DeepProbe analyzed memory image <b>{case}</b> (profile: {profile}) and identified "
        f"<b>{len(findings)}</b> findings ({sev_counts['Critical']} critical, "
        f"{sev_counts['High']} high, {sev_counts['Medium']} medium). "
        f"<b>{len(correlated_findings)}</b> correlated attack chain(s) were detected.",
        sBody,
    ))
    story.append(Spacer(1, 4 * mm))

    # ── 3. High-Severity Findings ─────────────────────────────────────────────
    high_sev = [f for f in regular_findings
                if _weight_to_severity(f.get("weight", 0)) in ("Critical", "High")]
    high_sev.sort(key=lambda f: f.get("weight", 0), reverse=True)

    story.append(Paragraph(f"High-Severity Findings  ({len(high_sev)})", sH1))
    story.append(_hr())

    if not high_sev:
        story.append(Paragraph("No critical or high severity findings detected.", sBody))
    else:
        for f in high_sev:
            fid  = f.get("id", "")
            sev  = _weight_to_severity(f.get("weight", 0))
            sev_c = SEVERITY_COLORS.get(sev, C_BLUE)
            mitre = ", ".join(f.get("mitre", [])) or "—"
            narr  = _narrative(fid)
            ev    = f.get("evidence", [])
            ev_preview = ""
            if ev and isinstance(ev, list) and isinstance(ev[0], dict):
                parts = []
                for k, v in list(ev[0].items())[:4]:
                    parts.append(f"{k}: {_safe(v)}")
                ev_preview = "  |  ".join(parts)

            block = [
                Table(
                    [[Paragraph(f.get("title", fid), sH2),
                      Paragraph(f"[{sev}]  Score: {f.get('weight', 0)}", sBodySmall)]],
                    colWidths=[PAGE_W - 2 * MARGIN - 40 * mm, 40 * mm],
                    style=TableStyle([
                        ("BACKGROUND",    (0, 0), (-1, -1), C_PANEL),
                        ("LINEBELOW",     (0, 0), (-1, -1), 1.5, sev_c),
                        ("TOPPADDING",    (0, 0), (-1, -1), 5),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                        ("LEFTPADDING",   (0, 0), (0, -1),  6),
                        ("RIGHTPADDING",  (-1, 0), (-1, -1), 6),
                        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                        ("TEXTCOLOR",     (1, 0), (1, 0),   sev_c),
                        ("FONTNAME",      (1, 0), (1, 0),   "Helvetica-Bold"),
                        ("ALIGN",         (1, 0), (1, 0),   "RIGHT"),
                    ]),
                ),
                Paragraph(f"<b>MITRE ATT&amp;CK:</b> {mitre}", sTag),
                Paragraph(narr, sBody),
            ]
            if ev_preview:
                block.append(Paragraph(f"<i>Sample evidence: {ev_preview}</i>", sBodySmall))
            block.append(Spacer(1, 3 * mm))
            story.append(KeepTogether(block))

    # ── 4. Correlated Attack Chains ───────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"Correlated Attack Chains  ({len(correlated_findings)})", sH1))
    story.append(_hr())

    if not correlated_findings:
        story.append(Paragraph(
            "No correlated attack chains were produced. This is expected when findings "
            "are isolated (no shared process IDs) or when the image has low activity.",
            sBody,
        ))
    else:
        for cf in sorted(correlated_findings, key=lambda f: f.get("weight", 0), reverse=True):
            fid    = cf.get("id", "")
            chains = cf.get("correlated_chains", [])
            narr   = _narrative(fid, cf)
            mitre_str = ', '.join(cf.get('mitre', [])) or '—'

            chain_block = [
                Paragraph(cf.get("title", fid), sH2),
                Paragraph(f"<b>Weight:</b> {cf.get('weight', 0)}  |  "
                          f"<b>MITRE:</b> {mitre_str}", sTag),
                Paragraph(narr, sBody),
            ]

            for item in chains:
                corr_type = item.get("correlation_type", "")
                sub_findings = item.get("correlated_findings", [])

                if corr_type == "system_wide" or fid == "correlation_system_wide":
                    # System-wide: show layers and contributing findings per layer
                    layers = item.get("layers_involved", [])
                    layers_str = ", ".join(layers) if layers else "multiple layers"
                    chain_block.append(
                        Paragraph(
                            f"  <b>Layers affected:</b> {layers_str}",
                            sBodySmall,
                        )
                    )
                    # Group sub-findings by layer
                    layer_groups: dict = {}
                    for sf in sub_findings:
                        layer = sf.get("layer", "unknown")
                        layer_groups.setdefault(layer, []).append(
                            sf.get("title") or sf.get("finding_id", "?")
                        )
                    for layer, titles in sorted(layer_groups.items()):
                        chain_block.append(
                            Paragraph(
                                f"    [{layer.upper()}]: {', '.join(titles)}",
                                sBodySmall,
                            )
                        )
                else:
                    pid = item.get("correlated_pid", "?")
                    confidence = item.get("confidence", "")
                    conf_label = (
                        f"[{confidence.upper()}]  " if confidence else ""
                    )
                    sub_titles = ", ".join(
                        sf.get("title") or sf.get("finding_id", "?")
                        for sf in sub_findings
                    ) or "—"
                    chain_block.append(
                        Paragraph(
                            f"  {conf_label}PID {pid}: {sub_titles}",
                            sBodySmall,
                        )
                    )

            chain_block.append(Spacer(1, 3 * mm))
            story.append(KeepTogether(chain_block))

    # ── 5. Timeline Events ────────────────────────────────────────────────────
    tl_rows: List[Dict] = []
    for fname in ("windows_registry_shimcache.csv", "windows_registry_amcache.csv"):
        fp = artifacts_dir / fname
        if fp.exists():
            try:
                import csv as _csv, io as _io
                with open(fp, newline="", encoding="utf-8", errors="replace") as fh:
                    reader = _csv.DictReader(fh)
                    for row in reader:
                        cols = list(row.keys())
                        ts_col   = next((c for c in cols if re.search(r"(modified|time|date|last)", c, re.I)), None)
                        path_col = next((c for c in cols if re.search(r"(path|file|application|name|ref)", c, re.I)), None)
                        if ts_col and path_col:
                            ts_v   = str(row.get(ts_col, ""))[:19].strip()
                            path_v = str(row.get(path_col, "")).strip()
                            if ts_v and ts_v not in ("N/A", "nan", "None", "") and path_v:
                                tl_rows.append({
                                    "Timestamp": ts_v,
                                    "Artifact":  "Shimcache" if "shimcache" in fname else "Amcache",
                                    "Path":      path_v,
                                })
                            if len(tl_rows) >= 60:
                                break
            except Exception:
                pass

    story.append(PageBreak())
    story.append(Paragraph(f"Execution Timeline  ({len(tl_rows)} events)", sH1))
    story.append(_hr())

    if not tl_rows:
        story.append(Paragraph(
            "No timeline artifacts found. Timeline requires Shimcache or Amcache registry "
            "hive data present in memory (Windows images only).",
            sBody,
        ))
    else:
        tl_data = [["Timestamp", "Artifact", "Path"]]
        for r in sorted(tl_rows, key=lambda x: x["Timestamp"])[:50]:
            tl_data.append([
                Paragraph(_safe(r["Timestamp"]), sBodySmall),
                Paragraph(_safe(r["Artifact"]),  sBodySmall),
                Paragraph(_safe(r["Path"]),       sBodySmall),
            ])
        tl_table = Table(tl_data, colWidths=[42 * mm, 22 * mm, PAGE_W - 2 * MARGIN - 64 * mm])
        tl_table.setStyle(_table_style())
        story.append(tl_table)

    # ── 6. All Findings Reference Table ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"All Findings Reference  ({len(findings)})", sH1))
    story.append(_hr())

    all_data = [["#", "Finding", "Severity", "Score", "MITRE ATT&CK"]]
    for i, f in enumerate(sorted(findings, key=lambda f: f.get("weight", 0), reverse=True), 1):
        fid  = f.get("id", "")
        sev  = "Chain" if fid.startswith("correlation_") else _weight_to_severity(f.get("weight", 0))
        mitre_str = ", ".join(f.get("mitre", [])) or "—"
        all_data.append([
            Paragraph(str(i), sBodySmall),
            Paragraph(f.get("title", fid), sBodySmall),
            Paragraph(sev, sBodySmall),
            Paragraph(str(f.get("weight", 0)), sBodySmall),
            Paragraph(mitre_str, sBodySmall),
        ])

    col_w_all = PAGE_W - 2 * MARGIN
    ref_table = Table(
        all_data,
        colWidths=[8 * mm, col_w_all * 0.37, 18 * mm, 12 * mm, col_w_all - 8 * mm - col_w_all * 0.37 - 18 * mm - 12 * mm],
    )
    ref_table.setStyle(_table_style())
    story.append(ref_table)

    # ── Footer / Build ────────────────────────────────────────────────────────
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_MUTED)
        canvas.drawString(MARGIN, 10 * mm,
            f"DeepProbe Memory Forensics  |  Case: {case}  |  {now_str}")
        canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    try:
        doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
        print(f"PDF report: {out_path}")
    except Exception as exc:
        print(f"[WARN] PDF generation failed: {exc}")


# ---------------------------------------------------------------------------
# System-wide cross-layer compromise detector
# ---------------------------------------------------------------------------

# Forensic layer membership — which finding IDs belong to each layer
_LAYER_PROCESS = frozenset({
    "psxview_hidden", "malfind_injection", "hollowed_process", "ldr_unlinked_module",
    "entropy_anomaly", "vad_exec_private", "iat_redirection", "threads_start_outside_module",
    "lsass_credential_dump", "handles_lsass_access", "amsi_bypass", "etw_patching",
    "token_impersonation", "exec_from_tmp", "unusual_parent_child", "unknown_process_name",
    "wmi_suspicious_spawn", "lolbin_enhanced", "suspicious_cmdline_args",
})
_LAYER_KERNEL = frozenset({
    "ssdt_hooks_suspicious", "kernel_callbacks_suspicious", "registry_getcellroutine_hooked",
    "modules_hidden_vs_modscan", "registry_orphan_hives", "verinfo_mismatch",
})
_LAYER_NETWORK = frozenset({
    "suspicious_connection", "suspicious_network_enrichment", "suspicious_port_activity",
    "suspicious_network_malicious_ip", "netscan_beacon_like", "lateral_movement_ports",
    "exfil_connections", "archive_staging",
})
_LAYER_SYSTEM = frozenset({
    # Persistence mechanisms — registry, scheduled tasks, services
    "registry_run_key_persistence", "scheduled_tasks_suspicious", "services_suspicious",
    # File-system artifacts
    "filescan_suspicious_names", "strings_sensitive_iocs", "dumpit_present",
    # Shell / user-space history
    "bash_history_suspicious", "userassist_suspicious",
    # Linux-specific persistence
    "linux_cron_persistence", "linux_ldpreload",
})

# Minimum weight to count as "high/critical" for this correlation
_SYSTEM_WIDE_MIN_WEIGHT = 7


def eng_system_wide_compromise(all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect system-wide compromise by identifying high/critical findings that
    span ≥2 distinct forensic layers (process, kernel, network) without any
    shared PID or parent-child relationship.

    This catches distributed attack patterns that no pair-based correlation rule
    can anticipate — e.g. a kernel rootkit callback installed alongside a
    network C2 channel via a completely different process.

    Returns a list containing a single chain dict (for consistency with the
    correlated_chains format), or an empty list if the threshold isn't met.
    """
    layer_hits: Dict[str, List[Dict]] = {
        "process": [], "kernel": [], "network": [], "system": []
    }

    for f in all_findings:
        fid = f.get("id", "")
        w   = f.get("weight", 0)
        # Skip correlations themselves and low-weight findings
        if fid.startswith("correlation_") or w < _SYSTEM_WIDE_MIN_WEIGHT:
            continue
        if fid in _LAYER_PROCESS:
            layer_hits["process"].append(f)
        elif fid in _LAYER_KERNEL:
            layer_hits["kernel"].append(f)
        elif fid in _LAYER_NETWORK:
            layer_hits["network"].append(f)
        elif fid in _LAYER_SYSTEM:
            layer_hits["system"].append(f)

    active_layers = {name: hits for name, hits in layer_hits.items() if hits}
    if len(active_layers) < 2:
        return []   # need ≥2 distinct layers

    # Build one chain item per contributing finding (capped at 4 per layer)
    chain: List[Dict] = []
    layer_display = {
        "process": "Process Layer",
        "kernel":  "Kernel Layer",
        "network": "Network Layer",
        "system":  "System/Persistence Layer",
    }
    for layer_name, layer_findings in active_layers.items():
        for f in sorted(layer_findings, key=lambda x: x.get("weight", 0), reverse=True)[:4]:
            chain.append({
                "finding_id": f.get("id", ""),
                "title":      f.get("title", f.get("id", "")),
                "evidence":   f.get("evidence", [])[:3],
                "layer":      layer_display[layer_name],
                "time_utc":   f.get("time_utc", "unknown"),
            })

    active_layer_names = sorted(layer_display[n] for n in active_layers)
    return [{
        "correlated_pid":      "system-wide",
        "correlated_findings": chain,
        "correlated_rule_ids": [f["finding_id"] for f in chain],
        "confidence":          "medium",
        "correlation_type":    "system_wide",
        "layers_involved":     active_layer_names,
        "note": (
            f"System-wide compromise detected across {len(active_layers)} forensic layers: "
            + ", ".join(active_layer_names)
            + ". High/critical indicators exist across separate processes with no shared PID. "
            "This pattern is characteristic of a sophisticated, multi-stage intrusion."
        ),
    }]


def render_html(case: str, profile: str, score_sum: int, band: str, findings: List[Dict[str, Any]], detections_config: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    narrative_list_html = ""
    if findings:
        for f in sorted(findings, key=lambda x: x.get('weight', 0), reverse=True):
            narrative = render_html_explanation(f.get('id', ''), f, detections_config, baseline_config)
            narrative_list_html += f"<li>**{html_escape(f.get('title', f.get('id')))}**: {html_escape(narrative)}</li>"
    if not narrative_list_html:
        narrative_list_html = "<li>No significant findings detected in this memory image.</li>"
    
    rows = []
    sorted_findings = sorted(findings, key=lambda f: f.get('weight', 0), reverse=True)
    for f in sorted_findings:
        # Correlation findings store their data in correlated_chains, not evidence
        _ev_for_html = f.get("correlated_chains", None) or f.get("evidence", [])
        evidence_html = render_html_evidence(f.get('id',''), _ev_for_html)
        explanation_html = render_html_explanation(f.get('id',''), f, detections_config, baseline_config)
        mitre_ttps_str = ", ".join(f.get('mitre', []))
        rows.append(f"""
<tr>
  <td>{html_escape(f.get('title',''))}</td>
  <td>{html_escape(mitre_ttps_str)}</td>
  <td>{f.get('weight',0)}</td>
  <td>{evidence_html}</td>
  <td>{explanation_html}</td>
</tr>""")
    table = "\n".join(rows) if rows else "<tr><td colspan=5>No findings</td></tr>"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>DeepProbe Forensics Report</title>
<style>
body{{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Arial;padding:24px;background:#0b0f14;color:#e5e7eb}}
h1,h2,h3{{margin:0 0 8px}}
small{{color:#9ca3af}}
.card{{background:#111827;padding:16px;border-radius:12px;box-shadow:0 0 0 1px #1f2937 inset;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{border-bottom:1px solid #1f2937;padding:8px 10px;text-align:left;vertical-align:top}}
th{{color:#93c5fd}}
.badge{{display:inline-block;padding:2px 8px;border-radius:9999px;background:#1f2937}}
ul{{margin:0; padding:0 0 0 20px;}}
ol{{margin:0; padding:0 0 0 20px;}}
li{{padding:2px 0;}}
</style></head>
<body>
  <h1>DeepProbe Forensics Report</h1>
  <div class="card">
    <div><b>Case:</b> {html_escape(case)} &nbsp; <b>Profile:</b> {html_escape(profile)} &nbsp; <b>Generated:</b> {html_escape(now_iso())}</div>
    <div style="margin-top:8px"><b>Total Score:</b> {score_sum} &nbsp; <span class="badge">{html_escape(band)}</span></div>
  </div>
  <div class="card">
    <h2>Key Incident Narratives 📖</h2>
    <ul style="list-style-type: disc; padding-left: 25px;">
      {narrative_list_html}
    </ul>
    <small>These narratives summarize the most significant activities detected.</small>
  </div>
  <div class="card">
    <h2>Detailed Findings</h2>
    <table>
      <tr><th>Finding Title</th><th>MITRE TTPs</th><th>Severity Score</th><th>Key Evidence</th><th>Detailed Explanation</th></tr>
      {table}
    </table>
    <small>Full raw outputs are available in the artifacts/ directory for deeper analysis.</small>
  </div>
</body></html>"""


# ---------------------------
# Main
# ---------------------------

def main():
    print("[DEBUG] Main function started.")
    ap = argparse.ArgumentParser(description="Volatility detections CLI")
    ap.add_argument("--image", required=True, help="Memory image path (e.g., memory.raw)")
    ap.add_argument("--case", default="case1")
    ap.add_argument("--detections", default="detections.yaml")
    ap.add_argument("--baseline", default="baseline.yaml")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--api-key", default="", help="API key for IP enrichment services (optional).")
    args = ap.parse_args()
    print("[DEBUG] Arguments parsed successfully.")

    outdir = Path(args.outdir)
    ensure_dirs(outdir)

    detections_config_path = Path(args.detections)
    if not detections_config_path.exists():
        print(f"Error: Detections file not found at {detections_config_path}", file=sys.stderr)
        sys.exit(1)
    print(f"[DEBUG] Loading detections from: {detections_config_path}")
    det = yaml.safe_load(detections_config_path.read_text())
    print(f"[DEBUG] Detections config loaded: {json.dumps(det, indent=2)[:500]}...")

    baseline_config_path = Path(args.baseline)
    if not baseline_config_path.exists():
        print(f"Error: Baseline file not found at {baseline_config_path}", file=sys.stderr)
        sys.exit(1)
    print(f"[DEBUG] Loading baseline from: {baseline_config_path}")
    base = yaml.safe_load(baseline_config_path.read_text())
    print(f"[DEBUG] Baseline config loaded: {json.dumps(base, indent=2)[:500]}...")

    vol = find_vol_binary(det.get("volatility", {}).get("v3_binaries", ["vol","volatility3"]))
    if not vol:
        print("Neither volatility3 nor vol found on PATH", file=sys.stderr)
        sys.exit(3)
    print(f"[DEBUG] Volatility binary found: {vol}")

    info_txt = run_plugin(vol, args.image, "windows.info", "text", outdir)
    oskey = detect_os(info_txt)
    print(f"[i] Detected OS profile: {oskey}")
    os_prof = (det.get("os_profiles", {}).get(oskey, {}))
    plugins = os_prof.get("plugins", [])
    cache_outputs: Dict[str, Any] = {}

    for p in plugins:
        name = p["name"]
        fmt  = p.get("format","text")
        fallbacks = p.get("fallback", [])
        print(f"[+] Running plugin: {name} (fmt={fmt})")
        used, content = try_plugin_with_fallbacks(vol, args.image, name, fmt, fallbacks, outdir)
        cache_outputs[used] = {"format": fmt, "content": content}
        if used != name:
            print(f"[i] Fallback used: {used}")
        if content:
            print(f"[DEBUG] Captured content for {used} (first 200 chars):\n{content[:200]}...")
        else:
            print(f"[DEBUG] Captured content for {used} is EMPTY or None.")

    def get_csv(name):
        content_info = cache_outputs.get(name, {})
        if not content_info or content_info.get("format") != "csv": return []
        return parse_csv(content_info.get("content", ""))

    def get_txt(name):
        content_info = cache_outputs.get(name, {})
        if not content_info: return ""
        return content_info.get("content", "")

    detections_cfg = os_prof.get("detections", [])
    findings = []
    score = 0

    for rule in detections_cfg:
        if not rule.get("enabled", True): continue
        rid, title, weight, mitre = rule["id"], rule.get("title", rule["id"]), int(rule.get("weight", 1)), rule.get("mitre", [])
        ev = []
        if rid.startswith("correlation_") or rule.get("engine") == "network_enrichment": continue
        print(f"[i] Running detection engine: {rid}")
        try:
            if rid == "unknown_process_name":
                ps = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                ev = eng_unknown_process_name(ps, base, oskey)
            elif rid == "psxview_hidden":
                ev = eng_psxview_hidden(get_csv("windows.psxview"))
            elif rid == "suspicious_port_activity":
                rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_suspicious_port_activity(rows, rule.get("params", {}).get("suspicious_ports", []))
            elif rid == "suspicious_connection":
                rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_suspicious_connection(rows, base)
            elif rid == "malfind_injection":
                text = get_txt("windows.malfind") if oskey == "windows" else get_txt(f"{oskey}.malfind")
                ev = eng_malfind_injection(text, rule.get("params", {}).get("keywords", []))
            elif rid == "hollowed_process":
                ev = eng_hollowed_process(get_txt("windows.hollowprocesses"), rule.get("params", {}).get("keywords", []))
            elif rid == "ldr_unlinked_module":
                ev = eng_ldr_unlinked_module(get_txt("windows.ldrmodules"), rule.get("params", {}).get("temp_like_paths", []))
            elif rid == "handles_dangerous_access":
                ev = eng_handles_general(get_txt("windows.handles"), rule.get("params", {}).get("access_regex", ""))
            elif rid == "handles_lsass_access":
                ev = eng_handles_general(get_txt("windows.handles"), rule.get("params", {}).get("access_regex", ""), rule.get("params", {}).get("target_process_regex","(?i)^lsass\\.exe$"), True)
            elif rid == "services_suspicious":
                ev = eng_services_suspicious(get_csv("windows.svcscan"), rule.get("params", {}).get("temp_like_paths", []), base)
            elif rid == "scheduled_tasks_suspicious":
                text = get_txt("windows.scheduled_tasks") or get_txt("windows.registry.scheduled_tasks")
                ev = eng_scheduled_tasks(text, rule.get("params", {}).get("temp_like_paths", []), rule.get("params", {}).get("risky_exts", []))
            elif rid == "filescan_suspicious_names" or rid == "dumpit_present":
                text = get_txt("windows.filescan") if oskey=="windows" else get_txt(f"{oskey}.pagecache.Files")
                ev = eng_filescan_path_match(text, rule.get("params", {}).get("any_path_contains", []), rule.get("params", {}).get("any_file_ext", []), rule.get("params", {}).get("any_name_contains", []), base)
            elif rid == "registry_run_key_persistence" or rid == "registry_recentdocs_py_exe":
                ev = eng_registry_printkey_matches(vol, args.image, outdir, rule.get("params", {}).get("keys", []), rule.get("params", {}).get("value_regex", ""), base)
            elif rid == "userassist_suspicious":
                ev = eng_userassist_suspicious(get_txt("windows.registry.userassist"), rule.get("params", {}).get("any_path_contains", []))
            elif rid == "unusual_parent_child":
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                ev = eng_unusual_parent_child(ps, rule.get("params", {}), base)
            elif rid == "sessions_anomalous":
                rows = get_csv("windows.sessions")
                ev = eng_sessions_anomalous(rows, base.get("sessions",{}).get("ignore_users",[]), rule.get("params", {}).get("suspicious_auth_packages", []))
            elif rid == "suspicious_cmdline_args":
                ev = eng_suspicious_cmdline(get_csv("windows.cmdline"), rule.get("params", {}).get("suspicious_keywords", []), base)
            elif rid == "bash_history_suspicious":
                text = get_txt("linux.bash") if oskey == "linux" else get_txt("mac.bash")
                ev = eng_bash_history_grep(text, rule.get("params", {}).get("suspicious_keywords", []))
            elif rid == "exec_from_tmp":
                ps = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                ev = eng_exec_from_tmp(ps, rule.get("params", {}).get("temp_like_paths", []))
            # --- Credential Dump ---
            elif rid == "lsass_credential_dump":
                ev = eng_lsass_credential_dump(
                    get_csv("windows.cmdline"),
                    get_txt("windows.malfind")
                )
            # --- Entropy Anomaly ---
            elif rid == "entropy_anomaly":
                ev = eng_entropy_anomaly(
                    get_txt("windows.vadinfo") or get_txt("windows.vadwalk"),
                    rule.get("params", {}).get("threshold", 7.0)
                )
            # --- Linux-specific engines ---
            elif rid == "linux_hidden_process":
                ev = eng_linux_hidden_process(get_csv("linux.pslist"), get_csv("linux.psscan"))
            elif rid == "linux_syscall_hooks":
                ev = eng_linux_syscall_hooks(get_txt("linux.check_syscall"))
            elif rid == "linux_unsigned_module":
                ev = eng_linux_unsigned_module(get_txt("linux.check_modules"))
            elif rid == "lsof_suspicious_open":
                ev = eng_lsof_suspicious_open(
                    get_txt("linux.lsof"),
                    rule.get("params", {}).get("any_path_contains", []),
                    rule.get("params", {}).get("any_name_contains", [])
                )
            elif rid == "linux_ldpreload":
                ev = eng_linux_ldpreload(get_txt("linux.envars"))
            elif rid == "linux_cron_persistence":
                ev = eng_linux_cron_persistence(
                    get_txt("linux.bash"),
                    get_txt("linux.lsof")
                )
            # New Engines
            elif rid == "ssdt_hooks_suspicious":
                ev = eng_windows_ssdt_hooks(get_txt("windows.ssdt"), rule.get("params", {}).get("allowed_modules_regex", ""))
            elif rid == "kernel_callbacks_suspicious":
                ev = eng_windows_callbacks_suspicious(get_txt("windows.callbacks"), rule.get("params", {}).get("known_good_modules_regex", ""))
            elif rid == "iat_redirection":
                ev = eng_iat_redirection(get_txt("windows.iat"))
            elif rid == "vad_exec_private":
                ev = eng_vad_private_rx(get_txt("windows.vadinfo") or get_txt("windows.vadwalk"), rule.get("params", {}).get("require_executable", True))
            elif rid == "threads_start_outside_module":
                ev = eng_threads_start_outside_module(get_txt("windows.suspicious_threads") or get_txt("windows.thrdscan"))
            elif rid == "netscan_beacon_like":
                ev = eng_netscan_beacon_like(get_csv("windows.netscan"), rule.get("params", {}).get("suspicious_process_regex", ""))
            elif rid == "verinfo_mismatch":
                ev = eng_verinfo_mismatch(get_csv("windows.verinfo"), rule.get("params", {}).get("system_dir_regex", ""))
            elif rid == "strings_sensitive_iocs":
                text = get_txt("windows.strings")
                ev = eng_strings_ioc_match(text, rule.get("params", {}).get("patterns", []))
            elif rid == "modules_hidden_vs_modscan":
                ev = eng_modules_vs_modscan_diff(get_txt("windows.modules"), get_txt("windows.modscan"))
            elif rid == "registry_getcellroutine_hooked":
                ev = eng_registry_getcellroutine_hook(get_txt("windows.registry.getcellroutine"))
            elif rid == "registry_orphan_hives":
                ev = eng_registry_orphan_hives(get_txt("windows.registry.hivelist"), get_txt("windows.registry.hivescan"))
            elif rid == "statistics_profile_anomaly":
                ev = eng_statistics_baseline_anomaly(get_txt("windows.statistics"), base)

            # ── NEW: modern attack technique detections ───────────────────────
            elif rid == "amsi_bypass":
                cmdline_src = get_csv("windows.cmdline")
                ev = eng_amsi_bypass(cmdline_src, get_txt("windows.malfind"))
            elif rid == "etw_patching":
                ev = eng_etw_patching(get_csv("windows.cmdline"))
            elif rid == "token_impersonation":
                ev = eng_token_impersonation(get_txt("windows.handles"))
            elif rid == "lateral_movement_ports":
                net_rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_lateral_movement_ports(net_rows)
            elif rid == "wmi_suspicious_spawn":
                ps = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                ev = eng_wmi_suspicious_spawn(ps)
            elif rid == "lolbin_enhanced":
                ev = eng_lolbin_enhanced(get_csv("windows.cmdline"))
            elif rid == "archive_staging":
                ev = eng_archive_staging(get_txt("windows.filescan") if oskey == "windows" else get_txt(f"{oskey}.pagecache.Files"))
            elif rid == "exfil_connections":
                net_rows = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
                ev = eng_exfil_connections(net_rows)

        except Exception as e:
            print(f"[warn] Engine {rid} failed: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        
        if ev:
            findings.append({"id": rid, "title": title, "mitre": mitre, "weight": weight, "evidence": ev})
            score += weight
        print(f"[i] Finished detection engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

    print(f"[i] Running master network enrichment engine...")
    network_enrichment_rules = [r for r in detections_cfg if r.get("engine") == "network_enrichment" and r.get("enabled", True)]
    netstat_rows_for_master_engine = get_csv("windows.netstat") or get_csv("windows.netscan") if oskey == "windows" else get_csv(f"{oskey}.netstat") or []
    network_findings = []
    if network_enrichment_rules and netstat_rows_for_master_engine:
        network_findings = eng_network_enrichment_master(netstat_rows_for_master_engine, network_enrichment_rules, base, args.api_key)
        for fnd in network_findings:
            findings.append(fnd)
            score += fnd["weight"]
    print(f"[i] Finished master network enrichment engine. Current total score: {score}. Total network findings generated: {len(network_findings)}")


    print(f"[i] Starting correlation analysis...")
    for rule in detections_cfg:
        if not rule.get("enabled", True): continue
        rid, title, weight, mitre = rule["id"], rule.get("title", rule["id"]), int(rule.get("weight", 1)), rule.get("mitre", [])
        ev = []
        if not rid.startswith("correlation_"): continue
        print(f"[i] Running correlation engine: {rid}")
        try:
            ev = eng_correlated_findings(findings, rule.get("params", {}).get("correlation_pairs", []))
        except Exception as e:
            print(f"[warn] Correlation engine {rid} failed: {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
        if ev:
            # Store chains in a dedicated key — never reuse the generic "evidence" field
            # for correlated findings because the data shape is completely different.
            # The UI reads finding["correlated_chains"] directly.
            findings.append({
                "id":               rid,
                "title":            title,
                "mitre":            mitre,
                "weight":           weight,
                "correlated_chains": ev,    # [{correlated_pid, correlated_findings, correlated_rule_ids}]
            })
            score += weight
        print(f"[i] Finished correlation engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

    # ── System-wide cross-layer correlation ──────────────────────────────────
    # Runs after all individual and pair-based correlations so it has the full
    # findings set to evaluate.  Only appended if ≥2 distinct layers have
    # high/critical findings that weren't already linked by a stronger chain.
    print("[i] Running system-wide cross-layer correlation...")
    sw_chains = eng_system_wide_compromise(findings)
    if sw_chains:
        sw_weight = 18
        findings.append({
            "id":               "correlation_system_wide",
            "title":            "System-Wide Compromise Detected",
            "mitre":            ["T1562", "T1055", "T1071", "T1059", "T1547"],
            "weight":           sw_weight,
            "correlated_chains": sw_chains,
        })
        score += sw_weight
        print(f"[i] System-wide correlation fired. Layers: "
              f"{sw_chains[0].get('layers_involved', [])}")
    else:
        print("[i] System-wide correlation: threshold not met.")

    bands = (base.get("report", {}).get("severity_bands") or det.get("scoring", {}).get("severity_bands") or [])
    band_label = "Unknown"
    for band in bands:
        if score <= int(band["max"]):
            band_label = band["label"]
            break

    findings_path = outdir / "findings.jsonl"
    with findings_path.open("w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd, ensure_ascii=False) + "\n")

    # Write a dedicated correlated_findings.json for easy inspection / external tooling
    correlated_only = [fnd for fnd in findings if fnd.get("id", "").startswith("correlation_")]
    correlated_json_path = outdir / "correlated_findings.json"
    with correlated_json_path.open("w", encoding="utf-8") as cf:
        json.dump(correlated_only, cf, indent=2, ensure_ascii=False)
    print(f"Correlated findings JSON: {correlated_json_path}  ({len(correlated_only)} chains)")

    print("\n=== SUMMARY ===")
    print(f"Score: {score}  => Severity: {band_label}")
    print(f"Raw artifacts: {outdir/'artifacts'}")
    print(f"Findings JSONL: {findings_path}")
    html_path = outdir / "report.html"
    write_file(html_path, render_html(args.case, oskey, score, band_label, findings, det, base))
    print(f"HTML report: {html_path}")

    pdf_path = outdir / "report.pdf"
    generate_pdf_report(
        out_path=pdf_path,
        case=args.case,
        profile=oskey,
        score_sum=score,
        band=band_label,
        findings=findings,
        detections_config=det,
        artifacts_dir=outdir / "artifacts",
    )

if __name__ == "__main__":
    main()
