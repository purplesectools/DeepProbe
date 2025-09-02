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


def get_ip_info(ip: str, api_key: str) -> Dict[str, str]:
    info = {"country": "N/A", "isp": "N/A", "reputation": "N/A"}
    if not api_key:
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            if response.status_code == 200:
                data = response.json()
                info["country"] = data.get("country", "N/A")
                info["isp"] = data.get("org", "N/A")
                info["reputation"] = "Clean (ipinfo.io fallback)"
        except Exception as e:
            print(f"[warn] ipinfo.io fallback failed for {ip}: {e}", file=sys.stderr)
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
        print(f"[info] Querying AbuseIPDB for IP: {ip}...")
        response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=5)
        response.raise_for_status()

        data = response.json().get('data', {})
        info["country"] = data.get("countryCode", "N/A")
        info["isp"] = data.get("isp", "N/A")
        abuse_score = data.get("abuseConfidenceScore", 0)
        if abuse_score > 60:
            info["reputation"] = "Malicious"
        elif abuse_score > 20:
            info["reputation"] = "Suspicious"
        else:
            info["reputation"] = "Clean"
        info["abuse_reports"] = data.get("totalReports", 0)
        info["last_reported"] = data.get("lastReportedAt", "N/A")
        print(f"[info] AbuseIPDB result for {ip}: Country={info['country']}, Reputation={info['reputation']}", file=sys.stderr)

    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] AbuseIPDB HTTP error for {ip}: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        info["reputation"] = f"API Error ({e.response.status_code})"
    except requests.exceptions.ConnectionError as e:
        print(f"[ERROR] AbuseIPDB connection error for {ip}: {e}", file=sys.stderr)
        info["reputation"] = "Network Error"
    except requests.exceptions.Timeout:
        print(f"[ERROR] AbuseIPDB API request timed out for {ip}.", file=sys.stderr)
        info["reputation"] = "Timeout"
    except Exception as e:
        print(f"[ERROR] Unexpected error during AbuseIPDB call for {ip}: {e}", file=sys.stderr)
        info["reputation"] = "Unknown Error"
    
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
    if "NtSystemRoot" in info_text or "IsPAE" in info_txt:
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

def eng_correlated_findings(all_findings: List[Dict[str, Any]], correlation_pairs: List[Dict[str, Any]]):
    findings = []
    for pair in correlation_pairs:
        primary_ids = set(pair.get("primary_ids", []))
        secondary_ids = set(pair.get("secondary_ids", []))
        primary_pids = set()
        secondary_pids = set()
        for f in all_findings:
            if f['id'] in primary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        primary_pids.add(str(pid))
        for f in all_findings:
            if f['id'] in secondary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        secondary_pids.add(str(pid))
        correlated_pids = primary_pids.intersection(secondary_pids)
        if correlated_pids:
            for pid in sorted(list(correlated_pids)):
                correlated_info = []
                for f in all_findings:
                    if f['id'] in (primary_ids | secondary_ids):
                        pid_evidence = [ev for ev in f.get('evidence', []) if (ev.get('pid') == pid or ev.get('requestor_pid') == pid)]
                        if pid_evidence:
                            correlated_info.append({
                                "finding_id": f['id'], "title": f['title'], "evidence": pid_evidence,
                                "time_utc": f.get('time_utc', 'unknown')
                            })
                findings.append({
                    "correlated_pid": pid, "correlated_findings": correlated_info,
                    "correlated_rule_ids": list(primary_ids | secondary_ids),
                })
    return findings


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
        correlated_pids = evidence[0].get("correlated_pid", "N/A")
        correlated_info = evidence[0].get("correlated_findings", [])
        details_html = ""
        for info in correlated_info:
            details_html += f"<li><b>{html_escape(info.get('title'))}:</b> {html_escape(json.dumps(info.get('evidence'), ensure_ascii=False))}</li>"
        return f"<p>Correlated PID: <b>{html_escape(correlated_pids)}</b></p><ul>{details_html}</ul>"
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
        evidence_html = render_html_evidence(f.get('id',''), f.get('evidence', []))
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
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                ev = eng_exec_from_tmp(ps, rule.get("params", {}).get("temp_like_paths", []))
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
            findings.append({"id": rid, "title": title, "mitre": mitre, "weight": weight, "evidence": ev})
            score += weight
        print(f"[i] Finished correlation engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

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

    print("\n=== SUMMARY ===")
    print(f"Score: {score}  => Severity: {band_label}")
    print(f"Raw artifacts: {outdir/'artifacts'}")
    print(f"Findings JSONL: {findings_path}")
    html_path = outdir / "report.html"
    write_file(html_path, render_html(args.case, oskey, score, band_label, findings, det, base))
    print(f"HTML report: {html_path}")

if __name__ == "__main__":
    main()
