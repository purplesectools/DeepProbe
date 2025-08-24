#!/usr/bin/env python3
"""

Tested with: Volatility 3 (2.26.x). Python 3.10+.

Usage:
  python runner.py --image memory.raw --case case1 \\
    --detections detections.yaml --baseline detections.yaml --outdir out \\
    --api-key YOUR_IP_ENRICHMENT_API_KEY \\ # For IP enrichment
    --openai-api-key YOUR_OPENAI_API_KEY   # NEW: For OpenAI integration

Notes:
- Keeps stdout very chatty so you can see exactly what runs.
- Handles Win7 limitations gracefully (skips unsupported plugins).
- Places “-r csv” BEFORE plugin name when format=csv (Vol3 quirk).
"""

import argparse, json, os, re, shutil, subprocess, sys, time, textwrap
from pathlib import Path
from datetime import datetime, UTC # Import UTC for timezone-aware datetime

from typing import Dict, List, Any, Tuple

# Import requests for API calls (already present, used for IP enrichment)
import requests
import ipaddress # Import ipaddress for robust IP validation

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
            stderr=subprocess.STDOUT if capture is None else None,
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
    (outdir / "artifacts").mkdir(parents=True, exist_ok=True)
    (outdir / "logs").mkdir(exist_ok=True)


def write_file(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8", errors="ignore")


def now_iso() -> str:
    # Use timezone-aware objects to represent datetimes in UTC.
    return datetime.now(UTC).isoformat() + "Z"


def compile_any_contains_to_regex(parts: List[str]) -> re.Pattern:
    # Accepts glob-like strings; compile into a single big OR regex
    escaped = []
    for p in parts:
        escaped.append(re.escape(p)) # Escape special characters in glob-like strings
    regex = "(" + "|".join(escaped) + ")"
    return re.compile(regex, re.IGNORECASE)


def in_cidrs(ip: str, cidrs: List[str]) -> bool:
    # light checker for RFC1918 vs public; for full CIDR math use ipaddress
    try:
        # Ensure ipaddress is imported at the top of the file
        addr = ipaddress.ip_address(ip)
        for block in cidrs:
            if addr in ipaddress.ip_network(block, strict=False):
                return True
    except Exception:
        return False # Fallback to False if ipaddress fails


def get_ip_info(ip: str, api_key: str) -> Dict[str, str]: # <--- api_key parameter added
    """Fetches country, ISP, and reputation for an IP address using a provided API key."""
    info = {"country": "N/A", "isp": "N/A", "reputation": "N/A"}

    if not api_key:
        print(f"[warn] API key not provided for IP enrichment of {ip}. Using basic ipinfo.io fallback.", file=sys.stderr)
        # Fallback to ipinfo.io for basic geo-info if no key
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            if response.status_code == 200:
                data = response.json()
                info["country"] = data.get("country", "N/A")
                info["isp"] = data.get("org", "N/A")
                # Default to Clean if no API key for reputation
                info["reputation"] = "Clean (ipinfo.io fallback)" # Added for clarity
        except Exception as e:
            print(f"[warn] ipinfo.io fallback failed for {ip}: {e}", file=sys.stderr)
        return info

    # --- AbuseIPDB API Integration ---
    abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': api_key, # Use the API key provided by the user
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90 # How far back to check for reports
    }

    try:
        print(f"[info] Querying AbuseIPDB for IP: {ip}...")
        response = requests.get(abuseipdb_url, headers=headers, params=params, timeout=5)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        data = response.json().get('data', {})
        
        info["country"] = data.get("countryCode", "N/A")
        info["isp"] = data.get("isp", "N/A")
        
        # AbuseIPDB provides an abuseConfidenceScore (0-100)
        abuse_score = data.get("abuseConfidenceScore", 0)
        if abuse_score > 60: # Threshold for "Malicious"
            info["reputation"] = "Malicious"
        elif abuse_score > 20: # Threshold for "Suspicious"
            info["reputation"] = "Suspicious"
        else:
            info["reputation"] = "Clean"
        
        # Optionally add more details from AbuseIPDB response
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
        print("[ERROR] AbuseIPDB API request timed out for {ip}.", file=sys.stderr)
        info["reputation"] = "Timeout"
    except Exception as e:
        print(f"[ERROR] Unexpected error during AbuseIPDB call for {ip}: {e}", file=sys.stderr)
        info["reputation"] = "Unknown Error"
    
    return info


# ---------------------------
# OpenAI GPT Integration
# ---------------------------

def get_ai_verdict(findings: List[Dict[str, Any]], openai_api_key: str) -> Dict[str, Any]:
    """
    Generates an AI-powered verdict, key findings, and known malware resemblance
    based on memory forensic findings and MITRE TTPs, using the OpenAI GPT API.
    """
    # Default structure to return if API key is missing or call fails
    default_ai_response = {
        "verdict": "N/A",
        "plain_summary": "No AI verdict generated.",
        "key_findings": [],
        "attack_chain": [],
        "malware_match": "None apparent",
        "confidence": "N/A",
        "anomalies": {"flags": [], "corrections": []},
        "glossary": {},
        "approx_ordering": True
    }

    if not openai_api_key:
        print("[info] OpenAI API key not provided. Skipping AI verdict generation.")
        return default_ai_response

    # --- Pre-processing findings for better LLM input ---
    # Enrich findings with a 'time_utc' field where possible for better attack chain ordering
    enriched_findings = []
    for f in findings:
        f_copy = f.copy()
        time_found = "unknown"
        # Attempt to extract timestamp from evidence, prioritizing CreateTime
        if f.get('evidence'):
            for ev_item in f['evidence']:
                # Prioritize 'CreateTime' from pslist/psscan/etc.
                if 'CreateTime' in ev_item and ev_item['CreateTime'] and ev_item['CreateTime'] != "0":
                    time_found = ev_item['CreateTime']
                    break
                # Then 'LastUpdated' from userassist
                elif 'LastUpdated' in ev_item and ev_item['LastUpdated'] and ev_item['LastUpdated'] != "0":
                    time_found = ev_item['LastUpdated']
                    break
                # For network connections, consider connection establishment time if available or default to finding time
                elif 'Time' in ev_item and ev_item['Time'] and ev_item['Time'] != "0":
                     time_found = ev_item['Time']
                     break


        f_copy['time_utc'] = time_found
        enriched_findings.append(f_copy)

    # Collect all unique MITRE TTPs from all findings
    all_ttps = set()
    for f in enriched_findings: # Use enriched findings
        for ttp in f.get('mitre', []):
            all_ttps.add(ttp)
    ttps_list = sorted(list(all_ttps))

    # Select top N most severe findings for summary, ensuring correlations are also considered in top
    # Prioritize higher weight, then correlation findings
    sorted_findings_for_prompt = sorted(
        enriched_findings,
        key=lambda f: (f.get('weight', 0), 1 if f['id'].startswith('correlation_') else 0),
        reverse=True
    )
    # Provide enough context for the LLM, up to a reasonable limit
    top_findings_for_prompt = sorted_findings_for_prompt[:15] # Increased from 10 to 15


    # Build the PROMPT for OpenAI
    system_prompt_parts = [
        "You are a DFIR assistant specializing in Windows/Linux memory forensics. Your task is to analyze the provided forensic findings and generate a structured JSON report.",
        "",
        "Output rule: Return valid JSON only matching the exact schema below. No prose, no backticks, no extra keys, no trailing commas. Be extremely strict with the JSON format. Do not include any text before or after the JSON. The response must be a single, complete JSON object. Ensure all string values in the JSON are properly escaped if they contain quotes or special characters.",
        "",
        "Truthfulness: Use only facts present in the evidence. Never invent PIDs, IPs, users, paths, hashes, or times. If a detail is missing, use 'unknown' or omit that field (e.g., if actor.pid is unknown, set it to \"unknown\"). For network ports, ensure they are valid (not '0' or empty string). If a port is genuinely '0' or invalid in the original data, mark it as 'unknown' or omit that specific port detail.",
        "",
        "Non-technical clarity: Ensure 'plain_summary', 'key_findings', and 'attack_chain' actions are in brief, simple, clear, and plain English that anyone can follow, avoiding jargon where possible. Explain what happened, how it happened, and what's unusual about it.",
        "",
        "Actionability: 'key_findings' must be single-sentence, highly specific, and reference concrete indicators (process names, PIDs, file paths, IP addresses, ports) directly from the evidence. Each 'key_finding' should describe a distinct, important observation. For network connections, always include IP and port if available and valid. **For suspicious network communication, explicitly state *why* it is suspicious (e.g., 'connecting to a known malicious IP', 'communicating on a highly unusual port', 'communicating with an IP address in a suspicious country/region').**",
        "",
        "Correlation: If findings belong to a chain (e.g., 'correlation_*' ID), clearly state this in the 'key_findings' description and integrate them coherently into the 'attack_chain'. The 'action' in 'attack_chain' steps should explicitly reflect the correlated nature of the event when applicable, for example: 'Process XYZ (PID 123) engaged in evasive network communication to malicious IP 1.2.3.4 (correlated from hidden process and network connection findings).'",
        "",
        "Sanity checks & corrections:",
        "- Correctly classify network endpoints: **Loopback (127.0.0.0/8), private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), and '0.0.0.0' (which means listening on all interfaces) are internal network addresses and should NOT be described as 'external' or 'malicious' unless there is explicit and overwhelming evidence of malicious activity originating from or targeting another host within that *same* internal network.** If an endpoint is mislabeled (e.g., “remote 127.0.0.1”), correct the label (e.g., “loopback/local”) and record the correction under 'anomalies.corrections'. Specifically, for '0.0.0.0', describe it as 'listening on all interfaces' or 'unbound socket' in the narrative/summary, not as an 'invalid IP address' or inherently suspicious.",
        "- **Crucially, a process simply listening on a local port (e.g., 127.0.0.1 or 0.0.0.0, or a high ephemeral port without corresponding external connections to known malicious infrastructure) is NOT direct evidence of a Command and Control (C2) channel.** C2 implies *external* communication to an attacker-controlled server. If local port activity is flagged, describe it precisely (e.g., 'opened an unusual local port for listening') without implying external C2 unless there is clear evidence of an external connection from that port to a suspicious external IP.",
        "- Flag inconsistent or impossible fields (negative PIDs, malformed IPs, impossible times, or 'port 0' as a meaningful port) in 'anomalies.flags'.",
        "",
        "Timeline rules:",
        "- Build 'attack_chain' in chronological order (UTC) using 'time_utc' from findings. If 'time_utc' is 'unknown', order by PPID→PID and then by correlation links. Set 'approx_ordering': true if any 'time_utc' is 'unknown'.",
        "",
        "Verdict set: ['Malicious Activity Detected','Suspicious Activity Found','No Significant Threat'].",
        "Malware match: Return a well-supported, specific malware family name (e.g., 'Ryuk Ransomware', 'Emotet'). If no specific malware resemblance is *strongly supported* by the TTPs, **you MUST return 'None apparent'**.",
        "Confidence set: ['High','Medium','Low','N/A'] ('N/A' only when 'malware_match' is 'None apparent').",
        "",
        "Key findings count: 3–5 when available and relevant; otherwise include all supportable items (no fabrication).",
        "",
        "Output schema (strict):",
        json.dumps({ # Embed the schema directly for strict adherence
            "verdict": "string",
            "plain_summary": "string",
            "key_findings": ["string", "..."],
            "attack_chain": [
                {
                    "step": 1,
                    "time_utc": "YYYY-MM-DDThh:mm:ssZ|unknown",
                    "actor": {"process": "string|unknown", "pid": "number|unknown", "ppid": "number|unknown", "user": "string|unknown"},
                    "action": "string",
                    "target": {"process": "string|unknown", "pid": "number|unknown", "object": "path|ip:port|registry|unknown"},
                    "evidence_refs": ["string", "..."],
                    "correlation_id": "correlation_*|none"
                }
            ],
            "malware_match": "string",
            "confidence": "High|Medium|Low|N/A",
            "anomalies": {
                "flags": ["string", "..."],
                "corrections": [
                    {"field": "string", "original": "string", "corrected": "string", "reason": "string"}
                ]
            },
            "glossary": {
                "term_or_process": "plain-English explanation",
                "ttp_id": "plain-English explanation"
            },
            "approx_ordering": False
        }, indent=2)
    ]

    # --- Start of Few-Shot Example ---
    few_shot_example_input_findings = [
        {
            "id": "psxview_hidden_example",
            "title": "Hidden process detected by PSXVIEW",
            "narrative": "A process attempted to hide its presence from standard monitoring tools.",
            "mitre": ["T1014", "T1055"],
            "weight": 10,
            "evidence": [{
                "PID": "1234",
                "Name": "malware.exe",
                "pslist": "False",
                "psscan": "True",
                "CreateTime": "2024-07-15T10:00:00Z"
            }],
            "time_utc": "2024-07-15T10:00:00Z"
        },
        {
            "id": "suspicious_network_enrichment_example",
            "title": "Malicious IP connection detected",
            "narrative": "A process connected to a known malicious IP address.",
            "mitre": ["T1071.001", "T1573.002"],
            "weight": 8,
            "evidence": [{
                "PID": "1234",
                "Owner": "SYSTEM",
                "ForeignAddr": "1.2.3.4",
                "ForeignPort": "4444",
                "ip": "1.2.3.4",
                "country": "RU",
                "reputation": "Malicious",
                "CreateTime": "2024-07-15T10:05:00Z" # Using CreateTime for consistent timestamp in example
            }],
            "time_utc": "2022-07-15T10:05:00Z"
        },
        {
            "id": "correlation_hidden_process_network",
            "title": "Correlated: Hidden Process with Malicious Network Connection",
            "narrative": "A hidden process (PID 1234) established a connection to a malicious IP address (1.2.3.4:4444).",
            "mitre": ["T1014", "T1071.001", "T1573.002"],
            "weight": 15,
            "evidence": [{
                "correlated_pid": "1234",
                "correlated_findings": [
                    {"finding_id": "psxview_hidden_example", "title": "Hidden process detected by PSXVIEW"},
                    {"finding_id": "suspicious_network_enrichment_example", "title": "Malicious IP connection detected"}
                ]
            }],
            "time_utc": "2022-07-15T10:05:00Z"
        }
    ]

    few_shot_example_output = {
        "verdict": "Malicious Activity Detected",
        "plain_summary": "The system shows strong indicators of a highly evasive attack, including a hidden process maintaining persistent malicious network communication to an external server.",
        "key_findings": [
            "Process 'malware.exe' (PID: 1234) was found to be hidden from standard process lists, indicating evasion.",
            "Process 'malware.exe' (PID: 1234) established an outbound connection to a known malicious IP address 1.2.3.4 on port 4444.",
            "Correlated: A hidden process (PID: 1234) simultaneously engaged in evasive behavior and suspicious network communication to 1.2.3.4:4444, strongly suggesting active command and control."
        ],
        "attack_chain": [
            {
                "step": 1,
                "time_utc": "2024-07-15T10:00:00Z",
                "actor": {"process": "malware.exe", "pid": 1234, "ppid": "unknown", "user": "unknown"},
                "action": "initiated as a hidden process to evade detection",
                "target": {"process": "malware.exe", "pid": 1234, "object": "unknown"},
                "evidence_refs": ["psxview_hidden_example"],
                "correlation_id": "none"
            },
            {
                "step": 2,
                "time_utc": "2024-07-15T10:05:00Z",
                "actor": {"process": "malware.exe", "pid": 1234, "ppid": "unknown", "user": "unknown"},
                "action": "established an outbound network connection to a malicious IP address",
                "target": {"process": "unknown", "pid": "unknown", "object": "1.2.3.4:4444"},
                "evidence_refs": ["suspicious_network_enrichment_example", "correlation_hidden_process_network"],
                "correlation_id": "correlation_hidden_process_network"
            }
        ],
        "malware_match": "Remote Access Trojan (RAT)",
        "confidence": "High",
        "anomalies": {
            "flags": [],
            "corrections": []
        },
        "glossary": {
            "T1014": "Defense Evasion - A technique to avoid detection by security tools and analysts.",
            "T1071.001": "Command and Control - The method used by attackers to communicate with compromised systems over standard protocols."
        },
        "approx_ordering": False
    }
    # --- End of Few-Shot Example ---


    user_prompt_parts = [ # FIX: Initialized user_prompt_parts here
        "**Here is a synthetic example to guide your response format and content. DO NOT use these specific details in your actual output; this is for learning the structure only.**",
        ""
    ]
    for f in few_shot_example_input_findings:
        example_evidence_summary_parts = []
        if f.get('time_utc') and f['time_utc'] != 'unknown':
            example_evidence_summary_parts.append(f"Time (UTC): {f['time_utc']}")
        if f.get('evidence'):
            first_ev = f['evidence'][0]
            for key in ['PID', 'Name', 'ImageFileName', 'ip', 'ForeignAddr', 'LocalPort', 'ForeignPort', 'Path', 'CommandLine', 'Key', 'Decoded', 'User', 'Command', 'correlated_pid', 'correlated_findings', 'Proto', 'State', 'Country', 'Reputation', 'ServiceName', 'ServiceType', 'ImagePath', 'TaskLine', 'Notes']: # Added 'Notes' for enriched network findings
                val = first_ev.get(key)
                # Ensure values are meaningful and not '0' or empty for numeric/port fields
                if val is not None and str(val).strip() not in ['', 'N/A']:
                    if key in ['PID', 'PPID']: example_evidence_summary_parts.append(f"{key.upper()}: {val}")
                    elif key in ['ip', 'ForeignAddr']:
                        # Special handling for 0.0.0.0 and 127.0.0.1
                        if str(val).strip() == '0.0.0.0':
                            example_evidence_summary_parts.append("Network Address: 0.0.0.0 (listening on all interfaces)")
                        elif str(val).strip() == '127.0.0.1':
                             example_evidence_summary_parts.append("Network Address: 127.0.0.1 (loopback/local)")
                        else:
                            port = first_ev.get('ForeignPort') # Get associated foreign port
                            # Filter out '0' or empty ports
                            port_str = f":{port}" if port and str(port).strip() not in ['0', 'N/A', ''] else ""
                            example_evidence_summary_parts.append(f"Network Connection IP: {val}{port_str}")
                    elif key in ['LocalPort', 'ForeignPort'] and str(val).strip() not in ['', 'N/A', '']: # Corrected: Removed '0' from filter here, as '0' could be a valid port for some raw sockets, although uncommon.
                        example_evidence_summary_parts.append(f"Port: {val}") # Just the port number
                    elif key == 'Name' or key == 'ImageFileName': example_evidence_summary_parts.append(f"Process Name: \"{val}\"")
                    elif key == 'Path' or key == 'ImagePath': example_evidence_summary_parts.append(f"File Path: \"{val}\"")
                    elif key == 'CommandLine': example_evidence_summary_parts.append(f"Command Line: \"{val}\"")
                    elif key == 'Key': example_evidence_summary_parts.append(f"Registry Key: \"{val}\"")
                    elif key == 'Decoded': example_evidence_summary_parts.append(f"Registry Value: \"{val}\"")
                    elif key == 'User': example_evidence_summary_parts.append(f"User: \"{val}\"")
                    elif key == 'Command': example_evidence_summary_parts.append(f"Command: \"{val}\"")
                    elif key == 'Proto': example_evidence_summary_parts.append(f"Protocol: {val}")
                    elif key == 'State': example_evidence_summary_parts.append(f"Connection State: {val}")
                    elif key == 'Country': example_evidence_summary_parts.append(f"Country: {val}")
                    elif key == 'Reputation': example_evidence_summary_parts.append(f"Reputation: {val}")
                    elif key == 'Notes': example_evidence_summary_parts.append(f"Suspicion Reason: {val}") # For enrichment notes
                    elif key == 'ServiceName': example_evidence_summary_parts.append(f"Service Name: {val}")
                    elif key == 'ServiceType': example_evidence_summary_parts.append(f"Service Type: {val}")
                    elif key == 'TaskLine': example_evidence_summary_parts.append(f"Scheduled Task: \"{val}\"")
                    elif key == 'correlated_pid': example_evidence_summary_parts.append(f"Correlated PID: {val}")
                    elif key == 'correlated_findings':
                        titles = [c.get('title', 'unknown') for c in val]
                        example_evidence_summary_parts.append(f"Correlated with: {', '.join(titles)}")
                    else: example_evidence_summary_parts.append(f"{key.replace('_', ' ').title()}: {val}")
        
        example_evidence_summary_formatted = ", ".join(example_evidence_summary_parts) if example_evidence_summary_parts else "No specific evidence details provided."

        user_prompt_parts.append(f"- Finding ID: {f.get('id', 'N/A')}")
        user_prompt_parts.append(f"  Title: {f.get('title', 'N/A')}")
        user_prompt_parts.append(f"  Narrative: {f.get('narrative', 'N/A')}")
        user_prompt_parts.append(f"  MITRE TTPs: {', '.join(f.get('mitre', ['N/A']))}")
        user_prompt_parts.append(f"  Severity: {f.get('weight', 0)}")
        user_prompt_parts.append(f"  Evidence Summary: {example_evidence_summary_formatted}")
        user_prompt_parts.append("")

    user_prompt_parts.append("**Example AI Output (for format only - DO NOT use these specific details in your actual output):**")
    user_prompt_parts.append(json.dumps(few_shot_example_output, indent=2))
    user_prompt_parts.append("") # Separate example from actual data

    user_prompt_parts.append("--- END OF EXAMPLE ---\n")
    user_prompt_parts.append("Now, analyze the following ACTUAL memory forensic findings and provide your response in the EXACT JSON format described above:")
    user_prompt_parts.append("")


    # ... (the loop for actual findings remains the same as before) ...
    for f in top_findings_for_prompt:
        evidence_summary_parts = []
        if f.get('time_utc') and f['time_utc'] != 'unknown':
            evidence_summary_parts.append(f"Time (UTC): {f['time_utc']}")

        if f.get('evidence'):
            first_evidence = f['evidence'][0]
            for key in ['name', 'process', 'pid', 'ppid', 'path', 'command_line', 'ip', 'ForeignAddr', 'LocalPort', 'ForeignPort', 'User', 'Command', 'ServiceName', 'ImagePath', 'ServiceType', 'TaskLine', 'Key', 'Name', 'Decoded', 'Proto', 'State', 'Country', 'Reputation', 'Notes']: # Added 'Notes'
                val = first_evidence.get(key)
                # Filter out '0' for ports and other empty-like values
                if val is not None and str(val).strip() not in ['', 'N/A', '0']:
                    if key in ['pid', 'ppid']:
                        evidence_summary_parts.append(f"{key.upper()}: {val}")
                    elif key in ['ForeignAddr', 'ip']:
                        # Special handling for 0.0.0.0 and 127.0.0.1 in actual findings summary
                        if str(val).strip() == '0.0.0.0':
                            evidence_summary_parts.append("Network Address: 0.0.0.0 (listening on all interfaces)")
                        elif str(val).strip() == '127.0.0.1':
                             evidence_summary_parts.append("Network Address: 127.0.0.1 (loopback/local)")
                        else:
                            port = first_evidence.get('ForeignPort')
                            port_str = f":{port}" if port and str(port).strip() not in ['0', 'N/A', ''] else ""
                            evidence_summary_parts.append(f"Network Connection IP: {val}{port_str}")
                    elif key in ['LocalPort', 'ForeignPort'] and str(val).strip() not in ['', 'N/A', '']: # Corrected: Removed '0' from filter here
                        evidence_summary_parts.append(f"Port: {val}")
                    elif key == 'command_line':
                        evidence_summary_parts.append(f"Command Line: \"{str(val).strip()}\"")
                    elif key == 'path' or key == 'ImagePath':
                        evidence_summary_parts.append(f"File Path: \"{str(val).strip()}\"")
                    elif key == 'Key':
                        evidence_summary_parts.append(f"Registry Key: {val}")
                    elif key == 'Decoded':
                        evidence_summary_parts.append(f"Registry Value: \"{str(val).strip()}\"")
                    elif key in ['Name', 'Process', 'Owner', 'ServiceName', 'ImageFileName', 'User', 'COMM']:
                         evidence_summary_parts.append(f"Process Name: \"{str(val).strip()}\"")
                    elif key == 'Proto':
                        evidence_summary_parts.append(f"Protocol: {val}")
                    elif key == 'State':
                        evidence_summary_parts.append(f"Connection State: {val}")
                    elif key == 'Country':
                        evidence_summary_parts.append(f"Country: {val}")
                    elif key == 'Reputation':
                        evidence_summary_parts.append(f"Reputation: {val}")
                    elif key == 'Notes': # Add Notes from network enrichment
                        evidence_summary_parts.append(f"Suspicion Reason: {val}")
                    elif key == 'TaskLine':
                        evidence_summary_parts.append(f"Scheduled Task: \"{str(val).strip()}\"")
                    else:
                        evidence_summary_parts.append(f"{key.replace('_', ' ').title()}: {str(val).strip()}")

            if not evidence_summary_parts and first_evidence:
                evidence_summary_parts.append("Raw Evidence: " + "; ".join([f"{k}:{str(v).strip()}" for k, v in first_evidence.items() if v is not None]))

        # Special handling for correlation findings in evidence summary sent to LLM for ACTUAL findings
        if f['id'].startswith('correlation_') and f.get('evidence'):
            correlated_pid = f['evidence'][0].get('correlated_pid', 'unknown')
            # Corrected: Removed the extra single quote after [0]
            correlated_finding_titles = [cf.get('title', 'Unknown finding') for cf in f['evidence'][0].get('correlated_findings', [])]
            # More descriptive summary for correlation in prompt input
            chunks = []
            if correlated_pid:
                chunks.append(f"Correlated PID: {correlated_pid}")
            if correlated_finding_titles:
                chunks.append(f"Correlated with: {', '.join(correlated_finding_titles)}")

            if chunks:
                evidence_summary_formatted = f"**This is a correlated finding.** {'. '.join(chunks)}. This suggests a multi-stage attack or linked malicious behaviors."
            else:
                evidence_summary_formatted = "**This is a correlated finding.** This suggests a multi-stage attack or linked malicious behaviors."
        elif evidence_summary_parts:
            evidence_summary_formatted = ", ".join(evidence_summary_parts) + "."
        else:
            evidence_summary_formatted = "No specific evidence details provided."

        user_prompt_parts.append(f"- Finding ID: {f.get('id', 'N/A')}")
        user_prompt_parts.append(f"  Title: {f.get('title', 'N/A')}")
        user_prompt_parts.append(f"  Narrative: {f.get('narrative', 'N/A')}")
        user_prompt_parts.append(f"  MITRE TTPs: {', '.join(f.get('mitre', ['N/A']))}") # Ensure MITRE TTPs are joined for the prompt
        user_prompt_parts.append(f"  Severity: {f.get('weight', 0)}")
        user_prompt_parts.append(f"  Evidence Summary: {evidence_summary_formatted}")
        user_prompt_parts.append("")

    user_prompt_parts.append("\nAll Detected MITRE ATT&CK TTPs (for holistic view):")
    if ttps_list:
        user_prompt_parts.append(f"- {', '.join(ttps_list)}")
    else:
        user_prompt_parts.append("- No specific TTPs identified in findings.")

    # Combine system and user prompt for the API call
    system_prompt = "\n".join(system_prompt_parts)
    user_prompt = "\n".join(user_prompt_parts)

    print(f"[info] OpenAI: Preparing prompt with {len(top_findings_for_prompt)} findings and {len(ttps_list)} TTPs.")
    # print(f"[DEBUG] Full System Prompt: \n{system_prompt[:2500]}...") # Log part of the prompt
    # print(f"[DEBUG] Full User Prompt: \n{user_prompt[:2500]}...") # Log part of the prompt


    try:
        # OpenAI API endpoint
        openai_url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {openai_api_key}"
        }

        # OpenAI API payload format
        payload = {
            "model": "gpt-4o-mini",  # Using a recent, capable, and cost-effective GPT model
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"}, # Requesting JSON output
            "temperature": 0.0, # Setting temperature to 0.0 for maximum determinism
            "max_tokens": 1500 # Increased tokens for larger, more detailed output
        }
        
        # Exponential backoff retry logic
        retries = 0
        max_retries = 3
        while retries < max_retries:
            try:
                print(f"[info] OpenAI: Sending request (Attempt {retries + 1}/{max_retries})...")
                response = requests.post(openai_url, headers=headers, json=payload, timeout=120) # Increased timeout to 120s
                response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                
                result = response.json()
                
                # Check OpenAI's response structure
                if result.get('choices') and result['choices'][0].get('message') and result['choices'][0]['message'].get('content'):
                    json_str = result['choices'][0]['message']['content']
                    print("[info] OpenAI: Received response. Parsing JSON...")
                    try:
                        parsed_json = json.loads(json_str)
                        # Validate the parsed JSON against the expected top-level keys
                        expected_keys = ["verdict", "plain_summary", "key_findings", "attack_chain",
                                         "malware_match", "confidence", "anomalies", "glossary", "approx_ordering"]
                        
                        # Basic validation: ensure all expected keys are present and types are generally correct
                        is_valid_schema = True
                        for key in expected_keys:
                            if key not in parsed_json:
                                print(f"[warn] Missing key in AI response: {key}. Defaulting to N/A for this key.", file=sys.stderr)
                                # If a key is missing, add it with a default value to avoid downstream errors
                                parsed_json[key] = default_ai_response.get(key)
                                is_valid_schema = False
                        
                        # Ensure malware_match and confidence are handled correctly if 'None apparent'
                        if parsed_json.get("malware_match") == "None apparent":
                            parsed_json["confidence"] = "N/A"
                        elif parsed_json.get("confidence") == "N/A" and parsed_json.get("malware_match") != "None apparent":
                            parsed_json["confidence"] = "Low" # Default to low if malware is identified but confidence is N/A

                        print("[info] OpenAI: Successfully parsed AI verdict and performed post-processing.")
                        return parsed_json # Return the full structured response
                    except json.JSONDecodeError as e:
                        print(f"[ERROR] OpenAI response content is not valid JSON: {e} - Content: {json_str}", file=sys.stderr)
                        return default_ai_response # Return default on JSON decode error
                else:
                    print(f"[warn] OpenAI API response structure unexpected (no choices/message/content): {result}", file=sys.stderr)
                    return default_ai_response # Return default on unexpected structure

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429 and retries < max_retries - 1: # Too Many Requests
                    delay = 2 ** retries # Exponential backoff
                    print(f"[warn] OpenAI: Rate limit hit ({e.response.status_code}). Retrying in {delay} seconds...", file=sys.stderr)
                    time.sleep(delay)
                    retries += 1
                else:
                    print(f"[ERROR] OpenAI HTTP error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
                    return default_ai_response
            except requests.exceptions.ConnectionError as e:
                print(f"[ERROR] OpenAI connection error: {e}", file=sys.stderr)
                return default_ai_response
            except requests.exceptions.Timeout:
                print("[ERROR] OpenAI API request timed out.", file=sys.stderr)
                return default_ai_response
            except Exception as e:
                print(f"[ERROR] An unexpected error occurred during OpenAI call: {e}", file=sys.stderr)
                return default_ai_response
        
        print(f"[ERROR] Failed to get OpenAI response after {max_retries} retries.", file=sys.stderr)
        return default_ai_response

    except Exception as e:
        print(f"[ERROR] Could not prepare OpenAI API call: {e}", file=sys.stderr)
        return default_ai_response


# ---------------------------
# Volatility Runner
# ---------------------------

def run_plugin(vol: str, image: str, plugin: str, fmt: str, outdir: Path) -> str:
    """
    Executes a single plugin and returns the content.
    Places '-r csv' BEFORE plugin name when format=csv (Vol3 requirement).
    """
    base = [vol, "-f", image, "--quiet"]
    if fmt == "csv":
        cmd = base + ["-r", "csv", plugin]
    else:
        cmd = base + [plugin]

    # Replace dots in the plugin name with underscores to ensure consistent artifact filenames
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
            check=True
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
    """
    Try primary plugin, else fallback list. Returns (plugin_used, content).
    """
    print(f"[DEBUG] Trying plugin: {name}")
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
    # Simple heuristic: check for “windows.info” fields, else linux/mac
    if "NtSystemRoot" in info_text or "IsPAE" in info_text:
        return "windows"
    # we could run linux.boottime/mac.pslist if needed; default:
    # Light sniff:
    if "Linux" in info_text or "linux" in info_text:
        return "linux"
    if "Darwin" in info_text or "Mac" in info_text:
        return "macos"
    return "windows"  # assume windows for CTFs if ambiguous


# ---------------------------
# Parsers (minimal but effective)
# ---------------------------

def parse_csv(text: str) -> List[Dict[str, str]]:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        print("[DEBUG] parse_csv received empty text or only whitespace lines.")
        return []
    # If Vol put a banner line, keep header detection robust:
    # Find first line that contains commas and plausible header tokens
    header_idx = 0
    for i, l in enumerate(lines[:10]):
        if "," in l and not l.lower().startswith("volatility 3"):
            header_idx = i
            break
    hdr = [h.strip() for h in lines[header_idx].split(",")]
    rows = []
    for l in lines[header_idx+1:]:
        # tolerate extra commas in text by splitting at most len(hdr)-1
        parts = l.split(",", len(hdr)-1)
        parts += [""] * (len(hdr)-len(parts))
        rows.append({hdr[i]: parts[i].strip() for i in range(len(hdr))})
    print(f"[DEBUG] parse_csv parsed {len(rows)} rows with headers: {hdr}")
    return rows


def kv_parse(text: str) -> Dict[str, str]:
    # parse Key: Value lines
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
    """Generates a finding for a specific PID."""
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
    # pslist CSV headers for Vol3: PID,PPID,ImageFileName,CreateTime,...
    for r in pslist_rows:
        name = r.get("ImageFileName", "") or r.get("Name", "")
        pid  = r.get("PID", "")
        if name and (name not in wl):
            findings.append({"pid": pid, "name": name, "path": r.get("Path","")})
    return findings

def eng_psxview_hidden(rows):
    # headers: Name, PID, pslist, psscan, thrdscan, csrss, ...
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
                    "pslist": r.get("pslist",""),
                    "psscan": r.get("psscan",""),
                    "thrdscan": r.get("thrdscan",""),
                    "csrss": r.get("csrss",""),
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
        if not faddr or faddr in ("0.0.0.0","::","*"): # Ensure 0.0.0.0 and :: are not considered suspicious *foreign* addresses
            continue
        # If it's an IP:port, check CIDR + port allowlists
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

# NEW MASTER ENGINE FOR NETWORK ENRICHMENT
def eng_network_enrichment_master(netstat_rows: List[Dict[str, Any]], detection_rules: List[Dict[str, Any]], baseline: Dict[str, Any], api_key: str) -> List[Dict[str, Any]]:
    findings = []
    processed_ips = {}  # Cache to avoid redundant API calls

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
            
            # Skip loopback (127.0.0.1, ::1) and unspecified (0.0.0.0, ::) addresses,
            # as well as private IP ranges (RFC1918). These are typically internal or listening,
            # not external IPs for reputation lookups.
            if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_private:
                print(f"[DEBUG_TRACE] Skipping internal/loopback/unspecified IP: {foreign_ip}") 
                continue
            
            # Only enrich non-whitelisted IPs (from baseline allow_cidrs)
            if not in_cidrs(foreign_ip, allow_cidrs):
                unique_ips_to_process.add(foreign_ip)
            else:
                print(f"[DEBUG_TRACE] Skipping whitelisted IP: {foreign_ip}") 
        except ValueError:
            print(f"[DEBUG_TRACE] Skipping invalid foreign IP address: '{foreign_ip}'") 
            continue

    print(f"[DEBUG] eng_network_enrichment_master: Unique IPs to process: {unique_ips_to_process}")

    # Perform enrichment for all unique IPs
    for ip in unique_ips_to_process:
        if ip in processed_ips:
            enriched_data = processed_ips[ip]
        else:
            print(f"[info] Fetching enrichment for IP: {ip}")
            enriched_data = get_ip_info(ip, api_key) # <--- Pass api_key here
            processed_ips[ip] = enriched_data
        
        print(f"[DEBUG] IP {ip} enrichment data: {enriched_data}")

    # Now, iterate through each enriched IP and apply ALL relevant network detection rules
    for ip, enriched_data in processed_ips.items():
        for detection_rule in detection_rules:
            # Only apply rules that are specifically for 'network_enrichment' engine
            if detection_rule.get('engine') != 'network_enrichment':
                continue

            is_suspicious_for_this_rule = False
            reasons = []

            rules_logic = detection_rule.get("logic", [])
            print(f"[DEBUG_TRACE] Applying rule '{detection_rule['id']}' to IP {ip} with enriched data: {enriched_data}...") # Enhanced Debug

            for logic_rule in rules_logic:
                rule_id = logic_rule.get("rule_id")
                matches = logic_rule.get("match", [])

                rule_matched_locally = True # Assume true, then find if any criteria fail
                # All match criteria within a single 'match' block must pass (AND logic)
                for match_criteria in matches:
                    field = match_criteria.get("field")
                    value = match_criteria.get("value")
                    operator = match_criteria.get("operator", "==")

                    if field in enriched_data:
                        data_val = enriched_data[field]
                        print(f"[DEBUG_TRACE]   Comparing Field: '{field}' (Data: '{data_val}') {operator} Target: '{value}' for rule '{detection_rule['id']}'") # Added debug trace
                        if operator == "==":
                            if not (str(data_val).lower() == str(value).lower()):
                                rule_matched_locally = False
                                print(f"[DEBUG_TRACE]     Comparison FAILED for rule '{detection_rule['id']}' on field '{field}'.") # Added debug
                                break # One criteria failed, this match block fails
                            else:
                                print(f"[DEBUG_TRACE]     Comparison SUCCEEDED for rule '{detection_rule['id']}' on field '{field}'.") # Added debug
                        elif operator == "<":
                            try:
                                if not (float(data_val) < float(value)):
                                    rule_matched_locally = False
                                    print(f"[DEBUG_TRACE]     Comparison FAILED (<) for rule '{detection_rule['id']}' on field '{field}'.") # Added debug
                                    break
                                else:
                                    print(f"[DEBUG_TRACE]     Comparison SUCCEEDED (<) for rule '{detection_rule['id']}' on field '{field}'.") # Added debug
                            except ValueError:
                                rule_matched_locally = False # Non-numeric comparison
                                print(f"[DEBUG_TRACE]     Comparison FAILED (<) non-numeric for rule '{detection_rule['id']}' on field '{field}'.") # Added debug
                                break
                        # Add other operators as needed

                if rule_matched_locally:
                    is_suspicious_for_this_rule = True
                    # Collect reasons for the finding
                    for match_criteria in matches:
                        field = match_criteria.get("field")
                        value = match_criteria.get("value")
                        if field in enriched_data:
                            reasons.append(f"Field '{field}' ({enriched_data[field]}) matches condition '{value}'")
                    print(f"[DEBUG_TRACE] Logic rule '{rule_id}' matched for IP {ip} under detection '{detection_rule['id']}'.") # Enhanced Debug
                    break # If any logic_rule matches, the detection rule is triggered for this IP

            if is_suspicious_for_this_rule:
                print(f"[DEBUG_TRACE] IP {ip} is determined to be SUSPICIOUS for rule '{detection_rule['id']}'.")
                # Find the original netstat row(s) for this IP to include PID/Owner
                associated_connections = [
                    conn for conn in netstat_rows
                    if (conn.get("ForeignAddr", "") or conn.get("ForeignIP", "")) == ip
                ]

                pids = list(set([c.get("Pid", c.get("PID", "N/A")) for c in associated_connections]))
                owners = list(set([c.get("Owner", c.get("Process", "N/A")) for c in associated_connections]))

                pids_display = ", ".join(p for p in pids if p and p != "N/A") or "N/A"
                owners_display = ", ".join(o for o in owners if o and o != "N/A") or "N/A"

                finding_evidence = {
                    "pid": pids_display,
                    "owner": owners_display,
                    "ip": ip,
                    "country": enriched_data.get("country", "N/A"),
                    "isp": enriched_data.get("isp", "N/A"),
                    "reputation": enriched_data.get("reputation", "N/A"),
                    "notes": "; ".join(reasons) # These notes are important for the LLM
                }
                print(f"[DEBUG_TRACE] Appending finding evidence for rule '{detection_rule['id']}': {finding_evidence}") # Enhanced Debug

                findings.append({
                    "id": detection_rule["id"],
                    "title": detection_rule["title"],
                    "narrative": detection_rule["narrative"],
                    "mitre": detection_rule.get("mitre", []),
                    "weight": detection_rule["weight"],
                    "evidence": [finding_evidence]
                })
    print(f"[DEBUG] eng_network_enrichment_master: Found {len(findings)} total network findings.")
    return findings


def eng_suspicious_port_activity(rows, suspicious_ports: List[int]):
    print(f"[DEBUG] eng_suspicious_port_activity: Received {len(rows)} rows.")
    findings = []
    susp_ports = {str(p) for p in suspicious_ports}
    for r in rows:
        local_port = r.get("LocalPort", "")
        foreign_port = r.get("ForeignPort", "")
        
        # Only consider ports that are not '0' or empty
        if (local_port and str(local_port).strip() != '0' and local_port in susp_ports) or \
           (foreign_port and str(foreign_port).strip() != '0' and foreign_port in susp_ports):
            findings.append({
                "pid": r.get("PID",""),
                "owner": r.get("Owner","") or r.get("Process",""),
                "Proto": r.get("Proto",""),
                "LocalPort": local_port,
                "ForeignPort": foreign_port,
                "Notes": "Connection found on a known suspicious port." # Added a default note for clarity
            })
            print(f"[DEBUG] Suspicious port match: PID {r.get('PID','')}, Local:{local_port}, Foreign:{foreign_port}")
    print(f"[DEBUG] eng_suspicious_port_activity: Found {len(findings)} findings.")
    return findings

def eng_correlated_findings(all_findings: List[Dict[str, Any]], correlation_pairs: List[Dict[str, Any]]):
    print(f"[DEBUG] eng_correlated_findings: Received {len(all_findings)} existing findings for correlation.")
    findings = []

    for pair in correlation_pairs:
        primary_ids = set(pair.get("primary_ids", []))
        secondary_ids = set(pair.get("secondary_ids", []))

        primary_pids = set()
        secondary_pids = set()

        # Gather PIDs for primary findings
        for f in all_findings:
            if f['id'] in primary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        primary_pids.add(pid)

        # Gather PIDs for secondary findings
        for f in all_findings:
            if f['id'] in secondary_ids:
                for ev in f.get('evidence', []):
                    pid = ev.get('pid') or ev.get('requestor_pid')
                    if pid:
                        secondary_pids.add(pid)

        # Check for intersection of PIDs
        correlated_pids = primary_pids.intersection(secondary_pids)
        print(f"[DEBUG] Correlating {primary_ids} and {secondary_ids}. Shared PIDs: {correlated_pids}")

        if correlated_pids:
            for pid in sorted(list(correlated_pids)):
                correlated_info = []
                for f in all_findings:
                    if f['id'] in (primary_ids | secondary_ids):
                        # Find evidence items for the current correlated PID
                        pid_evidence = [ev for ev in f.get('evidence', []) if (ev.get('pid') == pid or ev.get('requestor_pid') == pid)]
                        if pid_evidence:
                            correlated_info.append({
                                "finding_id": f['id'],
                                "title": f['title'],
                                "evidence": pid_evidence,
                                "time_utc": f.get('time_utc', 'unknown') # Pass through timestamp
                            })

                findings.append({
                    "correlated_pid": pid,
                    "correlated_findings": correlated_info,
                    "correlated_rule_ids": list(primary_ids | secondary_ids),
                })
    print(f"[DEBUG] eng_correlated_findings: Found {len(findings)} correlation findings.")
    return findings


def eng_malfind_injection(text, keywords: List[str]):
    findings = []
    if not text.strip():
        return findings
    blocks = text.splitlines()
    acc = []
    for line in blocks:
        if line.strip():
            acc.append(line)
    if not acc:
        return findings
    blob = "\n".join(acc)
    matches = re.finditer(r"^PID:\s*(\d+).*?Process:\s*([^\s]+).*?Start:\s*([0-9xa-fA-F]+).*?Protection:\s*([^\r\n]+)", blob, re.I|re.M|re.S)
    for m in matches:
        item = {
            "pid": m.group(1),
            "process": m.group(2),
            "Start": m.group(3),
            "Protection": m.group(4).strip(),
            "PrivateMemory": "",
            "Notes": ""
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
    if not text.strip():
        return findings
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
    if not text.strip():
        return findings
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
    if not text.strip():
        return findings
    re_access = re.compile(access_regex, re.I) if access_regex else None
    re_target = re.compile(target_regex, re.I) if target_regex else None
    for line in text.splitlines():
        low = line.lower()
        if re_access and not re_access.search(low):
            continue
        if re_target and not re_target.search(low):
            continue
        m = re.search(r"(?i)PID\s+(\d+).*?(?i)Process\s+([^\s]+)", line)
        req_pid = m.group(1) if m else ""
        req_name = m.group(2) if m else ""
        tgt = ""
        if "lsass" in low:
            tgt = "lsass.exe"
        findings.append({
            "requestor_pid": req_pid,
            "requestor_name": req_name,
            "target_pid": "",
            "target_name": tgt,
            "GrantedAccess": line.strip()
        })
    return findings

def eng_services_suspicious(rows: List[Dict[str, str]], temp_like_paths: List[str]): # Now takes rows (CSV)
    findings = []
    if not rows or not temp_like_paths:
        return findings
    rx = compile_any_contains_to_regex(temp_like_paths)

    for r in rows: # Iterate through CSV rows
        image_path = r.get("ImagePath", "")
        service_name = r.get("ServiceName", "")

        if image_path and rx.search(image_path.lower()):
            findings.append({
                "ServiceName": service_name,
                "ServiceType": r.get("Type", "N/A"), # Assuming 'Type' is available from svcscan CSV
                "ImagePath": image_path,
                "Start": r.get("Start", "N/A"),
                "Pid": r.get("Pid", "N/A")
            })
    return findings

def eng_scheduled_tasks(text, temp_like_paths: List[str], risky_exts: List[str]):
    findings = []
    if not text.strip():
        return findings
    rx_path = compile_any_contains_to_regex(temp_like_paths) if temp_like_paths else None
    rx_ext  = re.compile(r"\.(" + "|".join([re.escape(e) for e in risky_exts]) + r")(\.|$)", re.I) if risky_exts else None
    for line in text.splitlines():
        low = line.lower()
        if (rx_path and rx_path.search(low)) or (rx_ext and rx_ext.search(low)):
            findings.append({"TaskLine": line.strip()})
    return findings

def eng_filescan(text, any_path_contains: List[str], any_file_ext: List[str], any_name_contains: List[str]):
    findings = []
    if not text.strip():
        return findings
    rx_path = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    rx_names = compile_any_contains_to_regex(any_name_contains) if any_name_contains else None
    rx_ext = None
    if any_file_ext:
        rx_ext = re.compile(r"\.(" + "|".join([re.escape(e) for e in any_file_ext]) + r")(\.|$)", re.I)
    for line in text.splitlines():
        low = line.lower()
        hit = False
        if rx_path and rx_path.search(low):
            hit = True
        if rx_names and rx_names.search(low):
            hit = True
        if rx_ext and rx_ext.search(low):
            hit = True
        if hit:
            m = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(.*)$", line.strip())
            findings.append({
                "Offset": m.group(1) if m else "",
                "Path": m.group(2) if m else line.strip()
            })
    return findings

def eng_registry_printkey_matches(vol, image, outdir, keys: List[str], value_regex: str):
    findings = []
    rx = re.compile(value_regex, re.I) if value_regex else None

    for key in keys:
        plugin_name = "windows.registry.printkey"
        # Using specific args for printkey to target exact key
        cmd_args = [vol, "-f", image, "--quiet", plugin_name, "--key", key]
        rc, out = sh(cmd_args)

        safe_key_name = re.sub(r"[^A-Za-z0-9]+", "_", key)
        artifact_path = outdir / "artifacts" / f"{plugin_name.replace('.', '_')}_{safe_key_name}.txt"
        write_file(artifact_path, out)

        if not rx or not out.strip():
            continue
        for line in out.splitlines():
            if rx.search(line):
                # Attempt to parse key, name, and decoded value more accurately
                m = re.match(r'^\s*([0-9a-fA-F]+)\s+(\w+)\s+([^\s]+)\s+(.*)$', line.strip())
                if m:
                    offset, name, type_val, decoded = m.groups()
                    findings.append({
                        "Key": key,
                        "Name": name.strip(),
                        "Type": type_val.strip(),
                        "Decoded": decoded.strip()
                    })
                else:
                    findings.append({"Key": key, "Name": "", "Decoded": line.strip()})
    return findings


def eng_userassist_suspicious(text, any_path_contains: List[str]):
    findings = []
    if not text.strip():
        return findings
    rx = compile_any_contains_to_regex(any_path_contains) if any_path_contains else None
    for line in text.splitlines():
        low = line.lower()
        if rx and rx.search(low):
            # Robustly extract the path, count, and last updated time
            # Look for paths like \??\C:\... or {GUID}\path\to\program.exe
            path_match = re.search(r'\\??\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)
            guid_path_match = re.search(r'\{[0-9A-F-]+\}\\(.*?)(?=\s+Count:|\s+Last Updated:|$)', line, re.IGNORECASE)

            extracted_path = ""
            if path_match:
                extracted_path = path_match.group(1).strip()
            elif guid_path_match:
                extracted_path = guid_path_match.group(1).strip()

            count_match = re.search(r'Count:\s*(\d+)', line)
            last_updated_match = re.search(r'Last Updated:\s*(.*)', line)

            findings.append({
                "Path": extracted_path if extracted_path else line.strip(), # Fallback to full line if parsing fails
                "Count": count_match.group(1) if count_match else "",
                "LastUpdated": last_updated_match.group(1) if last_updated_match else ""
            })
    return findings

def eng_unusual_parent_child(pslist_rows, pairs):
    bypid = {r.get("PID",""): r.get("ImageFileName","") or r.get("Name","") for r in pslist_rows}
    findings = []
    for r in pslist_rows:
        pid = r.get("PID","")
        name = r.get("ImageFileName","") or r.get("Name","")
        ppid = r.get("PPID","")
        parent = bypid.get(ppid, "")
        for pair in pairs:
            if re.search(pair["parent"], parent or "", re.I) and re.search(pair["child"], name or "", re.I):
                findings.append({"pid": pid, "name": name, "ppid": ppid, "parent_name": parent})
                break
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
                    "SessionId": r.get("SessionId",""),
                    "User": r.get("User",""),
                    "AuthPackage": r.get("AuthPackage",""),
                    "LogonType": r.get("LogonType",""),
                    "Pid": r.get("Pid","") or r.get("PID",""),
                    "Process": r.get("Process","") or r.get("ImageFileName",""),
                })
    return findings

# NEW ENGINE: Suspicious Command-Line Arguments
def eng_suspicious_cmdline(cmdline_rows: List[Dict[str, str]], suspicious_keywords: List[str]):
    findings = []
    if not cmdline_rows or not suspicious_keywords:
        return findings

    rx = compile_any_contains_to_regex(suspicious_keywords)
    for r in cmdline_rows: # Iterate through cmdline plugin output
        pid = r.get("PID", "")
        name = r.get("ImageFileName", "") # windows.cmdline uses ImageFileName
        cmdline = r.get("CommandLine", "")

        if cmdline and rx.search(cmdline):
            findings.append({
                "pid": pid,
                "name": name,
                "command_line": cmdline
            })
    return findings

# NEW ENGINE: Bash History Suspicious Commands
def eng_bash_history_grep(text: str, suspicious_keywords: List[str]):
    findings = []
    if not text.strip() or not suspicious_keywords:
        return findings

    rx = compile_any_contains_to_regex(suspicious_keywords)

    current_user = "Unknown" # Default user
    for line in text.splitlines():
        line_lower = line.lower()

        # Attempt to parse "User: <username>" lines for context
        user_match = re.match(r'^\s*User:\s*(.+)$', line, re.IGNORECASE)
        if user_match:
            current_user = user_match.group(1).strip()
            continue

        # Attempt to parse "Command: <command_line>" lines
        command_match = re.match(r'^\s*Command:\s*(.+)$', line, re.IGNORECASE)
        if command_match:
            command = command_match.group(1).strip()
        else:
            # If no "Command:" prefix, assume the whole line is a command
            command = line.strip()

        if command and rx.search(command):
            findings.append({
                "User": current_user,
                "Command": command
            })
    return findings


# ---------------------------
# HTML report
# ---------------------------

def html_escape(s: str) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def render_html_evidence(finding_id: str, evidence: List[Dict[str, Any]]) -> str:
    """Intelligently formats evidence for the HTML report based on the finding ID."""
    print(f"[DEBUG_HTML] Evidence for {finding_id}: {evidence}") # NEW DEBUG LOG

    if not evidence:
        return "No key evidence."

    # Generic fallback for new rules not explicitly handled
    if finding_id == "suspicious_cmdline_args":
        display_items = [f"PID **{html_escape(r['pid'])}**: `{html_escape(r['command_line'])}`" for r in evidence[:3]]
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "registry_run_key_persistence":
        display_items = []
        for r in evidence[:3]:
            key_name = r.get("Key", "N/A").split("\\")[-1] # Get just the key name (e.g., Run)
            entry_name = r.get("Name", "N/A")
            decoded_val = r.get("Decoded", "N/A")
            display_items.append(f"Key: **{html_escape(key_name)}** - Entry: `{html_escape(entry_name)}` - Value: `{html_escape(decoded_val)}`")
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious Run Key entries:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "unknown_process_name":
        display_items = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])}" for r in evidence[:3]]
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "unusual_parent_child": # New handler
        display_items = [f"Child: `{html_escape(r['name'])}` (PID: {html_escape(r['pid'])}) spawned by Parent: `{html_escape(r['parent_name'])}` (PPID: {html_escape(r['ppid'])})" for r in evidence[:3]]
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Unusual parent-child process chains:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "services_suspicious": # Updated handler
        display_items = [f"Service: `{html_escape(r['ServiceName'])}` (Type: {html_escape(r.get('ServiceType', 'N/A'))}) running from `{html_escape(r['ImagePath'])}`" for r in evidence[:3]]
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious services detected:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "scheduled_tasks_suspicious":
        display_items = [f"Task: `{html_escape(r['TaskLine'])}`" for r in evidence[:3]]
        if len(evidence) > 3:
            display_items.append(f"...and {len(evidence)-3} more.")
        return f"<p>Suspicious scheduled tasks:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id == "psxview_hidden":
        # Changed to describe the mismatch without using "psxview" directly in the evidence summary
        critical_processes = ["lsass.exe", "services.exe", "winlogon.exe"]
        critical_evidence = [r for r in evidence if r.get('name') in critical_processes]
        lines = [f"PID **{html_escape(r['pid'])}**: {html_escape(r['name'])} (pslist: {html_escape(r.get('pslist',''))}, psscan: {html_escape(r.get('psscan',''))})" for r in critical_evidence]
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
        # Ensure that "(deleted)" paths are prominently displayed
        deleted_paths = [p for p in unique_paths if "(deleted)" in p.lower()]
        other_paths = [p for p in unique_paths if "(deleted)" not in p.lower()]

        display_lines = []
        if deleted_paths:
            display_lines.append(f"<b>Deleted files still in memory:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in deleted_paths[:2]])

        if other_paths and len(display_lines) < 3: # Add more general suspicious files if space
            display_lines.append(f"<b>Other suspicious paths:</b>")
            display_lines.extend([f"`{html_escape(p)}`" for p in other_paths[:(3 - len(display_lines))]])

        if len(unique_paths) > 3:
            display_lines.append(f"...and {len(unique_paths)-len(display_lines) + (2 if deleted_paths else 0)} more.") # Adjust count based on initial selection

        if not display_lines:
            return f"<p>Suspicious files found: See full details in raw artifacts.</p>"

        return f"<p>Suspicious files found:</p><ul>{''.join(f'<li>{item}</li>' for item in display_lines)}</ul>"

    if finding_id == "registry_recentdocs_py_exe":
        decoded_paths = []
        for r in evidence:
            # The eng_registry_printkey_matches now extracts 'Decoded' more cleanly
            if r.get('Decoded'):
                decoded_paths.append(r['Decoded'])
        lines = [f"File: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3:
            lines.append(f"...and {len(decoded_paths)-3} more.")
        return f"<p>Accessed files:</p><ul>{''.join(f'<li>{item}</li>' for item in lines)}</ul>"

    if finding_id == "userassist_suspicious":
        decoded_paths = []
        for r in evidence:
            # Path should now contain the cleaner extracted path from eng_userassist_suspicious
            clean_path = Path(r.get('Path', '')).name # Just get the basename
            if clean_path:
                decoded_paths.append(clean_path)
        lines = [f"Program: `{html_escape(path)}`" for path in list(set(decoded_paths))[:3]]
        if len(decoded_paths) > 3:
            lines.append(f"...and {len(decoded_paths)-3} more.")
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
        print(f"[DEBUG_TRACE] Processing network_evidence_list for HTML: {network_evidence_list}")
        for r in network_evidence_list: # Loop over the actual network evidence items
            # Ensure proper handling of 'N/A' for reputation color
            reputation_color = "#EF4444" if r.get('reputation') == "Malicious" else \
                               "#F59E0B" if r.get('reputation') == "Suspicious" else \
                               "#34D399" if r.get('reputation') == "Clean" else "#9CA3AF" # Default to gray for N/A

            table_rows += f"""
<tr>
  <td>{html_escape(r.get('pid', 'N/A'))}</td>
  <td>{html_escape(r.get('owner', 'N/A'))}</td>
  <td>{html_escape(r.get('ip', 'N/A'))}</td>
  <td>{html_escape(r.get('country', 'N/A'))}</td>
  <td>{html_escape(r.get('isp', 'N/A'))}</td>
  <td style="color: {reputation_color}; font-weight: bold;">{html_escape(r.get('reputation', 'N/A'))}</td>
</tr>
"""
        return f"""
<p>Malicious IPs identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">PID</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Owner</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">IP</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Country</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">ISP</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Reputation</th>
  </tr>
  {table_rows}
</table>
"""
    if finding_id == "suspicious_port_activity":
        table_rows = ""
        for r in evidence:
            # Filter out port '0' for display as well
            local_port_display = html_escape(r['LocalPort']) if r.get('LocalPort') and str(r['LocalPort']).strip() != '0' else 'N/A'
            foreign_port_display = html_escape(r['ForeignPort']) if r.get('ForeignPort') and str(r['ForeignPort']).strip() != '0' else 'N/A'

            table_rows += f"""
<tr>
  <td>{html_escape(r['pid'])}</td>
  <td>{html_escape(r['owner'])}</td>
  <td>{html_escape(r['Proto'])}</td>
  <td>{local_port_display}</td>
  <td>{foreign_port_display}</td>
</tr>
"""
        return f"""
<p>Connections on suspicious ports identified:</p>
<table style="width:100%; border-collapse:collapse;">
  <tr>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">PID</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Owner</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Proto</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Local Port</th>
    <th style="padding:4px 6px; border-bottom: 1px solid #1f2937;">Foreign Port</th>
  </tr>
  {table_rows}
</table>
"""
    if finding_id == "bash_history_suspicious": # New HTML renderer for bash history
        display_items = [f"User: **{html_escape(r['User'])}** - Command: `{html_escape(r['Command'])}`" for r in evidence[:5]]
        if len(evidence) > 5:
            display_items.append(f"...and {len(evidence)-5} more.")
        return f"<p>Suspicious commands found in Bash history:</p><ul>{''.join(f'<li>{item}</li>' for item in display_items)}</ul>"

    if finding_id.startswith("correlation"):
        correlated_pids = evidence[0].get("correlated_pid", "N/A")
        correlated_info = evidence[0].get("correlated_findings", [])

        details_html = ""
        for info in correlated_info:
            details_html += f"<li><b>{html_escape(info.get('title'))}:</b> {html_escape(json.dumps(info.get('evidence'), ensure_ascii=False))}</li>"

        return f"<p>Correlated PID: <b>{html_escape(correlated_pids)}</b></p><ul>{details_html}</ul>"

    # Default rendering for other findings
    if len(evidence) == 1:
        return f"<pre style=\"white-space:pre-wrap;margin:0\">{html_escape(json.dumps(evidence[0], ensure_ascii=False, indent=2))}</pre>"
    else:
        return f"<p>Multiple evidence items. See raw artifacts for full details.</p>"


def render_html_explanation(finding_id: str, finding: Dict[str, Any], detections_config: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    """Provides a human-readable explanation (narrative) for each finding by looking up in detections_config."""
    # Find the rule in the detections_config
    original_narrative = "No specific narrative available for this finding."
    for os_profile in detections_config.get('os_profiles', {}).values():
        for rule in os_profile.get('detections', []):
            if rule.get('id') == finding_id:
                original_narrative = rule.get('narrative', original_narrative)
                break
        if original_narrative != "No specific narrative available for this finding.":
            break

    # Custom logic for suspicious_port_activity to refine C2 language for local connections
    if finding_id == "suspicious_port_activity":
        is_local_only = True
        allow_cidrs = baseline_config.get("network", {}).get("allow_cidrs", []) or []
        for ev_item in finding.get('evidence', []):
            foreign_addr = ev_item.get('ForeignAddr', '').strip() or ev_item.get('ip', '').strip()
            # If there's any foreign address that is NOT local/internal, it's not purely local.
            # Also check if LocalPort is present and ForeignPort is not, suggesting a local listener
            if foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                is_local_only = False
                break
            # If it's a local address and there's no foreign address, it's likely a listener.
            if (foreign_addr in ["0.0.0.0", "127.0.0.1", "::"] or in_cidrs(foreign_addr, allow_cidrs)) and not ev_item.get('ForeignPort'):
                 is_local_only = True # Re-confirm local only for listeners
            # If both local and foreign exist, and foreign is NOT local, then not local-only
            if ev_item.get('LocalPort') and ev_item.get('ForeignPort') and foreign_addr and foreign_addr not in ["0.0.0.0", "127.0.0.1", "::"] and not in_cidrs(foreign_addr, allow_cidrs):
                 is_local_only = False
                 break


        if is_local_only:
            # Rephrase for local-only suspicious ports
            return "A process was observed communicating or listening on a port that is commonly associated with unusual internal services or local debugging activity. While unusual, this does not directly indicate external command and control (C2) communication unless coupled with further evidence of external connections."
    
    return original_narrative # Return original if not this specific finding or not purely local


def render_html(case: str, profile: str, score_sum: int, band: str, findings: List[Dict[str, Any]], detections_config: Dict[str, Any], ai_verdict_data: Dict[str, Any], baseline_config: Dict[str, Any]) -> str:
    # Prepare the list of narratives for the summary section
    narrative_list_html = ""
    if findings:
        for f in sorted(findings, key=lambda x: x.get('weight', 0), reverse=True):
            # Pass baseline_config to render_html_explanation
            narrative = render_html_explanation(f.get('id', ''), f, detections_config, baseline_config)
            narrative_list_html += f"<li>**{html_escape(f.get('title', f.get('id')))}**: {html_escape(narrative)}</li>"

    if not narrative_list_html:
        narrative_list_html = "<li>No significant findings detected in this memory image.</li>"

    # AI Verdict Section HTML
    ai_verdict_html = ""
    # Ensure ai_verdict_data is not empty or default before rendering
    if ai_verdict_data and ai_verdict_data.get('verdict') != 'N/A' and ai_verdict_data.get('plain_summary') != 'No AI verdict generated.':
        verdict = html_escape(ai_verdict_data.get('verdict', 'N/A'))
        plain_summary_content = html_escape(ai_verdict_data.get('plain_summary', 'N/A'))
        
        key_findings_list_html = ""
        if ai_verdict_data.get('key_findings'):
            key_findings_list_html = "<ul>" + "".join([f"<li>{html_escape(f)}</li>" for f in ai_verdict_data['key_findings']]) + "</ul>"

        attack_chain_html = ""
        if ai_verdict_data.get('attack_chain'):
            attack_chain_html = "<h3>Attack Chain</h3><ol>"
            for step in ai_verdict_data['attack_chain']:
                time_info = html_escape(step.get('time_utc', 'unknown'))
                
                actor_process = html_escape(step['actor'].get('process', 'unknown'))
                actor_pid = html_escape(str(step['actor'].get('pid', 'unknown')))
                actor_ppid = html_escape(str(step['actor'].get('ppid', 'unknown')))
                actor_user = html_escape(step['actor'].get('user', 'unknown'))

                actor_info_parts = []
                if actor_process != 'unknown': actor_info_parts.append(f"Process: {actor_process}")
                if actor_pid != 'unknown': actor_info_parts.append(f"PID: {actor_pid}")
                if actor_ppid != 'unknown': actor_info_parts.append(f"PPID: {actor_ppid}")
                if actor_user != 'unknown': actor_info_parts.append(f"User: {actor_user}")
                actor_info_str = ", ".join(actor_info_parts) if actor_info_parts else "Unknown Actor"


                action_info = html_escape(step.get('action', 'unknown'))

                target_info = ""
                target_process = html_escape(step.get('target', {}).get('process', 'unknown'))
                target_pid = html_escape(str(step.get('target', {}).get('pid', 'unknown')))
                target_object = html_escape(step.get('target', {}).get('object', 'unknown'))
                
                target_info_parts = []
                if target_process != 'unknown': target_info_parts.append(f"Process: {target_process}")
                if target_pid != 'unknown': target_info_parts.append(f"PID: {target_pid}")
                if target_object != 'unknown': target_info_parts.append(f"Object: {target_object}")
                target_info_str = ", ".join(target_info_parts) if target_info_parts else "Unknown Target"

                correlation_note = ""
                if step.get('correlation_id') and step['correlation_id'] != 'none':
                    correlation_note = f" (Correlated from {html_escape(step['correlation_id'].replace('correlation_', '').replace('_', ' '))})"


                attack_chain_html += f"<li>[{time_info}] {actor_info_str} -> {action_info}. Target: [{target_info_str}]{correlation_note}</li>"
            attack_chain_html += "</ol>"
            if ai_verdict_data.get('approx_ordering'):
                attack_chain_html += "<small><i>Note: Attack chain ordering is approximate due to missing or inconsistent timestamps.</i></small>"


        malware_match = html_escape(ai_verdict_data.get('malware_match', 'None apparent'))
        confidence = html_escape(ai_verdict_data.get('confidence', 'N/A'))

        anomalies_html = ""
        if ai_verdict_data.get('anomalies', {}).get('flags') or ai_verdict_data.get('anomalies', {}).get('corrections'):
            anomalies_html = "<h3>Anomalies and Corrections</h3>"
            if ai_verdict_data['anomalies'].get('flags'):
                anomalies_html += "<p><b>Flags (Inconsistent Data):</b></p><ul>"
                anomalies_html += "".join([f"<li>{html_escape(f)}</li>" for f in ai_verdict_data['anomalies']['flags']]) + "</ul>"
            if ai_verdict_data['anomalies'].get('corrections'):
                anomalies_html += "<p><b>Corrections Made:</b></p><ul>"
                anomalies_html += "".join([f"<li>Field: {html_escape(c['field'])}, Original: `{html_escape(c['original'])}`, Corrected: `{html_escape(c['corrected'])}` ({html_escape(c['reason'])})</li>" for c in ai_verdict_data['anomalies']['corrections']]) + "</ul>"

        glossary_html = ""
        if ai_verdict_data.get('glossary'):
            glossary_html = "<h3>Glossary</h3><ul>"
            for term, explanation in ai_verdict_data['glossary'].items():
                glossary_html += f"<li><b>{html_escape(term)}:</b> {html_escape(explanation)}</li>"
            glossary_html += "</ul>"


        ai_verdict_html = f"""
  <div class="card" style="background-color: #36454F; color: #F5F5DC;">
    <h2>AI Verdict: {verdict}</h2>
    <p><b>Summary:</b> {plain_summary_content}</p>
    <h3>Key Findings</h3>
    {key_findings_list_html}
    {attack_chain_html}
    <p><b>Potential Malware Family Match:</b> {malware_match} (Confidence: {confidence})</p>
    {anomalies_html}
    {glossary_html}
    <small><i>Powered by OpenAI GPT. Please cross-reference with detailed findings.</i></small>
  </div>
"""

    rows = []
    sorted_findings = sorted(findings, key=lambda f: f.get('weight', 0), reverse=True)

    for f in sorted_findings:
        evidence_html = render_html_evidence(f.get('id',''), f.get('evidence', []))
        # Pass baseline_config to render_html_explanation
        explanation_html = render_html_explanation(f.get('id',''), f, detections_config, baseline_config)

        # Fix: Join the MITRE TTPs list into a string before passing to html_escape
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

  {ai_verdict_html} <!-- AI Verdict Section -->

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
    ap = argparse.ArgumentParser(description="Volatility detections CLI")
    ap.add_argument("--image", required=True, help="Memory image path (e.g., memory.raw)")
    ap.add_argument("--case", default="case1")
    ap.add_argument("--detections", default="detections.yaml")
    ap.add_argument("--baseline", default="baseline.yaml")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--api-key", default="", help="API key for IP enrichment services (optional).")
    ap.add_argument("--openai-api-key", default="", help="OpenAI API key for AI-powered verdict (optional).") # NEW: OpenAI API key
    args = ap.parse_args() # Corrected from ap.ap_arg.parse_args()

    outdir = Path(args.outdir)
    ensure_dirs(outdir)

    # Load detections config once and pass it around
    detections_config_path = Path(args.detections)
    if not detections_config_path.exists():
        print(f"Error: Detections file not found at {detections_config_path}", file=sys.stderr)
        sys.exit(1)
    print(f"[DEBUG] Loading detections from: {detections_config_path}")
    det = yaml.safe_load(detections_config_path.read_text())
    print(f"[DEBUG] Detections config loaded: {json.dumps(det, indent=2)[:500]}...")


    base = yaml.safe_load(Path(args.baseline).read_text())
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
    print(f"[DEBUG] Plugins to run for {oskey} profile: {[p['name'] for p in plugins]}")

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
        
        # ADDED DEBUG PRINT for captured content
        if content:
            print(f"[DEBUG] Captured content for {used} (first 200 chars):\n{content[:200]}...")
        else:
            print(f"[DEBUG] Captured content for {used} is EMPTY or None.")


    from io import StringIO # Moved import here to resolve error with parse_csv

    def get_csv(name):
        print(f"[DEBUG] Attempting to get CSV for: {name}")
        content_info = cache_outputs.get(name, {})
        if not content_info:
            print(f"[DEBUG] No content found in cache for {name}.")
            return []
        if content_info.get("format") != "csv":
            print(f"[DEBUG] Cached format for {name} is {content_info.get('format')}, not CSV. Skipping parse_csv.")
            return []
        parsed_data = parse_csv(content_info.get("content", ""))
        print(f"[DEBUG] get_csv for {name}: Parsed {len(parsed_data)} rows. (from cache or actual plugin output)")
        return parsed_data

    def get_txt(name):
        print(f"[DEBUG] Attempting to get TXT for: {name}")
        content_info = cache_outputs.get(name, {})
        if not content_info:
            print(f"[DEBUG] No content found in cache for {name}.")
            return ""
        content = content_info.get("content", "")
        print(f"[DEBUG] get_txt for {name}: Content length {len(content)}.")
        return content

    detections_cfg = os_prof.get("detections", [])
    findings = []
    score = 0

    # First pass: run individual rules
    for rule in detections_cfg:
        if not rule.get("enabled", True):
            continue
        rid   = rule["id"]
        title = rule.get("title", rid)
        weight= int(rule.get("weight", 1))
        mitre = rule.get("mitre", []) # Changed to list here
        ev = []

        # Special handling for network_enrichment engine: it's a master engine that applies all rules of its type
        if rule.get("engine") == "network_enrichment":
            # This rule will be handled by the master engine below.
            continue
        
        # Skip correlation rules for the first pass
        if rid.startswith("correlation_"):
            continue

        print(f"[i] Running detection engine: {rid}")
        try:
            if rid == "process_pid_match":
                ps = get_csv("windows.pslist") if oskey == "windows" else get_csv(f"{oskey}.pslist")
                params = rule.get("params", {})
                ev = eng_process_pid_match(ps, params.get("target_pid"))

            elif rid == "unknown_process_name":
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                ev = eng_unknown_process_name(ps, base, oskey)

            elif rid == "psxview_hidden":
                rows = get_csv("windows.psxview")
                ev = eng_psxview_hidden(rows)

            elif rid == "suspicious_port_activity":
                print("[DEBUG] Calling get_csv for network data (suspicious_port_activity).")
                if oskey == "windows":
                    if "windows.netstat" in cache_outputs:
                        rows = get_csv("windows.netstat")
                    elif "windows.netscan" in cache_outputs:
                        rows = get_csv("windows.netscan")
                    else:
                        rows = []
                else:
                    rows = get_csv(f"{oskey}.netstat") if f"{oskey}.netstat" in cache_outputs else []
                print(f"[DEBUG] Suspicious_port_activity received {len(rows)} parsed rows for processing.")
                params = rule.get("params", {})
                ev = eng_suspicious_port_activity(rows, params.get("suspicious_ports", []))

            elif rid == "suspicious_connection": # This is the old generic network connection rule
                print("[DEBUG] Calling get_csv for network data (suspicious_connection).")
                if oskey == "windows":
                    if "windows.netstat" in cache_outputs:
                        rows = get_csv("windows.netstat")
                    elif "windows.netscan" in cache_outputs:
                        rows = get_csv("windows.netscan")
                    else:
                        rows = []
                else:
                    rows = get_csv(f"{oskey}.netstat") if f"{oskey}.netstat" in cache_outputs else []
                print(f"[DEBUG] Suspicious_connection received {len(rows)} parsed rows for processing.")
                ev = eng_suspicious_connection(rows, base)

            elif rid == "malfind_injection":
                params = rule.get("params", {})
                kws = params.get("keywords", [])
                text = get_txt("windows.malfind") if oskey=="windows" else get_txt(f"{oskey}.malfind")
                ev = eng_malfind_injection(text, kws)

            elif rid == "hollowed_process":
                params = rule.get("params", {})
                kws = params.get("keywords", [])
                text = get_txt("windows.hollowprocesses")
                ev = eng_hollowed_process(text, kws)

            elif rid == "ldr_unlinked_module":
                params = rule.get("params", {})
                paths = params.get("temp_like_paths", [])
                text = get_txt("windows.ldrmodules")
                ev = eng_ldr_unlinked_module(text, paths)

            elif rid == "handles_dangerous_access":
                params = rule.get("params", {})
                access_rx = params.get("access_regex","")
                text = get_txt("windows.handles")
                ev = eng_handles_general(text, access_rx)

            elif rid == "handles_lsass_access":
                params = rule.get("params", {})
                access_rx = params.get("access_regex","")
                target_rx = params.get("target_process_regex","(?i)^lsass\\.exe$")
                text = get_txt("windows.handles")
                ev = eng_handles_general(text, access_rx, target_rx, lsass_special=True)

            elif rid == "services_suspicious":
                rows = get_csv("windows.svcscan") # Now reads CSV
                paths = rule.get("params", {}).get("temp_like_paths", [])
                ev = eng_services_suspicious(rows, paths) # Pass rows instead of text

            elif rid == "scheduled_tasks_suspicious":
                text = get_txt("windows.scheduled_tasks") or get_txt("windows.registry.scheduled_tasks")
                params = rule.get("params", {})
                ev = eng_scheduled_tasks(text, params.get("temp_like_paths", []), params.get("risky_exts", []))

            elif rid == "filescan_suspicious_names":
                text = get_txt("windows.filescan") if oskey=="windows" else get_txt(f"{oskey}.pagecache.Files")
                params = rule.get("params", {})
                ev = eng_filescan(text,
                                  params.get("any_path_contains", []),
                                  params.get("any_file_ext", []),
                                  params.get("any_name_contains", []))

            elif rid == "registry_recentdocs_py_exe":
                params = rule.get("params", {})
                keys = params.get("keys", [])
                value_regex = params.get("value_regex","")
                ev = eng_registry_printkey_matches(vol, args.image, outdir, keys, value_regex)

            elif rid == "registry_run_key_persistence":
                params = rule.get("params", {})
                keys = params.get("keys", [])
                value_regex = params.get("value_regex","")
                ev = eng_registry_printkey_matches(vol, args.image, outdir, keys, value_regex)

            elif rid == "userassist_suspicious":
                text = get_txt("windows.registry.userassist")
                params = rule.get("params", {})
                ev = eng_userassist_suspicious(text, params.get("any_path_contains", []))

            elif rid == "exec_from_tmp":
                ps = get_csv("windows.pslist") if oskey=="windows" else get_csv(f"{oskey}.pslist")
                params = rule.get("params", {})
                rx = compile_any_contains_to_regex(params.get("temp_like_paths", []))
                tmp_ev = []
                for r in ps:
                    name = r.get("ImageFileName","") or r.get("Name","")
                    pid  = r.get("PID","")
                    path = r.get("Path","")
                    line = f"{name} {path}"
                    if rx and rx.search(line.lower()):
                        tmp_ev.append({"pid": pid, "name": name, "path": path})
                ev = tmp_ev

            elif rid == "suspicious_cmdline_args":
                cmdline_data = get_csv("windows.cmdline") # Get data from windows.cmdline
                params = rule.get("params", {})
                ev = eng_suspicious_cmdline(cmdline_data, params.get("suspicious_keywords", [])) # Pass cmdline_data

            elif rid == "unusual_parent_child":
                ps = get_csv("windows.pslist") # Still uses pslist for parent-child
                ev = eng_unusual_parent_child(ps, rule.get("params",{}).get("pairs",[]))

            elif rid == "sessions_anomalous":
                rows = get_csv("windows.sessions")
                params = rule.get("params", {})
                ev = eng_sessions_anomalous(rows,
                                            base.get("sessions",{}).get("ignore_users",[]),
                                            params.get("suspicious_auth_packages", []))

            elif rid == "dumpit_present":
                text = get_txt("windows.filescan") if oskey=="windows" else get_txt(f"{oskey}.pagecache.Files")
                params = rule.get("params", {})
                ev = eng_filescan(text,
                                  params.get("any_path_contains", []),
                                  params.get("any_file_ext", []),
                                  params.get("any_name_contains", []))


            # Linux/macOS specific engines
            elif rid == "linux_hidden_process":
                # Placeholder logic - assuming pslist/psscan available
                pslist_data = get_csv("linux.pslist")
                psscan_data = get_csv("linux.psscan")
                # Simple check for demo: find PIDs in psscan but not pslist
                pslist_pids = {r.get('PID') for r in pslist_data if r.get('PID')}
                psscan_pids = {r.get('PID') for r in psscan_data if r.get('PID')}
                hidden_pids = psscan_pids - pslist_pids

                ev = []
                for r in psscan_data:
                    if r.get('PID') in hidden_pids:
                        ev.append({
                            "pid": r.get('PID'),
                            "name": r.get('COMM'), # Linux processes have 'COMM' not ImageFileName
                            "pslist_present": "False",
                            "psscan_present": "True"
                        })

            elif rid == "linux_syscall_hooks":
                # This engine would parse linux.check_syscall output
                text = get_txt("linux.check_syscall")
                # Dummy logic: find lines containing "hooked"
                ev = [{"Details": line.strip()} for line in text.splitlines() if "hooked" in line.lower()]

            elif rid == "linux_unsigned_module":
                # This engine would parse linux.check_modules output
                text = get_txt("linux.check_modules")
                # Dummy logic: find lines containing "unsigned" or "taint"
                ev = [{"Details": line.strip()} for line in text.splitlines() if "unsigned" in line.lower() or "taint" in line.lower()]

            elif rid == "lsof_suspicious_open":
                text = get_txt("linux.lsof") if oskey == "linux" else get_txt("mac.lsof") # Common for Linux/macOS
                params = rule.get("params", {})
                any_path_contains = params.get("any_path_contains", [])
                any_name_contains = params.get("params", {}).get("any_name_contains", [])

                # Placeholder for eng_lsof_suspicious_open - needs to be defined
                # For now, a generic placeholder
                ev = []
                # if text:
                #     for line in text.splitlines():
                #         if any(p.lower() in line.lower() for p in any_path_contains) or \
                #            any(n.lower() in line.lower() for n in any_name_contains):
                #             ev.append({"Details": line.strip()})


            elif rid == "exec_from_tmp":
                ps = get_csv("linux.pslist") if oskey == "linux" else get_csv("mac.pslist")
                params = rule.get("params", {})
                rx = compile_any_contains_to_regex(params.get("temp_like_paths", []))
                tmp_ev = []
                for r in ps:
                    name = r.get("COMM","") # Linux/macOS processes use COMM
                    pid  = r.get("PID","")
                    path = r.get("PATH","") # Some pslist variants have PATH
                    cmdline = r.get("COMMAND","") # Common for linux.psaux, but pslist might have it

                    line_to_check = f"{name} {path} {cmdline}"
                    if rx and rx.search(line.lower()):
                        tmp_ev.append({"pid": pid, "name": name, "path": path, "cmdline": cmdline})
                ev = tmp_ev

            elif rid == "bash_history_suspicious": # New engine call
                if oskey == "linux":
                    text = get_txt("linux.bash")
                elif oskey == "macos":
                    text = get_txt("mac.bash")
                else:
                    text = "" # No bash history for Windows

                params = rule.get("params", {})
                ev = eng_bash_history_grep(text, params.get("suspicious_keywords", []))

        except Exception as e:
            print(f"[warn] Engine {rid} failed: {e}")
            print(f"[DEBUG] Full traceback for engine {rid} failure:", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

        if ev:
            findings.append({
                "id": rid,
                "title": title,
                "mitre": mitre,
                "weight": weight,
                "evidence": ev
            })
            score += weight
        print(f"[i] Finished detection engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")


    # Now run the master network enrichment engine, passing all network-related rules
    print(f"[i] Running master network enrichment engine...")
    network_enrichment_rules = [r for r in detections_cfg if r.get("engine") == "network_enrichment" and r.get("enabled", True)]
    
    if oskey == "windows":
        if "windows.netstat" in cache_outputs:
            netstat_rows_for_master_engine = get_csv("windows.netstat")
        elif "windows.netscan" in cache_outputs:
            netstat_rows_for_master_engine = get_csv("windows.netscan")
        else:
            netstat_rows_for_master_engine = []
    else:
        netstat_rows_for_master_engine = get_csv(f"{oskey}.netstat") if f"{oskey}.netstat" in cache_outputs else []

    if network_enrichment_rules and netstat_rows_for_master_engine:
        # Call the master engine once, it will apply all network_enrichment rules
        network_findings = eng_network_enrichment_master(netstat_rows_for_master_engine, network_enrichment_rules, base, args.api_key)
        for fnd in network_findings:
            findings.append(fnd)
            score += fnd["weight"]
    print(f"[i] Finished master network enrichment engine. Current total score: {score}. Total network findings generated: {len(network_findings)}")


    # Second pass: run correlation rules
    print(f"[i] Starting correlation analysis...")
    for rule in detections_cfg:
        if not rule.get("enabled", True):
            continue
        rid = rule["id"]

        # Only process correlation rules in the second pass
        if not rid.startswith("correlation_"):
            continue

        title = rule.get("title", rid)
        weight = int(rule.get("weight", 1))
        mitre = rule.get("mitre", []) # Changed to list here
        ev = []

        print(f"[i] Running correlation engine: {rid}")
        try:
            if rid.startswith("correlation_"):
                params = rule.get("params", {})
                ev = eng_correlated_findings(findings, params.get("correlation_pairs", []))

        except Exception as e:
            print(f"[warn] Correlation engine {rid} failed: {e}")
            print(f"[DEBUG] Full traceback for correlation engine {rid} failure:", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

        if ev:
            findings.append({
                "id": rid,
                "title": title,
                "mitre": mitre,
                "weight": weight,
                "evidence": ev
            })
            score += weight
        print(f"[i] Finished correlation engine: {rid}. Current total score: {score}. Findings generated: {len(ev)}")

    # Generate AI verdict if OpenAI API key is provided
    # Initialize with default_ai_response to ensure all keys are present
    ai_verdict_data = {"verdict": "N/A", "plain_summary": "No AI verdict generated.", "malware_match": "None apparent", "confidence": "N/A", "key_findings": [], "attack_chain": [], "anomalies": {"flags": [], "corrections": []}, "glossary": {}, "approx_ordering": True} 

    if args.openai_api_key:
        print("[info] Attempting to generate AI verdict using OpenAI GPT...")
        ai_verdict_data = get_ai_verdict(findings, args.openai_api_key)
        
        # Log parsed data for debugging
        print(f"[info] AI Verdict: {ai_verdict_data.get('verdict')}")
        print(f"[info] AI Plain Summary: {ai_verdict_data.get('plain_summary')}")
        print(f"[info] AI Key Findings: {ai_verdict_data.get('key_findings')}")
        print(f"[info] AI Attack Chain (steps): {len(ai_verdict_data.get('attack_chain', []))}")
        print(f"[info] AI Malware Match: {ai_verdict_data.get('malware_match')} (Confidence: {ai_verdict_data.get('confidence')})")
        print(f"[info] AI Anomalies Flags: {ai_verdict_data.get('anomalies', {}).get('flags')}")
        print(f"[info] AI Anomalies Corrections: {ai_verdict_data.get('anomalies', {}).get('corrections')}")
        print(f"[info] AI Glossary (terms): {len(ai_verdict_data.get('glossary', {}))}")
        print(f"[info] AI Approx Ordering: {ai_verdict_data.get('approx_ordering')}")


        # FIX: Save AI verdict data to a file for app.py to read
        ai_verdict_path = outdir / "ai_verdict.json"
        try:
            with open(ai_verdict_path, 'w', encoding='utf-8') as f:
                json.dump(ai_verdict_data, f, ensure_ascii=False, indent=2)
            print(f"[info] AI verdict saved to: {ai_verdict_path}")
        except Exception as e:
            print(f"[warn] Could not save AI verdict to file: {e}", file=sys.stderr)


    bands = (base.get("report", {}).get("severity_bands") or
             det.get("scoring", {}).get("severity_bands") or [])
    band_label = "Unknown"
    for band in bands:
        if score <= int(band["max"]):
            band_label = band["label"]
            break

    findings_path = outdir / "findings.jsonl"
    with findings_path.open("w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd, ensure_ascii=False) + "\n")

    print("\n=== SUMMARY ==O")
    print(f"Score: {score}  => Severity: {band_label}")
    print(f"Raw artifacts: {outdir/'artifacts'}")
    print(f"Findings JSONL: {findings_path}")
    # FIX: Ensure html_path is defined before trying to print it.
    html_path = outdir / "report.html" # Redefine html_path here to ensure it's always available
    write_file(html_path, render_html(args.case, oskey, score, band_label, findings, det, ai_verdict_data, base))
    print(f"HTML report: {html_path}")

if __name__ == "__main__":
    main()


