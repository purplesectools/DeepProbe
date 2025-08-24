import streamlit as st
import subprocess
import sys
import time
import re
import base64
from pathlib import Path
import os
import json
import yaml
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from streamlit.components.v1 import html
from datetime import datetime

# --- Configuration ---
BASE_DIR = Path(__file__).parent
CLI_SCRIPT_PATH = BASE_DIR / "runner.py"
MEMORY_FOLDER = BASE_DIR / "memory"
OUTPUT_FOLDER = BASE_DIR / "out" # Base output directory

# Ensure necessary directories exist at startup.
try:
    MEMORY_FOLDER.mkdir(exist_ok=True)
    OUTPUT_FOLDER.mkdir(exist_ok=True)
except Exception as e:
    print(f"FATAL ERROR: Could not create necessary directories for DeepProbe. Please check file system permissions. Error: {e}", file=sys.stderr)
    st.error(f"Initialization Error: DeepProbe could not create essential directories ('memory/', 'out/'). "
             f"Please verify your file system permissions in the directory where you are running the app. Error: {e}")
    st.stop()

# --- Backend and Reporting Helper Functions ---
def html_escape(text):
    """Escapes HTML special characters in a string to prevent misinterpretation as HTML or links."""
    if text is None:
        return ""
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')

def get_friendly_scan_name(plugin_name):
    """Maps technical plugin names to user-friendly descriptions."""
    mapping = {
        "windows.info": "Detecting operating system...",
        "windows.pslist": "Analyzing running processes...",
        "windows.psxview": "Scanning for hidden processes...",
        "windows.netscan": "Investigating network connections...",
        "windows.netstat": "Checking network statistics...",
        "windows.malfind": "Searching for injected code...",
        "windows.hollowprocesses": "Checking for hollowed processes...",
        "windows.ldrmodules": "Analyzing loaded modules for unlinked DLLs...",
        "windows.handles": "Inspecting process handles for suspicious access...",
        "windows.svcscan": "Scans system services...",
        "windows.scheduled_tasks": "Reviewing scheduled tasks for persistence...",
        "windows.filescan": "Scanning for suspicious files in memory...",
        "windows.registry.printkey": "Querying registry keys for anomalies...",
        "windows.registry.userassist": "Analyzing user execution history...",
        "windows.sessions": "Inspecting user logon sessions...",
        "linux.pslist": "Analyzing Linux processes...",
        "linux.psscan": "Scanning Linux for hidden processes...",
        "linux.lsof": "Checking Linux open files and network connections...",
        "linux.sockstat": "Analyzing Linux socket statistics...",
        "linux.check_syscall": "Checking system call table integrity for potential hooks on Linux.",
        "linux.check_modules": "Checking Linux kernel modules...",
        "linux.bash": "Analyzing Linux Bash history...",
        "mac.pslist": "Analyzing macOS processes...",
        "mac.lsof": "Checking macOS open files and network connections...",
        "mac.netstat": "Checking macOS network statistics...",
        "mac.malfind": "Searching macOS for injected code...",
        "mac.bash": "Analyzing macOS Bash history...",
        "windows.dlllist": "Listing loaded DLLs for Windows processes...",
        "windows.apihooks": "Detecting Windows API hooks...",
        "windows.devicetree": "Analyzing Windows device tree...",
        "windows.modscan": "Scanning Windows kernel modules...",
        "windows.consoles": "Recovers Windows console history...",
        "windows.clipboard": "Recovers Windows clipboard contents...",
        "windows.registry.shimcache": "Analyzing Windows Shimcache for execution artifacts...",
        "windows.registry.amcache": "Analyzing Windows Amcache for execution artifacts...",
        "windows.envars": "Listing Windows environment variables...",
        "windows.callbacks": "Analyzing Windows kernel callbacks...",
        "linux.envars": "Listing Linux environment variables...",
        "linux.librarylist": "Enumerating Linux shared libraries...",
        "linux.lsmod": "Listing Linux loaded kernel modules...",
        "mac.sessions": "Listing macOS user sessions...",
        "mac.mount": "Displaying macOS mounted filesystems...",
        "mac.volumes": "Listing macOS volumes...",
        "mac.dmesg": "Recovers macOS kernel ring buffer messages...",
    }
    return mapping.get(plugin_name, f"Running scan: {plugin_name}...")

def run_analysis_and_show_progress(case_name, memory_file_path, ip_enrichment_api_key, openai_api_key, progress_bar, status_text):
    """
    Executes the backend analysis script, captures its output in real-time,
    and updates the UI with progress. Includes a timeout.
    """
    # Dynamically define the output paths based on the project name
    project_output_folder = OUTPUT_FOLDER / case_name
    project_artifacts_folder = project_output_folder / "artifacts"

    # Ensure the project-specific directories exist
    project_output_folder.mkdir(exist_ok=True)
    project_artifacts_folder.mkdir(exist_ok=True)

    for p in [CLI_SCRIPT_PATH]:
        if not p.exists():
            status_text.error(f"FATAL ERROR: A required script '`{html_escape(p.name)}`' was not found.")
            return False
    
    # Check if detections.yaml and baseline.yaml exist at BASE_DIR
    if not (BASE_DIR / "detections.yaml").exists():
        status_text.error(f"FATAL ERROR: '`detections.yaml`' not found at '`{html_escape(str(BASE_DIR))}`'.")
        return False
    if not (BASE_DIR / "baseline.yaml").exists():
        status_text.error(f"FATAL ERROR: '`baseline.yaml`' not found at '`{html_escape(str(BASE_DIR))}`'.")
        return False

    cmd = [
        sys.executable, '-u', str(CLI_SCRIPT_PATH),
        "--image", str(memory_file_path), "--case", case_name,
        "--detections", str(BASE_DIR / "detections.yaml"),
        "--baseline", str(BASE_DIR / "baseline.yaml"),
        "--outdir", str(project_output_folder),
        "--api-key", ip_enrichment_api_key
    ]

    # Add OpenAI API key if provided
    if openai_api_key:
        cmd.extend(["--openai-api-key", openai_api_key])

    st.session_state.analysis_logs = []
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace', bufsize=1
    )

    TOTAL_STEPS = 20
    current_step = 0
    status_text.info("Preparing analysis environment...")

    for line in iter(process.stdout.readline, ''):
        st.session_state.analysis_logs.append(line)
        if "[+] Running plugin:" in line:
            current_step += 1
            try:
                plugin_name = line.split(":", 1)[1].strip().split(" ")[0]
                friendly_name = get_friendly_scan_name(plugin_name)
                status_text.info(friendly_name)
            except IndexError:
                pass
            progress_fraction = min(1.0, current_step / TOTAL_STEPS)
            progress_percent = int(progress_fraction * 100)
            progress_bar.progress(progress_fraction, text=f"{progress_percent}% Complete")
        if "[i] Running detection engine:" in line or "[i] Starting correlation analysis:" in line:
            status_text.info(line.strip().replace("[i] ", ""))

    try:
        process.wait(timeout=900)
    except subprocess.TimeoutExpired:
        process.kill()
        status_text.error("Analysis Timed Out after 15 minutes. The memory image may be corrupt or too complex.")
        st.session_state.analysis_successful = False
        return False

    if process.returncode == 0:
        progress_bar.progress(1.0, text="100% Complete")
        status_text.success("Analysis Complete! Redirecting to results...")
        st.session_state.analysis_successful = True
        return True
    else:
        status_text.error(f"Analysis Failed. Exit code: `{html_escape(str(process.returncode))}`.")
        st.session_state.analysis_successful = False
        with st.expander("Show Error Log"):
            st.code(''.join(st.session_state.analysis_logs), language='text')
        return False

def load_findings(project_name):
    """Loads findings from the project-specific directory."""
    project_output_folder = OUTPUT_FOLDER / project_name
    findings_jsonl_path = project_output_folder / "findings.jsonl"
    
    findings = []
    if findings_jsonl_path.exists():
        with open(findings_jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"Warning: Could not decode line: {line}")
    return findings

def load_ai_verdict(project_name):
    """Loads the AI verdict data from a JSON file in the project-specific directory."""
    project_output_folder = OUTPUT_FOLDER / project_name
    ai_verdict_path = project_output_folder / "ai_verdict.json"
    
    if ai_verdict_path.exists():
        with open(ai_verdict_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Could not decode AI verdict JSON from {ai_verdict_path}")
    return {"verdict": "N/A", "plain_summary": "AI verdict not available.", "key_findings": [], "attack_chain": [], "malware_match": "None apparent", "confidence": "N/A", "anomalies": {"flags": [], "corrections": []}, "glossary": {}, "approx_ordering": True}

def load_detections_config():
    """Loads the detections.yaml config from the base directory."""
    detections_path = BASE_DIR / "detections.yaml"
    if detections_path.exists():
        with open(detections_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return None

def get_narrative(finding_id, detections_config):
    if not detections_config: return "Detections config not found."
    for os_profile in detections_config.get('os_profiles', {}).values():
        for rule in os_profile.get('detections', []):
            if rule.get('id') == finding_id:
                narrative = rule.get('narrative', 'No narrative available.')
                narrative = narrative.replace("psxview mismatch", "hidden process detection anomaly")
                narrative = narrative.replace("LdrModules", "loaded modules")
                narrative = narrative.replace("ldrmodules", "loaded modules")

                if ("network" in narrative.lower() or "c2" in narrative.lower()) and "command and control" not in narrative.lower():
                    narrative += " This communication often serves as a 'Command and Control' (C2) channel, allowing attackers to remotely send commands and receive data from compromised systems."
                return narrative
    return "Narrative not found."

def categorize_findings(findings, detections_config):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    total_score = 0
    severity_bands = detections_config.get('scoring', {}).get('severity_bands', []) if detections_config else []

    for f in findings:
        weight = f.get('weight', 0)
        total_score += weight
        for band in severity_bands:
            if weight <= int(band['max']):
                if band['label'] == "Critical": counts["Critical"] += 1
                elif band['label'] == "High": counts["High"] += 1
                elif band['label'] == "Medium": counts["Medium"] += 1
                elif band['label'] == "Low": counts["Low"] += 1
                elif band['label'] == "Informational": counts["Informational"] += 1
                break

    overall_severity = "Informational"
    for band in severity_bands:
        if total_score <= int(band['max']):
            overall_severity = band['label']
            break

    return counts, overall_severity, total_score

def get_user_friendly_correlated_title(finding_id):
    """Maps internal finding IDs to user-friendly titles for the correlated findings steps."""
    mapping = {
        'psxview_hidden': 'Hidden Process Detected',
        'suspicious_connection': 'Suspicious Network Connection',
        'suspicious_port_activity': 'Suspicious Port Usage',
        'suspicious_network_enrichment': 'Malicious IP Communication',
        'malfind_injection': 'Code Injection Found',
        'ldr_unlinked_module': 'Hidden Module Loaded',
        'suspicious_cmdline_args': 'Suspicious Command Line',
        'registry_run_key_persistence': 'Registry Persistence',
        'exec_from_tmp': 'Execution From Temp Directory',
        'filescan_suspicious_names': 'Suspicious File Found',
        'unusual_parent_child': 'Unusual Parent Process',
        'bash_history_suspicious': 'Suspicious Shell Command',
    }
    return mapping.get(finding_id, finding_id.replace('_', ' ').title())


def render_correlated_finding_narrative(finding, detections_config):
    """
    Renders a correlated finding as a narrative flow for the 'Attack Story' section.
    """
    html_content_title = f"<h4><span style='text-decoration: none; color: inherit;'>{html_escape(finding.get('title', 'Correlated Threat'))}</span></h4>"
    html(html_content_title, height=45)

    st.markdown(f"<p style='font-size: 1.1rem; color: #566573; text-decoration: none;'>{html_escape(get_narrative(finding.get('id'), detections_config))}</p>", unsafe_allow_html=True)

    evidence_list = finding.get('evidence', [])
    if not evidence_list:
        st.write("No detailed evidence for this correlated finding.")
        return

    for item in evidence_list:
        pid = item.get('correlated_pid')
        html_content_pid = f"<h5><span style='text-decoration: none; color: inherit;'>Involved Process ID (PID): `{html_escape(str(pid))}`</span></h5>"
        html(html_content_pid, height=35)
        findings_details = item.get('correlated_findings', [])

        def sort_key_correlated_findings(f):
            finding_id = f.get('finding_id', '')
            if any(key in finding_id for key in ['exec_from_tmp', 'psxview_hidden', 'malfind_injection', 'cmdline_args', 'parent_child', 'registry_run_key_persistence', 'userassist']):
                return 0
            elif any(key in finding_id for key in ['network', 'connection', 'port', 'netstat', 'netscan', 'enrichment']):
                return 1
            else:
                return 2
        findings_details = sorted(findings_details, key=sort_key_correlated_findings)

        path_html = "<div class='attack-path-container'>"
        for i, f_details in enumerate(findings_details):
            finding_id = f_details.get('finding_id')

            step_title_display = get_user_friendly_correlated_title(finding_id)

            primary_evidence_item = f_details.get('evidence', [{}])[0]

            description_parts = []

            process_name_for_step = primary_evidence_item.get('name') or primary_evidence_item.get('process') or primary_evidence_item.get('owner') or primary_evidence_item.get('ImageFileName')

            if finding_id == 'psxview_hidden':
                description_parts.append(f"A process (<code>{html_escape(str(process_name_for_step))}</code>) attempted to **hide its presence**.")
            elif finding_id in ('suspicious_connection', 'suspicious_port_activity', 'suspicious_network_enrichment'):
                remote_ip = primary_evidence_item.get('ForeignAddr') or primary_evidence_item.get('ip')
                remote_port = primary_evidence_item.get('ForeignPort')

                if remote_ip and remote_ip not in ['None', '0.0.0.0'] and remote_port not in ['None', 0]:
                    description_parts.append(f"Communicated with external host: <code>{html_escape(str(remote_ip))}:{html_escape(str(remote_port))}</code>.")
                elif remote_ip and remote_ip not in ['None', '0.0.0.0']:
                    description_parts.append(f"Connected to suspicious external IP: <code>{html_escape(str(remote_ip))}</code>.")
                else:
                    local_port = primary_evidence_item.get('LocalPort') or primary_evidence_item.get('ForeignPort')
                    description_parts.append(f"Opened a suspicious local port: <code>{html_escape(str(local_port))}</code>.")
            elif finding_id == 'malfind_injection':
                description_parts.append(f"Injected malicious code into process memory.")
            elif finding_id == 'ldr_unlinked_module':
                description_parts.append(f"Loaded a **hidden or unlinked module**.")
            elif finding_id == 'suspicious_cmdline_args':
                cmdline = primary_evidence_item.get('command_line')
                description_parts.append(f"Executed with suspicious command-line: <code>{html_escape(str(cmdline))}</code>.")
            elif finding_id == 'registry_run_key_persistence':
                key_path = primary_evidence_item.get('Key', 'N/A')
                entry = primary_evidence_item.get('Name')
                description_parts.append(f"Set for **auto-start** via Registry Run Key.")
            elif finding_id == 'exec_from_tmp':
                path = primary_evidence_item.get('path')
                description_parts.append(f"Executed from a **temporary directory**: (`{html_escape(str(path))}`).")
            elif finding_id == 'filescan_suspicious_names':
                path = primary_evidence_item.get('Path')
                description_parts.append(f"A **suspicious file** was found on disk/memory: (`{html_escape(str(path))}`).")
            elif finding_id == 'unusual_parent_child':
                parent = primary_evidence_item.get('parent_name', 'an unknown process')
                child = primary_evidence_item.get('name', 'a process')
                description_parts.append(f"Process `{html_escape(str(child))}` was spawned by an **unusual parent**: `{html_escape(str(parent))}`.")
            elif finding_id == 'bash_history_suspicious':
                cmd = primary_evidence_item.get('Command')
                user = primary_evidence_item.get('User', 'A user')
                description_parts.append(f"{html_escape(str(user))} executed a **suspicious command**.")
            else:
                description_parts.append(html_escape(get_narrative(finding_id, detections_config)))

            step_description = "<br>".join(description_parts)

            path_html += f"""
            <div class='attack-step'>
                <b style='text-decoration: none;'>{html_escape(step_title_display)}</b><hr>
                <p style='text-decoration: none;'>{step_description}</p>
            </div>
            """
            if i < len(findings_details) - 1:
                path_html += "<div class='attack-arrow'>&rarr;</div>"
        path_html += "</div>"
        st.markdown(path_html, unsafe_allow_html=True)
        st.markdown("---")

def render_evidence_as_table(evidence_list, finding_id):
    if not evidence_list:
        st.info("No detailed evidence provided for this finding.")
        return
    
    processed_evidence_list = []
    if finding_id == "suspicious_network_enrichment" and \
       len(evidence_list) > 0 and \
       isinstance(evidence_list[0], dict) and \
       'id' in evidence_list[0] and \
       evidence_list[0]['id'] == finding_id and \
       'evidence' in evidence_list[0] and \
       isinstance(evidence_list[0]['evidence'], list):
        
        for item in evidence_list:
            if 'evidence' in item and isinstance(item['evidence'], list):
                processed_evidence_list.extend(item['evidence'])
            else:
                processed_evidence_list.append(item)
    else:
        processed_evidence_list = evidence_list

    if not processed_evidence_list:
        st.info("No detailed evidence artifacts found for this finding after processing.")
        return
    
    df = pd.DataFrame(processed_evidence_list)
    df.replace(['', None, 'None'], np.nan, inplace=True)
    df.dropna(axis=1, how='all', inplace=True)
    if df.empty:
        st.info("No detailed evidence artifacts found for this finding.")
        return

    COLUMN_CONFIG = {
        "psxview_hidden": { "columns": ["pid", "name", "pslist", "psscan"], "rename": {"pid": "PID", "name": "Process Name", "pslist": "Visible in Process List", "psscan": "Found by DeepProbe Scan"}},
        "suspicious_cmdline_args": { "columns": ["pid", "name", "command_line"], "rename": {"pid": "PID", "name": "Process", "command_line": "Suspicious Command Line"}},
        "suspicious_connection": { "columns": ["owner", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"], "rename": {"owner": "Process", "LocalAddr": "Local Address", "LocalPort": "Local Port", "ForeignAddr": "Remote Address", "ForeignPort": "Remote Port"}},
        "suspicious_network_enrichment": { "columns": ["pid", "owner", "ip", "country", "isp", "reputation", "notes"], "rename": {"pid": "PID", "owner": "Process Owner", "ip": "Remote IP", "country": "Country", "isp": "ISP", "reputation": "Reputation", "notes": "Reason"}},
        "unusual_parent_child": { "columns": ["name", "pid", "parent_name", "ppid"], "rename": {"name": "Child Process", "pid": "Child PID", "parent_name": "Parent Process", "ppid": "Parent PID"}},
        "malfind_injection": { "columns": ["process", "pid", "Start", "Protection"], "rename": {"process": "Process", "pid": "PID", "Start": "Start Address", "Protection": "Memory Protection"}},
        "filescan_suspicious_names": { "columns": ["Path", "Offset"], "rename": {"Path": "File Path", "Offset": "Memory Offset"}},
        "userassist_suspicious": { "columns": ["Path", "Count", "LastUpdated"], "rename": {"Path": "Program Path", "Count": "Execution Count", "LastUpdated": "Last Executed"}},
        "registry_run_key_persistence": { "columns": ["Key", "Name", "Decoded"], "rename": {"Key": "Registry Key", "Name": "Entry", "Decoded": "Command Executed"}},
        "exec_from_tmp": {"columns": ["pid", "name", "path"], "rename": {"pid": "PID", "name": "Process Name", "path": "Execution Path"}},
        "bash_history_suspicious": {"columns": ["User", "Command"], "rename": {"User": "User", "Command": "Command Executed"}},
        "correlation_findings": {
            "columns": ["correlated_pid", "correlated_findings", "correlated_rule_ids"],
            "rename": {
                "correlated_pid": "Correlated PID",
                "correlated_findings": "Included Findings (Summary)",
                "correlated_rule_ids": "Triggered Rule IDs"
            }
        },
    }

    config = COLUMN_CONFIG.get(finding_id)
    df_display = df
    if config:
        existing_cols = [col for col in config["columns"] if col in df.columns]
        if existing_cols:
            df_display = df[existing_cols].rename(columns=config["rename"])
            if finding_id == 'psxview_hidden' and 'Visible in Process List' in df_display.columns:
                df_display['Visible in Process List'] = df_display['Visible in Process List'].apply(lambda x: 'Yes' if str(x).lower() == 'true' else 'No (Hidden)')
                df_display['Found by DeepProbe Scan'] = df_display['Found by DeepProbe Scan'].apply(lambda x: 'Yes' if str(x).lower() == 'true' else 'No')

            if finding_id.startswith('correlation_'):
                if 'Included Findings (Summary)' in df_display.columns:
                    df_display['Included Findings (Summary)'] = df_display['Included Findings (Summary)'].apply(
                        lambda x: ", ".join([get_user_friendly_correlated_title(item.get('finding_id', 'Unknown')) for item in x])
                                  if isinstance(x, list) else str(x)
                    )
                if 'Triggered Rule IDs' in df_display.columns:
                    df_display['Triggered Rule IDs'] = df_display['Triggered Rule IDs'].apply(
                        lambda x: ", ".join(x) if isinstance(x, list) else str(x)
                    )

    column_config_render = {}
    if finding_id == 'filescan_suspicious_names' and 'File Path' in df_display.columns:
        column_config_render["File Path"] = st.column_config.TextColumn(width="large")
    if finding_id == 'suspicious_network_enrichment' and 'Remote IP' in df_display.columns:
        column_config_render["Remote IP"] = st.column_config.TextColumn(width="small")
        column_config_render["Country"] = st.column_config.TextColumn(width="small")
        column_config_render["ISP"] = st.column_config.TextColumn(width="medium")
        column_config_render["Reputation"] = st.column_config.TextColumn(width="small")
        column_config_render["Reason"] = st.column_config.TextColumn(width="large")

    if finding_id.startswith('correlation_'):
        if 'Correlated PID' in df_display.columns:
            column_config_render["Correlated PID"] = st.column_config.TextColumn(width="small")
        if 'Included Findings (Summary)' in df_display.columns:
            column_config_render["Included Findings (Summary)"] = st.column_config.TextColumn(width="large")
        if 'Triggered Rule IDs' in df_display.columns:
            column_config_render["Triggered Rule IDs"] = st.column_config.TextColumn(width="large")

    st.dataframe(df_display, use_container_width=True, hide_index=True, column_config=column_config_render)

artifact_descriptions = {
    "report.html": {"title": "Full Analysis Report (HTML)", "description": "The complete HTML analysis report generated by DeepProbe."},
    "findings.jsonl": {"title": "Detected Findings (JSONL Data)", "description": "Raw JSON Lines format of all detected forensic findings."},
    "ai_verdict.json": {"title": "AI Verdict (JSON Data)", "description": "The AI-generated verdict and summary of the memory forensic analysis."},
    "console_output.log": {"title": "CLI Console Output Log", "description": "Comprehensive log of the analysis process and console output."},
    "memory_dump.raw": {"title": "Raw Memory Dump File", "description": "The raw memory image file (if a copy was made)."},
    "dump_files.zip": {"title": "Dumped Files (ZIP Archive)", "description": "Archive containing dumped processes or extracted files from memory."},
    
    "windows_info.txt": {"title": "Windows System Information", "description": "Detailed information about the Windows OS and kernel, including build number, architecture, and installed updates."},
    "windows_pslist.csv": {"title": "Windows Process List", "description": "Lists all active processes on Windows, including PID, PPID, and image file paths."},
    "windows_psscan.csv": {"title": "Windows PsScan (Deep Process Scan)", "description": "Results of a deeper scan for potentially hidden or unlinked processes on Windows, often more thorough than pslist."},
    "windows_psxview.csv": {"title": "Windows PsXView (Hidden Processes)", "description": "Shows mismatches between different process visibility lists, highlighting potentially hidden processes."},
    "windows_pstree.txt": {"title": "Windows Process Tree", "description": "Displays Windows processes in a hierarchical tree structure, showing parent-child relationships."},
    "windows_cmdline.csv": {"title": "Windows Command Line Arguments", "description": "Full command-line arguments for all running Windows processes, useful for identifying unusual process execution."},
    "windows_netstat.csv": {"title": "Windows Netstat", "description": "Active network connections and listening ports for Windows processes."},
    "windows_netscan.csv": {"title": "Windows Netscan", "description": "Detailed network connection scan results on Windows."},
    "windows_malfind.txt": {"title": "Windows Malfind (Injected Code)", "description": "Extracted injected code from process memory on Windows, indicating potential code injection attacks."},
    "windows_hollowprocesses.txt": {"title": "Windows Hollow Processes", "description": "Detects process hollowing, a technique where a legitimate process's memory is replaced with malicious code."},
    "windows_ldrmodules.txt": {"title": "Windows Loaded Modules (LDR)", "description": "Lists dynamically loaded DLLs and identifies unlinked modules in memory, often used by malware for stealth."},
    "windows_handles.txt": {"title": "Windows Handles", "description": "Enumerates open kernel object handles by processes on Windows, useful for identifying privileged access or resource abuse."},
    "windows_svcscan.csv": {"title": "Windows Services Scan", "description": "Lists all services configured on a Windows system, including their states, paths, and associated executables."},
    "windows_scheduled_tasks.txt": {"title": "Windows Scheduled Tasks", "description": "Shows all configured scheduled tasks on Windows, which can be used for **persistence or malicious execution** at specific times."},
    "windows_registry_scheduled_tasks.txt": {"title": "Windows Registry Scheduled Tasks (Fallback)", "description": "Alternative output for scheduled tasks from the registry."},
    "windows_filescan.txt": {"title": "Windows Filescan (Memory)", "description": "Scans for open files and deleted files still in memory on Windows, which can reveal deleted malware components."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs.txt": {"title": "Registry: Recent Docs (All Types)", "description": "Comprehensive list of recently accessed documents and files from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_exe.txt": {"title": "Registry: Recent Docs (Executables)", "description": "Recently accessed executable files (programs) from the Registry's RecentDocs key, indicating user or process execution history."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_js.txt": {"title": "Registry: Recent Docs (JavaScript)", "description": "Recently accessed JavaScript files from the Registry's RecentDocs key, useful for identifying script execution."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_lnk.txt": {"title": "Registry: Recent Docs (Shortcuts)", "description": "Recently accessed shortcut (.lnk) files from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_ps1.txt": {"title": "Registry: Recent Docs (PowerShell)", "description": "Recently accessed PowerShell scripts from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_py.txt": {"title": "Registry: Recent Docs (Python)", "description": "Recently accessed Python scripts from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_txt.txt": {"title": "Registry: Recent Docs (Text Files)", "description": "Recently accessed text files from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Explorer_RecentDocs_vbs.txt": {"title": "Registry: Recent Docs (VBScript)", "description": "Recently accessed VBScript files from the Registry's RecentDocs key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Run.txt": {"title": "Registry: Run Key Auto-Start", "description": "Programs configured to automatically start when Windows boots via the 'Run' registry key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_RunOnce.txt": {"title": "Registry: RunOnce Auto-Start", "description": "Programs configured to run only once at Windows startup via the 'RunOnce' registry key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_Policies_Explorer_Run.txt": {"title": "Registry: Policies Explorer Run Auto-Start", "description": "Auto-run entries from the Windows Registry Policies Explorer Run key."},
    "windows_registry_printkey_Software_Microsoft_Windows_CurrentVersion_RunServices.txt": {"title": "Registry: RunServices Key", "description": "Programs configured to run as services via the 'RunServices' registry key."},
    "windows_registry_printkey_Software_WOW6432Node_Microsoft_Windows_CurrentVersion_Run.txt": {"title": "Registry: Run Key (WOW6432Node)", "description": "Auto-start entries for 32-bit applications on 64-bit Windows systems."},
    "windows_registry_printkey_Software_WOW6432Node_Microsoft_Windows_CurrentVersion_RunOnce.txt": {"title": "Registry: RunOnce Key (WOW6432Node)", "description": "Run-once entries for 32-bit applications on 64-bit Windows systems."},
    "windows_registry_printkey_Software_Microsoft_Windows_NT_CurrentVersion_Windows_AppInit_DLLs.txt": {"title": "Registry: AppInit DLLs", "description": "DLLs configured to load into every user-mode application on Windows, a common persistence mechanism."},
    "windows_registry_printkey_System_CurrentControlSet_Services.txt": {"title": "Registry: Services Configuration", "description": "Raw configuration details for all Windows services found in the registry."},
    "windows_registry_userassist.txt": {"title": "Registry: UserAssist (GUI Program History)", "description": "Records recently executed GUI applications on Windows, providing user activity history and launch counts."},
    "windows_sessions.csv": {"title": "Windows Sessions", "description": "Lists active user logon sessions on Windows, including user accounts and authentication packages."},
    "windows_getsids.txt": {"title": "Windows Get SIDs", "description": "Lists Security Identifiers (SIDs) for processes and users on Windows."},
    "windows_registryprintkey.txt": {"title": "Windows Registry Printkey (Generic)", "description": "Raw output from a generic Volatility registry printkey plugin for a non-specific path or the root registry hive."},
    "windows_dlllist.txt": {"title": "Windows DLL List", "description": "Lists loaded DLLs for each process, useful for identifying injected or suspicious modules."},
    "windows_apihooks.txt": {"title": "Windows API Hooks", "description": "Detects modifications to Windows API functions, often a sign of malware attempting to intercept system calls."},
    "windows_devicetree.txt": {"title": "Windows Device Tree", "description": "Provides a hierarchical view of devices on the system, which can sometimes reveal rogue hardware or drivers."},
    "windows_modscan.txt": {"title": "Windows Kernel Module Scan", "description": "Scans for loaded kernel modules and drivers, identifying potentially hidden or malicious ones."},
    "windows_consoles.txt": {"title": "Windows Console History", "description": "Recovers command history from console windows (cmd.exe, PowerShell), revealing user activity or attacker commands."},
    "windows_clipboard.txt": {"title": "Windows Clipboard Contents", "description": "Recovers data from the system clipboard, potentially containing sensitive information copied by a user or malware."},
    "windows_registry_shimcache.txt": {"title": "Windows Registry: Shimcache (AppCompatCache)", "description": "Records metadata about recently executed applications, useful for execution artifacts and determining program compatibility."},
    "windows_registry_amcache.csv": {"title": "Windows Registry: Amcache", "description": "Provides detailed information about executed programs and their hash values, often used in forensics."},
    "windows_envars.txt": {"title": "Windows Environment Variables", "description": "Lists environment variables for processes, which can sometimes contain paths to malicious tools or configurations."},
    "windows_callbacks.txt": {"title": "Windows Kernel Callbacks", "description": "Lists registered kernel callbacks, which can be hooked by rootkits for stealthy operations."},
    "linux_info.txt": {"title": "Linux System Information", "description": "Detailed information about the Linux OS and kernel."},
    "linux_pslist.csv": {"title": "Linux Process List", "description": "Lists all active processes on Linux."},
    "linux_psscan.csv": {"title": "Linux PsScan (Deep Process Scan)", "description": "Results of a deeper scan for potentially hidden processes on Linux."},
    "linux_psaux.txt": {"title": "Linux PsAux (Detailed Processes)", "description": "Provides detailed process information including full command lines on Linux."},
    "linux_lsof.txt": {"title": "Linux LSOF (List Open Files)", "description": "Lists open files and network connections for Linux processes."},
    "linux_sockstat.txt": {"title": "Linux Socket Statistics", "description": "Displays detailed network socket statistics on Linux."},
    "linux_check_syscall.txt": {"title": "Linux Syscall Check", "description": "Checks the integrity of the system call table for potential kernel hooks on Linux."},
    "linux_check_modules.txt": {"title": "Linux Kernel Module Check", "description": "Lists loaded kernel modules on Linux, useful for detecting rootkits."},
    "linux_bash.txt": {"title": "Linux Bash History", "description": "Extracts Bash shell command history from Linux users."},
    "linux_netstat.txt": {"title": "Linux Netstat", "description": "Displays network connections and routing tables on Linux."},
    "linux_memmap.txt": {"title": "Linux Memory Map", "description": "Provides a detailed memory map of processes and regions on Linux."},
    "linux_envars.txt": {"title": "Linux Environment Variables", "description": "Lists environment variables for Linux processes, potentially revealing configurations or paths."},
    "linux_librarylist.txt": {"title": "Linux Library List", "description": "Enumerates shared libraries loaded by Linux processes."},
    "linux_lsmod.txt": {"title": "Linux Loaded Modules (LSMOD)", "description": "Lists loaded kernel modules in the Linux kernel."},

    "mac_info.txt": {"title": "macOS System Information", "description": "Detailed information about the macOS and kernel."},
    "mac_pslist.csv": {"title": "macOS Process List", "description": "Lists all active processes on macOS."},
    "mac_lsof.txt": {"title": "macOS LSOF (List Open Files)", "description": "Lists open files and network connections for macOS processes."},
    "mac_netstat.csv": {"title": "macOS Netstat", "description": "Displays active network connections for macOS processes."},
    "mac_malfind.txt": {"title": "macOS Malfind (Injected Code)", "description": "Extracts injected code from process memory on macOS."},
    "mac_bash.txt": {"title": "macOS Bash History", "description": "Extracts Bash shell command history from macOS users."},
    "mac_ifconfig.txt": {"title": "macOS Ifconfig", "description": "Displays network interface configuration and IP addresses on macOS."},
    "mac_sessions.txt": {"title": "macOS User Sessions", "description": "Lists active user sessions on macOS."},
    "mac_mount.txt": {"title": "macOS Mounted Filesystems", "description": "Displays mounted filesystems on macOS, useful for external storage analysis."},
    "mac_volumes.txt": {"title": "macOS Volumes", "description": "Lists detected volumes on macOS, including external and hidden ones."},
    "mac_dmesg.txt": {"title": "macOS Kernel Ring Buffer (Dmesg)", "description": "Recovers messages from the kernel ring buffer, providing system events and error logs."},
}


# --- Main Application UI ---
def main():
    print("[DEBUG] DeepProbe UI: main() function started.")

    st.set_page_config(page_title="DeepProbe | Memory Forensics", page_icon="🕵️", layout="wide", initial_sidebar_state="expanded") # Changed emoji

    if 'analysis_successful' not in st.session_state: st.session_state.analysis_successful = False
    if 'active_page' not in st.session_state: st.session_state.active_page = "Home"
    if 'project_name' not in st.session_state: st.session_state.project_name = ""
    if 'ip_enrichment_api_key' not in st.session_state: st.session_state.ip_enrichment_api_key = ""
    if 'openai_api_key' not in st.session_state: st.session_state.openai_api_key = ""

    try:
        st.markdown("""<style>
                @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
                .block-container { padding-top: 2rem !important; }
                html, body, .stApp { font-family: 'Roboto', sans-serif; background-color: #f0f2f6; color: #333; }
                .header { background-color: #2c3e50; padding: 2rem 2rem 1.5rem 2rem; border-bottom: 1px solid #dcdcdc; display: flex; align-items: center; gap: 1rem; margin: -2rem -1rem 1rem -1rem; }
                .header h1 { font-size: 2.5rem; font-weight: 700; color: #ffffff; margin: 0; }
                .header span { font-size: 1rem; font-weight: 300; color: #bdc3c7; padding-top: 10px; }

                [data-testid="stSidebar"] {
                    background-image: linear-gradient(to bottom, #eaf2f8, #fdfefe);
                    border-right: 1px solid #d4e6f1;
                }
                [data-testid="stSidebar"] > div:first-child {
                    display: flex;
                    flex-direction: column;
                    height: 100%;
                }
                .sidebar-footer {
                    margin-top: auto;
                    padding-bottom: 1rem;
                }
                [data-testid="stSidebar"] h2 {
                    color: #2874a6;
                    border-bottom: 2px solid #a9cce3;
                    padding-bottom: 5px;
                }
                [data-testid="stSidebar"] .stButton > button {
                    background-color: #3498db; color: white; font-weight: bold;
                    width: 100%; padding: 0.75rem 0; border-radius: 8px; border: none;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                [data-testid="stSidebar"] .stButton > button:hover {
                    background-color: #2980b9;
                    box-shadow: 0 4pX 8px rgba(0,0,0,0.15);
                }
                [data-testid="stSidebar"] .stMarkdown, 
                [data-testid="stSidebar"] .stInfo,
                [data-testid="stSidebar"] .stText,
                [data-testid="stSidebar"] p,
                [data-testid="stSidebar"] li {
                    color: #566573 !important;
                }
                /* Specific background for the st.info box in sidebar */
                [data-testid="stSidebar"] .stInfo { 
                    background-color: #e8f6f8; /* Lighter background for info box */
                    color: #2e86c1 !important; /* Dark blue text for info box */
                    padding: 0.75rem;
                    border-radius: 6px;
                    margin-bottom: 1rem;
                }

                .stTextInput label {
                    color: #333 !important;
                }
                .stTextInput input {
                    background-color: #ffffff !important;
                    border: 1px solid #bdc3c7 !important;
                    border-radius: 8px !important;
                    padding: 10px !important;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05) inset;
                    transition: border-color 0.2s, box-shadow 0.2s;
                    color: #333 !important;
                }
                .stTextInput input:focus {
                    border-color: #3498db !important;
                    box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.25) !important;
                }

                /* Styling for selectbox */
                .stSelectbox label {
                    color: #333 !important;
                }
                .stSelectbox div[data-baseweb="select"] > div {
                    background-color: #ffffff !important;
                    border: 1px solid #dcdcdc !important;
                    color: #333 !important;
                    border-radius: 8px;
                }
                .stSelectbox div[data-baseweb="select"] > div:hover {
                    border-color: #3498db !important;
                }
                .stSelectbox div[data-baseweb="select"] > div > div {
                     color: #333 !important;
                }
                /* Option list in selectbox */
                div[role="listbox"] {
                    background-color: #ffffff !important;
                    border: 1px solid #dcdcdc !important;
                }
                div[role="option"] {
                    color: #333 !important;
                }
                div[role="option"]:hover {
                    background-color: #eaf2f8 !important;
                }


                .scan-widget-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
                .scan-widget {
                    background-color: #ffffff;
                    border: 1px solid #dcdcdc;
                    border-radius: 8px;
                    padding: 1.5rem 1rem;
                    text-align: center;
                    transition: all 0.2s ease-in-out;
                    cursor: default;
                    color: #333; /* Default text color for scan widgets */
                }
                .scan-widget:hover { transform: translateY(-5px); border-color: #3498db; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
                .scan-widget:nth-of-type(1) { background-color: #d1ecf1; color: #0c5460; } /* Light teal */
                .scan-widget:nth-of-type(2) { background-color: #d4edda; color: #155724; } /* Light green */
                .scan-widget:nth-of-type(3) { background-color: #f8d7da; color: #721c24; } /* Light red */
                .scan-widget:nth-of-type(4) { background-color: #e2e6ea; color: #383d41; } /* Light gray */
                .scan-widget:nth-of-type(5) { background-color: #ffeeba; color: #856404; } /* Light yellow */
                .scan-widget:nth-of-type(6) { background-color: #cce5ff; color: #004085; } /* Light blue */
                .scan-widget:nth-of-type(7) { background-color: #f0e68c; color: #695d01; } /* Khaki */
                .scan-widget:nth-of-type(8) { background-color: #e0b0ff; color: #5a008c; } /* Light purple */

                .severity-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
                .severity-box { color: white; padding: 1rem; border-radius: 8px; text-align: center; }
                .severity-title { font-size: 1.2rem; font-weight: bold; } .severity-count { font-size: 2.5rem; font-weight: bold; }
                .severity-box.critical { background-color: #c0392b; } .severity-box.high { background-color: #e67e22; } .severity-box.medium { background-color: #f1c40f; color: #333; } .severity-box.low { background-color: #5dade2; }
                .severity-box.informational { background-color: #2ecc71; }

                h1, h2, h3, h4, h5, h6 { 
                    color: #2c3e50; /* Ensures all headings are dark */
                    font-weight: 700; /* Makes all headings bold */
                    margin-top: 1.5rem; /* Add spacing above headings for better visual separation */
                    margin-bottom: 0.5rem;
                }
                /* Specific adjustment for h1 to ensure it doesn't get too much top margin if it's the very first element */
                .block-container h1:first-of-type {
                    margin-top: 0rem;
                }

                /* Ensure paragraph and list item text in the main content area is dark */
                .st-emotion-cache-1g8o8z p, /* Target specific Streamlit paragraph class if needed */
                .st-emotion-cache-1g8o8z li, /* Target specific Streamlit list item class if needed */
                .block-container p,
                .block-container li {
                    color: #333 !important;
                }
                
                /* Styling for the main content area form button */
                [data-testid="stForm"] .stButton > button {
                    background-color: #3498db; /* Blue primary color */
                    color: white; /* White text */
                    font-weight: bold;
                    width: 100%;
                    padding: 0.75rem 0;
                    border-radius: 8px;
                    border: none;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    transition: background-color 0.2s ease-in-out, box-shadow 0.2s ease-in-out;
                }
                [data-testid="stForm"] .stButton > button:hover {
                    background-color: #2980b9; /* Darker blue on hover */
                    box-shadow: 0 4px 8px rgba(0,0,0,0.15);
                }


                .attack-path-container { display: flex; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-top: 15px; justify-content: center; }
                .attack-step { background-color: #eaf2f8; border: 1px solid #d4e6f1; border-radius: 8px; padding: 1rem; width: 280px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); min-height: 120px; display: flex; flex-direction: column; justify-content: center; align-items: center; color: #333;}
                .attack-step hr { margin: 0.5rem 0; border-top: 1px solid #aed6f1; width: 80%; }
                .attack-step p { font-size: 0.9rem; color: #555; margin: 0; }
                .attack-arrow { font-size: 2rem; color: #5dade2; font-weight: bold; display: flex; align-items: center; justify-content: center; padding: 0 10px; }

                .verdict-box {
                    padding: 1.5rem;
                    border-radius: 12px;
                    margin-bottom: 2rem;
                    text-align: center;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }
                /* AI Verdict Box */
                .verdict-box.ai-verdict { background-color: #34495e; color: white; }
                .verdict-box.ai-verdict h2, .verdict-box.ai-verdict p, .verdict-box.ai-verdict li, .verdict-box.ai-verdict small { color: white !important; }
                
                /* Rule-Based Verdict Boxes - using existing severity colors */
                .verdict-box.critical { background-color: #c0392b; color: white; }
                .verdict-box.high { background-color: #e67e22; color: white; }
                .verdict-box.medium { background-color: #f1c40f; color: #333; } /* Dark text for medium for contrast */
                .verdict-box.low { background-color: #5dade2; color: white; }
                .verdict-box.informational { background-color: #2ecc71; color: white; }

                .verdict-box h2 {
                    color: inherit;
                    font-size: 2.2rem;
                    margin-bottom: 0.5rem;
                }
                .verdict-box p {
                    font-size: 1.1rem;
                    opacity: 0.9;
                }

                .card { background-color: #ffffff; border: 1px solid #dcdcdc; border-radius: 12px; box-shadow: 0 0 0 1px #a9cce3 inset; margin-bottom: 16px; color: #333; }
                .card.critical { border-left: 8px solid #c0392b !important; }
                .card.high { border-left: 8px solid #e67e22 !important; }
                .card.medium { border-left: 8px solid #f1c40f !important; }
                .card.low { border-left: 8px solid #5dade2 !important; }
                .card.informational { border-left: 8px solid #2ecc71 !important; }


                .narrative-block {
                    background-color: #f8f9fa;
                    border-left: 4px solid #3498db;
                    padding: 10px 15px;
                    margin-top: 10px;
                    border-radius: 4px;
                }
                .narrative-block p {
                    color: #333;
                    margin: 0;
                }

                .findings-narrative-list {
                    padding-left: 0;
                    list-style: none;
                }
                .findings-narrative-item {
                    background-color: #ffffff;
                    border: 1px solid #e0e0e0;
                    border-radius: 6px;
                    padding: 10px 15px;
                    margin-bottom: 8px;
                    display: flex;
                    align-items: flex-start;
                    gap: 10px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                    border-left-width: 8px;
                }
                .findings-narrative-item.critical { border-left-color: #c0392b; }
                .findings-narrative-item.high { border-left-color: #e67e22; }
                .findings-narrative-item.medium { border-left-color: #f1c40f; }
                .findings-narrative-item.low { border-left-color: #5dade2; }
                .findings-narrative-item.informational { border-left-color: #2ecc71; }

                .findings-narrative-item strong {
                    flex-shrink: 0;
                    color: #2c3e50;
                    font-size: 0.95rem;
                    width: 200px;
                }
                .findings-narrative-item span {
                    flex-grow: 1;
                    color: #555;
                    font-size: 0.9rem;
                }

                .artifact-card {
                    background-color: #ffffff; /* Light background for card */
                    border: 1px solid #dcdcdc;
                    border-radius: 8px;
                    padding: 1rem;
                    margin-bottom: 1rem;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); /* Lighter shadow */
                    display: flex;
                    flex-direction: column;
                    justify-content: space-between;
                    height: 100%;
                    min-height: 200px;
                }
                .artifact-card h3 {
                    margin-top: 0;
                    font-size: 1.1rem;
                    color: #2874a6; /* Darker blue for title */
                }
                .artifact-card p {
                    font-size: 0.85rem;
                    color: #566573; /* Darker grey for description */
                    flex-grow: 1;
                    overflow: hidden;
                    text-overflow: ellipsis;
                }
                .artifact-card .stDownloadButton button {
                    margin-top: 10px;
                    width: 100%;
                    background-color: #3498db; /* Blue download button */
                    color: white;
                    font-weight: bold;
                    border-radius: 8px;
                    border: none;
                    padding: 0.5rem 0;
                    transition: background-color 0.2s;
                    cursor: pointer;
                }
                .artifact-card .stDownloadButton button:hover {
                    background-color: #2980b9; /* Darker blue on hover */
                }
                /* Styling for missing artifact files */
                .artifact-card.missing-file {
                    background-color: #fdf2f2; /* Light red background */
                    border-color: #f5c6cb;
                }
                .artifact-card.missing-file h3 {
                    color: #dc3545; /* Dark red title */
                }
                .artifact-card.missing-file p {
                    color: #833a41; /* Darker red description */
                }
                .artifact-card.missing-file .stDownloadButton button {
                    background-color: #ced4da; /* Greyed out button */
                    color: #6c757d;
                    cursor: not-allowed;
                }
                .artifact-card.missing-file .stDownloadButton button:hover {
                    background-color: #ced4da;
                }

                .stTabs [data-testid="stTabRecButton"] {
                    font-size: 1.35rem;
                    font-weight: 700;
                    color: #2c3e50; /* Dark text for tabs */
                    background-color: #ecf0f1;
                    border: 2px solid #bdc3c7;
                    border-bottom: none;
                    border-radius: 10px 10px 0 0;
                    padding: 1rem 2rem;
                    margin-right: 10px;
                    transition: all 0.2s ease-in-out;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                }
                .stTabs [data-testid="stTabRecButton"]:hover {
                    background-color: #dfe6e9;
                    color: #3498db;
                }
                .stTabs [data-testid="stTabRecButton"][aria-selected="true"] {
                    background-color: #3498db; /* Active tab in blue */
                    color: white;
                    border: 2px solid #3498db;
                    border-bottom: none;
                    margin-bottom: -2px;
                    padding-bottom: calc(1rem + 2px);
                    box-shadow: 0 6px 12px rgba(52, 152, 219, 0.4);
                }
                .progress-container {
                    margin-top: 2rem;
                    padding: 1rem;
                    border: 1px solid #dcdcdc;
                    border-radius: 8px;
                    background-color: #ffffff;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
                    width: 50%;
                    margin-left: auto;
                    margin-right: auto;
                    color: #333; /* Ensure text is dark */
                }
                /* Ensure all default Streamlit text is dark in light mode */
                .st-cq, .st-ci, .st-ea, .st-eq, .st-es, .st-eu, .st-ew, .st-ex, .st-b5, .st-b6, .st-b7, .st-b8, .st-b9, .st-ba, .st-bb,
                .stBlock > div > div > p, .stBlock > div > div > ul > li,
                .stMarkdown, .stText,
                .stDataFrame /* For dataframes to have dark text */
                 {
                    color: #333 !important;
                }
                .stTextArea textarea {
                    color: #333 !important;
                    background-color: #ffffff !important;
                    border: 1px solid #dcdcdc !important;
                }
                /* Adjust for Streamlit's internal element targeting for code blocks */
                .stCode, [data-testid="stCodeBlock"] code {
                    background-color: #f8f9fa !important;
                    color: #333 !important;
                    border: 1px solid #e0e0e0 !important;
                }

            </style>""", unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error loading UI styles. This might be a Streamlit rendering issue. Error: {e}")
        st.stop()


    st.markdown('<div class="header"><h1>DeepProbe</h1><span>Memory Forensics Framework</span></div>', unsafe_allow_html=True)

    with st.sidebar:
        html_sidebar_about_title = "<h2><span style='text-decoration: none; color: inherit;'>About DeepProbe</span></h2>"
        html(html_sidebar_about_title, height=45)
        st.write(
            "**DeepProbe** is an automated framework that enhances memory forensics by building upon the powerful **Volatility 3** engine. "
            "Its intelligent analysis engine correlates disparate artifacts from memory to identify complex threat patterns and uncover attack chains that might otherwise be missed."
        )
        st.markdown("---")
        html_sidebar_supported_formats_title = "<h2><span style='text-decoration: none; color: inherit;'>Supported Formats</span></h2>"
        html(html_sidebar_supported_formats_title, height=45)
        st.info(f"Place your memory image file inside the `{html_escape(str(MEMORY_FOLDER.name))}/` folder.")
        st.markdown("- Raw Memory Dumps (`.raw`, `.mem`, `.bin`)\n- VMware Snapshots (`.vmem`)\n- Hibernation Files (`hiberfil.sys`)")

        st.markdown('<div class="sidebar-footer">', unsafe_allow_html=True)
        if st.button("New Analysis / Home"):
            st.session_state.active_page = "Home"
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    status_text_global = st.empty()
    progress_bar_global = st.empty()

    if st.session_state.active_page == "Home":
        render_home_page(status_text_global, progress_bar_global)
    elif st.session_state.active_page == "Results":
        render_results_page()

def render_home_page(status_text_global, progress_bar_global):
    """Renders the main input form and analysis capabilities view."""
    
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        html_new_analysis_job_title = "<h1><span style='text-decoration: none; color: inherit;'>New Analysis Job</span></h1>"
        html(html_new_analysis_job_title, height=70)
        st.write("Configure your analysis by providing a project name and the memory image filename.")

        with st.form("analysis_form"):
            project_name = st.text_input("**Project Name**", placeholder="e.g., Q4_Incident_Response")
            memory_file_name = st.text_input("**Memory File Name**", placeholder="e.g., workstation-dump.raw")
            ip_enrichment_api_key = st.text_input("**IP Enrichment API Key (Optional)**", type="password", help="Enter your API key for IP geo-location and reputation services.")
            openai_api_key = st.text_input("**OpenAI API Key (Optional)**", type="password", help="Enter your OpenAI API key for AI-powered verdict and summary.")
            
            submitted = st.form_submit_button("Launch Analysis")
        
    with col2:
        html_analysis_capabilities_title = "<h2><span style='text-decoration: none; color: inherit;'>Analysis Capabilities</span></h2>"
        html(html_analysis_capabilities_title, height=50)
        st.markdown("""
            <div class="scan-widget-grid">
                <div class="scan-widget"><div class="title">Hidden Process Detection</div></div>
                <div class="scan-widget"><div class="title">Unlinked Module Analysis</div></div>
                <div class="scan-widget"><div class="title">Risky Network Connections</div></div>
                <div class="scan-widget"><div class="title">Suspicious Port Usage</div></div>
                <div class="scan-widget"><div class="title">Process Hollowing</div></div>
                <div class="scan-widget"><div class="title">Code Injection</div></div>
                <div class="scan-widget"><div class="title">Suspicious Command Lines</div></div>
                <div class="scan-widget"><div class="title">Registry Persistence</div></div>
            </div>
        """, unsafe_allow_html=True)

    if submitted:
        if not project_name or not memory_file_name:
            st.error("Both Project Name and Memory File Name are mandatory.")
            status_text_global.empty()
            progress_bar_global.empty()
        else:
            memory_file_path = MEMORY_FOLDER / memory_file_name
            if not memory_file_path.exists():
                st.error(f"File not found: '`{html_escape(memory_file_name)}`' does not exist in the '`{html_escape(str(MEMORY_FOLDER))}`' directory.")
                status_text_global.empty()
                progress_bar_global.empty()
            else:
                st.session_state.project_name = project_name
                st.session_state.ip_enrichment_api_key = ip_enrichment_api_key
                st.session_state.openai_api_key = openai_api_key

                progress_bar_global.progress(0, text="0% Complete")

                success = run_analysis_and_show_progress(
                    project_name, memory_file_path,
                    ip_enrichment_api_key,
                    openai_api_key,
                    progress_bar_global, status_text_global
                )
                
                if success:
                    st.session_state.active_page = "Results"
                    time.sleep(1)
                    st.rerun()
                else:
                    status_text_global.empty()
                    progress_bar_global.empty()

def render_results_page():
    """Renders the final report with all visualizations."""
    html_results_for_title = f"<h1><span style='text-decoration: none; color: inherit;'>Results for: {html_escape(st.session_state.project_name)}</span></h1>"
    html(html_results_for_title, height=70)
    detections_config = load_detections_config()

    if not st.session_state.analysis_successful:
        st.error("Analysis did not complete successfully. No report to display.")
        return

    findings = load_findings(st.session_state.project_name)
    ai_verdict_from_file = load_ai_verdict(st.session_state.project_name)

    correlated_findings = [f for f in findings if f.get('id', '').startswith('correlation_')]
    regular_findings = [f for f in findings if not f.get('id', '').startswith('correlation_')]

    severity_counts, overall_severity_label, total_score = categorize_findings(findings, detections_config)

    html_overall_verdict_title = "<h2><span style='text-decoration: none; color: inherit;'>Overall Verdict</span></h2>"
    html(html_overall_verdict_title, height=50)
    if ai_verdict_from_file.get('verdict') != 'N/A' and ai_verdict_from_file.get('plain_summary') != 'AI verdict not available.':
        ai_data = ai_verdict_from_file

        st.markdown(f"""
            <div class="verdict-box ai-verdict">
                <h2>AI Verdict: <span style='text-decoration: none; color: inherit;'>{html_escape(ai_data.get('verdict', 'N/A'))}</span></h2>
                <p style='text-decoration: none;'><b>Summary:</b> {html_escape(ai_data.get('plain_summary', 'No summary provided by AI.'))}</p>
        """, unsafe_allow_html=True)

        html_key_findings_title = "<h3><span style='text-decoration: none; color: inherit;'>Key Findings</span></h3>"
        html(html_key_findings_title, height=40)
        key_findings_html = "<ul>"
        if ai_data.get('key_findings'):
            for finding_text in ai_data['key_findings']:
                if "command and control" in finding_text.lower() or "c2" in finding_text.lower():
                    key_findings_html += f"<li style='text-decoration: none;'>{html_escape(finding_text)} - _This indicates a communication channel used by attackers to remotely control the compromised system._</li>"
                else:
                    key_findings_html += f"<li style='text-decoration: none;'>{html_escape(finding_text)}</li>"
        else:
            key_findings_html += "<li style='text-decoration: none;'>No key findings identified by AI.</li>"
        key_findings_html += "</ul>"
        st.markdown(key_findings_html, unsafe_allow_html=True)

        html_attack_chain_title = "<h3><span style='text-decoration: none; color: inherit;'>Attack Chain</span></h3>"
        html(html_attack_chain_title, height=40)
        attack_chain_html = "<ol>"
        if ai_data.get('attack_chain'):
            for step in ai_data['attack_chain']:
                actor_str = f"<b>Process:</b> {html_escape(step.get('actor', {}).get('process', 'unknown'))} (PID: {html_escape(str(step.get('actor', {}).get('pid', 'unknown')))})"
                if step.get('actor', {}).get('user') != 'unknown':
                    actor_str += f", User: {html_escape(step.get('actor', {}).get('user'))}"
                
                target_str = ""
                if step.get('target', {}).get('object') != 'unknown':
                    target_str = f"<b>Target:</b> {html_escape(step.get('target', {}).get('object', 'unknown'))}"
                elif step.get('target', {}).get('process') != 'unknown':
                    target_str = f"<b>Target Process:</b> {html_escape(step.get('target', {}).get('process'))} (PID: {html_escape(str(step.get('target', {}).get('pid', 'unknown')))})"

                correlation_note = ""
                if step.get('correlation_id') and step['correlation_id'] != 'none':
                    correlation_note = f" _(Correlated from {html_escape(step['correlation_id'].replace('correlation_', '').replace('_', ' '))})_"

                step_action = html_escape(step.get('action', 'unknown action'))
                if "command and control" in step_action.lower() or "c2" in step_action.lower():
                    step_action += " - _This is the remote communication channel established by the attacker._"

                attack_chain_html += (
                    f"<li style='text-decoration: none;'>"
                    f"[{html_escape(step.get('time_utc', 'unknown'))}] "
                    f"{actor_str} {step_action}. "
                    f"{target_str}{correlation_note}"
                    f"</li>"
                )
        else:
            attack_chain_html += "<li style='text-decoration: none;'>No attack chain generated by AI.</li>"
        attack_chain_html += "</ol>"
        
        if ai_data.get('approx_ordering'):
            st.markdown("<small style='text-decoration: none;'><i>Note: Attack chain ordering is approximate due to missing or inconsistent timestamps.</i></small>", unsafe_allow_html=True)

        st.markdown(f"<p style='text-decoration: none;'><b>Potential Malware Family Match:</b> {html_escape(ai_data.get('malware_match', 'None apparent'))} (Confidence: {html_escape(ai_data.get('confidence', 'N/A'))})</p>", unsafe_allow_html=True)

        html_anomalies_corrections_title = "<h3><span style='text-decoration: none; color: inherit;'>Anomalies and Corrections</span></h3>"
        html(html_anomalies_corrections_title, height=40)
        anomalies_html = ""
        if ai_data.get('anomalies', {}).get('flags'):
            anomalies_html += "<p style='text-decoration: none;'><b>Flags (Inconsistent Data):</b></p><ul>"
            anomalies_html += "".join([f"<li style='text-decoration: none;'>{html_escape(flag)}</li>" for flag in ai_data['anomalies']['flags']])
            anomalies_html += "</ul>"
        if ai_data.get('anomalies', {}).get('corrections'):
            anomalies_html += "<p style='text-decoration: none;'><b>Corrections Made:</b></p><ul>"
            anomalies_html += "".join([f"<li style='text-decoration: none;'>Field: `{html_escape(corr.get('field'))}`, Original: `{html_escape(corr.get('original'))}`, Corrected: `{html_escape(corr.get('corrected'))}` (Reason: {html_escape(corr.get('reason'))})</li>" for corr in ai_data['anomalies']['corrections']])
            anomalies_html += "</ul>"
        
        if not (ai_data.get('anomalies', {}).get('flags') or ai_data.get('anomalies', {}).get('corrections')):
            anomalies_html = "<p style='text-decoration: none;'>No anomalies or corrections noted by AI.</p>"
        st.markdown(anomalies_html, unsafe_allow_html=True)

        html_glossary_title = "<h3><span style='text-decoration: none; color: inherit;'>Glossary</span></h3>"
        html(html_glossary_title, height=40)
        glossary_html = "<ul>"
        if ai_data.get('glossary'):
            glossary_html += "".join([f"<li style='text-decoration: none;'><b>{html_escape(term)}:</b> {html_escape(explanation)}</li>" for term, explanation in ai_data['glossary'].items()])
        else:
            glossary_html += "<li style='text-decoration: none;'>No glossary terms provided by AI.</li>"
        glossary_html += "</ul>"
        st.markdown(glossary_html, unsafe_allow_html=True)

        st.markdown("<small style='text-decoration: none;'><i>Powered by OpenAI GPT. Please cross-reference with detailed findings.</i></small>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("---")

    verdict_message = ""
    verdict_summary = ""
    verdict_class = ""

    if overall_severity_label == "Critical":
        verdict_message = "MALWARE: HIGHLY LIKELY - IMMEDIATE ACTION REQUIRED!"
        verdict_summary = "DeepProbe's rule engine detected strong indicators of active malware and highly suspicious attack patterns."
        verdict_class = "critical"
    elif overall_severity_label == "High":
        verdict_message = "HIGH SUSPICION: INVESTIGATE NOW!"
        verdict_summary = "Significant suspicious activities, including potential attack chains, were found. Further investigation is strongly recommended."
        verdict_class = "high"
    elif overall_severity_label == "Medium":
        verdict_message = "UNUSUAL ACTIVITY DETECTED: REVIEW REQUIRED"
        verdict_summary = "DeepProbe identified several unusual activities that could be legitimate but also hint at potential early-stage compromise or misconfiguration."
        verdict_class = "medium"
    elif overall_severity_label == "Low":
        verdict_message = "LOW-LEVEL ANOMALIES: FOR INFORMATIONAL REVIEW"
        verdict_summary = "Minor anomalies or informational findings were detected. These are generally not indicative of a direct threat but are provided for completeness."
        verdict_class = "low"
    else:
        verdict_message = "NO SIGNIFICANT THREATS DETECTED"
        verdict_summary = "DeepProbe's rule engine found no definitive signs of malware or suspicious attack patterns in the memory image."
        verdict_class = "informational"

    # Use a generic verdict box if no AI verdict is available, or use a new one with a margin if AI verdict exists
    verdict_box_style = "margin-top: 1.5rem;" if ai_verdict_from_file.get('verdict') != 'N/A' else ""

    st.markdown(f"""
        <div class="verdict-box {verdict_class}" {"style='margin-top: 1.5rem;'" if ai_verdict_from_file.get('verdict') != 'N/A' else ""}>
            <h2><span style='text-decoration: none; color: inherit;'>DeepProbe Rule-Based Verdict: {html_escape(verdict_message)}</span></h2>
            <p style='text-decoration: none;'>{html_escape(verdict_summary)}</p>
            <p style='text-decoration: none;'>Overall Risk Score: <b>{html_escape(str(total_score))}</b></p>
        </div>
    """, unsafe_allow_html=True)


    if not findings:
        st.success("Analysis completed, and no suspicious findings were detected.")
        return

    report_tab, artifacts_tab = st.tabs(["Analysis Report", "Raw Artifacts"]) # Removed emojis from tab titles

    with report_tab:
        html_analysis_summary_title = "<h2><span style='text-decoration: none; color: inherit;'>Analysis Summary</span></h2>"
        html(html_analysis_summary_title, height=50)
        st.markdown(f"""
        <div class="severity-grid">
            <div class="severity-box critical"><div class="severity-title">Critical</div><div class="severity-count">{severity_counts['Critical']}</div></div>
            <div class="severity-box high"><div class="severity-title">High</div><div class="severity-count">{severity_counts['High']}</div></div>
            <div class="severity-box medium"><div class="severity-title">Medium</div><div class="severity-count">{severity_counts['Medium']}</div></div>
            <div class="severity-box low"><div class="severity-title">Low</div><div class="severity-count">{severity_counts['Low']}</div></div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        if correlated_findings:
            html_attack_story_title = "<h2><span style='text-decoration: none; color: inherit;'>The Attack Story: How DeepProbe Uncovered the Threat</span></h2>"
            html(html_attack_story_title, height=50)
            st.write("DeepProbe analyzed multiple indicators to build a high-confidence narrative of a potential attack. The following shows the attack flow step-by-step.")
            sorted_correlated_findings = sorted(correlated_findings, key=lambda f: f['weight'], reverse=True)
            for f in sorted_correlated_findings:
                render_correlated_finding_narrative(f, detections_config)
            st.markdown("---")

        html_findings_narrative_title = "<h2><span style='text-decoration: none; color: inherit;'>Findings Narrative</span></h2>"
        html(html_findings_narrative_title, height=50)
        st.write("A quick overview of every suspicious activity detected and why it's considered an issue:")

        st.markdown("<div class='findings-narrative-list'>", unsafe_allow_html=True)
        sorted_findings_for_narrative = sorted(findings, key=lambda x: x.get('weight', 0), reverse=True)
        for f in sorted_findings_for_narrative:
            finding_severity_class = "informational"
            for band in detections_config.get('scoring', {}).get('severity_bands', []):
                if f.get('weight', 0) <= int(band['max']):
                    finding_severity_class = band['label'].lower()
                    break

            st.markdown(f"""
                <div class='findings-narrative-item {finding_severity_class}'>
                    <strong style='text-decoration: none;'>{html_escape(f.get('title'))}:</strong> <span style='text-decoration: none;'>{html_escape(get_narrative(f.get('id'), detections_config))}</span>
                </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("---")

        html_recent_commands_overview_title = "<h2><span style='text-decoration: none; color: inherit;'>Recent Commands Overview</span></h2>" # Removed emoji
        html(html_recent_commands_overview_title, height=50)
        st.write("Below are commands and command-line arguments identified as potentially suspicious or relevant from the memory image:")
        
        recent_commands_df_data = []
        for finding in findings:
            if finding['id'] == 'suspicious_cmdline_args':
                for ev in finding.get('evidence', []):
                    recent_commands_df_data.append({
                        "Type": "Windows Command Line",
                        "Process Name": ev.get('name', 'N/A'),
                        "PID": ev.get('pid', 'N/A'),
                        "Command/Arguments": ev.get('command_line', 'N/A')
                    })
            elif finding['id'] == 'bash_history_suspicious':
                for ev in finding.get('evidence', []):
                    recent_commands_df_data.append({
                        "Type": "Bash History",
                        "Process Name": "N/A", 
                        "PID": "N/A",
                        "User": ev.get('User', 'N/A'),
                        "Command/Arguments": ev.get('Command', 'N/A')
                    })
        
        if recent_commands_df_data:
            recent_commands_df = pd.DataFrame(recent_commands_df_data)
            desired_columns = ["Type", "Process Name", "PID", "User", "Command/Arguments"]
            for col in desired_columns:
                if col not in recent_commands_df.columns:
                    recent_commands_df[col] = 'N/A'
            recent_commands_df = recent_commands_df[desired_columns]
            
            st.dataframe(recent_commands_df, use_container_width=True, hide_index=True)
            st.info("This table highlights commands executed or found in console history. Review these for unauthorized or malicious activity.")
        else:
            st.info("No suspicious commands were found in the analysis.")
        st.markdown("---")

        html_all_detected_activities_title = "<h2><span style='text-decoration: none; color: inherit;'>All Detected Activities: Detailed Findings</span></h2>"
        html(html_all_detected_activities_title, height=50)
        st.write("Below are all individual suspicious activities found, ordered by severity.")

        sorted_regular_findings = sorted(regular_findings, key=lambda x: x.get('weight', 0), reverse=True)

        for f in sorted_regular_findings:
            finding_severity_class = "informational"
            for band in detections_config.get('scoring', {}).get('severity_bands', []):
                if f.get('weight', 0) <= int(band['max']):
                    finding_severity_class = band['label'].lower()
                    break

            html_finding_title = f"<h3 style='color: #2c3e50;'><span style='text-decoration: none; color: inherit;'>{html_escape(f.get('title'))}</span></h3>"
            
            st.markdown(f"""
            <div class="card {finding_severity_class}">
            """, unsafe_allow_html=True)
            html(html_finding_title, height=45)
            st.markdown(f"""
                <p style='text-decoration: none;'>Severity Score: <b>{html_escape(str(f.get('weight', 0)))}</b> | MITRE ATT&CK®: <code>{html_escape(", ".join(f.get('mitre', [])))}</code></p>
                <div class="narrative-block">
                    <p style='text-decoration: none;'><b>Why it's an issue:</b> {html_escape(get_narrative(f.get('id'), detections_config))}</p>
                </div>
                <p style='text-decoration: none;'><b>Supporting Evidence:</b></p>
            </div>
            """, unsafe_allow_html=True)

            render_evidence_as_table(f.get('evidence', []), f.get('id'))
            st.markdown("---")

    with artifacts_tab:
        html_downloadable_raw_artifacts_title = "<h2><span style='text-decoration: none; color: inherit;'>Downloadable Raw Artifacts</span></h2>" # Removed emoji
        html(html_downloadable_raw_artifacts_title, height=50)
        
        project_artifacts_folder = OUTPUT_FOLDER / st.session_state.project_name / "artifacts"
        
        print(f"[DEBUG] Artifacts folder path: {project_artifacts_folder}")

        if not st.session_state.analysis_successful:
            st.info("No artifacts available. Please run an analysis.")
            print("[DEBUG] Analysis not successful or no project name, skipping artifact display.")
        elif not project_artifacts_folder.exists():
            st.warning(f"Artifacts folder does not exist: '`{html_escape(str(project_artifacts_folder))}`'. This might mean no artifacts were generated or the path is incorrect.")
            print(f"[DEBUG] Artifacts folder does not exist: {project_artifacts_folder}")
        else:
            st.write("These are the raw text or CSV files generated during the scan. You can download them or view their content directly.")

            artifact_files = [] 
            try:
                if project_artifacts_folder.exists():
                    artifact_files = [f for f in os.listdir(project_artifacts_folder) if os.path.isfile(os.path.join(project_artifacts_folder, f))]
                    # Filter for only .txt, .csv, .json, and .jsonl files for inline viewing
                    viewable_artifact_files = sorted([f for f in artifact_files if f.endswith(('.txt', '.csv', '.json', '.jsonl'))])
                    
                    print(f"[DEBUG] Found {len(artifact_files)} total files, {len(viewable_artifact_files)} viewable files in artifacts folder.")
                else:
                    print(f"[DEBUG] Artifacts folder does not exist: {project_artifacts_folder}")
                    viewable_artifact_files = []

                if not artifact_files:
                    st.info("No raw artifact files were generated for this project.")
                    print("[DEBUG] No artifact files found in the list after scanning folder.")
                else:
                    st.markdown("---")
                    st.subheader("View Artifact File Content")
                    
                    selected_artifact_to_view = st.selectbox(
                        "Select an artifact file to view:",
                        options=["-- Select a file --"] + viewable_artifact_files,
                        key="artifact_viewer_selectbox"
                    )

                    if selected_artifact_to_view and selected_artifact_to_view != "-- Select a file --":
                        file_path_to_view = project_artifacts_folder / selected_artifact_to_view
                        try:
                            if selected_artifact_to_view.endswith(('.csv', '.jsonl')):
                                # Read as CSV for structured display
                                df_content = pd.read_csv(file_path_to_view)
                                st.dataframe(df_content, use_container_width=True)
                            elif selected_artifact_to_view.endswith('.json'):
                                with open(file_path_to_view, 'r', encoding='utf-8') as f:
                                    json_content = json.load(f)
                                st.json(json_content) # Streamlit's JSON viewer
                            else: # Treat as plain text
                                with open(file_path_to_view, 'r', encoding='utf-8') as f:
                                    text_content = f.read()
                                st.text_area("File Content", text_content, height=400, key="artifact_text_viewer")
                        except Exception as view_e:
                            st.error(f"Error reading or displaying selected file '`{html_escape(selected_artifact_to_view)}`': {html_escape(str(view_e))}")
                            print(f"[ERROR] Error viewing artifact file {selected_artifact_to_view}: {view_e}")
                    
                    st.markdown("---")
                    st.subheader("Download All Artifact Files")

                    artifact_files_sorted = sorted(artifact_files)
                    
                    col_count = 3
                    cols = st.columns(col_count)
                    col_idx = 0

                    for file_name in artifact_files_sorted:
                        artifact_info = artifact_descriptions.get(file_name, {})
                        display_title = artifact_info.get("title", file_name)
                        description = artifact_info.get("description", "Raw output from a Volatility plugin or DeepProbe artifact file.")
                        
                        file_path = project_artifacts_folder / file_name
                        
                        print(f"[DEBUG] Processing file: {file_name}")

                        is_file_present = file_path.exists()
                        card_class = ""
                        download_button_disabled = False
                        if not is_file_present:
                            card_class = "missing-file"
                            description = "File not found on disk. It may not have been generated by the analysis."
                            download_button_disabled = True

                        with cols[col_idx]:
                            st.markdown(f"""
                                <div class="artifact-card {card_class}">
                                    <h3 style='text-decoration: none;'><span style='text-decoration: none; color: inherit;'>{html_escape(display_title)}</span></h3>
                                    <p style='text-decoration: none;'><small>{html_escape(description)}</small></p>
                                    <div style="flex-grow: 1;"></div>
                                    """, unsafe_allow_html=True)
                            
                            file_data = b""
                            if is_file_present:
                                try:
                                    with open(file_path, "rb") as fp:
                                        file_data = fp.read()
                                except Exception as read_e:
                                    st.error(f"Error reading file '`{html_escape(file_name)}`': {html_escape(str(read_e))}")
                                    print(f"[ERROR] Error reading artifact file {file_name}: {read_e}")
                                    download_button_disabled = True

                            st.download_button(
                                label=f"Download {file_name}",
                                data=file_data,
                                file_name=file_name,
                                mime="application/octet-stream",
                                key=f"download_artifact_{file_name}",
                                disabled=download_button_disabled
                            )
                            st.markdown("</div>", unsafe_allow_html=True)
                        col_idx = (col_idx + 1) % col_count

            except Exception as e:
                st.error(f"Could not read or process artifact files from '`{html_escape(str(project_artifacts_folder))}`'. Error: {html_escape(str(e))}")
                print(f"[ERROR] Outer artifact rendering loop failed: {e}")

if __name__ == "__main__":
    main()

