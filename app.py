import streamlit as st
import subprocess
import sys
import time
import re
import base64
import math
import requests
from pathlib import Path
import os
import json
import yaml
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from streamlit.components.v1 import html
from datetime import datetime

# --- Configuration ---
BASE_DIR = Path(__file__).parent
CLI_SCRIPT_PATH = BASE_DIR / "runner.py"
MEMORY_FOLDER = BASE_DIR / "memory"
OUTPUT_FOLDER = BASE_DIR / "out" # Base output directory
BASELINE_FILE_PATH = BASE_DIR / "baseline.yaml"
DETECTIONS_FILE_PATH = BASE_DIR / "detections.yaml"

# Ollama — reads from env var set by docker-compose; falls back to localhost for dev
def _resolve_ollama_host() -> str:
    """
    Pick the right Ollama base URL depending on where the app is running.

    Priority:
      1. OLLAMA_HOST env var (set by docker-compose to http://ollama:11434) — always wins.
      2. If we're inside a Docker container (/.dockerenv exists) and no explicit var was
         given, reach the host machine via the special DNS name `host.docker.internal`.
         This covers the case where someone runs the DeepProbe container standalone
         while Ollama is running on the host.
      3. Plain localhost — for native / dev runs outside Docker.
    """
    explicit = os.environ.get("OLLAMA_HOST", "")
    if explicit:
        return explicit
    if Path("/.dockerenv").exists():
        return "http://host.docker.internal:11434"
    return "http://localhost:11434"

OLLAMA_HOST = _resolve_ollama_host()
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "llama3.2:3b")

RECOMMENDED_MODELS = [
    "llama3.2:3b",    # 2 GB  — fast, works on any machine
    "llama3.1:8b",    # 5 GB  — better reasoning
    "mistral:7b",     # 4 GB  — excellent instruction following
    "phi3:mini",      # 2.3 GB — lightest option
    "gemma2:2b",      # 1.6 GB — Google Gemma, very lightweight
]

# set_page_config MUST be the first Streamlit command executed.
# It lives here at module scope so it runs before any other st.* call
# (including the CSS st.markdown block below).
st.set_page_config(
    page_title="DeepProbe | Memory Forensics",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Ollama helper functions
# ---------------------------------------------------------------------------

def check_ollama_health() -> bool:
    """Return True if the Ollama service is reachable."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def get_ollama_models() -> list:
    """Return list of model names already pulled in Ollama."""
    try:
        r = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=3)
        if r.status_code == 200:
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass
    return []


def pull_ollama_model(model_name: str) -> tuple:
    """
    Pull a model from the Ollama library.
    Returns (success: bool, message: str).
    Uses stream=False so the whole pull happens in one request (up to 10 min).
    """
    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/pull",
            json={"name": model_name, "stream": False},
            timeout=600,
        )
        if r.status_code == 200:
            return True, f"Model `{model_name}` downloaded successfully."
        return False, f"Pull failed — HTTP {r.status_code}: {r.text[:200]}"
    except requests.exceptions.Timeout:
        return False, "Pull timed out (>10 min). Try a smaller model or check your connection."
    except Exception as e:
        return False, f"Pull error: {e}"


def query_ollama(model: str, prompt: str) -> str:
    """Send a prompt to Ollama and return the response text.

    Determinism settings:
      temperature=0  → greedy decoding, no randomness.
      seed=42        → reproducible outputs across identical prompts.
      top_p=1.0      → disable nucleus sampling (irrelevant at temp=0 but explicit).
    These settings prevent hallucinations by making the model output the single
    most probable token at every step instead of sampling randomly.
    """
    try:
        r = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0,
                    "seed": 42,
                    "top_p": 1.0,
                    "num_predict": 512,   # cap token budget — forensic summaries don't need to be long
                },
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("response", "No response returned by model.")
    except requests.exceptions.ConnectionError:
        return "⚠️ Cannot reach Ollama service. Is it running? Check the sidebar status."
    except requests.exceptions.Timeout:
        return "⚠️ Ollama took too long to respond. Try a smaller/faster model."
    except requests.exceptions.HTTPError as e:
        # Try to get the real reason from Ollama's JSON body
        body_msg = ""
        if e.response is not None:
            try:
                body_msg = e.response.json().get("error", "")
            except Exception:
                body_msg = e.response.text or ""
            if e.response.status_code == 404 or (
                "not found" in body_msg.lower() or "pull" in body_msg.lower()
            ):
                return (
                    f"⚠️ Model **{model}** is not downloaded yet. "
                    "Open the sidebar, select the model and click '⬇️ Download' to pull it first."
                )
        return f"⚠️ Ollama returned an error ({e.response.status_code if e.response else '?'}): {body_msg or str(e)}"
    except Exception as e:
        return f"⚠️ Ollama error: {e}"


def _clean_evidence_for_llm(raw_evidence: list, max_items: int = 3) -> list:
    """
    Filter and sanitise evidence items before sending to an LLM.
    Removes:
      - Volatility internal messages (warnings, library path lines, progress output)
      - Items that are plain strings containing no useful forensic data
      - Keys whose values are empty, None, or noise strings
    Returns a list of clean dicts with at most max_items entries.
    """
    _NOISE_PATTERNS = re.compile(
        r"(^WARNING|^ERROR|^INFO|Traceback|\.pyc|site-packages|volatility3|"
        r"^\s*$|Progress:|Stacking attempts|incompatible:|PluginRequirements)",
        re.IGNORECASE,
    )
    _NOISE_VALUES = {"", "None", "N/A", "nan", "0", "0.0", "-", "—"}

    cleaned = []
    for item in raw_evidence:
        if not isinstance(item, dict):
            # Skip raw string lines (Volatility console output)
            continue
        filtered = {
            k: v for k, v in item.items()
            if str(v).strip() not in _NOISE_VALUES
            and not _NOISE_PATTERNS.search(str(v))
        }
        if filtered:
            cleaned.append(filtered)
        if len(cleaned) >= max_items:
            break
    return cleaned


def query_llm(finding: dict, model: str = DEFAULT_MODEL, gemini_key: str = "") -> str:
    """
    Unified LLM call for individual (non-correlated) findings.
    Evidence is pre-filtered through _clean_evidence_for_llm() before the prompt is built.
    The prompt enforces strict evidence-bound output with no hallucination, no unsafe
    remediation advice, and no MITRE IDs embedded inline in explanation text.
    """
    title  = finding.get('title', 'Unknown Finding')
    weight = finding.get('weight', 0)
    # MITRE IDs provided as reference metadata only — not for inline embedding
    mitre_ref = ', '.join(finding.get('mitre', [])) or 'None provided'

    clean_ev = _clean_evidence_for_llm(finding.get("evidence", []), max_items=3)
    evidence_sample = (
        json.dumps(clean_ev, indent=2, ensure_ascii=False)
        if clean_ev else "(no structured evidence available)"
    )

    prompt = (
        "You are a memory forensics analyst reviewing a single finding from an automated scan.\n\n"
        "HARD CONSTRAINTS — non-negotiable rules for your response:\n"
        "1. Use ONLY the finding title and evidence fields provided below. "
        "   Do NOT generate or infer file paths, process names, IP addresses, PIDs, "
        "   module names, registry keys, or memory values not present in the evidence.\n"
        "2. Do NOT mention lateral movement, credential theft, persistence, C2 communication, "
        "   privilege escalation, or any attack technique UNLESS the finding title or evidence "
        "   explicitly names it.\n"
        "3. Do NOT embed MITRE technique IDs inline in your explanation. "
        "   MITRE tags are provided as reference metadata only — do not quote them in body text.\n"
        "4. Avoid hedging language: do NOT write 'may be used', 'could indicate', "
        "   'might suggest', 'possibly', or 'likely' unless the evidence explicitly limits certainty. "
        "   State what the evidence shows directly, or omit the claim.\n"
        "5. Remediation — ONLY use these safe forms: "
        "   'isolate the system', 'investigate affected processes', 'collect memory artifacts', "
        "   'preserve the memory image', 'escalate to the IR team'. "
        "   NEVER recommend killing, terminating, or stopping a specific process by name.\n"
        "6. If the evidence is insufficient to support a statement, say so explicitly.\n\n"
        f"Finding: {title}\n"
        f"Severity Score: {weight} / 15\n"
        f"MITRE reference (metadata only, do not quote inline): {mitre_ref}\n"
        f"Evidence (filtered, up to 3 items):\n{evidence_sample}\n\n"
        "Respond with exactly three short paragraphs:\n"
        "**What this means:** Summarise what the evidence shows — state facts, not assumptions.\n"
        "**Why it is dangerous:** Describe the confirmed risk based only on the evidence provided.\n"
        "**Immediate actions:** List 2-3 steps using only the safe remediation forms above."
    )

    if gemini_key:
        return query_gemini(gemini_key, {
            **finding,
            "evidence": clean_ev,
            "_prompt_override": prompt,
        })
    return query_ollama(model, prompt)


def query_llm_correlated(finding: dict, model: str = DEFAULT_MODEL, gemini_key: str = "") -> str:
    """
    LLM call specifically for correlated / system-wide findings.
    Builds a chain-aware prompt from correlated_chains. Evidence items are
    pre-filtered through _clean_evidence_for_llm() to remove Volatility noise
    before any values reach the model.
    """
    fid    = finding.get("id", "")
    title  = finding.get("title", "Correlated Threat")
    # Use MITRE IDs exactly as provided — never remap or reinterpret
    mitre  = ", ".join(finding.get("mitre", [])) or "None provided"
    chains = finding.get("correlated_chains", [])

    # ------------------------------------------------------------------
    # Build sanitised chain text — only clean forensic signals reach LLM
    # ------------------------------------------------------------------
    chain_lines: list = []
    for item in chains:
        pid       = item.get("correlated_pid", "?")
        corr_type = item.get("correlation_type", "")
        layers    = item.get("layers_involved", [])

        sub_findings = item.get("correlated_findings", [])
        for sf in sub_findings[:8]:
            layer_tag = f"[{sf.get('layer', corr_type or 'unknown').upper()}] " if sf.get("layer") else ""
            role_tag  = f" ({sf.get('process_role', '')})" if sf.get("process_role") else ""

            # Clean the evidence sample — removes Volatility warnings, library paths, etc.
            raw_ev = sf.get("evidence", [])
            clean  = _clean_evidence_for_llm(raw_ev, max_items=1)
            if clean:
                # Only include key-value pairs where the value is ≤60 chars (avoids memory blobs)
                ev_parts = [
                    f"{k}: {str(v)[:60]}"
                    for k, v in list(clean[0].items())[:4]
                    if str(v).strip() not in ("", "None", "N/A", "nan")
                    and len(str(v)) <= 200            # skip raw hex / base64 blobs
                    and not str(v).startswith("0x")  # skip memory addresses
                ]
                ev_txt = ", ".join(ev_parts)
            else:
                ev_txt = ""

            chain_lines.append(
                f"  • {layer_tag}{sf.get('title', sf.get('finding_id', '?'))}{role_tag}"
                + (f"  [evidence: {ev_txt}]" if ev_txt else "")
            )

    chain_text = "\n".join(chain_lines) or "  (no individual findings listed)"

    # ------------------------------------------------------------------
    # Hard constraint block — injected into every correlated prompt
    # ------------------------------------------------------------------
    _HARD_CONSTRAINTS = (
        "HARD CONSTRAINTS — non-negotiable rules for your response:\n"
        "1. Use ONLY the finding names and evidence fields explicitly listed below. "
        "   Do NOT generate, infer, or assume file paths, process names, PIDs, "
        "   memory addresses, module names, or registry keys not present in the data.\n"
        "2. Do NOT mention lateral movement, credential theft, persistence, C2 communication, "
        "   privilege escalation, or any attack technique UNLESS a finding in the list below "
        "   explicitly names it. Do not add attack claims beyond what the findings state.\n"
        "3. Do NOT embed MITRE technique IDs inline in your explanation. "
        "   MITRE tags are provided as reference metadata — do not quote them in body text.\n"
        "4. Avoid hedging language: do NOT write 'may be used', 'could indicate', "
        "   'might suggest', 'possibly', or 'likely' unless the evidence explicitly limits certainty. "
        "   State what the evidence shows directly, or omit the claim entirely.\n"
        "5. Remediation — ONLY use these safe forms: "
        "   'isolate the system', 'investigate affected processes', 'collect memory artifacts', "
        "   'preserve the memory image', 'escalate to the IR team'. "
        "   NEVER name a specific process to kill, terminate, or stop.\n"
        "6. Use 'analysis indicates' or 'evidence shows' — not 'the attacker did'.\n"
        "7. If the evidence is insufficient to support a statement, say so explicitly "
        "   rather than filling the gap with plausible-sounding detail.\n\n"
    )

    # System-wide compromise
    if fid == "correlation_system_wide":
        all_layers = sorted({
            layer
            for item in chains
            for layer in item.get("layers_involved", [])
        })
        prompt = (
            "You are a memory forensics analyst producing an evidence-bound summary "
            "of a system-wide compromise for an incident response team.\n\n"
            + _HARD_CONSTRAINTS +
            f"Confirmed forensic layers ({len(all_layers)} simultaneously active): "
            f"{', '.join(all_layers) or 'multiple layers'}\n"
            f"MITRE reference (metadata only, do not quote inline): {mitre}\n\n"
            f"Findings present in this memory image:\n{chain_text}\n\n"
            "Respond with exactly three sections:\n\n"
            "**What this means:** Summarise what each listed finding shows. "
            "State only what the evidence above directly supports. "
            "Do not infer a sequence of events, initial access method, or attacker motivation.\n\n"
            "**Why it is dangerous:** Describe the confirmed risk of having high-severity "
            "indicators across multiple forensic layers simultaneously. "
            "Base every statement on a specific finding from the list above — "
            "do not extrapolate or add attack claims not present in the findings.\n\n"
            "**Immediate actions:** List exactly 3 steps. "
            "Use only these forms: 'isolate the system', 'investigate affected processes', "
            "'collect memory artifacts', 'preserve the memory image', 'escalate to the IR team'. "
            "Do not name a specific process to terminate or stop."
        )
    else:
        # Pair-based correlated finding
        confidence = chains[0].get("confidence", "") if chains else ""
        conf_scope = {
            "strong": "within the same process (PID-level match)",
            "medium": "across a parent-child process pair",
            "weak":   "as co-present behavioral indicators in the same image",
        }.get(confidence, "across multiple correlated findings")

        prompt = (
            f"You are a memory forensics analyst reviewing a correlated finding.\n"
            f"Correlation: {title}\n"
            f"Scope: {conf_scope}\n\n"
            + _HARD_CONSTRAINTS +
            f"MITRE reference (metadata only, do not quote inline): {mitre}\n\n"
            f"Findings present in this memory image:\n{chain_text}\n\n"
            "Respond with exactly three sections:\n\n"
            "**What this means:** Describe what the correlated evidence shows — "
            "which findings are linked, how they relate, and what the combination confirms. "
            "State only what the listed findings directly support. "
            "Do not add attack claims beyond what the findings name.\n\n"
            "**Why it is dangerous:** Explain the confirmed risk this correlation represents "
            "and why it is more severe than any single finding alone. "
            "Every statement must be grounded in a specific finding from the list above.\n\n"
            "**Immediate actions:** List 2-3 steps. "
            "Use only these forms: 'isolate the system', 'investigate affected processes', "
            "'collect memory artifacts', 'preserve the memory image', 'escalate to the IR team'. "
            "Do not name a specific process to terminate or stop."
        )

    if gemini_key:
        return query_gemini(gemini_key, {
            "title":    title,
            "mitre":    finding.get("mitre", []),
            "weight":   finding.get("weight", 0),
            "evidence": [],
            "_prompt_override": prompt,
        })
    return query_ollama(model, prompt)


# Ensure necessary directories exist at startup.
try:
    MEMORY_FOLDER.mkdir(exist_ok=True)
    OUTPUT_FOLDER.mkdir(exist_ok=True)
except Exception as e:
    print(f"FATAL ERROR: Could not create necessary directories for DeepProbe. Please check file system permissions. Error: {e}", file=sys.stderr)
    st.error(f"Initialization Error: DeepProbe could not create essential directories ('memory/', 'out/'). "
             f"Please verify your file system permissions in the directory where you are running the app. Error: {e}")
    st.stop()

# --- Custom CSS Fixes ---
# This CSS removes the Streamlit header and its associated spacing, and also the default top padding.
st.markdown(
    """
    <style>
    /* Remove Streamlit default padding */
    .block-container {
        padding-top: 0rem;
    }

    /* Hide Streamlit top header (Deploy, hamburger menu, etc.) */
    header[data-testid="stHeader"] {
        display: none;
    }

    /* Also hide empty space left by toolbar */
    div[data-testid="stDecoration"] {
        display: none;
    }
    
    /* --- Custom Table Styling --- */
    /* This section is a stronger fix for table rendering */
    div[data-testid="stTable"] table,
    div[data-testid="stDataFrame"] table,
    .stTable table,
    .stDataFrame table {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
    }

    div[data-testid="stTable"] table td, 
    div[data-testid="stTable"] table th,
    div[data-testid="stDataFrame"] table td, 
    div[data-testid="stDataFrame"] table th,
    .stTable table td, .stTable table th,
    .stDataFrame table td, .stDataFrame table th {
        background-color: #161b22 !important;
        color: #c9d1d9 !important;
        border: 1px solid #30363d !important;
    }

    .stDataFrame thead th {
        background-color: #161b22 !important;
        color: #2ecc71 !important; /* Retain green header */
        border-bottom: 2px solid #2ecc71 !important;
    }

    .stDataFrame tbody tr:hover {
        background-color: #21262d !important;
    }

    /* Make sure scrollbar/scroll container also uses dark background */
    .stDataFrame [data-testid="stTable"] {
        background-color: #161b22 !important;
    }

    /* Also include styling for the artifacts tab tables */
    [data-testid="stVerticalBlock"] [data-testid="stDataFrame"] thead th {
        color: #2ecc71 !important;
    }
    [data-testid="stVerticalBlock"] [data-testid="stDataFrame"] tbody tr td {
        color: #c9d1d9 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

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
        "windows.dlllist": "Listing loaded DLLs for each process, useful for identifying injected or suspicious modules.",
        "windows.apihooks": "Detecting Windows API hooks...",
        "windows.devicetree": "Analyzing Windows device tree...",
        "windows.modscan": "Scanning Windows kernel modules...",
        "windows.consoles": "Recovers Windows console history...",
        "windows.clipboard": "Recovers clipboard contents...",
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

def run_analysis_and_show_progress(case_name, memory_file_path, ip_enrichment_api_key, progress_bar, status_text):
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
    if not DETECTIONS_FILE_PATH.exists():
        status_text.error(f"FATAL ERROR: '`detections.yaml`' not found at '`{html_escape(str(BASE_DIR))}`'.")
        return False
    if not BASELINE_FILE_PATH.exists():
        status_text.error(f"FATAL ERROR: '`baseline.yaml`' not found at '`{html_escape(str(BASE_DIR))}`'.")
        return False

    cmd = [
        sys.executable, '-u', str(CLI_SCRIPT_PATH),
        "--image", str(memory_file_path), "--case", case_name,
        "--detections", str(DETECTIONS_FILE_PATH),
        "--baseline", str(BASELINE_FILE_PATH),
        "--outdir", str(project_output_folder),
        "--api-key", ip_enrichment_api_key
    ]


    st.session_state.analysis_logs = []
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding='utf-8', errors='replace', bufsize=1
    )

    TOTAL_STEPS = 20
    current_step = 0
    status_text.info("Preparing analysis environment…")

    completed_plugins = []
    checklist_placeholder = st.empty()

    def _render_checklist(done_list, current_msg=""):
        lines = []
        for p in done_list[-12:]:          # show last 12 to avoid overflow
            lines.append(f"✅ `{p}`")
        if current_msg:
            lines.append(f"⟳ *{current_msg}*")
        checklist_placeholder.markdown("\n\n".join(lines))

    # Robust loop reading subprocess output line-by-line
    while True:
        line = process.stdout.readline()
        if not line and process.poll() is not None:
            break
        if line:
            st.session_state.analysis_logs.append(line)
            if "[+] Running plugin:" in line:
                current_step += 1
                try:
                    plugin_name = line.split(":", 1)[1].strip().split(" ")[0]
                    friendly_name = get_friendly_scan_name(plugin_name)
                    status_text.info(friendly_name)
                    if completed_plugins:
                        completed_plugins[-1] = completed_plugins[-1]   # keep prev
                    # mark the previous as done and show the current as in-progress
                    _render_checklist(completed_plugins, friendly_name)
                    completed_plugins.append(friendly_name)
                except IndexError:
                    pass
                progress_fraction = min(1.0, current_step / TOTAL_STEPS)
                progress_bar.progress(progress_fraction, text=f"{int(progress_fraction*100)}% Complete")
            elif "[i] Running detection engine:" in line:
                msg = line.strip().replace("[i] Running detection engine: ", "Running engine: ")
                status_text.info(msg)
                _render_checklist(completed_plugins, msg)
            elif "[i] Starting correlation analysis:" in line or "[i] Finished correlation" in line:
                status_text.info("Running correlation analysis…")
                _render_checklist(completed_plugins, "Correlating findings…")
            elif "[WARN]" in line:
                # Emit API fallback warning visibly
                st.warning(line.strip().replace("[WARN] ", "⚠️ "))

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

def load_detections_config():
    """Loads the detections.yaml config from the base directory."""
    if DETECTIONS_FILE_PATH.exists():
        with open(DETECTIONS_FILE_PATH, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return None

def load_baseline_config():
    """Loads the baseline.yaml config from the base directory."""
    if BASELINE_FILE_PATH.exists():
        with open(BASELINE_FILE_PATH, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    return None

_BUILTIN_NARRATIVES = {
    "correlation_evasion_priv_esc": (
        "Evasion techniques (AMSI bypass, ETW patching) were detected alongside privilege "
        "escalation indicators (token impersonation, code injection). This combination suggests "
        "an attacker actively suppressing defenses while elevating their access level — a "
        "hallmark of post-exploitation activity following initial access."
    ),
    "correlation_lolbin_chain": (
        "Living-off-the-land binaries (LOLBins) or WMI were detected in conjunction with "
        "network activity or persistence mechanisms. Attackers abuse built-in system tools "
        "to blend with normal activity while establishing command-and-control channels or "
        "maintaining long-term access."
    ),
    "correlation_exfil_chain": (
        "Archive staging artifacts were detected alongside outbound connections or suspicious "
        "network activity. This pattern matches the Collection and Exfiltration phases of the "
        "MITRE ATT&CK framework — data is gathered, compressed, and then transferred to "
        "attacker-controlled infrastructure."
    ),
}

# ---------------------------------------------------------------------------
# Dynamic narrative helpers
# ---------------------------------------------------------------------------

_LAYER_FRIENDLY_NAMES = {
    "process": "Process Layer",
    "kernel":  "Kernel Layer",
    "network": "Network Layer",
    "system":  "System Artifact Layer",
}

def _friendly_layer_name(layer: str) -> str:
    """Return a human-readable layer name."""
    return _LAYER_FRIENDLY_NAMES.get(str(layer).lower(), str(layer).replace("_", " ").title())

def _oxford_join(items: list) -> str:
    """Join a list with Oxford comma: 'a, b, and c'."""
    items = [str(i) for i in items if i and str(i) not in ("", "None", "N/A")]
    if not items:   return "unknown activity"
    if len(items) == 1: return items[0]
    if len(items) == 2: return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"

def build_dynamic_chain_narrative(finding: dict) -> str:
    """
    Generate a dynamic, evidence-specific plain-English narrative for correlated findings.
    Uses actual correlated_chains data so every report tells the story of THIS memory image,
    not generic boilerplate.
    """
    fid    = finding.get("id", "")
    chains = finding.get("correlated_chains", [])

    # No chain data → fall back to static text
    if not chains:
        if fid in _BUILTIN_NARRATIVES:
            return _BUILTIN_NARRATIVES[fid]
        return "No correlation details available for this finding."

    # ----------------------------------------------------------------
    # System-wide: group findings by layer, tell each layer's story
    # ----------------------------------------------------------------
    if fid == "correlation_system_wide":
        layer_findings: dict = {}
        for item in chains:
            for sf in item.get("correlated_findings", []):
                layer = sf.get("layer", "unknown")
                ev0   = (sf.get("evidence") or [{}])[0]
                proc  = (
                    ev0.get("name") or ev0.get("process") or
                    ev0.get("ImageFileName") or ev0.get("owner") or ""
                )
                layer_findings.setdefault(layer, []).append({
                    "title":   sf.get("title") or sf.get("finding_id", "suspicious activity"),
                    "process": str(proc).strip(),
                    "pid":     str(ev0.get("PID") or ev0.get("pid") or "").strip(),
                })

        layer_names = sorted(layer_findings.keys())
        total       = sum(len(v) for v in layer_findings.values())
        layer_list  = _oxford_join([_friendly_layer_name(l) for l in layer_names])

        parts = [
            f"This memory image contains {total} high-severity indicator"
            f"{'s' if total != 1 else ''} spread across "
            f"{len(layer_names)} separate parts of the system at the same time — "
            f"the {layer_list}. "
            f"When threats appear simultaneously across independent system layers like this, "
            f"it means the attacker is not just visiting: they are deeply embedded and actively "
            f"operating across the entire machine."
        ]

        for layer in layer_names:
            items  = layer_findings[layer]
            fname  = _friendly_layer_name(layer)
            titles = [i["title"] for i in items[:3]]
            procs  = list({
                i["process"] for i in items
                if i["process"] not in ("", "None", "N/A")
            })[:2]
            proc_clause  = (f", specifically linked to {_oxford_join(procs)}" if procs else "")
            title_clause = _oxford_join(titles)
            parts.append(
                f"In the {fname}{proc_clause}: {title_clause}."
            )

        parts.append(
            "All of this is happening at the same time, which is the most alarming part. "
            "A single suspicious process might be a false alarm. Suspicious activity across "
            "the kernel, network, and system artifacts simultaneously points to a real, "
            "active intrusion. The machine should be isolated immediately and not trusted "
            "until a full forensic investigation is complete."
        )
        return "  ".join(parts)

    # ----------------------------------------------------------------
    # Other correlated findings: brief chain-specific narrative
    # ----------------------------------------------------------------
    all_titles: list = []
    pids:       list = []
    for item in chains:
        pid = item.get("correlated_pid", "")
        if pid and pid not in ("system-wide", "None", ""):
            pids.append(str(pid))
        for sf in item.get("correlated_findings", []):
            t = sf.get("title") or sf.get("finding_id", "")
            if t:
                all_titles.append(t)

    confidence   = (chains[0].get("confidence", "") if chains else "")
    pid_clause   = (
        f" (PID{'s' if len(pids) > 1 else ''} {', '.join(pids[:3])})" if pids else ""
    )
    conf_note    = {
        "strong": "These findings were detected inside the same process",
        "medium": "These findings are linked through a parent-child process relationship",
        "weak":   "These findings co-exist as a behavioral pattern across this memory image",
    }.get(confidence, "These findings were correlated")
    finding_list = _oxford_join(all_titles[:5])

    # Use the static narrative as the opening sentence if available
    base = _BUILTIN_NARRATIVES.get(fid, "")
    if base:
        return f"{base}  In this image, {conf_note.lower()}{pid_clause}: {finding_list}."
    return (
        f"{conf_note}{pid_clause}. The following indicators were detected together: "
        f"{finding_list}. Their simultaneous presence suggests coordinated attacker activity "
        f"rather than isolated anomalies."
    )


def get_narrative(finding_id, detections_config):
    # Programmatically-generated findings (correlations not in YAML) use built-in narratives
    if finding_id in _BUILTIN_NARRATIVES:
        return _BUILTIN_NARRATIVES[finding_id]
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

# ---------------------------------------------------------------------------
# Gemini AI helper
# ---------------------------------------------------------------------------
def query_gemini(api_key: str, finding: dict) -> str:
    """Call Gemini API to explain a finding in plain English."""
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash:generateContent?key={api_key}"
    )
    # Allow callers to inject a fully-formed prompt (used by query_llm_correlated)
    prompt = finding.get("_prompt_override") or None
    if not prompt:
        evidence_sample = json.dumps(finding.get("evidence", [])[:3], indent=2, ensure_ascii=False)
        prompt = (
            f"You are a memory forensics expert. A security analyst is reviewing this finding "
            f"from a live memory image analysis. Explain it clearly and concisely.\n\n"
            f"Finding Title: {finding.get('title', 'Unknown')}\n"
            f"MITRE ATT&CK: {', '.join(finding.get('mitre', []))}\n"
            f"Severity Score: {finding.get('weight', 0)}\n"
            f"Evidence (sample):\n{evidence_sample}\n\n"
            f"Provide exactly three short paragraphs:\n"
            f"1. What this finding means in plain English\n"
            f"2. Why it is dangerous and what the attacker is likely doing\n"
            f"3. The top 2-3 immediate containment/investigation actions the analyst should take"
        )
    try:
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        print(f"[warn] Gemini API HTTP {status}: {e}", file=sys.stderr)
        if status == 400:
            return "⚠️ AI summary unavailable — Gemini rejected the request (invalid API key or model not available)."
        if status == 429:
            return "⚠️ AI summary unavailable — Gemini rate limit hit. Wait a moment and try again."
        return "⚠️ AI summary unavailable — Gemini returned an error. Check your API key."
    except requests.exceptions.Timeout:
        return "⚠️ AI summary unavailable — Gemini took too long to respond. Try again shortly."
    except Exception as e:
        print(f"[warn] Gemini error: {e}", file=sys.stderr)
        return "⚠️ AI summary unavailable. Use the local Ollama model as an alternative."


# ---------------------------------------------------------------------------
# Plotly attack-chain network graph
# ---------------------------------------------------------------------------
def render_attack_chain_graph(correlated_finding: dict):
    """Render attack chain as an interactive Plotly network graph.

    Reads from `correlated_chains` — the dedicated key for correlation data —
    rather than the generic `evidence` field which is used by non-correlation findings.
    Each chain item is {"correlated_pid": str, "correlated_findings": [...]}.
    """
    chains = correlated_finding.get("correlated_chains", [])
    if not chains:
        return

    for item in chains:
        pid = item.get("correlated_pid", "?")
        chain_findings = item.get("correlated_findings", [])
        confidence     = item.get("confidence", "weak")
        corr_type      = item.get("correlation_type", "")
        if not chain_findings:
            continue

        # Centre node colour encodes correlation strength
        _centre_colors = {"strong": "#2ecc71", "medium": "#3498db", "weak": "#e67e22"}
        centre_color = _centre_colors.get(confidence, "#8b949e")

        # Centre label: special handling for non-PID correlation types
        if corr_type == "system_wide":
            centre_label = "🌐 System-Wide"
            centre_color = "#9b59b6"   # purple — distinct from PID-based chains
        elif corr_type == "parent_child":
            centre_label = f"PID {pid}\n(parent)"
        else:
            centre_label = f"PID {pid}"

        n = len(chain_findings)
        radius = 2.2
        angles = [math.pi / 2 + 2 * math.pi * i / n for i in range(n)]

        # Node data
        node_x = [0.0]
        node_y = [0.0]
        node_labels = [centre_label]
        node_colors = [centre_color]
        node_sizes = [28]
        node_hover = [f"<b>Correlated PID: {pid}</b><br>Confidence: {confidence}"]

        severity_colors = {
            "psxview_hidden": "#e74c3c", "malfind_injection": "#e74c3c",
            "ldr_unlinked_module": "#e74c3c", "handles_lsass_access": "#e74c3c",
            "lsass_credential_dump": "#e74c3c", "entropy_anomaly": "#e74c3c",
            "suspicious_connection": "#f39c12", "suspicious_network_enrichment": "#f39c12",
            "suspicious_port_activity": "#f39c12", "netscan_beacon_like": "#f39c12",
        }

        edge_x, edge_y = [], []
        for i, cf in enumerate(chain_findings):
            fx = radius * math.cos(angles[i])
            fy = radius * math.sin(angles[i])
            node_x.append(fx)
            node_y.append(fy)
            fid = cf.get("finding_id", "")
            title = get_user_friendly_correlated_title(fid)
            node_labels.append(title)
            node_colors.append(severity_colors.get(fid, "#9b59b6"))
            node_sizes.append(20)
            ev_count   = len(cf.get("evidence", []))
            role       = cf.get("process_role", "")
            role_txt   = f"<br>Role: {role}" if role else ""
            co_pres    = " (co-presence)" if cf.get("co_presence") else ""
            node_hover.append(f"<b>{title}</b>{co_pres}<br>Evidence items: {ev_count}{role_txt}")
            edge_x += [0, fx, None]
            edge_y += [0, fy, None]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=edge_x, y=edge_y, mode="lines",
            line=dict(width=1.5, color="#30363d"),
            hoverinfo="none", showlegend=False
        ))
        fig.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(size=node_sizes, color=node_colors, line=dict(color="#0d1117", width=2)),
            text=node_labels,
            textfont=dict(color="#c9d1d9", size=11),
            textposition=["middle center"] + ["top center"] * n,
            hovertext=node_hover, hoverinfo="text",
            showlegend=False
        ))
        fig.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font=dict(color="#c9d1d9", family="Fira Code"),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-3.5, 3.5]),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-3.5, 3.5]),
            margin=dict(l=10, r=10, t=10, b=10),
            height=360
        )
        st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# MITRE ATT&CK heatmap
# ---------------------------------------------------------------------------
def render_mitre_heatmap(findings: list):
    """Render a bar chart of triggered MITRE ATT&CK techniques."""
    tactic_map = {
        "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Priv Escalation",
        "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
        "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0010": "Exfiltration",
        "TA0011": "C2", "TA0040": "Impact",
        "T1055": "Process Injection", "T1003": "OS Credential Dump", "T1003.001": "LSASS Memory",
        "T1059": "Command Scripting", "T1547.001": "Registry Run Keys", "T1053": "Scheduled Task",
        "T1053.003": "Cron", "T1053.005": "Sched Task/Job", "T1071": "App Layer Protocol",
        "T1014": "Rootkit", "T1036": "Masquerading", "T1027": "Obfuscated Files",
        "T1574": "Hijack Execution Flow", "T1574.006": "LD_PRELOAD", "T1078": "Valid Accounts",
        "T1112": "Modify Registry", "T1105": "Ingress Tool Transfer", "T1106": "Native API",
        "T1204": "User Execution", "T1562.001": "Disable/Modify Tools",
        "T1082": "System Info Discovery", "T1057": "Process Discovery", "T1550": "Use Alt Material",
        "T1021": "Remote Services", "T1552": "Unsecured Credentials",
    }
    counts: dict = {}
    for f in findings:
        for tag in f.get("mitre", []):
            label = tactic_map.get(tag, tag)
            counts[label] = counts.get(label, 0) + 1

    if not counts:
        st.info("No MITRE ATT&CK tags found in current findings.")
        return

    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    labels = [i[0] for i in sorted_items]
    values = [i[1] for i in sorted_items]
    colors = ["#e74c3c" if v >= 3 else "#f39c12" if v == 2 else "#2ecc71" for v in values]

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker=dict(color=colors),
        text=[str(v) for v in values], textposition="outside",
        textfont=dict(color="#c9d1d9")
    ))
    fig.update_layout(
        paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
        font=dict(color="#c9d1d9", family="Fira Code"),
        xaxis=dict(showgrid=True, gridcolor="#21262d", color="#c9d1d9", title="Number of Findings"),
        yaxis=dict(showgrid=False, color="#c9d1d9", autorange="reversed"),
        margin=dict(l=10, r=60, t=10, b=40),
        height=max(300, len(labels) * 28)
    )
    st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Timeline from shimcache / amcache artifacts
# ---------------------------------------------------------------------------
def _build_timeline_rows(project_name: str) -> list:
    """
    Shared helper — load and filter shimcache/amcache artifacts into a list of
    {'Timestamp', 'Artifact', 'Description'} dicts.  Used by both render_timeline()
    and the summary panel so the count is always consistent with what renders.
    """
    artifacts_dir = OUTPUT_FOLDER / project_name / "artifacts"
    rows = []

    # ── Shimcache ──────────────────────────────────────────────────────────────
    shimcache_path = artifacts_dir / "windows_registry_shimcache.csv"
    if shimcache_path.exists():
        try:
            df_sc = pd.read_csv(shimcache_path, on_bad_lines="skip")
            ts_col = next(
                (c for c in df_sc.columns if re.search(r"(modified|time|date|last)", c, re.I)), None
            )
            path_col = next(
                (c for c in df_sc.columns if re.search(r"(path|file|application)", c, re.I)), None
            )
            if ts_col and path_col:
                for _, row in df_sc.dropna(subset=[ts_col, path_col]).head(100).iterrows():
                    ts_val = str(row[ts_col])[:19]
                    if ts_val not in ("N/A", "nan", "None", ""):
                        rows.append({
                            "Timestamp": ts_val,
                            "Artifact": "Shimcache",
                            "Description": str(row[path_col]),
                        })
        except Exception:
            pass

    # ── Amcache ────────────────────────────────────────────────────────────────
    amcache_path = artifacts_dir / "windows_registry_amcache.csv"
    if amcache_path.exists():
        try:
            df_am = pd.read_csv(amcache_path, on_bad_lines="skip")
            ts_col = next(
                (c for c in df_am.columns if re.search(r"(time|date|modified|write)", c, re.I)), None
            )
            path_col = next(
                (c for c in df_am.columns if re.search(r"(path|file|name|ref)", c, re.I)), None
            )
            if ts_col and path_col:
                for _, row in df_am.dropna(subset=[ts_col, path_col]).head(100).iterrows():
                    ts_val = str(row[ts_col])[:19]
                    if ts_val not in ("N/A", "nan", "None", ""):
                        rows.append({
                            "Timestamp": ts_val,
                            "Artifact": "Amcache",
                            "Description": str(row[path_col]),
                        })
        except Exception:
            pass

    return rows


def render_timeline(project_name: str):
    """Load shimcache/amcache artifacts and render a timeline scatter plot."""
    timeline_rows = _build_timeline_rows(project_name)

    if not timeline_rows:
        st.markdown(
            '<div class="empty-state">'
            '<div class="es-icon">🕒</div>'
            '<div class="es-title">No timeline artifacts found.</div>'
            '<div class="es-sub">This may occur if the memory image lacks execution history (Shimcache/Amcache).<br>'
            'Timeline data is only available for Windows images where registry hives are present in memory.</div>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    df = pd.DataFrame(timeline_rows)
    try:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df = df.dropna(subset=["Timestamp"]).sort_values("Timestamp")
    except Exception:
        pass

    color_map = {"Shimcache": "#2ecc71", "Amcache": "#3498db"}
    fig = px.scatter(
        df, x="Timestamp", y="Artifact",
        color="Artifact", color_discrete_map=color_map,
        hover_data={"Description": True, "Timestamp": True, "Artifact": False},
        title="Execution Timeline (Shimcache / Amcache)"
    )
    fig.update_traces(marker=dict(size=10, symbol="diamond"))
    fig.update_layout(
        paper_bgcolor="#0d1117", plot_bgcolor="#161b22",
        font=dict(color="#c9d1d9", family="Fira Code"),
        xaxis=dict(showgrid=True, gridcolor="#21262d", color="#c9d1d9"),
        yaxis=dict(showgrid=False, color="#c9d1d9"),
        title_font_color="#2ecc71",
        margin=dict(l=10, r=10, t=50, b=40),
        height=320,
        legend=dict(bgcolor="#161b22", bordercolor="#30363d")
    )
    st.plotly_chart(fig, use_container_width=True)

    with st.expander("View raw timeline data"):
        df_disp = df.copy()
        if "Timestamp" in df_disp.columns:
            df_disp["Timestamp"] = df_disp["Timestamp"].astype(str)
        st.dataframe(df_disp, use_container_width=True, hide_index=True)


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
        # Modern attack technique detections
        'amsi_bypass': 'AMSI Bypass Detected',
        'etw_patching': 'ETW Patching / Audit Evasion',
        'token_impersonation': 'Token Impersonation / Privilege Abuse',
        'lateral_movement_ports': 'Lateral Movement Port Activity',
        'wmi_suspicious_spawn': 'WMI Suspicious Process Spawn',
        'lolbin_enhanced': 'Living-off-the-Land Binary Abuse',
        'archive_staging': 'Archive Staging for Exfiltration',
        'exfil_connections': 'Bulk Exfiltration Connections',
        # Correlation rule IDs
        'correlation_evasion_priv_esc': 'Evasion + Privilege Escalation Chain',
        'correlation_lolbin_chain': 'LOLBin Lateral Movement Chain',
        'correlation_exfil_chain': 'Staging + Exfiltration Chain',
        'correlation_system_wide': 'System-Wide Compromise — Multi-Layer Indicators',
    }
    return mapping.get(finding_id, finding_id.replace('_', ' ').title())

def render_correlated_finding_narrative(finding, detections_config):
    """
    Renders a correlated finding as a narrative flow for the 'Attack Story' section.
    """
    html_content_title = f"<h4 style='color: #2ecc71;'><span style='text-decoration: none; color: inherit;'>{html_escape(finding.get('title', 'Correlated Threat'))}</span></h4>"
    html(html_content_title, height=45)

    # Use dynamic narrative that reflects the actual findings in THIS image
    narrative_text = build_dynamic_chain_narrative(finding)
    st.markdown(
        f"<p style='font-size: 1.05rem; color: #c9d1d9; line-height: 1.7;'>"
        f"{html_escape(narrative_text)}</p>",
        unsafe_allow_html=True,
    )

    # Correlation findings store their data in correlated_chains, not evidence
    chain_list = finding.get('correlated_chains', [])
    if not chain_list:
        st.write("No correlated chain details available for this finding.")
        return

    for item in chain_list:
        pid      = item.get('correlated_pid')
        corr_type = item.get('correlation_type', '')
        if corr_type == "system_wide":
            layers = item.get('layers_involved', [])
            layer_txt = ", ".join(layers) if layers else "multiple layers"
            html_content_pid = (
                f"<h5 style='color:#9b59b6;'><span style='text-decoration:none;color:inherit;'>"
                f"🌐 System-Wide Indicators — spans: {html_escape(layer_txt)}</span></h5>"
            )
        elif corr_type == "parent_child":
            html_content_pid = (
                f"<h5 style='color:#3498db;'><span style='text-decoration:none;color:inherit;'>"
                f"Parent Process PID: `{html_escape(str(pid))}`</span></h5>"
            )
        else:
            html_content_pid = (
                f"<h5 style='color: #2ecc71;'><span style='text-decoration: none; color: inherit;'>"
                f"Involved Process ID (PID): `{html_escape(str(pid))}`</span></h5>"
            )
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
            elif finding_id == 'amsi_bypass':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('name', 'A process')
                pattern = primary_evidence_item.get('pattern', 'unknown pattern')
                description_parts.append(f"<code>{html_escape(str(process))}</code> attempted to **disable AMSI** (Anti-Malware Scan Interface) using: <code>{html_escape(str(pattern))}</code>, preventing detection of malicious scripts.")
            elif finding_id == 'etw_patching':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('name', 'A process')
                pattern = primary_evidence_item.get('pattern', 'audit-disabling command')
                description_parts.append(f"<code>{html_escape(str(process))}</code> patched **Event Tracing for Windows (ETW)** or manipulated audit logs (<code>{html_escape(str(pattern))}</code>), blinding security monitoring.")
            elif finding_id == 'token_impersonation':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('name', 'A process')
                handle_type = primary_evidence_item.get('type', 'Token')
                description_parts.append(f"<code>{html_escape(str(process))}</code> obtained a **privileged token handle** ({html_escape(str(handle_type))}) — indicative of token impersonation or privilege escalation.")
            elif finding_id == 'lateral_movement_ports':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('owner', 'A process')
                port = primary_evidence_item.get('ForeignPort') or primary_evidence_item.get('port', 'unknown')
                dst = primary_evidence_item.get('ForeignAddr', '')
                dst_info = f" → <code>{html_escape(str(dst))}</code>" if dst and dst not in ['None', '0.0.0.0'] else ''
                description_parts.append(f"<code>{html_escape(str(process))}</code> connected on **lateral movement port {html_escape(str(port))}**{dst_info}, suggesting remote execution or file share access.")
            elif finding_id == 'wmi_suspicious_spawn':
                parent = primary_evidence_item.get('parent_name') or primary_evidence_item.get('Parent', 'WmiPrvSE')
                child = primary_evidence_item.get('name') or primary_evidence_item.get('Child', 'cmd.exe')
                description_parts.append(f"**WMI** (<code>{html_escape(str(parent))}</code>) spawned <code>{html_escape(str(child))}</code> — a classic **WMI lateral movement or persistence** technique used to execute commands without direct process invocation.")
            elif finding_id == 'lolbin_enhanced':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('name', 'A LOLBin')
                matched = primary_evidence_item.get('matched_pattern') or primary_evidence_item.get('pattern', '')
                extra = f" (pattern: <code>{html_escape(str(matched))}</code>)" if matched else ""
                description_parts.append(f"**Living-off-the-Land binary** <code>{html_escape(str(process))}</code> was abused{extra} to proxy execution, download payloads, or bypass application controls.")
            elif finding_id == 'archive_staging':
                path = primary_evidence_item.get('path') or primary_evidence_item.get('Path', 'unknown path')
                description_parts.append(f"An **archive file** was created at a staging location: <code>{html_escape(str(path))}</code> — consistent with data collection prior to exfiltration.")
            elif finding_id == 'exfil_connections':
                process = primary_evidence_item.get('process') or primary_evidence_item.get('owner', 'A process')
                count = primary_evidence_item.get('connection_count', '')
                count_info = f" ({html_escape(str(count))} connections)" if count else ""
                description_parts.append(f"<code>{html_escape(str(process))}</code> maintained **multiple simultaneous outbound connections**{count_info} to external hosts, consistent with bulk data exfiltration.")
            elif f_details.get('layer'):
                # System-wide chain: each item carries a 'layer' label
                layer_label = html_escape(f_details.get('layer', 'Unknown Layer'))
                description_parts.append(
                    f"<b>[{layer_label}]</b> — {html_escape(get_user_friendly_correlated_title(finding_id))} "
                    f"detected as part of a multi-layer intrusion pattern."
                )
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

def render_evidence_as_list(evidence_list, finding_id):
    """
    Renders evidence items as a detailed list, useful for findings with simple key-value pairs.
    """
    if not evidence_list:
        st.info("No detailed evidence provided for this finding.")
        return

    st.markdown("<ul style='list-style-type: none; padding-left: 0;'>", unsafe_allow_html=True)
    for item in evidence_list[:10]: # Limit to top 10 items for readability
        item_details = ""
        if finding_id == 'kernel_callbacks_suspicious':
            item_details = f"Callback: `{html_escape(item.get('Details', 'N/A'))}`, Owner: `{html_escape(item.get('OwnerModule', 'N/A'))}`"
        elif finding_id == 'modules_hidden_vs_modscan':
            item_details = f"Module: `{html_escape(item.get('Module', 'N/A'))}`, Base Address: `{html_escape(item.get('Base', 'N/A'))}`"
        elif finding_id == 'registry_orphan_hives':
            item_details = f"Orphaned Hive: `{html_escape(item.get('HivePath', 'N/A'))}`"
        elif finding_id == 'dumpit_present':
            item_details = f"Tool Path: `{html_escape(item.get('Path', 'N/A'))}`"
        
        st.markdown(f"<li>{item_details}</li>", unsafe_allow_html=True)
    
    if len(evidence_list) > 10:
        st.markdown(f"<li>...and {len(evidence_list) - 10} more. See raw artifacts for full details.</li>", unsafe_allow_html=True)
    st.markdown("</ul>", unsafe_allow_html=True)


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
        "unknown_process_name": { "columns": ["pid", "name", "path"], "rename": {"pid": "PID", "name": "Process Name", "path": "Path"}},
        "suspicious_cmdline_args": { "columns": ["pid", "name", "command_line"], "rename": {"pid": "PID", "name": "Process", "command_line": "Suspicious Command Line"}},
        "suspicious_connection": { "columns": ["owner", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"], "rename": {"owner": "Process", "LocalAddr": "Local Address", "LocalPort": "Local Port", "ForeignAddr": "Remote Address", "ForeignPort": "Remote Port"}},
        "suspicious_network_enrichment": { "columns": ["pid", "owner", "ip", "country", "isp", "reputation", "notes"], "rename": {"pid": "PID", "owner": "Process Owner", "ip": "Remote IP", "country": "Country", "isp": "ISP", "reputation": "Reputation", "notes": "Reason"}},
        "unusual_parent_child": { "columns": ["name", "pid", "parent_name", "ppid"], "rename": {"name": "Child Process", "pid": "Child PID", "parent_name": "Parent Process", "ppid": "Parent PID"}},
        "malfind_injection": { "columns": ["process", "pid", "Start", "Protection"], "rename": {"process": "Process", "pid": "PID", "Start": "Start Address", "Protection": "Memory Protection"}},
        "filescan_suspicious_names": { "columns": ["Path", "Offset"], "rename": {"Path": "File Path", "Offset": "Memory Offset"}},
        "userassist_suspicious": { "columns": ["Path", "Count", "LastUpdated"], "rename": {"Path": "Program Path", "Count": "Execution Count", "LastUpdated": "Last Executed"}},
        "registry_run_key_persistence": { "columns": ["Key", "Name", "Decoded"], "rename": {"Key": "Registry Key", "Name": "Entry", "Decoded": "Command Executed"}},
        "exec_from_tmp": {"columns": ["pid", "name", "path"], "rename": {"pid": "PID", "name": "Process Name", "path": "Execution Path"}},
        "bash_history_suspicious": { "columns": ["User", "Command"], "rename": {"User": "User", "Command": "Command Executed"}},
        "correlation_findings": {
            "columns": ["correlated_pid", "correlated_findings", "correlated_rule_ids"],
            "rename": {
                "correlated_pid": "Correlated PID",
                "correlated_findings": "Included Findings (Summary)",
                "correlated_rule_ids": "Triggered Rule IDs"
            }
        },
        "dumpit_present": { "columns": ["Path"], "rename": {"Path": "Memory Acquisition Tool Path"}},
        "kernel_callbacks_suspicious": { "columns": ["Details", "OwnerModule"], "rename": {"Details": "Callback Details", "OwnerModule": "Owner Module"}},
        "modules_hidden_vs_modscan": { "columns": ["Module", "Base", "Notes"], "rename": {"Module": "Module Name", "Base": "Base Address", "Notes": "Notes"}},
        "registry_orphan_hives": { "columns": ["HivePath", "Notes"], "rename": {"HivePath": "Orphaned Hive Path", "Notes": "Notes"}},
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
    "report.pdf":  {"title": "PDF Report (Shareable)", "description": "Professional PDF report suitable for sharing with stakeholders. Includes verdict, high-severity findings, attack chains, and timeline."},
    "findings.jsonl": {"title": "Detected Findings (JSONL Data)", "description": "Raw JSON Lines format of all detected forensic findings."},
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
    "windows_registry_printkey_Software_WOW6432Node_Microsoft_Windows_CurrentVersion_RunOnce.txt": {"title": "Registry: Run-once entries for 32-bit applications on 64-bit Windows systems."},
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
    "windows_registry_shimcache.csv": {"title": "Windows Registry: Shimcache (AppCompatCache)", "description": "Records metadata about recently executed applications, useful for execution artifacts and determining program compatibility."},
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

    # Note: st.set_page_config() is called at module level (top of file) so it
    # fires before any other st.* command. Do NOT call it again here.

    if 'analysis_successful' not in st.session_state: st.session_state.analysis_successful = False
    if 'active_page' not in st.session_state: st.session_state.active_page = "Home"
    if 'project_name' not in st.session_state: st.session_state.project_name = ""
    if 'ip_enrichment_api_key' not in st.session_state: st.session_state.ip_enrichment_api_key = ""
    if 'gemini_api_key' not in st.session_state: st.session_state.gemini_api_key = ""
    if 'selected_model' not in st.session_state: st.session_state.selected_model = DEFAULT_MODEL
    if 'dark_mode' not in st.session_state: st.session_state.dark_mode = True
    if 'ai_responses' not in st.session_state: st.session_state.ai_responses = {}

    # Custom dark theme and hacker vibe CSS
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;700&display=swap');
        
        /* --- General Dark Theme & Hacker Vibe --- */
        html, body, [data-testid="stAppViewContainer"] {
            background-color: #0d1117;
            color: #c9d1d9;
            font-family: 'Fira Code', monospace;
        }
        
        /* This is the key change to remove the top whitespace */
        [data-testid="stAppViewContainer"] > .main {
            padding-top: 0rem;
        }
        
        /* --- Main UI Containers & Headers --- */
        .header {
            background-color: #161b22;
            padding: 2rem 2rem 1.5rem 2rem;
            border-bottom: 1px solid #30363d;
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-top: 0rem;
            margin-left: -1rem;
            margin-right: -1rem;
            margin-bottom: 1rem;
        }
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            color: #2ecc71;
            margin: 0;
            text-shadow: 1px 1px 2px rgba(46, 204, 113, 0.4);
        }
        .header span {
            font-size: 1rem;
            font-weight: 400;
            color: #8b949e;
            padding-top: 10px;
        }
        h1, h2, h3, h4, h5, h6 {
            color: #2ecc71;
            font-weight: 700;
            margin-top: 1.5rem;
            margin-bottom: 0.5rem;
        }
        
        /* --- Sidebar & Footer --- */
        [data-testid="stSidebar"] {
            background-color: #161b22;
            border-right: 1px solid #30363d;
        }
        [data-testid="stSidebar"] h2 {
            color: #2ecc71;
            border-bottom: 2px solid #30363d;
            padding-bottom: 5px;
        }
        .sidebar-footer {
            margin-top: auto;
            padding-bottom: 1rem;
        }
        
        /* --- Form Inputs and Buttons --- */
        .stTextInput label, .stSelectbox label, .stMarkdown, .stInfo, .stText, p, li, .stTextarea label, .st-bf, .st-bp, .st-bb, .st-bh, .st-bi {
            color: #c9d1d9 !important;
        }
        .stTextInput input, .stSelectbox div[data-baseweb="select"] > div, .stTextArea textarea {
            background-color: #0d1117 !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
            color: #c9d1d9 !important;
        }
        .stTextInput input:focus, .stSelectbox div[data-baseweb="select"] > div:focus-within {
            border-color: #2ecc71 !important;
            box-shadow: 0 0 0 3px rgba(46, 204, 113, 0.25) !important;
        }
        
        .stButton > button {
            background-color: #21262d;
            color: #2ecc71;
            font-weight: bold;
            border: 1px solid #30363d;
            border-radius: 6px;
        }
        .stButton > button:hover {
            background-color: #30363d;
            border-color: #2ecc71;
            color: #2ecc71;
        }

        /* The rule below is the fix for the button text color */
        div.stButton > button:first-child span {
            color: #000000 !important;
            font-weight: bold;
        }

        /* Also apply the same color to the button when hovered */
        div.stButton > button:first-child:hover span {
            color: #000000 !important;
        }

        /* The following rule is to ensure the button itself is black */
        div.stButton > button:first-child {
            background-color: #000000;
        }
        
        /* Tooltip text color */
        .st-emotion-cache-12t9k8e {
            color: #c9d1d9 !important;
        }
        
        /* --- Analysis Widgets and Severity Boxes --- */
        .scan-widget, .card, .artifact-card, .verdict-box, .narrative-block, .findings-narrative-item {
            background-color: #161b22;
            border-color: #30363d;
            color: #c9d1d9;
        }
        .scan-widget-grid { display: flex; flex-wrap: wrap; gap: 1rem; }
        .scan-widget {
             cursor: default;
             text-align: center;
             transition: all 0.2s ease-in-out;
             padding: 1.5rem 1rem;
             border-radius: 8px;
             box-shadow: 0 4px 12px rgba(0,0,0,0.1);
             min-width: 200px;
             flex: 1;
        }
        .scan-widget:hover {
            transform: translateY(-5px);
            border-color: #2ecc71;
            box-shadow: 0 4px 12px rgba(46, 204, 113, 0.4);
        }
        .scan-widget .title {
            font-weight: bold;
            color: #2ecc71;
            text-shadow: 0 0 5px rgba(46, 204, 113, 0.2);
        }

        /* --- Capability Groups --- */
        .cap-group {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 1rem 1.2rem 0.8rem 1.2rem;
            margin-bottom: 0.85rem;
        }
        .cap-group-header {
            font-size: 0.95rem;
            font-weight: 700;
            color: #2ecc71;
            margin-bottom: 0.5rem;
            letter-spacing: 0.02em;
        }
        .cap-group.highlight {
            border-color: #2ecc71;
            box-shadow: 0 0 12px rgba(46, 204, 113, 0.15);
        }
        .cap-item {
            display: inline-block;
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 5px;
            font-size: 0.78rem;
            color: #c9d1d9;
            padding: 0.2rem 0.55rem;
            margin: 0.2rem 0.2rem 0.2rem 0;
        }

        /* --- Feature Badges --- */
        .badge-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0 0.8rem 0; }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
            background: #0d1117;
            border: 1px solid #2ecc71;
            border-radius: 20px;
            padding: 0.22rem 0.7rem;
            font-size: 0.75rem;
            font-weight: 600;
            color: #2ecc71;
            white-space: nowrap;
        }

        /* --- Summary Panel --- */
        .summary-panel {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin: 0.75rem 0 1.2rem 0;
        }
        .summary-card {
            flex: 1;
            min-width: 90px;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 0.6rem 0.8rem;
            text-align: center;
        }
        .summary-card .s-value {
            font-size: 1.6rem;
            font-weight: 700;
            color: #2ecc71;
            line-height: 1.1;
        }
        .summary-card .s-label {
            font-size: 0.7rem;
            color: #8b949e;
            margin-top: 0.15rem;
        }

        /* --- Empty State --- */
        .empty-state {
            text-align: center;
            padding: 2rem 1rem;
            border: 1px dashed #30363d;
            border-radius: 10px;
            margin: 1rem 0;
        }
        .empty-state .es-icon { font-size: 2.2rem; margin-bottom: 0.4rem; }
        .empty-state .es-title { font-size: 1rem; font-weight: 700; color: #c9d1d9; margin-bottom: 0.3rem; }
        .empty-state .es-sub { font-size: 0.82rem; color: #8b949e; }
        
        .card.critical { border-left: 8px solid #f85149 !important; }
        .card.high { border-left: 8px solid #ff7b72 !important; }
        .card.medium { border-left: 8px solid #e3b341 !important; }
        .card.low { border-left: 8px solid #2ecc71 !important; }
        .card.informational { border-left: 8px solid #8b949e !important; }
        
        .verdict-box {
            background-color: #161b22;
            border-left: 8px solid #2ecc71 !important;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
        }
        .verdict-box.critical { border-color: #f85149 !important; }
        .verdict-box.high { border-color: #e67e22 !important; }
        .verdict-box.medium { border-color: #e3b341 !important; }
        .verdict-box.low { border-color: #2ecc71 !important; }
        .verdict-box.informational { border-color: #8b949e !important; }

        .verdict-box h2, .verdict-box p { color: inherit !important; }

        /* --- Custom Element Styling --- */
        .attack-path-container { display: flex; align-items: flex-start; flex-wrap: wrap; gap: 10px; margin-top: 15px; justify-content: center; }
        .attack-step { background-color: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; width: 280px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.05); min-height: 120px; display: flex; flex-direction: column; justify-content: center; align-items: center; color: #c9d1d9;}
        .attack-step hr { margin: 0.5rem 0; border-top: 1px solid #30363d; width: 80%; }
        .attack-step p { font-size: 0.9rem; color: #c9d1d9; margin: 0; }
        .attack-arrow { font-size: 2rem; color: #2ecc71; font-weight: bold; display: flex; align-items: center; justify-content: center; padding: 0 10px; }
        .narrative-block {
            background-color: #21262d;
            border-left: 4px solid #2ecc71;
            padding: 10px 15px;
            margin-top: 10px;
            border-radius: 4px;
        }
        .narrative-block p {
            color: #c9d1d9;
            margin: 0;
        }

        .findings-narrative-list {
            padding-left: 0;
            list-style: none;
        }
        .findings-narrative-item {
            background-color: #21262d;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 10px 15px;
            margin-bottom: 8px;
            display: flex;
            align-items: flex-start;
            gap: 10px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            border-left-width: 8px;
        }
        .findings-narrative-item.critical { border-left-color: #f85149; }
        .findings-narrative-item.high { border-left-color: #ff7b72; }
        .findings-narrative-item.medium { border-left-color: #e3b341; }
        .findings-narrative-item.low { border-left-color: #2ecc71; }
        .findings-narrative-item.informational { border-left-color: #8b949e; }
        
        .findings-narrative-item strong {
            flex-shrink: 0;
            color: #2ecc71;
            font-size: 0.95rem;
            width: 200px;
        }
        .findings-narrative-item span {
            flex-grow: 1;
            color: #c9d1d9;
            font-size: 0.9rem;
        }

        .stTabs [data-testid="stTabRecButton"] {
            font-size: 1.35rem;
            font-weight: 700;
            background-color: #21262d;
            color: #c9d1d9;
            border: 2px solid #30363d;
            border-bottom: none;
            border-radius: 10px 10px 0 0;
        }
        .stTabs [data-testid="stTabRecButton"]:hover {
            background-color: #30363d;
            color: #2ecc71;
        }
        .stTabs [data-testid="stTabRecButton"][aria-selected="true"] {
            background-color: #2ecc71;
            color: #161b22;
            border: 2px solid #2ecc71;
            border-bottom: none;
        }
        .artifact-card {
            background-color: #21262d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            height: 100%;
            min-height: 200px;
        }
        .artifact-card h3 {
            margin-top: 0;
            font-size: 1.1rem;
            color: #2ecc71;
        }
        .artifact-card p {
            font-size: 0.85rem;
            color: #c9d1d9;
            flex-grow: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .artifact-card .stDownloadButton button {
            margin-top: 10px;
            width: 100%;
            background-color: #2ecc71;
            color: #161b22;
            font-weight: bold;
            border-radius: 8px;
            border: none;
            padding: 0.5rem 0;
            transition: background-color 0.2s;
            cursor: pointer;
        }
        .artifact-card .stDownloadButton button:hover {
            background-color: #21ba64;
        }
        /* Styling for missing artifact files */
        .artifact-card.missing-file {
            background-color: #2d191c;
            border-color: #30363d;
        }
        .artifact-card.missing-file h3 {
            color: #f85149;
        }
        .artifact-card.missing-file p {
            color: #c9d1d9;
        }
        .artifact-card.missing-file .stDownloadButton button {
            background-color: #30363d;
            color: #8b949e;
            cursor: not-allowed;
        }
        .artifact-card.missing-file .stDownloadButton button:hover {
            background-color: #30363d;
        }

        .severity-grid {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .severity-box {
            flex: 1;
            text-align: center;
            border-radius: 8px;
            padding: 1rem;
            color: white;
            min-width: 120px;
        }
        
        .severity-box.critical { background-color: #f85149; }
        .severity-box.high { background-color: #ff7b72; } 
        .severity-box.medium { background-color: #e3b341; color: #333; } 
        .severity-box.low { background-color: #2ecc71; }
        .severity-box.informational { background-color: #8b949e; }
        
        .severity-title {
            font-size: 1.25rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }
        
        .severity-count {
            font-size: 2.5rem;
            font-weight: 700;
        }
        
        /* Table styling for dark theme */
        [data-testid="stDataFrame"] {
            background-color: #161b22;
            color: #c9d1d9;
            border: 1px solid #30363d;
        }
        [data-testid="stDataFrame"] table {
            background-color: #161b22;
            color: #c9d1d9;
        }
        [data-testid="stDataFrame"] thead th {
            background-color: #161b22 !important;
            color: #2ecc71;
            border-bottom: 2px solid #2ecc71;
        }
        [data-testid="stDataFrame"] tbody tr {
            background-color: #161b22;
            color: #c9d1d9;
        }
        [data-testid="stDataFrame"] tbody tr td {
            background-color: #161b22;
            color: #c9d1d9;
        }
        [data-testid="stDataFrame"] tbody tr:hover {
            background-color: #21262d;
        }
        
        /* Specific styling for artifact tables in Artifacts tab */
        [data-testid="stVerticalBlock"] [data-testid="stDataFrame"] thead th {
            color: #2ecc71;
        }
        [data-testid="stVerticalBlock"] [data-testid="stDataFrame"] tbody tr td {
            color: #c9d1d9;
        }
        </style>
        """, unsafe_allow_html=True)


    # Inject light-mode overrides when user toggles theme
    if not st.session_state.dark_mode:
        st.markdown("""
        <style>
        html, body, [data-testid="stAppViewContainer"] {
            background-color: #f6f8fa !important;
            color: #24292f !important;
        }
        [data-testid="stAppViewContainer"] > .main { background-color: #f6f8fa !important; }
        [data-testid="stSidebar"] { background-color: #ffffff !important; border-right: 1px solid #d0d7de !important; }
        .header { background-color: #ffffff !important; border-bottom: 1px solid #d0d7de !important; }
        .header h1 { color: #1a7f37 !important; }
        .stButton > button { background-color: #f6f8fa !important; color: #1a7f37 !important; border-color: #d0d7de !important; }
        .card, .verdict-box, .narrative-block, .findings-narrative-item,
        .attack-step, .artifact-card { background-color: #ffffff !important; border-color: #d0d7de !important; color: #24292f !important; }
        [data-testid="stDataFrame"] { background-color: #ffffff !important; color: #24292f !important; }
        [data-testid="stDataFrame"] thead th { background-color: #f6f8fa !important; color: #1a7f37 !important; border-bottom: 2px solid #1a7f37 !important; }
        [data-testid="stDataFrame"] tbody tr td { background-color: #ffffff !important; color: #24292f !important; }
        h1, h2, h3, h4, h5, h6 { color: #1a7f37 !important; }
        p, li, span, label { color: #24292f !important; }
        .stTextInput input, .stTextArea textarea { background-color: #ffffff !important; color: #24292f !important; border-color: #d0d7de !important; }
        </style>
        """, unsafe_allow_html=True)

    st.markdown('<div class="header"><h1>DeepProbe</h1><span>Memory Forensics Framework</span></div>', unsafe_allow_html=True)

    with st.sidebar:
        st.markdown("<h2 style='color: #2ecc71;'>About DeepProbe</h2>", unsafe_allow_html=True)
        st.write(
            "**DeepProbe** is a memory forensics engine built on **Volatility 3** that detects, "
            "correlates, and explains in memory threats.\n\n"
            "It goes beyond individual indicators by reconstructing **attack chains** and "
            "**timelines**, helping analysts understand how an intrusion unfolds.\n\n"
            "AI assisted explanations run fully locally via **Ollama**, ensuring sensitive "
            "data never leaves your environment."
        )
        st.markdown(
            '<div class="badge-row">'
            '<span class="badge">🔗 Correlation Engine</span>'
            '<span class="badge">🌐 OSINT Enrichment</span>'
            '<span class="badge">🤖 Local AI (Ollama)</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        st.markdown("---")

        # ── AI Engine (Ollama) ───────────────────────────────────────────
        st.markdown("<h2 style='color: #2ecc71;'>🤖 AI Engine</h2>", unsafe_allow_html=True)

        ollama_ok = check_ollama_health()
        if ollama_ok:
            st.success("🟢 Ollama connected")
        else:
            st.error("🔴 Ollama not reachable")
            st.caption(f"Expected at `{OLLAMA_HOST}`. Start with `docker compose up`.")

        if ollama_ok:
            pulled_models = get_ollama_models()

            # Model selector — show pulled models first, then recommended ones not yet pulled
            all_options = pulled_models + [
                m for m in RECOMMENDED_MODELS if m not in pulled_models
            ]
            # Preserve unique ordering
            seen = set()
            display_options = []
            for m in all_options:
                if m not in seen:
                    display_options.append(m)
                    seen.add(m)

            def _model_label(name):
                suffix = " ✅" if name in pulled_models else " ⬇️ (not downloaded)"
                return name + suffix

            selected_label = st.selectbox(
                "Model",
                options=display_options,
                index=display_options.index(st.session_state.selected_model)
                      if st.session_state.selected_model in display_options else 0,
                format_func=_model_label,
                help="✅ = already downloaded. ⬇️ = will be downloaded on first Ask AI click."
            )
            st.session_state.selected_model = selected_label

            # Manual pull button
            if selected_label not in pulled_models:
                if st.button(f"⬇️ Download {selected_label} now"):
                    with st.spinner(f"Downloading {selected_label} — this may take a few minutes…"):
                        ok, msg = pull_ollama_model(selected_label)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            else:
                st.caption(f"Model `{selected_label}` is ready.")

        st.markdown("---")

        # ── Gemini override (advanced / optional) ───────────────────────
        with st.expander("⚙️ Advanced: Gemini API override"):
            st.caption(
                "Provide a Gemini key only if you prefer cloud inference over local Ollama. "
                "**Warning:** findings (including extracted memory data) will be sent to Google."
            )
            gemini_key_input = st.text_input(
                "Gemini API Key",
                value=st.session_state.gemini_api_key,
                type="password",
                key="sidebar_gemini_key"
            )
            st.session_state.gemini_api_key = gemini_key_input

        st.markdown("---")

        # ── Supported formats ────────────────────────────────────────────
        st.markdown("<h2 style='color: #2ecc71;'>Supported Formats</h2>", unsafe_allow_html=True)
        st.info(f"Place memory images inside the `{html_escape(str(MEMORY_FOLDER.name))}/` folder.")
        st.markdown("- Raw dumps (`.raw`, `.mem`, `.bin`)\n- VMware snapshots (`.vmem`)\n- Hibernation files (`hiberfil.sys`)")
        st.markdown("---")

        # ── Configuration ────────────────────────────────────────────────
        st.markdown("<h2 style='color: #2ecc71;'>Configuration</h2>", unsafe_allow_html=True)
        if st.button("View Baseline"):
            st.session_state.active_page = "Baseline"
            st.rerun()
        if st.button("View Detections"):
            st.session_state.active_page = "Detections"
            st.rerun()

        st.markdown("---")
        st.markdown("<h2 style='color: #2ecc71;'>Theme</h2>", unsafe_allow_html=True)
        theme_label = "🌙 Dark Mode" if st.session_state.dark_mode else "☀️ Light Mode"
        if st.button(theme_label):
            st.session_state.dark_mode = not st.session_state.dark_mode
            st.rerun()

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
    elif st.session_state.active_page == "Baseline":
        render_baseline_page()
    elif st.session_state.active_page == "Detections":
        render_detections_page()

def render_detections_page():
    """Renders the detections rules page with tables for clarity."""
    st.markdown("<h1 style='color: #2ecc71;'>DeepProbe Detection Rules</h1>", unsafe_allow_html=True)
    st.write("This page displays the detection rules that the analysis engine uses to identify suspicious activity. The information is parsed directly from the `detections.yaml` file.")
    
    detections_config = load_detections_config()

    if not detections_config:
        st.warning("`detections.yaml` file not found or is empty. No detection rules are configured.")
        return

    os_profiles = detections_config.get('os_profiles', {})
    for os_name, os_data in os_profiles.items():
        st.markdown("---")
        st.markdown(f"<h2 style='color: #2ecc71;'>{os_name.capitalize()} Detections</h2>", unsafe_allow_html=True)
        
        detections = os_data.get('detections', [])
        if detections:
            detection_data = []
            for d in detections:
                mitre_tags = ", ".join(d.get('mitre', []))
                narrative_text = d.get('narrative', 'N/A').replace("psxview mismatch", "hidden process detection anomaly").replace("LdrModules", "loaded modules").replace("ldrmodules", "loaded modules")
                
                detection_data.append({
                    "Detection Rule": d.get('title', d.get('id', 'N/A')),
                    "Description": d.get('narrative', 'N/A'),
                    "Narrative": narrative_text,
                    "Severity Score": d.get('weight', 'N/A'),
                    "MITRE ATT&CK®": mitre_tags
                })
            
            df_detections = pd.DataFrame(detection_data)
            st.dataframe(df_detections, use_container_width=True, hide_index=True)
        else:
            st.info(f"No detection rules found for {os_name.capitalize()}.")


def render_baseline_page():
    """Renders the baseline exclusions page with tables for clarity."""
    st.markdown("<h1 style='color: #2ecc71;'>DeepProbe Baseline Exclusions</h1>", unsafe_allow_html=True)
    st.write("This page displays the list of entities (processes, network connections, etc.) that are **intentionally ignored** during analysis based on the `baseline.yaml` file. These are considered normal, expected, or whitelisted for your environment.")

    baseline_config = load_baseline_config()

    if not baseline_config:
        st.warning("`baseline.yaml` file not found or is empty. No exclusions are configured.")
        return

    # --- Render Process Whitelist ---
    st.markdown("---")
    st.markdown("<h2 style='color: #2ecc71;'>Excluded Processes</h2>", unsafe_allow_html=True)
    st.write("The following processes are ignored by the analysis engine:")

    process_data = []
    process_whitelist = baseline_config.get('process_whitelist', {})
    for os_type, processes in process_whitelist.items():
        if processes:
            for process in processes:
                process_data.append({"Operating System": os_type.capitalize(), "Excluded Process Name": process})

    if process_data:
        df_processes = pd.DataFrame(process_data)
        st.dataframe(df_processes, use_container_width=True, hide_index=True)
    else:
        st.info("No processes are currently whitelisted.")

    # --- Render Network Whitelist ---
    st.markdown("---")
    st.markdown("<h2 style='color: #2ecc71;'>Excluded Network Connections</h2>", unsafe_allow_html=True)
    st.write("The following IP addresses and ports are ignored by the analysis engine:")
    
    network_config = baseline_config.get('network', {})

    # Allowed CIDRs
    allow_cidrs = network_config.get('allow_cidrs', [])
    if allow_cidrs:
        st.markdown("### Allowed IP Addresses (CIDR)")
        df_cidrs = pd.DataFrame({"CIDR": allow_cidrs})
        st.dataframe(df_cidrs, use_container_width=True, hide_index=True)
    else:
        st.info("No IP addresses are currently whitelisted.")

    # Allowed Ports
    allow_ports = network_config.get('allow_ports', [])
    if allow_ports:
        st.markdown("### Allowed Ports")
        df_ports = pd.DataFrame({"Port": allow_ports})
        st.dataframe(df_ports, use_container_width=True, hide_index=True)
    else:
        st.info("No ports are currently whitelisted.")

    # --- Render Sessions Whitelist ---
    st.markdown("---")
    st.markdown("<h2 style='color: #2ecc71;'>Excluded Sessions</h2>", unsafe_allow_html=True)
    st.write("The following user sessions are ignored by the analysis engine:")

    sessions_data = baseline_config.get('sessions', {}).get('ignore_users', [])
    if sessions_data:
        df_sessions = pd.DataFrame({"Excluded User": sessions_data})
        st.dataframe(df_sessions, use_container_width=True, hide_index=True)
    else:
        st.info("No user sessions are currently whitelisted.")

    # --- Render Command Line Whitelist (if it exists) ---
    st.markdown("---")
    st.markdown("<h2 style='color: #2ecc71;'>Command-Line Exclusions</h2>", unsafe_allow_html=True)
    st.write("The following command-line patterns are whitelisted:")

    cmdline_data = baseline_config.get('command_line_allowlist', [])
    if cmdline_data:
        df_cmdline = pd.DataFrame(cmdline_data)
        st.dataframe(df_cmdline, use_container_width=True, hide_index=True)
    else:
        st.info("No command-line patterns are currently whitelisted.")


def render_home_page(status_text_global, progress_bar_global):
    """Renders the main input form and analysis capabilities view."""
    
    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.markdown("<h1 style='color: #2ecc71;'>New Analysis Job</h1>", unsafe_allow_html=True)
        st.write("Configure your analysis by providing a project name and the memory image filename.")

        with st.form("analysis_form"):
            project_name = st.text_input("**Project Name**")
            memory_file_name = st.text_input("**Memory File Name**")
            ip_enrichment_api_key = st.text_input(
                "**IP Enrichment API Key (Optional)**",
                type="password",
                help="AbuseIPDB API key for IP reputation scoring. Falls back to ipinfo.io if blank or on failure."
            )
            st.caption("💡 AI explanations use the local Ollama model selected in the sidebar — no API key required. "
                       "A Gemini override is available under ⚙️ Advanced in the sidebar if you prefer cloud AI.")
            submitted = st.form_submit_button("🚀 Launch Analysis")
        
    with col2:
        st.markdown("<h2 style='color: #2ecc71;'>Analysis Capabilities</h2>", unsafe_allow_html=True)
        st.markdown("""
            <div class="cap-group">
                <div class="cap-group-header">🧠 Core Memory Analysis</div>
                <span class="cap-item">Hidden Process Detection</span>
                <span class="cap-item">Process Hollowing</span>
                <span class="cap-item">Code Injection</span>
                <span class="cap-item">Unlinked Module Detection</span>
                <span class="cap-item">Entropy / Shellcode Analysis</span>
                <span class="cap-item">AMSI Bypass Detection</span>
                <span class="cap-item">ETW Patching</span>
                <span class="cap-item">Token Impersonation</span>
            </div>
            <div class="cap-group">
                <div class="cap-group-header">🌐 Network &amp; Threat Intelligence</div>
                <span class="cap-item">Suspicious Network Connections</span>
                <span class="cap-item">Suspicious Port Usage</span>
                <span class="cap-item">Lateral Movement Ports</span>
                <span class="cap-item">IP Reputation (OSINT-based)</span>
                <span class="cap-item">Bulk Exfiltration Detection</span>
            </div>
            <div class="cap-group">
                <div class="cap-group-header">🔐 Credential &amp; Access Monitoring</div>
                <span class="cap-item">LSASS Access Detection</span>
                <span class="cap-item">Credential Dumping Indicators</span>
                <span class="cap-item">WMI Suspicious Spawns</span>
                <span class="cap-item">LOLBin Abuse</span>
            </div>
            <div class="cap-group">
                <div class="cap-group-header">⚙️ Persistence &amp; Execution</div>
                <span class="cap-item">Registry Run Key Persistence</span>
                <span class="cap-item">Suspicious Command Lines</span>
                <span class="cap-item">Scheduled Tasks &amp; Services</span>
                <span class="cap-item">Archive Staging</span>
                <span class="cap-item">Execution from Temp Paths</span>
            </div>
            <div class="cap-group highlight">
                <div class="cap-group-header">🔗 Advanced Analysis</div>
                <span class="cap-item">Attack Chain Correlation</span>
                <span class="cap-item">Timeline Reconstruction</span>
                <span class="cap-item">Multi-Stage Threat Detection</span>
                <span class="cap-item">MITRE ATT&amp;CK Mapping</span>
                <span class="cap-item">Local AI Explanations</span>
            </div>
        """, unsafe_allow_html=True)

    if submitted:
        if not project_name or not memory_file_name:
            st.error("Both Project Name and Memory File Name are mandatory.")
            status_text_global.empty()
            progress_bar_global.empty()
        else:
            memory_file_path = MEMORY_FOLDER / memory_file_name
            project_output_folder = OUTPUT_FOLDER / project_name
            findings_jsonl_path = project_output_folder / "findings.jsonl"
            
            if findings_jsonl_path.exists():
                st.warning(f"Report for project '`{html_escape(project_name)}`' already exists. Skipping analysis and showing saved results.")
                st.session_state.analysis_successful = True
                st.session_state.project_name = project_name
                time.sleep(2)
                st.session_state.active_page = "Results"
                st.rerun()
            else:
                if not memory_file_path.exists():
                    st.error(f"File not found: '`{html_escape(memory_file_name)}`' does not exist in the '`{html_escape(str(MEMORY_FOLDER))}`' directory.")
                    status_text_global.empty()
                    progress_bar_global.empty()
                else:
                    st.session_state.project_name = project_name
                    st.session_state.ip_enrichment_api_key = ip_enrichment_api_key
                    # gemini_api_key is managed via the sidebar Advanced expander — don't overwrite it here
                    st.session_state.ai_responses = {}

                    progress_bar_global.progress(0, text="0% Complete")
    
                    success = run_analysis_and_show_progress(
                        project_name, memory_file_path,
                        ip_enrichment_api_key,
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
    st.markdown(f"<h1 style='color: #2ecc71;'>Results for: {html_escape(st.session_state.project_name)}</h1>", unsafe_allow_html=True)
    detections_config = load_detections_config()

    if not st.session_state.analysis_successful:
        st.error("Analysis did not complete successfully. No report to display.")
        return

    findings = load_findings(st.session_state.project_name)

    correlated_findings = [f for f in findings if f.get('id', '').startswith('correlation_')]
    regular_findings = [f for f in findings if not f.get('id', '').startswith('correlation_')]

    severity_counts, overall_severity_label, total_score = categorize_findings(findings, detections_config)

    st.markdown("<h2 style='color: #2ecc71;'>Overall Verdict</h2>", unsafe_allow_html=True)

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

    st.markdown(f"""
        <div class="verdict-box {verdict_class}">
            <h2 style='color: inherit;'>DeepProbe Rule-Based Verdict: <span style='text-decoration: none; color: inherit;'>{html_escape(verdict_message)}</span></h2>
            <p style='text-decoration: none; color: inherit;'>{html_escape(verdict_summary)}</p>
            <p style='text-decoration: none; color: inherit;'>Overall Risk Score: <b>{html_escape(str(total_score))}</b></p>
        </div>
    """, unsafe_allow_html=True)


    if not findings:
        st.success("Analysis completed, and no suspicious findings were detected.")
        return

    # --- Summary panel -----------------------------------------------------------
    # Use the same helper as render_timeline() so the count is always consistent
    # with what actually renders in the Timeline tab.
    _timeline_count = len(_build_timeline_rows(st.session_state.project_name))

    st.markdown(
        f'<div class="summary-panel">'
        f'<div class="summary-card"><div class="s-value">{len(findings)}</div><div class="s-label">Total Findings</div></div>'
        f'<div class="summary-card"><div class="s-value">{len(correlated_findings)}</div><div class="s-label">Correlated Chains</div></div>'
        f'<div class="summary-card"><div class="s-value">{len(regular_findings)}</div><div class="s-label">Individual Findings</div></div>'
        f'<div class="summary-card"><div class="s-value">{_timeline_count if _timeline_count else "—"}</div><div class="s-label">Timeline Events</div></div>'
        f'<div class="summary-card"><div class="s-value">{total_score}</div><div class="s-label">Risk Score</div></div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    report_tab, attack_tab, timeline_tab, mitre_tab, artifacts_tab = st.tabs([
        "📋 Analysis Report",
        "🕸️ Attack Chain Graph",
        "⏱️ Timeline",
        "🎯 MITRE ATT&CK",
        "📁 Raw Artifacts"
    ])

    with report_tab:
        st.markdown("<h2 style='color: #2ecc71;'>Analysis Summary</h2>", unsafe_allow_html=True)

        # --- Severity donut chart ---
        donut_labels = ["Critical", "High", "Medium", "Low", "Informational"]
        donut_values = [severity_counts[l] for l in donut_labels]
        donut_colors = ["#e74c3c", "#ff7b72", "#e3b341", "#2ecc71", "#8b949e"]
        if sum(donut_values) > 0:
            donut_fig = go.Figure(go.Pie(
                labels=donut_labels,
                values=donut_values,
                hole=0.55,
                marker=dict(colors=donut_colors, line=dict(color="#0d1117", width=2)),
                textinfo="label+value",
                textfont=dict(color="#c9d1d9", size=12),
                hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>",
            ))
            donut_fig.add_annotation(
                text=f"<b>{sum(donut_values)}</b><br>findings",
                x=0.5, y=0.5, font=dict(size=16, color="#c9d1d9"), showarrow=False
            )
            donut_fig.update_layout(
                paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                showlegend=True,
                legend=dict(bgcolor="#161b22", bordercolor="#30363d", font=dict(color="#c9d1d9")),
                margin=dict(l=20, r=20, t=20, b=20),
                height=300
            )
            col_donut, col_stats = st.columns([1, 1])
            with col_donut:
                st.plotly_chart(donut_fig, use_container_width=True)
            with col_stats:
                st.markdown("<br>", unsafe_allow_html=True)
                for label, color in zip(donut_labels, donut_colors):
                    count = severity_counts[label]
                    st.markdown(
                        f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:8px;'>"
                        f"<div style='width:14px;height:14px;border-radius:3px;background:{color};flex-shrink:0;'></div>"
                        f"<span style='color:#c9d1d9;font-size:1rem;'><b>{label}</b>: {count}</span></div>",
                        unsafe_allow_html=True
                    )
        else:
            st.info("No findings to display in severity chart.")
        st.markdown("---")

        if correlated_findings:
            st.markdown("<h2 style='color: #2ecc71;'>The Attack Story: How DeepProbe Uncovered the Threat</h2>", unsafe_allow_html=True)
            st.write("DeepProbe correlated multiple indicators to build a high-confidence narrative. Below is the step-by-step attack flow.")
            sorted_correlated_findings = sorted(correlated_findings, key=lambda f: f['weight'], reverse=True)
            for f in sorted_correlated_findings:
                render_correlated_finding_narrative(f, detections_config)
            st.markdown("---")

        st.markdown("<h2 style='color: #2ecc71;'>Findings Narrative</h2>", unsafe_allow_html=True)
        st.write("A quick overview of every suspicious activity detected and why it's considered an issue:")

        st.markdown("<div class='findings-narrative-list'>", unsafe_allow_html=True)
        sorted_findings_for_narrative = sorted(findings, key=lambda x: x.get('weight', 0), reverse=True)
        for f in sorted_findings_for_narrative:
            finding_severity_class = "informational"
            for band in detections_config.get('scoring', {}).get('severity_bands', []):
                if f.get('weight', 0) <= int(band['max']):
                    finding_severity_class = band['label'].lower()
                    break

            # Correlated findings: use the dynamic chain narrative builder so the text
            # is specific to THIS analysis (not generic boilerplate or "Narrative not found.")
            fid_for_narr = f.get('id', '')
            if fid_for_narr.startswith('correlation_'):
                narrative_for_item = build_dynamic_chain_narrative(f)
            else:
                narrative_for_item = get_narrative(fid_for_narr, detections_config)

            st.markdown(f"""
                <div class='findings-narrative-item {finding_severity_class}'>
                    <strong style='color: #2ecc71;'>{html_escape(f.get('title', fid_for_narr))}:</strong> <span style='color: #c9d1d9;'>{html_escape(narrative_for_item)}</span>
                </div>
            """, unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("---")
        
        st.markdown("<h2 style='color: #2ecc71;'>Recent Commands Overview</h2>", unsafe_allow_html=True)
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

        st.markdown("<h2 style='color: #2ecc71;'>All Detected Activities: Detailed Findings</h2>", unsafe_allow_html=True)
        st.write("Click any finding to expand evidence details. Use **Ask AI** for a plain-English explanation.")

        sorted_regular_findings = sorted(regular_findings, key=lambda x: x.get('weight', 0), reverse=True)
        gemini_key = st.session_state.get("gemini_api_key", "")

        severity_badge_colors = {
            "critical": "#e74c3c", "high": "#ff7b72",
            "medium": "#e3b341", "low": "#2ecc71", "informational": "#8b949e"
        }

        for f in sorted_regular_findings:
            finding_id = f.get('id', '')
            finding_severity_class = "informational"
            for band in detections_config.get('scoring', {}).get('severity_bands', []):
                if f.get('weight', 0) <= int(band['max']):
                    finding_severity_class = band['label'].lower()
                    break

            badge_color = severity_badge_colors.get(finding_severity_class, "#8b949e")
            mitre_str = ", ".join(f.get('mitre', []))
            narrative_text = get_narrative(finding_id, detections_config)

            # Expander label includes severity badge and title
            expander_label = (
                f"[{finding_severity_class.upper()}]  {f.get('title', finding_id)}"
                f"  |  Score: {f.get('weight', 0)}"
                + (f"  |  MITRE: {mitre_str}" if mitre_str else "")
            )

            with st.expander(expander_label, expanded=(finding_severity_class in ("critical", "high"))):
                st.markdown(
                    f"<div class='narrative-block'>"
                    f"<p><b>Why it's an issue:</b> {html_escape(narrative_text)}</p>"
                    f"</div>",
                    unsafe_allow_html=True
                )

                # Ask AI button — always visible; uses local Ollama (or Gemini if key provided)
                ai_key = f"ai_{finding_id}_{f.get('weight', 0)}"
                col_ev, col_ai = st.columns([3, 1])
                with col_ai:
                    if st.button("🤖 Ask AI", key=f"btn_{ai_key}"):
                        chosen_model = st.session_state.get("selected_model", DEFAULT_MODEL)
                        gemini_key = st.session_state.get("gemini_api_key", "")

                        # Auto-pull model if not yet downloaded (and Gemini isn't being used)
                        if not gemini_key:
                            pulled = get_ollama_models()
                            if chosen_model not in pulled:
                                with st.spinner(f"⬇️ Downloading {chosen_model} first — this may take a few minutes…"):
                                    ok, pull_msg = pull_ollama_model(chosen_model)
                                if not ok:
                                    st.session_state.ai_responses[ai_key] = f"⚠️ Could not download model: {pull_msg}"
                                    st.rerun()

                        spinner_label = (
                            "Querying Gemini…" if gemini_key
                            else f"Querying {chosen_model} locally…"
                        )
                        with st.spinner(spinner_label):
                            response = query_llm(
                                f,
                                model=chosen_model,
                                gemini_key=gemini_key,
                            )
                            st.session_state.ai_responses[ai_key] = response
                if ai_key in st.session_state.ai_responses:
                    st.info(st.session_state.ai_responses[ai_key])
                with col_ev:
                    st.markdown("**Supporting Evidence:**")
                    render_evidence_as_table(f.get('evidence', []), finding_id)

        st.markdown("---")

        # --- Report downloads ---
        st.markdown("<h3 style='color:#2ecc71;'>Download Reports</h3>", unsafe_allow_html=True)
        dl_col1, dl_col2 = st.columns(2)
        report_html_path = OUTPUT_FOLDER / st.session_state.project_name / "report.html"
        report_pdf_path  = OUTPUT_FOLDER / st.session_state.project_name / "report.pdf"
        with dl_col1:
            if report_html_path.exists():
                with open(report_html_path, "rb") as rp:
                    st.download_button(
                        label="⬇️ Download HTML Report",
                        data=rp.read(),
                        file_name=f"deepprobe_{html_escape(st.session_state.project_name)}_report.html",
                        mime="text/html",
                        key="download_html_report",
                        use_container_width=True,
                    )
            else:
                st.button("⬇️ Download HTML Report", disabled=True, use_container_width=True)
        with dl_col2:
            if report_pdf_path.exists():
                with open(report_pdf_path, "rb") as rp:
                    st.download_button(
                        label="📄 Download PDF Report",
                        data=rp.read(),
                        file_name=f"deepprobe_{html_escape(st.session_state.project_name)}_report.pdf",
                        mime="application/pdf",
                        key="download_pdf_report",
                        use_container_width=True,
                    )
            else:
                st.button("📄 Download PDF Report", disabled=True,
                          help="PDF not found — re-run analysis to generate it.",
                          use_container_width=True)

    # -----------------------------------------------------------------------
    # Attack Chain Graph tab
    # -----------------------------------------------------------------------
    with attack_tab:
        st.markdown("<h2 style='color: #2ecc71;'>Interactive Attack Chain Graph</h2>", unsafe_allow_html=True)
        st.write(
            "Each graph shows a correlated threat chain. The **green centre node** is the shared process (PID). "
            "Outer nodes are the individual findings linked to it. Hover over any node for details."
        )
        if correlated_findings:
            sorted_cf = sorted(correlated_findings, key=lambda f: f['weight'], reverse=True)
            for cf in sorted_cf:
                # Determine confidence across all chains in this finding
                # Priority: strongest confidence level wins
                chains = cf.get("correlated_chains", [])
                conf_levels   = {c.get("confidence", "weak") for c in chains}
                conf_types    = {c.get("correlation_type", "") for c in chains}
                if "strong" in conf_levels:
                    confidence = "strong"
                elif "medium" in conf_levels:
                    confidence = "medium"
                else:
                    confidence = "weak"

                _CONF_META = {
                    "strong": ("#2ecc71", "Strong — Same Process"),
                    "medium": ("#3498db", "Medium — Parent↔Child"),
                    "weak":   ("#e67e22", "Weak — Behavioral Co-presence"),
                }
                conf_badge_color, conf_label = _CONF_META.get(confidence, ("#8b949e", confidence.title()))

                st.markdown(
                    f"<h4 style='color:#2ecc71;'>{html_escape(cf.get('title', 'Correlated Chain'))}"
                    f"<span style='font-size:0.65em; margin-left:0.6em; background:{conf_badge_color}22; "
                    f"color:{conf_badge_color}; border:1px solid {conf_badge_color}; "
                    f"border-radius:4px; padding:2px 7px;'>{conf_label}</span></h4>",
                    unsafe_allow_html=True
                )
                st.markdown(
                    f"<p style='color:#c9d1d9;'>{html_escape(get_narrative(cf.get('id'), detections_config))}</p>",
                    unsafe_allow_html=True
                )
                # Show explanatory note for non-strong correlations
                if confidence in ("medium", "weak"):
                    note = next((c.get("note","") for c in chains if c.get("note")), "")
                    if note:
                        st.caption(f"ℹ️ {note}")
                render_attack_chain_graph(cf)

                # ── Ask AI ── chain-aware LLM explanation
                ai_key_cf = f"ai_cf_{cf.get('id','')}_{cf.get('weight',0)}"
                col_graph, col_ai = st.columns([4, 1])
                with col_ai:
                    if st.button("🤖 Ask AI", key=f"btn_{ai_key_cf}", use_container_width=True):
                        chosen_model = st.session_state.get("selected_model", DEFAULT_MODEL)
                        gemini_key   = st.session_state.get("gemini_api_key", "")
                        if not gemini_key:
                            pulled = get_ollama_models()
                            if chosen_model not in pulled:
                                with st.spinner(f"⬇️ Downloading {chosen_model}…"):
                                    ok, pull_msg = pull_ollama_model(chosen_model)
                                if not ok:
                                    st.session_state.ai_responses[ai_key_cf] = (
                                        f"⚠️ Could not download model: {pull_msg}"
                                    )
                        spinner_label = (
                            "Querying Gemini…" if gemini_key
                            else f"Querying {chosen_model} locally…"
                        )
                        with st.spinner(spinner_label):
                            response = query_llm_correlated(
                                cf,
                                model=chosen_model,
                                gemini_key=gemini_key,
                            )
                            st.session_state.ai_responses[ai_key_cf] = response
                if ai_key_cf in st.session_state.ai_responses:
                    st.info(st.session_state.ai_responses[ai_key_cf])

                st.markdown("---")
        else:
            st.markdown(
                '<div class="empty-state">'
                '<div class="es-icon">🔗</div>'
                '<div class="es-title">No correlated attack chains found.</div>'
                '<div class="es-sub">This may indicate isolated or low-activity findings in the memory image.<br>'
                'Chains appear when multiple indicators share the same process ID.</div>'
                '</div>',
                unsafe_allow_html=True,
            )

    # -----------------------------------------------------------------------
    # Timeline tab
    # -----------------------------------------------------------------------
    with timeline_tab:
        st.markdown("<h2 style='color: #2ecc71;'>Execution Timeline</h2>", unsafe_allow_html=True)
        st.write(
            "Reconstructs a chronological view of execution artifacts from **Shimcache** and **Amcache** "
            "registry artifacts. Useful for establishing when suspicious programs first appeared on the system."
        )
        render_timeline(st.session_state.project_name)

    # -----------------------------------------------------------------------
    # MITRE ATT&CK tab
    # -----------------------------------------------------------------------
    with mitre_tab:
        st.markdown("<h2 style='color: #2ecc71;'>MITRE ATT&CK® Coverage</h2>", unsafe_allow_html=True)
        st.write(
            "Shows which MITRE ATT&CK techniques and tactics were triggered by this analysis. "
            "Red bars indicate techniques seen in 3+ findings."
        )
        render_mitre_heatmap(findings)

        # Table of all triggered techniques
        st.markdown("---")
        st.markdown("#### Triggered Techniques Detail")
        mitre_rows = []
        for f in findings:
            for tag in f.get("mitre", []):
                mitre_rows.append({
                    "Technique": tag,
                    "Finding": f.get("title", f.get("id", "")),
                    "Severity Score": f.get("weight", 0)
                })
        if mitre_rows:
            df_mitre = pd.DataFrame(mitre_rows).sort_values("Severity Score", ascending=False)
            st.dataframe(df_mitre, use_container_width=True, hide_index=True)

    with artifacts_tab:
        st.markdown("<h2 style='color: #2ecc71;'>Downloadable Raw Artifacts</h2>", unsafe_allow_html=True)
        
        project_artifacts_folder = OUTPUT_FOLDER / st.session_state.project_name / "artifacts"
        
        if not st.session_state.analysis_successful:
            st.info("No artifacts available. Please run an analysis.")
        elif not project_artifacts_folder.exists():
            st.warning(f"Artifacts folder does not exist: '`{html_escape(str(project_artifacts_folder))}`'. This might mean no artifacts were generated or the path is incorrect.")
        else:
            st.write("These are the raw text or CSV files generated during the scan. You can download them or view their content directly.")

            artifact_files = [] 
            try:
                if project_artifacts_folder.exists():
                    artifact_files = [f for f in os.listdir(project_artifacts_folder) if os.path.isfile(os.path.join(project_artifacts_folder, f))]
                    # Filter for only .txt, .csv, .json, and .jsonl files for inline viewing
                    viewable_artifact_files = sorted([f for f in artifact_files if f.endswith(('.txt', '.csv', '.json', '.jsonl'))])
                else:
                    viewable_artifact_files = []

                if not artifact_files:
                    st.info("No raw artifact files were generated for this project.")
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
                                    <h3 style='color: #2ecc71;'>{html_escape(display_title)}</h3>
                                    <p><small>{html_escape(description)}</small></p>
                                    <div style="flex-grow: 1;"></div>
                                    """, unsafe_allow_html=True)
                            
                            file_data = b""
                            if is_file_present:
                                try:
                                    with open(file_path, "rb") as fp:
                                        file_data = fp.read()
                                except Exception as read_e:
                                    st.error(f"Error reading file '`{html_escape(file_name)}`': {html_escape(str(read_e))}")
                                    download_button_disabled = True

                            st.download_button(
                                label=f"Download",
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

if __name__ == "__main__":
    main()
