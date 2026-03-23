import streamlit as st
import base64
import tempfile
import re
import os
import time
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Import parsing / logging
import Evtx.Evtx as evtx
import win32evtlog

# Import new utility modules
from utils.ml_engine import detect_anomalies
from utils.mitre_mapper import generate_attack_graph
from utils.threat_intel import analyze_iocs
from utils.ai_analyzer import analyze_threats_with_ai
from utils.event_id_db import get_event_info

# Import PRO-Level Upgrade Modules
from utils.edr_actions import kill_process, isolate_host, restore_host
from utils.soar_playbooks import auto_block_ip, auto_disable_user
from utils.report_gen import generate_pdf_report
from utils.deobfuscator import analyze_payload_obfuscation
import psutil

import sqlite3
import datetime

def init_history_db():
    conn = sqlite3.connect("history.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  scan_type TEXT,
                  source TEXT,
                  events_scanned INTEGER,
                  threats_found INTEGER,
                  anomalies_found INTEGER)''')
    conn.commit()
    conn.close()

def log_scan(scan_type, source, events_scanned, threats_found, anomalies_found):
    try:
        conn = sqlite3.connect("history.db")
        c = conn.cursor()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO scan_history (timestamp, scan_type, source, events_scanned, threats_found, anomalies_found) VALUES (?, ?, ?, ?, ?, ?)",
                  (timestamp, scan_type, source, events_scanned, threats_found, anomalies_found))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging history: {e}")

def get_scan_history():
    try:
        conn = sqlite3.connect("history.db")
        df = pd.read_sql_query("SELECT timestamp, scan_type, source, events_scanned, threats_found, anomalies_found FROM scan_history ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

# Initialize the history DB on startup
init_history_db()

# ─── Page Config ───
st.set_page_config(
    page_title="OVERWATCH-APT · Advanced Threat Hunting",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─── Authentication Guard ───
if not st.session_state.get("authenticated", False):
    st.switch_page("app.py")

# ─── Hide default Streamlit fluff ───
st.markdown("""
<style>
    [data-testid="stSidebarNav"] { display: none !important; }
    #MainMenu { visibility: hidden; }
    [data-testid="stToolbar"] { display: none !important; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─── Minimal Red/Black Animated Theme ───
def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        return base64.b64encode(f.read()).decode()

def apply_theme(bg_image_path):
    bg_b64 = get_base64(bg_image_path)
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    @keyframes slowPan {{
        0% {{ background-position: 0% 0%; }}
        50% {{ background-position: 100% 100%; }}
        100% {{ background-position: 0% 0%; }}
    }}

    @keyframes slideUpFadeIn {{
        0% {{ opacity: 0; transform: translateY(20px); }}
        100% {{ opacity: 1; transform: translateY(0); }}
    }}

    .stApp > header + .main {{
        animation: slideUpFadeIn 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }}

    .stApp {{
        background-color: #050505;
        background-image: linear-gradient(rgba(5, 5, 5, 0.8), rgba(5, 5, 5, 0.8)), url("data:image/png;base64,{bg_b64}");
        background-size: 150% 150%;
        background-attachment: fixed;
        animation: slowPan 45s linear infinite;
        font-family: 'Inter', sans-serif;
    }}

    h1, h2, h3, h4, h5, h6 {{
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
    }}
    p, span, label, div {{
        color: #d1d5db !important;
    }}

    .app-title {{
        text-align: center;
        font-size: 1.6rem;
        font-weight: 700;
        color: #ef4444 !important; /* Red Accent */
        letter-spacing: 2px;
        font-family: 'JetBrains Mono', monospace !important;
        margin-bottom: 0.2rem;
        text-transform: uppercase;
    }}
    .app-subtitle {{
        text-align: center;
        font-size: 0.85rem;
        color: #9ca3af !important;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 1.5rem;
    }}

    .glass-panel {{
        background: rgba(10, 10, 10, 0.8);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 10px;
        padding: 1.2rem;
        margin: 0.6rem 0;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
    }}
    .glass-panel:hover {{
        transform: translateY(-2px);
        box-shadow: 0 8px 24px rgba(239, 68, 68, 0.15);
    }}

    [data-testid="stFileUploader"] {{
        background: rgba(10, 10, 10, 0.6) !important;
        border: 1px dashed rgba(239, 68, 68, 0.3) !important;
        border-radius: 10px !important;
        padding: 0.8rem !important;
    }}

    .stButton > button {{
        background: rgba(239, 68, 68, 0.1) !important;
        color: #ef4444 !important;
        border: 1px solid rgba(239, 68, 68, 0.4) !important;
        border-radius: 6px !important;
        padding: 0.5rem 1.5rem !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        transition: all 0.3s ease !important;
        font-family: 'Inter', sans-serif !important;
    }}
    .stButton > button:hover {{
        background: #ef4444 !important;
        color: #ffffff !important;
        border-color: #ef4444 !important;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
        transform: translateY(-2px);
    }}
    .stButton > button:active {{
        transform: translateY(0px) scale(0.98);
    }}

    .stTabs [data-baseweb="tab-list"] {{
        background: rgba(10, 10, 10, 0.8);
        border-radius: 8px;
        padding: 3px;
        border: 1px solid rgba(239, 68, 68, 0.2);
    }}
    .stTabs [data-baseweb="tab"] {{
        color: #9ca3af !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        transition: color 0.3s ease, transform 0.3s ease !important;
    }}
    .stTabs [data-baseweb="tab"]:hover {{
        color: #ef4444 !important;
        transform: translateY(-1px);
    }}
    .stTabs [aria-selected="true"] {{
        background: rgba(239, 68, 68, 0.1) !important;
        color: #ef4444 !important;
        border-radius: 6px;
    }}
    .stTabs [data-baseweb="tab-highlight"] {{ display: none !important; }}
    .stTabs [data-baseweb="tab-border"] {{ display: none !important; }}

    /* ── Inputs & Selects ── */
    .stTextInput > div > div > input,
    .stSelectbox > div > div {{
        background: rgba(10, 10, 10, 0.8) !important;
        border: 1px solid rgba(239, 68, 68, 0.2) !important;
        border-radius: 6px !important;
        color: #f8fafc !important;
    }}
    .stTextInput > div > div > input:focus, .stSelectbox > div > div:focus {{
        border-color: #ef4444 !important;
        box-shadow: 0 0 5px rgba(239, 68, 68, 0.3) !important;
    }}
    .stTextInput label, .stSelectbox label {{
        color: #9ca3af !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
    }}

    /* ── Alerts ── */
    .stSuccess {{
        background: rgba(34, 197, 94, 0.1) !important;
        border: 1px solid rgba(34, 197, 94, 0.3) !important;
        border-radius: 6px !important;
    }}
    .stError {{
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.4) !important;
        border-radius: 6px !important;
    }}
    .stInfo {{
        background: rgba(59, 130, 246, 0.1) !important;
        border: 1px solid rgba(59, 130, 246, 0.3) !important;
    }}
    .stWarning {{
        background: rgba(245, 158, 11, 0.1) !important;
        border: 1px solid rgba(245, 158, 11, 0.3) !important;
    }}

    /* ── Metrics ── */
    [data-testid="stMetric"] {{
        background: rgba(10, 10, 10, 0.8);
        border: 1px solid rgba(239, 68, 68, 0.2);
        border-radius: 8px;
        padding: 0.8rem;
    }}
    [data-testid="stMetricValue"] {{
        color: #ef4444 !important;
    }}

    /* ── Expander ── */
    .streamlit-expanderHeader {{
        background: rgba(239, 68, 68, 0.1) !important;
        border-radius: 6px !important;
        color: #f8fafc !important;
        border: 1px solid rgba(239, 68, 68, 0.2);
    }}

    /* ── Dataframe ── */
    .stDataFrame {{
        border: 1px solid rgba(239, 68, 68, 0.2) !important;
        border-radius: 8px !important;
    }}
    </style>
    """, unsafe_allow_html=True)

apply_theme('background/bg_red_black.png')


# ─── Core Detection Logic ───
def detect_threats(log_data):
    # Fallback generic regex for static static analysis (.evtx)
    threats = []
    patterns = [
        (r'failed login|logon failure|4625', "⚠️ Failed login attempts"),
        (r'account locked out', "🔒 Account lockout events"),
        (r'privilege escalation|elevated privileges', "🔺 Privilege escalation"),
        (r'malware|ransomware|mimikatz|cobaltstrike', "🦠 Known Malicious Signature"),
        (r'new user account|account created', "👤 New user account creation"),
        (r'port scan|unusual network traffic', "🌐 Suspicious network scanning"),
        (r'registry change|registry key modified', "📝 Suspicious registry changes"),
        (r'firewall disabled|anti-virus disabled', "🛑 Defense Evasion (Security Tools Disabled)"),
        (r'scheduled task created', "📅 Suspicious scheduled task"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, log_data, re.IGNORECASE):
            threats.append(label)
    return threats

def analyze_live_event(eid, payload):
    """
    High-fidelity, practical event analysis. 
    Returns: (Threat Name, Loophole/Tactic, Remediation Action)
    """
    threat, loophole, remediation = None, None, None
    
    payload_lower = payload.lower()
    
    if eid == 4625:
        threat = "Failed Logon Attempt (Possible Brute Force)"
        loophole = "Credential Access / Brute Force (T1110)"
        remediation = "Investigate source IP. Enforce account lockout thresholds and MFA."
    elif eid == 4720:
        threat = "New User Account Created"
        loophole = "Persistence / Backdoor Account Creation (T1136)"
        remediation = "Verify if account creation was authorized. Audit the 'Administrators' group."
    elif eid == 1102:
        threat = "Audit Log Cleared"
        loophole = "Defense Evasion / Indicator Removal (T1070)"
        remediation = "CRITICAL: Investigate immediately. Ensure logs are forwarded to a secure remote SIEM."
    elif eid == 4688:
        suspicious_cmds = ['powershell', 'cmd.exe', 'whoami', 'net.exe', 'vssadmin', 'certutil', 'bitsadmin', 'Invoke-Expression']
        if any(cmd in payload_lower for cmd in suspicious_cmds):
            threat = "Suspicious Administrative Process Execution"
            loophole = "Execution / Discovery (T1059)"
            remediation = "Review command-line arguments in Payload. Restrict PowerShell execution policy."
    elif eid == 4698:
        threat = "Scheduled Task Created"
        loophole = "Persistence / Privilege Escalation (T1053)"
        remediation = "Review task trigger and action executable. Remove unauthorized tasks to prevent reboot persistence."
    elif re.search(r'mimikatz|cobaltstrike|metasploit|bloodhound', payload_lower):
        threat = "Known Malware/Tool Signature Detected"
        loophole = "Malware Execution / Credential Dumping"
        remediation = "Isolate host from network immediately. Run full memory and file AV scan."
            
    return threat, loophole, remediation

def extract_event_id(xml_data):
    """Extracts the EventID from raw EVTX XML."""
    match = re.search(r'<EventID.*?>(\d+)</EventID>', xml_data)
    return match.group(1) if match else "0"


# ─── Main UI ───
st.markdown('<div class="app-title">🔍 OVERWATCH-APT v2.0</div>', unsafe_allow_html=True)
st.markdown('<div class="app-subtitle">Advanced Threat Hunting Engine</div>', unsafe_allow_html=True)

tab_static, tab_live, tab_history, tab_network, tab_settings = st.tabs(["📂 Static Analysis", "📡 Live Monitor", "📜 Scan History", "🌐 Network", "⚙️ Settings"])

# ─── Session State ───
if "gemini_api" not in st.session_state:
    st.session_state["gemini_api"] = ""
if "vt_api" not in st.session_state:
    st.session_state["vt_api"] = ""
if "autopilot_enabled" not in st.session_state:
    st.session_state["autopilot_enabled"] = False

# ─── TAB: SETTINGS ───
with tab_settings:
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
    st.markdown("### 🔑 API Integrations")
    st.info("These keys unlock the advanced AI and Threat Intel Lookup features. They are stored locally in your session.")
    
    col1, col2 = st.columns(2)
    with col1:
        st.session_state["gemini_api"] = st.text_input("Google Gemini API Key (for AI Analysis)", type="password", value=st.session_state["gemini_api"])
    with col2:
        st.session_state["vt_api"] = st.text_input("VirusTotal API Key (for IOC Lookups)", type="password", value=st.session_state["vt_api"])
        
    if st.button("Save Integrations"):
        st.success("API Keys saved securely to session!")
    
    st.markdown("---")
    st.markdown("### 🤖 SOAR Autopilot (Active Defense)")
    st.info("When Autopilot is enabled, the system will automatically block brute-force IPs in the firewall and disable compromised user accounts without requiring manual confirmation.")
    
    autopilot_toggle = st.toggle("Enable Autopilot Features", value=st.session_state["autopilot_enabled"])
    if autopilot_toggle != st.session_state["autopilot_enabled"]:
        st.session_state["autopilot_enabled"] = autopilot_toggle
        st.toast(f"Autopilot is now {'ENABLED 🔴' if autopilot_toggle else 'DISABLED ⚪'}")

    st.markdown('</div>', unsafe_allow_html=True)


# ─── TAB: STATIC ANALYSIS ───
with tab_static:
    uploaded_file = st.file_uploader("Upload a Windows Event Log (.evtx)", type=["evtx"])
    
    if uploaded_file is not None:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".evtx") as temp_file:
                temp_file.write(uploaded_file.read())
                temp_file_path = temp_file.name

            threat_found = False
            all_threats = []
            event_counts = {}
            raw_xml_sample = ""
            record_count = 0

            with st.spinner("Analyzing EVTX file..."):
                with evtx.Evtx(temp_file_path) as log:
                    for record in log.records():
                        record_count += 1
                        xml_data = record.xml()
                        
                        if record_count == 1:
                            raw_xml_sample = xml_data  # Save an example for the AI
                            
                        eid = extract_event_id(xml_data)
                        event_counts[eid] = event_counts.get(eid, 0) + 1

                        threats = detect_threats(xml_data)
                        if threats:
                            threat_found = True
                            all_threats.extend(threats)

            os.remove(temp_file_path)

            st.markdown("---")
            col_results, col_graphs = st.columns([1, 1.2])

            with col_results:
                st.markdown(f"**📊 Records Scanned:** `{record_count}`")
                st.markdown("### 🚨 Detected Core Threats")
                if threat_found:
                    for msg in set(all_threats):
                        st.error(msg)
                else:
                    st.success("✅ No suspicious standard activities detected.")

                st.markdown("### 🧠 ML Anomaly Detection (Isolation Forest)")
                anomalies = detect_anomalies(event_counts)
                if anomalies:
                    st.warning(f"Detected unusual frequency spikes for Event IDs: {', '.join(anomalies)}")
                    for anom_eid in anomalies:
                        info = get_event_info(anom_eid)
                        count = event_counts.get(anom_eid, 0)
                        sev = info['severity']
                        sev_colors = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢', 'Unknown': '⚪'}
                        sev_icon = sev_colors.get(sev, '⚪')
                        with st.expander(f"{sev_icon} EID {anom_eid} — {info['name']}  ({count} occurrences)"):
                            st.markdown(f"**Severity:** {sev_icon} {sev}")
                            st.markdown(f"**What triggers this event:**")
                            st.info(info['action'])
                            st.markdown(f"**What this spike means for your system:**")
                            st.error(info['effect'])
                            if info['mitre'] != 'N/A':
                                st.markdown(f"**MITRE ATT&CK:** `{info['mitre']}`")
                            st.markdown("**🛠️ How to resolve this:**")
                            for step_idx, step in enumerate(info.get('remediation', []), 1):
                                st.markdown(f"{step_idx}. {step}")
                else:
                    st.info("No statistical anomalies found in event frequencies.")

                st.markdown("### 🌐 Automated Threat Intel (VirusTotal)")
                if st.session_state["vt_api"]:
                    with st.spinner("Querying VT API for extracted IOCs..."):
                        vt_results = analyze_iocs(st.session_state["vt_api"], raw_xml_sample) # Using sample to prevent massive API usage
                        if not vt_results:
                            st.info("No IP addresses or Hashes found to scan.")
                        for res in vt_results:
                            if res["vt_result"].get("malicious"):
                                st.error(f"**{res['type']}:** {res['value']} - Malicious Hits: {res['vt_result']['score']}/{res['vt_result']['total']}")
                            else:
                                st.success(f"**{res['type']}:** {res['value']} - Clean ({res['vt_result'].get('total', 0)} engines)")
                else:
                    st.info("⚠️ VirusTotal API key not provided. Extraction bypassed.")

                st.markdown("### 🤖 AI Threat Assessor")
                if st.button("Generate Executive IR Report"):
                    with st.spinner("Consulting Google Gemini AI..."):
                        report = analyze_threats_with_ai(st.session_state["gemini_api"], list(set(all_threats)), raw_xml_sample)
                        st.write(report)

            with col_graphs:
                st.markdown("### 🕸️ Interactive Attack Chain (MITRE ATT&CK)")
                st.plotly_chart(generate_attack_graph(all_threats), use_container_width=True)

                if threat_found:
                    st.markdown("### 📊 Threat Distribution")
                    threat_count = pd.Series(all_threats).value_counts()
                    fig, ax = plt.subplots(figsize=(6, 3))
                    fig.patch.set_facecolor('#0a0a0f')
                    ax.set_facecolor('#0a0a0f')
                    threat_count.plot(kind='barh', ax=ax, color='#5eead4')
                    ax.tick_params(colors='#94a3b8')
                    for spine in ax.spines.values():
                        spine.set_color('#1a2332')
                    st.pyplot(fig)

            # Log the scan to history
            log_scan("Static (.evtx)", uploaded_file.name, record_count, len(all_threats), len(anomalies))

        except Exception as e:
            st.error(f"Error reading file: {e}")


# ─── TAB: LIVE MONITOR ───
with tab_live:
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
    st.markdown("### 📡 Real-Time Threat Monitor")
    st.write("Streams local Windows Event Logs and filters out noise, showing **only** high-fidelity suspicious events with loophole analysis and remediation steps.")
    
    col_log, col_fetch = st.columns([1, 1])
    with col_log:
        log_type = st.selectbox("Windows Log Source", ["Security", "System", "Application"], index=0)
    with col_fetch:
        fetch_num = st.slider("Events to analyze (Depth)", 100, 5000, 1000)
    
    if st.button(f"Scan Last {fetch_num} live '{log_type}' Events", type="primary"):
        with st.spinner("Interrogating Windows APIs..."):
            server = "localhost"
            try:
                hand = win32evtlog.OpenEventLog(server, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
                malicious_events = []
                
                # Visual UX: Progress Bar to show deep analysis is happening
                analyze_text = f"Fetching {fetch_num} logs from {log_type}..."
                progress_bar = st.progress(0, text=analyze_text)
                total_events = len(events[:fetch_num])
                
                for idx, event in enumerate(events[:fetch_num]):
                    # Update progress bar for UX confidence
                    if idx % max(1, total_events // 25) == 0:
                        percent_complete = int((idx / total_events) * 100)
                        progress_bar.progress(percent_complete, text=f"Inspecting Event {idx}/{total_events}...")
                        time.sleep(0.04)
                        
                    eid = getattr(event, 'EventID', 0) & 0xFFFF
                    strings = event.StringInserts
                    payload = " ".join([str(s) for s in strings]) if strings else ""
                    
                    threat, loophole, remediation = analyze_live_event(eid, payload)
                    
                    if threat:
                        malicious_events.append({
                            "Time": event.TimeGenerated.Format(),
                            "EID": eid,
                            "Source": event.SourceName,
                            "Threat Focus": threat,
                            "Attack Loophole": loophole,
                            "Remediation Options": remediation,
                            "Payload": payload,
                            "Decoded Payload": analyze_payload_obfuscation(payload)
                        })
                
                progress_bar.progress(100, text="Correlation Complete.")
                time.sleep(0.5)
                progress_bar.empty()
                    
                st.success(f"Successfully processed {fetch_num} raw events.")
                
                if malicious_events:
                    st.error(f"🚨 ALERT: Found {len(malicious_events)} suspicious threats!")
                    
                    for idx, data in enumerate(malicious_events):
                        with st.expander(f"⚠️ {data['Time']} | EID: {data['EID']} | {data['Threat Focus']}"):
                            st.write(f"**Target Source:** `{data['Source']}`")
                            st.error(f"**Exploited Loophole / Tactic:** {data['Attack Loophole']}")
                            st.info(f"**Remediation Action:** {data['Remediation Options']}")
                            
                            st.write("**Extracted Resource Payload:**")
                            disp_payload = data['Payload'][:300] + "..." if len(data['Payload']) > 300 else data['Payload']
                            st.code(disp_payload, language='text')

                            if data['Decoded Payload']:
                                st.warning("🔐 **Obfuscated Payload Decoded!**")
                                st.code(data['Decoded Payload'], language='powershell')

                            # SOAR and EDR Actions
                            if st.session_state["autopilot_enabled"]:
                                if data['EID'] == 4625: # Brute Force
                                    st.success(f"🤖 **Autopilot:** Auto-blocking attacker IP...")
                                    res_ok, res_msg = auto_block_ip("0.0.0.0") # In real scenerio parse IP from payload
                                    st.write(res_msg)
                            
                            st.write("---")
                            st.write("**Active EDR Actions:**")
                            edr1, edr2 = st.columns(2)
                            with edr1:
                                if st.button("🔴 ISOLATE HOST (Kill Network)", key=f"iso_{idx}"):
                                    res_ok, res_msg = isolate_host()
                                    if res_ok: st.success(res_msg)
                                    else: st.error(res_msg)
                                if st.button("🟢 RESTORE HOST NETWORK", key=f"uniso_{idx}"):
                                    res_ok, res_msg = restore_host()
                                    st.success(res_msg)
                            with edr2:
                                pid_guess = st.text_input("Enter Process ID to Kill (if known):", key=f"pid_kill_{idx}")
                                if st.button("💀 Terminate Process", key=f"btn_kill_{idx}"):
                                    if pid_guess.isdigit():
                                        ok, msg = kill_process(int(pid_guess))
                                        st.success(msg) if ok else st.error(msg)
                                    else:
                                        st.error("Invalid PID.")
                            
                    st.write("---")
                    st.write("**Summary Table of Active Threats:**")
                    summary_df = pd.DataFrame(malicious_events).drop(columns=['Payload', 'Decoded Payload'])
                    st.dataframe(summary_df, use_container_width=True)
                else:
                    st.success(f"✅ **Clean Stream.** Deep-scanned {total_events} events. No critical indicators detected.")

                log_scan("Live Stream", log_type, fetch_num, len(malicious_events), 0)
                
            except Exception as e:
                st.error(f"Failed to read live logs. (Try running as Administrator). Error: {e}")
    st.markdown('</div>', unsafe_allow_html=True)


# ─── TAB: SCAN HISTORY ───
with tab_history:
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
    st.markdown("### 📜 Scan History")
    st.write("Audit log of all Static Analysis and Live Monitor operations.")
    
    history_df = get_scan_history()
    if not history_df.empty:
        st.dataframe(
            history_df,
            use_container_width=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp", format="D MMM YYYY, h:mm a"),
                "scan_type": "Scan Type",
                "source": "Target Source",
                "events_scanned": "Events Analyzed",
                "threats_found": "Threats Blocked",
                "anomalies_found": "ML Anomalies"
            },
            hide_index=True,
        )
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Scans", len(history_df))
        col2.metric("Events Analyzed", f"{history_df['events_scanned'].sum():,}")
        col3.metric("Threats Detected", f"{history_df['threats_found'].sum():,}")
        
        st.markdown("---")
        if st.button("📑 Generate Executive PDF Report"):
            with st.spinner("Compiling PDF Report..."):
                pdf_path = generate_pdf_report(history_df)
                st.success(f"Report Generated: {pdf_path}")
                with open(pdf_path, "rb") as pdf_file:
                    st.download_button(
                        label="⬇️ Download Executive Report",
                        data=pdf_file,
                        file_name="Overwatch_APT_Executive_Report.pdf",
                        mime="application/pdf"
                    )
    else:
        st.info("No scan history yet. Run an analysis to start logging.")
    
    st.markdown('</div>', unsafe_allow_html=True)


# ─── TAB: NETWORK MONITOR ───
with tab_network:
    st.markdown('<div class="glass-panel">', unsafe_allow_html=True)
    st.markdown("### 🌐 Live Network Socket Connections")
    st.write("Lightweight NTA (Network Traffic Analysis) to detect anomalous outbound C2 beaconing or lateral movement directly from the OS socket layer (via `psutil`).")
    
    if st.button("Refresh Network State"):
        with st.spinner("Querying Host Sockets..."):
            conns = psutil.net_connections(kind='inet')
            parsed_conns = []
            for c in conns:
                status = c.status
                if status == 'ESTABLISHED':
                    try:
                        pname = psutil.Process(c.pid).name() if c.pid else "System"
                    except:
                        pname = "Unknown"
                        
                    remote_addr = "N/A"
                    conn_security = "⚪ Unknown"
                    if c.raddr:
                        r_port = c.raddr.port
                        remote_addr = f"{c.raddr.ip}:{r_port}"
                        
                        secure_ports = [443, 22, 993, 465, 8443, 8501, 3389]
                        insecure_ports = [80, 21, 23, 143, 25, 445]
                        if r_port in secure_ports:
                            conn_security = "🔒 Secure (Encrypted)"
                        elif r_port in insecure_ports:
                            conn_security = "⚠️ Insecure (Plaintext)"
                            
                    parsed_conns.append({
                        "Process": pname,
                        "PID": c.pid,
                        "Local Addr": f"{c.laddr.ip}:{c.laddr.port}",
                        "Remote Addr": remote_addr,
                        "Security": conn_security,
                        "State": status
                    })
            if parsed_conns:
                df_net = pd.DataFrame(parsed_conns)
                st.dataframe(df_net, use_container_width=True)
            else:
                st.info("No active ESTABLISHED outbound connections right now.")
                
    st.info("Tip: If you see an unknown process opening remote connections, use the 'Live Monitor' EDR Actions to terminate the PID or Isolate the Host.")
    st.markdown('</div>', unsafe_allow_html=True)
