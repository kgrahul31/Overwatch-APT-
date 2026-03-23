# 🛡️ Overwatch-APT - Threat Detection & APT Hunting

**Overwatch-APT** is an interactive Streamlit-based web application designed to detect potential cyber threats by analyzing Windows Event Logs (.evtx files). It offers a user-friendly interface for log upload, automatic threat detection, and visualization of suspicious activities.

---

## 📂 Project Structure

- `Main.py` - Script for offline APT hunting by parsing local Windows event logs using the `win32evtlog` module.
- `app.py` - The main Streamlit app interface for login, registration, and launching the threat detection page (`app1.py`).
- `app1.py` - The core detection engine for uploaded `.evtx` files with real-time threat detection and visualization.
- `model.xml` - Sample XML-formatted event log for testing.
- `.evtx` files - Sample event log files used for testing and demonstration.
- `users.db` - SQLite database to store user credentials securely.

---

## 🚀 Features

- 🧠 **Threat Detection**:
  - Scans `.evtx` logs for known indicators of compromise (IOCs).
  - Detects failed logins, account lockouts, malware signatures, privilege escalations, etc.
- 🔍 **APT Hunting**:
  - `Main.py` allows bulk scanning of live system event logs from multiple categories (System, Security, Application).
- 🎨 **Interactive UI**:
  - Modern interface using Streamlit with custom background.
  - Login/Registration system with `sqlite3`.
- 📊 **Visualization**:
  - Matplotlib-generated bar graphs of threat occurrences.
- 🎤 **Voice Control** *(experimental)*:
  - Voice input integrated after login using `speech_recognition`.

---

## 🛠️ Installation

2. Install Requirements
  pip install -r requirements.txt

3. Run the App
   streamlit run app.py
