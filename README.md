<div align="center">
  <h1>🛡️ Overwatch-APT</h1>
  <p><strong>Advanced Threat Detection & Live APT Hunting Engine</strong></p>

  [![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
  [![Streamlit App](https://img.shields.io/badge/Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
</div>

---

## 📖 Overview

**Overwatch-APT** is an interactive, powerful Streamlit-based web application and CLI toolkit designed to detect potential cyber threats, advanced persistent threats (APTs), and sophisticated malware by analyzing Windows Event Logs (`.evtx` and `.csv` files). 

It offers a sleek **minimalist crimson and dark-themed UI**, advanced live log scanning, and integrations with modern **Machine Learning (ML) engines** and **AI Analyzers** to uncover the deepest hidden threats within your environment.

## ✨ Key Features

- 🧠 **Smart Threat Detection & ML Engine**:
  - Automatically scans and correlates `.evtx` logs for known indicators of compromise (IOCs).
  - Detects failed logins, account lockouts, malware signatures, and privilege escalations.
  - Features an integrated **AI Analyzer** to detect sophisticated anomalies and explain exploited loopholes.
- ⚡ **Live APT Hunting**:
  - `Main.py` (CLI) and `app1.py` (GUI) allow bulk scanning of live system event logs.
  - Automatically sorts logs across an extensive array of categories: *System, Security, Application, Windows Defender, PowerShell, Sysmon, WinRM, Scheduled Tasks, and Terminal Services*.
- 🎨 **Minimalist Red & Black UI**:
  - A modern, deeply aesthetic interface built with Streamlit, tailored for analysts working in dark environments.
  - Built-in secure SQLite3-based Login and Registration system.
- 📊 **Automated Reporting & Visualization**:
  - Generates comprehensive visual bar graphs showing threat occurrence frequencies.
  - Exports actionable reports to **Excel (.xlsx)**, **CSV**, and **Timesketch-compatible** formats.
- 🛠️ **Remediation & Actionable Intelligence**:
  - Provides clear remediation options for detected endpoints and highlights exact resources (Process IDs, IPs) exploited by each event.

---

## 📂 Project Architecture

| File / Directory | Description |
|------------------|-------------|
| 🖥️ `app.py` | Main Streamlit App gateway (Login, Registration, Entryway). |
| 🛡️ `Sourcecode/pages/app1.py` | Core Live Threat Detection dashboard and file uploader. |
| 🔍 `overwatch-apt.py` | CLI variant for offline APT hunting using massive `.evtx` log dumps. |
| 🤖 `Sourcecode/utils/` | Contains ML engines, AI analyzers, MITRE ATT&CK mappers, and EDR actions. |
| 📚 `lib/` | Internal parsing dictionaries, CSV detection rules, and Evtx Hunting signatures. |

---

## 🚀 Getting Started

### Prerequisites

Ensure you have **Python 3.9+** installed on your Windows environment. 

### 1. Clone the Repository
```bash
git clone https://github.com/kgrahul31/Overwatch-APT-.git
cd Overwatch-APT-
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Web Interface
To start the sleek Streamlit graphical interface:
```bash
streamlit run Sourcecode/app.py
```

### 4. Running the CLI Threat Hunter
To run bulk offline log analysis and generate an extensive Excel report:
```bash
python overwatch-apt.py -p "path/to/logs/folder" -o "My_APT_Report"
```
*(This will automatically parse and sort all `.evtx` files found in the folder and output `My_APT_Report_Report.xlsx` alongside Timesketch CSVs).*

---

## 🎨 Interface Preview

> *(Add screenshots of your application here)*
> 
> *Screenshot 1: The Dark/Crimson Login Gateway*  
> *Screenshot 2: Live Threat Detection Dashboard showing AI-analyzed loopholes*  

---

## 🤝 Contributing

Contributions, issues, and feature requests are highly welcome! 
Feel free to check the [issues page](https://github.com/kgrahul31/Overwatch-APT-/issues) if you want to contribute.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

<div align="center">
  <b>Built with ❤️ by Security Researchers & Threat Hunters</b>
</div>
