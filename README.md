🛡️ WinIR-QuickScan

Lightweight Windows Incident Response Collection \& Analysis Toolkit

WinIR-QuickScan is a defensive incident-response utility that collects high-value forensic artifacts from a Windows system and performs automated analysis to identify suspicious activity commonly investigated by SOC and IR teams.

This tool is designed for rapid triage, blue-team learning, and portfolio demonstration.

🚨 Why This Project Matters

Modern SOC analysts are expected to quickly:

Triage authentication failures and privilege escalation

Identify persistence mechanisms

Review system and security telemetry

Produce structured, actionable findings

WinIR-QuickScan demonstrates real-world IR workflows, not offensive tooling or malware.

✨ Features

Collects Windows Security and System event logs

Detects suspicious authentication activity (Event ID 4625 bursts)

Flags privileged logons (4672)

Identifies newly created user accounts (4720)

Detects suspicious service creation (7045)

Enumerates startup persistence locations

Generates structured JSON output and HTML summary reports

Modular detection logic written in Python

🧰 Tech Stack

PowerShell – artifact collection

Python 3 – detection logic \& reporting

Windows Event Logs

HTML / JSON – analyst-friendly output

📁 Project Structure
WinIR-QuickScan/
├── collector.ps1        # Forensic artifact collection
├── analyze.py           # Detection engine \& report generator
├── detections.py        # Modular detection rules
├── output/
│   ├── security\_events.json
│   ├── system\_events.json
│   ├── startup\_items.json
│   └── report.html
<<<<<<< HEAD
├── screenshot
=======
## 📊 Dashboard Preview

<p align="center">
  <img src="screenshots/dashboard.png" width="900">
</p>
>>>>>>> 39541ce (Added dashboard screenshot)
│   ├── collector\_run.png
│   ├── json\_output.png
│   └── report\_view.png
└── README.md

▶️ How It Works

Collector gathers relevant Windows telemetry

Data is written to structured JSON files

Analyzer applies detection logic to identify suspicious patterns

Findings are summarized in an HTML report for rapid review

🚀 Usage
1️⃣ Run the Collector (Administrator Required)
.\\collector.ps1 -HoursBack 48

2️⃣ Run the Analyzer
python analyze.py

3️⃣ Review Results

Open output/report.html in your browser.

🧠 Learning Objectives

This project demonstrates:

Windows security event interpretation

Incident response data collection

Detection logic design

Defensive automation

Analyst-oriented reporting

⚠️ Disclaimer

This tool is intended for defensive and educational purposes only.
Run only on systems you own or are authorized to analyze.

🗺️ Roadmap

Sigma-style rule support

MITRE ATT\&CK mapping

CSV export for SIEM ingestion

Timeline-based analysis mode

Hash validation of persistence files

👤 Author

Joseph E. Autorino
GitHub: https://github.com/JeAuto00

