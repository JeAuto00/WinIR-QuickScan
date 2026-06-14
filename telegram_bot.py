import json
import subprocess
from pathlib import Path
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

import os

TOKEN = os.getenv("TELEGRAM_TOKEN")
AUTHORIZED_USER_ID = int(os.getenv("TELEGRAM_USER_ID", "0"))

PROJECT_DIR = Path(r"C:\Users\stair\WinIR-QuickScan")
OUTPUT_DIR = PROJECT_DIR / "output"


def is_authorized(update: Update):
    return update.effective_user and update.effective_user.id == AUTHORIZED_USER_ID


def calculate_risk(findings):
    score = 0

    for f in findings:
        severity = str(f.get("severity", "")).lower()

        if "critical" in severity:
            score += 35
        elif "high" in severity:
            score += 20
        elif "medium" in severity:
            score += 10
        elif "low" in severity:
            score += 3

    return min(score, 100)

def collect_network_telemetry():
    net_path = OUTPUT_DIR / "network_connections.json"

    cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Depth 3"
    ]

    result = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True)

    if result.returncode == 0 and result.stdout.strip():
        net_path.write_text(result.stdout, encoding="utf-8")

    return net_path


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ WinIR Bot Online\n\n"
        "/id - Get your ID\n"
        "/scan - Run scan\n"
        "/alerts - Show alerts\n"
        "/report - Get report"
    )


async def get_id(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"Your Telegram ID is: {update.effective_user.id}")


async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized.")
        return

    await update.message.reply_text("🔍 Running scan...")

    subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", "collector.ps1", "-HoursBack", "48"],
        cwd=PROJECT_DIR
    )

    subprocess.run(
        ["python", "analyze.py"],
        cwd=PROJECT_DIR
    )

    collect_edr_telemetry()

    await update.message.reply_text("✅ Scan complete.")

    await alerts(update, context)
    await send_report(update)

    collect_network_telemetry()

    collect_network_connections()

def build_timeline():
    timeline = []

    security_path = OUTPUT_DIR / "security_events.json"

    if security_path.exists():
        try:
            events = json.loads(security_path.read_text(encoding="utf-8"))

            for e in events[:20]:
                eid = str(e.get("Id", ""))
                time = str(e.get("TimeCreated", ""))

                if eid == "4625":
                    timeline.append(f"[{time}] Failed login")
                elif eid == "4672":
                    timeline.append(f"[{time}] Privileged login")
                elif eid == "4720":
                    timeline.append(f"[{time}] New user created")

        except:
            pass

    return timeline

def collect_network_connections():
    net_path = OUTPUT_DIR / "network_connections.json"

    cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State | ConvertTo-Json"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        net_path.write_text(result.stdout, encoding="utf-8")

    return net_path

def collect_edr_telemetry():
    edr_path = OUTPUT_DIR / "edr_processes.json"

    cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Depth3"
    ]

    result = subprocess.run(
        cmd,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        edr_path.write_text(result.stdout, encoding="utf-8")

    return edr_path

def run_detection_engine():
    findings = []

    security_path = OUTPUT_DIR / "security_events.json"
    startup_path = OUTPUT_DIR / "startup_items.json"
    ports_path = OUTPUT_DIR / "listening_ports.json"

    # --- Security Event Detections ---
    if security_path.exists():
        try:
            events = json.loads(security_path.read_text(encoding="utf-8"))

            failed_4625 = [e for e in events if str(e.get("Id", "")) == "4625"]
            priv_4672 = [e for e in events if str(e.get("Id", "")) == "4672"]
            new_user_4720 = [e for e in events if str(e.get("Id", "")) == "4720"]
            user_enabled_4722 = [e for e in events if str(e.get("Id", "")) == "4722"]
            user_added_admin_4732 = [e for e in events if str(e.get("Id", "")) == "4732"]
            audit_cleared_1102 = [e for e in events if str(e.get("Id", "")) == "1102"]

            if len(failed_4625) >= 10:
                findings.append({
                    "title": f"Possible brute force activity: {len(failed_4625)} failed logons",
                    "severity": "High",
                    "mitre": "T1110 - Brute Force"
                })

            if len(priv_4672) >= 15:
                findings.append({
                    "title": f"High volume privileged logons: {len(priv_4672)} special privilege events",
                    "severity": "Medium",
                    "mitre": "T1078 - Valid Accounts"
                })

            if new_user_4720:
                findings.append({
                    "title": f"New user account created: {len(new_user_4720)} event(s)",
                    "severity": "High",
                    "mitre": "T1136 - Create Account"
                })

            if user_enabled_4722:
                findings.append({
                    "title": f"Disabled user account enabled: {len(user_enabled_4722)} event(s)",
                    "severity": "High",
                    "mitre": "T1098 - Account Manipulation"
                })

            if user_added_admin_4732:
                findings.append({
                    "title": f"User added to privileged local group: {len(user_added_admin_4732)} event(s)",
                    "severity": "Critical",
                    "mitre": "T1098 - Account Manipulation"
                })

            if audit_cleared_1102:
                findings.append({
                    "title": "Security audit log was cleared",
                    "severity": "Critical",
                    "mitre": "T1070.001 - Clear Windows Event Logs"
                })

        except Exception as e:
            findings.append({
                "title": f"Security event parsing failed: {e}",
                "severity": "Low",
                "mitre": "N/A"
            })

    # --- NETWORK DETECTION ---
    net_path = OUTPUT_DIR / "network_connections.json"

    if net_path.exists():
        try:
            conns = json.loads(net_path.read_text(encoding="utf-8"))

            if isinstance(conns, dict):
                conns = [conns]

            suspicious_ips = []

            for c in conns:
                remote = str(c.get("RemoteAddress", ""))

                if remote and not remote.startswith(("127.", "192.168", "10.", "172.")):
                    suspicious_ips.append(remote)

            if suspicious_ips:
                findings.append({
                    "title": f"Outbound connections to external IPs detected: {len(suspicious_ips)}",
                    "severity": "Medium",
                    "mitre": "T1071 - Application Layer Protocol"
                })

        except Exception:
            pass

    # --- Persistence Detections ---
    if startup_path.exists():
        try:
            startup_items = json.loads(startup_path.read_text(encoding="utf-8"))

            suspicious_keywords = [
                "temp", "appdata", "powershell", "cmd.exe", "wscript",
                "cscript", "rundll32", "regsvr32", ".ps1", ".vbs",
                ".bat", ".hta", "encodedcommand", "downloadstring"
            ]

            for item in startup_items:
                text = json.dumps(item).lower()

                if any(k in text for k in suspicious_keywords):
                    findings.append({
                        "title": "Suspicious startup persistence item detected",
                        "severity": "High",
                        "mitre": "T1547.001 - Registry Run Keys / Startup Folder"
                    })
                    break

        except Exception as e:
            findings.append({
                "title": f"Startup parsing failed: {e}",
                "severity": "Low",
                "mitre": "N/A"
            })

    # --- Network Exposure Detections ---
    if ports_path.exists():
        try:
            ports = json.loads(ports_path.read_text(encoding="utf-8"))

            risky_ports = {
                "21": "FTP",
                "23": "Telnet",
                "135": "RPC",
                "139": "NetBIOS",
                "445": "SMB",
                "3389": "RDP",
                "5985": "WinRM HTTP",
                "5986": "WinRM HTTPS"
            }

            hits = []

            for p in ports:
                text = json.dumps(p).lower()
                for port, service in risky_ports.items():
                    if f":{port}" in text or f'"{port}"' in text:
                        hits.append(f"{port}/{service}")

            if hits:
                findings.append({
                    "title": f"Risky listening service exposed: {', '.join(sorted(set(hits)))}",
                    "severity": "Medium",
                    "mitre": "T1046 - Network Service Discovery"
                })

        except Exception as e:
            findings.append({
                "title": f"Port parsing failed: {e}",
                "severity": "Low",
                "mitre": "N/A"
            })

    # --- ATTACK CHAIN DETECTION ---
    try:
        if security_path.exists():
            events = json.loads(security_path.read_text(encoding="utf-8"))

            failed = [e for e in events if str(e.get("Id")) == "4625"]
            privileged = [e for e in events if str(e.get("Id")) == "4672"]
            new_users = [e for e in events if str(e.get("Id")) == "4720"]
            admin_added = [e for e in events if str(e.get("Id")) == "4732"]

            # 🔥 Chain 1: Brute Force → Privileged Access
            if len(failed) > 10 and len(privileged) > 5:
                findings.append({
                    "title": "Attack Chain Detected: Brute Force → Privileged Access",
                    "severity": "Critical",
                    "mitre": "T1110 → T1078"
                })

            # 🔥 Chain 2: Account Creation → Privilege Escalation
            if new_users and admin_added:
                findings.append({
                    "title": "Attack Chain Detected: Account Creation → Admin Privilege",
                    "severity": "Critical",
                    "mitre": "T1136 → T1098"
                })

            # 🔥 Chain 3: Log Clearing (Cover Tracks)
            cleared = [e for e in events if str(e.get("Id")) == "1102"]
            if cleared:
                findings.append({
                    "title": "Defense Evasion Detected: Logs Cleared",
                    "severity": "Critical",
                    "mitre": "T1070.001"
                })

    except Exception:
        pass

    # --- EDR MODE: Process / Command-Line Detection ---
    edr_path = OUTPUT_DIR / "edr_processes.json"

    if edr_path.exists():
        try:
            processes = json.loads(edr_path.read_text(encoding="utf-8"))

            if isinstance(processes, dict):
                processes = [processes]

            suspicious_terms = [
                "encodedcommand",
                "downloadstring",
                "invoke-webrequest",
                "iex",
                "mimikatz",
                "net user",
                "net localgroup administrators",
                "vssadmin delete shadows",
                "bcdedit",
                "reg add",
                "schtasks",
                "rundll32",
                "regsvr32",
                "certutil",
                "bitsadmin"
            ]

            risky_paths = [
                "\\appdata\\",
                "\\temp\\",
                "\\downloads\\",
                "\\public\\"
            ]

            for p in processes:
                name = str(p.get("Name", "")).lower()
                cmdline = str(p.get("CommandLine", "")).lower()
                path = str(p.get("ExecutablePath", "")).lower()

                if any(term in cmdline for term in suspicious_terms):
                    findings.append({
                        "title": f"Suspicious command line detected: {name}",
                        "severity": "High",
                        "mitre": "T1059 - Command and Scripting Interpreter"
                    })

                if any(rp in path for rp in risky_paths):
                    findings.append({
                        "title": f"Process running from risky user-writable path: {name}",
                        "severity": "Medium",
                        "mitre": "T1204 - User Execution"
                    })

        except Exception as e:
            findings.append({
                "title": f"EDR process parsing failed: {e}",
                "severity": "Low",
                "mitre": "N/A"
            })

            for p in processes:
                parent = str(p.get("ParentProcessId", ""))
                name = str(p.get("Name", "")).lower()
                cmdline = str(p.get("CommandLine", "")).lower()

                if "powershell" in name and "cmd" in cmdline:
                    findings.append({
                        "title": "Suspicious process chain: PowerShell spawning CMD",
                        "severity": "High",
                        "mitre": "T1059"
                    })

                if "winword" in name and "powershell" in cmdline:
                    findings.append({
                        "title": "Possible macro attack: Word spawning PowerShell",
                        "severity": "Critical",
                        "mitre": "T1204"
                    })

    # --- NETWORK / SMB / LATERAL MOVEMENT DETECTIONS ---
    net_path = OUTPUT_DIR / "network_connections.json"

    if net_path.exists():
        try:
            conns = json.loads(net_path.read_text(encoding="utf-8"))

            if isinstance(conns, dict):
                conns = [conns]

            smb_ports = {"445", "139"}
            lateral_ports = {
                "135": "RPC",
                "139": "NetBIOS",
                "445": "SMB",
                "3389": "RDP",
                "5985": "WinRM",
                "5986": "WinRM HTTPS"
            }

            smb_hits = []
            lateral_hits = []
            external_hits = []

            for c in conns:
                local_port = str(c.get("LocalPort", ""))
                remote_port = str(c.get("RemotePort", ""))
                remote_ip = str(c.get("RemoteAddress", ""))
                state = str(c.get("State", ""))

                if local_port in smb_ports or remote_port in smb_ports:
                    smb_hits.append(f"{remote_ip}:{remote_port} ({state})")

                if remote_port in lateral_ports:
                    lateral_hits.append(f"{remote_ip}:{remote_port}/{lateral_ports[remote_port]} ({state})")

                if remote_ip and not remote_ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
                    if remote_ip not in ("0.0.0.0", "::", "::1"):
                        external_hits.append(f"{remote_ip}:{remote_port} ({state})")

            if smb_hits:
                findings.append({
                    "title": f"SMB network activity detected: {len(smb_hits)} connection(s)",
                    "severity": "Medium",
                    "mitre": "T1021.002 - SMB/Windows Admin Shares"
                })

            if lateral_hits:
                findings.append({
                    "title": f"Possible lateral movement ports observed: {', '.join(sorted(set(lateral_hits[:5])))}",
                    "severity": "High",
                    "mitre": "T1021 - Remote Services"
                })

            if len(external_hits) >= 5:
                findings.append({
                    "title": f"Multiple external network connections detected: {len(external_hits)} connection(s)",
                    "severity": "Medium",
                    "mitre": "T1071 - Application Layer Protocol"
                })

        except Exception as e:
            findings.append({
                "title": f"Network telemetry parsing failed: {e}",
                "severity": "Low",
                "mitre": "N/A"
            })

    return findings


async def alerts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized.")
        return

    findings = run_detection_engine()

    if not findings:
        await update.message.reply_text("✅ SOC Alert Check: No suspicious findings detected.")
        return

    if not findings:
        await update.message.reply_text("✅ No findings detected.")
        return

    risk_score = calculate_risk(findings)

    if risk_score >= 70:
        risk_level = "🔴 HIGH"
    elif risk_score >= 35:
        risk_level = "🟠 MEDIUM"
    else:
        risk_level = "🟢 LOW"

    msg = f"🚨 SOC ALERT\n\nRisk: {risk_score}/100\nLevel: {risk_level}\n\n"

    critical = [f for f in findings if f.get("severity") == "Critical"]
    high = [f for f in findings if f.get("severity") == "High"]
    medium = [f for f in findings if f.get("severity") == "Medium"]

    if critical:
        msg += "💀 CRITICAL THREATS\n"
        for f in critical[:3]:
            msg += f"• {f['title']}\n  MITRE: {f['mitre']}\n\n"

    if high:
        msg += "🔴 HIGH\n"
        for f in high[:3]:
            msg += f"• {f['title']}\n\n"

    if medium:
        msg += "🟠 MEDIUM\n"
        for f in medium[:3]:
            msg += f"• {f['title']}\n\n"

    timeline = build_timeline()

    if timeline:
        msg += "\n🕒 TIMELINE\n"
        for t in timeline[:5]:
            msg += f"{t}\n"

    await update.message.reply_text(msg)

async def godmode(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized.")
        return

    await update.message.reply_text("🔥 GOD MODE SCAN STARTED")

    await scan(update, context)

    summary = (
        "🛡️ FINAL GOD MODE COMPLETE\n\n"
        "Modules:\n"
        "✅ Windows Event Collection\n"
        "✅ SOC Detection Engine\n"
        "✅ Attack Chain Correlation\n"
        "✅ EDR Process Telemetry\n"
        "✅ Risk Scoring\n"
        "✅ HTML Report Delivery\n\n"
        "Status: Defender-grade lab tool online."
    )

    await update.message.reply_text(summary)

def build_soc_summary():
    report_json = OUTPUT_DIR / "report.json"

    if not report_json.exists():
        return "No report data found."

    with open(report_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    network = data.get("network_summary", {})

    risk_score = network.get("risk_score", 0)
    risk_level = network.get("risk_level", "Low")

    top_processes = network.get("top_processes", [])[:5]
    mitre = network.get("mitre_heatmap", [])[:5]

    process_text = "\n".join(
        f"• {p.get('process')} ({p.get('count')})"
        for p in top_processes
    ) or "None"

    mitre_text = "\n".join(
        f"• {m.get('technique')} ({m.get('count')})"
        for m in mitre
    ) or "None"

    ioc_hits = network.get("ioc_hits", [])[:5]

    ioc_text = "\n".join(
        f"🚨 {ioc.get('title')} | {ioc.get('severity')}"
        for ioc in ioc_hits
    ) or "None"

    return f"""
🚨 WinIR SOC Report

Risk Score: {risk_score}/100
Risk Level: {risk_level}

🔥 Top Processes
{process_text}

🎯 MITRE Heatmap
{mitre_text}

IOC Hits:
{ioc_text}
"""


async def send_report(update: Update):
    report = OUTPUT_DIR / "report.html"

    if report.exists():

        summary = build_soc_summary()

        await update.message.reply_text(summary)

        await update.message.reply_document(
            document=open(report, "rb")
    )
    else:
        await update.message.reply_text("Report not found.")


async def report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_authorized(update):
        await update.message.reply_text("Unauthorized.")
        return

    await send_report(update)


app = ApplicationBuilder().token(TOKEN).build()

app.add_handler(CommandHandler("start", start))
app.add_handler(CommandHandler("id", get_id))
app.add_handler(CommandHandler("scan", scan))
app.add_handler(CommandHandler("alerts", alerts))
app.add_handler(CommandHandler("report", report))
app.add_handler(CommandHandler("godmode", godmode))

print("🔥 WinIR EDR SOC Bot Running...")
app.run_polling()