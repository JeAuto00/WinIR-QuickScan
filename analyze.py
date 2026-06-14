from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
import argparse
# --- Helper: normalize .NET-style dates ---
import re
from datetime import datetime, timezone
import argparse
import requests
from pathlib import Path
import os
from dotenv import load_dotenv
from detections import detect_network_behavior

load_dotenv()

alerts_path = Path("C:/MiningLab/alerts.log")
alerts = []

if alerts_path.exists():
    with alerts_path.open("r", encoding="utf-8", errors="ignore") as f:
        alerts = [line.strip() for line in f if line.strip()]

try:
    with open("output/telemetry.json", "r", encoding="utf-8") as f:
        telemetry = json.load(f)
except:
    telemetry = {}

def send_telegram_alert(message):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not token or not chat_id:
        print("Telegram secrets not set.")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    requests.post(url, data={
        "chat_id": chat_id,
        "text": message
    }, timeout=10)   

def normalize_dotnet_date(val):
    """
    Converts /Date(1771245924826)/ into a readable UTC timestamp.
    """
    if not isinstance(val, str):
        return val

    m = re.match(r"^/Date\((\d+)\)/$", val)
    if not m:
        return val

    ms = int(m.group(1))
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


from detections import (
    detect_failed_logon_bursts,
    detect_new_local_user,
    detect_special_priv_logons,
    detect_rdp_logons,
    detect_suspicious_startup_items,
    detect_risky_listening_ports,
    Finding
)

def load_json(path: Path) -> Any:
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8-sig").strip()
    if not content:
        return []
    return json.loads(content)



def finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "title": f.title,
        "severity": f.severity,
        "recommendation": f.recommendation,
        "mitre": getattr(f, "mitre", []),
        "evidence": f.evidence,
        
    }


def make_html_report(telemetry, findings, network_summary=None):
    rows = []

    for f in findings:
        sev_color = (
        "red" if f["severity"] == "High"
        else "orange" if f["severity"] == "Medium"
        else "green"
        )

        rows.append(f"""
<div class="card" style="border-left-color:{sev_color};">
  <h3 style="margin:0;">{f['title']}</h3>
  <p><b>Severity:</b> {f['severity']}</p<p><b>Severity:</b> 
  <span class="badge badge-{f['severity'].lower()}">
  {f['severity']}
  </span>
  </p>>
  <p><b>Recommendation:</b> {f['recommendation']}</p>
  <p><b>MITRE ATT&CK:</b> {"; ".join([f"{t['id']} - {t['name']}" for t in f.get('mitre', [])]) or "N/A"}</p>
  <details>
    <summary>Evidence</summary>
    <pre>{json.dumps(f['evidence'], indent=2)[:4000]}</pre>
  </details>
</div>
""")

    # 🔥 ADD THIS PART (ALERTS + DASHBOARD)

    alerts_path = Path("C:/MiningLab/alerts.log")
    alerts = []

    if alerts_path.exists():
        with alerts_path.open("r", encoding="utf-8", errors="ignore") as f:
            alerts = [line.strip() for line in f if line.strip()]

    alerts_path = Path("C:/MiningLab/alerts.log")
    alerts = []

    if alerts_path.exists():
        with alerts_path.open("r", encoding="utf-8", errors="ignore") as f:
            alerts = [line.strip() for line in f if line.strip()]

    # 🔥 ADD THIS HERE
    if alerts:
        latest = alerts[-1]
        send_telegram_alert(f"🚨 ALERT: {latest}")

    alerts_html = "".join(
    f"<li style='color:red; font-weight:bold;'>{a}</li>" if "ALERT" in a.upper()
    else f"<li>{a}</li>"
    for a in alerts
)

    total_alerts = len(alerts)
    high_cpu_alerts = sum(1 for a in alerts if "HIGH CPU" in a.upper())
    xmrig_alerts = sum(1 for a in alerts if "XMRIG" in a.upper())

    alert_count = sum(1 for a in alerts if "ALERT" in a.upper())
    tcp_count = sum(1 for a in alerts if "TCP" in a.upper())

    timeline_counts = {}

    for a in alerts:
        parts = a.split(" ")
        if len(parts) >= 2:
            minute_key = f"{parts[0]} {parts[1][:5]}"
            timeline_counts[minute_key] = timeline_counts.get(minute_key, 0) + 1

    # 🔥 TIMELINE MUST COME FIRST
    timeline_items = sorted(timeline_counts.items(), reverse=True)
    timeline_items = timeline_items[:10]

    # 🔥 NOW YOU CAN USE IT
    interval_count = len(timeline_items) if timeline_items else 1
    alert_rate = round(total_alerts / interval_count, 2)

    last_updated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    max_chart = max(alert_count, high_cpu_alerts, tcp_count, 1)

    alert_width = int((alert_count / max_chart) * 100)
    cpu_width = int((high_cpu_alerts / max_chart) * 100)
    tcp_width = int((tcp_count / max_chart) * 100)

    timeline_counts = {}

    for a in alerts:
        parts = a.split(" ")
        if len(parts) >= 2:
            minute_key = f"{parts[0]} {parts[1][:5]}"
            timeline_counts[minute_key] = timeline_counts.get(minute_key, 0) + 1

    timeline_items = sorted(timeline_counts.items(), reverse=True)
    timeline_items = timeline_items[:10]
    max_timeline = max((count for _, count in timeline_items), default=1)

    timeline_html = "".join(
        f"""
        <div class="timeline-row">
          <div class="timeline-time">{label}</div>
          <div class="timeline-bar-wrap">
            <div class="timeline-bar" style="width:{int((count / max_timeline) * 100)}%;">{count}</div>
          </div>
        </div>
        """
        for label, count in timeline_items
    ) if timeline_items else "<p>No timeline data available.</p>"


 
    # 🔥 DARK MODE HTML

    top_ips_html = ""
    top_processes_html = ""

    if network_summary:
        top_ips = network_summary.get("top_external_ips", [])
        top_processes = network_summary.get("top_processes", [])
        external_count = network_summary.get("external_connection_count", 0)
        process_tree = network_summary.get("process_tree", [])

        attack_chains = network_summary.get("attack_chains", [])

        attack_chain_html = "".join(
            f"""
            <li>
               <b>{item.get('parent')}</b>
               └── {item.get('child')}<br>
               Destination: {item.get('destination')}<br>
               MITRE: {', '.join(item.get('techniques', []))}
            </li>
            """
            for item in attack_chains
        )

        risk_history = network_summary.get("risk_history", [])

        risk_history_html = "".join(
            f"""
            <tr>
              <td>{item.get('timestamp')}</td>
              <td>{item.get('risk_score')}</td>
              <td>{item.get('risk_level')}</td>
            </tr>
            """
            for item in risk_history[-10:]
        )

        risk_points = network_summary.get("risk_history", [])[-10:]

        risk_chart_points = ",".join(
            f"{item.get('risk_score', 0)}"
            for item in risk_points
        )

        risk_chart_labels = ",".join(
            f"'{item.get('timestamp', '')[-8:]}'"
            for item in risk_points
        )

        process_tree_html = "".join(
            f"""
            <li>
               <b>{item.get('parent')}</b>
               └── {item.get('child')}
               (PID: {item.get('pid')})<br>
               Destination: {item.get('destination')}
            </li>
            """
            for item in process_tree
        )

        top_ips_html = "".join(
            f"""
            <tr>
              <td>{item.get('ip')}</td>
              <td>{item.get('count')}</td>
            </tr>
            """
            for item in top_ips
        )

        top_processes_html = "".join(
            f"""
            <tr>
              <td>{item.get('process')}</td>
              <td>{item.get('count')}</td>
            </tr>
            """
            for item in top_processes
        )

        ioc_hits = network_summary.get("ioc_hits", [])

        ioc_hits_html = "".join(
            f"""
            <li>
              <b>{item.get('title')}</b><br>
              Severity: {item.get('severity')}<br>
              <pre>{json.dumps(item.get('evidence', {}), indent=2)}</pre>
            </li>
            """
            for item in ioc_hits
        ) or "<li>No IOC hits detected.</li>"

        mitre_heatmap = network_summary.get("mitre_heatmap", [])

        mitre_heatmap_html = "".join(
            f"""
            <tr>
              <td>{item.get('technique')}</td>
              <td>{item.get('count')}</td>
            </tr>
            """
            for item in mitre_heatmap
        )

        timeline_items = network_summary.get("incident_timeline", [])

        incident_timeline_html = "".join(
            f"""
            <li>
              <b>{item.get('event')}</b><br>
              Process: {item.get('process')} |
              Parent: {item.get('parent')} |
              PID: {item.get('pid')}<br>
              Destination: {item.get('destination')}<br>
              <code>{item.get('command_line')}</code>
            </li>
            """
            for item in timeline_items
        )

        network_html = f"""
        <div class="card" style="border-left-color:#00bcd4;">
          <h2>🌎 Network Summary</h2>
          <h2>🚨 Host Risk Score: {network_summary.get("risk_score", 0)}/100</h2>
          <p><b>Risk Level:</b> {network_summary.get("risk_level", "Low")}</p>
          <p><b>External Connections:</b> {external_count}</p>
          <h3>Incident Timeline</h3>
          <h3>🌳 Process Tree</h3>

          <ul>
            {process_tree_html}
          </ul>

        <h3>🚨 Attack Chains</h3>

        <ul>
          {attack_chain_html}
        </ul>

        <h3>📈 Risk Trend History</h3>
        <table>
          <tr>
            <th>Timestamp</th>
            <th>Risk Score</th>
            <th>Risk Level</th>
          </tr>
          {risk_history_html}
        </table>

         <h3>🔥 MITRE Heatmap</h3>
         <table>
           <tr>
             <th>Technique</th>
             <th>Count</th>
           </tr>
           {mitre_heatmap_html}
          </table>

          <ol>
            {incident_timeline_html}
          </ol>

          <h3>🚨 IOC Hits</h3>
          <ul>
            {ioc_hits_html}
          </ul>

          <h3>Top External IPs</h3>
          <table>
            <tr>
              <th>Remote IP</th>
              <th>Connection Count</th>
            </tr>
            {top_ips_html}
          </table>

          <h3>📊 Live Risk Trend Chart</h3>

          <div style="display:flex; align-items:flex-end; gap:8px; height:160px; border-left:1px solid #555; border-bottom:1px solid #555;       padding:10px;">
            {"".join([
              f"<div title='Risk {item.get('risk_score', 0)}' style='height:{max(item.get('risk_score', 0), 3)}%; width:24px; background:#00bcd4; border-radius:4px 4px 0 0; text-align:center; font-size:10px;'>{item.get('risk_score', 0)}</div>"
              for item in risk_points
            ])}
          </div>

          <h3>Top Network Processes</h3>
          <table>
            <tr>
              <th>Process</th>
              <th>Connection Count</th>
            </tr>
            {top_processes_html}
          </table>
        </div>
        """
    else:
        network_html = """
        <div class="card" style="border-left-color:#00bcd4;">
          <h2>🌎 Network Summary</h2>
          <p>No network summary available.</p>
        </div>
        """

    return f"""<!doctype html>
<html style="background:#0f172a; color:#e2e8f0;">
<head>
  <meta charset="utf-8"/>
  <title>WinIR-QuickScan Report</title>

  <style>
  html, body {{ background:#111215 !important; color:#e5e7eb !important; margin:0; }}
  body {{
    font-family: "Segoe UI", Arial, sans-serif;
    max-width: 1200px;
    margin: 24px auto !important;
    min-height:100vh;
    padding: 0 16px;
  }}

  h1 {{
    color:#f97316;
    font-size: 30px;
    margin-bottom: 8px;
    letter-spacing: 0.5px;
  }}

  h2 {{
    color:#f3f4f6;
    border-bottom:1px solid #2f2f35;
    padding-bottom:8px;
    margin-top: 28px;
    font-size: 20px;
  }}

  h3 {{
    color:#ffffff;
    font-size: 18px;
    margin-bottom: 10px;
  }}

  p, li, summary, b {{
    color:#d1d5db;
  }}

  a {{
    color:#f97316;
  }}

  pre {{
    background:#1a1c22 !important;
    color:#d1fae5 !important;
    padding:14px;
    border-radius:10px;
    white-space:pre-wrap;
    border:1px solid #2f2f35;
    overflow-x:auto;
  }}

  .topbar {{
    background:#1a1c22;
    border:1px solid #2f2f35;
    border-left:4px solid #f97316;
    padding:16px 20px;
    border-radius:10px;
    margin-bottom:20px;
  }}

  .subtle {{
    color:#9ca3af;
    font-size:14px;
  }}

  .dashboard-grid {{
    display:grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap:16px;
    margin:18px 0 8px 0;
  }}

  .stat-card {{
    background:#1a1c22;
    border:1px solid #2f2f35;
    border-top:3px solid #f97316;
    border-radius:10px;
    padding:16px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.25);
  }}

  .stat-label {{
    color:#9ca3af;
    font-size:13px;
    text-transform:uppercase;
    letter-spacing:0.08em;
    margin-bottom:8px;
  }}

  .stat-value {{
    color:#ffffff;
    font-size:30px;
    font-weight:700;
  }}

  .card {{
    background:#1a1c22 !important;
    color:#e5e7eb !important;
    border-left-width:6px;
    border-left-style:solid;
    padding:14px 16px;
    margin-bottom:16px;
    border-radius:10px;
    border:1px solid #2f2f35;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
  }}

  .card:hover {{
    box-shadow: 0 0 0 1px #f97316, 0 0 14px rgba(249,115,22,0.18);
  }}

  .badge {{
    display:inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    font-weight: bold;
    font-size: 12px;
    margin-left: 6px;
  }}

  .badge-high {{
    background: #7f1d1d;
    color: #fecaca;
    border:1px solid #dc2626;
  }}

  .badge-medium {{
    background: #78350f;
    color: #fde68a;
    border:1px solid #f59e0b;
  }}

  .badge-low {{
    background: #14532d;
    color: #bbf7d0;
    border:1px solid #16a34a;
  }}

  .alert-list {{
    padding-left:0;
    list-style:none;
  }}

  .alert-item {{
    padding: 10px 12px;
    margin-bottom: 10px;
    border-radius: 8px;
    border:1px solid #2f2f35;
    font-family: Consolas, monospace;
    font-size: 13px;
  }}

  .alert-red {{
    background: rgba(127, 29, 29, 0.35);
    border-left: 4px solid #dc2626;
    color: #fecaca;
  }}

  .alert-yellow {{
    background: rgba(120, 53, 15, 0.35);
    border-left: 4px solid #f59e0b;
    color: #fde68a;
  }}

  .alert-blue {{
    background: rgba(30, 64, 175, 0.30);
    border-left: 4px solid #3b82f6;
    color: #bfdbfe;
  }}

  .section-panel {{
    background:#15171c;
    border:1px solid #2f2f35;
    border-radius:10px;
    padding:18px;
    margin-top:14px;
  }}

  ul {{
    padding-left:20px;
  }}

  details {{
    margin-top:10px;
  }}

  summary {{
    cursor:pointer;
    color:#f97316;
    font-weight:600;
  }}

.chart-panel {{
  background:#15171c;
  border:1px solid #2f2f35;
  border-radius:10px;
  padding:18px;
  margin-top:14px;
}}

.chart-row {{
  margin-bottom:16px;
}}

.chart-label {{
  font-size:14px;
  color:#d1d5db;
  margin-bottom:6px;
}}

.chart-bar-wrap {{
  background:#0f1115;
  border:1px solid #2f2f35;
  border-radius:999px;
  height:22px;
  overflow:hidden;
}}

.chart-bar {{
  height:100%;
  border-radius:999px;
  text-align:right;
  padding-right:8px;
  line-height:22px;
  font-size:12px;
  font-weight:700;
}}

.chart-red {{
  background:#dc2626;
  color:white;
}}

.chart-yellow {{
  background:#f59e0b;
  color:black;
}}

.chart-blue {{
  background:#3b82f6;
  color:white;
}}

.timeline-panel {{
  background:#15171c;
  border:1px solid #2f2f35;
  border-radius:10px;
  padding:18px;
  margin-top:14px;
  max-height:400px;
  overflow-y:auto;
}}

.timeline-row {{
  display:grid;
  grid-template-columns: 160px 1fr;
  gap:12px;
  align-items:center;
  margin-bottom:12px;
}}

.timeline-time {{
  font-family: Consolas, monospace;
  color:#9ca3af;
  font-size:13px;
}}

.timeline-bar-wrap {{
  background:#0f1115;
  border:1px solid #2f2f35;
  border-radius:999px;
  height:22px;
  overflow:hidden;
}}

.timeline-bar {{
  height:100%;
  background:#f97316;
  color:white;
  font-size:12px;
  font-weight:700;
  line-height:22px;
  text-align:right;
  padding-right:8px;
  border-radius:999px;
}}

</style>
</head>

<body>
  <div class="topbar">
    <h1>WinIR-QuickScan</h1>
    <p class="subtle">Endpoint Detection and Incident Response Dashboard</p>
    <p class="subtle">Last Updated: {last_updated}</p>
  </div>

  <h2>Detection Dashboard</h2>
  <div class="dashboard-grid">
    <div class="stat-card">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value">{total_alerts}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High CPU Alerts</div>
      <div class="stat-value">{high_cpu_alerts}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">XMRig Alerts</div>
      <div class="stat-value">{xmrig_alerts}</div>
    </div>
  </div>
  <h2>Alert Activity Overview</h2>
<div class="chart-panel">
  <div class="chart-row">
    <div class="chart-label">Critical Alerts ({alert_count})</div>
    <div class="chart-bar-wrap">
      <div class="chart-bar chart-red" style="width:{alert_width}%;">{alert_count}</div>

    </div>
  </div>

  <div class="chart-row">
    <div class="chart-label">High CPU Alerts ({high_cpu_alerts})</div>
    <div class="chart-bar-wrap">
      <div class="chart-bar chart-yellow" style="width:{cpu_width}%;">{high_cpu_alerts}</div>
    </div>
  </div>

  <div class="chart-row">
    <div class="chart-label">TCP Connection Events ({tcp_count})</div>
    <div class="chart-bar-wrap">
      <div class="chart-bar chart-blue" style="width:{tcp_width}%;">{tcp_count}</div>
    </div>
  </div>

{network_html}

</div>
<h2>Alert Timeline</h2>
<p class="subtle">Showing last 10 alert intervals</p>
<div class="timeline-panel">
  {timeline_html}
</div>

<script>
window.addEventListener("load", function() {{
  const panel = document.querySelector(".timeline-panel");
  if (panel) {{
    panel.scrollTop = 0;
  }}
}});
</script>

<h2>Host Summary</h2>



  <p style="color:#94a3b8; margin-top:-10px;">Last Updated: {last_updated}</p>
  <h2>Detection Dashboard</h2>
  <p>Total Alerts: {total_alerts}</p>
  <p>High CPU Alerts: {high_cpu_alerts}</p>
  <p>XMRig Alerts: {xmrig_alerts}</p>

  <h2>Host Summary</h2>
  <pre>
{json.dumps(telemetry, indent=2)}
  </pre>

  <h2>Suspicious Process Monitoring</h2>
  <ul>
    {alerts_html}
  </ul>

  <h2>Findings</h2>
  {''.join(rows) if rows else '<p>No findings</p>'}

</body>
</html>
"""
    


    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>WinIR-QuickScan Report</title>
  <meta http-equiv="refresh" content="5">
</head>
<body style="font-family: Arial, sans-serif; max-width: 960px; margin: 24px auto;">
  <h1>WinIR-QuickScan</h1>

  <h2>Host Summary</h2>
<pre>
{json.dumps(telemetry, indent=2)}
</pre>

  <h2> Suspicious Process Monitoring</h2>
  <ul>
    {alerts_html}
  </ul>

  <h2>Findings</h2>
  {''.join(rows) if rows else '<p>No findings triggered by current thresholds.</p>'}
</body>
</html>
"""
    rows.append(f"""
<div class="card" style="border-left-color:{sev_color};">
  <h3 style="margin:0;">{f['title']}</h3>
  <p><b>Severity:</b> 
  <span style="color:{sev_color}; font-weight:bold;">
  {f['severity']}
  </span>
  </p>
  <p><b>Recommendation:</b> {f['recommendation']}</p>
  <p><b>MITRE ATT&CK:</b> {"; ".join([f"{t['id']} - {t['name']}" for t in f.get('mitre', [])]) or "N/A"}</p>
  <details>
    <summary>Evidence</summary>
    <pre>{json.dumps(f['evidence'], indent=2)[:4000]}</pre>
  </details>
</div>
""")
        
def parse_args():
    p = argparse.ArgumentParser(description="WinIR-QuickScan analyzer")
    p.add_argument("--demo", action="store_true", help="Include demo finding for report styling tests")
    return p.parse_args()

def update_risk_history(outdir, risk_score, risk_level):
    history_path = outdir / "risk_history.json"

    if history_path.exists():
        try:
            history = json.loads(history_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            history = []
    else:
        history = []

    history.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "risk_score": risk_score,
        "risk_level": risk_level
    })

    history = history[-30:]

    history_path.write_text(
        json.dumps(history, indent=2),
        encoding="utf-8"
    )

    return history

def main() -> None:
    args = parse_args()
    outdir = Path("output")
    startup_items = load_json(outdir / "startup_items.json")
    security_events = load_json(outdir / "security_events.json")
    system_events = load_json(outdir / "system_events.json")
    telemetry = load_json(outdir / "telemetry.json") or {}
    if isinstance(telemetry, dict) and "BootTime" in telemetry:
        telemetry["BootTime"] = normalize_dotnet_date(telemetry["BootTime"])

    

    alerts_path = Path("C:/MiningLab/alerts.log")
    alerts = []

    if alerts_path.exists():
        with alerts_path.open("r", encoding="utf-8", errors="ignore") as f:
            alerts = [line.strip() for line in f if line.strip()]

    
    listening_ports = load_json(outdir / "listening_ports.json")

    # ... your detection calls ...

    findings: List[Finding] = []

    f1 = detect_failed_logon_bursts(security_events, window_minutes=5, threshold=10)
    if f1: findings.append(f1)

    f2 = detect_new_local_user(security_events)
    if f2: findings.append(f2)

    f3 = detect_special_priv_logons(security_events, threshold=10)
    if f3: findings.append(f3)

    f4 = detect_rdp_logons(security_events)
    if f4: findings.append(f4)

    f6 = detect_suspicious_startup_items(startup_items)
    if f6: findings.append(f6)

    f7 = detect_risky_listening_ports(listening_ports)
    if f7: findings.append(f7)

    findings_dicts = [finding_to_dict(f) for f in findings]

    network_findings, network_summary = detect_network_behavior("output")
    findings.extend(network_findings)

    risk_history = update_risk_history(
        outdir,
        network_summary.get("risk_score", 0),
        network_summary.get("risk_level", "Low")
    )

    network_summary["risk_history"] = risk_history

    if args.demo:
       findings_dicts.append({
           "title": "DEMO: Sample High Severity Finding",
           "severity": "High",
           "recommendation": "This is a demo entry to validate report formatting and severity coloring.",
           "mitre": [],
           "evidence": [{"note": "Demo enabled via --demo flag."}]
        })

    report_data = {
    "findings": findings_dicts,
    "network_summary": network_summary
    }

    (outdir / "report.json").write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    (outdir / "report.html").write_text(make_html_report(telemetry, findings_dicts, network_summary), encoding="utf-8")

    print(f"[+] Wrote {outdir/'report.json'}")
    print(f"[+] Wrote {outdir/'report.html'}")

if __name__ == "__main__":
    main()

