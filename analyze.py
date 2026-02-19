from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
import argparse
# --- Helper: normalize .NET-style dates ---
import re
from datetime import datetime, timezone
import argparse

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


def make_html_report(telemetry: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    rows = []

    for f in findings:
        sev_color = (
            "red" if f["severity"] == "High"
            else "orange" if f["severity"] == "Medium"
            else "green"
        )

        rows.append(f"""
<div style="border-left:6px solid {sev_color}; padding:12px; margin-bottom:16px; background:#fafafa;">
  <h3 style="margin:0;">{f['title']}</h3>
  <p><b>Severity:</b> {f['severity']}</p>
  <p><b>Recommendation:</b> {f['recommendation']}</p>
  <p><b>MITRE ATT&CK:</b> {"; ".join([f"{t['id']} - {t['name']}" for t in f.get('mitre', [])]) or "N/A"}</p>
  <details>
    <summary>Evidence</summary>
    <pre style="white-space:pre-wrap;">{json.dumps(f['evidence'], indent=2)[:4000]}</pre>
  </details>
</div>
""")

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>WinIR-QuickScan Report</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 960px; margin: 24px auto;">
  <h1>WinIR-QuickScan</h1>

  <h2>Host Summary</h2>
  <pre style="background:#f7f7f7; padding:12px; border-radius:12px;">
{json.dumps(telemetry, indent=2)}
  </pre>

  <h2>Findings</h2>
  {''.join(rows) if rows else '<p>No findings triggered by current thresholds.</p>'}
</body>
</html>
"""
def parse_args():
    p = argparse.ArgumentParser(description="WinIR-QuickScan analyzer")
    p.add_argument("--demo", action="store_true", help="Include demo finding for report styling tests")
    return p.parse_args()

def main() -> None:
    args = parse_args()
    outdir = Path("output")
    startup_items = load_json(outdir / "startup_items.json")
    security_events = load_json(outdir / "security_events.json")
    system_events = load_json(outdir / "system_events.json")
    telemetry = load_json(outdir / "telemetry.json") or {}
    if isinstance(telemetry, dict) and "BootTime" in telemetry:
        telemetry["BootTime"] = normalize_dotnet_date(telemetry["BootTime"])

    
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

    if args.demo:
       findings_dicts.append({
           "title": "DEMO: Sample High Severity Finding",
           "severity": "High",
           "recommendation": "This is a demo entry to validate report formatting and severity coloring.",
           "mitre": [],
           "evidence": [{"note": "Demo enabled via --demo flag."}]
        })

    (outdir / "report.json").write_text(json.dumps(findings_dicts, indent=2), encoding="utf-8")
    (outdir / "report.html").write_text(make_html_report(telemetry, findings_dicts), encoding="utf-8")

    print(f"[+] Wrote {outdir/'report.json'}")
    print(f"[+] Wrote {outdir/'report.html'}")

if __name__ == "__main__":
    main()
