from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from detections import (
    detect_failed_logon_bursts,
    detect_new_local_user,
    detect_special_priv_logons,
    detect_service_installs,
    detect_rdp_logons,
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
        "evidence": f.evidence,
    }

def make_html_report(telemetry: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    rows = []
    for f in findings:
        rows.append(f"""
        <div style="border:1px solid #ddd; border-radius:12px; padding:12px; margin:12px 0;">
          <h3 style="margin:0 0 6px 0;">{f['title']}</h3>
          <p style="margin:0 0 6px 0;">
          <b>Severity:</b> 
          <span style="color:{'red' if f['severity']=='High' else 'orange' if f['severity']=='Medium' else 'green'};">
          {f['severity']}
    </span>
</p>

          <p style="margin:0 0 6px 0;"><b>Recommendation:</b> {f['recommendation']}</p>
          <details>
            <summary>Evidence (show)</summary>
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
  <pre style="background:#f7f7f7; padding:12px; border-radius:12px;">{json.dumps(telemetry, indent=2)}</pre>

  <h2>Findings</h2>
  {''.join(rows) if rows else '<p>No findings triggered by current thresholds.</p>'}
</body>
</html>
"""

def main() -> None:
    outdir = Path("output")
    security_events = load_json(outdir / "security_events.json")
    system_events = load_json(outdir / "system_events.json")
    telemetry = load_json(outdir / "telemetry.json") or {}

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

    f5 = detect_service_installs(system_events)
    if f5: findings.append(f5)

    findings_dicts = [finding_to_dict(f) for f in findings]

    # --- Demo finding so the HTML shows styling even when no detections trigger ---
    findings_dicts.append({
    "title": "DEMO: Sample High Severity Finding",
    "severity": "High",
    "recommendation": "This is a demo entry to validate report formatting and severity coloring.",
    "evidence": [{"note": "Remove this demo block before final GitHub release."}]
    })


    (outdir / "report.json").write_text(json.dumps(findings_dicts, indent=2), encoding="utf-8")
    (outdir / "report.html").write_text(make_html_report(telemetry, findings_dicts), encoding="utf-8")

    print(f"[+] Wrote {outdir/'report.json'}")
    print(f"[+] Wrote {outdir/'report.html'}")

if __name__ == "__main__":
    main()
