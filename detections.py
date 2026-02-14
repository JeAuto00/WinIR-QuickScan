from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import re

@dataclass
class Finding:
    title: str
    severity: str  # Low/Medium/High
    evidence: List[Dict[str, Any]]
    recommendation: str

def _parse_dt(s: str) -> Optional[datetime]:
    if not s:
        return None
    # Handles typical PowerShell JSON datetime strings
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        try:
            # fallback: "2/13/2026 9:12:00 AM"
            return datetime.strptime(s, "%m/%d/%Y %I:%M:%S %p")
        except Exception:
            return None

def detect_failed_logon_bursts(events: List[Dict[str, Any]], window_minutes: int = 5, threshold: int = 10) -> Optional[Finding]:
    """
    Brute-force-ish behavior: many 4625 within a short window.
    """
    failed = []
    for e in events:
        if int(e.get("Id", -1)) == 4625:
            t = _parse_dt(str(e.get("TimeCreated", "")))
            if t:
                failed.append((t, e))
    failed.sort(key=lambda x: x[0])

    bursts = []
    i = 0
    win = timedelta(minutes=window_minutes)
    while i < len(failed):
        start_t = failed[i][0]
        j = i
        bucket = []
        while j < len(failed) and failed[j][0] - start_t <= win:
            bucket.append(failed[j][1])
            j += 1
        if len(bucket) >= threshold:
            bursts.append({"start": start_t.isoformat(), "count": len(bucket), "sample": bucket[:5]})
        i += 1

    if not bursts:
        return None

    return Finding(
        title=f"Possible brute-force: {len(bursts)} burst(s) of failed logons (4625)",
        severity="High",
        evidence=bursts,
        recommendation="Verify source of failures (remote access, RDP, VPN). Ensure strong passwords/MFA, account lockout policy, and review exposed services."
    )

def detect_new_local_user(events: List[Dict[str, Any]]) -> Optional[Finding]:
    created = [e for e in events if int(e.get("Id", -1)) == 4720]
    if not created:
        return None
    return Finding(
        title="New user account created (4720)",
        severity="High",
        evidence=created[:10],
        recommendation="Confirm the account is expected. If not, disable/delete it and review who created it. Check group membership changes (4732)."
    )

def detect_special_priv_logons(events: List[Dict[str, Any]], threshold: int = 10) -> Optional[Finding]:
    priv = [e for e in events if int(e.get("Id", -1)) == 4672]
    if len(priv) < threshold:
        return None
    return Finding(
        title=f"High volume of privileged logons (4672): {len(priv)}",
        severity="Medium",
        evidence=priv[:10],
        recommendation="Review if privileged activity is expected (admin work, updates). If not, check 4624 logons around these times and validate admin accounts."
    )

def detect_service_installs(system_events: List[Dict[str, Any]]) -> Optional[Finding]:
    installs = [e for e in system_events if int(e.get("Id", -1)) == 7045]
    if not installs:
        return None
    return Finding(
        title=f"New services installed (7045): {len(installs)}",
        severity="High",
        evidence=installs[:10],
        recommendation="Validate service name/path are legitimate. Unexpected services may indicate persistence. Investigate the service binary and publisher."
    )

def detect_rdp_logons(events: List[Dict[str, Any]]) -> Optional[Finding]:
    """
    Looks for RDP-ish logons: 4624 message often includes Logon Type 10 for RemoteInteractive.
    We'll approximate by searching Message text.
    """
    rdp = []
    for e in events:
        if int(e.get("Id", -1)) == 4624:
            msg = str(e.get("Message", ""))
            if re.search(r"Logon Type:\s+10\b", msg):
                rdp.append(e)
    if not rdp:
        return None
    return Finding(
        title=f"Remote Interactive (RDP) logons detected: {len(rdp)}",
        severity="Medium",
        evidence=rdp[:10],
        recommendation="Confirm RDP usage is expected. If not, disable RDP, restrict firewall rules, and ensure NLA + MFA/VPN for remote access."
    )
