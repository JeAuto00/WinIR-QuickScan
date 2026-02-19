from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
import re
from collections import Counter
from dataclasses import dataclass, field

@dataclass
class Finding:
    title: str
    severity: str  # Low/Medium/High
    evidence: List[Dict[str, Any]]
    recommendation: str
    mitre: List[Dict[str, str]] = field(default_factory=list)  # [{ "id": "Txxxx", "name": "..." }, ...]


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

def _extract_field(message: str, field: str):
    if not message:
        return None
    m = re.search(rf"(?im)^{re.escape(field)}\s*:\s*(.+)$", message)
    return m.group(1).strip() if m else None

def _extract_logon_id(message: str):
    return _extract_field(message, "Logon ID")

def _extract_logon_type(message: str):
    val = _extract_field(message, "Logon Type")
    if not val:
        return None
    m = re.search(r"(\d+)", val)
    return int(m.group(1)) if m else None

def _extract_account_name(message: str):
    val = _extract_field(message, "Account Name")
    if not val:
        return None
    return val


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

def detect_special_priv_logons(security_events, threshold=10):
    # Build LogonID -> LogonType map from 4624
    logon_id_to_type = {}
    for e in security_events or []:
        try:
            if int(e.get("Id")) != 4624:
                continue
        except Exception:
            continue

        msg = e.get("Message", "")
        logon_id = _extract_logon_id(msg)
        logon_type = _extract_logon_type(msg)
        if logon_id and logon_type is not None:
            logon_id_to_type[logon_id] = logon_type

    # Count 4672 + top accounts + correlated logon types
    total_4672 = 0
    account_counter = Counter()
    logon_type_counter = Counter()
    examples = []

    for e in security_events or []:
        try:
            if int(e.get("Id")) != 4672:
                continue
        except Exception:
            continue

        total_4672 += 1
        msg = e.get("Message", "")

        acct = _extract_account_name(msg) or "UNKNOWN"
        account_counter[acct] += 1

        logon_id = _extract_logon_id(msg)
        if logon_id and logon_id in logon_id_to_type:
            logon_type_counter[logon_id_to_type[logon_id]] += 1

        if len(examples) < 5:
            examples.append({
                "TimeCreated": e.get("TimeCreated"),
                "Account": acct,
                "LogonID": logon_id
            })

    if total_4672 < threshold:
        return None

    type_names = {
        2: "Interactive (Console)",
        3: "Network",
        4: "Batch",
        5: "Service",
        7: "Unlock",
        8: "NetworkCleartext",
        9: "NewCredentials",
        10: "RemoteInteractive (RDP)",
        11: "CachedInteractive",
    }

    top_accounts = [{"account": a, "count": c} for a, c in account_counter.most_common(5)]
    top_types = [{"logon_type": t, "name": type_names.get(t, "Unknown"), "count": c}
                 for t, c in logon_type_counter.most_common(5)]

    evidence = {
        "total_4672": total_4672,
        "top_accounts": top_accounts,
        "top_logon_types_from_4624": top_types,
        "examples": examples,
        "note": "Logon Types are correlated from 4624 using Logon ID. Some 4672 events may not match a 4624 within the collected window."
    }

    return Finding(
        title=f"High volume of privileged logons (4672): {total_4672}",
        severity="Medium",
        recommendation=(
            "Review whether privileged activity is expected (admin work, updates). "
            "If not expected, verify the top triggering accounts, check correlated 4624 logon types (e.g., RDP=10), "
            "and investigate the timeline for suspicious patterns."
        ),
        mitre=[],
        evidence=evidence
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

def detect_suspicious_startup_items(startup_items: List[Dict[str, Any]]) -> Optional[Finding]:
    """
    Flags suspicious persistence via Run keys / Startup folder.
    Heuristics:
      - Executables/scripts launched from AppData/Temp/Downloads
      - LOLBins commonly used for abuse (powershell, wscript, cscript, mshta, rundll32, regsvr32)
      - Script extensions in startup (.ps1, .vbs, .js, .hta, .bat, .cmd)
    """
    if not startup_items:
        return None

    suspicious = []
    lolbins = ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "cmd.exe")
    bad_paths = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\")
    bad_exts = (".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".scr")

    for item in startup_items:
        val = str(item.get("Value", "")).lower()
        name = str(item.get("Name", "")).lower()

        if any(lp in val for lp in bad_paths) or any(lb in val for lb in lolbins) or any(val.endswith(ext) for ext in bad_exts):
            suspicious.append(item)

    if not suspicious:
        return None

    return Finding(
        title=f"Possible persistence: suspicious startup items ({len(suspicious)})",
        severity="Medium",
        evidence=suspicious[:25],
        recommendation="Review Run/RunOnce entries and Startup folders. Validate publisher/path. Remove unknown entries and investigate the referenced binary/script.",
        mitre=[
            {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder"},
            {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
        ]
    )

def detect_risky_listening_ports(listeners: List[Dict[str, Any]]) -> Optional[Finding]:
    """
    Flags risky or commonly abused listening ports.
    Also highlights suspicious process names (scripting LOLBins) listening.
    """
    if not listeners:
        return None

    # Commonly sensitive/abused ports (not always bad, but worth review)
    risky_ports = {
        3389: ("RDP", "Remote Desktop"),
        445: ("SMB", "File sharing / lateral movement risk"),
        5985: ("WinRM", "Remote management (HTTP)"),
        5986: ("WinRM", "Remote management (HTTPS)"),
        22: ("SSH", "Remote access"),
        135: ("RPC", "Windows RPC endpoint mapper"),
        139: ("NetBIOS", "Legacy file sharing"),
    }

    lolbins = {"powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "cmd"}

    flagged = []
    for e in listeners:
        port = e.get("Port")
        proc = (e.get("Process") or "").lower()

        # Flag if port is risky or if a LOLBin appears to be listening
        if isinstance(port, int) and port in risky_ports:
            service, note = risky_ports[port]
            item = dict(e)
            item["Why"] = f"Sensitive port: {port} ({service}) - {note}"
            flagged.append(item)
        elif proc in lolbins:
            item = dict(e)
            item["Why"] = f"Suspicious listener process: {proc}"
            flagged.append(item)

    if not flagged:
        return None

    return Finding(
        title=f"Network exposure: risky listening ports / processes ({len(flagged)})",
        severity="Medium",
        evidence=flagged[:50],
        recommendation="Confirm remote services are required. Restrict via firewall/VPN, disable unused services (e.g., RDP/WinRM), and validate the owning process is legitimate.",
        mitre=[
            {"id": "T1046", "name": "Network Service Discovery"},
            {"id": "T1021", "name": "Remote Services"},
        ],
    )

def _extract_field(message: str, field: str):
    """
    Extracts values like 'Account Name: bob' from Windows event Message text.
    Returns stripped value or None.
    """
    if not message:
        return None
    # Matches: "Account Name: value" until end of line
    m = re.search(rf"(?im)^{re.escape(field)}\s*:\s*(.+)$", message)
    return m.group(1).strip() if m else None

def _extract_logon_id(message: str):
    # In Security event messages: "Logon ID: 0x12345"
    return _extract_field(message, "Logon ID")

def _extract_logon_type(message: str):
    # In 4624 messages: "Logon Type: 10"
    val = _extract_field(message, "Logon Type")
    if not val:
        return None
    # Sometimes it’s like "10" or "10 (RemoteInteractive)"
    m = re.search(r"(\d+)", val)
    return int(m.group(1)) if m else None

def _extract_account_name(message: str):
    # In 4672 messages usually under Subject: "Account Name: USER"
    val = _extract_field(message, "Account Name")
    if not val:
        return None
    # Ignore placeholders
    if val.upper() in ("-", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
        return val
    return val

