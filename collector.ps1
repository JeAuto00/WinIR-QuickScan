param(
  [string]$OutDir = ".\output",
  [int]$HoursBack = 48
)

$ErrorActionPreference = "Stop"

# Create output directory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$since = (Get-Date).AddHours(-1 * $HoursBack)

Write-Host "[*] Collecting Windows Event Logs since $since ..." -ForegroundColor Cyan

# --- Security events (common IR focus) ---
# 4624 Successful logon
# 4625 Failed logon
# 4634 Logoff
# 4672 Special privileges assigned
# 4688 Process creation (only if audit enabled)
# 4720 User created
# 4722 User enabled
# 4723/4724 Password change/reset
# 4725 User disabled
# 4726 User deleted
# 4732 Added to local group (e.g. Administrators)
$securityIds = @(4624,4625,4634,4672,4688,4720,4722,4723,4724,4725,4726,4732)

$security = Get-WinEvent -FilterHashtable @{
  LogName   = "Security"
  Id        = $securityIds
  StartTime = $since
} -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    TimeCreated = $_.TimeCreated
    LogName     = $_.LogName
    Id          = $_.Id
    Level       = $_.LevelDisplayName
    Provider    = $_.ProviderName
    MachineName = $_.MachineName
    Message     = $_.Message
  }
}

$securityPath = Join-Path $OutDir "security_events.json"
$security | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $securityPath
Write-Host "[+] Wrote $securityPath" -ForegroundColor Green

# --- System events for service installs (7045) ---
$systemIds = @(7045)
$system = Get-WinEvent -FilterHashtable @{
  LogName   = "System"
  Id        = $systemIds
  StartTime = $since
} -ErrorAction SilentlyContinue | ForEach-Object {
  [PSCustomObject]@{
    TimeCreated = $_.TimeCreated
    LogName     = $_.LogName
    Id          = $_.Id
    Level       = $_.LevelDisplayName
    Provider    = $_.ProviderName
    MachineName = $_.MachineName
    Message     = $_.Message
  }
}

$systemPath = Join-Path $OutDir "system_events.json"
$system | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $systemPath
Write-Host "[+] Wrote $systemPath" -ForegroundColor Green

# --- Basic host telemetry (nice in reports) ---
$telemetry = [PSCustomObject]@{
  Hostname = $env:COMPUTERNAME
  User     = $env:USERNAME
  Domain   = $env:USERDOMAIN
  OS       = (Get-CimInstance Win32_OperatingSystem).Caption
  OSBuild  = (Get-CimInstance Win32_OperatingSystem).BuildNumber
  BootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  IPs      = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object {$_.IPAddress -notlike "169.254*"} |
             Select-Object -ExpandProperty IPAddress)
}

$telemetryPath = Join-Path $OutDir "telemetry.json"
$telemetry | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 $telemetryPath
Write-Host "[+] Wrote $telemetryPath" -ForegroundColor Green

Write-Host "[*] Collection complete." -ForegroundColor Cyan
