param(
  [string]$OutDir = ".\output",
  [int]$HoursBack = 48
)

$ErrorActionPreference = "Stop"

# --- Require admin for Security log access ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
  Write-Error "Run PowerShell as Administrator to collect Security event logs."
}

# Create output directory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$since = (Get-Date).AddHours(-1 * $HoursBack)
Write-Host "[*] Collecting Windows Event Logs since $since ..." -ForegroundColor Cyan

function Write-JsonSafe {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Object
  )
  if ($null -eq $Object -or ($Object -is [System.Array] -and $Object.Count -eq 0)) {
    "[]" | Out-File -Encoding UTF8 $Path
  } else {
    $Object | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $Path
  }
}

# --- Security events (common IR focus) ---
$securityIds = @(4624,4625,4634,4672,4688,4720,4722,4723,4724,4725,4726,4732)
$securityPath = Join-Path $OutDir "security_events.json"

try {
  $security = Get-WinEvent -FilterHashtable @{
    LogName   = "Security"
    Id        = $securityIds
    StartTime = $since
  } -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
      TimeCreated = $_.TimeCreated
      LogName     = $_.LogName
      Id          = [int]$_.Id
      Level       = $_.LevelDisplayName
      Provider    = $_.ProviderName
      MachineName = $_.MachineName
      Message     = $_.Message
    }
  }
} catch {
  Write-Warning "Security log collection failed: $($_.Exception.Message)"
  $security = @()
}

Write-JsonSafe -Path $securityPath -Object $security
Write-Host "[+] Wrote $securityPath" -ForegroundColor Green

# --- System events for service installs (7045) ---
$systemIds  = @(7045)
$systemPath = Join-Path $OutDir "system_events.json"

try {
  $system = Get-WinEvent -FilterHashtable @{
    LogName   = "System"
    Id        = $systemIds
    StartTime = $since
  } -ErrorAction Stop | ForEach-Object {
    [PSCustomObject]@{
      TimeCreated = $_.TimeCreated
      LogName     = $_.LogName
      Id          = [int]$_.Id
      Level       = $_.LevelDisplayName
      Provider    = $_.ProviderName
      MachineName = $_.MachineName
      Message     = $_.Message
    }
  }
} catch {
  # No matches is normal; don't fail the script
  $system = @()
}

Write-JsonSafe -Path $systemPath -Object $system
if ($system.Count -eq 0) {
  Write-Host "[+] Wrote $systemPath (0 events / none matched 7045)" -ForegroundColor Yellow
} else {
  Write-Host "[+] Wrote $systemPath ($($system.Count) events)" -ForegroundColor Green
}

# --- Basic host telemetry ---
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
Write-JsonSafe -Path $telemetryPath -Object $telemetry
Write-Host "[+] Wrote $telemetryPath" -ForegroundColor Green

# --- Persistence: Startup / Run keys ---
Write-Host "[*] Collecting persistence locations (Run keys + Startup folders)..." -ForegroundColor Cyan

function Get-RunKeyValues($path) {
  $items = @()
  try {
    $props = (Get-ItemProperty -Path $path -ErrorAction Stop).PSObject.Properties |
      Where-Object { $_.Name -notmatch '^PS(.*)$' }

    foreach ($p in $props) {
      $items += [PSCustomObject]@{
        Location = $path
        Name     = $p.Name
        Value    = [string]$p.Value
      }
    }
  } catch {
    # ignore missing keys
  }
  return $items
}

$startupItems = @()

$runPaths = @(
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
  "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($rp in $runPaths) { $startupItems += Get-RunKeyValues $rp }

$startupFolders = @(
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($sf in $startupFolders) {
  if (Test-Path $sf) {
    Get-ChildItem -Path $sf -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $startupItems += [PSCustomObject]@{
        Location = $sf
        Name     = $_.Name
        Value    = $_.FullName
      }
    }
  }
}

$startupPath = Join-Path $OutDir "startup_items.json"
Write-JsonSafe -Path $startupPath -Object $startupItems
Write-Host "[+] Wrote $startupPath" -ForegroundColor Green

# --- Network: Listening ports + owning process ---
Write-Host "[*] Collecting listening ports + owning process..." -ForegroundColor Cyan

$listen = @()
$lines = netstat -ano -p tcp | Select-String -Pattern "LISTENING"

foreach ($line in $lines) {
  $parts = ($line -replace "\s+", " ").Trim().Split(" ")
  if ($parts.Length -ge 5) {
    $proto  = $parts[0]
    $local  = $parts[1]
    $state  = $parts[3]
    $procId = [int]$parts[4]

    $port = $null
    if ($local -match ":(\d+)$") { $port = [int]$Matches[1] }

    $pname = $null
    try { $pname = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $pname = $null }

    $listen += [PSCustomObject]@{
      Protocol = $proto
      Local    = $local
      Port     = $port
      State    = $state
      PID      = $procId
      Process  = $pname
    }
  }
}

$listeningPath = Join-Path $OutDir "listening_ports.json"
Write-JsonSafe -Path $listeningPath -Object $listen
Write-Host "[+] Wrote $listeningPath" -ForegroundColor Green
