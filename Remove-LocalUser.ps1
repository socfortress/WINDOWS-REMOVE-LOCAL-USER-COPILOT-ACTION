[CmdletBinding()]
param(
  [string]$TargetUser,
  [string]$Arg1,
  [string]$LogPath = "$env:TEMP\RemoveLocalUser-script.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5
$runStart = Get-Date

if ($Arg1 -and -not $TargetUser) { $TargetUser = $Arg1 }

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}
function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length/1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  return (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz')
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Remove Local User [$TargetUser] ==="

$ts = Now-Timestamp
$lines = @()

try {
  if (-not $TargetUser) { throw "TargetUser is required (pass -TargetUser or -Arg1)" }

  if ($TargetUser -in @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')) {
    throw "Refusing to delete protected system account '$TargetUser'"
  }

  $user = Get-LocalUser -Name $TargetUser -ErrorAction Stop

  Remove-LocalUser -Name $TargetUser -ErrorAction Stop
  Write-Log "User '$TargetUser' has been removed." 'INFO'

  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    type           = 'user_removed'
    target_user    = $TargetUser
    status         = 'removed'
  } | ConvertTo-Json -Compress -Depth 4)
  $verifyUser = Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue
  $lines += ([pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    type           = 'verify_user'
    target_user    = $TargetUser
    exists         = [bool]$verifyUser
  } | ConvertTo-Json -Compress -Depth 4)

  $summary = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    type           = 'summary'
    target_user    = $TargetUser
    status         = if ($verifyUser) { 'failed' } else { 'removed' }
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }

  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    type           = 'error'
    target_user    = $TargetUser
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
