[CmdletBinding()]
param(
  [string]$TargetUser,
  [string]$Arg1,
  [string]$LogPath = "$env:TEMP\RemoveLocalUser-script.log",
  [string]$ARLog  = 'C:\ Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

if ($Arg1 -and -not $TargetUser) { $TargetUser = $Arg1 }

$ErrorActionPreference = 'Stop'
$HostName  = $env:COMPUTERNAME
$LogMaxKB  = 100
$LogKeep   = 5
$runStart  = Get-Date

function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN' {Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function To-ISO8601 {
  param($dt)
  if($dt -and $dt -is [datetime] -and $dt.Year -gt 1900){ $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
}

function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Remove Local User [$TargetUser] ==="

$tsNow = To-ISO8601 (Get-Date)
$lines = New-Object System.Collections.ArrayList

try{
  if (-not $TargetUser) { throw "TargetUser is required (pass -TargetUser or -Arg1)" }

  $summary = @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'summary'
    description    = 'Run summary and outcome'
    target_user    = $TargetUser
    status         = 'unknown'
    duration_s     = $null
  }

  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'verify_source'
    description    = 'Input parameters and environment'
    computer       = $HostName
    target_user    = $TargetUser
  }) )

  $protected = @('Administrator','DefaultAccount','Guest','WDAGUtilityAccount')
  if ($TargetUser -in $protected) {
    throw "Refusing to delete protected system account '$TargetUser'"
  }

  $user = Get-LocalUser -Name $TargetUser -ErrorAction Stop
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'user_lookup'
    description    = 'User object prior to deletion'
    target_user    = $TargetUser
    enabled        = $user.Enabled
    lastlogon      = To-ISO8601 $user.LastLogon
    sid            = $user.SID.Value
  }) )

  $loggedOn = (quser 2>$null) | Select-String -SimpleMatch $TargetUser
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'precheck_sessions'
    description    = 'Is target user currently logged on (quser heuristic)'
    target_user    = $TargetUser
    user_logged_on = [bool]$loggedOn
  }) )

  Remove-LocalUser -Name $TargetUser -ErrorAction Stop
  Write-Log "User '$TargetUser' has been removed." 'INFO'
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'action'
    description    = 'Remove-LocalUser executed'
    target_user    = $TargetUser
    result         = 'removed'
  }) )

  $verifyUser = Get-LocalUser -Name $TargetUser -ErrorAction SilentlyContinue
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'verify_user'
    description    = 'Post-removal verification'
    target_user    = $TargetUser
    exists         = [bool]$verifyUser
  }) )

  $summary.status     = if ($verifyUser) { 'failed' } else { 'removed' }
  $summary.duration_s = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  $lines = ,(New-NdjsonLine $summary) + $lines

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch{
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = 'remove_local_user'
    copilot_action = $true
    item           = 'error'
    description    = 'Unhandled error during removal'
    target_user    = $TargetUser
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally{
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
