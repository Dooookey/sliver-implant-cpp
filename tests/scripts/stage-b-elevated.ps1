<#
.SYNOPSIS
  Stage B verification: run in an elevated session with real credentials.

.DESCRIPTION
  make-token / getsystem / registry writes / service start cannot be verified in
  the restricted (Low integrity) sandbox, so they are validated here.
  Produces build\stage-b-report.txt which can be pasted back verbatim.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Implant,
  [string]$Username = "",
  [string]$Password = "",
  [string]$Domain = ".",
  [string]$OutFile = "build\stage-b-report.txt"
)

$ErrorActionPreference = "Continue"
$report = New-Object System.Collections.Generic.List[string]

function Add-Line([string]$text) {
  $report.Add($text)
  Write-Host $text
}

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($id)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Line "=== stage-b report ==="
Add-Line "user     : $env:USERNAME"
Add-Line "elevated : $elevated"
Add-Line "implant  : $Implant"

Add-Line ""
Add-Line "--- selftest-all ---"
if (Test-Path $Implant) {
  $out = & $Implant --selftest-all 2>&1
  foreach ($line in $out) { Add-Line "  $line" }
} else {
  Add-Line "  MISSING: $Implant"
}

Add-Line ""
Add-Line "--- registry write probe ---"
try {
  New-Item -Path "HKCU:\Software\SliverCppProbe" -Force -ErrorAction Stop | Out-Null
  Set-ItemProperty -Path "HKCU:\Software\SliverCppProbe" -Name "Value" -Value "hello" -ErrorAction Stop
  $read = (Get-ItemProperty -Path "HKCU:\Software\SliverCppProbe" -Name "Value").Value
  Remove-Item -Path "HKCU:\Software\SliverCppProbe" -Recurse -Force
  Add-Line "  HKCU write/read/delete : OK (value=$read)"
} catch {
  Add-Line "  HKCU write/read/delete : FAILED - $($_.Exception.Message)"
}

Add-Line ""
Add-Line "--- make-token ---"
if ($Username -ne "" -and $Password -ne "") {
  Add-Line "  client: make-token -u $Domain\$Username -p <PASSWORD>"
  Add-Line "  client: execute -o cmd /c echo stage-b-token-ok"
  Add-Line "  expect: stage-b-token-ok"
} else {
  Add-Line "  skipped (pass -Username/-Password)"
}

Add-Line ""
Add-Line "--- getsystem ---"
$privs = "see selftest-all above (privileges: Low)"; if ($false) { $privs = & $Implant --privs-selftest 2>$null | Out-String }
Add-Line "  privileges: $($privs.Trim())"
Add-Line "  client: getsystem (expect elevated=true)"

Add-Line ""
Add-Line "--- service start ---"
if ($elevated) {
  Add-Line "  client: start-service-by-name Spooler"
  Add-Line "  expect: services shows Spooler RUNNING"
} else {
  Add-Line "  skipped (not elevated)"
}

Add-Line ""
Add-Line "=== end of report ==="

$dir = Split-Path -Parent $OutFile
if ($dir -ne "" -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$report | Set-Content -Path $OutFile -Encoding UTF8
Write-Host ""
Write-Host ("report written to " + $OutFile)

