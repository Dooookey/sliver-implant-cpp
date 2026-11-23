# mtls-session-selftest.ps1 - end-to-end session against the Go mTLS peer.
#
#   pwsh -File tests/scripts/mtls-session-selftest.ps1 -Config msvc-x64-debug -Port 9446
#
# Covers: TLS 1.3 mTLS -> MUX/1 -> yamux -> signed Register -> server initiated
# stream -> UnknownMessageType reply.
param(
  [string]$Config = "msvc-x64-debug",
  [int]$Port = 9446,
  [string]$Address = "127.0.0.1",
  [string]$Name = "cpp-implant",
  [string]$AgePriv = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$build = Join-Path $root "build\$Config"
$fixtures = Join-Path $build "mtls-fixtures"
$serverExe = Join-Path $build "mtls-testserver.exe"
$clientExe = Join-Path $build "bin\implant.exe"

if (-not (Test-Path $clientExe)) { throw "implant.exe not found: $clientExe" }
New-Item -ItemType Directory -Force -Path $fixtures | Out-Null

Write-Host "==> building the Go mTLS peer"
Push-Location (Join-Path $root "tests\mtls-testserver")
try {
  & go build -o $serverExe .
  if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
  Pop-Location
}

Write-Host "==> starting $serverExe on ${Address}:${Port}"
$server = Start-Process -FilePath $serverExe `
  -ArgumentList "-addr", "${Address}:${Port}", "-age-priv", $AgePriv, "-out", $fixtures `
  -PassThru -NoNewWindow `
  -RedirectStandardOutput (Join-Path $build "mtls-server.log") `
  -RedirectStandardError (Join-Path $build "mtls-server.err")

try {
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path (Join-Path $fixtures "server.pub")) { break }
  }
  if (-not (Test-Path (Join-Path $fixtures "server.pub"))) { throw "fixtures missing" }

  Write-Host "==> session (register + unknown-message roundtrip)"
  # The implant logs to stderr; native stderr must not abort the script.
  $ErrorActionPreference = "Continue"
  & $clientExe --mtls $Address $Port `
      (Join-Path $fixtures "ca.pem") `
      (Join-Path $fixtures "client.pem") `
      (Join-Path $fixtures "client.key") `
      $AgePriv `
      (Join-Path $fixtures "server.pub") `
      $Name 2>&1 | ForEach-Object { Write-Host $_ }
  $rc = $LASTEXITCODE
  $ErrorActionPreference = "Stop"
} finally {
  if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

Start-Sleep -Milliseconds 300
$log = Get-Content (Join-Path $build "mtls-server.log") -ErrorAction SilentlyContinue
$log | Write-Host
Get-Content (Join-Path $build "mtls-server.err") -ErrorAction SilentlyContinue | Write-Host

# The implant exits non-zero when the peer closes the session (that is how the
# -1 from sliver_session_run() surfaces), so assert on what the peer actually
# observed instead of on the exit code.
$required = @(
  'REGISTER ok',
  'LS ok',
  'DOWNLOAD ok',
  'EXECUTE ok',
  'PORTFWD DATA: "HTTP/1.0 200 OK',
  'hello-portfwd',
  'SHELL ok',
  'big-output-ok=true'
)
$missing = @()
foreach ($needle in $required) {
  if (-not ($log -match [regex]::Escape($needle))) { $missing += $needle }
}
if ($missing.Count -ne 0) {
  throw ("session selftest failed, missing: " + ($missing -join ', ') + " (implant exit $rc)")
}
Write-Host "==> session selftest passed (implant exit $rc)"
