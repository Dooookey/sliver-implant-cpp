# yamux-selftest.ps1 - yamux + signed-frame interop check (no Sliver server needed).
#
#   pwsh -File tests/scripts/yamux-selftest.ps1 -Config msvc-x64-debug -Port 9444
#
# Starts the Go interop server (hashicorp/yamux, real protocol implementation),
# runs `implant.exe --yamux-selftest`, then stops the server.
param(
  [string]$Config = "msvc-x64-debug",
  [int]$Port = 9444,
  [string]$Address = "127.0.0.1",
  [string]$AgePriv = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$build = Join-Path $root "build\$Config"
$fixtures = Join-Path $build "yamux-fixtures"
$serverExe = Join-Path $build "yamux-testserver.exe"
$clientExe = Join-Path $build "bin\implant.exe"

if (-not (Test-Path $clientExe)) { throw "implant.exe not found: $clientExe" }
New-Item -ItemType Directory -Force -Path $fixtures | Out-Null

Write-Host "==> building the Go yamux interop server"
Push-Location (Join-Path $root "tests\yamux-testserver")
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
  -RedirectStandardOutput (Join-Path $build "yamux-server.log") `
  -RedirectStandardError (Join-Path $build "yamux-server.err")

try {
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path (Join-Path $fixtures "server.pub")) { break }
  }
  if (-not (Test-Path (Join-Path $fixtures "server.pub"))) { throw "server.pub was not produced" }

  Write-Host "==> yamux + frame roundtrip"
  & $clientExe --yamux-selftest $Address $Port $AgePriv (Join-Path $fixtures "server.pub")
  $rc = $LASTEXITCODE
} finally {
  if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

Get-Content (Join-Path $build "yamux-server.err") -ErrorAction SilentlyContinue | Write-Host
if ($rc -ne 0) { throw "yamux selftest failed (exit $rc)" }
Write-Host "==> yamux selftest passed"
