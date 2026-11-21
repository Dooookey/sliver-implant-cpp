# tls-selftest.ps1 - run the C implant's TLS 1.3 handshake against the Go test server.
#
#   pwsh -File tests/scripts/tls-selftest.ps1 -Config msvc-x64-debug -Port 9443
#
# Builds the Go fixture server, starts it, runs `implant.exe --tls-selftest`,
# prints the negotiated parameters and stops the server again.
param(
  [string]$Config = "msvc-x64-debug",
  [int]$Port = 9443,
  [string]$Address = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$build = Join-Path $root "build\$Config"
$fixtures = Join-Path $build "tls-fixtures"
$serverExe = Join-Path $build "tls-testserver.exe"
$clientExe = Join-Path $build "bin\implant.exe"

if (-not (Test-Path $clientExe)) {
  throw "implant.exe not found: $clientExe (build preset $Config first)"
}
New-Item -ItemType Directory -Force -Path $fixtures | Out-Null

Write-Host "==> building the Go TLS fixture server"
Push-Location (Join-Path $root "tests\tls-testserver")
try {
  & go build -o $serverExe .
  if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
  Pop-Location
}

Write-Host "==> starting $serverExe on ${Address}:${Port}"
$server = Start-Process -FilePath $serverExe `
  -ArgumentList "-addr", "${Address}:${Port}", "-out", $fixtures `
  -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $build "tls-server.log") `
  -RedirectStandardError (Join-Path $build "tls-server.err")

try {
  $ready = $false
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path (Join-Path $fixtures "client.key")) { $ready = $true; break }
  }
  if (-not $ready) { throw "fixture server did not produce certificates" }

  Write-Host "==> handshake"
  & $clientExe --tls-selftest $Address $Port `
      (Join-Path $fixtures "ca.pem") `
      (Join-Path $fixtures "client.pem") `
      (Join-Path $fixtures "client.key")
  $rc = $LASTEXITCODE
} finally {
  if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

if ($rc -ne 0) { throw "handshake selftest failed (exit $rc)" }
Write-Host "==> handshake selftest passed"
