# inject-config-selftest.ps1 - prove that generate-cpp style config injection
# produces a self-contained implant: config.json -> implant_secrets.c -> the
# binary connects with NO command line arguments.
#
#   pwsh -File tests/scripts/inject-config-selftest.ps1 -Port 9448
param(
  [int]$Port = 9448,
  [string]$Address = "127.0.0.1",
  [string]$AgePriv = "AGE-SECRET-KEY-1TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST",
  [switch]$Gui,
  [switch]$EmptyBuildId
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$fixtures = Join-Path $root "build\inject-fixtures"
$work = Join-Path $root "build\injected"
$serverExe = Join-Path $root "build\mtls-testserver.exe"

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
  -RedirectStandardOutput (Join-Path $root "build\inject-server.log") `
  -RedirectStandardError (Join-Path $root "build\inject-server.err")

try {
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    if (Test-Path (Join-Path $fixtures "server.pub")) { break }
  }
  if (-not (Test-Path (Join-Path $fixtures "server.pub"))) { throw "fixtures missing" }

  Write-Host "==> writing the build configuration (this is what GenerateCpp emits)"
  $config = @{
    name                   = "injected-implant"
    build_id               = $(if ($EmptyBuildId) { "" } else { "inject-selftest" })
    strategy               = "s"
    beacon                 = $false
    poll_timeout           = 0
    reconnect_interval_ns  = 60000000000
    beacon_interval_ns     = 60000000000
    beacon_jitter_ns       = 0
    max_connection_errors  = 1000
    features               = @{ mtls = $true; http = $false; dns = $false; wg = $false; pivot = $false }
    c2                     = @(@{ url = "mtls://${Address}:${Port}" })
    limits                 = @{
      domain_joined = $false; datetime = ""; hostname = ""; username = ""
      file_exists = ""; locale = ""
    }
    secrets                = @{
      peer_public_key           = "age1selftest"
      peer_private_key          = $AgePriv
      peer_public_key_signature = "untrusted comment: test`nAAAA"
      age_server_public_key     = "age1server"
      minisign_server_public_key = [IO.File]::ReadAllText((Join-Path $fixtures "server.pub"))
      mtls_ca_cert              = [IO.File]::ReadAllText((Join-Path $fixtures "ca.pem"))
      mtls_cert                 = [IO.File]::ReadAllText((Join-Path $fixtures "client.pem"))
      mtls_key                  = [IO.File]::ReadAllText((Join-Path $fixtures "client.key"))
      wg_implant_priv_key       = ""
      wg_server_pub_key         = ""
      wg_peer_tun_ip            = ""
    }
  }
  $configPath = Join-Path $root "build\injected-config.json"
  $config | ConvertTo-Json -Depth 6 | Set-Content $configPath -Encoding UTF8
  Write-Host "    $configPath"

  Write-Host "==> configure + build with the injected configuration"
  & cmake -S $root -B $work -G "Visual Studio 17 2022" -A x64 `
      "-DSLIVER_CONFIG_JSON=$configPath" -DIMPLANT_FORMAT=exe -DIMPLANT_DEBUG_LOG=ON -DBUILD_TESTING=OFF
  if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
  & cmake --build $work --config Release
  if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

  $exe = Join-Path $work "bin\implant.exe"
  if (-not (Test-Path $exe)) { throw "artifact not found: $exe" }
  Write-Host ("    {0} ({1} bytes)" -f $exe, (Get-Item $exe).Length)

  Write-Host "==> running the implant with NO arguments"
  $ErrorActionPreference = "Continue"
  # The implant stays connected until the peer closes the session, so run it as a
  # job and stop it if the peer never does.
  $job = Start-Job -ScriptBlock {
    param($path)
    & $path 2>&1
  } -ArgumentList $exe
  if (Wait-Job -Job $job -Timeout 45) {
    Receive-Job -Job $job | ForEach-Object { Write-Host $_ }
  } else {
    Write-Host "    (implant still running after 45s - stopping it)"
    Stop-Job -Job $job
    Receive-Job -Job $job | ForEach-Object { Write-Host $_ }
  }
  Remove-Job -Job $job -Force
  $rc = 0
  $ErrorActionPreference = "Stop"

  if ($Gui) {
    Write-Host "==> GUI subsystem variant (no console, logs to %TEMP%\sliver-implant.log)"
    $guiWork = Join-Path $root "build\injected-gui"
    & cmake -S $root -B $guiWork -G "Visual Studio 17 2022" -A x64 `
        "-DSLIVER_CONFIG_JSON=$configPath" -DIMPLANT_FORMAT=exe -DIMPLANT_GUI=ON -DBUILD_TESTING=OFF
    if ($LASTEXITCODE -ne 0) { throw "cmake configure (gui) failed" }
    & cmake --build $guiWork --config Release
    if ($LASTEXITCODE -ne 0) { throw "cmake build (gui) failed" }

    $guiExe = Join-Path $guiWork "bin\implant.exe"
    $logPath = Join-Path ([IO.Path]::GetTempPath()) "sliver-implant.log"
    Write-Host "    artifact: $guiExe ($((Get-Item $guiExe).Length) bytes)"
    Write-Host "    GUI builds attach to the parent console and log to $logPath"
    Write-Host "    run it manually (SmartScreen/AV may prompt for unsigned binaries):"
    Write-Host "      Unblock-File '$guiExe'"
    Write-Host "      & '$guiExe'"
  }
} finally {
  if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}

Start-Sleep -Milliseconds 300
Get-Content (Join-Path $root "build\inject-server.log") -ErrorAction SilentlyContinue | Write-Host
Get-Content (Join-Path $root "build\inject-server.err") -ErrorAction SilentlyContinue | Write-Host

if ($rc -ne 0) { throw "injected-config selftest failed (exit $rc)" }
Write-Host "==> injected-config selftest passed (no arguments, config baked in)"



