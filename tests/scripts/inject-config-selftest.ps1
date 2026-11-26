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
  [switch]$EmptyBuildId,
  # Beacon flow: the config carries beacon=true + a 5s interval and the peer runs
  # its register/check-in mode instead of the session script.
  [switch]$Beacon,
  # Plain-HTTP C2 (POLL channel): the peer speaks the same envelope protocol over
  # HTTP request/response bodies.
  [switch]$Http,
  # HTTPS C2 (TLS without client certs / without verification, like the Go implant).
  [switch]$Https
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
$peerArgs = @("-addr", "${Address}:${Port}", "-age-priv", $AgePriv, "-out", $fixtures)
if ($Beacon) { $peerArgs += "-beacon" }
if ($Http) { $peerArgs += "-http" }
if ($Https) { $peerArgs += "-http", "-https" }
$server = Start-Process -FilePath $serverExe `
  -ArgumentList $peerArgs `
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
    beacon                 = [bool]$Beacon
    poll_timeout           = 0
    reconnect_interval_ns  = 60000000000
    # Must mirror what cppbuild writes: a session build gets 0, a beacon build
    # gets the chosen interval. The implant validates the interval only for
    # beacon builds.
    beacon_interval_ns     = $(if ($Beacon) { 5000000000 } else { 0 })
    beacon_jitter_ns       = 0
    max_connection_errors  = 1000
    features               = @{ mtls = (-not ($Http -or $Https)); http = [bool]($Http -or $Https); dns = $false; wg = $false; pivot = $false }
    c2                     = @(@{ url = $(if ($Https) { "https://${Address}:${Port}/c2" } elseif ($Http) { "http://${Address}:${Port}/c2" } else { "mtls://${Address}:${Port}" }) })
    limits                 = @{
      domain_joined = $false; datetime = ""; hostname = ""; username = ""
      file_exists = ""; locale = ""
    }
    # Mirrors the "http" object server/cppbuild writes from the C2 profile. The
    # implant exposes it through sliver_config_http_* (no runtime consumer yet).
    http                   = @{
      user_agent             = "sliver-selftest/1.0"
      nonce_query_arg_chars  = "abcdef"
      nonce_query_arg_length = 4
      nonce_mode             = "query"
      headers                = @(
        @{ method = "GET"; name = "Accept"; value = "*/*"; probability = 100 }
      )
      url_parameters         = @(
        @{ method = "GET"; name = "n"; value = "1"; probability = 100 }
      )
      path_segments          = @(
        @{ is_file = $false; value = "api" },
        @{ is_file = $true; value = "index" }
      )
      extensions             = @("php")
      min_path_length        = 2
      max_path_length        = 6
      min_file_gen           = 1
      max_file_gen           = 3
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
  $runSeconds = if ($Beacon -or $Http -or $Https) { 40 } else { 150 }
  if (Wait-Job -Job $job -Timeout $runSeconds) {
    Receive-Job -Job $job | ForEach-Object { Write-Host $_ }
  } else {
    Write-Host "    (implant still running after ${runSeconds}s - stopping it)"
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
$serverLog = Join-Path $root "build\inject-server.log"
Get-Content $serverLog -ErrorAction SilentlyContinue | Write-Host
Get-Content (Join-Path $root "build\inject-server.err") -ErrorAction SilentlyContinue | Write-Host

if ($Beacon) {
  # Beacon regression net: registration must reach the peer, and a task handed to
  # the implant must come back as a result on a later check-in.
  $log = Get-Content $serverLog -Raw -ErrorAction SilentlyContinue
  $prefix = if ($Http -or $Https) { "HTTP " } else { "" }
  if ($log -notmatch "${prefix}BEACON REGISTER ok") {
    $rc = 1
    Write-Host "    MISSING: ${prefix}BEACON REGISTER ok"
  }
  if ($log -notmatch "${prefix}BEACON CHECKIN ok") {
    $rc = 1
    Write-Host "    MISSING: ${prefix}BEACON CHECKIN ok"
  }
  $wantTasks = if ($Http -or $Https) { "tasks=1" } else { "tasks=2" }
  if ($log -notmatch "${prefix}BEACON CHECKIN ok: $wantTasks") {
    $rc = 1
    Write-Host "    MISSING: ${prefix}BEACON CHECKIN ok: $wantTasks (task dispatch/result queue)"
  }
}

if ($rc -ne 0) { throw "injected-config selftest failed (exit $rc)" }
if ($Beacon) {
  Write-Host "==> injected-config beacon selftest passed (register + checkin + result)"
} else {
  Write-Host "==> injected-config selftest passed (no arguments, config baked in)"
}



