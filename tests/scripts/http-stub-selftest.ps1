# http-stub-selftest.ps1 - offline regression for the HTTP C2 protocol.
#
# Starts tests/gzipfix's listener stub (real age exchange + CipherContext +
# cookie semantics), builds an implant whose HTTP config points at it, runs it and
# asserts the session handshake plus at least one authenticated POST.
#
#   pwsh -File tests/scripts/http-stub-selftest.ps1 -Port 9780
param(
  [int]$Port = 9780,
  [string]$Address = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$build = Join-Path $root "build"
$work = Join-Path $build "stub-implant"

Write-Host "==> building the stub + fixture tool"
Push-Location (Join-Path $root "tests\gzipfix")
try {
  & go build -o (Join-Path $build "gzipfix.exe") .
  if ($LASTEXITCODE -ne 0) { throw "go build failed" }
  & (Join-Path $build "gzipfix.exe") keyex-gen | Out-Null
} finally {
  Pop-Location
}

$serverId = (Get-Content (Join-Path $build "keyex-server.id") -Raw).Trim()
$serverPub = (Get-Content (Join-Path $build "keyex-server.pub") -Raw).Trim()
$peerId = (Get-Content (Join-Path $build "keyex-peer.id") -Raw).Trim()
$peerPub = (Get-Content (Join-Path $build "keyex-peer.pub") -Raw).Trim()

Write-Host "==> starting the listener stub on ${Address}:${Port}"
$env:STUB_ADDR = "${Address}:${Port}"
$env:STUB_SERVER_ID = $serverId
$env:STUB_PEER_ID = $peerId
$env:STUB_COOKIE = "sid"
# Queue one Ls request: Envelope{ID=42, Type=5 (LsReq), Data={Path="."}} so the
# implant has to dispatch it and post the Ls response back.
$env:STUB_TASK = "082a10051a030a012e"
$stubLog = Join-Path $build "stub.log"
$stub = Start-Process -FilePath (Join-Path $build "gzipfix.exe") -ArgumentList "stub" `
  -PassThru -NoNewWindow -RedirectStandardOutput $stubLog `
  -RedirectStandardError (Join-Path $build "stub.err")

try {
  Start-Sleep -Seconds 2

  Write-Host "==> writing the build configuration"
  $config = @{
    name                  = "stub-implant"
    build_id              = "stub-selftest"
    strategy              = "s"
    beacon                = $false
    poll_timeout          = 0
    reconnect_interval_ns = 60000000000
    beacon_interval_ns    = 0
    beacon_jitter_ns      = 0
    max_connection_errors = 1000
    features              = @{ mtls = $false; http = $true; dns = $false; wg = $false; pivot = $false }
    c2                    = @(@{ url = "http://${Address}:${Port}/" })
    limits                = @{
      domain_joined = $false; datetime = ""; hostname = ""; username = ""
      file_exists = ""; locale = ""
    }
    encoders              = @{ base64 = 101; base58 = 102; base32 = 103; hex = 104; english = 105; gzip = 106; png = 107 }
    secrets               = @{
      peer_public_key          = $peerPub
      peer_private_key         = $peerId
      peer_public_key_signature = ""
      age_server_public_key    = $serverPub
      minisign_server_public_key = "RWQdummykeyforthestubtestonly000000000000000000000000000000000000="
      mtls_ca_cert             = ""
      mtls_cert                = ""
      mtls_key                 = ""
      wg_implant_priv_key      = ""
      wg_server_pub_key        = ""
      wg_peer_tun_ip           = ""
    }
  }
  $configPath = Join-Path $work "config.json"
  New-Item -ItemType Directory -Force -Path $work | Out-Null
  $json = $config | ConvertTo-Json -Depth 12
  [IO.File]::WriteAllText($configPath, $json, (New-Object Text.UTF8Encoding($false)))

  Write-Host "==> configure + build"
  & cmake -S $root -B $work -G "Visual Studio 17 2022" -A x64 `
      "-DSLIVER_CONFIG_JSON=$configPath" -DIMPLANT_FORMAT=exe -DIMPLANT_DEBUG_LOG=ON -DBUILD_TESTING=OFF
  if ($LASTEXITCODE -ne 0) { throw "cmake configure failed" }
  & cmake --build $work --config Release
  if ($LASTEXITCODE -ne 0) { throw "cmake build failed" }

  $exe = Join-Path $work "bin\implant.exe"
  Write-Host "==> running the implant against the stub"
  $job = Start-Job -ScriptBlock { param($p) & $p 2>&1 } -ArgumentList $exe
  Start-Sleep -Seconds 15
  $out = Receive-Job -Job $job -ErrorAction SilentlyContinue
  Stop-Job -Job $job -ErrorAction SilentlyContinue
  Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
  $out | ForEach-Object { Write-Host $_ }

  $log = Get-Content $stubLog -Raw -ErrorAction SilentlyContinue
  $fail = 0
  if ($log -notmatch "STUB SESSION ok") { Write-Host "    MISSING: STUB SESSION ok"; $fail = 1 }
  if ($log -notmatch "STUB POST ok") { Write-Host "    MISSING: STUB POST ok"; $fail = 1 }
  if ($log -notmatch "STUB RESULT ok") { Write-Host "    MISSING: STUB RESULT ok (task dispatch + result upload)"; $fail = 1 }
  if ($fail -ne 0) { throw "http stub selftest failed" }
  Write-Host "==> http stub selftest passed (session + authenticated post)"
} finally {
  if ($stub -and -not $stub.HasExited) { Stop-Process -Id $stub.Id -Force }
  Remove-Item Env:STUB_ADDR, Env:STUB_SERVER_ID, Env:STUB_PEER_ID, Env:STUB_COOKIE -ErrorAction SilentlyContinue
}
