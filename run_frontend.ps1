$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host '=== VANET PQC IDS: BROWSER DEMO ===' -ForegroundColor Cyan
$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { throw 'Python launcher (py.exe) was not found.' }
py -3.11 -c "import oqs, cryptography; print('Python cryptography dependencies: OK')"
if ($LASTEXITCODE -ne 0) { throw 'Python dependencies are missing. Run: py -3.11 -m pip install -r requirements.txt' }

# Avoid accidentally attaching the browser to an older RSU process.
$listener = Get-NetUDPEndpoint -LocalPort 5002 -ErrorAction SilentlyContinue
if ($listener) {
    throw 'UDP port 5002 is already in use. Stop the existing RSU server window first, then run this script again.'
}

Write-Host 'Starting the RSU server...' -ForegroundColor Yellow
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\simulator\rsu_server.py')
$deadline = (Get-Date).AddSeconds(30)
$ready = $null
$keyReady = $false
do {
    Start-Sleep -Milliseconds 500
    $ready = Get-NetUDPEndpoint -LocalPort 5002 -ErrorAction SilentlyContinue
    $keyReady = (Test-Path '.\results\rsu_mlkem_public_key.bin') -and ((Get-Item '.\results\rsu_mlkem_public_key.bin' -ErrorAction SilentlyContinue).Length -gt 0)
} until (($ready -and $keyReady) -or (Get-Date) -ge $deadline)
if (-not $ready -or -not $keyReady) {
    throw 'RSU did not become ready within 30 seconds. Check the RSU terminal for startup errors.'
}

$forwardListener = Get-NetUDPEndpoint -LocalPort 5200 -ErrorAction SilentlyContinue
if ($forwardListener) { throw 'UDP port 5200 is already in use. Stop the old forwarding monitor and retry.' }
Write-Host 'Starting the geographic forwarding monitor...' -ForegroundColor Yellow
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\simulator\forwarding_monitor.py')
Start-Sleep -Seconds 1
Write-Host 'Starting the browser dashboard...' -ForegroundColor Yellow
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\frontend\server.py')
Start-Sleep -Seconds 2
Start-Process 'http://127.0.0.1:8765'
Write-Host ''
Write-Host 'Dashboard: http://127.0.0.1:8765' -ForegroundColor Green
Write-Host 'Select Vehicle A/B/C and click Run secure transmission.'
Write-Host 'Watch the browser for the 12 stages and the RSU terminal for live processing logs.'
Write-Host 'This demo uses the existing crypto, detector, risk and forwarding modules. It does not start SUMO.'
Write-Host 'To stop, press Ctrl+C in the RSU, forwarding monitor and dashboard windows.'
