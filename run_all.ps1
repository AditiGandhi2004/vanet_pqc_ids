$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

Write-Host '=== VANET PQC IDS: PRE-FLIGHT ===' -ForegroundColor Cyan
$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { throw 'Python launcher (py.exe) not found. Install Python 3.11 and enable the Python Launcher.' }
py -3.11 -c "import sys; print('Python:', sys.version)"
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 is not available. Run: py -3.11 --version' }

if (-not $env:SUMO_HOME) { $env:SUMO_HOME = 'C:\Program Files (x86)\SUMO' }
if (-not $env:SUMO_BINARY) { $env:SUMO_BINARY = Join-Path $env:SUMO_HOME 'bin\sumo-gui.exe' }
if (-not (Test-Path $env:SUMO_BINARY)) {
    $found = Get-Command sumo-gui.exe -ErrorAction SilentlyContinue
    if ($found) { $env:SUMO_BINARY = $found.Source }
    else { throw "SUMO GUI not found at '$env:SUMO_BINARY'. Set SUMO_HOME or SUMO_BINARY to your actual SUMO installation." }
}
$env:Path = "$env:Path;$env:SUMO_HOME\bin"
Write-Host "SUMO: $env:SUMO_BINARY" -ForegroundColor Green

py -3.11 -c "import oqs, traci, pandas, sklearn, cryptography; print('Python dependencies: OK'); print('ML-DSA-65 supported:', 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms()); print('ML-KEM-768 supported:', 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms())"
if ($LASTEXITCODE -ne 0) {
    throw 'One or more Python/native dependencies are unavailable. Activate the project venv and run: python -m pip install -r requirements.txt. If oqs fails, install a compatible native liboqs as documented in README.md.'
}

$required = @('sumo\vanet.sumocfg','sumo\vanet.net.xml','sumo\vanet.rou.xml','results\vanet_ids_dataset.csv','results\vanet_ids_model.pkl')
foreach ($item in $required) { if (-not (Test-Path $item)) { throw "Required project file missing: $item" } }
Write-Host 'Project files: OK' -ForegroundColor Green

$env:VANET_FORWARD_HOST = if ($env:VANET_FORWARD_HOST) { $env:VANET_FORWARD_HOST } else { '127.0.0.1' }
$env:VANET_FORWARD_PORT = if ($env:VANET_FORWARD_PORT) { $env:VANET_FORWARD_PORT } else { '5200' }
Write-Host 'Opening RSU, forwarding monitor and SUMO bridge in separate PowerShell windows...' -ForegroundColor Cyan
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\simulator\rsu_server.py')
Start-Sleep -Seconds 2
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\simulator\forwarding_monitor.py')
Start-Sleep -Seconds 1
Start-Process -FilePath powershell.exe -WorkingDirectory $ProjectRoot -ArgumentList @('-NoExit','-Command','py -3.11 .\simulator\sumo_bridge.py')
Write-Host ''
Write-Host 'Launched. Watch the three new windows:' -ForegroundColor Green
Write-Host '1) RSU: decrypt/authenticate, signature checks, IDS, response, geographic forwarding decisions.'
Write-Host '2) Forwarding monitor: accepted geographic forwarding packets.'
Write-Host '3) SUMO bridge: simulated vehicle states, signatures/encryption, UDP sends.'
Write-Host 'To stop: press Ctrl+C in each console window.'
