# Start All PKI Entities using PowerShell Jobs
# Avvia tutte le entità come background jobs

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PKI Startup (Jobs Mode)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Stop existing processes
Write-Host "[1] Arresto processi esistenti..." -ForegroundColor Yellow
Get-Process python* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Job | Stop-Job -ErrorAction SilentlyContinue
Get-Job | Remove-Job -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Host "  Done" -ForegroundColor Green
Write-Host ""

# Read configuration
$configPath = ".\entity_configs.json"
if (-not (Test-Path $configPath)) {
    Write-Host "[ERROR] File entity_configs.json non trovato!" -ForegroundColor Red
    exit 1
}

$config = Get-Content $configPath | ConvertFrom-Json

Write-Host "[2] Avvio entità..." -ForegroundColor Yellow
Write-Host ""

# Start RootCA
Write-Host "  [1/6] Avvio RootCA (5999)..." -NoNewline
Start-Job -Name "RootCA" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity RootCA --port 5999
} | Out-Null
Start-Sleep -Seconds 3
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5999/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

# Start TLM
Write-Host "  [2/6] Avvio TLM (5050)..." -NoNewline
Start-Job -Name "TLM" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity TLM --id TLM_MAIN --port 5050
} | Out-Null
Start-Sleep -Seconds 3
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5050/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

# Start EA_004
Write-Host "  [3/6] Avvio EA_004 (5000)..." -NoNewline
Start-Job -Name "EA_004" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity EA --id EA_004 --port 5000
} | Out-Null
Start-Sleep -Seconds 2
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

# Start EA_005
Write-Host "  [4/6] Avvio EA_005 (5001)..." -NoNewline
Start-Job -Name "EA_005" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity EA --id EA_005 --port 5001
} | Out-Null
Start-Sleep -Seconds 2
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5001/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

# Start AA_004
Write-Host "  [5/6] Avvio AA_004 (5021)..." -NoNewline
Start-Job -Name "AA_004" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity AA --id AA_004 --port 5021
} | Out-Null
Start-Sleep -Seconds 2
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5021/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

# Start AA_005
Write-Host "  [6/6] Avvio AA_005 (5022)..." -NoNewline
Start-Job -Name "AA_005" -ScriptBlock {
    Set-Location $using:PWD
    python server.py --entity AA --id AA_005 --port 5022
} | Out-Null
Start-Sleep -Seconds 2
try {
    $r = Invoke-WebRequest -Uri "http://localhost:5022/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
    Write-Host " OK" -ForegroundColor Green
} catch {
    Write-Host " STARTING..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Startup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Jobs attivi:" -ForegroundColor Green
Get-Job | Format-Table -Property Id, Name, State
Write-Host ""

Write-Host "Endpoints:" -ForegroundColor Yellow
Write-Host "  RootCA:  http://localhost:5999/health" -ForegroundColor White
Write-Host "  TLM:     http://localhost:5050/health" -ForegroundColor White
Write-Host "  EA_004:  http://localhost:5000/health" -ForegroundColor White
Write-Host "  EA_005:  http://localhost:5001/health" -ForegroundColor White
Write-Host "  AA_004:  http://localhost:5021/health" -ForegroundColor White
Write-Host "  AA_005:  http://localhost:5022/health" -ForegroundColor White
Write-Host ""

Write-Host "Dashboard:" -ForegroundColor Yellow
Write-Host "  http://localhost:8080/pki_dashboard.html" -ForegroundColor White
Write-Host ""

Write-Host "Comandi utili:" -ForegroundColor Cyan
Write-Host "  Get-Job | Receive-Job       # Vedi output" -ForegroundColor White
Write-Host "  .\stop_all.ps1              # Ferma tutto" -ForegroundColor White
Write-Host ""
