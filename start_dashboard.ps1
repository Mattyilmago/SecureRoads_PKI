# Script per avviare il server HTTP della dashboard PKI
# Avvia automaticamente RootCA, TLM e il server HTTP sulla porta 8080

param(
    [switch]$SkipEntities  # Skip RootCA e TLM se già avviati
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PKI Dashboard Startup" -ForegroundColor Cyan
Write-Host "  Dashboard + RootCA + TLM" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verifica se la porta 8080 e' gia' in uso
$portInUse = netstat -ano | Select-String ":8080" | Select-String "LISTENING"
if ($portInUse) {
    Write-Host "ATTENZIONE: Porta 8080 gia' in uso!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Processi sulla porta 8080:" -ForegroundColor Cyan
    $portInUse | ForEach-Object {
        $line = $_.Line
        if ($line -match '\s+(\d+)\s*$') {
            $processId = $matches[1]
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                Write-Host "  PID $processId - $($process.ProcessName)" -ForegroundColor White
            }
        }
    }
    Write-Host ""
    $response = Read-Host "Vuoi terminare questi processi e riavviare? (s/n)"
    if ($response -eq 's' -or $response -eq 'S') {
        $portInUse | ForEach-Object {
            $line = $_.Line
            if ($line -match '\s+(\d+)\s*$') {
                $processId = $matches[1]
                Write-Host "Stopping PID $processId..." -ForegroundColor Yellow
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
        Start-Sleep -Seconds 2
        Write-Host "[OK] Processi terminati" -ForegroundColor Green
    } else {
        Write-Host "[STOP] Uscita" -ForegroundColor Red
        exit
    }
}

# ============================================
# AVVIO ROOTCA E TLM
# ============================================

if (-not $SkipEntities) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Avvio RootCA e TLM" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    # Directory root del progetto
    $projectRoot = $PSScriptRoot
    
    # Avvia RootCA (porta 5999) usando Start-Job per tenerlo in background
    Write-Host "[1/2] Avvio RootCA sulla porta 5999..." -ForegroundColor Cyan
    
    $rootcaJob = Start-Job -ScriptBlock {
        param($workDir)
        Set-Location $workDir
        python server.py --entity RootCA --port 5999
    } -ArgumentList $projectRoot
    
    if ($rootcaJob) {
        Write-Host "      RootCA avviato (Job ID: $($rootcaJob.Id))" -ForegroundColor Green
    } else {
        Write-Host "      ERRORE: Impossibile avviare RootCA" -ForegroundColor Red
    }
    
    # Avvia TLM (porta 5050)
    Write-Host "[2/2] Avvio TLM sulla porta 5050..." -ForegroundColor Cyan
    
    $tlmJob = Start-Job -ScriptBlock {
        param($workDir)
        Set-Location $workDir
        python server.py --entity TLM --id TLM_MAIN --port 5050
    } -ArgumentList $projectRoot
    
    if ($tlmJob) {
        Write-Host "      TLM avviato (Job ID: $($tlmJob.Id))" -ForegroundColor Green
    } else {
        Write-Host "      ERRORE: Impossibile avviare TLM" -ForegroundColor Red
    }
    
    # Attesa avvio entities
    # Write-Host ""
    # Write-Host "Attesa avvio entities (10 secondi)..." -ForegroundColor Yellow
    # Start-Sleep -Seconds 10
    
    # Verifica che siano attivi
    Write-Host ""
    Write-Host "Verifica stato entities:" -ForegroundColor Cyan
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5999/health" -Method GET -TimeoutSec 3 -UseBasicParsing
        Write-Host "  RootCA (5999): OK" -ForegroundColor Green
    } catch {
        Write-Host "  RootCA (5999): NON RISPONDE" -ForegroundColor Red
        Write-Host "    Verifica logs\ROOT_CA.log per dettagli" -ForegroundColor Yellow
    }
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5050/health" -Method GET -TimeoutSec 3 -UseBasicParsing
        Write-Host "  TLM (5050): OK" -ForegroundColor Green
    } catch {
        Write-Host "  TLM (5050): NON RISPONDE" -ForegroundColor Red
        Write-Host "    Verifica logs\TLM_MAIN.log per dettagli" -ForegroundColor Yellow
    }
    
    Write-Host ""
} else {
    Write-Host "[INFO] Skip avvio entities (parametro -SkipEntities attivo)" -ForegroundColor Yellow
    Write-Host ""
}

# ============================================
# AVVIO DASHBOARD HTTP SERVER
# ============================================

# Verifica che pki_dashboard.html esista
$dashboardPath = Join-Path $PSScriptRoot "pki_dashboard.html"
if (-not (Test-Path $dashboardPath)) {
    Write-Host "[ERROR] File pki_dashboard.html non trovato!" -ForegroundColor Red
    Write-Host "   Percorso atteso: $dashboardPath" -ForegroundColor Yellow
    exit 1
}

Write-Host "[INFO] Directory root: $PSScriptRoot" -ForegroundColor Cyan
Write-Host "[INFO] Dashboard file: pki_dashboard.html" -ForegroundColor Cyan
Write-Host ""

Write-Host "[START] Avvio server HTTP sulla porta 8080..." -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  PKI Dashboard Attiva!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Dashboard:" -ForegroundColor Yellow
Write-Host "  http://localhost:8080/pki_dashboard.html" -ForegroundColor Cyan -BackgroundColor Black
Write-Host ""
if (-not $SkipEntities) {
    Write-Host "Entities attive:" -ForegroundColor Yellow
    Write-Host "  RootCA:  http://localhost:5999/health" -ForegroundColor Cyan
    Write-Host "  TLM:     http://localhost:5050/health" -ForegroundColor Cyan
    Write-Host ""
}
Write-Host "[INFO] Per fermare tutto: Ctrl+C e poi Get-Job | Stop-Job; Get-Job | Remove-Job" -ForegroundColor Gray
Write-Host "[INFO] Oppure premi Ctrl+C per fermare solo la dashboard" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# Avvia il server HTTP Python
try {
    python -m http.server 8080
} catch {
    Write-Host ""
    Write-Host "[ERROR] Errore durante l'avvio del server: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "[INFO] Verifica che Python sia installato e nel PATH" -ForegroundColor Yellow
    
    # Cleanup jobs on error
    if (-not $SkipEntities) {
        Get-Job | Stop-Job
        Get-Job | Remove-Job
    }
    exit 1
}

# Cleanup quando termina
if (-not $SkipEntities) {
    Write-Host ""
    Write-Host "[INFO] Cleanup jobs..." -ForegroundColor Yellow
    Get-Job | Stop-Job
    Get-Job | Remove-Job
}
