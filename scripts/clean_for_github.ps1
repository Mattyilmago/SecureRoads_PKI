# ====================================================================
# SecureRoad PKI - GitHub Cleanup Script
# Rimuove file non necessari prima del push
# ====================================================================

param(
    [switch]$DryRun,
    [switch]$Aggressive
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SecureRoad PKI - GitHub Cleanup" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "MODE: DRY-RUN - Nessun file verra eliminato" -ForegroundColor Yellow
    Write-Host ""
}

$FilesRemoved = 0
$SpaceFreed = 0

function Remove-ItemSafe {
    param([string]$Path, [string]$Description)
    
    if (Test-Path $Path) {
        $size = 0
        try {
            $item = Get-Item $Path -ErrorAction SilentlyContinue
            if ($item -is [System.IO.DirectoryInfo]) {
                $size = (Get-ChildItem $Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
            } else {
                $size = $item.Length
            }
        } catch {}
        
        if ($null -eq $size) { $size = 0 }
        $sizeMB = [math]::Round($size / 1MB, 2)
        
        if ($DryRun) {
            Write-Host "  [DRY-RUN] Eliminerei: $Description ($sizeMB MB)" -ForegroundColor Yellow
        } else {
            Write-Host "  Elimino: $Description ($sizeMB MB)" -ForegroundColor Red
            Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue
            $script:FilesRemoved++
            $script:SpaceFreed += $size
        }
    }
}

# ====================================================================
# 1. CACHE E FILE TEMPORANEI
# ====================================================================
Write-Host "1. Pulizia cache e file temporanei..." -ForegroundColor Cyan

# __pycache__
$pycacheDirs = Get-ChildItem -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue
Write-Host "  Trovate $($pycacheDirs.Count) cartelle __pycache__" -ForegroundColor Gray
foreach ($dir in $pycacheDirs) {
    Remove-ItemSafe -Path $dir.FullName -Description "__pycache__"
}

# File .pyc .pyo
$compiledFiles = Get-ChildItem -Path . -Include "*.pyc","*.pyo" -Recurse -ErrorAction SilentlyContinue
Write-Host "  Trovati $($compiledFiles.Count) file compilati Python" -ForegroundColor Gray
foreach ($file in $compiledFiles) {
    Remove-ItemSafe -Path $file.FullName -Description $file.Name
}

# File temporanei
$tempFiles = Get-ChildItem -Recurse -Include "*.log","*.tmp","*.bak" -ErrorAction SilentlyContinue
Write-Host "  Trovati $($tempFiles.Count) file temporanei" -ForegroundColor Gray
foreach ($file in $tempFiles) {
    Remove-ItemSafe -Path $file.FullName -Description $file.Name
}

# .pytest_cache
Remove-ItemSafe -Path ".\.pytest_cache\" -Description ".pytest_cache"
Write-Host ""

# ====================================================================
# 2. VIRTUAL ENVIRONMENT
# ====================================================================
Write-Host "2. Virtual Environment..." -ForegroundColor Cyan
Remove-ItemSafe -Path ".\.venv\" -Description "Virtual environment"
Write-Host ""

# ====================================================================
# 3. DATI GENERATI
# ====================================================================
Write-Host "3. Dati generati durante i test..." -ForegroundColor Cyan
Remove-ItemSafe -Path ".\data\" -Description "Dati PKI generati"
Remove-ItemSafe -Path ".\results\" -Description "Risultati test"
Write-Host ""

# ====================================================================
# 4. CERTIFICATI E CHIAVI
# ====================================================================
Write-Host "4. Certificati e chiavi private..." -ForegroundColor Cyan
Remove-ItemSafe -Path ".\certs\" -Description "Certificati TLS"
Write-Host ""

# ====================================================================
# 5. SCRIPT RIDONDANTI
# ====================================================================
Write-Host "5. Script PowerShell ridondanti..." -ForegroundColor Cyan
Remove-ItemSafe -Path ".\start_all_entities.bat" -Description "start_all_entities.bat"
Remove-ItemSafe -Path ".\run_pki_test.ps1" -Description "run_pki_test.ps1"
Remove-ItemSafe -Path ".\deployment_checklist.ps1" -Description "deployment_checklist.ps1"
Write-Host ""

# ====================================================================
# 6. ESEMPI RIDONDANTI
# ====================================================================
Write-Host "6. File examples ridondanti..." -ForegroundColor Cyan
Remove-ItemSafe -Path ".\examples\create_sample_pki.py" -Description "create_sample_pki.py"
Remove-ItemSafe -Path ".\examples\generate_enrollment_request.py" -Description "generate_enrollment_request.py"
Remove-ItemSafe -Path ".\examples\monitoring_demo.py" -Description "monitoring_demo.py"
Remove-ItemSafe -Path ".\examples\start_api_with_swagger.py" -Description "start_api_with_swagger.py"
Write-Host ""

# ====================================================================
# 7. DOCUMENTAZIONE OPZIONALE
# ====================================================================
if ($Aggressive) {
    Write-Host "7. Documentazione opzionale..." -ForegroundColor Cyan
    Remove-ItemSafe -Path ".\docs\CODE_EVALUATION.md" -Description "CODE_EVALUATION.md"
    Remove-ItemSafe -Path ".\docs\SLIDE_TEMPLATE.md" -Description "SLIDE_TEMPLATE.md"
    Remove-ItemSafe -Path ".\docs\TEST_SUMMARY.md" -Description "TEST_SUMMARY.md"
    Remove-ItemSafe -Path ".\docs\INDEX.md" -Description "INDEX.md"
    Write-Host ""
}

# ====================================================================
# RIEPILOGO
# ====================================================================
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "  RIEPILOGO PULIZIA" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Green

if ($DryRun) {
    Write-Host "  Modalita: DRY-RUN" -ForegroundColor Yellow
} else {
    Write-Host "  File/cartelle rimosse: $FilesRemoved" -ForegroundColor Green
    Write-Host "  Spazio liberato: $([math]::Round($SpaceFreed / 1MB, 2)) MB" -ForegroundColor Green
}

Write-Host ""
Write-Host "Dimensione finale progetto:" -ForegroundColor Cyan
$finalSize = (Get-ChildItem -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
Write-Host "  $([math]::Round($finalSize / 1MB, 2)) MB" -ForegroundColor White
Write-Host ""

Write-Host "File importanti mantenuti:" -ForegroundColor Green
Write-Host "  - Codice sorgente" -ForegroundColor Gray
Write-Host "  - Test suite" -ForegroundColor Gray
Write-Host "  - Script test Raspberry Pi" -ForegroundColor Gray
Write-Host "  - Documentazione principale" -ForegroundColor Gray
Write-Host "  - Configurazioni template" -ForegroundColor Gray
Write-Host "  - Script utili" -ForegroundColor Gray
Write-Host "  - pki_dashboard.html" -ForegroundColor Gray
Write-Host ""

if (-not $DryRun) {
    Write-Host "Prossimi passi per GitHub:" -ForegroundColor Yellow
    Write-Host "  1. git status" -ForegroundColor Gray
    Write-Host "  2. git add ." -ForegroundColor Gray
    Write-Host "  3. git commit -m 'message'" -ForegroundColor Gray
    Write-Host "  4. git push origin main" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Pulizia completata!" -ForegroundColor Green
Write-Host ""
