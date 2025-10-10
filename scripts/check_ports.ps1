# Script per verificare quali porte PKI sono in uso
# Controlla le porte standard usate dalle entita PKI
# Port Ranges: EA (5000-5019), AA (5020-5039), TLM (5040), RootCA (5999)

Write-Host "`n" -NoNewline
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "  VERIFICA PORTE PKI" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan
Write-Host ""

# Porte standard PKI - Range completi
$ea_ports = 5000..5019      # 20 porte per EA
$aa_ports = 5020..5039      # 20 porte per AA
$tlm_ports = @(5040)        # 1 porta per TLM
$rootca_ports = @(5999)     # 1 porta per RootCA

$all_ports = $rootca_ports + $ea_ports + $aa_ports + $tlm_ports

Write-Host "Scansione porte PKI..." -ForegroundColor Cyan
Write-Host "  - RootCA: 5999" -ForegroundColor Gray
Write-Host "  - EA: 5000-5019 (20 istanze)" -ForegroundColor Gray
Write-Host "  - AA: 5020-5039 (20 istanze)" -ForegroundColor Gray
Write-Host "  - TLM: 5040 (1 istanza)" -ForegroundColor Gray
Write-Host ""

$in_use_count = 0
$available_count = 0

foreach ($port in $all_ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    
    if ($connections) {
        $in_use_count++
        $process = Get-Process -Id $connections[0].OwningProcess -ErrorAction SilentlyContinue
        
        # Determina tipo entità dalla porta
        $entity_type = if ($port -eq 5999) { "RootCA" }
                      elseif ($port -ge 5000 -and $port -le 5019) { "EA" }
                      elseif ($port -ge 5020 -and $port -le 5039) { "AA" }
                      elseif ($port -eq 5040) { "TLM" }
                      else { "Unknown" }
        
        Write-Host "  [X] Porta $port " -NoNewline -ForegroundColor Red
        Write-Host "($entity_type) " -NoNewline -ForegroundColor Yellow
        Write-Host "IN USO" -NoNewline -ForegroundColor Red
        
        if ($process) {
            Write-Host " - Processo: $($process.ProcessName) (PID: $($process.Id))" -ForegroundColor Gray
        } else {
            Write-Host "" -ForegroundColor Gray
        }
    } else {
        $available_count++
        # Non mostrare le porte disponibili per non riempire lo schermo (41 porte totali)
        # Mostra solo un messaggio riepilogativo alla fine
    }
}

Write-Host ""
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "  RIEPILOGO" -ForegroundColor Yellow
Write-Host "="*70 -ForegroundColor Cyan
Write-Host "  Porte totali:      $($all_ports.Count)" -ForegroundColor Cyan
Write-Host "  Porte in uso:      $in_use_count" -ForegroundColor $(if ($in_use_count -gt 0) { "Red" } else { "Green" })
Write-Host "  Porte disponibili: $available_count" -ForegroundColor Green
Write-Host "="*70 -ForegroundColor Cyan
Write-Host ""

# Mostra processi Python attivi
$python_processes = Get-Process python* -ErrorAction SilentlyContinue

if ($python_processes) {
    Write-Host "Processi Python attivi:" -ForegroundColor Yellow
    foreach ($proc in $python_processes) {
        Write-Host "   PID $($proc.Id): $($proc.Path)" -ForegroundColor Gray
    }
    Write-Host ""
}

# Suggerimenti
if ($in_use_count -gt 0) {
    Write-Host "SUGGERIMENTI:" -ForegroundColor Cyan
    Write-Host "   - Per fermare tutti i processi Python:" -ForegroundColor White
    Write-Host "     Get-Process python* | Stop-Process -Force" -ForegroundColor Gray
    Write-Host ""
    Write-Host "   - Per verificare quale processo usa una porta specifica (es. 5000):" -ForegroundColor White
    Write-Host "     netstat -ano | findstr :5000" -ForegroundColor Gray
    Write-Host ""
}
