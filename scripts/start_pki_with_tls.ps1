# Start All PKI Entities with TLS/mTLS (ETSI Compliant)
# =======================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Starting PKI Infrastructure with TLS" -ForegroundColor Cyan
Write-Host " ETSI TS 102941 Compliant" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Array per tracciare i processi
$processes = @()

# Entities da avviare
# NOTA: Le porte sono auto-assegnate, i config file possono sovrascriverle
$entities = @(
    @{Type="RootCA"; Id="RootCA"; Config="configs/root_ca_config.json"},
    @{Type="EA"; Id="EA_001"; Config="configs/ea_001_config.json"},
    @{Type="EA"; Id="EA_002"; Config="configs/ea_002_config.json"},
    @{Type="EA"; Id="EA_003"; Config="configs/ea_003_config.json"},
    @{Type="AA"; Id="AA_001"; Config="configs/aa_001_config.json"},
    @{Type="AA"; Id="AA_002"; Config="configs/aa_002_config.json"},
    @{Type="TLM"; Id="TLM_MAIN"; Config="configs/tlm_main_config.json"}
)

# Avvia ogni entity come processo (senza finestra)
foreach ($entity in $entities) {
    $entityType = $entity.Type
    $entityId = $entity.Id
    $configPath = $entity.Config
    
    Write-Host "Starting $entityId with TLS (auto port)..." -NoNewline
    
    try {
        # Le porte sono auto-assegnate o lette dal config file
        $process = Start-Process -FilePath "python" `
            -ArgumentList "server.py --entity $entityType --id $entityId --config $configPath" `
            -NoNewWindow `
            -PassThru
        
        $processes += $process
        Write-Host " ✅ (PID: $($process.Id))" -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }
    catch {
        Write-Host " ❌ $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n🔒 All entities started with TLS/mTLS enabled"
Write-Host "📜 Certificate Authority: certs/tls_ca_cert.pem"
Write-Host "🔐 Client certificates required for connections"
Write-Host ""
Write-Host "Port Assignments (auto-assigned from ranges):" -ForegroundColor Yellow
Write-Host "  RootCA: 5999"
Write-Host "  EA_001, EA_002, EA_003: 5000-5019 range"
Write-Host "  AA_001, AA_002: 5020-5039 range"
Write-Host "  TLM_MAIN: 5050"
Write-Host ""
Write-Host "Check actual port assignments with: .\scripts\check_ports.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "Client certificate for testing: certs/clients/test_client_cert.pem"
Write-Host "Client private key: certs/clients/test_client_key.pem"
Write-Host ""
Write-Host "Commands:" -ForegroundColor Yellow
Write-Host "  Get-Process python*                    # Check status"
Write-Host "  Stop-Process -Id <PID>                 # Stop specific entity"
Write-Host "  Get-Process python* | Stop-Process     # Stop all entities"
Write-Host ""
Write-Host "💡 Tip: Open pki_dashboard.html to monitor entities"
Write-Host ""
