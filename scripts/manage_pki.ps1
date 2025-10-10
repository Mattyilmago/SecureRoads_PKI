# PKI Process Manager
# Script per gestire le entità PKI avviate come processi in background

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("status", "stop", "logs", "restart")]
    [string]$Action = "status",
    
    [Parameter(Mandatory=$false)]
    [string]$EntityName
)

function Show-Status {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  PKI Entities Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $pythonProcesses = Get-Process python* -ErrorAction SilentlyContinue
    
    if (-not $pythonProcesses) {
        Write-Host "No PKI entities running" -ForegroundColor Yellow
        return
    }
    
    # Leggi le porte in uso per identificare le entità
    $portMap = @{
        5999 = "RootCA"
        5000 = "EA_001"
        5001 = "EA_002"
        5002 = "EA_003"
        5003 = "AA_001"
        5004 = "AA_002"
        5005 = "TLM_MAIN"
    }
    
    foreach ($proc in $pythonProcesses) {
        # Trova quale porta sta usando questo processo
        $connections = Get-NetTCPConnection -OwningProcess $proc.Id -State Listen -ErrorAction SilentlyContinue
        
        if ($connections) {
            foreach ($conn in $connections) {
                $port = $conn.LocalPort
                if ($portMap.ContainsKey($port)) {
                    $entityName = $portMap[$port]
                    Write-Host "  [Running] " -NoNewline -ForegroundColor Green
                    Write-Host "$entityName (PID: $($proc.Id), Port: $port)"
                }
            }
        } else {
            Write-Host "  [Unknown] " -NoNewline -ForegroundColor Yellow
            Write-Host "Python process (PID: $($proc.Id))"
        }
    }
    Write-Host ""
}

function Stop-Entities {
    param([string]$Name)
    
    if ($Name) {
        # Mappa nome entità -> porta
        $portMap = @{
            "RootCA" = 5999
            "EA_001" = 5000
            "EA_002" = 5001
            "EA_003" = 5002
            "AA_001" = 5003
            "AA_002" = 5004
            "TLM_MAIN" = 5005
        }
        
        $port = $portMap[$Name]
        if (-not $port) {
            Write-Host "Unknown entity: $Name" -ForegroundColor Red
            return
        }
        
        Write-Host "Stopping $Name (port $port)..." -NoNewline
        
        # Trova il processo che usa questa porta
        $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        if ($conn) {
            Stop-Process -Id $conn.OwningProcess -Force
            Write-Host " ✅" -ForegroundColor Green
        } else {
            Write-Host " ❌ Not found" -ForegroundColor Red
        }
    } else {
        Write-Host "Stopping all PKI entities..." -ForegroundColor Yellow
        $pythonProcesses = Get-Process python* -ErrorAction SilentlyContinue
        
        if (-not $pythonProcesses) {
            Write-Host "No entities running" -ForegroundColor Yellow
            return
        }
        
        foreach ($proc in $pythonProcesses) {
            Write-Host "  Stopping PID $($proc.Id)..." -NoNewline
            Stop-Process -Id $proc.Id -Force
            Write-Host " ✅" -ForegroundColor Green
        }
        Write-Host "All entities stopped" -ForegroundColor Green
    }
}

function Show-Logs {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Host "Please specify entity name with -EntityName parameter" -ForegroundColor Yellow
        Write-Host "Available: RootCA, EA_001, EA_002, EA_003, AA_001, AA_002, TLM_MAIN" -ForegroundColor Gray
        return
    }
    
    $logFile = "$Name.log"
    
    if (-not (Test-Path $logFile)) {
        Write-Host "Log file not found: $logFile" -ForegroundColor Red
        return
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Logs: $Name" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    Get-Content $logFile -Tail 50
}

function Restart-Entity {
    param([string]$Name)
    
    if (-not $Name) {
        Write-Host "Please specify entity name with -EntityName parameter" -ForegroundColor Yellow
        return
    }
    
    Write-Host "Restarting $Name..." -ForegroundColor Yellow
    
    # Stop existing
    Stop-Entities -Name $Name
    Start-Sleep -Seconds 1
    
    # Determine entity info
    $entityInfo = switch ($Name) {
        "RootCA" { @{Type="RootCA"; Id="RootCA"; Port=5999} }
        "EA_001" { @{Type="EA"; Id="EA_001"; Port=5000} }
        "EA_002" { @{Type="EA"; Id="EA_002"; Port=5001} }
        "EA_003" { @{Type="EA"; Id="EA_003"; Port=5002} }
        "AA_001" { @{Type="AA"; Id="AA_001"; Port=5003} }
        "AA_002" { @{Type="AA"; Id="AA_002"; Port=5004} }
        "TLM_MAIN" { @{Type="TLM"; Id="TLM_MAIN"; Port=5005} }
        default { $null }
    }
    
    if (-not $entityInfo) {
        Write-Host "Unknown entity: $Name" -ForegroundColor Red
        return
    }
    
    # Restart
    $process = Start-Process -FilePath "python" `
        -ArgumentList "server.py --entity $($entityInfo.Type) --id $($entityInfo.Id) --port $($entityInfo.Port)" `
        -NoNewWindow `
        -PassThru
    
    Write-Host "✅ $Name restarted (PID: $($process.Id))" -ForegroundColor Green
}

# Main execution
switch ($Action) {
    "status" { Show-Status }
    "stop" { Stop-Entities -Name $EntityName }
    "logs" { Show-Logs -Name $EntityName }
    "restart" { Restart-Entity -Name $EntityName }
}
