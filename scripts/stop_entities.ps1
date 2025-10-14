# ============================================
# STOP ALL PKI ENTITIES
# ============================================
# Stops all running pythonw.exe and python.exe processes (PKI entities)
# Usage: .\scripts\stop_all_entities.ps1 [-Force]
#   -Force : Stop without confirmation

param(
    [switch]$Force
)

Write-Host ""
Write-Host "STOPPING ALL PKI ENTITIES" -ForegroundColor Red
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""

# Check if PID file exists
if (Test-Path "running_entities_pids.txt") {
    Write-Host "Reading PIDs from: running_entities_pids.txt" -ForegroundColor Cyan
    Write-Host ""
    Get-Content "running_entities_pids.txt" | Where-Object { $_ -notmatch "^#" -and $_ -ne "" }
    Write-Host ""
}

# Get all pythonw and python processes
$pythonwProcesses = Get-Process pythonw* -ErrorAction SilentlyContinue
$pythonProcesses = Get-Process python -ErrorAction SilentlyContinue

# Combine all processes
$allProcesses = @()
if ($pythonwProcesses) { $allProcesses += $pythonwProcesses }
if ($pythonProcesses) { $allProcesses += $pythonProcesses }

$processes = $allProcesses

if ($processes) {
    Write-Host "Found $($processes.Count) Python processes:" -ForegroundColor Yellow
    $processes | Format-Table Id, ProcessName, @{Label="Memory (MB)"; Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}}, StartTime -AutoSize
    Write-Host ""
    
    # Confirm before stopping (unless -Force is used)
    $confirmed = $Force
    if (-not $Force) {
        $confirm = Read-Host "Stop all these processes? (Y/N)"
        $confirmed = ($confirm -eq "Y" -or $confirm -eq "y")
    } else {
        Write-Host "Force mode: stopping without confirmation..." -ForegroundColor Yellow
        $confirmed = $true
    }
    
    if ($confirmed) {
        Write-Host ""
        Write-Host "Stopping processes..." -ForegroundColor Yellow
        $processes | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        # Also check and kill processes on PKI ports (parallel processing)
        Write-Host "Checking PKI ports in parallel..." -ForegroundColor Cyan
        # EA: 5000-5019 (20 ports), AA: 5020-5039 (20 ports), TLM: 5050, RootCA: 5999
        # Note: Dashboard port 8080 is NOT stopped by this script
        
        # Dividi le porte in gruppi per parallelizzare (same method as stop_all.ps1)
        $portGroups = @(
            @(5000..5019),  # Gruppo EA (20 ports)
            @(5020..5039),  # Gruppo AA (20 ports)
            @(5050, 5999)   # Gruppo TLM e RootCA (escludendo dashboard 8080)
        )
        
        # Avvia job per ogni gruppo di porte
        $jobs = @()
        foreach ($group in $portGroups) {
            $job = Start-Job -ScriptBlock {
                param($portsInGroup)
                $messages = @()
                foreach ($port in $portsInGroup) {
                    $conn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
                    if ($conn) {
                        $processId = $conn.OwningProcess
                        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                        $messages += "Killed process on port $port"
                    }
                }
                $messages
            } -ArgumentList $group
            $jobs += $job
        }
        
        # Aspetta che tutti i job finiscano
        $jobs | Wait-Job
        
        # Raccogli output dai job e mostra messaggi
        foreach ($job in $jobs) {
            $outputs = Receive-Job $job
            foreach ($output in $outputs) {
                Write-Host "  $output" -ForegroundColor Yellow
            }
            Remove-Job $job
        }
        
        # Verify
        $remainingPythonw = Get-Process pythonw* -ErrorAction SilentlyContinue
        $remainingPython = Get-Process python -ErrorAction SilentlyContinue
        $remaining = @()
        if ($remainingPythonw) { $remaining += $remainingPythonw }
        if ($remainingPython) { $remaining += $remainingPython }
        
        if ($remaining) {
            Write-Host ""
            Write-Host "Some processes still running!" -ForegroundColor Red
            $remaining | Format-Table Id, ProcessName -AutoSize
        } else {
            Write-Host ""
            Write-Host "All processes stopped successfully!" -ForegroundColor Green
            
            # Clean up PID file
            if (Test-Path "running_entities_pids.txt") {
                Remove-Item "running_entities_pids.txt" -Force
                Write-Host "Removed running_entities_pids.txt" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "Cancelled" -ForegroundColor Gray
    }
} else {
    Write-Host "No Python processes found (nothing to stop)" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host ""
