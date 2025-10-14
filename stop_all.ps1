# Stop all PKI entities and dashboard (FORCE MODE)
Write-Host ""
Write-Host "STOPPING ALL PKI ENTITIES (FORCE MODE)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Yellow

$pythonProcesses = Get-Process python* -ErrorAction SilentlyContinue
if ($pythonProcesses) {
    Write-Host "Stopping $($pythonProcesses.Count) Python processes..." -ForegroundColor Yellow
    $pythonProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "Python processes stopped" -ForegroundColor Green
}

Write-Host "Checking PKI ports..." -ForegroundColor Cyan
# EA ports: 5000-5019 (20 ports), AA ports: 5020-5039 (20 ports), TLM: 5050, RootCA: 5999, Dashboard: 8080
$ports = @()
$ports += 5000..5019  # EA range (20 ports)
$ports += 5020..5039  # AA range (20 ports)
$ports += 5050        # TLM
$ports += 5999        # RootCA
$ports += 8080        # Dashboard

# Dividi le porte in gruppi per parallelizzare
$portGroups = @(
    @(5000..5019),  # Gruppo EA
    @(5020..5039),  # Gruppo AA
    @(5050, 5999, 8080)  # Gruppo TLM, RootCA, Dashboard
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

Start-Sleep -Seconds 2
$remaining = Get-Process python* -ErrorAction SilentlyContinue
if (-not $remaining) {
    Write-Host ""
    Write-Host "All processes stopped successfully!" -ForegroundColor Green
}
