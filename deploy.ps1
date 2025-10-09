# SecureRoad PKI - Production Deployment Checklist
# PowerShell script - Simplified version
# Author: SecureRoad PKI Project

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("EA", "AA", "TLM", "RootCA")]
    [string]$Entity,
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateConfig,
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "config.json"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SecureRoad PKI - Production Deployment Checklist" -ForegroundColor Cyan
Write-Host "  ETSI TS 102941 Compliant" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$PassedChecks = 0
$FailedChecks = 0
$Warnings = 0

function Test-Check {
    param(
        [string]$Description,
        [scriptblock]$Test,
        [bool]$Critical = $true
    )
    
    Write-Host -NoNewline "Checking: $Description... "
    
    try {
        $result = Invoke-Command -ScriptBlock $Test
        if ($result) {
            Write-Host "PASS" -ForegroundColor Green
            $script:PassedChecks++
            return $true
        } else {
            if ($Critical) {
                Write-Host "FAIL" -ForegroundColor Red
                $script:FailedChecks++
            } else {
                Write-Host "WARNING" -ForegroundColor Yellow
                $script:Warnings++
            }
            return $false
        }
    } catch {
        Write-Host "ERROR: $_" -ForegroundColor Red
        if ($Critical) {
            $script:FailedChecks++
        } else {
            $script:Warnings++
        }
        return $false
    }
}

# Generate Config
if ($GenerateConfig) {
    Write-Host "Generating production config template..." -ForegroundColor Cyan
    Write-Host ""
    
    # Generate secure random string for API key
    $apiKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 43 | ForEach-Object {[char]$_})
    
    $configTemplate = @{
        environment = "production"
        host = "0.0.0.0"
        port = 5000
        debug = $false
        api_keys = @($apiKey)
        cors_origins = @("https://your-domain.com", "https://admin.your-domain.com")
        rate_limit_per_second = 100
        rate_limit_burst = 500
        log_level = "INFO"
        tls_enabled = $true
        tls_cert = "certs/server_cert.pem"
        tls_key = "certs/server_key.pem"
        secret_key = [guid]::NewGuid().ToString()
    }
    
    $configTemplate | ConvertTo-Json -Depth 10 | Out-File -FilePath "config.production.json" -Encoding UTF8
    
    Write-Host "Generated: config.production.json" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT:" -ForegroundColor Yellow
    Write-Host "1. Review and customize config.production.json"
    Write-Host "2. Generate TLS certificates"
    Write-Host "3. Update cors_origins with your actual domains"
    Write-Host "4. NEVER commit this file to git!"
    Write-Host ""
    exit 0
}

# ============================================================================
# PHASE 1: ENVIRONMENT CHECKS
# ============================================================================

Write-Host "PHASE 1: Environment Checks" -ForegroundColor Yellow
Write-Host ""

Test-Check "Python 3.8+ installed" {
    try {
        $versionOutput = python --version 2>&1
        $versionString = $versionOutput.ToString()
        return $versionString -like "Python 3.*"
    } catch {
        return $false
    }
}

Test-Check "Virtual environment activated" {
    return $null -ne $env:VIRTUAL_ENV
}

Test-Check "Dependencies installed" {
    try {
        $result = pip list 2>&1 | Select-String "cryptography"
        return $null -ne $result
    } catch {
        return $false
    }
}

Test-Check "Flask installed" {
    try {
        $result = pip list 2>&1 | Select-String "Flask"
        return $null -ne $result
    } catch {
        return $false
    }
}

# ============================================================================
# PHASE 2: SECURITY CHECKS
# ============================================================================

Write-Host ""
Write-Host "PHASE 2: Security Checks" -ForegroundColor Yellow
Write-Host ""

$configExists = Test-Check "Configuration file exists" {
    return Test-Path $ConfigPath
} -Critical $false

if ($configExists) {
    try {
        $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        
        Test-Check "API keys configured" {
            return ($null -ne $config.api_keys) -and ($config.api_keys.Count -gt 0)
        }
        
        Test-Check "API keys are strong (>= 32 chars)" {
            foreach ($key in $config.api_keys) {
                if ($key.Length -lt 32) {
                    return $false
                }
            }
            return $true
        }
        
        Test-Check "TLS enabled" {
            return $config.tls_enabled -eq $true
        }
        
        Test-Check "CORS origins restricted" {
            return ($config.cors_origins -ne "*")
        } -Critical $false
        
    } catch {
        Write-Host "Warning: Could not parse config file" -ForegroundColor Yellow
        $script:Warnings++
    }
}

Test-Check ".gitignore configured" {
    if (Test-Path ".gitignore") {
        $gitignore = Get-Content ".gitignore" -Raw
        return ($gitignore -like "*config.json*")
    }
    return $false
}

# ============================================================================
# PHASE 3: CODE QUALITY CHECKS
# ============================================================================

Write-Host ""
Write-Host "PHASE 3: Code Quality Checks" -ForegroundColor Yellow
Write-Host ""

Test-Check "All tests pass" {
    try {
        $output = python -m pytest tests/ -v --tb=no -q 2>&1
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

Test-Check "No hardcoded secrets in examples/" {
    if (Test-Path "examples/") {
        $files = Get-ChildItem -Path "examples/" -Filter "*.py" -Recurse
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -Raw
            if ($content -like '*API_KEY = "*' -and $content -notlike '*os.getenv*') {
                Write-Host "  Found in: $($file.Name)" -ForegroundColor Yellow
                return $false
            }
        }
    }
    return $true
}

# ============================================================================
# PHASE 4: ENTITY-SPECIFIC CHECKS
# ============================================================================

if ($Entity) {
    Write-Host ""
    Write-Host "PHASE 4: Entity Checks ($Entity)" -ForegroundColor Yellow
    Write-Host ""
    
    $dataPath = "data\$($Entity.ToLower())"
    
    Test-Check "Entity data directory exists" {
        return Test-Path $dataPath
    } -Critical $false
}

# ============================================================================
# PHASE 5: RUNTIME CHECKS
# ============================================================================

Write-Host ""
Write-Host "PHASE 5: Runtime Checks" -ForegroundColor Yellow
Write-Host ""

Test-Check "Sufficient disk space (>1GB)" {
    $drive = Get-PSDrive -Name C
    return $drive.Free -gt 1GB
}

Test-Check "Write permissions in data/ directory" {
    try {
        $testFile = "data\.write_test.tmp"
        New-Item -Path $testFile -ItemType File -Force | Out-Null
        Remove-Item $testFile -Force
        return $true
    } catch {
        return $false
    }
}

# ============================================================================
# SUMMARY
# ============================================================================

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Passed:   $PassedChecks" -ForegroundColor Green
Write-Host "Failed:   $FailedChecks" -ForegroundColor Red
Write-Host "Warnings: $Warnings" -ForegroundColor Yellow
Write-Host ""

if ($FailedChecks -eq 0) {
    Write-Host "ALL CRITICAL CHECKS PASSED!" -ForegroundColor Green
    Write-Host ""
    
    if ($Warnings -gt 0) {
        Write-Host "Some warnings detected. Review before production." -ForegroundColor Yellow
        Write-Host ""
    }
    
    if (-not $CheckOnly) {
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Generate secure API key:"
        Write-Host "   python start_production_server.py --generate-key"
        Write-Host ""
        Write-Host "2. Create config:"
        Write-Host "   .\deploy.ps1 -GenerateConfig"
        Write-Host ""
        Write-Host "3. Start server:"
        Write-Host "   python start_production_server.py --entity EA --config config.json"
        Write-Host ""
    }
    
    exit 0
} else {
    Write-Host "DEPLOYMENT BLOCKED - Fix issues above!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Quick Fixes:" -ForegroundColor Cyan
    Write-Host "- Generate API key:     python start_production_server.py --generate-key"
    Write-Host "- Install dependencies: pip install -r requirements.txt"
    Write-Host "- Run tests:            python -m pytest tests/ -v"
    Write-Host "- Create config:        .\deploy.ps1 -GenerateConfig"
    Write-Host ""
    
    exit 1
}
