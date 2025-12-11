# Minimal-AD-Scanner.ps1
$ErrorActionPreference = 'SilentlyContinue'

# Load PowerView if available
if (-not (Get-Command Get-DomainUser -ErrorAction SilentlyContinue)) {
    if (Test-Path ".\PowerView.ps1") { Import-Module .\PowerView.ps1 -Force }
}

# Check AS-REP
Write-Host "`n[!] AS-REP Roastable Accounts:" -ForegroundColor Red
try {
    Get-DomainUser -PreauthNotRequired | Select-Object samaccountname, userprincipalname | ForEach-Object {
        Write-Host "  • $($_.samaccountname)" -ForegroundColor Red
    }
} catch { Write-Host "  [-] Error checking AS-REP" -ForegroundColor Yellow }

# Check Kerberoasting
Write-Host "`n[!] Kerberoastable Accounts:" -ForegroundColor Yellow
try {
    Get-DomainUser -SPN | Select-Object samaccountname, userprincipalname | ForEach-Object {
        Write-Host "  • $($_.samaccountname)" -ForegroundColor Yellow
    }
} catch { Write-Host "  [-] Error checking Kerberoasting" -ForegroundColor Yellow }

# Check Unconstrained Delegation
Write-Host "`n[!] Computers with Unconstrained Delegation:" -ForegroundColor Magenta
try {
    Get-DomainComputer -Unconstrained | Select-Object Name | ForEach-Object {
        Write-Host "  • $($_.Name)" -ForegroundColor Magenta
    }
} catch { Write-Host "  [-] Error checking delegation" -ForegroundColor Yellow }
