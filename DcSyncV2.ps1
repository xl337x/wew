# Self-Contained DCSync Hunter Tool
# Fixed version with proper function calls

function Get-CurrentUserDomain {
    try {
        return [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    } catch {
        try {
            return $env:USERDNSDOMAIN
        } catch {
            return $null
        }
    }
}

function Convert-SidToString {
    param([Byte[]]$SidBytes)
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SidBytes,0)
        return $sid.Value
    } catch { return $null }
}

function Get-DomainObjectAcl {
    param(
        [Parameter(Mandatory=$True)]
        [String]$DistinguishedName,
        [Switch]$ResolveGUIDs
    )
    
    $domain = Get-CurrentUserDomain
    if (-not $domain) {
        Write-Error "Not in a domain or cannot determine domain"
        return
    }
    
    try {
        $searchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
        $searcher.Filter = "(distinguishedName=$DistinguishedName)"
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        
        $result = $searcher.FindOne()
        if ($result) {
            $entry = $result.GetDirectoryEntry()
            $entry.RefreshCache("ntSecurityDescriptor")
            $acl = $entry.ObjectSecurity
            
            $output = @()
            foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                $obj = New-Object PSObject
                $obj | Add-Member NoteProperty "ObjectDN" $DistinguishedName
                $obj | Add-Member NoteProperty "ActiveDirectoryRights" $ace.ActiveDirectoryRights
                $obj | Add-Member NoteProperty "SecurityIdentifier" $ace.IdentityReference.Value
                
                # Check for ObjectAceType (DCSync rights)
                if ($ace.ObjectType -ne [Guid]::Empty) {
                    $obj | Add-Member NoteProperty "ObjectAceType" $ace.ObjectType.ToString()
                }
                
                if ($ace.InheritanceType -ne "None") {
                    $obj | Add-Member NoteProperty "InheritanceType" $ace.InheritanceType
                }
                
                $output += $obj
            }
            return $output
        }
    } catch {
        Write-Warning "Error accessing $DistinguishedName : $_"
    }
    return @()
}

function Get-DomainUser {
    param([String]$Identity)
    
    $domain = Get-CurrentUserDomain
    if (-not $domain) {
        Write-Error "Not in a domain or cannot determine domain"
        return
    }
    
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domain")
    
    if ($Identity) {
        $searcher.Filter = "(&(objectClass=user)(samaccountname=$Identity))"
    } else {
        $searcher.Filter = "(objectClass=user)"
    }
    
    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "objectsid", "memberof", "useraccountcontrol"))
    
    try {
        $result = $searcher.FindOne()
        if ($result) {
            $output = New-Object PSObject
            $output | Add-Member NoteProperty "samaccountname" $result.Properties["samaccountname"][0]
            
            # Convert SID
            if ($result.Properties["objectsid"]) {
                $sidString = Convert-SidToString $result.Properties["objectsid"][0]
                $output | Add-Member NoteProperty "objectsid" $sidString
            }
            
            # Get group membership
            if ($result.Properties["memberof"]) {
                $output | Add-Member NoteProperty "memberof" @($result.Properties["memberof"])
            }
            
            # User account control flags
            if ($result.Properties["useraccountcontrol"]) {
                $uac = $result.Properties["useraccountcontrol"][0]
                $flags = @()
                if ($uac -band 0x0002) { $flags += "ACCOUNTDISABLE" }
                if ($uac -band 0x0020) { $flags += "PASSWD_NOTREQD" }
                if ($uac -band 0x0200) { $flags += "NORMAL_ACCOUNT" }
                if ($uac -band 0x10000) { $flags += "DONT_EXPIRE_PASSWORD" }
                if ($uac -band 0x20000) { $flags += "SMARTCARD_REQUIRED" }
                if ($uac -band 0x1000000) { $flags += "PARTIAL_SECRETS_ACCOUNT" }
                $output | Add-Member NoteProperty "useraccountcontrol" ($flags -join ", ")
            }
            
            return $output
        }
    } catch {
        Write-Error "Error finding user: $_"
    }
}

function Get-DomainDN {
    $domain = Get-CurrentUserDomain
    if (-not $domain) { return $null }
    
    $parts = $domain.Split('.')
    $dn = "DC=" + ($parts -join ",DC=")
    return $dn
}

function Find-DCSyncUsers {
    <#
    .SYNOPSIS
    Automatically finds all users with DCSync rights in the current domain.
    #>
    
    Write-Host "[*] Hunting for DCSync Users" -ForegroundColor Yellow
    Write-Host "[*] Domain: $(Get-CurrentUserDomain)" -ForegroundColor Cyan
    
    $domainDN = Get-DomainDN
    if (-not $domainDN) {
        Write-Error "Could not determine domain DN"
        return
    }
    
    Write-Host "[*] Domain DN: $domainDN" -ForegroundColor Cyan
    
    # DCSync GUIDs
    $DCSyncGUIDs = @{
        "DS-Replication-Get-Changes" = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-All" = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-In-Filtered-Set" = "89e95b76-444d-4c62-991a-0facbeda640c"
    }
    
    # Get ACLs for the domain
    Write-Host "[*] Retrieving domain ACLs..." -ForegroundColor Gray
    $acls = Get-DomainObjectAcl -DistinguishedName $domainDN
    
    $dcsyncUsers = @{}
    
    foreach ($acl in $acls) {
        if ($acl.ObjectAceType) {
            foreach ($guidName in $DCSyncGUIDs.Keys) {
                if ($acl.ObjectAceType -like "*$($DCSyncGUIDs[$guidName])*") {
                    $sid = $acl.SecurityIdentifier
                    
                    if (-not $dcsyncUsers.ContainsKey($sid)) {
                        $dcsyncUsers[$sid] = @{
                            SID = $sid
                            Rights = @()
                            Username = $null
                        }
                    }
                    
                    if ($guidName -notin $dcsyncUsers[$sid].Rights) {
                        $dcsyncUsers[$sid].Rights += $guidName
                    }
                }
            }
        }
    }
    
    Write-Host "[*] Found $($dcsyncUsers.Count) principals with DCSync rights" -ForegroundColor Green
    
    # Try to resolve SIDs to usernames
    foreach ($sid in $dcsyncUsers.Keys) {
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $user = $objSID.Translate([System.Security.Principal.NTAccount])
            $dcsyncUsers[$sid].Username = $user.Value
        } catch {
            $dcsyncUsers[$sid].Username = "UNRESOLVED: $sid"
        }
    }
    
    # Output results
    if ($dcsyncUsers.Count -eq 0) {
        Write-Host "[!] No users with DCSync rights found (or couldn't read ACLs)" -ForegroundColor Yellow
    } else {
        foreach ($sid in $dcsyncUsers.Keys | Sort-Object) {
            Write-Host "`n[+] DCSync User Found!" -ForegroundColor Red
            Write-Host "   Username: $($dcsyncUsers[$sid].Username)" -ForegroundColor White
            Write-Host "   SID: $sid" -ForegroundColor Gray
            Write-Host "   Rights: $($dcsyncUsers[$sid].Rights -join ', ')" -ForegroundColor Yellow
        }
    }
    
    return $dcsyncUsers
}

function Test-DCSyncForUser {
    <#
    .SYNOPSIS
    Checks if a specific user has DCSync rights.
    #>
    param(
        [Parameter(Mandatory=$True)]
        [String]$Username
    )
    
    Write-Host "[*] Checking DCSync rights for user: $Username" -ForegroundColor Yellow
    
    # Get user details
    $user = Get-DomainUser -Identity $Username
    if (-not $user) {
        Write-Error "User $Username not found"
        return $false
    }
    
    Write-Host "[*] User SID: $($user.objectsid)" -ForegroundColor Cyan
    
    $domainDN = Get-DomainDN
    if (-not $domainDN) {
        Write-Error "Could not determine domain DN"
        return $false
    }
    
    $dcsyncRights = @()
    
    # DCSync GUIDs
    $dcsyncGUIDs = @{
        "DS-Replication-Get-Changes" = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-All" = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        "DS-Replication-Get-Changes-In-Filtered-Set" = "89e95b76-444d-4c62-991a-0facbeda640c"
    }
    
    # Get ACLs for the domain
    $acls = Get-DomainObjectAcl -DistinguishedName $domainDN
    
    foreach ($acl in $acls) {
        if ($acl.SecurityIdentifier -eq $user.objectsid) {
            foreach ($rightName in $dcsyncGUIDs.Keys) {
                $guid = $dcsyncGUIDs[$rightName]
                if ($acl.ObjectAceType -and $acl.ObjectAceType -like "*$guid*") {
                    if ($rightName -notin $dcsyncRights) {
                        $dcsyncRights += $rightName
                    }
                }
            }
        }
    }
    
    if ($dcsyncRights.Count -gt 0) {
        Write-Host "[!] USER HAS DCSYNC RIGHTS!" -ForegroundColor Red
        Write-Host "    Username: $($user.samaccountname)" -ForegroundColor White
        Write-Host "    SID: $($user.objectsid)" -ForegroundColor Gray
        Write-Host "    Rights: $($dcsyncRights -join ', ')" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "[+] User does NOT have DCSync rights" -ForegroundColor Green
        return $false
    }
}

function Get-DCSyncUsersQuick {
    <#
    .SYNOPSIS
    Quick check for common DCSync users using built-in PowerShell
    #>
    
    Write-Host "[*] Quick DCSync Check" -ForegroundColor Yellow
    
    # Check common admin groups
    $adminGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Administrators",
        "Schema Admins"
    )
    
    foreach ($group in $adminGroups) {
        try {
            Write-Host "[*] Checking $group members..." -ForegroundColor Gray
            $groupObj = [ADSI]("WinNT://$env:USERDOMAIN/$group,group")
            $members = $groupObj.psbase.Invoke("Members")
            
            foreach ($member in $members) {
                $name = $member.GetType().InvokeMember("Name", 'GetProperty', $null, $member, $null)
                Write-Host "  [+] $name (in $group)" -ForegroundColor Green
            }
        } catch {
            # Continue if group doesn't exist or can't be accessed
        }
    }
    
    # Direct check using your example method
    Write-Host "`n[*] Checking using ACL method..." -ForegroundColor Yellow
    Find-DCSyncUsers
}

# Main execution
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "==============================================" -ForegroundColor Cyan
    Write-Host "        DCSync Hunter - Fixed Version         " -ForegroundColor Cyan
    Write-Host "==============================================" -ForegroundColor Cyan
    
    # Check if we're in a domain
    $domain = Get-CurrentUserDomain
    if (-not $domain) {
        Write-Host "[!] Not in a domain environment!" -ForegroundColor Red
        Write-Host "[*] Current user domain: $env:USERDOMAIN" -ForegroundColor Yellow
        exit
    }
    
    Write-Host "[*] Domain: $domain" -ForegroundColor Green
    
    # Option 1: Quick check
    Get-DCSyncUsersQuick
    
    # Option 2: Check specific user
    Write-Host "`n[*] Testing specific users..." -ForegroundColor Yellow
    $testUsers = @("administrator", "adunn", "krbtgt")
    
    foreach ($user in $testUsers) {
        try {
            Test-DCSyncForUser -Username $user
        } catch {
            Write-Host "[!] Error checking $user : $_" -ForegroundColor Red
        }
    }
    
    Write-Host "`n[*] Done!" -ForegroundColor Green
}
