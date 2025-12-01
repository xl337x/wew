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
    
    # Step 2: Enumerate what start user can control
    Write-Host "`n[2] Enumerating what $StartUser can control..." -ForegroundColor Green
    $controlledUsers = @()
    
    foreach($line in Get-Content .\ad_users.txt) {
        $acls = Get-Acl "AD:\$(Get-ADUser $line)" | Select-Object -ExpandProperty Access | Where-Object {$_.IdentityReference -match "$Domain\\$StartUser"}
        
        foreach($acl in $acls) {
            # Resolve GUID to human-readable format
            $resolvedRight = "Standard Right"
            if($acl.ObjectType -ne '00000000-0000-0000-0000-000000000000') {
                if($acl.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529') {
                    $resolvedRight = "User-Force-Change-Password (Reset Password)"
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
        
        # Get SID for the controlled user
        $sid = (Get-ADUser $controlledUser -Properties sid).sid.Value
        
        # Check what this user can access
        $allObjects = Get-ADObject -Filter * -Properties nTSecurityDescriptor
        $foundObjects = @()
        
        foreach($obj in $allObjects) {
            $objAcl = Get-Acl "AD:\$($obj.DistinguishedName)"
            $relevantACEs = $objAcl.Access | Where-Object { 
                $_.IdentityReference -match "$Domain\\$controlledUser" -or 
                ($_.IdentityReference -match "S-\d-\d-\d+" -and $_.IdentityReference -eq $sid)
            }
            
            foreach($ace in $relevantACEs) {
                if($ace.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteProperty|WriteDacl|WriteOwner|ExtendedRight") {
                    Write-Host "`nAceType               : $($ace.AceType)"
                    Write-Host "ObjectDN              : $($obj.DistinguishedName)"
                    Write-Host "ActiveDirectoryRights : $($ace.ActiveDirectoryRights)"
                    Write-Host "InheritanceFlags      : $($ace.InheritanceFlags)"
                    Write-Host "IsInherited           : $($ace.IsInherited)"
                    Write-Host "IdentityReference     : $($ace.IdentityReference)"
                    
                    # Check if it's a group
                    if($obj.ObjectClass -contains "group") {
                        Write-Host "`n[+] This is a GROUP object!" -ForegroundColor Yellow
                        Write-Host "[+] $controlledUser has $($ace.ActiveDirectoryRights) over group: $($obj.Name)" -ForegroundColor Green
                        
                        # Check group nesting
                        $groupMembership = Get-ADGroup $obj -Properties MemberOf | Select-Object -ExpandProperty MemberOf
                        if($groupMembership) {
                            Write-Host "`n[+] Group Nesting Discovery:" -ForegroundColor Magenta
                            foreach($parentGroupDN in $groupMembership) {
                                $parentGroupName = (Get-ADObject $parentGroupDN -Properties Name).Name
                                Write-Host "   $($obj.Name) is member of: $parentGroupName" -ForegroundColor Cyan
                                
                                # Check what this parent group can do
                                $parentGroupSid = (Get-ADGroup $parentGroupName -Properties sid).sid.Value
                                $parentGroupRights = Get-ADObject -Filter * | ForEach-Object {
                                    $acl2 = Get-Acl "AD:\$($_.DistinguishedName)"
                                    $acl2.Access | Where-Object { $_.IdentityReference -eq "$Domain\$parentGroupName" -or $_.IdentityReference -eq $parentGroupSid }
                                }
                                
                                foreach($parentRight in $parentGroupRights) {
                                    if($parentRight.ActiveDirectoryRights -match "GenericAll|WriteProperty") {
                                        Write-Host "      -> $parentGroupName has $($parentRight.ActiveDirectoryRights) over: $($_.Name)" -ForegroundColor Red
                                    }
                                }
                            }
                        }
                    }
                    
                    $foundObjects += $obj
                }
            }
        }
        
        # Check for DCSync rights
        Write-Host "`n[4] Checking for DCSync rights..." -ForegroundColor Green
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
        }
    }
    
    # Cleanup
    Remove-Item ad_users.txt -ErrorAction SilentlyContinue
    
    Write-Host "`n`n=== Tool Execution Complete ===" -ForegroundColor Cyan
    Write-Host "Attack chain discovered!" -ForegroundColor Green
}

# Usage: Get-ADACLChain -Domain "INLANEFREIGHT" -StartUser "wley"

# Interactive version:
$Domain = Read-Host "Enter domain (e.g., INLANEFREIGHT)"
$StartUser = Read-Host "Enter starting username (e.g., wley)"
Get-ADACLChain -Domain $Domain -StartUser $StartUser
