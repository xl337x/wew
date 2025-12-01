function Invoke-ACLChain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,
        
        [Parameter(Mandatory=$false)]
        [string]$StartUser,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxDepth = 5,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeComputers,
        
        [Parameter(Mandatory=$false)]
        [switch]$QuickScan,
        
        [Parameter(Mandatory=$false)]
        [switch]$ExportJSON,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputFile = "acl_chain_results.json"
    )
    
    # Auto-detect domain if not specified
    if(-not $Domain) {
        try {
            $Domain = (Get-ADDomain).NetBIOSName
            Write-Host "[*] Auto-detected domain: $Domain" -ForegroundColor Cyan
        } catch {
            Write-Host "[!] Could not auto-detect domain. Please specify -Domain parameter." -ForegroundColor Red
            return
        }
    }
    
    # Interactive mode if no user specified
    if(-not $StartUser) {
        $StartUser = Read-Host "[?] Enter starting username"
    }
    
    # Validate user exists
    try {
        $startUserObj = Get-ADUser $StartUser -ErrorAction Stop
        Write-Host "[+] Starting enumeration from: $($startUserObj.DistinguishedName)" -ForegroundColor Green
    } catch {
        Write-Host "[!] User '$StartUser' not found in domain" -ForegroundColor Red
        return
    }
    
    # Global cache for performance
    $script:userCache = @{}
    $script:groupCache = @{}
    $script:objectCache = @{}
    $script:processedPaths = @{}
    $script:attackChain = @()
    
    # Interesting rights to track
    $criticalRights = @(
        'GenericAll', 'GenericWrite', 'WriteProperty', 'WriteDacl', 'WriteOwner',
        'ExtendedRight', 'AllExtendedRights', 'ForceChangePassword', 'Self', 'WriteMembers'
    )
    
    # Extended rights GUIDs
    $extendedRightsGUIDs = @{
        '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'
        '00000000-0000-0000-0000-000000000000' = 'All'
    }
    
    function Get-CachedADUser {
        param([string]$Identity)
        if(-not $script:userCache.ContainsKey($Identity)) {
            try {
                $script:userCache[$Identity] = Get-ADUser $Identity -Properties memberOf, servicePrincipalName, adminCount -ErrorAction Stop
            } catch {
                return $null
            }
        }
        return $script:userCache[$Identity]
    }
    
    function Get-CachedADGroup {
        param([string]$Identity)
        if(-not $script:groupCache.ContainsKey($Identity)) {
            try {
                $script:groupCache[$Identity] = Get-ADGroup $Identity -Properties member, memberOf, adminCount -ErrorAction Stop
            } catch {
                return $null
            }
        }
        return $script:groupCache[$Identity]
    }
    
    function Resolve-ExtendedRight {
        param([string]$GUID)
        
        if($extendedRightsGUIDs.ContainsKey($GUID)) {
            return $extendedRightsGUIDs[$GUID]
        }
        
        try {
            $rootDSE = Get-ADRootDSE
            $right = Get-ADObject -SearchBase "CN=Extended-Rights,$($rootDSE.ConfigurationNamingContext)" `
                                  -Filter {rightsGuid -eq $GUID} `
                                  -Properties DisplayName -ErrorAction Stop
            if($right) {
                $extendedRightsGUIDs[$GUID] = $right.DisplayName
                return $right.DisplayName
            }
        } catch {}
        
        return $GUID
    }
    
    function Test-CriticalRight {
        param($ACE)
        
        $rights = $ACE.ActiveDirectoryRights.ToString()
        foreach($critical in $criticalRights) {
            if($rights -match $critical) {
                return $true
            }
        }
        return $false
    }
    
    function Get-EffectivePermissions {
        param(
            [string]$PrincipalName,
            [string]$PrincipalSID,
            [int]$Depth = 0,
            [array]$Path = @()
        )
        
        if($Depth -ge $MaxDepth) { return @() }
        
        $pathKey = "$PrincipalName-$Depth"
        if($script:processedPaths.ContainsKey($pathKey)) { return @() }
        $script:processedPaths[$pathKey] = $true
        
        $results = @()
        $indent = "  " * $Depth
        
        Write-Host "$indent[*] Depth $Depth | Enumerating: $PrincipalName" -ForegroundColor Cyan
        
        # Get direct group memberships
        $principal = Get-CachedADUser $PrincipalName
        if(-not $principal) {
            $principal = Get-CachedADGroup $PrincipalName
        }
        
        if(-not $principal) { return @() }
        
        $groups = @()
        if($principal.memberOf) {
            $groups = $principal.memberOf | ForEach-Object {
                $groupName = ($_ -split ',')[0] -replace 'CN=', ''
                $groupObj = Get-CachedADGroup $groupName
                if($groupObj) {
                    Write-Host "$indent  [+] Member of: $groupName" -ForegroundColor Gray
                    [PSCustomObject]@{
                        Name = $groupName
                        DN = $groupObj.DistinguishedName
                        SID = $groupObj.SID.Value
                        AdminCount = $groupObj.adminCount
                    }
                }
            }
        }
        
        # Build identity list (user + all groups)
        $identities = @(
            [PSCustomObject]@{Name = $PrincipalName; SID = $PrincipalSID; Type = 'User'}
        )
        $identities += $groups | ForEach-Object {
            [PSCustomObject]@{Name = $_.Name; SID = $_.SID; Type = 'Group'; AdminCount = $_.AdminCount}
        }
        
        # Enumerate all AD objects
        $filter = if($QuickScan) {
            {ObjectClass -eq 'user' -or ObjectClass -eq 'group' -or ObjectClass -eq 'computer' -or ObjectClass -eq 'organizationalUnit' -or ObjectClass -eq 'domain'}
        } else {
            {ObjectClass -like '*'}
        }
        
        $allObjects = Get-ADObject -Filter $filter -Properties nTSecurityDescriptor, objectClass, adminCount, servicePrincipalName
        
        Write-Host "$indent  [*] Scanning $($allObjects.Count) objects..." -ForegroundColor Yellow
        
        foreach($obj in $allObjects) {
            if(-not $IncludeComputers -and $obj.ObjectClass -eq 'computer') { continue }
            
            try {
                $acl = Get-Acl "AD:\$($obj.DistinguishedName)" -ErrorAction Stop
                
                foreach($identity in $identities) {
                    $relevantACEs = $acl.Access | Where-Object {
                        ($_.IdentityReference -eq "$Domain\$($identity.Name)") -or
                        ($_.IdentityReference -eq $identity.SID)
                    }
                    
                    foreach($ace in $relevantACEs) {
                        if(-not (Test-CriticalRight $ace)) { continue }
                        
                        $extRight = if($ace.ObjectType -ne '00000000-0000-0000-0000-000000000000') {
                            Resolve-ExtendedRight $ace.ObjectType.ToString()
                        } else { 'N/A' }
                        
                        $finding = [PSCustomObject]@{
                            Depth = $Depth
                            Path = ($Path + $PrincipalName) -join ' -> '
                            Source = $PrincipalName
                            SourceType = $identity.Type
                            ViaGroup = if($identity.Type -eq 'Group') { $identity.Name } else { 'Direct' }
                            TargetDN = $obj.DistinguishedName
                            TargetName = $obj.Name
                            TargetClass = $obj.ObjectClass
                            Rights = $ace.ActiveDirectoryRights.ToString()
                            ExtendedRight = $extRight
                            ACEType = $ace.AccessControlType
                            IsInherited = $ace.IsInherited
                            AdminCount = $obj.adminCount
                            HasSPN = if($obj.servicePrincipalName) { $true } else { $false }
                        }
                        
                        $results += $finding
                        $script:attackChain += $finding
                        
                        # Output finding
                        $color = if($finding.Rights -match 'GenericAll|WriteDacl|WriteOwner') { 'Red' }
                                 elseif($finding.Rights -match 'GenericWrite|WriteProperty') { 'Yellow' }
                                 else { 'Green' }
                        
                        Write-Host "$indent  [!] $($identity.Type): $($identity.Name) -> $($ace.ActiveDirectoryRights) -> $($obj.Name) [$($obj.ObjectClass)]" -ForegroundColor $color
                        
                        if($extRight -ne 'N/A') {
                            Write-Host "$indent      Extended: $extRight" -ForegroundColor Magenta
                        }
                        
                        if($identity.Type -eq 'Group' -and $identity.AdminCount -eq 1) {
                            Write-Host "$indent      [PRIVILEGED GROUP]" -ForegroundColor Red
                        }
                        
                        # Recursive enumeration for groups
                        if($obj.ObjectClass -eq 'group' -and ($ace.ActiveDirectoryRights -match 'GenericAll|WriteProperty|WriteMembers|Self')) {
                            Write-Host "$indent    [→] Can modify group membership, recursing..." -ForegroundColor Cyan
                            
                            $groupObj = Get-CachedADGroup $obj.Name
                            if($groupObj -and $groupObj.member) {
                                foreach($member in $groupObj.member) {
                                    $memberName = ($member -split ',')[0] -replace 'CN=', ''
                                    Write-Host "$indent      [M] Member: $memberName" -ForegroundColor Gray
                                }
                            }
                            
                            $nestedResults = Get-EffectivePermissions -PrincipalName $obj.Name `
                                                                      -PrincipalSID $groupObj.SID.Value `
                                                                      -Depth ($Depth + 1) `
                                                                      -Path ($Path + $PrincipalName)
                            $results += $nestedResults
                        }
                        
                        # Recursive enumeration for users with high privileges
                        if($obj.ObjectClass -eq 'user' -and ($ace.ActiveDirectoryRights -match 'GenericAll|ForceChangePassword|AllExtendedRights')) {
                            Write-Host "$indent    [→] Can compromise user, recursing..." -ForegroundColor Cyan
                            
                            $targetUser = Get-CachedADUser $obj.Name
                            if($targetUser) {
                                $nestedResults = Get-EffectivePermissions -PrincipalName $obj.Name `
                                                                          -PrincipalSID $targetUser.SID.Value `
                                                                          -Depth ($Depth + 1) `
                                                                          -Path ($Path + $PrincipalName)
                                $results += $nestedResults
                            }
                        }
                    }
                }
            } catch {
                # Silent fail on access denied
            }
        }
        
        return $results
    }
    
    function Test-DCSync {
        param([string]$PrincipalName)
        
        Write-Host "`n[*] Checking DCSync capabilities for: $PrincipalName" -ForegroundColor Yellow
        
        $domainDN = (Get-ADDomain).DistinguishedName
        $domainAcl = Get-Acl "AD:\$domainDN"
        
        $dcsyncGUIDs = @(
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
            '89e95b76-444d-4c62-991a-0facbeda640c'
        )
        
        $principal = Get-CachedADUser $PrincipalName
        if(-not $principal) { $principal = Get-CachedADGroup $PrincipalName }
        if(-not $principal) { return }
        
        $identities = @("$Domain\$PrincipalName", $principal.SID.Value)
        
        if($principal.memberOf) {
            foreach($groupDN in $principal.memberOf) {
                $groupName = ($groupDN -split ',')[0] -replace 'CN=', ''
                $group = Get-CachedADGroup $groupName
                if($group) {
                    $identities += "$Domain\$groupName"
                    $identities += $group.SID.Value
                }
            }
        }
        
        $foundRights = @()
        foreach($ace in $domainAcl.Access) {
            if($ace.IdentityReference -in $identities -and $ace.ObjectType -in $dcsyncGUIDs) {
                $foundRights += $ace
            }
        }
        
        if($foundRights.Count -gt 0) {
            Write-Host "[!] DCSYNC POSSIBLE!" -ForegroundColor Red -BackgroundColor Black
            foreach($right in $foundRights) {
                Write-Host "    Via: $($right.IdentityReference)" -ForegroundColor Red
                Write-Host "    Right: $(Resolve-ExtendedRight $right.ObjectType)" -ForegroundColor Red
            }
            return $true
        } else {
            Write-Host "[*] No DCSync rights found" -ForegroundColor Gray
            return $false
        }
    }
    
    # Main execution
    $startTime = Get-Date
    Write-Host "[*] Starting ACL chain enumeration at depth $MaxDepth" -ForegroundColor Green
    
    $startUserSID = (Get-ADUser $StartUser).SID.Value
    $permissions = Get-EffectivePermissions -PrincipalName $StartUser -PrincipalSID $startUserSID -Depth 0 -Path @()
    
    # DCSync check
    Test-DCSync -PrincipalName $StartUser
    
    # Summary
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    Write-Host "`n========== SUMMARY ==========" -ForegroundColor Cyan
    Write-Host "[+] Total findings: $($script:attackChain.Count)" -ForegroundColor Green
    Write-Host "[+] Max depth reached: $($script:attackChain | Measure-Object -Property Depth -Maximum | Select-Object -ExpandProperty Maximum)" -ForegroundColor Green
    Write-Host "[+] Execution time: $([math]::Round($duration, 2)) seconds" -ForegroundColor Green
    
    $criticalFindings = $script:attackChain | Where-Object { $_.Rights -match 'GenericAll|WriteDacl|WriteOwner' }
    Write-Host "[!] Critical findings: $($criticalFindings.Count)" -ForegroundColor $(if($criticalFindings.Count -gt 0) { 'Red' } else { 'Green' })
    
    # Export results
    if($ExportJSON) {
        $script:attackChain | ConvertTo-Json -Depth 10 | Out-File $OutputFile
        Write-Host "[+] Results exported to: $OutputFile" -ForegroundColor Green
    }
    
    return $script:attackChain
}

# Quick access aliases
Set-Alias -Name acl -Value Invoke-ACLChain -ErrorAction SilentlyContinue

# Example usage:
# Invoke-ACLChain -Domain "INLANEFREIGHT" -StartUser "wley" -MaxDepth 3
# Invoke-ACLChain -StartUser "wley" -QuickScan -ExportJSON
# acl -StartUser "wley" -MaxDepth 5
