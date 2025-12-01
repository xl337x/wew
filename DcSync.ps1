# Simple DCSync Checker
function Check-DCSync {
    param([String]$UserName = "adunn")
    
    Write-Host "DCSync Check for user: $UserName" -ForegroundColor Yellow
    
    # Get domain
    $domain = $env:USERDNSDOMAIN
    if (-not $domain) { $domain = $env:USERDOMAIN }
    Write-Host "Domain: $domain" -ForegroundColor Cyan
    
    # Build domain DN
    $domainDN = ($domain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
    Write-Host "Domain DN: $domainDN" -ForegroundColor Gray
    
    # Import PowerView if available
    try {
        Import-Module .\PowerView.ps1 -ErrorAction SilentlyContinue
        Write-Host "[*] PowerView loaded" -ForegroundColor Green
    } catch {
        Write-Host "[!] PowerView not found, using alternative method" -ForegroundColor Yellow
    }
    
    # Method 1: Try with PowerView if available
    if (Get-Command Get-DomainUser -ErrorAction SilentlyContinue) {
        Write-Host "`n[*] Using PowerView method..." -ForegroundColor Green
        
        # Get user SID
        $user = Get-DomainUser -Identity $UserName | Select-Object samaccountname, objectsid
        if ($user) {
            Write-Host "User found: $($user.samaccountname)" -ForegroundColor White
            Write-Host "User SID: $($user.objectsid)" -ForegroundColor Gray
            
            # Check DCSync rights
            $acls = Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs | 
                    Where-Object { $_.ObjectAceType -match 'Replication-Get' }
            
            $hasRights = $acls | Where-Object { $_.SecurityIdentifier -match $user.objectsid }
            
            if ($hasRights) {
                Write-Host "`n[!] USER HAS DCSYNC RIGHTS!" -ForegroundColor Red
                $hasRights | Select-Object AceQualifier, ActiveDirectoryRights, ObjectAceType
                return $true
            } else {
                Write-Host "`n[+] User does NOT have DCSync rights" -ForegroundColor Green
                return $false
            }
        }
    } 
    # Method 2: Native PowerShell
    else {
        Write-Host "`n[*] Using native PowerShell method..." -ForegroundColor Green
        
        # Simple check - look for admin group memberships
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=user)(samaccountname=$UserName))"
        $searcher.PropertiesToLoad.Add("memberof")
        
        try {
            $result = $searcher.FindOne()
            if ($result) {
                $groups = $result.Properties["memberof"]
                
                # Check for admin groups
                $adminGroups = @("*Domain Admins*", "*Enterprise Admins*", "*Administrators*")
                $isAdmin = $false
                
                foreach ($group in $groups) {
                    foreach ($adminPattern in $adminGroups) {
                        if ($group -like $adminPattern) {
                            Write-Host "[!] User is in admin group: $group" -ForegroundColor Red
                            $isAdmin = $true
                        }
                    }
                }
                
                if ($isAdmin) {
                    Write-Host "[!] User likely has DCSync rights (admin group membership)" -ForegroundColor Red
                    return $true
                } else {
                    Write-Host "[+] User not in obvious admin groups" -ForegroundColor Green
                }
            }
        } catch {
            Write-Host "[!] Error: $_" -ForegroundColor Red
        }
    }
    
    return $false
}

# Run it
Check-DCSync -UserName "adunn"
