# ============================================================================
# COMPREHENSIVE AD TRUST & DOMAIN ENUMERATION
# ============================================================================
# Features:
# - Auto-discovers current domain (no hardcoded values)
# - Runs all enumeration commands automatically
# - Supports both native AD cmdlets and PowerView
# - Clean, formatted output
# - Error handling
# ============================================================================

$ErrorActionPreference = 'SilentlyContinue'

# Auto-discover current domain
$currentDomain = $env:USERDNSDOMAIN
$domainObj = Get-ADDomain -ErrorAction SilentlyContinue
$forestObj = Get-ADForest -ErrorAction SilentlyContinue

# Check if PowerView is available
$powerViewAvailable = Get-Command Get-DomainTrust -ErrorAction SilentlyContinue

# Header
Write-Host "`n" + "="*90 -ForegroundColor Cyan
Write-Host "  COMPREHENSIVE AD TRUST & DOMAIN ENUMERATION" -ForegroundColor Yellow
Write-Host "="*90 -ForegroundColor Cyan
Write-Host "  Current Domain: " -NoNewline -ForegroundColor Gray
Write-Host $currentDomain -ForegroundColor White
Write-Host "  NetBIOS Name: " -NoNewline -ForegroundColor Gray
Write-Host $domainObj.NetBIOSName -ForegroundColor White
Write-Host "  Forest: " -NoNewline -ForegroundColor Gray
Write-Host $forestObj.Name -ForegroundColor White
Write-Host "  Scan Time: " -NoNewline -ForegroundColor Gray
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  PowerView: " -NoNewline -ForegroundColor Gray
if ($powerViewAvailable) {
    Write-Host "Available ✓" -ForegroundColor Green
} else {
    Write-Host "Not Loaded" -ForegroundColor Yellow
}
Write-Host "="*90 -ForegroundColor Cyan

# ============================================================================
# 1. DOMAIN TRUSTS - Get-ADTrust
# ============================================================================
Write-Host "`n[1] DOMAIN TRUSTS (Get-ADTrust)" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray

$trusts = Get-ADTrust -Filter *

if ($trusts) {
    Write-Host "Found $($trusts.Count) trust relationship(s)`n" -ForegroundColor Yellow
    
    $trusts | Format-Table @{
        Label="Trust Name"; Expression={$_.Name}; Width=30
    }, @{
        Label="Direction"; Expression={$_.Direction}; Width=15
    }, @{
        Label="Type"; Expression={$_.TrustType}; Width=15
    }, @{
        Label="IntraForest"; Expression={$_.IntraForest}; Width=12
    }, @{
        Label="Transitive"; Expression={$_.ForestTransitive}; Width=12
    } -AutoSize
    
    # Detailed view
    Write-Host "`nDetailed Trust Information:" -ForegroundColor Cyan
    foreach ($trust in $trusts) {
        Write-Host "`n  → $($trust.Name)" -ForegroundColor White
        Write-Host "    Direction: $($trust.Direction)" -ForegroundColor Gray
        Write-Host "    Trust Type: $($trust.TrustType)" -ForegroundColor Gray
        Write-Host "    IntraForest: $($trust.IntraForest)" -ForegroundColor Gray
        Write-Host "    Forest Transitive: $($trust.ForestTransitive)" -ForegroundColor Gray
        Write-Host "    SID Filtering (Forest Aware): $($trust.SIDFilteringForestAware)" -ForegroundColor Gray
        Write-Host "    SID Filtering (Quarantined): $($trust.SIDFilteringQuarantined)" -ForegroundColor Gray
        Write-Host "    Selective Authentication: $($trust.SelectiveAuthentication)" -ForegroundColor Gray
        Write-Host "    Source: $($trust.Source)" -ForegroundColor Gray
        Write-Host "    Target: $($trust.Target)" -ForegroundColor Gray
        
        if ($trust.WhenCreated) {
            Write-Host "    Created: $($trust.WhenCreated)" -ForegroundColor Gray
        }
        if ($trust.WhenChanged) {
            Write-Host "    Last Changed: $($trust.WhenChanged)" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "No trusts found or insufficient permissions.`n" -ForegroundColor Red
}

# ============================================================================
# 2. DOMAIN TRUSTS - Get-DomainTrust (PowerView)
# ============================================================================
if ($powerViewAvailable) {
    Write-Host "`n[2] DOMAIN TRUSTS (Get-DomainTrust - PowerView)" -ForegroundColor Green
    Write-Host "-"*90 -ForegroundColor DarkGray
    
    $domainTrusts = Get-DomainTrust
    
    if ($domainTrusts) {
        $domainTrusts | Format-Table SourceName, TargetName, TrustType, TrustDirection, TrustAttributes -AutoSize
    } else {
        Write-Host "No trusts found.`n" -ForegroundColor Red
    }
}

# ============================================================================
# 3. TRUST MAPPING - Get-DomainTrustMapping (PowerView)
# ============================================================================
if ($powerViewAvailable) {
    Write-Host "`n[3] DOMAIN TRUST MAPPING (Get-DomainTrustMapping - PowerView)" -ForegroundColor Green
    Write-Host "-"*90 -ForegroundColor DarkGray
    
    $trustMapping = Get-DomainTrustMapping
    
    if ($trustMapping) {
        $trustMapping | Format-Table SourceName, TargetName, TrustType, TrustDirection -AutoSize
    } else {
        Write-Host "No trust mappings found.`n" -ForegroundColor Red
    }
}

# ============================================================================
# 4. ENUMERATE USERS IN TRUSTED DOMAINS
# ============================================================================
Write-Host "`n[4] USERS IN TRUSTED DOMAINS" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray

if ($trusts) {
    foreach ($trust in $trusts) {
        Write-Host "`n  Enumerating: $($trust.Name)" -ForegroundColor Yellow
        
        # Try native AD cmdlet
        try {
            $users = Get-ADUser -Filter * -Server $trust.Name -ResultSetSize 10 -Properties SamAccountName, Name, Enabled
            
            if ($users) {
                Write-Host "  Found users (showing first 10):" -ForegroundColor Cyan
                $users | Format-Table @{
                    Label="SamAccountName"; Expression={$_.SamAccountName}; Width=25
                }, @{
                    Label="Name"; Expression={$_.Name}; Width=35
                }, @{
                    Label="Enabled"; Expression={$_.Enabled}; Width=10
                } -AutoSize
            } else {
                Write-Host "  No users found or access denied.`n" -ForegroundColor Red
            }
        } catch {
            Write-Host "  Could not enumerate (Access Denied or Connectivity Issue)`n" -ForegroundColor Red
        }
        
        # Try PowerView if available
        if ($powerViewAvailable) {
            try {
                $pvUsers = Get-DomainUser -Domain $trust.Name | Select-Object -First 10 samaccountname, name
                
                if ($pvUsers) {
                    Write-Host "  PowerView Results:" -ForegroundColor Cyan
                    $pvUsers | Format-Table -AutoSize
                }
            } catch {
                # Silent fail
            }
        }
    }
} else {
    Write-Host "No trusts to enumerate.`n" -ForegroundColor Red
}

# ============================================================================
# 5. NETDOM TRUST QUERY
# ============================================================================
Write-Host "`n[5] NETDOM TRUST QUERY" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray
Write-Host "Command: netdom query /domain:$currentDomain trust`n" -ForegroundColor Gray

$netdomTrusts = netdom query /domain:$currentDomain trust

if ($netdomTrusts) {
    $netdomTrusts | ForEach-Object {
        if ($_ -match '\S') {
            Write-Host $_ -ForegroundColor White
        }
    }
} else {
    Write-Host "No output from netdom trust query.`n" -ForegroundColor Red
}

# ============================================================================
# 6. NETDOM DOMAIN CONTROLLERS QUERY
# ============================================================================
Write-Host "`n[6] DOMAIN CONTROLLERS" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray
Write-Host "Command: netdom query /domain:$currentDomain dc`n" -ForegroundColor Gray

$netdomDCs = netdom query /domain:$currentDomain dc

if ($netdomDCs) {
    $netdomDCs | ForEach-Object {
        if ($_ -match '\S') {
            Write-Host $_ -ForegroundColor White
        }
    }
}

# Alternative: Get-ADDomainController
Write-Host "`nDomain Controllers (Get-ADDomainController):" -ForegroundColor Cyan
$dcs = Get-ADDomainController -Filter *

if ($dcs) {
    $dcs | Format-Table @{
        Label="Name"; Expression={$_.Name}; Width=25
    }, @{
        Label="IP Address"; Expression={$_.IPv4Address}; Width=15
    }, @{
        Label="Site"; Expression={$_.Site}; Width=25
    }, @{
        Label="OS"; Expression={$_.OperatingSystem}; Width=30
    } -AutoSize
}

# ============================================================================
# 7. NETDOM WORKSTATIONS QUERY
# ============================================================================
Write-Host "`n[7] WORKSTATIONS & SERVERS" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray
Write-Host "Command: netdom query /domain:$currentDomain workstation (showing first 20)`n" -ForegroundColor Gray

$netdomWS = netdom query /domain:$currentDomain workstation

if ($netdomWS) {
    $count = 0
    $netdomWS | ForEach-Object {
        if ($_ -match '\S' -and $count -lt 20) {
            Write-Host $_ -ForegroundColor White
            $count++
        }
    }
    if ($count -ge 20) {
        Write-Host "... (output truncated, showing first 20)" -ForegroundColor DarkGray
    }
}

# Alternative: Get-ADComputer
Write-Host "`nComputer Objects (Get-ADComputer - first 20):" -ForegroundColor Cyan
$computers = Get-ADComputer -Filter * -ResultSetSize 20 -Properties OperatingSystem

if ($computers) {
    $computers | Format-Table @{
        Label="Name"; Expression={$_.Name}; Width=30
    }, @{
        Label="Operating System"; Expression={$_.OperatingSystem}; Width=50
    } -AutoSize
}

# ============================================================================
# 8. NLTEST DOMAIN TRUSTS
# ============================================================================
Write-Host "`n[8] NLTEST DOMAIN TRUSTS" -ForegroundColor Green
Write-Host "-"*90 -ForegroundColor DarkGray
Write-Host "Command: nltest /domain_trusts`n" -ForegroundColor Gray

$nltestOutput = nltest /domain_trusts

if ($nltestOutput) {
    $nltestOutput | ForEach-Object {
        if ($_ -match '\S') {
            Write-Host $_ -ForegroundColor White
        }
    }
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Host "`n" + "="*90 -ForegroundColor Cyan
Write-Host "  ENUMERATION SUMMARY" -ForegroundColor Yellow
Write-Host "="*90 -ForegroundColor Cyan

Write-Host "`n  Domain Information:" -ForegroundColor Green
Write-Host "    Current Domain: $currentDomain" -ForegroundColor White
Write-Host "    NetBIOS Name: $($domainObj.NetBIOSName)" -ForegroundColor White
Write-Host "    Domain DN: $($domainObj.DistinguishedName)" -ForegroundColor White
Write-Host "    Forest: $($forestObj.Name)" -ForegroundColor White
Write-Host "    Domain Mode: $($domainObj.DomainMode)" -ForegroundColor White
Write-Host "    Forest Mode: $($forestObj.ForestMode)" -ForegroundColor White

Write-Host "`n  Trust Relationships:" -ForegroundColor Green
if ($trusts) {
    Write-Host "    Total Trusts: $($trusts.Count)" -ForegroundColor White
    $trusts | ForEach-Object {
        Write-Host "      • $($_.Name) [$($_.Direction) - $($_.TrustType)]" -ForegroundColor Cyan
    }
} else {
    Write-Host "    No trusts found" -ForegroundColor Yellow
}

Write-Host "`n  Domain Controllers:" -ForegroundColor Green
if ($dcs) {
    Write-Host "    Total DCs: $($dcs.Count)" -ForegroundColor White
    $dcs | ForEach-Object {
        Write-Host "      • $($_.Name) - $($_.IPv4Address)" -ForegroundColor Cyan
    }
}

Write-Host "`n  Computer Objects:" -ForegroundColor Green
$allComputers = Get-ADComputer -Filter *
if ($allComputers) {
    Write-Host "    Total Computers: $($allComputers.Count)" -ForegroundColor White
}

Write-Host "`n  User Objects:" -ForegroundColor Green
$allUsers = Get-ADUser -Filter *
if ($allUsers) {
    Write-Host "    Total Users: $($allUsers.Count)" -ForegroundColor White
}

Write-Host "`n" + "="*90 -ForegroundColor Cyan
Write-Host "  Enumeration completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host "="*90 -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = 'Continue'
