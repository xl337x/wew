# Save as: SYSVOL-Hunter.ps1
# Enhanced version with proper SMB discovery and authentication

function Show-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════╗
║         ACTIVE SYSVOL ENUMERATOR v5.0           ║
║     REAL AD Environment Detection & Access       ║
╚══════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

# ================================================
# 1. PROPER DOMAIN CONTROLLER DISCOVERY
# ================================================

function Get-DomainControllers {
    param([string]$Domain)
    
    Write-Host "`n[1] Discovering Domain Controllers..." -ForegroundColor Yellow
    $dcs = @()
    
    # Method 1: NLTEST (Most reliable for AD)
    try {
        Write-Host "  [*] Using nltest..." -ForegroundColor Gray
        $nltestResult = nltest /dclist:$Domain 2>$null
        $nltestResult | Select-String "\\\\(.+)\s+" | ForEach-Object {
            $dc = $_.Matches.Groups[1].Value
            $dcs += $dc
            Write-Host "    [+] DC found: $dc" -ForegroundColor Green
        }
    } catch {}
    
    # Method 2: DNS SRV Records
    if ($dcs.Count -eq 0) {
        try {
            Write-Host "  [*] Querying DNS SRV records..." -ForegroundColor Gray
            $dnsResult = Resolve-DnsName "_ldap._tcp.dc._msdcs.$Domain" -Type SRV -ErrorAction SilentlyContinue
            if ($dnsResult) {
                $dnsResult | ForEach-Object {
                    $dcs += $_.NameTarget
                    Write-Host "    [+] DC from DNS: $($_.NameTarget)" -ForegroundColor Green
                }
            }
        } catch {}
    }
    
    # Method 3: Try common DC naming conventions
    if ($dcs.Count -eq 0) {
        Write-Host "  [*] Trying common DC names..." -ForegroundColor Gray
        $domainShort = $Domain.Split('.')[0]
        $commonNames = @("$domainShort-DC01", "$domainShort-DC02", "DC01", "DC02", "DC", "PDC", "BDC", "AD", "AD01")
        
        foreach ($name in $commonNames) {
            $fullName = "$name.$Domain"
            Write-Host "    Testing: $fullName" -ForegroundColor DarkGray -NoNewline
            
            try {
                if (Test-Connection -ComputerName $fullName -Count 1 -Quiet) {
                    $dcs += $fullName
                    Write-Host " [OK]" -ForegroundColor Green
                } else {
                    Write-Host " [FAIL]" -ForegroundColor DarkGray
                }
            } catch {
                Write-Host " [ERROR]" -ForegroundColor Red
            }
        }
    }
    
    return $dcs | Select-Object -Unique
}

# ================================================
# 2. SMB SHARE ENUMERATION (Proper Method)
# ================================================

function Get-SMBShares {
    param([string]$Computer)
    
    Write-Host "  [*] Enumerating SMB shares on $Computer..." -ForegroundColor Gray
    $shares = @()
    
    try {
        # Method 1: net view (most reliable)
        $netResult = net view \\$Computer 2>$null
        if ($netResult) {
            $netResult | Where-Object { $_ -match '^\s+(\w+)\s+' } | ForEach-Object {
                $shareName = $matches[1]
                if ($shareName -notin @("IPC$", "print$")) {
                    $shares += $shareName
                    Write-Host "    [+] Share: $shareName" -ForegroundColor Green
                }
            }
        }
        
        # Method 2: WMI (if available)
        try {
            $wmiShares = Get-WmiObject -Class Win32_Share -ComputerName $Computer -ErrorAction SilentlyContinue
            $wmiShares | Where-Object { $_.Type -eq 0 } | ForEach-Object { # Type 0 = Disk Drive
                if ($_.Name -notin $shares) {
                    $shares += $_.Name
                }
            }
        } catch {}
        
    } catch {
        Write-Host "    [!] Could not enumerate shares" -ForegroundColor Red
    }
    
    return $shares
}

# ================================================
# 3. FIND SYSVOL/NETLOGON PATHS
# ================================================

function Find-SysvolPaths {
    param([string]$Computer, [string]$Domain)
    
    $paths = @()
    
    # Try standard SYSVOL paths
    $testPaths = @(
        "\\$Computer\SYSVOL\$Domain\scripts",
        "\\$Computer\SYSVOL\$Domain\Policies",
        "\\$Computer\SYSVOL\sysvol\$Domain\scripts", 
        "\\$Computer\NETLOGON",
        "\\$Computer\SYSVOL"
    )
    
    foreach ($path in $testPaths) {
        Write-Host "    Testing: $path" -ForegroundColor DarkGray -NoNewline
        try {
            if (Test-Path $path -ErrorAction SilentlyContinue) {
                Write-Host " [FOUND!]" -ForegroundColor Green
                $paths += $path
                
                # List contents if accessible
                try {
                    $items = Get-ChildItem $path -ErrorAction SilentlyContinue
                    foreach ($item in $items) {
                        Write-Host "      ↳ $($item.Name)" -ForegroundColor DarkGray
                    }
                } catch {}
            } else {
                Write-Host " [NOT FOUND]" -ForegroundColor DarkGray
            }
        } catch {
            Write-Host " [ERROR]" -ForegroundColor Red
        }
    }
    
    return $paths
}

# ================================================
# 4. ENHANCED FILE SEARCH WITH PATTERNS
# ================================================

function Search-ForSecrets {
    param([string]$Path)
    
    $secrets = @()
    
    try {
        # Find all files recursively
        $files = Get-ChildItem -Path $Path -Include *.vbs, *.ps1, *.bat, *.cmd, *.txt, *.xml, *.json, *.config, *.ini, *.reg -Recurse -ErrorAction SilentlyContinue
        
        Write-Host "    Found $($files.Count) files in $Path" -ForegroundColor Gray
        
        foreach ($file in $files) {
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction Stop
                
                # Enhanced regex patterns for secrets
                $patterns = @(
                    # Passwords
                    '(?i)password\s*[=:]\s*["'']([^"'']+)["'']',
                    '(?i)pwd\s*[=:]\s*["'']([^"'']+)["'']',
                    '(?i)pass\s*[=:]\s*["'']([^"'']+)["'']',
                    '(?i)administrator.*password\s*[=:]\s*["'']([^"'']+)["'']',
                    
                    # Group Policy Preferences (cpassword)
                    'cpassword="([^"]+)"',
                    'cpassword="([^"]+)"',
                    
                    # Connection strings with passwords
                    '(?i)connection.*string.*password=([^;]+)',
                    '(?i)uid=([^;]+).*pwd=([^;]+)',
                    
                    # API keys and tokens
                    '(?i)(api[_-]?key|token|secret)\s*[=:]\s*["'']([^"'']+)["'']'
                )
                
                foreach ($pattern in $patterns) {
                    if ($content -match $pattern) {
                        $secretValue = if ($matches[2]) { $matches[2] } else { $matches[1] }
                        
                        $secret = [PSCustomObject]@{
                            File = $file.FullName
                            Secret = $secretValue
                            Pattern = $pattern
                            FileName = $file.Name
                            FileSize = "$([math]::Round($file.Length/1KB,2)) KB"
                        }
                        
                        $secrets += $secret
                        
                        Write-Host "      [!] SECRET FOUND in $($file.Name)" -ForegroundColor Red
                        Write-Host "          Type: $($pattern.Split('|')[0])" -ForegroundColor Yellow
                        Write-Host "          Value: $secretValue" -ForegroundColor Red
                    }
                }
            } catch {
                # Couldn't read file, skip it
            }
        }
    } catch {
        Write-Host "    [!] Could not search path" -ForegroundColor Red
    }
    
    return $secrets
}

# ================================================
# 5. MAIN EXECUTION
# ================================================

Clear-Host
Show-Banner

# Get current domain info
try {
    $computerInfo = Get-WmiObject Win32_ComputerSystem
    $domain = $computerInfo.Domain
    $isDomainJoined = $computerInfo.PartOfDomain
    
    Write-Host "[*] Current Domain: $domain" -ForegroundColor Green
    Write-Host "[*] Domain Joined: $isDomainJoined" -ForegroundColor Green
    Write-Host "[*] Computer: $env:COMPUTERNAME" -ForegroundColor Green
    
} catch {
    Write-Host "[!] Could not get domain info" -ForegroundColor Red
    $domain = $env:USERDOMAIN
    $isDomainJoined = $false
}

if (-not $isDomainJoined -or $domain -eq "WORKGROUP") {
    Write-Host "`n[!] Not domain joined. This tool requires Active Directory." -ForegroundColor Red
    Write-Host "[*] Try running from a domain-joined machine." -ForegroundColor Yellow
    exit
}

# Get Domain Controllers
$domainControllers = Get-DomainControllers -Domain $domain

if ($domainControllers.Count -eq 0) {
    Write-Host "`n[!] No Domain Controllers found!" -ForegroundColor Red
    Write-Host "[*] Trying manual DC discovery..." -ForegroundColor Yellow
    
    # Manual fallback
    $domainControllers = @("$env:COMPUTERNAME.$domain", "localhost")
}

Write-Host "`n[2] Scanning Domain Controllers..." -ForegroundColor Yellow

$allSecrets = @()
$foundPaths = @()

foreach ($dc in $domainControllers) {
    Write-Host "`n[*] Processing DC: $dc" -ForegroundColor Cyan
    
    # First, check if we can access the DC
    try {
        if (Test-Connection -ComputerName $dc -Count 1 -Quiet) {
            Write-Host "  [+] DC is reachable" -ForegroundColor Green
            
            # Find SYSVOL paths
            $sysvolPaths = Find-SysvolPaths -Computer $dc -Domain $domain
            
            if ($sysvolPaths.Count -gt 0) {
                $foundPaths += $sysvolPaths
                
                # Search each path for secrets
                foreach ($path in $sysvolPaths) {
                    Write-Host "  [*] Searching for secrets in: $path" -ForegroundColor Yellow
                    $secrets = Search-ForSecrets -Path $path
                    $allSecrets += $secrets
                }
            } else {
                # If SYSVOL not found directly, enumerate shares
                $shares = Get-SMBShares -Computer $dc
                
                foreach ($share in $shares) {
                    $path = "\\$dc\$share"
                    Write-Host "  [*] Checking share: $share" -ForegroundColor Gray
                    
                    # Look for SYSVOL in share
                    try {
                        $items = Get-ChildItem $path -ErrorAction SilentlyContinue
                        foreach ($item in $items) {
                            if ($item.Name -match "SYSVOL|NETLOGON") {
                                $sysvolPath = "$path\$($item.Name)"
                                Write-Host "    [+] Found: $sysvolPath" -ForegroundColor Green
                                $foundPaths += $sysvolPath
                                
                                # Search for secrets
                                $secrets = Search-ForSecrets -Path $sysvolPath
                                $allSecrets += $secrets
                            }
                        }
                    } catch {}
                }
            }
        } else {
            Write-Host "  [!] DC not reachable via ping" -ForegroundColor Red
            
            # Try SMB directly anyway (might be firewall blocking ICMP)
            Write-Host "  [*] Trying SMB connection anyway..." -ForegroundColor Yellow
            $sysvolPaths = Find-SysvolPaths -Computer $dc -Domain $domain
            $foundPaths += $sysvolPaths
        }
        
    } catch {
        Write-Host "  [!] Error accessing DC: $_" -ForegroundColor Red
    }
}

# ================================================
# 6. RESULTS AND OUTPUT
# ================================================

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host " RESULTS SUMMARY " -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

if ($allSecrets.Count -gt 0) {
    Write-Host "`n[!] CRITICAL FINDINGS: $($allSecrets.Count) SECRETS FOUND!" -ForegroundColor Red -BackgroundColor Black
    
    # Group by type
    $grouped = $allSecrets | Group-Object { $_.Pattern.Split('|')[0] }
    
    foreach ($group in $grouped) {
        Write-Host "`n  [$($group.Name)]: $($group.Count) found" -ForegroundColor Yellow
        
        foreach ($secret in $group.Group | Select-Object -First 3) {
            $shortSecret = if ($secret.Secret.Length -gt 50) { 
                $secret.Secret.Substring(0, 47) + "..." 
            } else { 
                $secret.Secret 
            }
            
            Write-Host "    • $shortSecret" -ForegroundColor White
            Write-Host "      in $($secret.FileName)" -ForegroundColor DarkGray
        }
        
        if ($group.Count -gt 3) {
            Write-Host "    ... and $($group.Count - 3) more" -ForegroundColor Gray
        }
    }
    
    # Save results
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $allSecrets | Export-Csv -Path "sysvol_secrets_$timestamp.csv" -NoTypeInformation
    
    # Create a summary file
    $summary = @"
===============================================
SYSVOL SECRETS SCAN REPORT
Generated: $(Get-Date)
Domain: $domain
DCs Found: $($domainControllers.Count)
Paths Scanned: $($foundPaths.Count)
Total Secrets Found: $($allSecrets.Count)
===============================================

CREDENTIALS FOUND:
"@
    
    $allSecrets | ForEach-Object {
        $summary += "`n[$($_.FileName)]"
        $summary += "Secret: $($_.Secret)"
        $summary += "File: $($_.File)"
        $summary += "Size: $($_.FileSize)"
        $summary += "---"
    }
    
    $summary | Out-File "sysvol_summary_$timestamp.txt"
    
    Write-Host "`n[+] Reports saved:" -ForegroundColor Green
    Write-Host "    • sysvol_secrets_$timestamp.csv" -ForegroundColor White
    Write-Host "    • sysvol_summary_$timestamp.txt" -ForegroundColor White
    
} else {
    Write-Host "`n[-] No secrets found in SYSVOL/NETLOGON" -ForegroundColor Yellow
    
    if ($foundPaths.Count -gt 0) {
        Write-Host "[*] Paths checked:" -ForegroundColor Gray
        $foundPaths | ForEach-Object { Write-Host "    • $_" -ForegroundColor White }
    } else {
        Write-Host "[!] Could not access any SYSVOL paths" -ForegroundColor Red
        
        # Provide troubleshooting tips
        Write-Host "`n[*] TROUBLESHOOTING:" -ForegroundColor Cyan
        Write-Host "    1. Run with Domain Admin privileges" -ForegroundColor White
        Write-Host "    2. Check firewall: SMB (445) must be open" -ForegroundColor White
        Write-Host "    3. Try manually: \\DC01.$domain\SYSVOL\" -ForegroundColor White
        Write-Host "    4. Use net use: net use * /d /y && net use \\DC01.$domain" -ForegroundColor White
    }
}

# ================================================
# 7. QUICK ACCESS COMMANDS
# ================================================

Write-Host "`n" + "-" * 60 -ForegroundColor DarkGray
Write-Host " QUICK ACCESS COMMANDS " -ForegroundColor Cyan
Write-Host "-" * 60 -ForegroundColor DarkGray

if ($foundPaths.Count -gt 0) {
    Write-Host "`n[*] Copy these to explore manually:" -ForegroundColor Yellow
    
    foreach ($path in $foundPaths | Select-Object -First 5) {
        Write-Host "    dir `"$path`"" -ForegroundColor Green
    }
    
    Write-Host "`n[*] Search for passwords:" -ForegroundColor Yellow
    foreach ($path in $foundPaths | Select-Object -First 3) {
        Write-Host "    Get-ChildItem `"$path`" -Recurse -Include *.vbs,*.ps1 | Select-String 'password'" -ForegroundColor Green
    }
} else {
    # Fallback commands
    Write-Host "`n[*] Manual discovery commands:" -ForegroundColor Yellow
    Write-Host "    # Find all DCs:" -ForegroundColor White
    Write-Host "    nltest /dclist:$domain" -ForegroundColor Green
    
    Write-Host "    `n# Try standard SYSVOL paths:" -ForegroundColor White
    Write-Host "    Test-Path `"\\DC01.$domain\SYSVOL\$domain\scripts`"" -ForegroundColor Green
    Write-Host "    dir `"\\$env:COMPUTERNAME.$domain\SYSVOL\`"" -ForegroundColor Green
    
    Write-Host "    `n# Enumerate shares:" -ForegroundColor White
    Write-Host "    net view \\DC01.$domain" -ForegroundColor Green
}

Write-Host "`n[*] Scan complete at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
