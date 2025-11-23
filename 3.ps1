function Start-ADSystemAudit {
    param(
        [string]$OutputFile
    )
    
    $banner = @"
===================================================================
    Active Directory System Audit Tool
    Built-in Windows Commands Only - No External Dependencies
===================================================================
"@
    
    Write-Host $banner -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "[*] Starting comprehensive system audit..." -ForegroundColor Green
    Write-Host "[*] Current PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" -ForegroundColor Cyan
    Write-Host ""
    
    # Section 1: Basic Host Information
    Write-Host ""
    Write-Host "[*] BASIC HOST ENUMERATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Hostname:" -ForegroundColor Green
        hostname
        
        Write-Host ""
        Write-Host "[+] Current User and Domain:" -ForegroundColor Green
        whoami
        whoami /user
        whoami /priv
        whoami /groups
        
        Write-Host ""
        Write-Host "[+] OS Version:" -ForegroundColor Green
        [System.Environment]::OSVersion.Version | Format-List
        
        Write-Host ""
        Write-Host "[+] System Information:" -ForegroundColor Green
        systeminfo
        
        Write-Host ""
        Write-Host "[+] Hotfixes and Patches:" -ForegroundColor Green
        wmic qfe get Caption,Description,HotFixID,InstalledOn
        
        Write-Host ""
        Write-Host "[+] Environment Variables:" -ForegroundColor Green
        Get-ChildItem Env: | Format-Table Key,Value -AutoSize
        
        Write-Host ""
        Write-Host "[+] Current Domain:" -ForegroundColor Green
        $env:USERDOMAIN
        
        Write-Host ""
        Write-Host "[+] Logon Server:" -ForegroundColor Green
        $env:LOGONSERVER
        
        Write-Host ""
        Write-Host "[+] Computer System Info:" -ForegroundColor Green
        wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:list
    } catch {
        Write-Host "[!] Error in Basic Host Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 2: PowerShell Configuration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] POWERSHELL CONFIGURATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] PowerShell Version:" -ForegroundColor Green
        Get-Host | Select-Object Version
        
        Write-Host ""
        Write-Host "[+] Loaded Modules:" -ForegroundColor Green
        Get-Module | Format-Table Name,Version,ModuleType
        
        Write-Host ""
        Write-Host "[+] Execution Policy:" -ForegroundColor Green
        Get-ExecutionPolicy -List | Format-Table
        
        Write-Host ""
        Write-Host "[+] PowerShell History:" -ForegroundColor Green
        if (Test-Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt") {
            Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-Object -Last 50
        } else {
            Write-Host "  No history file found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "[!] Error in PowerShell Configuration: $_" -ForegroundColor Red
    }
    
    # Section 3: Network Configuration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] NETWORK CONFIGURATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Network Adapters:" -ForegroundColor Green
        ipconfig /all
        
        Write-Host ""
        Write-Host "[+] ARP Cache:" -ForegroundColor Green
        arp -a
        
        Write-Host ""
        Write-Host "[+] Routing Table:" -ForegroundColor Green
        route print
        
        Write-Host ""
        Write-Host "[+] Active Network Connections:" -ForegroundColor Green
        netstat -ano
        
        Write-Host ""
        Write-Host "[+] DNS Cache:" -ForegroundColor Green
        ipconfig /displaydns | Select-Object -First 100
        
        Write-Host ""
        Write-Host "[+] Network Shares:" -ForegroundColor Green
        net share
        
        Write-Host ""
        Write-Host "[+] Network Views:" -ForegroundColor Green
        net view
    } catch {
        Write-Host "[!] Error in Network Configuration: $_" -ForegroundColor Red
    }
    
    # Section 4: Security Status
    Write-Host ""
    Write-Host ""
    Write-Host "[*] SECURITY STATUS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Firewall Profile Status:" -ForegroundColor Green
        netsh advfirewall show allprofiles
        
        Write-Host ""
        Write-Host "[+] Windows Defender Status:" -ForegroundColor Green
        sc query windefend
        
        Write-Host ""
        Write-Host "[+] Defender Configuration:" -ForegroundColor Green
        Get-MpComputerStatus
        
        Write-Host ""
        Write-Host "[+] Defender Preferences:" -ForegroundColor Green
        Get-MpPreference | Format-List
    } catch {
        Write-Host "[!] Error in Security Status: $_" -ForegroundColor Red
    }
    
    # Section 5: Active Sessions
    Write-Host ""
    Write-Host ""
    Write-Host "[*] ACTIVE USER SESSIONS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Current Sessions:" -ForegroundColor Green
        qwinsta
        
        Write-Host ""
        Write-Host "[+] Logged On Users:" -ForegroundColor Green
        query user
    } catch {
        Write-Host "[!] Error in Session Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 6: Local Users and Groups
    Write-Host ""
    Write-Host ""
    Write-Host "[*] LOCAL USERS AND GROUPS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Local Users:" -ForegroundColor Green
        Get-LocalUser | Format-Table Name,Enabled,LastLogon,PasswordRequired
        net user
        
        Write-Host ""
        Write-Host "[+] Local Groups:" -ForegroundColor Green
        Get-LocalGroup | Format-Table Name,Description
        net localgroup
        
        Write-Host ""
        Write-Host "[+] Local Administrators:" -ForegroundColor Green
        net localgroup administrators
        Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Format-Table
        
        Write-Host ""
        Write-Host "[+] All Local Group Memberships:" -ForegroundColor Green
        $groups = Get-LocalGroup
        foreach ($group in $groups) {
            Write-Host ""
            Write-Host "  [$($group.Name)]" -ForegroundColor Cyan
            Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | Format-Table
        }
    } catch {
        Write-Host "[!] Error in Local User/Group Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 7: Domain Enumeration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] DOMAIN ENUMERATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Domain Password Policy:" -ForegroundColor Green
        net accounts /domain
        
        Write-Host ""
        Write-Host "[+] Domain Groups:" -ForegroundColor Green
        net group /domain
        
        Write-Host ""
        Write-Host "[+] Domain Users:" -ForegroundColor Green
        net user /domain
        
        Write-Host ""
        Write-Host "[+] Domain Admins:" -ForegroundColor Green
        net group "Domain Admins" /domain
        
        Write-Host ""
        Write-Host "[+] Enterprise Admins:" -ForegroundColor Green
        net group "Enterprise Admins" /domain
        
        Write-Host ""
        Write-Host "[+] Domain Controllers:" -ForegroundColor Green
        net group "Domain Controllers" /domain
        
        Write-Host ""
        Write-Host "[+] Domain Computers:" -ForegroundColor Green
        net group "Domain Computers" /domain
        
        Write-Host ""
        Write-Host "[+] Schema Admins:" -ForegroundColor Green
        net group "Schema Admins" /domain
        
        Write-Host ""
        Write-Host "[+] Domain Views:" -ForegroundColor Green
        net view /domain
    } catch {
        Write-Host "[!] Error in Domain Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 8: WMI Enumeration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] WMI ENUMERATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Domain and Trust Information:" -ForegroundColor Green
        wmic ntdomain list /format:list
        wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
        
        Write-Host ""
        Write-Host "[+] User Accounts:" -ForegroundColor Green
        wmic useraccount list /format:list
        
        Write-Host ""
        Write-Host "[+] Groups:" -ForegroundColor Green
        wmic group list /format:list
        
        Write-Host ""
        Write-Host "[+] System Accounts:" -ForegroundColor Green
        wmic sysaccount list /format:list
        
        Write-Host ""
        Write-Host "[+] Running Processes:" -ForegroundColor Green
        wmic process list brief
        
        Write-Host ""
        Write-Host "[+] Services:" -ForegroundColor Green
        wmic service list brief
        
        Write-Host ""
        Write-Host "[+] Startup Programs:" -ForegroundColor Green
        wmic startup list full
        
        Write-Host ""
        Write-Host "[+] Installed Software:" -ForegroundColor Green
        wmic product get name,version,vendor
    } catch {
        Write-Host "[!] Error in WMI Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 9: DSQuery Enumeration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] DSQUERY ENUMERATION" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Domain Users:" -ForegroundColor Green
        dsquery user -limit 100
        
        Write-Host ""
        Write-Host "[+] Domain Computers:" -ForegroundColor Green
        dsquery computer -limit 100
        
        Write-Host ""
        Write-Host "[+] Domain Controllers:" -ForegroundColor Green
        dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 10 -attr sAMAccountName
        
        Write-Host ""
        Write-Host "[+] Users with Password Not Required:" -ForegroundColor Green
        dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl -limit 50
        
        Write-Host ""
        Write-Host "[+] Disabled Accounts:" -ForegroundColor Green
        dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr distinguishedName description -limit 50
        
        Write-Host ""
        Write-Host "[+] Service Principal Names:" -ForegroundColor Green
        dsquery * -filter "(servicePrincipalName=*)" -attr sAMAccountName servicePrincipalName -limit 50
        
        Write-Host ""
        Write-Host "[+] Organizational Units:" -ForegroundColor Green
        dsquery ou -limit 50
        
        Write-Host ""
        Write-Host "[+] Domain Groups:" -ForegroundColor Green
        dsquery group -limit 100
    } catch {
        Write-Host "[!] Error in DSQuery Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 10: Active Directory PowerShell Module
    Write-Host ""
    Write-Host ""
    Write-Host "[*] ACTIVE DIRECTORY POWERSHELL MODULE" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            
            Write-Host ""
            Write-Host "[+] Domain Information:" -ForegroundColor Green
            Get-ADDomain | Format-List
            
            Write-Host ""
            Write-Host "[+] Forest Information:" -ForegroundColor Green
            Get-ADForest | Format-List
            
            Write-Host ""
            Write-Host "[+] Domain Controllers:" -ForegroundColor Green
            Get-ADDomainController -Filter * | Format-Table Name,IPv4Address,OperatingSystem,Site
            
            Write-Host ""
            Write-Host "[+] Domain Users (First 100):" -ForegroundColor Green
            Get-ADUser -Filter * -Properties LastLogonDate,PasswordLastSet,PasswordNeverExpires | Select-Object Name,SamAccountName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires -First 100 | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Admins:" -ForegroundColor Green
            Get-ADGroupMember -Identity "Domain Admins" -Recursive | Format-Table Name,SamAccountName,objectClass
            
            Write-Host ""
            Write-Host "[+] Enterprise Admins:" -ForegroundColor Green
            Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Format-Table Name,SamAccountName,objectClass
            
            Write-Host ""
            Write-Host "[+] Domain Groups:" -ForegroundColor Green
            Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory -First 100 | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Computers:" -ForegroundColor Green
            Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate | Select-Object Name,OperatingSystem,LastLogonDate -First 100 | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Trusts:" -ForegroundColor Green
            Get-ADTrust -Filter * | Format-Table
            
            Write-Host ""
            Write-Host "[+] Group Policy Objects:" -ForegroundColor Green
            Get-GPO -All | Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime | Format-Table
            
            Write-Host ""
            Write-Host "[+] Fine-Grained Password Policies:" -ForegroundColor Green
            Get-ADFineGrainedPasswordPolicy -Filter * | Format-List
            
            Write-Host ""
            Write-Host "[+] Password Policy:" -ForegroundColor Green
            Get-ADDefaultDomainPasswordPolicy | Format-List
        } else {
            Write-Host "[!] Active Directory PowerShell module not available" -ForegroundColor Red
            Write-Host "    Install RSAT tools to enable this functionality" -ForegroundColor Gray
        }
    } catch {
        Write-Host "[!] Error in AD PowerShell Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 11: Security Checks
    Write-Host ""
    Write-Host ""
    Write-Host "[*] SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Scheduled Tasks:" -ForegroundColor Green
        schtasks /query /fo LIST /v | Select-Object -First 200
        
        Write-Host ""
        Write-Host "[+] Registry Auto-Run Keys:" -ForegroundColor Green
        reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
        reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
        reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
        reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
        
        Write-Host ""
        Write-Host "[+] Installed Drivers:" -ForegroundColor Green
        driverquery
        
        Write-Host ""
        Write-Host "[+] AppLocker Rules:" -ForegroundColor Green
        Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Format-List
        
        Write-Host ""
        Write-Host "[+] Windows Features:" -ForegroundColor Green
        Get-WindowsOptionalFeature -Online | Where-Object State -eq "Enabled" | Select-Object FeatureName,State | Format-Table
    } catch {
        Write-Host "[!] Error in Security Checks: $_" -ForegroundColor Red
    }
    
    # Section 12: File Search
    Write-Host ""
    Write-Host ""
    Write-Host "[*] SENSITIVE FILE SEARCH" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Searching for interesting files..." -ForegroundColor Green
        $searchPaths = @("C:\Users\$env:USERNAME\Desktop", "C:\Users\$env:USERNAME\Documents", "C:\Temp")
        $searchPatterns = @("*pass*", "*cred*", "*.config", "*.xml", "*.txt", "*.ini")
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                Write-Host "  Searching: $path" -ForegroundColor Gray
                foreach ($pattern in $searchPatterns) {
                    Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Depth 2 | 
                        Select-Object FullName, Length, LastWriteTime -First 20 | Format-Table
                }
            }
        }
    } catch {
        Write-Host "[!] Error in File Search: $_" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "    Audit Complete!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Cyan
    
    if ($OutputFile) {
        Write-Host ""
        Write-Host "[*] Results saved to: $OutputFile" -ForegroundColor Green
    }
}

# Execute
Write-Host ""
Write-Host "[*] Starting Active Directory System Audit..." -ForegroundColor Cyan
Write-Host ""
Start-ADSystemAudit
