# Ensure execution policy allows script run (if needed)
# powershell -ep bypass

Import-Module ActiveDirectory

# Get domain DN
$domainDN = (Get-ADDomain).DistinguishedName

# Get all enabled domain users (sAMAccountName)
$allUsers = Get-ADUser -Filter * -Properties sAMAccountName | Select-Object -ExpandProperty sAMAccountName

# Define replication GUIDs
$replicationGUIDs = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', # Replicating Directory Changes
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', # Replicating Directory Changes All
    '89e95b76-444d-4c62-991a-0facbeda640c'  # Replicating Directory Changes in Filtered Set
)

# Get domain ACL once (efficient)
$domainACL = Get-Acl "AD:\$domainDN"

Write-Host "[*] Checking DCSync rights for $($allUsers.Count) users..." -ForegroundColor Cyan

$dcsyncUsers = foreach ($user in $allUsers) {
    $matches = $domainACL.Access | Where-Object {
        $_.IdentityReference -like "*\$user" -and
        $_.ObjectType -in $replicationGUIDs -and
        $_.ActiveDirectoryRights -match "ExtendedRight"
    }
    if ($matches) {
        Write-Host "[+] DCSync rights found: $user" -ForegroundColor Green
        $user
    }
}

if ($dcsyncUsers) {
    Write-Host "`n[!] Users with DCSync rights:" -ForegroundColor Red
    $dcsyncUsers
} else {
    Write-Host "[*] No users found with DCSync rights." -ForegroundColor Yellow
}
