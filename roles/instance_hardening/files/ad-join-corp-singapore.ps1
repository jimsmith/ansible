<powershell>
Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses ("119.43.98.133")
$DomainAccountName = '900000010'
$DomainAccountPassword = 'P@$$word!'
$DomainName = 'DEVCORP.AD'
$NewComputerName = 'GEN3PTEST36'
$credentials = New-Object System.Management.Automation.PsCredential($DomainAccountName, (ConvertTo-SecureString $DomainAccountPassword -AsPlainText -Force)) 
Rename-Computer -NewName $NewComputerName -DomainCredential $credentials -Force
Add-Computer -DomainName $DomainName -Credential $credentials -OUPath "OU=Server_Hardening,OU=Gurgaon,DC=devcorp,DC=ad" 
Restart-Computer -ErrorAction Stop
</powershell>

