Write-Host 'Creating New Standard User:'
Write-Host 'Please Enter your Employee User-Name:'
$uName = Read-Host
Write-Host 'Please Enter the password (Will be changed after first LogIn):'
$Password = Read-Host -AsSecureString
$User = New-ADUser -Name $uName -Accountpassword $Password -Enabled $true -ChangePasswordAtLogon 1
Add-ADGroupMember -Identity StandardUsers -Members $uName
