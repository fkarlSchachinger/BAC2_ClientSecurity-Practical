$GPO_ASR = New-GPO -Name "ASR_Rules"  -Comment "Setting all ASR Rules to block Mode" #create new GPO
New-GPLink -Guid $GPO_ASR.Id -Target "OU=CMPEmployees, $((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1

$directory = Get-Location 
$pathGPO = Join-Path -Path $directory -ChildPath '\GPO\'
$GPO_Defender =New-GPO -Name "Defender"  -Comment "All Defender settings excluding ASR Rules" #create new GPO
Import-GPO -BackupId EB076832-10FF-439D-AE58-3E7FF0ABB799 -TargetName Defender -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
New-GPLink -Guid $GPO_Defender.Id -Target "OU=CMPEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1


Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "56a863a9-875e-4185-98a7-b882c64b5ce5" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "01443614-cd74-433a-b99e-2ecdc07bfc25" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "d3e037e1-3eb8-44c8-a917-57927947596d" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "3b576869-a4ec-4529-8536-b80a7769e899" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "26190899-1602-49e8-8b27-eb1d0a1ce869" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "e6db77e5-3df2-4cf1-b95a-636979351e5b" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -Value 1 -Type DWord
Set-GPRegistryValue -Name "ASR_Rules" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName "c1db55ab-c21a-4637-bb3f-a12568109d35" -Value 1 -Type DWord

Write-Host '====================================Finished Defender SetUp===================================='

#Implement File Redirection
$GPO_FileRedirection = New-GPO -Name "ScriptRedirection" -Comment "Redirects common script files to notepad"
Import-GPO -BackupId E962C0C0-70C9-4AC8-8D39-9955BC760896 -TargetName ScriptRedirection -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
New-GPLink -Guid $GPO_FileRedirection.Id -Target "OU=UsersEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1