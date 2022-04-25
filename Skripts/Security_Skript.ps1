<#
.SYNOPSIS
            ========================Security Implementation========================
######                                              #     #                                                    
#     # ######  ####  #    # #####  ####  #####     #     #   ##   #####  #####  ###### #    # # #    #  ####  
#     # #      #      #   #    #   #    # #    #    #     #  #  #  #    # #    # #      ##   # # ##   # #    # 
#     # #####   ####  ####     #   #    # #    #    ####### #    # #    # #    # #####  # #  # # # #  # #      
#     # #           # #  #     #   #    # #####     #     # ###### #####  #    # #      #  # # # #  # # #  ### 
#     # #      #    # #   #    #   #    # #         #     # #    # #   #  #    # #      #   ## # #   ## #    # 
######  ######  ####  #    #   #    ####  #         #     # #    # #    # #####  ###### #    # # #    #  ####  
                                                                                                               

    ©Franz-Karl Schachinger, https://github.com/fkarlSchachinger/
.DESCRIPTION
    Sets Auto-Lock Screen Registry
.EXAMPLE
    PS C:\> . ./AccessTheft.ps1 
    PS C:\> InitiateMitigations
    Explanation of what the example does
.INPUTS
    None
.OUTPUTS
    txt file
.NOTES
    ne
#>
function InitiateMitigations {
    Write-Host "Extracting and Removing ZIP";
    Expand-Archive .\GPO.zip
    Remove-Item .\GPO.zip
    Get-Module -ListAvailable GroupPolicy
    Get-Module GroupPolicy
    #Write-Verbose -Message "Starting Skript:"
    Write-Information "Creating Access_Mitigations Group Policy Object"
    $GPO_Access = New-GPO -Name "Access_Mitigations"  -Comment "Access Mitigations and Security Measures" #create new GPO
    $GPO_Firmware = New-GPO -Name "FirmwareSecurity"  -Comment "Firmware Security Measures" 
    $directory = Get-Location 
    $pathGPO = Join-Path -Path $directory -ChildPath '\GPO\'
    #Disabling automatic hotspot connections have to be done manually in GPO
    #Therefore importing pre-prepared GPO
    Import-GPO -BackupId E4DEFC66-A99C-4990-AA3F-FFA82C864C89 -TargetName Access_Mitigations -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    Import-GPO -BackupId 72A14C72-EC9D-46CE-9AC0-86C635CCBCAB -TargetName FirmwareSecurity -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    #link it to employee OU in AD
    New-GPLink -Guid $GPO_Access.Id -Target "OU=CMPEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    New-GPLink -Guid $GPO_Firmware.Id -Target "OU=CMPEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    #set lock screen timer
    #Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "InactivityTimeoutSecs" -Value 300 -Type DWord
    #Disable Autorun Feature
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "NoDriveTypeAutoRun" -Value 1 -Type DWord
    #Disable Device Installation
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyRemovableDevices" -Value 1 -Type DWord

    #Enable VirtualizationBasedSecurity for Windows Defender Credential Guard
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "RequireMicrosoftSignedBootChain" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
    $path = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    if(-not (Test-Path $path)){
        New-Item -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\" -Name "HypervisorEnforcedCodeIntegrity"
    }
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ValueName "Enabled" -Value 1 -Type DWord
    $path = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"
    if(-not (Test-Path $path)){
        New-Item -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\" -Name "SystemGuard"
    }
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -ValueName "Enabled" -Value 1 -Type DWord
    #Bitlocker enabling Skript
    #Skript can be found on Github and should be downloaded
    Write-Information 'Enabling BitLocker'
    .\StartUp_BitLocker.ps1
    #Create New User
    Write-Information 'Startung User Creation Script'
    .\CreateUser.ps1 
    #Create and Import StandardUser Policy Settings
    $GPO_StandardUser = New-GPO -Name "StandardUser"  -Comment "Default User Restrictions" 
    Import-GPO -BackupId 12406D13-7B68-4143-A90B-3EDFBFDCA4D3 -TargetName StandardUser -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    New-GPLink -Guid $GPO_StandardUser.Id -Target "OU=UsersEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1

    #Implement ASR Rules Settings
    .\SetASRRulesAndDefender.ps1
    #Implement Credential Guard
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LsaCfgFlags" -Value 1 -Type DWord

    #Implement Applocker Rule
    $GPO_Applocker = New-GPO -Name "Applocker"  -Comment "Restrict Executables, Scripts, Installation" 
    Import-GPO -BackupId 4CE1D07A-ED97-4DA8-A257-1A81A7B1EA89 -TargetName Applocker -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    New-GPLink -Guid $GPO_Applocker.Id -Target "OU=CMPEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1

    . .\ServicesAndProtocolls.ps1

    #Import MS Edge Standard of CIS 
    $GPO_Edge = New-GPO -Name "MsEdgeBaseline"  -Comment "MS Edge Baseline by CIS" 
    Import-GPO -BackupId 29D42EA1-A2E0-46D9-AEC4-9913624497BE -TargetName MsEdgeBaseline -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    New-GPLink -Guid $GPO_Edge.Id -Target "OU=UsersEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1

    #Import Monitring and Auditing Rules
    $GPO_Monitoring = New-GPO -Name "Monitoring"  -Comment "Monitoring and Auditing " 
    Import-GPO -BackupId 69593844-2A90-4D43-8C34-DAF6EDEA01E8 -TargetName Monitoring -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    New-GPLink -Guid $GPO_Monitoring.Id -Target "OU=UsersEmployees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    
    #Finally Update the GPO's on the target client
    Write-Host 'Input Remote Computer Name'
    $name = Read-Host 
    $cred = Get-Credential
    Invoke-Command -ComputerName $name -Credential $cred -ScriptBlock{
        gpupdate /force
    }

    #End of Measures, disable the admin account
    $user = whoami.exe | Out-String
    $userTrimmed = $user.Split("\")
    #net user $userTrimmed /active:no
}