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
    $end = "=====Finished====="
    #Write-Verbose -Message "Starting Skript:"
    Write-Information "Creating Access_Mitigations Group Policy Object"
    $GPO_Access = New-GPO -Name "Access_Mitigations"  -Comment "Access Mitigations and Security Measures" #create new GPO
    $GPO_Firmware = New-GPO -Name "FirmwareSecurity"  -Comment "Firmware Security Measures" 
    $directory = Get-Location 
    $pathGPO = Join-Path -Path $directory -ChildPath '\GPO\'
    Import-GPO -BackupId E4DEFC66-A99C-4990-AA3F-FFA82C864C89 -TargetName Access_Mitigations -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    Import-GPO -BackupId 72A14C72-EC9D-46CE-9AC0-86C635CCBCAB -TargetName FirmwareSecurity -path $pathGPO.ToString() -CreateIfNeeded -Domain "Test.local"
    #link it to employee OU in AD
    New-GPLink -Guid $GPO_Access.Id -Target "OU=Employees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    New-GPLink -Guid $GPO_Firmware.Id -Target "OU=Employees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1

    #set lock screen timer
    #Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "InactivityTimeoutSecs" -Value 300 -Type DWord
    #Disable Autorun Feature
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "NoDriveTypeAutoRun" -Value 1 -Type DWord
    #Disable Device Installation
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyRemovableDevices" -Value 1 -Type DWord
    #Disabling automatic hotspot connections have to be done manually in GPO
    #Therefore importing pre-prepared GPO

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
    #$directory = Get-Location 
    #$pathGPO = Join-Path -Path $directory -ChildPath '\GPO\'
    
    return $end
}