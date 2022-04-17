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
    Get-Module -ListAvailable GroupPolicy
    Get-Module GroupPolicy
    $end = "=====Finished====="
    #Create Separate Policy
    $GPO = New-GPO -Name "FirmwareSecurity"  -Comment "Firmware Security Measures" 
    #link it to employee OU in AD
    New-GPLink -Guid $GPO.Id -Target "OU=Employees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    #Enable VirtualizationBasedSecurity for Windows Defender Credential Guard
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "RequireMicrosoftSignedBootChain" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\" -ValueName "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -ValueName "Enabled" -Value 1 -Type DWord
    Set-GPRegistryValue -Name "FirmwareSecurity" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -ValueName "Enabled" -Value 1 -Type DWord
    

    return $end
}