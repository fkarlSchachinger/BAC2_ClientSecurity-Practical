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
    Write-Verbose -Message "Starting Skript:"
    $GPO = New-GPO -Name "Access_Mitigations"  -Comment "Access Mitigations and Security Measures" #create new GPO
    $GPO
    New-GPLink -Guid $GPO.Id -Target "OU=Employees,$((Get-AdDomain).DistinguishedName)" -LinkEnabled Yes -Order 1
    #set lock screen timer
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "InactivityTimeoutSecs" -Value 300 -Type DWord
    #Disable Autorun Feature
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -ValueName "NoDriveTypeAutoRun" -Value 1 -Type DWord
    #Disable Device Installation
    Set-GPRegistryValue -Name "Access_Mitigations" -Key "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -ValueName "DenyRemovableDevices" -Value 1 -Type DWord
    #Disabling automatic hotspot connections have to be done manually in GPO
    #Therefore importing pre-prepared GPO
    $directory = Get-Location
    $path = Join-Path -Path $directory -ChildPath '\GPO\'
    Import-GPO -BackupId E4DEFC66-A99C-4990-AA3F-FFA82C864C89 -TargetName Access_Mitigations -path 'C:\Users\Franz\Desktop\Skripts\gpo' -CreateIfNeeded -Domain "Test.local"
    return $end
}