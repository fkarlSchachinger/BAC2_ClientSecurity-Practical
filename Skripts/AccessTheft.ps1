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
    $end = "Finished"
    Write-Verbose -Message "Starting Skript:"
    New-ItemProperty -Path "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverTimeOut" -Value "500" -PropertyType "String"
   
    return $end
}