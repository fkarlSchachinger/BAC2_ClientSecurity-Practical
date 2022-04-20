$var = manage-bde.exe -status | Out-String
$test = select-string -pattern "Protection Off" -InputObject $var
$test

if($var.contains('Protection Status:    Protection Off')){
    manage-bde.exe -on C:
    Write-Host 'Bitlocker: Beginning Encryption of C: Drive after reboot'
    $title = 'Reboot for BitLocker Required:'
    $question = 'Reboot now (Y) or later (N)?'
    $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    if($decision -eq 0){
        Write-Host 'Rebooting now'
        Restart-Computer
    }else{
        Write-Host 'Reboot in 5 mins'
        #Start-Sleep -Seconds 300
        #Restart-Computer
    }
}else{
    Write-Host 'Already Encrypted'
}