Write-Host 'WinRM Services must be enabled on the Remote PC'
Write-Host 'Input Computer Name:'
$name = Read-Host
$cred = Get-Credential
$temp = 'XblAuthManager','XboxNetApiSvc','XblGameSave','XboxGipSvc','AxInstSV','PimIndexMaintenanceSvc_1a34cb0c','MapsBroker','lfsvc','NcbService','PhoneSvc','PcaSvc','RmSvc','SensorDataService','WalletService','wisvc';
$list = [System.Collections.ArrayList]$temp



Invoke-Command -ComputerName $name -Credential $cred -ScriptBlock{
    #Disable Unecessary Services
    foreach($item in $list){
        $new = Get-Service $item
        Set-Service -InputObject $new -StartUpType Disabled -Status Stopped 
    }
    #Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

    #Set TLS to 1.2 Version
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
}
