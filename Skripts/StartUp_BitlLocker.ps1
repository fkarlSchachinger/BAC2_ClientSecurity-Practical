$var = manage-bde.exe -status | Out-String
$test = select-string -pattern "Protection Off" -InputObject $var
$test

if($var.contains('Protection Status:    Protection Off')){
    manage-bde.exe -on C:
    Write-Host 'Bitlocker: Beginning Encryption of C: Drive'
}else{
    Write-Host 'test'
}