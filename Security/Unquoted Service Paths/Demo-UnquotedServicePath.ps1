$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AdobeARMservice"
$GetValue = Get-ItemPropertyValue -Path $RegistryPath -Name ImagePath
Set-ItemProperty -Path $RegistryPath -Name ImagePath -Value $GetValue.Replace("`"","") -Force