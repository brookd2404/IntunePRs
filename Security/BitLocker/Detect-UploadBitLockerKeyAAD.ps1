#region Variables
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
$Name = "RecoveryKeyUploaded"
$Type = "DWORD"
$Value = 'True'
#endregion

#region Main Script
Try {
    $Registry = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
    If ($Registry -eq $Value){
        Write-Output "Compliant"
        Exit 0
    } 
} 
Catch {
    Write-Warning "Not Compliant"
    Exit 1
}
#endregion Main Script