Param (
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo",
    $Name = "RecoveryKeyUploaded",
    $Type = "DWORD",
    $Value = 'True'
)
Remove-ItemProperty -Path $Path -Name $Name -ErrorAction Stop