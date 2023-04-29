<#
.SYNOPSIS
    Detects if the registry key from a successful remediation script for BitLocker Key Upload is present or not
.DESCRIPTION
    This script detect the presence of a specific registry key and if present marks the device as remediation NOT being required.
.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Detect-UploadBitLockerKeyAAD.ps1
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#region Variables
Param (
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo",
    $Name = "RecoveryKeyUploaded",
    $Type = "DWORD",
    $Value = 'True'
)
#endregion Variables

#region Main Script
Try {
    $Registry = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
    If ($Registry -eq $Value){
        Write-Output "Compliant"
        Exit 0
    }
    else {
        Write-Warning "Not Compliant"
        Exit 1
    } 
} 
Catch {
    Write-Warning "Not Compliant"
    Exit 1
}
#endregion Main Script