<#
.SYNOPSIS
    Detects if the BitLocker key has been uploaded recently and if not, attempt to force an upload to Azure AD
.DESCRIPTION
    This script detects the presence of a recent Event ID (845) and if not present will look for a Recovery Key, generate one if not present and then attempt to force an upload to Azure AD.
    Once an event ID of 845 is seen, a registry key is written to mark the device as compliant.
.NOTES

.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Remediate-UploadBitLockerKeyAAD.ps1
    
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#region Variables
Param (
    $LogName = 'PR-UploadBitLockerKeyAAD',
    $ErrorActionPreference = 'Stop'
)
#endregion Variables

#region Functions
function Start-Log {
    Param (
        [Parameter(Mandatory = $false)]
        [string]$LogName,
        [Parameter(Mandatory = $false)]
        [string]$LogFolder = 'Intune',
        [Parameter(Mandatory = $false)]
        [string]$LogMaxSize = 10 #Mb
    )

    If (!($LogName)) {
        $Global:LogName = $MyInvocation.MyCommand.Name
    }

    If (!($LogName)) {
        $Global:LogName = "ScriptLog-$(Get-Date -Format FileDate)"
    }

    try {
        If (Test-Path $env:SystemRoot\CCM) {
            $LogPath = "$env:SystemRoot\CCM\Logs" # places the logfile in with all the other ConfigMgr logs
        }
        Else {
            If (!(Test-Path $env:SystemDrive\ProgramData\$LogFolder\Logs)) {
                New-Item $env:SystemDrive\ProgramData\$LogFolder\Logs -ItemType Directory -Force | Out-Null
            }
            $LogPath = "$env:SystemDrive\ProgramData\$LogFolder\Logs" # places the logfile in a Logs folder inside either the default of Intune or a folder of your choosing in the ProgramData directory
        }

        ## Set the global variable to be used as the FilePath for all subsequent Write-Log calls in this session
        $global:ScriptLogFilePath = "$LogPath\$LogName`.log"
        Write-Verbose "Log set to: $ScriptLogFilePath"

        If (!(Test-Path $ScriptLogFilePath)) {
            Write-Verbose "Creating new log file."
            New-Item -Path $ScriptLogFilePath -ItemType File | Out-Null
        }
        else {
            #Check if an existing log file is more than the max specified size (10Mb default) in size and restart it
            If (((Get-Item $ScriptLogFilePath).length / 1MB) -ge $LogMaxSize) {
                Write-Verbose "Log has reached maximum size, creating a new log file."
                Remove-Item -Path $ScriptLogFilePath -Force | Out-Null
                New-Item -Path $ScriptLogFilePath -ItemType File | Out-Null
            }
        }
    }
    catch {
        Write-Error $_.Exception.Message
    }
}

function Write-Log {
    Param (
        [Parameter(Mandatory = $false)]
        [string]$Component = $LogRegion,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet(1, 2, 3, 'Information', 'Warning', 'Error')]
        [string]$LogLevel = 1
    )

    If (!($Component)) {
        $Component = $MyInvocation.MyCommand.Name
    }

    If ($MyInvocation.ScriptLineNumber) {
        $Component = "$Component - Line: $($MyInvocation.ScriptLineNumber)"
    }

    switch ($LogLevel) {
        'Information' { [int]$LogLevel = 1 }
        'Warning' { [int]$LogLevel = 2 }
        'Error' { [int]$LogLevel = 3 }
        Default { [int]$LogLevel = $LogLevel }
    }

    Write-Verbose $Message
    $TimeGenerated = (Get-Date -Format "HH':'mm':'ss.ffffff")
    $Thread = "$([Threading.Thread]::CurrentThread.ManagedThreadId)"
    $Source = $MyInvocation.ScriptName
    $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="{5}" file="{6}">'
    $LineFormat = $Message, $TimeGenerated, (Get-Date -Format 'MM-dd-yyyy'), $Component, $LogLevel, $Thread, $Source
    $Line = $Line -f $LineFormat
    Try {
        $Line | Out-File -FilePath $ScriptLogFilePath -Encoding utf8 -Append
    }
    catch {
        Write-Verbose "Warning: Unable to append to log file - Retrying"
        Try {
            $Line | Out-File -FilePath $ScriptLogFilePath -Encoding utf8 -Append
        }
        catch {
            Write-Verbose "Error: Failed to append to log file"
        }
    }
}

function Backup-BitLockerKeyToAAD([string]$diskMountPoint, $keyProtectorId) {
    $Script:LogRegion = "Backup-BitLockerKeyToAAD"
    Write-Log -Message "Check if we can use BackupToAAD-BitLockerKeyProtector commandlet" -LogLevel 1
    $cmdName = "BackupToAAD-BitLockerKeyProtector"
    if (Get-Command $cmdName -ErrorAction SilentlyContinue) {
        Write-Log -Message "BackupToAAD-BitLockerKeyProtector commandlet exists" -LogLevel 1
        BackupToAAD-BitLockerKeyProtector -MountPoint $diskMountPoint -KeyProtectorId $keyProtectorId
    }
    else {

        Write-Log -Message "BackupToAAD-BitLockerKeyProtector commandlet not available, using other mechanism" -LogLevel 2
        Write-Log -Message "Get the AAD Machine Certificate" -LogLevel 1
        $cert = Get-ChildItem Cert:\LocalMachine\My\ | Where-Object { $_.Issuer -match "CN=MS-Organization-Access" }

        Write-Log -Message "Obtain the AAD Device ID from the certificate" -LogLevel 1
        $id = $cert.Subject.Replace("CN=", "")

        Write-Log -Message "Get the tenant name from the registry" -LogLevel 1
        $tenant = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\$($id)).UserEmail.Split('@')[1]

        Write-Log -Message "Generate the body to send to AAD containing the recovery information" -LogLevel 1
        Write-Log -Message "Get the BitLocker key information from WMI" -LogLevel 1
        (Get-BitLockerVolume -MountPoint $diskMountPoint).KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' } | ForEach-Object {
            $key = $_
            Write-Verbose "kid : $($key.KeyProtectorId) key: $($key.RecoveryPassword)"
            $body = "{""key"":""$($key.RecoveryPassword)"",""kid"":""$($key.KeyProtectorId.replace('{', '').Replace('}', ''))"",""vol"":""OSV""}"

            Write-Log -Message "Create the URL to post the data to based on the tenant and device information" -LogLevel 1
            $url = "https://enterpriseregistration.windows.net/manage/$tenant/device/$($id)?api-version=1.0"

            Write-Log -Message "Post the data to the URL and sign it with the AAD Machine Certificate" -LogLevel 1
            $req = Invoke-WebRequest -Uri $url -Body $body -UseBasicParsing -Method Post -UseDefaultCredentials -Certificate $cert
            $req.RawContent
        }
    }
    Remove-Variable -Name LogRegion -Scope Script
}

function Test-RegistryKeyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        # The path to the registry key where the value should be.
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        # The name of the value being set.
        $Name
    )

    if ( -not (Test-Path -Path $Path -PathType Container) ) {
        return $false
    }

    $properties = Get-ItemProperty -Path $Path 
    if ( -not $properties ) {
        return $false
    }

    $member = Get-Member -InputObject $properties -Name $Name
    if ( $member ) {
        return $true
    }
    else {
        return $false
    }

}

function Test-BitLockerKeyUploaded {
    If (Test-RegistryKeyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -Name 'RecoveryKeyUploaded') {
        If ((Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -Name 'RecoveryKeyUploaded') -eq "True") {
            Return $true
        }
        Else {
            Return $false
        }
    }
    Else {
        Return $false
    }
}

Function Test-BitLockerKeyUploadSuccess {
    $Script:LogRegion = "Test-BitLockerKeyUploadSuccess"
    Try {
        If (Get-WinEvent -FilterHashTable @{LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; ID = '845'; StartTime = $((Get-Date).AddHours(-1)); EndTime = $(Get-Date) } -ErrorAction Stop) {
            Write-Log -Message "Found EventID 845, upload successful" -LogLevel 1
            Return $true
        }
    }
    Catch {
        Write-Log -Message "Could not find log entry: $($_.Exception.Message)" -LogLevel 2
        Return $false
    }
    Remove-Variable -Name LogRegion -Scope Script
}

#endregion Functions

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Remediation Script Start"

If (Get-Item HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo -ErrorAction SilentlyContinue) {
    If (!(Test-BitLockerKeyUploaded)) {
        Try {
            Write-Log -Message "Starting Process, Getting volume information." -LogLevel 1 -Component "BitLocker Key Info"
            $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive
            If ($null -eq ($blv.KeyProtector | Where-Object KeyProtectorType -eq RecoveryPassword).KeyProtectorID) {
                Try {
                    Write-Log -Message "No Recovery Key available, generating one now." -LogLevel 2 -Component "BitLocker Key Info"
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
                    $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive
                }
                Catch {
                    Write-Log -Message "Failed to add Recovery Key." -LogLevel 3 -Component "BitLocker Key Info"
                }
            }
            Write-Log -Message "Volume Type:           $($blv.VolumeType)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Mount Point:           $($blv.MountPoint)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Volume Status:         $($blv.VolumeStatus)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Protection Status:     $($blv.ProtectionStatus)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Encryption Method:     $($blv.EncryptionMethod)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Lock Status:           $($blv.LockStatus)" -LogLevel 1 -Component "BitLocker Key Info"
            Write-Log -Message "Capacity (GB):         $($blv.CapacityGB)" -LogLevel 1 -Component "BitLocker Key Info"

            Write-Log -Message "Backing up Recovery Key to Azure AD" -LogLevel 1 -Component "BitLocker Key Backup"
            foreach ($RecKey in $(($blv.KeyProtector | Where-Object KeyProtectorType -eq RecoveryPassword).KeyProtectorID)) {
                Write-Log -Message "RecKey: $RecKey" -LogLevel 1 -Component "BitLocker Key Backup"
                            
                Backup-BitLockerKeyToAAD -diskMountPoint $env:SystemDrive -keyProtectorId $RecKey
            }

            $BLKeyUploaded = Test-BitLockerKeyUploadSuccess

            If ($BLKeyUploaded) {
                Write-Log -Message "Finished" -LogLevel 1 -Component "BitLocker Key Backup"
                New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo -Name "RecoveryKeyUploaded" -Value "True" -Force | Out-Null
            }
            Else {
                Write-Log -Message "Key failed to upload, will retry" -LogLevel 3 -Component "BitLocker Key Backup"
                New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo -Name "RecoveryKeyUploaded" -Value "False" -Force | Out-Null

                Exit 1
            }

            Exit 0
        }
        Catch {
            Write-Log -Message "Key failed to upload" -LogLevel 3 -Component "BitLocker Key Backup"
            Write-Log -Message "Error found: $($_.Exception.Message)" -LogLevel 3 -Component "BitLocker Key Backup"
            New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo -Name "RecoveryKeyUploaded" -Value "False" -Force | Out-Null

            Exit 1
        }
    }
    Else {
        Write-Log -Message "Key Already Uploaded to AAD." -LogLevel 1 -Component "BitLocker Key Info"
        Exit 0
    }
}
Else {
    Write-Log -Message "Device not Cloud Joined, not running" -LogLevel 1 -Component "BitLocker Key Info"
    Exit 1
}

#endregion Main Script