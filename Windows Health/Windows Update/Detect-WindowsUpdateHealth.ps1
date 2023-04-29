<#
.SYNOPSIS
    Detects if a repair of the Windows Update components is required or not
.DESCRIPTION
    This script checks when Windows updates were last scanned for, installed and when the last repair was attempted to decide if remediation is required.
.NOTES
    Use the InstalledMonthsGrace and RepairRerunDays to adjust the frequency of running.
    It is recommended to deploy this to a dynamic AAD group based on the lowest build number acceptible within your environment and keep that maintained and incremented as required.
.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Detect-WindowsUpdateHealth.ps1
    Detect-WindowsUpdateHealth.ps1 -InstalledMonthsGrace 3
    Detect-WindowsUpdateHealth.ps1 -InstalledMonthsGrace 3 -RepairRerunDays 14
    Detect-WindowsUpdateHealth.ps1 -RepairRerunDays 30

.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#region Variables
#$VerbosePreference = "Continue"
Param (
    [Parameter(Mandatory = $false)]
    [string]$Company = 'PowerON',
    [Parameter(Mandatory = $false)]
    [string]$LogName = 'PR-WindowsUpdateHealth',
    [Parameter(Mandatory = $false)]
    [Int]$InstalledMonthsGrace = 3,
    [Parameter(Mandatory = $false)]
    [Int]$RepairRerunDays = 14
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
        Add-Content -Value $Line -Path $ScriptLogFilePath -Encoding 'utf8'
    }
    catch {
        Write-Verbose "Warning: Unable to append to log file - Retrying"
        Try {
            Add-Content -Value $Line -Path $ScriptLogFilePath -Encoding 'utf8'
        }
        catch {
            Write-Verbose "Error: Failed to append to log file"
        }
    }
}
Function Set-RegistryKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, HelpMessage = "Please Enter Registry Item Path", Position = 1)]
        $Path,
        [Parameter(Mandatory = $True, HelpMessage = "Please Enter Registry Item Name", Position = 2)]
        $Name,
        [Parameter(Mandatory = $True, HelpMessage = "Please Enter Registry Property Item Value", Position = 3)]
        $Value,
        [Parameter(Mandatory = $False, HelpMessage = "Please Enter Registry Property Type", Position = 4)]
        $PropertyType = "DWORD"
    )

    Try {
        Write-Log -Message "Setting registry [$Path] property [$Name] to [$Value]"

        # If path does not exist, create it
        If ( (Test-Path $Path) -eq $False ) {
            Write-Verbose "Creating new registry keys"
            $null = New-Item -Path $Path -Force
        }

        # Update registry value, create it if does not exist (DWORD is default)
        Write-Log -Message "Working on registry path [$Path]"
        $itemProperty = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        If ($null -ne $itemProperty) {
            Write-Log -Message "Setting registry property [$Name] to [$Value]"
            $itemProperty = Set-ItemProperty -Path $Path -Name $Name -Value $Value
        }
        Else {
            Write-Log -Message "Creating new registry property [$Name] to [$Value]"
            $itemProperty = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType
        }
    }
    catch {
        Write-Log -Message "Something went wrong writing registry property"
    }
}

#endregion Functions

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Windows Update Health Detection Script Starting" -LogLevel 1 -Component "Detection Script Start"

try {
    try {
        $WindowsUpdateRepairedRecently = (Get-ItemPropertyValue -Path HKLM:\Software\$Company\Remediations\WindowsUpdate -Name WindowsUpdateRepaired -ErrorAction SilentlyContinue) -gt (Get-Date).AddDays(-$RepairRerunDays)
    }
    catch {
        $WindowsUpdateRepairedRecently = $false
    }
    
    $WUInfo = (New-Object -ComObject Microsoft.Update.AutoUpdate)
    Write-Log -Message "Last WU Search Date: $($WUInfo.Results.LastSearchSuccessDate)" -LogLevel 1 -Component "Detection Script Start"
    Write-Log -Message "Last WU Install Date: $($WUInfo.Results.LastInstallationSuccessDate)" -LogLevel 1 -Component "Detection Script Start"
    
    $InstalledWithinGrace = $WUInfo.Results.LastInstallationSuccessDate -gt (Get-Date).AddMonths(-$InstalledMonthsGrace)
    $ScannedWithinGrace = $WUInfo.Results.LastSearchSuccessDate -gt (Get-Date).AddDays(-14)

    If (-not($InstalledWithinGrace -and $ScannedWithinGrace -and $WindowsUpdateRepairedRecently)) {
        Write-Log -Message "Needs Update Repair" -LogLevel 3 -Component "Detection Method"
        Set-RegistryKey -Path HKLM:\Software\$Company\Remediations\WindowsUpdate -Name WindowsUpdateRepaired -Value ''
        Exit 1
    }
    else {
        Write-Log -Message "No repairs needed" -LogLevel 1 -Component "Detection Method"
        Exit 0
    }    
}
catch {
    Write-Log -Message "An error occured during the PR detection script running" -LogLevel 3 -Component "Error Handling"
    Write-Log -Message "Unable to determine if repair is needed or not, exiting with 1 to be safe to force a remediation" -LogLevel 3 -Component "Error Handling"
    Write-Log -Message $error[0].ToString() -LogLevel 3 -Component "Error Handling"
    Exit 1
}

#endregion Main Script
