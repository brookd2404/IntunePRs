<#
.SYNOPSIS
    This script is used to detect if the printer inventory has been updated in the last 7 Days.
.DESCRIPTION
    This script is used to detect if the printer inventory has been updated in the last 7 Days. If it has not been updated in the last 7 days then the script will return a value of 1 to indicate that a remediation is needed. If the printer inventory has been updated in the last 7 days then the script will return a value of 0 to indicate that a remediation is not needed.
.LINK
    https://github.com/brookd2404/IntunePRs/tree/main/Inventory/Printer%20Inventory/Detect-PrinterInventory.ps1
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = "PR-PrinterInventory",
    [Parameter()]
    [string]$LogFolder = "",
    [parameter()]
    [string]$RegLastSyncLocation = "HKLM:\Software\ProactiveRemediation\Inventory-Printer"
)

#region Functions
function Start-Log {
    <#
    .SYNOPSIS
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr.
    .DESCRIPTION
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr.
    .PARAMETER LogName
        The name of the log file to be created. If not specified, the name of the script will be used.
    .PARAMETER LogFolder
        The name of the folder to be created in the ProgramData directory to store the log file. If not specified, the default of Intune will be used.
    .PARAMETER LogMaxSize
        The maximum size in Mb of the log file before it is restarted. If not specified, the default of 10Mb will be used.
    .EXAMPLE
        Start-Log
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr.
    .EXAMPLE
        Start-Log -LogName "MyLog"
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr with the name MyLog.log.
    .EXAMPLE
        Start-Log -LogName "MyLog" -LogFolder "MyFolder"
        Creates a log file in the CCM\Logs folder or in the ProgramData\MyFolder\Logs folder if the device is not managed by ConfigMgr with the name MyLog.log.
    #>
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
    <#
    .SYNOPSIS
        Writes a message to the log file.
    .DESCRIPTION
        Writes a message to the log file.
    .PARAMETER Message
        The message to be written to the log file.
    .PARAMETER LogLevel
        The level of the message to be written to the log file. Valid values are 1, 2, 3, Information, Warning, Error. Default is 1.
    .EXAMPLE
        Write-Log -Message "This is a test message"
        Writes a message to the log file.
    .EXAMPLE
        Write-Log -Message "This is a test message" -LogLevel 2
        Writes a message to the log file with a log level of 2.
    #>
    Param (
        [Parameter(Mandatory = $false)]
        [string]$Component,

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
#endregion Functions
#region Main Script
Start-Log -LogName $LogName -LogFolder $LogFolder
Write-Log -Message "Proactive Remediation Detection Script Starting" -LogLevel Information
Write-Log -Message "Checking if the last sync was more than 7 days ago" -LogLevel Information
try {
    IF (-NOT(Get-ItemProperty -Path $RegLastSyncLocation  -Name "LastSync" -ErrorAction SilentlyContinue)) {
        write-log -Message "LastSync key not found in registry, assuming this is the first sync, Exit Code: 1" -LogLevel Information
        Exit 1
    }
    ELSE {
        Write-Log -Message "LastSync key found in registry, checking if it was more than 7 days ago" -LogLevel Information
        $LastSyncDT = [DateTime]::Parse((Get-ItemProperty -Path $RegLastSyncLocation  -Name "LastSync" -ErrorAction SilentlyContinue).LastSync)
        Write-Log -Message "Last Sync was on $($LastSyncDT.ToString())" -LogLevel Information
        $TimeSpan = New-TimeSpan -Start $LastSyncDT -End (Get-Date)
        Write-Log -Message "Time since last sync is $($TimeSpan.days) days" -LogLevel Information
        IF ($TimeSpan.days -ge 7) {
            Write-Log -Message "Last sync was more than 7 days ago, Exit Code: 1" -LogLevel Information
            Exit 1
        }
        ELSE {
            Write-Log -Message "Last sync was less than 7 days ago, Exit Code: 0" -LogLevel Information
            Exit 0
        }  
    }
}
catch {
    Write-Log -Message "Error: $($_.Exception.Message)" -LogLevel Information
    Exit 1
}
#endregion