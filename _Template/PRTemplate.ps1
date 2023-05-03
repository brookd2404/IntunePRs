<#
.SYNOPSIS
    A short one-line action-based description, e.g. 'Tests if a function is valid'
.DESCRIPTION
    A longer description of the script, its purpose, common use cases, etc.
.LINK
    Specify a URI to a help page, this will show when Get-Help -Online is used.
.EXAMPLE
    Test-MyTestFunction -Verbose
    Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
.NOTES
    Information or caveats about the function e.g. 'This function is not supported in Linux'
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remediation script that it was remediated successfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remediation script that the remediation failed 
#>

<#
#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
example:
param(
    [Parameter()]
    [string]$LogName = 'PR-MyPRName'
    [Parameter()]
    [string]$RegPath = "HKLM:\Software\Policies...",
    [Parameter()]
    [string]$RegKey = "MyRegKey",
    [Parameter()]
    [string]$RegType = "DWord",
    [Parameter()]
    [int]$RegValue = 1
)
#>

#region Functions
function Start-Log {
    <#
    .SYNOPSIS
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch.
    .DESCRIPTION
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch.
    .PARAMETER LogName
        The name of the log file to be created. If not specified, the name of the script will be used.
    .PARAMETER LogFolder
        The name of the folder to be created in the ProgramData directory to store the log file. If not specified, the default of Intune will be used.
    .PARAMETER LogMaxSize
        The maximum size in Mb of the log file before it is restarted. If not specified, the default of 10Mb will be used.
    .EXAMPLE
        Start-Log
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch.
    .EXAMPLE
        Start-Log -LogName "MyLog"
        Creates a log file in the CCM\Logs folder or in the ProgramData\Intune\Logs folder if the device is not managed by ConfigMgr or Autopatch with the name MyLog.log.
    .EXAMPLE
        Start-Log -LogName "MyLog" -LogFolder "MyFolder"
        Creates a log file in the CCM\Logs folder or in the ProgramData\MyFolder\Logs folder if the device is not managed by ConfigMgr or Autopatch with the name MyLog.log.
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
    .PARAMETER Component
        The component helps identify in the logs which component you are looking at.
    .EXAMPLE
        Write-Log -Message "This is a test message"
        Writes a message to the log file.
    .EXAMPLE
        Write-Log -Message "This is a test message" -LogLevel 2
        Writes a message to the log file with a log level of 2 (Warning).
    .EXAMPLE
        Write-Log -Message "This is a test message" -LogLevel 2 -Component "Testing"
        Writes a message to the log file with a log level of 2 (Warning) marked as component Testing.
    #>
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
#endregion Functions

<#
Main script body starts here.
#>

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Script Start"

try {
    <# Attempt the following code #>

}
catch {
    <# Do this if a terminating exception happens #>

}

#endregion

<# Remove the commenting from this section to use if required.

#Region Cleanup
# This region can be enabled to remove the Proactive Remediation script from device in case of sensitive data being used in the script.
# Based on idea from: https://www.systanddeploy.com/2022/05/removing-automatically-proactive.html

$PR_Directory = (Get-Item $($MyInvocation.MyCommand.Path)).DirectoryName
$Remove_Script_Path = "$env:TEMP\Cleanup-Proactive-Remediation.ps1"

$Remove_Script = @"
Do {  
    `$ProcessesFound = Get-CimInstance -ClassName Win32_Process | Where-Object CommandLine -Like "*$PR_Directory*" 
    If (`$ProcessesFound) {
        Start-Sleep 5
    }
} Until (!`$ProcessesFound)
Remove-Item -Path $PR_Directory -Force -Recurse
"@

$Remove_Script | Out-File $Remove_Script_Path
Start-Process -FilePath powershell.exe $Remove_script_Path -WindowStyle Hidden
#endregion

#>
