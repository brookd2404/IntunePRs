<#
.SYNOPSIS
    Detects if the Windows 11 built-in Teams (personal) app is present
.DESCRIPTION
    This script detect the presence of the built-in Microsoft Teams (for personal use) app that comes with Windows 11 and mark the device for remediation.
.NOTES

.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Detect-TeamsPersonalApp.ps1
    
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#region Variables
Param (
    $LogName = 'PR-TeamsPersonalApp'    
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

#endregion Functions

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Detection Script Start"

try {

    If ($null -eq (Get-AppxPackage -Name MicrosoftTeams -AllUsers)) {
        Write-Log -Message "Microsoft Teams Personal App not present" -LogLevel 1 -Component "Get-AppxPackage"
        Exit 0
    }
    Else {
        Write-Log -Message "Microsoft Teams Personal App present" -LogLevel 1 -Component "Get-AppxPackage"
        Exit 1
    }
    

}
catch {
    Write-Log -Message "An error occured during the PR detection script running" -LogLevel 3 -Component "Error Handling"
    Write-Log -Message "Unable to determine if app removal is needed or not, exiting with 0 to be safe" -LogLevel 3 -Component "Error Handling"
    Write-Log -Message $error[0].ToString() -LogLevel 3 -Component "Error Handling"
    Exit 0

}

#endregion Main Script
