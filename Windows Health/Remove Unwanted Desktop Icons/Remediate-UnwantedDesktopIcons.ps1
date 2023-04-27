<#
.SYNOPSIS
    This Script is used to detect if remediation is required for unwanted desktop icons.
.DESCRIPTION
    This Script is used to detect if remediation is required for unwanted desktop icons. It will check the desktop for any shortcuts that match the specified extensions and contain the specified text.
.LINK
    https://github.com/brookd2404/IntunePRs/tree/main/Windows%20Health/Remove%20Unwanted%20Desktop%20Icons
.NOTES
    It does support RegEx... However, becareful what you wish for, it will be good to run it with just a detection for a while to see what it finds before you start deleting things.
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = 'PR-UnwantedDesktopIcons',
    [Parameter()]
    [array] $extensions = @(
        ".lnk",
        ".html",
        ".exe"
    ),
    [Parameter()]
    [array]$contains = @(
        $env:COMPUTERNAME,
        "Copy",
        "\(\d+\)" #RegEx to Match to find (1), (2), etc.
    ),
    [Parameter()]
    [string]$desktopPath = (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders").Desktop,
    [Parameter(HelpMessage = "Move the files to the Recycle Bin instead of deleting them")]
    [bool]$Recycle = $true
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
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Script Start - Remediation"

try {
    #Create Blank Array to store the files that match the criteria
    $remediationArray = @()
    #Checks if the Recycle parameter is set to true, then creates a shell object to access the recycle bin
    IF ($Recycle) {
        Write-Log -Message "Recycle is set to $Recycle" -LogLevel 1 -Component "Recycle Shell Load"
        $shell = New-Object -ComObject Shell.Application  
    }
    Write-Log -Message "Getting Desktop Items matching Exention Criteria" -LogLevel 1 -Component "Get Desktop Items"
    #Only return files that match the extension criteria
    $files = Get-ChildItem -Path $desktopPath -File | Where-Object { $_.Extension -in $extensions }
    Write-Log -Message "Found $($files.Count) Desktop Items matching Exention Criteria" -LogLevel 1 -Component "Get Desktop Items"
    $files | ForEach-Object {
        $file = $_
        FOREACH ($contain in $contains) {
            IF ($file.Name -match $contain) {
                try {
                    Write-Log -Message "Attempting to remediate $($file.Name) containing $($contain)" -LogLevel 2 -Component "Remediation - File"
                    IF ($Recycle) {
                        $item = $shell.Namespace(0).ParseName("$($file.FullName)")
                        $item.InvokeVerb("delete")
                    }
                    ELSE {
                        Remove-Item $file.FullName -Force -ErrorAction Stop
                    }
                    Write-Log -Message "Remediated $($file.Name) containing $($contain)" -LogLevel 1 -Component "Remediation - File"
                    $remediationArray += $file
                }
                catch {
                    Write-Log -Message "Error: $($_.Exception.Message)" -LogLevel 3 -Component "Remediation - File"
                }
            }
        }
    }

    Write-Log -Message "Remediated $($remediationArray.Count) Desktop Items" -LogLevel 1 -Component "Remediation - File"

}
catch {
    Write-Log -Message "Error: $($_.Exception.Message)" -LogLevel 3 -Component "Script Error"
}
#endregion
