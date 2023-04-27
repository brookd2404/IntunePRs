<#
.SYNOPSIS
    This script is used to Remediate the current configuration of Adobe Reader in the User Context. It is used in the Proactive Remediation process.
.DESCRIPTION
    This script is used to Remediate the current configuration of Adobe Reader in the User Context. It is used in the Proactive Remediation process.
.NOTES
    This is based on the NSA guidenlines for Adobe Reader (https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2905591/nsa-recommends-adobe-acrobat-reader-security-configurations/)
.LINK
    https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2905591/nsa-recommends-adobe-acrobat-reader-security-configurations/
.NOTES
    Remember, for Proactive Remediations use:
        - "Write-Output 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Write-Output 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>


#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = 'PR-AdobeConfiguration',
    [Parameter()]
    [object]$HKLMRegMap = @{
        "bEnableAlwaysOutlookAttachmentProtectedView" = 'HKCU:\Software\Adobe\Acrobat Reader\DC\TrustManager'
        "iURLPerms"                                   = 'HKCU:\Software\Adobe\Acrobat Reader\DC\TrustManager\cDefaultLaunchURLPerms'
        "tBuiltInPermList"                            = 'HKCU:\Software\Adobe\Acrobat Reader\DC\TrustManager\cDefaultLaunchURLPerms'
    },
    [object]$RegValueMap = @{
        "bEnableAlwaysOutlookAttachmentProtectedView" = 0 #Enables Protected View for Outlook (https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/TrustManager.html#idkeyname_1_28652)
        "iURLPerms"                                   = 1 #Blocks All Websites (https://www.adobe.com/devnet-docs/acrobatetk/tools/PrefRef/Windows/TrustManager.html#idkeyname_1_27271)
        "tBuiltInPermList"                            = "Version:1|https://eu365.com:1|" # version:1|<site>:<1-3>|...(1 is always ask; 2 is always allow, 3 is always block)
    }
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
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Remediation Script Start"

try {
    FOREACH ($Key in $HKLMRegMap.Keys) {
        $RegKey = Get-ItemProperty -Path $HKLMRegMap[$key] -Name $Key -ErrorAction SilentlyContinue
        IF ($null -ne $RegKey) {
            IF ($RegKey.$($key) -eq $RegValueMap[$key]) {
                Write-Log -Message "Registry Key $($RegKey.$($key)) - $Key already has a value of $($RegValueMap[$key])" -LogLevel 1 -Component "HKLM Remediate"
            }
            ELSE {
                Set-ItemProperty -Path $HKLMRegMap[$key] -Name $Key -Value $RegValueMap[$key] -Force 
                Write-Log -Message "Registry Key $($RegKey.$($key)) - $Key Remediated, the value is now $($RegValueMap[$key])" -LogLevel 1 -Component "HKLM Remediate"
            }
        }
        ELSE {
            $Type = $RegValueMap[$key].GetType().Name
            Switch ($Type) {
                {$_ -match "String|boolean"} {
                    $PropertyType = "String"
                }
                {$_ -match "Int32|Int64"} {
                    $PropertyType = "DWORD"
                }
            }
            IF(-NOT(Test-Path -Path "$($HKLMRegMap[$key])")) {
                New-Item -Path "$($HKLMRegMap[$key])" -Force | Out-Null
            }
            New-ItemProperty -Path $HKLMRegMap[$key] -Name $Key -Value $RegValueMap[$key] -PropertyType $PropertyType -Force
            Write-Log -Message "Registry Key $($RegKey.$($key)) - $Key Remediated, the value is now $($RegValueMap[$key])" -LogLevel 1 -Component "HKLM Remediate"
        }
    }
}
catch {
    Write-Log -Message "Error: $($_.Exception.Message)" -LogLevel 3 -Component "Error"
    EXIT 1
}
