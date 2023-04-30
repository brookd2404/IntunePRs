<#
.SYNOPSIS
    This script will remediate unquoted service paths on a device.
.DESCRIPTION
    This script will remediate unquoted service paths on a device.
.LINK
    https://www.tenable.com/plugins/nessus/63155
    https://github.com/brookd2404/IntunePRs/tree/main/Security/Unquoted%20Service%20Paths
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a Remediation script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a Remediation script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>


#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = 'PR-UnquotedServicePaths',
    [Parameter()]
    [array]$BaseKeys = @(
        "HKLM:\System\CurrentControlSet\Services", #Services
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", #32bit Uninstalls
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" #64bit Uninstalls
    ),
    [Parameter(HelpMessage = "RegEx that matches values containing .exe with a space in the exe path and no double quote encapsulation.")]
    [string]$Script:ValueRegEx = '(^(?!\u0022).*\s.*\.[Ee][Xx][Ee](?<!\u0022))(.*$)',
    [Parameter()]
    [bool]$LogRemediaionKeys = $True
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
Write-Log -Message "RegEx to match values: $ValueRegEx" -LogLevel 1 -Component "Remediation Script Start"
try {
    #Set Return Array for the Exit Code
    $ReturnValue = @()
    #Blacklist for keys to ignore
    $BlackList = $Null
    #Create an ArrayList to store results in
    $Values = New-Object System.Collections.ArrayList
    #Discovers all registry keys under the base keys
    $DiscKeys = Get-ChildItem -Recurse -Directory $BaseKeys -Exclude $BlackList -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name | % { ($_.ToString().Split('\') | Select-Object -Skip 1) -join '\' }
    Write-Log -Message "Found $($DiscKeys.Count) registry keys to check" -LogLevel 1 -Component "Remediation - Registry Scan"
    #Open the local registry
    Write-Log -Message "Opening registry" -LogLevel 1 -Component "Remediation - Registry Action"
    $Registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')
    ForEach ($RegKey in $DiscKeys) {
        #Open each key with write permissions
        IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Opened $RegKey" -LogLevel 1 -Component "Remediation - Registry Action" }
        Try { 
            $ParentKey = $Registry.OpenSubKey($RegKey, $True)
            IF (-Not($LogRemediaionKeys)) { Write-Log -message "Opened $ParentKey" -LogLevel 1 -Component "Remediation - Registry Action" }
        }
        Catch { 
            Write-Debug "Unable to open $RegKey"
            Write-Log -Message "Unable to open $RegKey" -LogLevel 3 -Component "Remediation - Registry Action"
        }
        #Test if registry key has values
        IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Checking if $RegKey has values" -LogLevel 1 -Component "Remediation - Registry Scan" }
        If ($ParentKey.ValueCount -gt 0) {
            IF (-Not($LogRemediaionKeys)) { Write-Log -Message "$RegKey has $($ParentKey.ValueCount) values" -LogLevel 1 -Component "Remediation - Registry Scan" }
            #Get all values that match the RegEx
            $MatchedValues = $ParentKey.GetValueNames() | ? { $_ -eq "ImagePath" -or $_ -eq "UninstallString" }
            IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Found $($MatchedValues.Count) values to check" -LogLevel 1 -Component "Remediation - Registry Scan" }
            ForEach ($Match in $MatchedValues) {
                $Value = $ParentKey.GetValue($Match)
                IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Value Matched: $Value" -LogLevel 1 -Component "Remediation - Registry Scan" }
                #Test if value matches RegEx
                If ($Value -match $ValueRegEx) {
                    IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Value $Value in $RegKey matches RegEx" -LogLevel 1 -Component "Remediation - Registry Scan" }
                    $RegType = $ParentKey.GetValueKind($Match)
                    IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Value $Value is of type $RegType" -LogLevel 1 -Component "Remediation - Registry Scan" }
                    If ($RegType -eq "ExpandString") {
                        IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Value $Value is of type ExpandString, Doing extra work to expand." -LogLevel 1 -Component "Remediation - Registry Scan" }
                        #Get the value without expanding the environmental names
                        $Value = $ParentKey.GetValue($Match, $Null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        $Value -match $ValueRegEx
                    }
                    #Uses the matches from the RegEx to build a new entry encapsulating the exe path with double quotes
                    $Correction = "$([char]34)$($Matches[1])$([char]34)$($Matches[2])"
                    IF (-Not([String]::IsNullOrEmpty($Correction))) {
                        Try { 
                            Write-Log -Message "Writing $Correction to $ParentKey" -LogLevel 1 -Component "Remediation - Registry Configuration"
                            $ParentKey.SetValue("$Match", "$Correction", [Microsoft.Win32.RegistryValueKind]::$RegType)
                            Write-Log -Message "Successfully wrote $Correction to $ParentKey" -LogLevel 1 -Component "Remediation - Registry Configuration"
                            "Successfully wrote $Correction to $ParentKey"
                        }
                        Catch {
                            Write-Log -Message "Failed to write $Correction to $ParentKey" -LogLevel 3 -Component "Remediation - Registry Configuration"
                            Write-Debug "Unable to write to $ParentKey"
                        }
                        #Add a hashtable containing details of corrected key to ArrayList
                        $Values.Add((New-Object PSObject -Property @{
                                    "Name"       = $Match
                                    "Type"       = $RegType
                                    "Value"      = $Value
                                    "Correction" = $Correction
                                    "ParentKey"  = "HKEY_LOCAL_MACHINE\$RegKey"
                                })) | Out-Null
                    }
                    
                }
            }
        }
        $ParentKey.Close()
        IF (-Not($LogRemediaionKeys)) { Write-Log -Message "Closing Parent Key" -LogLevel 1 -Component "Remediation - Registry Action" }
    }
    $Registry.Close()
    Write-Log -Message "Closed registry" -LogLevel 1 -Component "Remediation - Registry Action"
    $Values | Select-Object ParentKey,Value,Correction,Name,Type
}
catch {
    Write-Log -Message "Error: $_" -LogLevel 3 -Component "Remediation - Registry Scan"
    Exit 1
}
#endregion Main Script