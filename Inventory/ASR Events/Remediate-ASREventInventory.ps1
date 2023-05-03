<#
.SYNOPSIS
    This Proactive Remediation script will inventory ASR events and send them to a Log Analytics Workspace.
.DESCRIPTION
    This Proactive Remediation script will inventory ASR events and send them to a Log Analytics Workspace.
.NOTES
    If Microsoft decide to alter the format of the ASR events, this script will need to be updated.
.LINK
    https://github.com/brookd2404/IntunePRs/tree/main/Inventory/ASR%20Events
.NOTES
    DO NOT FORGET TO SET THE PARAMETERS AT THE TOP OF THE SCRIPT
    
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remediation script that it was remediated successfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remediation script that the remediation failed 
#>

#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = 'PR-ASRInventory',
    [Parameter(HelpMessage = "The number of hours to inventory ASR events. Default is 24.")]
    [int]$HourstoInventory = 24,
    [Parameter()]
    [string]$EventLogName = "Microsoft-Windows-Windows Defender/Operational",
    [parameter(HelpMessage = "The workspace ID of the Log Analytics Workspace that you want to send the data to.")]
    [string]$workspaceID = "<GUID>",
    [parameter(HelpMessage = "The primary key of the Log Analytics Workspace that you want to send the data to.")]
    [string]$primaryKey = "<GUID>",
    [parameter(HelpMessage = "The name of the Log Analytics table that you want to send the data to.")]
    [string]$LogType = "ASREvents",
    [parameter(HelpMessage = "The name of the field that will be used as the timestamp in the Log Analytics data.")]
    [string]$TimeStampField = "InventoryTime"
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
Function Build-Signature ($workspaceID, $primaryKey, $date, $contentLength, $method, $contentType, $resource) {
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($primaryKey)
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $workspaceID, $encodedHash
    return $authorization
}
# Create the function to create and post the request
Function Post-LogAnalyticsData($workspaceID, $primaryKey, $body, $logType) {
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -workspaceID $workspaceID `
        -primaryKey $primaryKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $workspaceID + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }
    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}
#endregion Functions

<#
Main script body starts here.
#>

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Script Start"

try {
    <#
        Get ASR Events from the last x number of hours
        EventID Details
        1121 = Block Mode Operation
        1122 = Audit Mode Operation
        1129 = User allowed an otherwise blocked operation 
    #>
    #Hash Table with the Event Types and GUIDS
    $guidTable = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" =	"AsrVulnerableSignedDriver"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" =	"AsrAdobeReaderChildProcess"
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" =	"AsrOfficeChildProcess"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" =	"AsrLsassCredentialTheft"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" =	"AsrExecutableEmailContent"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" =	"AsrUntrustedExecutable"
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" =	"AsrObfuscatedScript"
        "d3e037e1-3eb8-44c8-a917-57927947596d" =	"AsrScriptExecutableDownload"
        "3b576869-a4ec-4529-8536-b80a7769e899" =	"AsrExecutableOfficeContent"
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" =	"AsrOfficeProcessInjection"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" =	"AsrOfficeCommAppChildProcess"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" =	"AsrPersistenceThroughWmi"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" =	"AsrPsexecWmiChildProcess"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" =	"AsrUntrustedUsbProcess"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" =	"AsrOfficeMacroWin32ApiCalls"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" =	"AsrRansomware"
    }
    $DsregCmdStatus = dsregcmd /status
    if ($DsregCmdStatus -match "DeviceId") {
        $DeviceId = ($DsregCmdStatus -match "DeviceID")
        $DeviceId = ($DeviceId.Split(":").trim())
        $DeviceId = $DeviceId[1]
    }

    Write-Log -Message "Checking for ASR events in the last $HourstoInventory hours" -LogLevel 1 -Component "ASR Event Check"
    $ASREvents = Get-WinEvent -LogName $EventLogName | Where-Object {
    ($_.ID -match "1121|1122|1129") -and (
            (
                New-TimeSpan -Start $_.TimeCreated `
                    -End (Get-Date)
            ).Hours -le $HourstoInventory
        )
    }
    Write-Log -Message "Found $($ASREvents.Count) ASR events in the last $HourstoInventory hours" -LogLevel 1 -Component "ASR Event Check"
    Write-Log -Message "Number of Blocked ASR Events: $(($ASREvents | Where-Object {$_.ID -eq 1121}).Count)" -LogLevel 2 -Component "ASR Event Check"
    Write-Log -Message "Number of Audit ASR Events: $(($ASREvents | Where-Object {$_.ID -eq 1122}).Count)" -LogLevel 2 -Component "ASR Event Check"
    Write-Log -Message "Number of Allowed ASR Events: $(($ASREvents | Where-Object {$_.ID -eq 1129}).Count)" -LogLevel 2 -Component "ASR Event Check"
    $postObject = @()
    Write-Log -Message "Processing $($ASREvents.Count) ASR events" -LogLevel 1 -Component "ASR Event Processing"
    IF ($ASREvents.Count -gt 0) {
        FOREACH ($ASREvent in $ASREvents) {
            # Create a new PSObject to hold the event data
            $tmpObject = New-Object -TypeName PSObject
            # Add the base event data to the PSObject
            $tmpObject | Add-Member -MemberType NoteProperty -Name "EventID" -Value $ASREvent.ID
            $tmpObject | Add-Member -MemberType NoteProperty -Name "EventTime" -Value $ASREvent.TimeCreated
            $tmpObject | Add-Member -MemberType NoteProperty -Name "EventMessage" -Value $ASREvent.Message
            $tmpObject | Add-Member -MemberType NoteProperty -Name "EventLevel" -Value $ASREvent.LevelDisplayName
            $tmpObject | Add-Member -MemberType NoteProperty -Name "EventLog" -Value $ASREvent.LogName
            $tmpObject | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $ASREvent.MachineName
            $tmpObject | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value $DeviceId
            $tmpObject | Add-Member -MemberType NoteProperty -Name "ActionTypeGuid" -Value $ASREvent.Properties.Value[3]
            # Add the event specific data to the PSObject
            switch ($ASREvent.ID) {
                #If the event is 1121 or 1122, add the event specific data, if 1129, add the event specific data.
                { $PSItem -match "1121|1122" } {
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "Command" -Value $ASREvent.Properties.Value[11]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "User" -Value $ASREvent.Properties.Value[5]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "ExecutePath" -Value $ASREvent.Properties.Value[6]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "ProcessName" -Value $ASREvent.Properties.Value[7]
                    switch ($PsItem) {
                        1121 {
                            $tmpObject | Add-Member -MemberType NoteProperty -Name "Action" -Value "Blocked"
                            $tmpObject | Add-Member -MemberType NoteProperty -Name "ActionType" -Value "$($guidTable[$ASREvent.Properties.Value[3]])Blocked"
                        }
                        1122 {
                            $tmpObject | Add-Member -MemberType NoteProperty -Name "Action" -Value "Audit"
                            $tmpObject | Add-Member -MemberType NoteProperty -Name "ActionType" -Value "$($guidTable[$ASREvent.Properties.Value[3]])Audited"
                        }
                    }
                }
                1129 {
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "User" -Value $ASREvent.Properties.Value[4]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "ExecutePath" -Value $ASREvent.Properties.Value[5]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "ProcessName" -Value $ASREvent.Properties.Value[6]
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "Action" -Value "UserAllowed"
                    $tmpObject | Add-Member -MemberType NoteProperty -Name "ActionType" -Value "$($guidTable[$ASREvent.Properties.Value[3]])UserAllowed"
                }
            }
            $postObject += $tmpObject
        }
        try {
            Write-Log -Message "Uploading ASR Events" -LogLevel 1 -Component "Log Analytics Upload"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $JSONData = $postObject | ConvertTo-Json
            Post-LogAnalyticsData -workspaceID $workspaceID -primaryKey $primaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsondata)) -logType $logType
        }
        catch {
            Write-Log -Message "Failed to upload Printer Info" -LogLevel 3 -Component "Log Analytics Upload"
        }
    }
    ELSE {
        Write-Log -Message "No ASR events found in the last $HourstoInventory hours" -LogLevel 1 -Component "ASR Event Check"
    }
}
catch {
    Write-Log -Message "Failed to proccess ASR Events" -LogLevel 3 -Component "ASR Event Processing"
}

#endregion Main Script