<#
.SYNOPSIS
    This script is used to detect if the printer inventory has been updated in the last 7 Days.
.DESCRIPTION
    This script is used to detect if the printer inventory has been updated in the last 7 Days. If it has not been updated in the last 7 days then the script will return a value of 1 to indicate that a remediation is needed. If the printer inventory has been updated in the last 7 days then the script will return a value of 0 to indicate that a remediation is not needed.
.LINK
    https://github.com/brookd2404/IntunePRs/tree/main/Inventory/Printer%20Inventory/Detect-PrinterInventory.ps1
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remediation script that it was remediated successfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remediation script that the remediation failed 
#>

#As we cannot pass Params to PR's use this first section to define the "Parameters" for the script.
param(
    [Parameter()]
    [string]$LogName = "PR-PrinterInventory",
    [parameter()]
    [string]$RegLastSyncLocation = "HKLM:\Software\ProactiveRemediation\Inventory-Printer",
    [parameter()]
    #Replace this with the Workspace ID of the Log Analytics Workspace that you want to send the data to.
    [string]$workspaceID = "<GUID>",
    [parameter()]
    #Replace this with the Primary Key of the Log Analytics Workspace that you want to send the data to.
    [string]$primaryKey = "<GUID>",
    [parameter()]
    #Specify the name of the record type that you'll be creating
    [string]$LogType = "PrinterInventory",
    [parameter()]
    #Specify the name of the field that will be used as the timestamp in the Log Analytics data
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

# Create the function to create the authorization signature
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
#region Main Script
Start-Log -LogName $LogName -LogFolder $LogFolder
Write-Log -Message "Proactive Remediation Detection Script Starting" -LogLevel 2
try {
    $Printers = Get-WMIObject -Class Win32_Printer
    Write-Log -Message "$Printers" -LogLevel 1

    Write-Log -Message "Creating Printer Info Array" -LogLevel 1
    $PrinterInfo = @()
    ForEach ($Printer in $Printers) {
        Try {
            If ($null -eq $Printer.Location) {
                $Port = Get-WmiObject Win32_TcpIpPrinterPort -Filter "Name = '$($Printer.PortName)'" -ErrorAction Stop
                $PrinterLocation = $Port.HostAddress
            }
            Else {
                $PrinterLocation = $Printer.Location
            }
        }
        catch {
            $PrinterLocation = $Printer.Location
        }

        $TmpObject = [PSCustomObject]@{
            DeviceName             = $ENV:COMPUTERNAME
            PrinterName            = [string]$Printer.Name
            DeviceID               = [string]$Printer.DeviceID
            DriverName             = [string]$Printer.DriverName
            Location               = [string]$PrinterLocation
            Network                = [string]$Printer.Network
            CapabilityDescriptions = [string]$($Printer.CapabilityDescriptions -join ",")
            PrintProcessor         = [string]$Printer.PrintProcessor
            Shared                 = [string]$Printer.Shared
            ShareName              = [string]$Printer.ShareName
            ServerName             = [string]$Printer.ServerName
        }
        $PrinterInfo += $TmpObject
    }

    Remove-Variable -Name TmpObject

    try {
        Write-Log -Message "Uploading Printer Info" -LogLevel 1
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $JSONData = $PrinterInfo | ConvertTo-Json
        Post-LogAnalyticsData -workspaceID $workspaceID -primaryKey $primaryKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsondata)) -logType $logType
        
        IF (!(Get-ItemProperty -Path $RegLastSyncLocation  -Name "LastSync" -ErrorAction SilentlyContinue)) {
            IF (!(Test-Path -Path $RegLastSyncLocation  )) {
                Write-Log -Message "Creating LastSync Registry Key" -LogLevel 1
                New-Item -Path $RegLastSyncLocation  -ItemType Directory -Force | Out-Null
            }
            Write-Log -Message "Creating LastSync Registry Value" -LogLevel 1
            New-ItemProperty -Path $RegLastSyncLocation  -Name "LastSync" -PropertyType String -Value (Get-date) -Force | Out-Null
        }
        ELSE {
            Write-Log -Message "Updating LastSync Registry Value" -LogLevel 1
            Set-ItemProperty -Path $RegLastSyncLocation  -Name "LastSync" -Value (Get-Date -UFormat "%d %B %Y %T") -Force | Out-Null
        }

    }
    catch {
        Write-Log -Message "Failed to upload Printer Info" -LogLevel 3
    }
}
catch {
    Write-Log -Message "Error: $($_.Exception.Message)" -LogLevel 3
}
#endregion