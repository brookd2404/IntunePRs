<#
.SYNOPSIS
    Attempts to repair the health of Windows Update
.DESCRIPTION
    This script walks through various areas such as service state correction, Registry Keys from GPOs, folders that need emptying, optionally run DISM & SFC
.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Remediate-WindowsUpdateHealth.ps1
    Remediate-WindowsUpdateHealth.ps1 -ImageHealthRepair $true
    Remediate-WindowsUpdateHealth.ps1 -RespectNoAutoRebootWithLoggedOnUsers $false
.NOTES
    Running this script with the $ImageHealthRepair = $true, while fixing most problems, will take an excessive ammount of time and use host resources.
    The $RespectNoAutoRebootWithLoggedOnUsers = $true will make sure this specific Policy setting is re-applied by the script during repairs. Change to $false to ensure all the WU Policies are cleared out. 

    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed 
#>

#region Variables
#$VerbosePreference = "Continue"
Param (
    $Company = 'PowerON',
    $LogName = "PR-WindowsUpdateHealth",
    $ImageHealthRepair = $false,
    $RespectNoAutoRebootWithLoggedOnUsers = $true #Used to ensure if NoAutoRebootWithLoggedOnUsers exists in registry it is re-instated during repair (HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate)
)

$ServiceState = [PSCustomObject]@{
    Name  = $null
    State = $null
}

$ScriptRunOutput = [PSCustomObject]@{
    BeforeRemediation = [PSCustomObject]@{
        UpdateLocation                = ''
        LastSearchSuccessDate         = ''
        LastInstallationSuccessDate   = ''
        WUPoliciesPresent             = $false
        NoAutoRebootWithLoggedOnUsers = $false
    }
    AfterRemediation  = [PSCustomObject]@{
        UpdateLocation                = ''
        LastSearchSuccessDate         = ''
        LastInstallationSuccessDate   = ''
        WUPoliciesPresent             = $false
        NoAutoRebootWithLoggedOnUsers = $false
    }
    ServicesStopped   = @()
    ServicesStarted   = @()
    TMP               = $env:TMP
    TEMP              = $env:TEMP
    UserProfiles      = @()
    ImageHealth       = @()
    ResetBase         = ''
    CURollbackClean   = ''
    SFC               = ''
    FoldersCleaned    = @()
}
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

        ## Set the global variable to be used as the FilePath for all subsequent Write-Log -Message calls in this session
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
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'QWord', 'MultiString')]
        $PropertyType = "DWord"
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
Write-Log -Message "Windows Update Health Remediation Script Starting" -LogLevel 1 -Component "Script Startup"

#Checking where device is currently set to retrieve updates from
$MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
Write-Log -Message "Update Location currently set to: [$(($MUSM.Services| Where-Object IsDefaultAUService -eq $true).Name)]" -Component "Script Startup"
$ScriptRunOutput.BeforeRemediation.UpdateLocation = ($MUSM.Services | Where-Object IsDefaultAUService -eq $true).Name
$MUSM = (New-Object -ComObject Microsoft.Update.AutoUpdate)
$ScriptRunOutput.BeforeRemediation.LastSearchSuccessDate = $MUSM.Results.LastSearchSuccessDate
$ScriptRunOutput.BeforeRemediation.LastInstallationSuccessDate = $MUSM.Results.LastInstallationSuccessDate

Write-Log -Message "Pre-Remediation WU Info: $($ScriptRunOutput.BeforeRemediation)" -Component "WU Info"

try {
    #region Check, Fix and Stop Services Phase
    $Script:LogRegion = "Check, Fix and Stop Services"
    Write-Log -Message "Starting [Check, Fix and Stop Services] phase" -LogLevel 2
    #Specifically set services to Auto and ensure they are started
    $Services = @('cryptSvc', 'BITS', 'LanmanServer', 'LanmanWorkstation')
    foreach ($Service in $Services) {
        Write-Log -Message "Starting services that should be Auto started: [$Service]"
        If ((Get-Service -Name $Service).StartType -ne 'Automatic') {
            Write-Log -Message "Service Startup Type was set to disabled, setting to Automatic"
            Try { Set-Service -Name $Service -StartupType Automatic -ErrorAction Stop }
            catch { Write-Log -Message "Error setting service [$Service] to Automatic" -LogLevel 3 }
        }

        try {
            Start-Service -Name $Service
        }
        catch {
            Write-Log -Message "Unable to start service [$Service]"
        }
    }

    #Specifically set services to Manual
    $Services = @('lmhosts', 'IKEEXT', 'wuauserv')
    foreach ($Service in $Services) {
        Write-Log -Message "Checking service is set to Manual: [$Service]"
        If ((Get-Service -Name $Service).StartType -ne 'Manual') {
            Write-Log -Message "Service Startup Type was set to disabled, setting to Manual"
            Try { Set-Service -Name $Service -StartupType Manual -ErrorAction Stop }
            catch { Write-Log -Message "Error setting service [$Service] to Automatic" -LogLevel 3 }
        }
    }

    #Restart some services
    $ServicesToRestart = @('cryptSvc', 'appidsvc', 'BITS', 'wuauserv')
    foreach ($ServiceToRestart in $ServicesToRestart) {
        Write-Log -Message "Restarting service [$ServiceToRestart]"
        Try { Restart-Service -Name $ServiceToRestart -Force -ErrorAction Stop }
        catch { Write-Log -Message "Error restarting service [$ServiceToRestart]" -LogLevel 3 }
    }

    #Only runs if CM Agent is installed...
    #Prep ConfigMgr agent before service stop
    If (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        Write-Log -Message "Instructing ConfigMgr client to make next policy request a full policy instead of delta since the last policy request"
        Invoke-WMIMethod -Namespace root\ccm -Class SMS_Client -Name ResetPolicy -ArgumentList 0
    }

    Try {
        Write-Log -Message "Attempting to clear BITS Jobs using PowerShell before service stop"
        Get-BitsTransfer -AllUsers | Where-Object { $_.JobState -like "*Error*" } | Remove-BitsTransfer -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log -Message "Error clearing BITS Jobs" -LogLevel 3
    }

    #Stop and temporarilly disable
    Write-Log -Message "Stopping services"
    $ServiceState = @()
    $Services = @('ccmexec', 'BITS', 'wuauserv')
    foreach ($Service in $Services) {
        $Servicetmp = [PSCustomObject]@{
            Name        = $null
            State       = $null
            StartupType = $null
        }
        If (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
            Write-Log -Message "Stopping service [$Service]"
            $Servicetmp.StartupType = (Get-Service -Name $Service).StartType
            Write-Log -Message "Service Startup Type was configured for [$($Servicetmp.StartupType)]"
            Try { Set-Service -Name $Service -StartupType Disabled -ErrorAction Stop }
            catch { Write-Log -Message "Error disabling service [$Service]" -LogLevel 3 }
            try {
                Stop-Service -Name $Service -Force
                $Servicetmp.Name = $Service
                $Servicetmp.State = 'Stopped'
            }
            catch {
                Write-Log -Message "Unable to stop service [$Service]"
                $Servicetmp.Name = $Service
                $Servicetmp.State = 'Failed to Stop'
            }
        }
        Else {
            $Servicetmp.Name = $Service
            $Servicetmp.State = 'Not Present'
        }
        $ServiceState += $Servicetmp
    }

    $ScriptRunOutput.ServicesStopped = $ServiceState
    $ServiceState = @()
    $Servicetmp = @()
    Write-Log -Message "Finished [Check, Fix and Stop Services] phase" -LogLevel 2
    #endregion
  
    #region Registry Check/Fix Phase
    $Script:LogRegion = "Registry Check/Fix Phase"
    Write-Log -Message "Starting [Registry Check/Fix Phase] phase" -LogLevel 2

    #Set registry entry to allow the machine to use Windows Update for enabling .NET 3.5 instead of WSUS
    Set-RegistryKey -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing -Name RepairContentServerSource -Value 2

    #Check to see if No Reboot with Logged On User policy present
    $NoAutoRebootWithLoggedOnUsers = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers
    If ($NoAutoRebootWithLoggedOnUsers) {
        $ScriptRunOutput.BeforeRemediation.NoAutoRebootWithLoggedOnUsers = $true
    }

    #Reset WU Policy Keys
    If (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
        $ScriptRunOutput.BeforeRemediation.WUPoliciesPresent = $true
        Write-Log -Message "WindowsUpdate policies found in Registry, removing them..." -LogLevel 2
        Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force -Recurse

        If ($NoAutoRebootWithLoggedOnUsers -and $RespectNoAutoRebootWithLoggedOnUsers) {
            Write-Log -Message "NoAutoRebootWithLoggedOnUsers WindowsUpdate policy was previously present, putting it back..." -LogLevel 2
            Set-RegistryKey -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoRebootWithLoggedOnUsers -Value $NoAutoRebootWithLoggedOnUsers
        }

        Write-Log -Message "WindowsUpdate policies removed"
    }
    Write-Log -Message "Finished [Registry Check/Fix Phase] phase" -LogLevel 2
    #endregion

    #region Clean up files Phase
    $Script:LogRegion = "Clean up files phase"
    Write-Log -Message "Starting [Clean up files] phase" -LogLevel 2

    Write-Log -Message "Cleaning Temp Folders..."
    If (Test-Path $env:TMP) {
        Remove-Item -Path $env:TMP\* -Force -Recurse -ErrorAction SilentlyContinue
    }
    If (Test-Path $env:TEMP) {
        Remove-Item -Path $env:TEMP\* -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Cleaning *.tmp files in $env:SystemDrive..."
    If (Test-Path "$env:SystemDrive\*.tmp") {
        Remove-Item -Path $env:SystemDrive\*.tmp -Exclude "DumpStack.log.tmp" -Force -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Cleaning Temp directories in user profiles..."
    $UserProfiles = Get-ChildItem -Path C:\Users -Exclude Default, Public, defaultuser0
    $ScriptRunOutput.UserProfiles = $UserProfiles.FullName
    $UserProfiles | ForEach-Object {
        Write-Log -Message "Working on user directory [$_]"
        Remove-Item $_\AppData\Local\Temp\*.* -Force -Recurse -ErrorAction SilentlyContinue
    }

    Write-Log -Message "Cleaning $env:SystemRoot\Temp folder..."
    Remove-Item -Path $env:SystemRoot\Temp\*.* -Force -Recurse -ErrorAction SilentlyContinue

    Write-Log -Message "Removing Windows.old directory if it exists and empty"
    If (Test-Path $env:SystemDrive\Windows.old) {
        $WinOld = Get-ChildItem -Path $env:SystemDrive\Windows.old -Recurse
        If ($WinOld.Count -eq 0) {
            Write-Log -Message "Windows.old directory present and empty, removing"
            Remove-Item -Path $env:SystemDrive\Windows.old -Recurse -Force
        }
        Else {
            Write-Log -Message "Windows.old directory present but is not empty. Not removing"
        }
    }
    Else {
        Write-Log -Message "Windows.old directory not present"
    }

    Try {
        Write-Log -Message "Deleting the BranchCache Cache"
        Clear-BCCache -Force
    }
    catch {
        Write-Log -Message "Error - Unable to delete the BranchCache Cache" -LogLevel 3
    }

    Try {
        Write-Log -Message "Deleting the Delivery Optimization Cache"
        Delete-DeliveryOptimizationCache -Force
    }
    catch {
        Write-Log -Message "Error - Unable to delete the Delivery Optimization Cache" -LogLevel 3
    }

    Try {
        Write-Log -Message "Attempting to clear BITS queue folder"
        Remove-Item -Path "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*" -Recurse -Force -ErrorAction Stop
    }
    catch {
        Write-Log -Message "Error clearing BITS queue folder" -LogLevel 3
    }

    #Only runs if CM Agent is installed...
    If (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        Write-Log -Message "Emptying the ConfigMgr Cache"
        Try {
            ## Initialize the CCM resource manager com object
            [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
            ## Get the CacheElementIDs to delete
            $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
            ## Remove cache items
            ForEach ($CacheItem in $CacheInfo) {
                $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($CacheItem.CacheElementID))
            }
        }
        catch {
            Write-Log -Message "Error - There was an issue clearing the ConfigMgr Cache" -LogLevel 3
        }
    }

    Write-Log -Message "Clearing Software Distribution folders" -LogLevel 1
    #"$env:SystemRoot\System32\catroot2"
    $Folders = @("$env:SystemRoot\SoftwareDistribution\DataStore", "$env:SystemRoot\SoftwareDistribution\Download", "$env:SystemRoot\SoftwareDistribution\PostRebootEventCache.V2", "$env:SystemRoot\SoftwareDistribution\SLS")
    foreach ($Folder in $Folders) {
        try {
            If (Test-Path $Folder) {
                Remove-Item -Path $Folder -Force -Recurse -ErrorAction Stop
                $ScriptRunOutput.FoldersCleaned += $Folder
            }
        }
        catch {
            Write-Log -Message "Error - Unable to rename $Folder" -LogLevel 3
        }
    }

    Write-Log -Message "Clearing previous Windows Upgrade folders" -LogLevel 1
    $Folders = @("$env:SystemDrive\`$Windows.~BT", "$env:SystemDrive\`$Windows.~WS")
    foreach ($Folder in $Folders) {
        If (Test-Path $Folder) {
            try {
                Write-Log -Message "Attempting to remove $Folder"
                Remove-Item -Path $Folder -Force -Recurse -ErrorAction Stop
                $ScriptRunOutput.FoldersCleaned += $Folder
            }
            catch {
                Write-Log -Message "Warning - Unable to remove $Folder, attempting to rename"
                try {
                    Rename-Item -Path $Folder -NewName $Folder`.old -Force -ErrorAction Stop
                    $ScriptRunOutput.FoldersCleaned += $Folder
                }
                catch {
                    Write-Log -Message "Error - Unable to rename $Folder" -LogLevel 3
                }
            }
        }
        Else {
            Write-Log -Message "Folder [$Folder] does not exist, not attempting to remove."
        }
    }

    Write-Log -Message "Finished [Clean up files] phase" -LogLevel 2
    #endregion

    #region Image Health Check/Repair Phase
    $Script:LogRegion = "Image Health Check/Repair Phase"
    #Only runs if $ImageHealthRepair = $true (set in variables section at top of script)
    If ($ImageHealthRepair) {
        Write-Log -Message "Starting [Image Health Check/Repair] phase" -LogLevel 2
        try {
            Write-Log -Message "Restoring Windows Image Health"
            $ImageHealth = Repair-WindowsImage -Online -RestoreHealth -NoRestart
            $ScriptRunOutput.ImageHealth = $ImageHealth
        }
        catch {
            Write-Log -Message "Error restoring Windows Health" -LogLevel 3
            Write-Log -Message $error[0].ToString() -LogLevel 3
        }

        try {
            Write-Log -Message "Using DISM to reset base WIM"
            $ResetBase = Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
            Write-Log -Message "DISM ResetBase Output:"
            Write-Log -Message "$ResetBase"
            $ScriptRunOutput.ResetBase = $ResetBase[($ResetBase.count) - 1]
        }
        catch {
            Write-Log -Message "Error using DISM to reset base WIM" -LogLevel 3
            Write-Log -Message $error[0].ToString() -LogLevel 3
            $ScriptRunOutput.ResetBase = 'Error using DISM to reset base WIM'
        }

        try {
            Write-Log -Message "Using DISM to remove CU Rollbacks"
            $CURollbackClean = Dism.exe /online /Cleanup-Image /SPSuperseded
            Write-Log -Message "DISM CU Rollbacks Output:"
            Write-Log -Message "$CURollbackClean"
            $ScriptRunOutput.CURollbackClean = $CURollbackClean[($CURollbackClean.count) - 1]
        }
        catch {
            Write-Log -Message "Error using DISM to remove CU Rollbacks" -LogLevel 3
            Write-Log -Message $error[0].ToString() -LogLevel 3
            $ScriptRunOutput.CURollbackClean = 'Error using DISM to remove CU Rollbacks'
        }

        try {
            Write-Log -Message "Running System File Checker"
            $SFC = sfc /scannow
            ##TODO: Write better CBS Log parsing...
            Write-Log -Message 'SFC Output:'
            If ($SFC[($SFC.count) - 4] -eq 'Windows Resource Protection did not find any integrity violations.') {
                $ScriptRunOutput.SFC = 'Windows Resource Protection did not find any integrity violations.'
                Write-Log -Message 'Windows Resource Protection did not find any integrity violations.'
            }
            Else {
                $ScriptRunOutput.SFC = "Integrity violations, check log [$env:SystemRoot\Logs\CBS\CBS.log]."
                Write-Log -Message "Warning - Integrity violations, check log [$env:SystemRoot\Logs\CBS\CBS.log]."
            }
        }
        catch {
            Write-Log -Message "Error running SFC" -LogLevel 3
            Write-Log -Message $error[0].ToString() -LogLevel 3
            $ScriptRunOutput.SFC = 'Error running SFC'
        }
    }

    Write-Log -Message "Finished [Image Health Check/Repair] phase" -LogLevel 2
    #endregion

    #region Start Services Phase
    $Script:LogRegion = "Start Services Phase"
    Write-Log -Message "Starting [Start services] phase" -LogLevel 2

    $ServiceState = @()
    foreach ($Service in $Services) {
        $Servicetmp = [PSCustomObject]@{
            Name        = $null
            State       = $null
            StartupType = $null
        }
        If (Get-Service -Name $Service -ErrorAction SilentlyContinue) {
            Write-Log -Message "Starting service [$Service]"
            Try { Set-Service -Name $Service -StartUpType ($ScriptRunOutput.servicesstopped | Where-Object Name -eq $Service).StartupType -ErrorAction Stop }
            catch { Write-Log -Message "Error resetting service [$Service] StartUpType" -LogLevel 3 }
            $Servicetmp.StartupType = (Get-Service -Name $Service).StartType

            try {
                Start-Service -Name $Service
                $Servicetmp.Name = $Service
                $Servicetmp.State = 'Started'
            }
            catch {
                Write-Log -Message "Error - Unable to start service [$Service]" -LogLevel 3
                $Servicetmp.Name = $Service
                $Servicetmp.State = 'Failed to Start'
            }
        }
        Else {
            $Servicetmp.Name = $Service
            $Servicetmp.State = 'Not Present'
        }
        $ServiceState += $Servicetmp
    }
    $ScriptRunOutput.ServicesStarted = $ServiceState
    Write-Log -Message "Finished [Start services] phase" -LogLevel 2
    #endregion

    #region Refresh Windows Update Settings Phase
    $Script:LogRegion = "Refresh Windows Update Settings Phase"
    Write-Log -Message "Starting [Refresh Windows Update Settings] phase" -LogLevel 2
    Try {
        Write-Log -Message "Pausing for WUSA Service to finish inialising"
        Start-Sleep 15
        
        Write-Log -Message "Invoking UsoClient to Refresh Settings"
        Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "RefreshSettings" -Wait -NoNewWindow
    }
    catch {
        Write-Log -Message "Error refreshing Windows Update settings via USOClient.exe" -LogLevel 3
    }

    #Only runs if CM Agent is installed...
    If (Get-Service -Name ccmexec -ErrorAction SilentlyContinue) {
        Write-Log -Message "Instructing ConfigMgr client to make next policy request a full policy instead of delta since the last policy request"
        Invoke-WmiMethod -Namespace root\ccm -Class SMS_Client -Name ResetPolicy -ArgumentList 0
        Start-Sleep 15
        Write-Log -Message "Evaluating Policy"
        Invoke-WmiMethod -Namespace root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000021}"
        Start-Sleep 15
        Write-Log -Message "Scanning for Updates"
        Invoke-WmiMethod -Namespace root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000113}"
        Write-Log -Message "Sending unsent status messages"
        Invoke-WmiMethod -Namespace root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList "{00000000-0000-0000-0000-000000000111}"
        Try {
            $TargetedUpdates = Get-WmiObject -Namespace root\CCM\ClientSDK -Class CCM_SoftwareUpdate -Filter ComplianceState=0
            $approvedUpdates = ($TargetedUpdates | Measure-Object).count
            $pendingpatches = ($TargetedUpdates | Where-Object { $TargetedUpdates.EvaluationState -ne 8 } | Measure-Object).count
            $rebootpending = ($TargetedUpdates | Where-Object { $TargetedUpdates.EvaluationState -eq 8 } | Measure-Object).count
            $MissingUpdatesReformatted = @($TargetedUpdates | ForEach-Object { if ($_.ComplianceState -eq 0) { [WMI]$_.__PATH } })
            Write-Log -Message "Targeted Updates: [$approvedUpdates]"
            Write-Log -Message "Pending Updates: [$pendingpatches]"
            Write-Log -Message "Reboot Pending Updates: [$rebootpending]"
            Write-Log -Message "The following required updates were found:"
            Write-Log -Message "$MissingUpdatesReformatted"
        }
        catch {
            Write-Log -Message "Unable to query ConfigMgr for missing updates"
        }
    }
    Else {
        Try {
            Write-Log -Message "Invoking UsoClient to check for updates"
            #Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartScan" -Wait -NoNewWindow
            Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartInteractiveScan" -Wait -NoNewWindow
            Start-Sleep 120
        }
        catch {
            Write-Log -Message "Error invoking Windows Update check via USOClient.exe" -LogLevel 3
        }

    }

    #Checking where device is currently set to retrieve updates from
    Remove-Variable -Name MUSM
    $MUSM = New-Object -ComObject "Microsoft.Update.ServiceManager"
    Write-Log -Message "Update Location currently set to: [$(($MUSM.Services| Where-Object IsDefaultAUService -eq $true).Name)]"
    $ScriptRunOutput.AfterRemediation.UpdateLocation = ($MUSM.Services | Where-Object IsDefaultAUService -eq $true).Name
    $MUSM = (New-Object -ComObject Microsoft.Update.AutoUpdate)
    $ScriptRunOutput.AfterRemediation.LastSearchSuccessDate = $MUSM.Results.LastSearchSuccessDate
    $ScriptRunOutput.AfterRemediation.LastInstallationSuccessDate = $MUSM.Results.LastInstallationSuccessDate

    Write-Log -Message "Post-Remediation WU Info: $($ScriptRunOutput.AfterRemediation)"

    Write-Log -Message "Finished [Refresh Windows Update Settings] phase" -LogLevel 2
    #endregion

    #region Finish
    Write-Log -Message "Finishing Remediation and setting run date for detection" -LogLevel 2 -Component "Finish Phase"

    #Test WU Policy Keys
    If (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) {
        $ScriptRunOutput.AfterRemediation.WUPoliciesPresent = $true
        Write-Log -Message "WindowsUpdate policies found post remediation in Registry..." -LogLevel 2
        
        If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoRebootWithLoggedOnUsers -ErrorAction SilentlyContinue).NoAutoRebootWithLoggedOnUsers) {
            Write-Log -Message "NoAutoRebootWithLoggedOnUsers WindowsUpdate policy present..." -LogLevel 2
            $ScriptRunOutput.AfterRemediation.NoAutoRebootWithLoggedOnUsers = $true
        }
    }

    Set-RegistryKey -Path HKLM:\Software\$Company\Remediations\WindowsUpdate -Name WindowsUpdateRepaired -Value $(Get-Date)

    Write-Log -Message "Summary output (JSON):" -LogLevel 1 -Component "Finish Phase"
    $JSON = $ScriptRunOutput | ConvertTo-Json -Depth 5
    Write-Log -Message $JSON -Component "Finish Phase"

    Write-Log -Message "All done, have a good day!" -LogLevel 1 -Component "Finish Phase"
    Exit 0
    #endregion
}
catch {
    <# Do this if a terminating exception happens #>
    Write-Log -Message "Something went wrong during repair.  Error output:" -LogLevel 3 -Component "Error Handling"
    ForEach ($Errors in $error) {
        Write-Log -Message "`n" -LogLevel 3 -Component "Error Handling"
        $msg = "Line: " + $errors.InvocationInfo.ScriptLineNumber + " Error: " + $errors.ToString()
        Write-Log -Message $msg -LogLevel 3 -Component "Error Handling"
    }
    Set-RegistryKey -Path HKLM:\Software\$Company\Remediations\WindowsUpdate -Name WindowsUpdateRepaired -Value ''
    Exit 1
}

#endregion Main Script
