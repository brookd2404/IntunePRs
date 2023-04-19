<# 
.SYNOPSIS
    Configures TLS, SSL, WinHTTP, Cipher Suites etc to recommended hardening configuration
.DESCRIPTION
    This script configures the recommended settings for Protocols and Ciphers to disable legacy and insecure settings across the OS and .NET
.NOTES
    Designed for use as a remediation script in Intune but can be used standalone.
.LINK
    Reference Links:    
    Enable TLS 1.2 Client - https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client
    Configure Schanel Protocols - https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#configuring-schannel-protocols-in-the-windows-registry
    Set .Net Framework System Default TLS Versions - https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#systemdefaulttlsversions
    Cipher Suites in Win11 - https://learn.microsoft.com/en-us/windows/win32/secauthn/tls-cipher-suites-in-windows-11
    https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392
    0x00000800 = Enable TLS 1.2 by default
    Cipher Order - https://auspisec.com/blog/20220618/windows_best_practices_tls.html
.EXAMPLE
    Remediate-TLSConfig.ps1 -Verbose
.NOTES
    Remember, for Proactive Remediations use:
        - "Exit 0" - To signify in a detection script that a remediation is NOT needed and likewise in a remeditation script that it was remediated succesfully
        - "Exit 1" - To signify in a detection script that a remediation is needed and likewise in a remeditation script that the remediation failed
#>

#region Variables
param(
    [Parameter(Mandatory = $false)]
    [string]$LogName = 'PR-TLSConfig',
    [Parameter(Mandatory = $false)]
    $Protocols = [PSCustomObject]@{
        'TLS 1.0' = $false
        'TLS 1.1' = $false
        'TLS 1.2' = $true
        'TLS 1.3' = $true
        'SSL 1.2' = $false
        'SSL 2.0' = $false
        'SSL 3.0' = $false
    },
    [Parameter(Mandatory = $false)]
    $Ciphers = [PSCustomObject]@{
        'NULL' = $false
        'MD5' = $false
        'DES 56/56' = $false
        'Triple DES 168' = $false
        'RC2 40/128'  = $false
        'RC2 56/128'  = $false
        'RC2 128/128' = $false
        'RC4 40/128'  = $false
        'RC4 56/128'  = $false
        'RC4 64/128' = $false
        'RC4 128/128' = $false
    }
)
#endregion Variables

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

function Set-Protocol {
    Param (
        $Name,
        $Value
    )

    If ($Value) {
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Client" -Name 'Enabled' -Value 1
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Client" -Name 'DisabledByDefault' -Value 0
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Server" -Name 'Enabled' -Value 1
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Server" -Name 'DisabledByDefault' -Value 0
    }
    else {
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Client" -Name 'Enabled' -Value 0
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Client" -Name 'DisabledByDefault' -Value 1
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Server" -Name 'Enabled' -Value 0
        Set-RegistryKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Name\Server" -Name 'DisabledByDefault' -Value 1
    }
}

function Set-Cipher {
    Param (
        $Name,
        $Value
    )

    If ($Value) {
        Set-RegistryKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Name $Name -value 1
    }
    else {
        Set-RegistryKey -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Name $Name -value 0  
    }
}
#endregion Functions

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Remediation Script Start"

try {
    Write-Log -Message "Configuring Protcols" -Component "Config - Protocols and Ciphers"
    ForEach ($Protocol in $Protocols.PSObject.Properties) {
        Write-Log -Message "Configuring [$($Protocol.Name)] to [$($Protocol.Value)]"
        Set-Protocol -Name $Protocol.Name -Value $Protocol.Value
    }
    
    Write-Log -Message "Configuring Ciphers" -Component "Config - Protocols and Ciphers"
    ForEach ($Cipher in $Chipers.PSObject.Properties) {
        Write-Log -Message "Configuring [$($Cipher.Name)] to [$($Cipher.Value)]" -Component "Config - Protocols and Ciphers"
        Set-Cipher -Name $Cipher.Name -Value $Cipher.Value
    }

    # Update Windows and WinHTTP
    Write-Log -Message "Updating Windows and WinHTTP" -Component "Config - Windows and HTTP"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\' -Name DefaultSecureProtocols -Value '0xAA0'
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\' -Name DefaultSecureProtocols -Value '0xAA0'

    # .NET Framework Config
    Write-Log -Message "Updating .NET Config" -Component "Config - .NET"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name SystemDefaultTlsVersions -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name SchUseStrongCrypto -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name SystemDefaultTlsVersions -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto-Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name SystemDefaultTlsVersions -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name SchUseStrongCrypto -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SystemDefaultTlsVersions -Value 1
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto -Value 1

    # Cipher Ordering
    Write-Log -Message "Checking Cipher Ordering" -Component "Config - Cipher Order"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name Functions -Value 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CCM,TLS_ECDHE_ECDSA_WITH_AES_128_CCM,TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_CCM,TLS_DHE_RSA_WITH_AES_128_CCM' -PropertyType String
    Write-Log -Message "TLS Configuration Complete" -Component "Main Script"
    Exit 0
}
catch {
    Write-Log -Message "Something went wrong during config.  Error output:" -LogLevel 3 -Component "Error Handling"
    Write-Log -Message $error[0].ToString() -LogLevel 3 -Component "Error Handling"
    Exit 1
}

#endregion Main Script