<#
.SYNOPSIS
    Removes the Windows 11 built-in Teams (personal) app
.DESCRIPTION
    This script will remove the built-in Microsoft Teams (for personal use) app that comes with Windows 11.
    It will also add registry keys to prevent the re-installation and remove the Chat icon from the Taskbar. 
.LINK
    https://github.com/brookd2404/IntunePRs
.EXAMPLE
    Remediate-TeamsPersonalApp.ps1
    
.NOTES
    The key that controls re-installation of the Teams app is protected with only Trusted Installer having write access.
    This script will temporarily grant ownership of the key to SYSTEM and then grant full permissions to SYSTEM so it can be changed.
    Once the change is complete, the permission changes are reverted.

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
        Write-Log -Message "Something went wrong writing registry property" -LogLevel 3 -Component "Set-RegistryKey"
    }
}

function Set-ProtectedReg {
    [CmdletBinding(SupportsShouldProcess = $false)]
    Param(
        [Parameter(Mandatory = $true, HelpMessage = "Please Enter Registry Path")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        [Parameter(Mandatory = $false, HelpMessage = "Please Enter Username (Domain\User) to grant full control")]
        [string]$User,
        [Parameter(Mandatory = $false, HelpMessage = "Use this switch if you want to retain permissions. Default is to remove after using.")]
        [switch]$RetainPermissions,
        [Parameter(Mandatory = $false, HelpMessage = "Please Enter Registry Item Name")]
        [string]$Name,
        [Parameter(Mandatory = $false, HelpMessage = "Please Enter Registry Property Item Value")]
        $Value,
        [Parameter(Mandatory = $False, HelpMessage = "Please Enter Registry Property Type")]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'QWord', 'MultiString')]
        [string]$PropertyType = "DWord"
    )
  
    Begin {
        $AdjustTokenPrivileges = @"
  using System;
  using System.Runtime.InteropServices;
  
    public class TokenManipulator {
      [DllImport("kernel32.dll", ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();
  
      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
      [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
      [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  
      [StructLayout(LayoutKind.Sequential, Pack = 1)]
      internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
      }
  
      internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
      internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
      internal const int TOKEN_QUERY = 0x00000008;
      internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  
      public static bool AddPrivilege(string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
      }
  
      public static bool RemovePrivilege(string privilege) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_DISABLED;
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
      }
    }
"@
    }
  
    Process {
        $Item = Get-Item $Path

        Write-Log -Message "Giving current process token ownership rights" -Component "Set Protected Reg Key"
        Add-Type $AdjustTokenPrivileges -PassThru | Out-Null
        [void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege") 
        [void][TokenManipulator]::AddPrivilege("SeRestorePrivilege") 
  
        
        If ($User) {
            $TempOwner = New-Object System.Security.Principal.NTAccount($User)
            Write-Log -Message "Will assign temp ownership to: [$TempOwner]" -Component "Set Protected Reg Key"
        }
        Else {
            $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('@')[0]
            $TempOwner = New-Object System.Security.Principal.NTAccount($CurrentUser)
            Write-Log -Message "Will assign temp ownership to: [$TempOwner]" -Component "Set Protected Reg Key"
        }
        
        switch ($Item.Name.Split("\")[0]) {
            "HKEY_CLASSES_ROOT" { $rootKey = [Microsoft.Win32.Registry]::ClassesRoot; break }
            "HKEY_LOCAL_MACHINE" { $rootKey = [Microsoft.Win32.Registry]::LocalMachine; break }
            "HKEY_CURRENT_USER" { $rootKey = [Microsoft.Win32.Registry]::CurrentUser; break }
            "HKEY_USERS" { $rootKey = [Microsoft.Win32.Registry]::Users; break }
            "HKEY_CURRENT_CONFIG" { $rootKey = [Microsoft.Win32.Registry]::CurrentConfig; break }
        }
        $Key = $Item.Name.Replace(($Item.Name.Split("\")[0] + "\"), "")
        $Item = $rootKey.OpenSubKey($Key, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership) 
        $OriginalOwner = New-Object System.Security.Principal.NTAccount($item.GetAccessControl().Owner)
        Write-Log -Message "Got original owner: [$OriginalOwner]" -Component "Set Protected Reg Key"
        $OriginalACL = $Item.GetAccessControl()
        
        Write-Log -Message "Setting Temp Owner now..." -Component "Set Protected Reg Key"
        $ACL = [System.Security.AccessControl.RegistrySecurity]::new()
        $ACL.SetOwner($TempOwner)
        $Item.SetAccessControl($ACL)

        Write-Log -Message "Setting Full Control for $TempOwner on $Path" -Component "Set Protected Reg Key"
        $Item = $rootKey.OpenSubKey($Key, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions) 
        $ACL = $Item.GetAccessControl()
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule -ArgumentList $TempOwner, 'FullControl', 'ContainerInherit', 'None', 'Allow'
        $ACL.AddAccessRule($Rule)

        Write-Log -Message "Setting Original Owner now..." -Component "Set Protected Reg Key"
        $ACL.SetOwner($OriginalOwner)
        $Item.SetAccessControl($ACL)

        If ($Name) {
            Write-Log -Message "Reg Name specified, setting..." -Component "Set Protected Reg Key"
            Set-RegistryKey -Path $Path -Name $Name -Value $Value
        }

        If (-not($RetainPermissions)) {
            Write-Log -Message "No switch set to retain the set permissions, removing them..." -Component "Set Protected Reg Key"
            $ACL.RemoveAccessRule($Rule) | Out-Null
            $Item.SetAccessControl($ACL)
        }

        Write-Log -Message "Done." -Component "Set Protected Reg Key"
        $Item.Close()
    }

}
#endregion Functions

#region Main Script
Start-Log -LogName $LogName
Write-Log -Message "Proactive Remediation Script Starting" -LogLevel 1 -Component "Remediation Script Start"

Try {
    Write-Log -Message "Setting RegKey to force disablement of Teams personal"
    Set-ProtectedReg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -Name ConfigureChatAutoInstall -Value 1 -RetainPermissions
    Write-Log -Message "Setting RegKey to remove the Chat Icon from the Taskbar"
    Set-RegistryKey -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat' -Name ChatIcon -Value 3

    Write-Log -Message "Removing Microsoft Teams Personal App"
    If (Get-Process msteams -ErrorAction SilentlyContinue) {
        Try {
            Write-Log -Message "Stopping Microsoft Teams Personal app process"
            Stop-Process msteams -Force
            Write-Log -Message "Stopped"
        }
        catch {
            Write-Log -Message "Unable to stop process, trying to remove anyway" -LogLevel 2
        }
        
    }
    Get-AppxPackage -Name MicrosoftTeams -AllUsers | Remove-AppPackage -AllUsers -ErrorAction Stop
    Write-Log -Message "Microsoft Teams Personal App removed successfully"
    Exit 0
}
catch {
    Write-Log -Message "Error removing Microsoft Teams Personal App" -LogLevel 3
    Exit 1
}

#endregion Main Script
