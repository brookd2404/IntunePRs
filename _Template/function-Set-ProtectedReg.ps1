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
        Write-Verbose "Giving current process token ownership rights"
        Add-Type $AdjustTokenPrivileges -PassThru | Out-Null
        [void][TokenManipulator]::AddPrivilege("SeTakeOwnershipPrivilege") 
        [void][TokenManipulator]::AddPrivilege("SeRestorePrivilege") 
  
        # Change ownership
        If ($User) {
            $TempOwner = New-Object System.Security.Principal.NTAccount($User)
        }
        Else {
            $CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name).Split('@')[0]
            $TempOwner = New-Object System.Security.Principal.NTAccount($CurrentUser)
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
        $OriginalACL = $Item.GetAccessControl()

        $ACL = [System.Security.AccessControl.RegistrySecurity]::new()
        $ACL.SetOwner($TempOwner)
        $Item.SetAccessControl($ACL)

        Write-Verbose "Setting Full Control for $owner on $Path"
        $Item = $rootKey.OpenSubKey($Key, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions) 
        $ACL = $Item.GetAccessControl()
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule -ArgumentList $TempOwner, 'FullControl', 'ContainerInherit', 'None', 'Allow'
        $ACL.AddAccessRule($Rule)

        $ACL.SetOwner($OriginalOwner)
        $Item.SetAccessControl($ACL)

        If ($Name) {
            Try {
                Write-Verbose "Setting registry [$Path] property [$Name] to [$Value]"
        
                # If path does not exist, create it
                If ( (Test-Path $Path) -eq $False ) {
                    Write-Verbose "Creating new registry keys"
                    $null = New-Item -Path $Path -Force
                }
        
                # Update registry value, create it if does not exist (DWORD is default)
                Write-Verbose "Working on registry path [$Path]"
                $itemProperty = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
                If ($null -ne $itemProperty) {
                    Write-Verbose "Setting registry property [$Name] to [$Value]"
                    $itemProperty = Set-ItemProperty -Path $Path -Name $Name -Value $Value
                }
                Else {
                    Write-Verbose "Creating new registry property [$Name] to [$Value]"
                    $itemProperty = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType
                }
            }
            catch {
                Write-Verbose "Something went wrong writing registry property"
            }
        }

        If (-not($RetainPermissions)) {
            $ACL.RemoveAccessRule($Rule) | Out-Null
            $Item.SetAccessControl($ACL)
        }
        $Item.Close()
    }

}

#Example:
#Set-ProtectedReg -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" -Name ConfigureChatAutoInstall -Value 1 -RetainPermissions -Verbose