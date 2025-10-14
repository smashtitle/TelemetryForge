# BaselineConfiguration.ps1
# Common baseline configuration for all workstations and servers
# Apply this first before machine-specific configurations

Configuration BaselineConfiguration
{
  param(
    [Parameter(Mandatory)]
    [string]$NodeName,
    
    [Parameter(Mandatory)]
    [pscredential]$LocalAdminCredential
  )

  Import-DscResource -ModuleName xPSDesiredStateConfiguration
  Import-DscResource -ModuleName PSDscResources
  Import-DscResource -ModuleName ComputerManagementDsc
  Import-DscResource -ModuleName AuditPolicyDsc
  Import-DscResource -ModuleName NetworkingDsc
  Import-DscResource -ModuleName DSCR_AppxPackage

  Node $NodeName
  {
    LocalConfigurationManager
    {
      ConfigurationMode = 'ApplyOnly'
      RebootNodeIfNeeded = $true
      AllowModuleOverwrite = $true
      ActionAfterReboot = 'ContinueConfiguration'
    }

    # ===========================
    # Directory Structure
    # ===========================
    $toolsDir = 'C:\Tools\'
    $downloadsDir = Join-Path -Path $toolsDir -ChildPath 'Downloads'

    File EnsureToolsFolder
    {
      Ensure = 'Present'
      Type = 'Directory'
      DestinationPath = $toolsDir
    }

    File EnsureToolsDLFolder
    {
      Ensure = 'Present'
      Type = 'Directory'
      DestinationPath = $downloadsDir
      DependsOn = '[File]EnsureToolsFolder'
    }

    # ===========================
    # Windows Update - Disable
    # ===========================
    Service DisableWindowsUpdate
    {
      Name = 'wuauserv'
      State = 'Stopped'
      StartupType = 'Manual'
      Ensure = 'Present'
    }

    Registry NoAutoUpdate
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
      ValueName = 'NoAutoUpdate'
      ValueType = 'Dword'
      ValueData = '1'
      Ensure = 'Present'
      Force = $true
    }

    Registry DoNotConnectToWU
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
      ValueName = 'DoNotConnectToWindowsUpdateInternetLocations'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    # ===========================
    # SmartScreen - Disable
    # ===========================
    Registry DisableExplorerSmartScreen
    {
      Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
      ValueName = 'SmartScreenEnabled'
      ValueData = 'Off'
      ValueType = 'String'
      Ensure = 'Present'
    }

    Registry DisableSystemSmartScreen
    {
      Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
      ValueName = 'EnableSmartScreen'
      ValueData = 0
      ValueType = 'Dword'
      Ensure = 'Present'
    }

    # ===========================
    # SMB/RPC Configuration for Remote Administration
    # ===========================
    Service LanmanServerService
    {
      Name = 'LanmanServer'
      StartupType = 'Automatic'
      State = 'Running'
    }

    Registry LocalAccountTokenFilter
    {
      Ensure = 'Present'
      Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      ValueName = 'LocalAccountTokenFilterPolicy'
      ValueType = 'DWord'
      ValueData = 1
    }

    Script RestartLanmanAfterReg
    {
      DependsOn = '[Registry]LocalAccountTokenFilter'
      GetScript = { @{ Result = (Get-Service -Name 'LanmanServer').Status } }
      TestScript = { (Get-Service -Name 'LanmanServer').Status -eq 'Running' }
      SetScript = {
        Restart-Service -Name 'LanmanServer' -Force -ErrorAction SilentlyContinue
      }
    }

    # ===========================
    # Firewall Configuration
    # ===========================
    FirewallProfile DomainProfile
    {
      Name = 'Domain'
      Enabled = 'True'
      DependsOn = '[Service]LanmanServerService'
    }

    FirewallProfile PrivateProfile
    {
      Name = 'Private'
      Enabled = 'True'
      DependsOn = '[Service]LanmanServerService'
    }

    FirewallProfile PublicProfile
    {
      Name = 'Public'
      Enabled = 'True'
      DependsOn = '[Service]LanmanServerService'
    }

    Firewall Allow_SMB_TCP_445
    {
      Name = 'Allow-SMB-TCP-445'
      DisplayName = 'Allow SMB (TCP 445) for File and Printer Sharing'
      Group = 'File and Printer Sharing'
      Ensure = 'Present'
      Enabled = 'True'
      Profile = @('Domain', 'Private', 'Public')
      Direction = 'Inbound'
      Protocol = 'TCP'
      LocalPort = @('445')
      Description = 'Allow SMB file sharing required for PsExec Admin$ access'
      DependsOn = '[FirewallProfile]DomainProfile'
    }

    Firewall Allow_SMB_TCP_139
    {
      Name = 'Allow-SMB-TCP-139'
      DisplayName = 'Allow SMB (TCP 139) for File and Printer Sharing'
      Group = 'File and Printer Sharing'
      Ensure = 'Present'
      Enabled = 'True'
      Profile = @('Domain', 'Private', 'Public')
      Direction = 'Inbound'
      Protocol = 'TCP'
      LocalPort = @('139')
      Description = 'Allow NetBIOS-SSN used by some SMB variants'
      DependsOn = '[Firewall]Allow_SMB_TCP_445'
    }

    Firewall Allow_RPC_TCP_135
    {
      Name = 'Allow-RPC-TCP-135'
      DisplayName = 'Allow RPC Endpoint Mapper (TCP 135)'
      Group = 'File and Printer Sharing'
      Ensure = 'Present'
      Enabled = 'True'
      Profile = @('Domain', 'Private', 'Public')
      Direction = 'Inbound'
      Protocol = 'TCP'
      LocalPort = @('135')
      Description = 'Allow RPC endpoint mapper (required by some remote admin operations)'
      DependsOn = '[Firewall]Allow_SMB_TCP_139'
    }

    Firewall Allow_NBUDP_137_138
    {
      Name = 'Allow-NetBIOS-UDP-137-138'
      DisplayName = 'Allow NetBIOS Name/Datagram (UDP 137-138)'
      Group = 'File and Printer Sharing'
      Ensure = 'Present'
      Enabled = 'True'
      Profile = @('Domain', 'Private', 'Public')
      Direction = 'Inbound'
      Protocol = 'UDP'
      LocalPort = @('137', '138')
      Description = 'Allow NetBIOS name resolution and datagram service'
      DependsOn = '[Firewall]Allow_RPC_TCP_135'
    }

    Script Uninstall_OneDrive_PerMachine
    {
      GetScript  = { @{ Result = (Test-Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") -or
                               (Test-Path "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe") } }
      TestScript = { -not ((Test-Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe") -or
                           (Test-Path "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe")) }
      SetScript  = {
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $setup = if ([Environment]::Is64BitOperatingSystem) {
          Join-Path $env:WINDIR 'SysWOW64\OneDriveSetup.exe'
        } else {
          Join-Path $env:WINDIR 'System32\OneDriveSetup.exe'
        }
        if (Test-Path $setup) {
          Start-Process -FilePath $setup -ArgumentList '/uninstall' -Wait -WindowStyle Hidden
        }
      }
    }

    Script Uninstall_OneDrive_PerUser_AllProfiles
    {
      DependsOn = '[Script]Uninstall_OneDrive_PerMachine'
      GetScript = {
        $profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special }
        $hasAny   = $false
        foreach ($p in $profiles) {
          if (Test-Path (Join-Path $p.LocalPath 'AppData\Local\Microsoft\OneDrive')) { $hasAny = $true; break }
        }
        @{ Result = $hasAny }
      }
      TestScript = {
        -not (Get-CimInstance Win32_UserProfile | Where-Object {
          $_.LocalPath -like 'C:\Users\*' -and -not $_.Special -and
          (Test-Path (Join-Path $_.LocalPath 'AppData\Local\Microsoft\OneDrive'))
        })
      }
      SetScript = {
        $profiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like 'C:\Users\*' -and -not $_.Special }
        foreach ($p in $profiles) {
          $root  = Join-Path $p.LocalPath 'AppData\Local\Microsoft\OneDrive'
          $setup = Join-Path $root 'OneDriveSetup.exe'
          if (Test-Path $setup) {
            Start-Process -FilePath $setup -ArgumentList '/uninstall' -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
          }
          # remove leftovers
          @(
            $root,
            (Join-Path $p.LocalPath 'OneDrive')
          ) | ForEach-Object { if (Test-Path $_) { Remove-Item $_ -Recurse -Force -ErrorAction SilentlyContinue } }
        }
      }
    }

    # ===========================
    # RPC Firewall Installation
    # ===========================
    xRemoteFile GetRPCFW
    {
      DestinationPath = 'C:\Tools\Downloads\RPCFW_2.2.5.zip'
      Uri = 'https://github.com/zeronetworks/rpcfirewall/releases/download/v2.2.5/RPCFW_2.2.5.zip'
      DependsOn = '[File]EnsureToolsDLFolder'
    }

    Archive UnzipRPCFW
    {
      Path = 'C:\Tools\Downloads\RPCFW_2.2.5.zip'
      Destination = 'C:\Tools\'
      Ensure = 'Present'
      Force = $true
      DependsOn = '[xRemoteFile]GetRPCFW'
    }

    Script InstallRPCFW
    {
      GetScript = {
        $flag = Get-ItemProperty -Path 'HKLM:\SOFTWARE\_BaselineFlags' -Name 'RPCFWInstalled' -ErrorAction SilentlyContinue
        @{ Result = [bool]$flag }
      }
      TestScript = {
        (Get-Service -Name 'rpcFw*' -ErrorAction SilentlyContinue) -ne $null
      }
      SetScript = {
        $exe = 'C:\Tools\RPCFW_2.2.5\rpcFwManager.exe'
        Start-Process -FilePath $exe -ArgumentList '/install' -Wait
        Start-Process -FilePath $exe -ArgumentList '/start' -Wait
        New-Item -Path 'HKLM:\SOFTWARE\_BaselineFlags' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SOFTWARE\_BaselineFlags' -Name 'RPCFWInstalled' -Value '1' -PropertyType String -Force | Out-Null
      }
      DependsOn = '[Archive]UnzipRPCFW'
    }

    # ===========================
    # Sysmon Installation
    # ===========================
    xRemoteFile GetSysmonZip
    {
      DestinationPath = 'C:\Tools\Downloads\Sysmon.zip'
      Uri = 'https://download.sysinternals.com/files/Sysmon.zip'
      DependsOn = '[File]EnsureToolsDLFolder'
    }

    Archive UnzipSysmon
    {
      Path = 'C:\Tools\Downloads\Sysmon.zip'
      Destination = 'C:\Tools\Sysmon'
      Ensure = 'Present'
      Force = $true
      DependsOn = '[xRemoteFile]GetSysmonZip'
    }

    xRemoteFile GetSysmonConfig
    {
      DestinationPath = 'C:\Tools\Sysmon\sysmonconfig-research.xml'
      Uri = 'https://raw.githubusercontent.com/smashtitle/TelemetryForge/refs/heads/main/sysmonconfig-research.xml'
      DependsOn = '[Archive]UnzipSysmon'
    }

    Script InstallSysmon
    {
      GetScript = { @{ Result = (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) -ne $null } }
      TestScript = { (Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue) -ne $null }
      SetScript = {
        $dest = 'C:\Tools\Sysmon'
        $exe = Join-Path $dest 'Sysmon64.exe'
        if (-not (Test-Path $exe)) { throw "Sysmon64 executable not found at $dest" }

        $cfg = Join-Path $dest 'sysmonconfig-research.xml'
        if (-not (Test-Path $cfg)) { throw "Sysmon config not found" }

        Start-Process -FilePath $exe -ArgumentList '-accepteula', '-i', "`"$cfg`"" -Wait
      }
      DependsOn = '[xRemoteFile]GetSysmonConfig'
    }

    # ===========================
    # Consumer Features - Disable
    # ===========================
    Registry DisableConsumerFeatures
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
      ValueName = 'DisableWindowsConsumerFeatures'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    # ===========================
    # OneDrive - Remove and Disable
    # ===========================
    Script RemoveOneDrive
    {
      GetScript = { @{ Result = $false } }
      TestScript = { $false }
      SetScript = {
        Stop-Process -Name OneDrive -Force -ErrorAction SilentlyContinue
        $exe = "$env:SystemRoot\System32\OneDriveSetup.exe"
        if (Test-Path $exe)
        {
          Start-Process -FilePath $exe -ArgumentList '/uninstall' -Wait -WindowStyle Hidden
        }
      }
    }

    Registry DisableOneDriveSyncClient
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
      ValueName = 'DisableFileSyncNGSC'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    # ===========================
    # Microsoft Edge - Disable
    # ===========================
    Registry EdgeStartupBoostDisabled
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      ValueName = 'StartupBoostEnabled'
      ValueType = 'Dword'
      ValueData = 0
      Ensure = 'Present'
      Force = $true
    }

    Registry EdgeBackgroundModeDisabled
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
      ValueName = 'BackgroundModeEnabled'
      ValueType = 'Dword'
      ValueData = 0
      Ensure = 'Present'
      Force = $true
    }

    Service EdgeUpdateMediumService
    {
      Name = 'edgeupdatem'
      StartupType = 'Disabled'
      State = 'Stopped'
      Ensure = 'Present'
    }

    Service EdgeElevationService
    {
      Name = 'MicrosoftEdgeElevationService'
      StartupType = 'Disabled'
      State = 'Stopped'
      Ensure = 'Present'
    }

    Script DisableEdgeCore
    {
      GetScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineCore' -ErrorAction SilentlyContinue
        @{ Result = ($t -and $t.State -eq 'Disabled') }
      }
      TestScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineCore' -ErrorAction SilentlyContinue
        ($t -and $t.State -eq 'Disabled')
      }
      SetScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineCore' -ErrorAction SilentlyContinue
        if ($t) { Disable-ScheduledTask -InputObject $t | Out-Null }
      }
    }

    Script DisableEdgeUA
    {
      GetScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineUA' -ErrorAction SilentlyContinue
        @{ Result = ($t -and $t.State -eq 'Disabled') }
      }
      TestScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineUA' -ErrorAction SilentlyContinue
        ($t -and $t.State -eq 'Disabled')
      }
      SetScript = {
        $t = Get-ScheduledTask -TaskPath '\' -TaskName 'MicrosoftEdgeUpdateTaskMachineUA' -ErrorAction SilentlyContinue
        if ($t) { Disable-ScheduledTask -InputObject $t | Out-Null }
      }
    }

    # ===========================
    # Appx Packages - Remove
    # ===========================
    $AppxNames = @(
      'Microsoft.OneDrive',
      'Microsoft.ZuneMusic',
      'Microsoft.WindowsCamera',
      'Microsoft.WindowsCalculator',
      'Microsoft.WindowsAlarms',
      'Microsoft.Windows.Photos',
      'Microsoft.WindowsSoundRecorder',
      'Microsoft.WindowsNotepad',
      'Microsoft.WindowsTerminal',
      'Microsoft.Edge.GameAssist',
      'Microsoft.PowerAutomateDesktop',
      'Microsoft.StartExperiencesApp',
      'Microsoft.Paint',
      'Microsoft.ScreenSketch',
      'Microsoft.Todos',
      'Microsoft.YourPhone',
      'MicrosoftCorporationII.QuickAssist',
      'Microsoft.WindowsFeedbackHub',
      'Microsoft.GetHelp',
      'Microsoft.Windows.DevHome',
      'Microsoft.OutlookForWindows',
      'Microsoft.GamingApp',
      'Microsoft.XboxGamingOverlay',
      'Microsoft.XboxIdentityProvider',
      'Microsoft.XboxSpeechToTextOverlay',
      'Microsoft.Xbox.TCUI',
      'Microsoft.MicrosoftStickyNotes',
      'Microsoft.MicrosoftSolitaireCollection',
      'Microsoft.MicrosoftOfficeHub',
      'Microsoft.BingWeather',
      'Microsoft.BingNews',
      'Microsoft.BingSearch',
      'Microsoft.WidgetsPlatformRuntime',
      'Microsoft.HEVCVideoExtension',
      'Microsoft.HEIFImageExtension',
      'Microsoft.RawImageExtension',
      'Microsoft.VP9VideoExtensions',
      'Microsoft.WebpImageExtension',
      'Microsoft.WebMediaExtensions',
      'Microsoft.MPEG2VideoExtension',
      'Microsoft.AVCEncoderVideoExtension',
      'Microsoft.AV1VideoExtension',
      'Clipchamp.Clipchamp',
      'MSTeams'
    )

    # De-provision packages from the image so they don't install for new users
    cAppxProvisionedPackageSet Provisioned_Absent
    {
      Ensure      = 'Absent'
      PackageName = $AppxNames
      AllUsers    = $true   # requires DSCR_AppxPackage >= 0.4.0
    }

    # Remove already-installed packages for users
    cAppxPackageSet Installed_Absent
    {
      Ensure = 'Absent'
      Name   = $AppxNames
    }


    # ===========================
    # Event Logs - Custom Anchor Log
    # ===========================
    Script EnsureAnchorSource
    {
      GetScript = {
        $source = 'DetectionLab'
        if ([System.Diagnostics.EventLog]::SourceExists($source))
        {
          return @{ Result = 'Present' }
        }
        else
        {
          return @{ Result = 'Absent' }
        }
      }
      TestScript = {
        $source = 'DetectionLab'
        return [System.Diagnostics.EventLog]::SourceExists($source)
      }
      SetScript = {
        $LogName = 'Anchors'
        $source = 'DetectionLab'
        if (-not [System.Diagnostics.EventLog]::SourceExists($source))
        {
          New-EventLog -LogName $LogName -Source $source
        }
      }
    }

    WindowsEventLog Anchors
    {
      LogName = 'Anchors'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 4096000
      DependsOn = '[Script]EnsureAnchorSource'
    }

    # ===========================
    # Event Logs - Standard Logs
    # ===========================
    WindowsEventLog Security
    {
      LogName = 'Security'
      LogMode = 'Circular'
      MaximumSizeInBytes = 4294967295 # 4GB
    }

    WindowsEventLog System
    {
      LogName = 'System'
      LogMode = 'Circular'
      MaximumSizeInBytes = 4294967295 # 4GB
    }

    WindowsEventLog Application
    {
      LogName = 'Application'
      LogMode = 'Circular'
      MaximumSizeInBytes = 4294967295 # 4GB
    }

    WindowsEventLog PowerShellOperational
    {
      LogName = 'Microsoft-Windows-PowerShell/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog WmiOperational
    {
      LogName = 'Microsoft-Windows-WMI-Activity/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog TaskScheduler
    {
      LogName = 'Microsoft-Windows-TaskScheduler/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog SMBServerOperational
    {
      LogName = 'Microsoft-Windows-SMBServer/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog SMBServerSecurity
    {
      LogName = 'Microsoft-Windows-SMBServer/Security'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog SMBClientSecurity
    {
      LogName = 'Microsoft-Windows-SMBClient/Security'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog LSAOperational
    {
      LogName = 'Microsoft-Windows-LSA/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog CAPI2Operational
    {
      LogName = 'Microsoft-Windows-CAPI2/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog NTLMOperational
    {
      LogName = 'Microsoft-Windows-NTLM/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog CodeIntegrity
    {
      LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog GroupPolicyOperational
    {
      LogName = 'Microsoft-Windows-GroupPolicy/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog WinRMOperational
    {
      LogName = 'Microsoft-Windows-WinRM/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog TSRemoteConnectionManager
    {
      LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog TSLocalSessionManager
    {
      LogName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog DiagnosisScripted
    {
      LogName = 'Microsoft-Windows-Diagnosis-Scripted/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
    }

    WindowsEventLog SysmonOperational
    {
      LogName = 'Microsoft-Windows-Sysmon/Operational'
      IsEnabled = $true
      LogMode = 'Circular'
      MaximumSizeInBytes = 268435456
      DependsOn = '[Script]InstallSysmon'
    }

    # ===========================
    # Audit Policy Configuration
    # ===========================
    
    # Account Logon
    AuditPolicySubcategory APS_CredentialValidation_S { Name = 'Credential Validation'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_CredentialValidation_F { Name = 'Credential Validation'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_KerberosAuthSvc_S { Name = 'Kerberos Authentication Service'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_KerberosAuthSvc_F { Name = 'Kerberos Authentication Service'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_KerberosST_S { Name = 'Kerberos Service Ticket Operations'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_KerberosST_F { Name = 'Kerberos Service Ticket Operations'; AuditFlag = 'Failure' }

    # Account Management
    AuditPolicySubcategory APS_ComputerAcctMgmt_S { Name = 'Computer Account Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ComputerAcctMgmt_F { Name = 'Computer Account Management'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_OtherAcctMgmt_S { Name = 'Other Account Management Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_OtherAcctMgmt_F { Name = 'Other Account Management Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_SecGroupMgmt_S { Name = 'Security Group Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_SecGroupMgmt_F { Name = 'Security Group Management'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_UserAcctMgmt_S { Name = 'User Account Management'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_UserAcctMgmt_F { Name = 'User Account Management'; AuditFlag = 'Failure' }

    # Detailed Tracking
    AuditPolicySubcategory APS_PnP_S { Name = 'Plug and Play Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_PnP_F { Name = 'Plug and Play Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_ProcessCreation_S { Name = 'Process Creation'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ProcessCreation_F { Name = 'Process Creation'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_ProcessTermination_S { Name = 'Process Termination'; AuditFlag = 'Success' }
    AuditPolicySubcategory APD_ProcessTermination_F { Name = 'Process Termination'; AuditFlag = 'Failure'; Ensure = 'Absent' }
    AuditPolicySubcategory APS_RPCEvents_S { Name = 'RPC Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_RPCEvents_F { Name = 'RPC Events'; AuditFlag = 'Failure' }
    AuditPolicySubcategory APS_TokenRightAdjusted_S { Name = 'Token Right Adjusted Events'; AuditFlag = 'Success' }
    AuditPolicySubcategory APS_TokenRightAdjusted_F { Name = 'Token Right Adjusted Events'; AuditFlag = 'Failure' }

    # ===========================
    # PowerShell Logging
    # ===========================
    Registry PSModuleLogging
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
      ValueName = 'EnableModuleLogging'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    Registry PSModuleLoggingModules
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
      ValueName = '1'
      ValueType = 'String'
      ValueData = '*'
      Ensure = 'Present'
      Force = $true
    }

    Registry PSScriptBlockLogging
    {
      Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
      ValueName = 'EnableScriptBlockLogging'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    # ===========================
    # Process Command Line Auditing
    # ===========================
    Registry ProcessCmdLineAudit
    {
      Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
      ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
      ValueType = 'Dword'
      ValueData = 1
      Ensure = 'Present'
      Force = $true
    }

    # ===========================
    # Cleanup Temporary Files
    # ===========================
    Script CleanupTemps
    {
      GetScript = {
        if (Test-Path 'C:\Tools\.cleanup.done')
        {
          @{ Result = 'present' }
        }
        else
        {
          @{ Result = 'absent' }
        }
      }
      TestScript = {
        Test-Path 'C:\Tools\.cleanup.done'
      }
      SetScript = {
        $paths = @(
          "$env:windir\Temp\*",
          "C:\Windows\SoftwareDistribution\Download\*",
          "C:\Windows\Prefetch\*",
          "C:\Windows\SystemTemp\*",
          "$env:ProgramData\Temp\*",
          "C:\Tools\Downloads\*"
        )
        foreach ($p in $paths)
        {
          Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType File -Path "C:\Tools\.cleanup.done" -Force | Out-Null
      }
    }
  }
}

$ConfigData = @{
  AllNodes = @(
    @{
      NodeName                   = 'localhost'
      PSDscAllowPlainTextPassword = $true
    }
  )
}

$SecurePassword = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force
$Credential     = [pscredential]::new('azureadmin', $SecurePassword)

# Compile
$OutPath = Join-Path $PSScriptRoot 'MOF'
New-Item -ItemType Directory -Path $OutPath -Force | Out-Null

$params = @{
  NodeName              = 'localhost'
  LocalAdminCredential  = $Credential
  ConfigurationData     = $ConfigData
  OutputPath            = $OutPath
}
BaselineConfiguration @params

# Apply
Start-DscConfiguration -Path $OutPath -Wait -Verbose -Debug -Force
