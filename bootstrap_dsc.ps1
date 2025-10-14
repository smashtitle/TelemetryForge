<#
bootstrap_dsc.ps1
Bootstraps WinRM for Azure Run Command / DSC

- Bootstrap PSGet/NuGet
- Install required DSC modules
- Sets network profile to Private if Public
- Ensures WinRM service + listener exist
- Enables WinRM firewall rules
- Sets LocalAccountTokenFilterPolicy
- Emits a status summary
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Disable AppLocker
Stop-Service -Name AppIDSvc -Force

# Trust PSGallery and ensure NuGet provider
try { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop } catch { }
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
  Install-PackageProvider -Name NuGet -Force
}

# Install required DSC modules if missing
$modules = @(
  'PSDscResources',
  'xPSDesiredStateConfiguration',
  'ComputerManagementDsc',
  'AuditPolicyDsc',
  'NetworkingDsc',
  'DSCR_AppxPackage'
)
foreach ($m in $modules) {
  if (-not (Get-Module -ListAvailable -Name $m)) {
    Install-Module -Name $m -Scope AllUsers -Force
  }
}

function Set-NetworkProfilesPrivate {
    Get-NetConnectionProfile |
      Where-Object { $_.NetworkCategory -eq 'Public' -and $_.IPv4Connectivity -ne 'Disconnected' } |
      ForEach-Object {
          Write-Host "Changing $($_.InterfaceAlias) to Private"
          Set-NetConnectionProfile -InterfaceIndex $_.InterfaceIndex -NetworkCategory Private
      }
}

function Ensure-WinRMEnvelope {
    $targetKb = 8192
    Set-WSManInstance -ResourceURI winrm/config -ValueSet @{ MaxEnvelopeSizekb = $targetKb } -ErrorAction Stop
    Restart-Service WinRM -Force
}

function Ensure-WinRMService {
    $svc = Get-Service -Name WinRM -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name WinRM -StartupType Automatic }
    if ($svc.Status -ne 'Running')      { Start-Service -Name WinRM }
}

function Ensure-HttpsListener {
    if (-not (Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -match 'Transport=HTTPS' })) {
        $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
        $thumb = $cert.Thumbprint
        # use WSMan provider
        New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbprint $thumb -Force | Out-Null
        Write-Host "Created HTTPS listener with self-signed cert"
        Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Profile Domain,Private -Enabled True
    }
}

function Ensure-WinRMConfigured {
    if (-not (Test-WSMan -ErrorAction SilentlyContinue)) {
        Enable-PSRemoting -SkipNetworkProfileCheck -Force
    }
}

function Enable-WinRMFirewall {
    Write-Host "Enabling WinRM firewall rules (Domain/Private profiles)"
    Set-NetFirewallRule -DisplayGroup "Windows Remote Management" -Profile Domain,Private -Enabled True -ErrorAction SilentlyContinue
}

function Ensure-LocalAccountTokenFilterPolicy {
    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name 'LocalAccountTokenFilterPolicy' -PropertyType DWord -Value 1 -Force | Out-Null
}

Set-NetworkProfilesPrivate
Ensure-WinRMService
Ensure-HttpsListener
Ensure-WinRMConfigured
Enable-WinRMFirewall
Ensure-WinRMEnvelope
Ensure-LocalAccountTokenFilterPolicy

Write-Host "WinRM bootstrap complete."
try { Test-WSMan | Out-String | Write-Host } catch {}
