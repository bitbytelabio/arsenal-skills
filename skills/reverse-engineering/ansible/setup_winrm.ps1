# Windows Remote Management (WinRM) Setup Script for Reverse Engineering VMs
# Run this script in an Elevated Administrator PowerShell prompt on the guest Windows VM.
#
# Enables:
# - WinRM service quickconfig
# - Basic and Negotiate authentication
# - Unencrypted HTTP transport (standard for isolated sandbox/host-only lab networks)
# - Windows Firewall inbound rules for WinRM HTTP (5985) and HTTPS (5986)
# - LocalAccountTokenFilterPolicy registry setting for full administrative tokens via remote WinRM

[CmdletBinding()]
param(
    [int]$HttpPort = 5985,
    [int]$HttpsPort = 5986
)

$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  Configuring WinRM for Ansible Lab Provisioning   " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Verify Administrative Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be executed from an elevated PowerShell window (Run as Administrator)."
    exit 1
}

# 2. Ensure Network Connection Profile allows remote management (Private/Domain)
try {
    Write-Host "[1/6] Setting Network Profile to Private..." -ForegroundColor Yellow
    Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Could not update network category to Private: $_"
}

# 3. Configure WinRM Service Startup
Write-Host "[2/6] Configuring WinRM Service..." -ForegroundColor Yellow
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# 4. QuickConfig
Write-Host "[3/6] Running winrm quickconfig..." -ForegroundColor Yellow
& winrm quickconfig -q -force

# Set a WSMan property when that build still exposes it.
# Windows 11 24H2 removed Service\MaxTimeoutms. $ErrorActionPreference Stop
# used to abort the rest of this script on that missing path.
function Set-WsmanValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "WSMan path not present on this build, skipped: $Path"
        return
    }
    Set-Item -Path $Path -Value $Value
}

# 5. Configure WinRM Service Auth and Listener Settings
Write-Host "[4/6] Configuring WinRM Authentication & Service settings..." -ForegroundColor Yellow
Set-WsmanValue -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
Set-WsmanValue -Path "WSMan:\localhost\Service\Auth\Negotiate" -Value $true
Set-WsmanValue -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value $true
Set-WsmanValue -Path "WSMan:\localhost\Service\MaxConcurrentOperationsPerUser" -Value 4294967295
Set-WsmanValue -Path "WSMan:\localhost\Service\MaxConnections" -Value 300
# Older Windows: Service\MaxTimeoutms. 24H2 keeps EnumerationTimeoutms instead.
Set-WsmanValue -Path "WSMan:\localhost\Service\MaxTimeoutms" -Value 1800000
Set-WsmanValue -Path "WSMan:\localhost\Service\EnumerationTimeoutms" -Value 1800000

# Client settings (in case VM needs to communicate outbound over WSMan)
Set-WsmanValue -Path "WSMan:\localhost\Client\AllowUnencrypted" -Value $true
Set-WsmanValue -Path "WSMan:\localhost\Client\Auth\Basic" -Value $true

# Ensure HTTP listener is active
$httpListener = Get-ChildItem -Path WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTP" }
if (-not $httpListener) {
    Write-Host "Creating HTTP Listener on port $HttpPort..." -ForegroundColor Yellow
    & winrm create winrm/config/listener?Address=*+Transport=HTTP
}

# 6. Windows Firewall Rules for WinRM
Write-Host "[5/6] Creating Windows Firewall Rules..." -ForegroundColor Yellow
$fwRules = @(
    @{ Name = "WinRM-HTTP-In"; Port = $HttpPort; Protocol = "TCP"; Desc = "WinRM HTTP Port 5985 for Ansible" },
    @{ Name = "WinRM-HTTPS-In"; Port = $HttpsPort; Protocol = "TCP"; Desc = "WinRM HTTPS Port 5986 for Ansible" }
)

foreach ($r in $fwRules) {
    $existing = Get-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -Name $r.Name `
                            -DisplayName $r.Desc `
                            -Description $r.Desc `
                            -Profile Any `
                            -Direction Inbound `
                            -Action Allow `
                            -Protocol $r.Protocol `
                            -LocalPort $r.Port | Out-Null
        Write-Host "Created firewall rule: $($r.Name) on port $($r.Port)" -ForegroundColor Green
    } else {
        Set-NetFirewallRule -Name $r.Name -Enabled True -Profile Any | Out-Null
        Write-Host "Firewall rule $($r.Name) already exists and is enabled." -ForegroundColor Green
    }
}

# 7. LocalAccountTokenFilterPolicy for Local Admin Accounts
# When connecting with a local user (e.g. Administrator or vagrant), UAC remote restrictions
# strip administrative privileges unless LocalAccountTokenFilterPolicy is set to 1.
Write-Host "[6/6] Setting LocalAccountTokenFilterPolicy to 1..." -ForegroundColor Yellow
$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}
Set-ItemProperty -Path $registryPath -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord -Force

# Restart WinRM to apply all changes cleanly
Write-Host "Restarting WinRM service..." -ForegroundColor Yellow
Restart-Service -Name WinRM

Write-Host "==================================================" -ForegroundColor Green
Write-Host "WinRM setup complete! The VM is ready for Ansible." -ForegroundColor Green
Write-Host "Test connection from host:" -ForegroundColor Green
Write-Host "ansible windows_vms -i inventory.ini -m win_ping" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Green
