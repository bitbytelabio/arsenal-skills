<#
.SYNOPSIS
    Toggles, checks, or configures Microsoft Defender Antivirus / Real-Time Protection for Windows RE/Malware analysis sandbox VMs.

.DESCRIPTION
    Reverse engineering, unpacking, and dynamic malware analysis require disabling Windows Defender
    real-time monitoring, behavior monitoring, script scanning, and cloud submission, or adding
    broad directory exclusions, to prevent sample quarantine and analysis tool interference.
    
    This script can be executed locally in an elevated Administrator PowerShell prompt or remotely via WinRM/Ansible.

.PARAMETER Action
    The action to perform: 'status' (default), 'disable', 'enable'.

.PARAMETER ExclusionPaths
    Array of folder paths to exclude from Windows Defender scanning. Defaults to 'C:\Tools', 'C:\Workspace'.

.PARAMETER ClearExclusions
    Switch indicating whether to remove specified exclusion paths instead of preserving/adding them when enabling Defender. Defaults to $false.

.EXAMPLE
    .\toggle_defender.ps1 -Action status
    .\toggle_defender.ps1 -Action disable
    .\toggle_defender.ps1 -Action enable
    .\toggle_defender.ps1 -Action enable -ClearExclusions
    .\toggle_defender.ps1 -Action disable -ExclusionPaths "C:\Tools", "C:\Samples", "C:\Workspace"
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("status", "disable", "enable")]
    [string]$Action = "status",

    [Parameter(Position = 1)]
    [string[]]$ExclusionPaths = @("C:\Tools", "C:\Workspace"),

    [Parameter(Position = 2)]
    [switch]$ClearExclusions = $false
)

$ErrorActionPreference = "Continue"

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Yellow
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DefenderStatus {
    $statusObj = [PSCustomObject]@{
        StatusTimestamp             = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        AntivirusEnabled            = $false
        RealTimeProtectionEnabled   = $false
        BehaviorMonitorEnabled      = $false
        IoavProtectionEnabled       = $false
        ScriptScanningEnabled       = $false
        AMServiceEnabled            = $false
        IsTamperProtected           = $false
        AntispywareSignatureVersion = "N/A"
        AntivirusSignatureVersion   = "N/A"
        ExclusionPaths              = @()
        GroupPolicyDisabled         = $false
    }

    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus) {
            $statusObj.AntivirusEnabled            = [bool]$mpStatus.AntivirusEnabled
            $statusObj.RealTimeProtectionEnabled   = [bool]$mpStatus.RealTimeProtectionEnabled
            $statusObj.BehaviorMonitorEnabled      = [bool]$mpStatus.BehaviorMonitorEnabled
            $statusObj.IoavProtectionEnabled       = [bool]$mpStatus.IoavProtectionEnabled
            $statusObj.ScriptScanningEnabled       = [bool]$mpStatus.ScriptScanningEnabled
            $statusObj.AMServiceEnabled            = [bool]$mpStatus.AMServiceEnabled
            if ($mpStatus.PSObject.Properties['IsTamperProtected']) {
                $statusObj.IsTamperProtected       = [bool]$mpStatus.IsTamperProtected
            }
            $statusObj.AntispywareSignatureVersion = [string]$mpStatus.AntispywareSignatureVersion
            $statusObj.AntivirusSignatureVersion   = [string]$mpStatus.AntivirusSignatureVersion
        }
    } catch {
        Write-WarnMsg "Failed to query Get-MpComputerStatus: $_"
    }

    try {
        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
        if ($prefs -and $prefs.ExclusionPath) {
            $statusObj.ExclusionPaths = @($prefs.ExclusionPath)
        } else {
            $statusObj.ExclusionPaths = @()
        }
    } catch {
        Write-WarnMsg "Failed to query Get-MpPreference: $_"
    }

    $polPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (Test-Path $polPath) {
        $val = (Get-ItemProperty -Path $polPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue).DisableAntiSpyware
        if ($val -eq 1) {
            $statusObj.GroupPolicyDisabled = $true
        }
    }

    return $statusObj
}

function Disable-Defender {
    Write-Step "Disabling Windows Defender features via Set-MpPreference..."

    # Ensure exclusion directories exist
    foreach ($path in $ExclusionPaths) {
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }

    try {
        Set-MpPreference `
            -DisableRealtimeMonitoring $true `
            -DisableBehaviorMonitoring $true `
            -DisableIntrusionPreventionSystem $true `
            -DisableIOAVProtection $true `
            -DisableScriptScanning $true `
            -SubmitSamplesConsent 2 `
            -MAPSReporting 0 `
            -ErrorAction SilentlyContinue
        Write-Success "Set-MpPreference protections disabled."
    } catch {
        Write-WarnMsg "Set-MpPreference warning: $_"
    }

    # Add missing exclusion paths without replacing existing ones
    try {
        $currPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        $existing = @()
        if ($currPrefs -and $currPrefs.ExclusionPath) {
            $existing = @($currPrefs.ExclusionPath)
        }
        $toAdd = @()
        foreach ($path in $ExclusionPaths) {
            $alreadyPresent = $false
            foreach ($ep in $existing) {
                if ($ep -ieq $path) {
                    $alreadyPresent = $true
                    break
                }
            }
            if (-not $alreadyPresent) {
                $toAdd += $path
            }
        }
        if ($toAdd.Count -gt 0) {
            Add-MpPreference -ExclusionPath $toAdd -ErrorAction SilentlyContinue
            Write-Success "Added missing exclusion paths: $($toAdd -join ', ')"
        } else {
            Write-Success "All specified exclusion paths already active."
        }
    } catch {
        Write-WarnMsg "Exclusion configuration warning: $_"
    }

    # Configure Registry Policies for persistent disable
    Write-Step "Applying registry policies under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender..."
    $defPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $rtPol  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

    if (-not (Test-Path $defPol)) {
        New-Item -Path $defPol -Force | Out-Null
    }
    if (-not (Test-Path $rtPol)) {
        New-Item -Path $rtPol -Force | Out-Null
    }

    try {
        Set-ItemProperty -Path $defPol -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $defPol -Name "DisableAntiVirus" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rtPol -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rtPol -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rtPol -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $rtPol -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Success "Registry policy keys updated successfully."
    } catch {
        Write-WarnMsg "Registry configuration warning: $_"
    }
}

function Enable-Defender {
    Write-Step "Re-enabling Windows Defender features via Set-MpPreference..."

    try {
        Set-MpPreference `
            -DisableRealtimeMonitoring $false `
            -DisableBehaviorMonitoring $false `
            -DisableIntrusionPreventionSystem $false `
            -DisableIOAVProtection $false `
            -DisableScriptScanning $false `
            -SubmitSamplesConsent 1 `
            -MAPSReporting 2 `
            -ErrorAction SilentlyContinue
        Write-Success "Set-MpPreference protections re-enabled."
    } catch {
        Write-WarnMsg "Set-MpPreference warning: $_"
    }
    if ($ClearExclusions) {
        Write-Step "Clearing analysis exclusion paths ($($ExclusionPaths -join ', ')) from Defender..."
        try {
            Remove-MpPreference -ExclusionPath $ExclusionPaths -ErrorAction SilentlyContinue
            Write-Success "Analysis exclusion paths cleared for pristine baseline testing."
        } catch {
            Write-WarnMsg "Remove-MpPreference warning: $_"
        }
    } else {
        Write-Step "Ensuring analysis exclusion paths remain active ($($ExclusionPaths -join ', '))..."
        # Ensure exclusion directories exist
        foreach ($path in $ExclusionPaths) {
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path -Force | Out-Null
            }
        }
        try {
            $currPrefs = Get-MpPreference -ErrorAction SilentlyContinue
            if ($currPrefs) {
                $existing = @()
                if ($currPrefs.ExclusionPath) {
                    $existing = @($currPrefs.ExclusionPath)
                }
                $toAdd = @()
                foreach ($path in $ExclusionPaths) {
                    $alreadyPresent = $false
                    foreach ($ep in $existing) {
                        if ($ep -ieq $path) {
                            $alreadyPresent = $true
                            break
                        }
                    }
                    if (-not $alreadyPresent) {
                        $toAdd += $path
                    }
                }
                if ($toAdd.Count -gt 0) {
                    Add-MpPreference -ExclusionPath $toAdd -ErrorAction SilentlyContinue
                    Write-Success "Added missing exclusion paths: $($toAdd -join ', ')"
                }
                Write-Success "Analysis exclusion paths ($($ExclusionPaths -join ', ')) protected so tools are not quarantined."
            } else {
                Write-WarnMsg "Could not query Get-MpPreference; skipping exclusion updates to avoid overwriting exclusions."
            }
        } catch {
            Write-WarnMsg "Add-MpPreference exclusion warning: $_"
        }
    }

    Write-Step "Restoring registry policies under HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender..."
    $defPol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $rtPol  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"

    if (Test-Path $defPol) {
        Remove-ItemProperty -Path $defPol -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $defPol -Name "DisableAntiVirus" -ErrorAction SilentlyContinue
    }
    if (Test-Path $rtPol) {
        Remove-ItemProperty -Path $rtPol -Name "DisableRealtimeMonitoring" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $rtPol -Name "DisableBehaviorMonitoring" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $rtPol -Name "DisableOnAccessProtection" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $rtPol -Name "DisableScanOnRealtimeEnable" -ErrorAction SilentlyContinue
    }
    Write-Success "Registry policy keys restored."
}

# Execution Entry Point
if ($Action -ne "status" -and -not (Test-IsAdmin)) {
    Write-Error "Action '$Action' requires elevated Administrator privileges. Please run as Administrator."
    exit 1
}

switch ($Action) {
    "disable" {
        Disable-Defender
        $status = Get-DefenderStatus
        Write-Host ""
        Write-Host "=== Defender Status after DISABLE ===" -ForegroundColor Yellow
        $status | Format-List
        Write-Output ($status | ConvertTo-Json -Compress)
        if ($status.RealTimeProtectionEnabled) {
            if ($status.IsTamperProtected) {
                Write-Error "Failed to disable Defender: Tamper Protection is ENABLED on this machine and blocked policy changes. Please disable Tamper Protection manually in Windows Security settings first."
            } else {
                Write-Error "Failed to disable Defender: RealTimeProtectionEnabled is still true after applying disable preferences."
            }
            exit 1
        }
    }
    "enable" {
        Enable-Defender
        $status = Get-DefenderStatus
        Write-Host ""
        Write-Host "=== Defender Status after ENABLE ===" -ForegroundColor Green
        $status | Format-List
        Write-Output ($status | ConvertTo-Json -Compress)
    }
    "status" {
        $status = Get-DefenderStatus
        Write-Host "=== Windows Defender Status ===" -ForegroundColor Cyan
        $status | Format-List
        Write-Output ($status | ConvertTo-Json -Compress)
    }
}
