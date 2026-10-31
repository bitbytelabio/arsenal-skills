<#
.SYNOPSIS
    Manages the @zavora-ai/computer-use-mcp server on the Windows VM.

.DESCRIPTION
    Desktop automation (screenshots, mouse, keyboard, clipboard, window management)
    requires an active interactive desktop GUI session (WinSta0\Default), NOT a headless
    background WinRM session.

    This script:
    1. Ensures portproxy is configured (0.0.0.0:$Port -> 127.0.0.1:$Port) so external clients
       can connect, while also supporting loopback-only connections over SSH tunnels.
    2. Launches 'computer-use-mcp-console --no-demo --no-open' (listening on 127.0.0.1:$Port) inside
       the desktop session. The '--no-open' flag is essential on Windows to prevent attempting
       to spawn macOS 'open', which fails and crashes the server.
    3. Supports -Action start, stop, restart, status.

.PARAMETER Action
    Action to perform: 'start' (default), 'stop', 'restart', 'status'.

.PARAMETER Port
    Port number for the MCP server. Defaults to 4517.

.PARAMETER EnablePortProxy
    Whether to ensure netsh portproxy 0.0.0.0:$Port -> 127.0.0.1:$Port is configured. Defaults to $true.

.EXAMPLE
    .\start_computer_use_server.ps1 -Action start
    .\start_computer_use_server.ps1 -Action status
    .\start_computer_use_server.ps1 -Action stop
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "restart", "status")]
    [string]$Action = "start",

    [Parameter(Position = 1)]
    [int]$Port = 4517,

    [Parameter(Position = 2)]
    [switch]$EnablePortProxy = $true
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

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-PortProxy {
    param([int]$TargetPort)

    Write-Step "Checking netsh interface portproxy for port $TargetPort..."
    $existing = netsh interface portproxy show v4tov4 | Out-String

    $pattern = "0\.0\.0\.0\s+$TargetPort\s+127\.0\.0\.1\s+$TargetPort"
    if ($existing -match $pattern) {
        Write-Success "Portproxy rule 0.0.0.0:$TargetPort -> 127.0.0.1:$TargetPort already present."
    } else {
        if (-not (Test-IsAdmin)) {
            Write-Warn "Administrative privileges required to add portproxy rule. Skipping portproxy configuration."
            return
        }
        Write-Step "Adding netsh portproxy rule: 0.0.0.0:$TargetPort -> 127.0.0.1:$TargetPort"
        netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=$TargetPort connectaddress=127.0.0.1 connectport=$TargetPort
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Portproxy rule created successfully."
        } else {
            Write-Err "Failed to add portproxy rule (exit code $LASTEXITCODE)."
        }
    }
}

function Find-ServerExecutable {
    $candidates = @(
        "$env:APPDATA\npm\computer-use-mcp-console.cmd",
        "$env:ProgramFiles\nodejs\computer-use-mcp-console.cmd",
        "$env:LOCALAPPDATA\npm\computer-use-mcp-console.cmd"
    )

    foreach ($path in $candidates) {
        if (Test-Path $path) {
            return $path
        }
    }

    $cmd = Get-Command "computer-use-mcp-console.cmd" -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

function Get-ServerProcesses {
    $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'node%' OR Name LIKE 'cmd%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match "computer-use-mcp" }
    return $procs
}

function Get-ServerStatus {
    param([int]$TargetPort)

    Write-Step "Checking Computer Use MCP Server status (Port $TargetPort)..."
    
    # Check processes
    $procs = Get-ServerProcesses
    if ($procs) {
        Write-Success "Running process(es) detected:"
        foreach ($p in $procs) {
            Write-Host "    PID: $($p.ProcessId) | Name: $($p.Name) | Command: $($p.CommandLine)" -ForegroundColor Gray
        }
    } else {
        Write-Warn "No running computer-use-mcp process detected."
    }

    # Check listening port
    $netConnections = Get-NetTCPConnection -LocalPort $TargetPort -ErrorAction SilentlyContinue
    if ($netConnections) {
        Write-Success "Port $TargetPort is LISTENING:"
        foreach ($conn in $netConnections) {
            Write-Host "    $($conn.LocalAddress):$($conn.LocalPort) -> State: $($conn.State) (PID: $($conn.OwningProcess))" -ForegroundColor Gray
        }
    } else {
        Write-Warn "Port $TargetPort is not actively listening on any local interface."
    }

    # Check portproxy
    $portproxy = netsh interface portproxy show v4tov4 | Out-String
    Write-Host "`nPortproxy Configuration:" -ForegroundColor Cyan
    Write-Host $portproxy -ForegroundColor Gray
}

function Stop-Server {
    param([int]$TargetPort)

    Write-Step "Stopping Computer Use MCP Server processes..."
    $procs = Get-ServerProcesses
    if (-not $procs) {
        Write-Success "No active computer-use-mcp processes found."
        return
    }

    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            Write-Success "Terminated process PID $($p.ProcessId) ($($p.Name))."
        } catch {
            Write-Warn "Could not terminate PID $($p.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Start-Server {
    param([int]$TargetPort, [bool]$ProxyEnabled)

    if ($ProxyEnabled) {
        Ensure-PortProxy -TargetPort $TargetPort
    }

    $existingProcs = Get-ServerProcesses
    if ($existingProcs) {
        Write-Warn "Server process is already running:"
        foreach ($p in $existingProcs) {
            Write-Host "    PID: $($p.ProcessId) | Command: $($p.CommandLine)" -ForegroundColor Gray
        }
        return
    }

    $bin = Find-ServerExecutable
    $startCmd = ""
    $startArgs = ""

    if ($bin) {
        Write-Step "Using detected console binary: $bin"
        $startCmd = "cmd.exe"
        $startArgs = "/c `"$bin`" --no-demo --no-open"
    } else {
        Write-Step "Console binary not found in standard paths; launching via npx..."
        $startCmd = "npx.cmd"
        $startArgs = "-y -p @zavora-ai/computer-use-mcp computer-use-mcp-console --no-demo --no-open"
    }

    Write-Step "Launching MCP server: $startCmd $startArgs"
    
    $logPath = "C:\Tools\computer_use_server.log"
    if (-not (Test-Path "C:\Tools")) {
        New-Item -ItemType Directory -Path "C:\Tools" -Force | Out-Null
    }

    $proc = Start-Process -FilePath $startCmd `
                          -ArgumentList $startArgs `
                          -WorkingDirectory "C:\Tools" `
                          -RedirectStandardOutput $logPath `
                          -RedirectStandardError "C:\Tools\computer_use_server_err.log" `
                          -WindowStyle Hidden `
                          -PassThru

    Start-Sleep -Seconds 2

    if ($proc.HasExited) {
        Write-Err "Process exited immediately with code $($proc.ExitCode)."
        if (Test-Path "C:\Tools\computer_use_server_err.log") {
            Get-Content "C:\Tools\computer_use_server_err.log" | ForEach-Object { Write-Err "  $_" }
        }
    } else {
        Write-Success "Computer Use MCP Server started successfully (PID: $($proc.Id))."
        Write-Host "    Log file: $logPath" -ForegroundColor Gray
    }
}

switch ($Action) {
    "start" {
        Start-Server -TargetPort $Port -ProxyEnabled $EnablePortProxy
        Get-ServerStatus -TargetPort $Port
    }
    "stop" {
        Stop-Server -TargetPort $Port
    }
    "restart" {
        Stop-Server -TargetPort $Port
        Start-Sleep -Seconds 1
        Start-Server -TargetPort $Port -ProxyEnabled $EnablePortProxy
        Get-ServerStatus -TargetPort $Port
    }
    "status" {
        Get-ServerStatus -TargetPort $Port
    }
}
