# Windows VM Ansible Provisioning & Tool Setup Guide

This guide details automated provisioning of Windows Virtual Machines (running under UTM on macOS, VMware Workstation/Fusion, or Hyper-V) for malware analysis, reverse engineering, forensic triage, and telemetry monitoring using Ansible and a structured tool catalog.

---

## 1. Overview & Architecture

Reverse engineering and dynamic analysis frequently demand a pristine Windows guest VM with:
1. **Telemetry & Endpoint Monitoring**: `osquery` (for live SQL queries of processes, sockets, persistence), `Sysmon` (Windows Event Log process/network tracing).
2. **Network Analysis**: `Wireshark` / `TShark` with Npcap loopback support, `Fiddler Classic`, and `mitmproxy`.
3. **Forensic Triage**: Microsoft `Sysinternals Suite` (`Procmon`, `Procexp`, `Autoruns`, `TCPView`, `strings`), `ProcDOT`.
4. **Disassembly & Debugging**: `x64dbg`, `Ghidra`, `Cutter`, `radare2`, `WinDbg`, and `IDA Pro Remote Debugger` (`win64_remote.exe`).
5. **PE Analysis**: `Detect It Easy (DIE)`, `PeStudio`, `PE-bear`, `YARA`.
6. **System Utilities**: `7-Zip`, `Git`, `Python 3.12`, `HxD Hex Editor`, `cURL`, and `Node.js LTS`.
- 7. **Automation & Agent Control**: `computer-use-mcp` (@zavora-ai/computer-use-mcp) running as an MCP Server on the Windows VM (port 4517) providing native Rust NAPI desktop automation (screenshots, mouse, keyboard, clipboard, window management) to host AI agents (MCP Clients).
8. **Defender Management**: `toggle_defender.ps1` and `playbook_defender.yml` to toggle real-time protection, script scanning, cloud MAPS reporting, and folder exclusions (`C:\Tools`, `C:\Workspace`).
Provisioning is automated through:
- **`ansible/windows_tools.json`**: Declarative tool catalog with package identifiers, binary paths, service definitions, tags, and enable/disable states.
- **`ansible/playbook_windows.yml`**: Ansible playbook that connects over WinRM, bootstraps Chocolatey, installs selected tools, creates Windows Firewall rules, starts `osqueryd`, and appends tool locations to the system PATH.
- **`scripts/setup_windows_vm.py`**: CLI utility for inspecting, toggling, and managing tools, generating WinRM scripts, creating Ansible inventories, and running playbooks.

---

## 2. Guest Windows VM Preparation (WinRM)

Ansible manages Windows hosts using **Windows Remote Management (WinRM)** over HTTP (port 5985) or HTTPS (port 5986).

### 2.1 Running `setup_winrm.ps1`
On the guest Windows VM:
1. Open PowerShell as **Administrator** (`Run as Administrator`).
2. Run the bundled script or generate it from host with:
   ```bash
   uv run scripts/setup_windows_vm.py winrm-script -o setup_winrm.ps1
   ```
3. Transfer and execute in PowerShell on guest:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\setup_winrm.ps1
   ```

### 2.2 What the WinRM Script Configures
- **Network Profile**: Switches active network adapters to `Private` to allow remote management.
- **Service Configuration**: Starts and sets `WinRM` service to `Automatic`.
- **QuickConfig**: Runs `winrm quickconfig -q -force`.
- **Authentication**: Enables `Basic` and `Negotiate` (NTLM) authentication, and enables unencrypted transport over port 5985 for isolated sandbox networks.
- **Firewall Rules**: Opens inbound ports 5985 (HTTP) and 5986 (HTTPS).
- **UAC Remote Restrictions**: Sets registry key `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy = 1`. This allows non-domain local Administrator accounts to connect over WinRM with a full administrative token.

---

## 3. Host Network & Hypervisor Configuration

### 3.1 UTM on macOS
UTM supports two primary network modes:
1. **Shared Network (NAT)**:
   - Configure Port Forwarding in UTM VM Settings -> Network:
     - Protocol: `TCP`, Host Port: `5985`, Guest Port: `5985` (WinRM)
     - Protocol: `TCP`, Host Port: `23946`, Guest Port: `23946` (IDA Remote Debugger)
   - Connect from host via `127.0.0.1:5985`.
2. **Bridged (Advanced)**:
   - Guest VM receives an IP directly from the host local network (e.g. `192.168.64.15`). Query with `utmctl ip-address <vm>`.

### 3.2 VMware Fusion / Workstation
- Use **Host-Only** (`vmnet1`) or **NAT** (`vmnet8`).
- Note the guest VM IP assigned by VMware DHCP (e.g. `172.16.x.x` or `192.168.x.x`).

---

## 4. Managing the Tool Catalog (`windows_tools.json`)
The catalog `ansible/windows_tools.json` (or `ansible/windows_tools.json`) organizes tools by category and schema:
```json
{
  "id": "osquery",
  "name": "osquery",
  "category": "telemetry_monitoring",
  "description": "SQL-powered operating system instrumentation...",
  "choco_package": "osquery",
  "winget_id": "Facebook.osquery",
  "binary_path": "C:\\Program Files\\osquery\\osqueryi.exe",
  "service_name": "osqueryd",
  "enabled": true,
  "tags": ["telemetry", "monitoring", "sql", "auditing"]
}
```

Use `setup_windows_vm.py` to inspect and modify:

### Summary of Catalog
```bash
uv run scripts/setup_windows_vm.py summary
```

### List Tools (Filtered)
```bash
# List all tools
uv run scripts/setup_windows_vm.py list

# Filter by category
uv run scripts/setup_windows_vm.py list --category debugging_disassembly

# Filter by tag
uv run scripts/setup_windows_vm.py list --tag forensics

### Toggle Tools
```bash
# Disable heavy tools (e.g. Ghidra if only doing quick triage)
uv run scripts/setup_windows_vm.py disable-tool ghidra

# Re-enable
uv run scripts/setup_windows_vm.py enable-tool ghidra

### Add Custom Tools
```bash
uv run scripts/setup_windows_vm.py add-tool \
  --name XORSearch \
  --category pe_analysis \
  --description "Search for given pattern in XOR/ROL/ROT encoded binary" \
  --choco xorsearch \
  --binary-path "C:\\ProgramData\\chocolatey\\bin\\xorsearch.exe" \
  --tags "search,xor,pe"
```

---

## 5. Provisioning with Ansible

### 5.0 Prerequisites: Controller Ansible Collections & PyWinRM
Check and install the controller requirements in one step. `deps` installs pywinrm into the Python that Ansible runs on (with a uv-installed Ansible this is not the `python3` on PATH), installs the five collections the playbooks use, and prints the IDA `dbgsrv` path it will copy from:
```bash
uv run scripts/setup_vm.py deps            # report only, exit 1 if something is missing
uv run scripts/setup_vm.py deps --install
```

### 5.1 Generate Inventory
```bash
uv run scripts/setup_windows_vm.py generate-inventory \
  --host 192.168.64.15 \
  --user Administrator \
  --password 'MalwareAnalysisLab2026!' \
  --port 5985
```

This writes `ansible/inventory.ini` (`ansible/inventory.ini`):
[windows_vms]
win-re-vm ansible_host=192.168.64.15 ansible_port=5985 ansible_user=Administrator ansible_password=MalwareAnalysisLab2026!

[windows_vms:vars]
ansible_connection=winrm
ansible_winrm_transport=ntlm
ansible_winrm_scheme=http
ansible_winrm_server_cert_validation=ignore
ansible_winrm_operation_timeout_sec=120
ansible_winrm_read_timeout_sec=180
```

### 5.2 Test Connectivity (`win_ping`)
```bash
ansible windows_vms -i ansible/inventory.ini -m win_ping
```
Expected output:
```json
win-re-vm | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

### 5.3 Execute Provisioning Playbook
```bash
# Run in check (dry-run) mode:
uv run scripts/setup_windows_vm.py run-playbook --check

# Execute full provisioning:
uv run scripts/setup_vm.py run-playbook --os windows -v

On macOS the runner sets `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`. Without it, Ansible's forked WinRM worker dies before `win_ping`.

UTM Windows ARM cannot reach Chocolatey until UTM Guest Tools (NetKVM) are installed and the NIC is Shared NAT. Host-only has no route to the package feeds. Switch back to host-only after the tools are in place.

A Chocolatey failure does not stop the play. The playbook retries that tool with its `winget_id` when one is set. winget is not on PATH in a WinRM session, so the task resolves `winget.exe` under `C:\Program Files\WindowsApps` and runs it through `become` (runas) as the WinRM user. MSIX packages such as WinDbg then register for that user. Current catalog ids: `x64dbg.portable` (there is no `x64dbg` package), `pebear` (not `pe-bear`), `python312` (the floating `python3` package is not 3.12), and `Microsoft.WinDbg` via winget (there is no `windbg` package). ProcDOT has no community package.

The playbook executes the following stages:
1. Gathers Windows facts and creates `C:\Tools`, `C:\Workspace`, and `C:\Tools\ida_dbgsrv`.
2. Adds Defender exclusions for `C:\Tools`, `C:\Workspace`, and `C:\ProgramData\chocolatey\lib`. Tamper Protection blocks turning Defender off from a script, but not exclusions. Without them Defender quarantines unpackers and debuggers right after extraction.
3. Copies `win64_remote.exe` and `win32_remote32.exe` from the host's IDA `dbgsrv` folder. If the folder was not found it prints "IDA debug servers NOT copied" instead of silently skipping.
4. Creates firewall rules for WinRM (5985, 5986) and the IDA debug server (23946).
5. Installs enabled tools with Chocolatey, then winget for every failed package and every tool that has only a `winget_id`.
6. Registers the Sysmon service: `Sysmon64a.exe` on ARM64, `Sysmon64.exe` on x64, with the SwiftOnSecurity config when GitHub is reachable.
7. Installs global npm packages (e.g. `@zavora-ai/computer-use-mcp`) and the Computer Use MCP scheduled task, firewall rule, and portproxy.
8. Writes `osquery.conf`, registers `osqueryd` if the package did not, and starts it.
9. Adds tool directories to the machine `PATH`.
10. Checks every catalog `binary_path` in the guest (environment variables and wildcards are expanded) and prints `found` and `missing` lists.

---

## 6. IDA Pro Remote Debugging on Windows VM

IDA Pro can debug native Windows 32-bit and 64-bit binaries remotely over TCP.

1. **Locate Server on Host**:
   - Bundled with IDA Pro under `dbgsrv/`:
     - `win64_remote.exe` (for 64-bit binaries)
     - `win32_remote32.exe` (for 32-bit binaries)
   - Verify via `setup_utm.py`:
     ```bash
     uv run scripts/setup_utm.py ida-server-info
     ```
2. **Transfer to Guest**:
   - Copy `win64_remote.exe` to `C:\Tools\ida_dbgsrv\` on the Windows VM.
3. **Firewall & Port**:
   - Port `23946` is opened automatically by `playbook_windows.yml`.
4. **Run Server on Guest**:
   - In guest PowerShell:
     ```powershell
     cd C:\Tools\ida_dbgsrv
     .\win64_remote.exe -p23946 -PSecretPassword
     ```
5. **Connect from Host IDA Pro**:
   - Select Debugger -> Run -> **Remote Windows debugger**.
   - Set **Hostname**: `<VM_IP>` (or `127.0.0.1` if UTM port-forwarded).
   - Set **Port**: `23946`.
   - Set password if configured.

---

## 7. UTM Snapshot Integration (`setup_utm.py`)

Always capture clean baseline snapshots before detonating untrusted binaries:

```bash
# 1. Check UTM and registered VMs
uv run scripts/setup_utm.py status

# 2. Capture a clean post-provisioning snapshot
uv run scripts/setup_utm.py snapshot-create "Windows-RE-Lab" "Clean-Tools-Provisioned"

# 3. List snapshots to verify
uv run scripts/setup_utm.py snapshot-list "Windows-RE-Lab"

# 4. Revert to baseline after malware run
uv run scripts/setup_utm.py snapshot-restore "Windows-RE-Lab" "Clean-Tools-Provisioned"
---

## 8. Computer Use MCP Server (@zavora-ai/computer-use-mcp)

### 8.1 Overview & Architecture
[`@zavora-ai/computer-use-mcp`](https://github.com/zavora-ai/computer-use-mcp) is a high-performance Model Context Protocol (MCP) server for Windows desktop automation. Built with native Rust NAPI bindings, it exposes low-latency capabilities to AI agents:
- **Screen Capture**: High-speed desktop and window screenshots.
- **Input Automation**: Mouse click, drag, move, scroll, keyboard text typing, and key combination presses.
- **Window Management**: Enumerating windows, focusing, minimizing, maximizing, and resizing.
- **Clipboard**: Reading and writing clipboard contents.

### 8.2 Execution & Connectivity Model

> **Crucial Execution & Network Boundary**:
> 1. **Interactive Desktop Session Required**: Desktop automation tools (screen capture, mouse input, window focus) require an active interactive Windows desktop session (logged into the GUI console or RDP session). Running them under a non-interactive WinRM service session fails because WinRM sessions lack an interactive desktop window station (`WinSta0\Default`). For this reason, the server is registered as a logon Scheduled Task (`ComputerUseMcpServer`) with `logon_type: interactive_token` or started via `C:\Tools\start_computer_use_server.ps1` inside the desktop session.
> 2. **Loopback & Remote Access**: Upstream `computer-use-mcp-console` listens on `127.0.0.1:4517` unauthenticated and requires `--no-open` on Windows to avoid crashing on spawn `open`. To allow host AI agents on the virtual network to connect directly, `netsh interface portproxy` forwards `0.0.0.0:4517` to `127.0.0.1:4517` and Windows Firewall rule `Computer-Use-MCP-Server-In` permits inbound TCP 4517. Alternatively, access can be tunneled via SSH.

### 8.3 Server Management on Windows VM (`start_computer_use_server.ps1`)

The server runner is deployed to `C:\Tools\start_computer_use_server.ps1`. Run inside the Windows VM:
```powershell
# Start the server in the interactive desktop session
C:\Tools\start_computer_use_server.ps1 -Action start -Port 4517

# Inspect running process, listening port, and portproxy configuration
C:\Tools\start_computer_use_server.ps1 -Action status -Port 4517

# Stop the server
C:\Tools\start_computer_use_server.ps1 -Action stop
```

### 8.4 Host AI Agent (MCP Client) Configuration

The Windows VM acts as the **MCP Server**, and the host machine (macOS / Linux / AI Agent) acts as the **MCP Client**.

Generate the client configuration snippet using `setup_windows_vm.py`:
```bash
# SSE format (direct network connection to Windows VM)
uv run scripts/setup_windows_vm.py mcp-client-config --host 192.168.64.12

# Stdio wrapper format via mcp-proxy (for Claude Desktop, Cursor, OMP)
uv run scripts/setup_windows_vm.py mcp-client-config --host 192.168.64.12 --format proxy

# SSH tunnel format (when port 4517 is forwarded via SSH tunnel: ssh -L 4517:127.0.0.1:4517 Administrator@192.168.64.12)
uv run scripts/setup_windows_vm.py mcp-client-config --host 192.168.64.12 --format ssh

Generated config snippets for the Host:
1. **Direct Network / SSE** (`--format sse`):
   ```json
   {
     "mcpServers": {
       "windows-vm-computer-use": {
         "url": "http://192.168.64.12:4517/mcp"
       }
     }
   }
   ```

2. **Stdio proxy wrapper** (`--format proxy`):
   ```json
   {
     "mcpServers": {
       "windows-vm-computer-use": {
         "command": "npx",
         "args": ["-y", "mcp-proxy", "http://192.168.64.12:4517/mcp"]
       }
     }
   }
   ```

3. **SSH Tunnel** (`--format ssh`):
   Forward port first: `ssh -L 4517:127.0.0.1:4517 Administrator@192.168.64.12`
   ```json
   {
     "mcpServers": {
       "windows-vm-computer-use": {
         "url": "http://127.0.0.1:4517/mcp"
       }
     }
   }
   ```
---

## 9. Windows Defender Management for Malware Analysis Labs

### 9.1 Why Disable Defender for Reverse Engineering
In dynamic malware analysis and reverse engineering environments, Windows Defender active protections (Real-Time Monitoring, Behavior Monitoring, IOAV script scanning, cloud sample submission) will quarantine benign RE utilities (e.g. `mimikatz`, `procdot`, custom packers) and prematurely terminate detonated malware samples.

To prevent interference without permanently corrupting OS integrity, Defender is managed via `toggle_defender.ps1` and `playbook_defender.yml`.

### 9.2 PowerShell Script Direct Execution (`toggle_defender.ps1`)
Run inside the Windows VM in an elevated Administrator PowerShell prompt:
```powershell
# Check current status (returns JSON & formatted list)
.\toggle_defender.ps1 -Action status

# Disable Real-Time Protection and add C:\Tools, C:\Workspace exclusions
.\toggle_defender.ps1 -Action disable
# Re-enable Defender protections (preserves and ensures C:\Tools, C:\Workspace exclusions remain active so analysis tools are not quarantined)
.\toggle_defender.ps1 -Action enable

# Re-enable Defender and clear exclusions for a 100% pristine clean baseline
.\toggle_defender.ps1 -Action enable -ClearExclusions

# Specify custom exclusion paths
.\toggle_defender.ps1 -Action disable -ExclusionPaths "C:\Tools", "C:\Samples", "C:\Workspace"
.\toggle_defender.ps1 -Action enable -ExclusionPaths "C:\Tools", "C:\Samples", "C:\Workspace"
```

### 9.3 Remote Management via Helper CLI (`setup_windows_vm.py`)
From the host controller:
```bash
# Check Defender status on guest VM over WinRM
uv run scripts/setup_windows_vm.py defender --action status

# Disable Defender on guest VM over WinRM
uv run scripts/setup_windows_vm.py defender --action disable
# Re-enable Defender (preserves analysis tool exclusions C:\Tools, C:\Workspace by default)
uv run scripts/setup_windows_vm.py defender --action enable

# Re-enable Defender and clear exclusions for pristine baseline testing
uv run scripts/setup_windows_vm.py defender --action enable --clear-exclusions

# Re-enable Defender with custom exclusion paths preserved
uv run scripts/setup_windows_vm.py defender --action enable --exclusions "C:\Tools,C:\Samples,C:\Workspace"

# Export the standalone PowerShell script to transfer manually
uv run scripts/setup_windows_vm.py defender --script-only -o toggle_defender.ps1
