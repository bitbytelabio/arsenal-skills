# Windows VM Ansible Provisioning

Provision a Windows analysis VM (UTM on macOS, VMware, or Hyper-V) over WinRM with `ansible/playbook_windows.yml` and the catalog `ansible/windows_tools.json`. Run commands from the skill directory.

---

## 1. What gets installed

From `ansible/windows_tools.json` (26 entries, all enabled except `procdot`):

| Category | Tools (catalog id → package) |
|---|---|
| telemetry_monitoring | `osquery` (choco `osquery`), `sysmon` (choco `sysmon`) |
| network_analysis | `tshark` (choco `wireshark`), `fiddler`, `mitmproxy` |
| forensics_triage | `sysinternals`, `autoruns`, `procmon`, `procdot` (off; no package) |
| debugging_disassembly | `x64dbg` (choco `x64dbg.portable`), `ghidra`, `cutter`, `radare2`, `windbg` (winget `Microsoft.WinDbg` only), `ida_dbgsrv` (copied from host) |
| pe_analysis | `die`, `pestudio`, `pe-bear` (choco `pebear`), `yara` |
| system_utilities | `7zip`, `git`, `python3` (choco `python312`), `hxd`, `curl`, `nodejs` (choco `nodejs-lts`) |
| automation_agent | `computer-use-mcp` (npm `@zavora-ai/computer-use-mcp`) |

Every entry with a Chocolatey package also has a `winget_id` fallback. Ports: WinRM 5985/5986, IDA 23946, Computer Use MCP 4517.

`uv run scripts/setup_windows_vm.py` and `uv run scripts/setup_vm.py` are the same CLI. `--os` defaults to `windows`.

---

## 2. Guest preparation (WinRM)

Export the script on the host:

```bash
uv run scripts/setup_vm.py winrm-script -o setup_winrm.ps1
```

Copy it into the guest (shared folder, or `guest-push` if the QEMU guest agent runs), then in an elevated PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\setup_winrm.ps1                 # -HttpPort 5985 -HttpsPort 5986
```

Or from the host through the guest agent:

```bash
VM="Windows-RE-Lab"
uv run scripts/setup_utm.py guest-push "$VM" ansible/setup_winrm.ps1 'C:\Windows\Temp\setup_winrm.ps1'
uv run scripts/setup_utm.py guest-exec "$VM" cmd.exe --timeout 120 \
  --args /c powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Windows\Temp\setup_winrm.ps1'
```

The script:
- Sets Public network profiles to Private.
- Sets `WinRM` to Automatic, starts it, runs `winrm quickconfig -q -force`.
- Enables Basic and Negotiate auth and `AllowUnencrypted` (lab only), raises WSMan limits, creates an HTTP listener if missing.
- Opens firewall rules `WinRM-HTTP-In` (5985) and `WinRM-HTTPS-In` (5986). It does not create an HTTPS listener.
- Sets `LocalAccountTokenFilterPolicy=1` so a local admin gets a full token over WinRM.

---

## 3. Network

| Hypervisor / mode | Inventory host |
|---|---|
| UTM Shared Network | Guest IP (`192.168.64.x`). No port forwarding in this mode |
| UTM Emulated VLAN | `127.0.0.1` with a forward, e.g. host `59850` → guest `5985`; pass `--port 59850` |
| UTM Bridged | Guest LAN IP |
| UTM Host Only | Guest IP; no internet, so package installs fail |
| VMware | Host-only (`vmnet1`) or NAT (`vmnet8`) guest IP |
| Hyper-V | Default Switch guest IP |

Get the IP with `utmctl ip-address "$VM"` (needs UTM Guest Tools) or `ipconfig` in the guest.

Windows 11 ARM on UTM needs UTM Guest Tools (NetKVM driver) before it has any network. Provision on Shared Network; Host Only has no route to Chocolatey or winget feeds. Switch to Host Only after provisioning if you need containment.

---

## 4. Catalog management

```bash
uv run scripts/setup_vm.py summary
uv run scripts/setup_vm.py list --category debugging_disassembly
uv run scripts/setup_vm.py list --tag forensics --enabled-only --json
uv run scripts/setup_vm.py disable-tool ghidra
uv run scripts/setup_vm.py enable-tool ghidra
uv run scripts/setup_vm.py add-tool \
  --id xorsearch \
  --name XORSearch \
  --category pe_analysis \
  --description "Search XOR/ROL/ROT encoded strings" \
  --choco xorsearch \
  --binary-path 'C:\ProgramData\chocolatey\bin\XORSearch.exe' \
  --tags "search,xor,pe"
```

`--id`, `--name`, `--category`, and `--binary-path` are required. A catalog entry looks like:

```json
{
  "id": "osquery",
  "name": "osquery",
  "category": "telemetry_monitoring",
  "choco_package": "osquery",
  "winget_id": "Facebook.osquery",
  "binary_path": "C:\\Program Files\\osquery\\osqueryi.exe",
  "service_name": "osqueryd",
  "enabled": true,
  "tags": ["telemetry", "monitoring", "sql", "auditing"]
}
```

`binary_path` may contain `%VARS%` and wildcards; the playbook expands both in the guest.

---

## 5. Provisioning

### 5.1 Controller dependencies

```bash
uv run scripts/setup_vm.py deps            # report; exit 1 if something is missing
uv run scripts/setup_vm.py deps --install  # collections + pywinrm into Ansible's own Python
```

With a uv- or brew-installed Ansible, pywinrm must go into Ansible's interpreter, not the `python3` on PATH. `deps` reads it from the `ansible-playbook` shebang.

### 5.2 Inventory

```bash
VM_IP=192.168.64.15
uv run scripts/setup_vm.py generate-inventory --os windows \
  --host "$VM_IP" --user Administrator --password 'MalwareAnalysisLab2026!'
```

This writes `ansible/inventory_windows.ini`:

```ini
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

`--transport credssp` or `--port 5986` switch the scheme to `https`; that needs an HTTPS listener in the guest, which `setup_winrm.ps1` does not create. See `ansible/inventory.example.ini` for a port-forwarded host line.

### 5.3 Test

```bash
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES \
  ansible windows_vms -i ansible/inventory_windows.ini -m ansible.windows.win_ping
```

```text
win-re-vm | SUCCESS => {
    "changed": false,
    "ping": "pong"
}
```

### 5.4 Run

```bash
uv run scripts/setup_vm.py run-playbook --os windows --check
uv run scripts/setup_vm.py run-playbook --os windows -v
uv run scripts/setup_vm.py run-playbook --os windows --extra-vars ida_dbgsrv_src=/path/to/dbgsrv
```

`run-playbook` sets `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` on macOS and passes `ida_dbgsrv_src` from `$IDA_DBGSRV`, `$IDADIR`, or `/Applications/IDA*.app`.

Play order:
1. Create `C:\Tools`, `C:\Workspace`, `C:\Tools\ida_dbgsrv`.
2. Add Defender exclusions `C:\Tools`, `C:\Workspace`, `C:\ProgramData\chocolatey\lib`. Tamper Protection does not block exclusions.
3. Copy `win64_remote.exe` and `win32_remote32.exe` from the host. Without a source it prints "IDA debug servers NOT copied".
4. Firewall rules `WinRM-HTTP-In` (5985), `WinRM-HTTPS-In` (5986), `IDA-Pro-Remote-Debugger` (23946).
5. Bootstrap Chocolatey, install each Chocolatey package (failures do not stop the play).
6. Retry failed packages and winget-only tools with winget. winget is an App Execution Alias and is not on PATH in a WinRM network logon. The task resolves `winget.exe` under `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*` and runs it with `become_method: runas` as the WinRM user, so MSIX packages (WinDbg) register for that user. Exit `-1978335189` (already installed) counts as success.
7. Register Sysmon (`Sysmon64a.exe` on ARM64, `Sysmon64.exe` on x64) with the SwiftOnSecurity config when GitHub is reachable.
8. `npm install -g` for npm entries.
9. Computer Use MCP: copy `C:\Tools\start_computer_use_server.ps1`, firewall rule `Computer-Use-MCP-Server-In` (4517), portproxy `0.0.0.0:4517` → `127.0.0.1:4517`, scheduled task `ComputerUseMcpServer` at logon (`interactive_token`).
10. Write `C:\Program Files\osquery\osquery.conf` if absent, register `osqueryd` if needed, start it.
11. Add tool folders to the machine `PATH` (Wireshark, chocolatey\bin, osquery, x64dbg, `C:\radare2\bin`, `C:\Tools\ida_dbgsrv`, `C:\Python312`, nodejs).
12. Check every `binary_path` and print `found` / `missing`.

### 5.5 Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `win_ping` hangs, then the worker dies; log shows `objc[...]: +[NSCharacterSet initialize] may have been in progress in another thread when fork() was called` | macOS fork safety kills pywinrm's forked worker | `export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` (the `setup_vm.py` runners set it) |
| `winrm or requests is not installed` | pywinrm in the wrong Python | `uv run scripts/setup_vm.py deps --install` |
| `ntlm: HTTPConnectionPool ... 401` / `the specified credentials were rejected` | Wrong password, or Microsoft account instead of a local account, or `LocalAccountTokenFilterPolicy` not set | Use a local admin; re-run `setup_winrm.ps1`; for `.\user` style names use `ansible_user=.\Administrator` |
| `basic: 401` | Basic auth disabled or unencrypted HTTP blocked | Re-run `setup_winrm.ps1` (enables Basic and `AllowUnencrypted`) or use `--transport ntlm` |
| `500 WinRMTransport` / `MaxEnvelopeSizekb` errors | Large module payloads or quota | `Set-Item WSMan:\localhost\MaxEnvelopeSizekb 8192` in the guest |
| `Connection refused` on 5985 | No listener or firewall on Public profile | `winrm enumerate winrm/config/listener`; re-run `setup_winrm.ps1` |
| `Read timed out` during a large install | Timeouts too short | Raise `ansible_winrm_read_timeout_sec` (must exceed `operation_timeout_sec`) |
| `winget: The term 'winget' is not recognized` | winget not on PATH under WinRM | Use the playbook's resolved path with `become_method: runas`; install App Installer if `WindowsApps\Microsoft.DesktopAppInstaller_*` is missing |
| winget `0x8A15000F` / source errors | Source not initialised for that user | `winget source reset --force` in an interactive session, then rerun |
| Chocolatey `Unable to obtain lock file access on 'C:\ProgramData\chocolatey\lib\<hash>'` | Another choco run, or a lock left by a killed run | Wait for the other run (`Get-Process choco`); otherwise delete the named lock file and any `lib-bad\<pkg>`, rerun |
| Chocolatey downloads fail | No internet (Host Only) or NetKVM missing | Shared Network + UTM Guest Tools during provisioning |
| Package installed but `missing` in summary | Catalog `binary_path` differs from the package layout | Check the real path, fix with `add-tool`/edit the JSON |
| Sysmon task fails | `Sysmon64a.exe` not found on ARM64 | Install `Microsoft.Sysinternals.Sysmon` with winget, rerun |
| Defender quarantines tools right after install | Exclusions not added (Tamper Protection is not the cause) | Check `Get-MpPreference \| Select ExclusionPath`; run `defender --action disable` |

---

## 6. IDA remote debugging

1. `uv run scripts/setup_utm.py ida-server-info` shows the host `dbgsrv` path.
2. The playbook copies `win64_remote.exe` and `win32_remote32.exe` to `C:\Tools\ida_dbgsrv\` and opens TCP 23946.
3. In the guest (elevated):
   ```powershell
   C:\Tools\ida_dbgsrv\win64_remote.exe -p23946 -PSecretPassword
   ```
4. In IDA: **Debugger > Select debugger... > Remote Windows debugger**, then **Debugger > Process options...**: Hostname = guest IP (or `127.0.0.1` with an Emulated VLAN forward), Port = `23946`, Password = `SecretPassword`.

Details and troubleshooting: [ida-remote-debugging.md](ida-remote-debugging.md).

---

## 7. Snapshots

Take a clean baseline after provisioning, with the VM shut down:

```bash
VM="Windows-RE-Lab"
uv run scripts/setup_utm.py status
uv run scripts/setup_utm.py snapshot-create "$VM" Clean-Tools-Provisioned
uv run scripts/setup_utm.py snapshot-list "$VM"
uv run scripts/setup_utm.py snapshot-restore "$VM" Clean-Tools-Provisioned
```

These call `utmctl snapshot` (UTM 5.0.8+). On older UTM, stop the VM and use `uv run scripts/setup_utm.py qcow2-snapshot <disk.qcow2> --create Clean-Tools-Provisioned`. See [utm-hypervisor-and-snapshots.md](utm-hypervisor-and-snapshots.md).

---

## 8. Computer Use MCP (`@zavora-ai/computer-use-mcp`)

[`@zavora-ai/computer-use-mcp`](https://github.com/zavora-ai/computer-use-mcp) (npm, Rust NAPI core) gives MCP clients screenshots, mouse, keyboard, clipboard, and window control.

- Desktop automation needs an interactive session. A WinRM session has no `WinSta0\Default`. The playbook registers the logon task `ComputerUseMcpServer` (`interactive_token`), so log in to the console (UTM auto-login or RDP) for it to start.
- The task runs `computer-use-mcp-console --no-demo --no-open` on `127.0.0.1:4517`. `--no-open` stops it from trying to spawn `open` on Windows.
- The server has no authentication. The portproxy `0.0.0.0:4517` → `127.0.0.1:4517` and firewall rule `Computer-Use-MCP-Server-In` expose it to the VM network. Keep the VM on a host-only or Shared network.

In the guest:

```powershell
C:\Tools\start_computer_use_server.ps1 -Action start -Port 4517
C:\Tools\start_computer_use_server.ps1 -Action status -Port 4517
C:\Tools\start_computer_use_server.ps1 -Action restart
C:\Tools\start_computer_use_server.ps1 -Action stop
```

On the host:

```bash
uv run scripts/setup_vm.py mcp-client-config --os windows --host "$VM_IP"                 # url http://<ip>:4517/mcp
uv run scripts/setup_vm.py mcp-client-config --os windows --host "$VM_IP" --format proxy  # npx -y mcp-proxy http://<ip>:4517/mcp
ssh -N -L 4517:127.0.0.1:4517 "Administrator@$VM_IP" &                                  # needs OpenSSH Server in the guest
uv run scripts/setup_vm.py mcp-client-config --os windows --host "$VM_IP" --format ssh    # url http://127.0.0.1:4517/mcp
```

Output shape (`--format sse`, the default):

```json
{
  "mcpServers": {
    "windows-vm-computer-use": {
      "url": "http://192.168.64.15:4517/mcp"
    }
  }
}
```

Give the snippet to the parent. Do not rewrite `mcp.json` yourself.

---

## 9. Windows Defender

Defender quarantines unpackers and dumpers and kills samples mid-run. `toggle_defender.ps1` and `playbook_defender.yml` manage it. Tamper Protection blocks `disable`; turn it off by hand in Windows Security first. `status` reports `IsTamperProtected`.

In the guest (elevated):

```powershell
.\toggle_defender.ps1 -Action status
.\toggle_defender.ps1 -Action disable                       # adds C:\Tools, C:\Workspace exclusions
.\toggle_defender.ps1 -Action enable                        # keeps exclusions
.\toggle_defender.ps1 -Action enable -ClearExclusions
.\toggle_defender.ps1 -Action disable -ExclusionPaths "C:\Tools","C:\Samples","C:\Workspace"
```

From the host (uses `ansible/inventory.ini`, falling back to `ansible/inventory_windows.ini`; pass `-i` to be explicit):

```bash
uv run scripts/setup_vm.py defender --action status -i ansible/inventory_windows.ini
uv run scripts/setup_vm.py defender --action disable -i ansible/inventory_windows.ini
uv run scripts/setup_vm.py defender --action enable -i ansible/inventory_windows.ini
uv run scripts/setup_vm.py defender --script-only -o toggle_defender.ps1
```

`--exclusions` replaces the default exclusion list (`C:\Tools,C:\Workspace`). `--clear-exclusions` removes those paths when Defender is managed:

```bash
uv run scripts/setup_vm.py defender --action enable --clear-exclusions -i ansible/inventory_windows.ini
```
