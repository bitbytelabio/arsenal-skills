# IDA Pro Remote Debugging Reference

Run the target in Docker, a UTM VM, or an Android emulator. Control it from IDA on the host through an IDA debug server.

---

## 1. Debug server binaries

Location:
- macOS: `/Applications/IDA Professional 9.x.app/Contents/MacOS/dbgsrv/` (or `$IDADIR/dbgsrv/`)
- Linux: `$IDADIR/dbgsrv/` (e.g. `/opt/ida-pro-9.x/dbgsrv/`)
- Windows: `%IDADIR%\dbgsrv\`

`uv run scripts/setup_utm.py ida-server-info` and `setup_vm.py run-playbook` look in `$IDA_DBGSRV`, `$IDADIR`, `$IDA_DIR`, `/Applications/IDA*.app`, `~/Applications/IDA*.app`, then `/opt/ida*/dbgsrv`.

IDA 9.4 ships (checked with `file`):

| Binary | OS | Arch | Debugger to select in IDA |
|---|---|---|---|
| `linux_server` | Linux | x86_64 | Remote Linux debugger |
| `linux_server32` | Linux | x86 | Remote Linux debugger |
| `armlinux_server` | Linux | AArch64 | Remote ARM Linux/Android debugger |
| `armlinux_server32` | Linux | ARMv7 | Remote ARM Linux/Android debugger |
| `armlinux_serverhf32` | Linux | ARMv7 hard-float | Remote ARM Linux/Android debugger |
| `win64_remote.exe` | Windows | x64 | Remote Windows debugger |
| `win32_remote32.exe` | Windows | x86 | Remote Windows debugger |
| `mac_server` | macOS | x86_64 | Remote Mac OS X debugger |
| `mac_server_arm` | macOS | arm64 | Remote ARM Mac OS debugger |
| `mac_server_arme` | macOS | arm64e | Remote ARM Mac OS debugger |
| `android_server` | Android | arm64 | Remote ARM Linux/Android debugger |
| `android_server32` | Android | ARM 32-bit | Remote ARM Linux/Android debugger |
| `android_x64_server` | Android | x86_64 | Remote Linux debugger |
| `android_x86_server` | Android | x86 | Remote Linux debugger |

There is no `linux_server64` or `armlinux_server64` in IDA 9.x; the unsuffixed name is 64-bit.

Server options (IDA 9.4 `--help`):

| Flag | Meaning |
|---|---|
| `-p PORT`, `--port-number` | Listen port (default 23946) |
| `-i IP`, `--ip-address` | Bind address (default any) |
| `-P PASS`, `--password` | Session password |
| `-t`, `--no-tls` | Plain TCP instead of TLS |
| `-c FILE`, `--certchain-file` / `-k FILE`, `--privkey-file` | TLS certificate and key |
| `-k`, `--on-broken-connection-keep-session` | Keep the debuggee when the link drops |
| `-K`, `--on-stop-kill-process` | Kill the debuggee when the session closes |
| `-v`, `--verbose` | Verbose log |

Use the server from the same IDA version as the client.

---

## 2. Docker

```bash
DBGSRV="$(ls -d /Applications/IDA*.app/Contents/MacOS/dbgsrv | tail -n1)"
mkdir -p work && cp "$DBGSRV/armlinux_server" work/    # linux_server on an x86_64 engine
docker run --rm -it \
  --name ida_debug_target \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -p 23946:23946 \
  -v "$PWD/work":/workspace -w /workspace \
  ubuntu:24.04 /workspace/armlinux_server -p23946
```

- `-p 23946:23946`: publishes the server on host `127.0.0.1:23946`.
- `--cap-add=SYS_PTRACE`: needed for `ptrace(2)`; without it attach and breakpoints fail.
- `--security-opt seccomp=unconfined`: the default profile blocks `personality(ADDR_NO_RANDOMIZE)` and some tracing calls.
- Do not add `--pid=host`, `--ipc=host`, `--privileged`, or `--network host` for an untrusted sample. Each one lets the sample reach outside the container. The hardened profile is in [malware-sandbox-isolation.md](../02-dynamic-instrumentation/malware-sandbox-isolation.md).

On Apple Silicon, an `--platform linux/amd64` container runs under emulation. ptrace inside it is unreliable. Debug arm64 builds with `armlinux_server`, or use an x86_64 VM.

ASLR inside the container follows the Docker VM kernel. Disable it per process with `setarch -R ./target` or globally in the VM with `sysctl -w kernel.randomize_va_space=0` (needs `--privileged`).

Dockerfile:

```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends gdb strace ltrace file \
    && rm -rf /var/lib/apt/lists/*
COPY armlinux_server /opt/dbgsrv/armlinux_server
RUN chmod +x /opt/dbgsrv/armlinux_server
EXPOSE 23946
CMD ["/opt/dbgsrv/armlinux_server", "-p23946"]
```

---

## 3. UTM virtual machines

The provisioning playbooks stage the servers and open the firewall:

| Guest | Server path | Firewall |
|---|---|---|
| Windows | `C:\Tools\ida_dbgsrv\win64_remote.exe`, `win32_remote32.exe` | Rule `IDA-Pro-Remote-Debugger`, TCP 23946 |
| Linux | `/opt/ida_dbgsrv/linux_server`, `linux_server32` (x86_64) or `armlinux_server`, `armlinux_server32` (ARM64) | UFW (Debian/Ubuntu) or firewalld (RHEL/Fedora), TCP 23946 |
| macOS | `/opt/ida_dbgsrv/mac_server_arm` (Apple Silicon) or `mac_server` | PF anchor `com.re.tools` (PF itself is not enabled by the play) |

The play copies them only when it gets `ida_dbgsrv_src`. `setup_vm.py run-playbook` fills it in automatically. If the play prints "IDA debug servers NOT copied", run `IDA_DBGSRV=/path/to/dbgsrv uv run scripts/setup_vm.py run-playbook --os <os>`.

Windows 11 on Apple Silicon is ARM64. `win64_remote.exe` runs there under x64 emulation and debugs x64 and x86 processes. IDA 9.4 has no native ARM64 Windows server, so native ARM64 PE targets need WinDbg in the guest.

### Network modes

| UTM mode | How IDA reaches the server |
|---|---|
| Shared Network (default, vmnet) | Guest IP on `192.168.64.0/24`. No port forwarding in this mode |
| Emulated VLAN (QEMU user net) | Port forward host `127.0.0.1:23946` → guest `23946`, connect to `127.0.0.1` |
| Bridged | Guest LAN IP |
| Host Only | Guest IP on the host-only subnet |

Get the guest IP (QEMU backend with guest agent only):

```bash
VM="Linux-RE-Lab"          # name or UUID from: utmctl list
utmctl ip-address "$VM"
```

Without a guest agent, read the IP in the guest (`ip -4 addr`, `ipconfig`, `ipconfig getifaddr en0`) or on the host from `/var/db/dhcpd_leases` (Shared Network and Apple NAT).

Emulated VLAN forward: VM Settings > Network > Network Mode **Emulated VLAN** > **Port Forwarding** > New: TCP, guest port `23946`, host address `127.0.0.1`, host port `23946`. Add host `2222` → guest `22` for SSH the same way. Use Emulated VLAN when the guest gets no DHCP lease on Shared Network (seen with the Ubuntu cloud image on UTM 5).

### Linux guest

```bash
sudo sysctl -w kernel.yama.ptrace_scope=0      # the playbook sets this persistently
/opt/ida_dbgsrv/armlinux_server -p23946         # linux_server on x86_64
```

For fixed addresses, set `sudo sysctl -w kernel.randomize_va_space=0` in the guest.

### Windows guest

```powershell
New-NetFirewallRule -DisplayName "IDA Remote Debugger" -Direction Inbound -LocalPort 23946 -Protocol TCP -Action Allow
C:\Tools\ida_dbgsrv\win64_remote.exe -p23946
```

Run it from an elevated prompt to debug elevated or service processes. From the host without the GUI (QEMU guest agent):

```bash
VM="Windows-RE-Lab"
uv run scripts/setup_utm.py guest-exec "$VM" cmd.exe \
  --args /c start "" 'C:\Tools\ida_dbgsrv\win64_remote.exe' -p23946
```

Quote Windows paths in single quotes on the host shell; bash removes unquoted backslashes. A server started by the guest agent runs as SYSTEM in session 0 and cannot show GUI windows of the debuggee.

### macOS guest

```bash
/opt/ida_dbgsrv/mac_server_arm -p23946      # run with sudo to attach to other users' processes
```

Hardened-runtime or platform binaries without `get-task-allow` cannot be attached while SIP is on. Disable SIP in the guest's Recovery (`csrutil disable`) for those targets.

---

## 4. Android emulator

```bash
DBGSRV="$(ls -d /Applications/IDA*.app/Contents/MacOS/dbgsrv | tail -n1)"
adb shell getprop ro.product.cpu.abi           # arm64-v8a -> android_server, x86_64 -> android_x64_server
adb push "$DBGSRV/android_server" /data/local/tmp/android_server
adb shell chmod 755 /data/local/tmp/android_server
adb forward tcp:23946 tcp:23946
adb shell su -c '/data/local/tmp/android_server -p23946'
```

On a Play Store image `su` comes from KernelSU ([host-and-lab-setup.md](host-and-lab-setup.md) section 3). Without root you can only debug a `debuggable` app as its own uid (`run-as`). In IDA use **Remote ARM Linux/Android debugger** with host `127.0.0.1`, port `23946`.

---

## 5. IDA client setup

1. **Debugger > Select debugger...** and pick the debugger from the table in section 1.
2. **Debugger > Process options...**:

| Field | Value |
|---|---|
| Application | Target path on the server machine (`/workspace/target`, `C:\Workspace\sample.exe`) |
| Input file | Same path as the IDB's input on the server machine |
| Directory | Working directory on the server machine |
| Parameters | Command-line arguments |
| Hostname | `127.0.0.1` (Docker, Emulated VLAN forward, `adb forward`) or the guest IP |
| Port | `23946` or the `-p` value |
| Password | The `-P` value, else empty |

3. **Debugger > Debugger options...**: **Suspend on process entry point**, **Suspend on library load/unload** as needed.
4. **Debugger > Start process** (F9) launches the target. **Debugger > Attach to process...** attaches to a running PID.

### From an agent

Use only the official HexRaysSA `ida-mcp` server. Load the bounded helper and follow [../04-tool-usage/ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md). Debugger choice, process options, and the entry breakpoint map to `re_dbg.load`, `re_dbg.start`, and `break_on_entry`.

---

## 6. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Connection refused on `127.0.0.1:23946` | No forward: UTM NIC is Shared Network, or Docker run without `-p` | Switch the NIC to Emulated VLAN and add the forward, or connect to the guest IP; re-run Docker with `-p 23946:23946` |
| Connection refused on the guest IP | Server not running or bound elsewhere | Guest: `ss -ltnp \| grep 23946` (Linux), `netstat -ano \| findstr 23946` (Windows), `lsof -iTCP:23946 -sTCP:LISTEN` (macOS) |
| Connection times out | Guest firewall | Linux `sudo ufw allow 23946/tcp`; Windows rule above; macOS application firewall: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /opt/ida_dbgsrv/mac_server_arm` |
| `utmctl ip-address` errors | No QEMU guest agent, or Apple backend VM | Install `qemu-guest-agent` (Linux) or UTM Guest Tools (Windows); for Apple VMs read the IP in the guest or `/var/db/dhcpd_leases` |
| Handshake fails right after connect | Server copied from a different IDA version | Copy the server from the same IDA install as the client |
| "Bad password" in the server log | `-P` set, client password empty or different | Match the password in Process options |
| `ptrace: Operation not permitted` (Linux) | Yama `ptrace_scope` ≥ 1, or Docker without `SYS_PTRACE` | `sysctl kernel.yama.ptrace_scope=0`; add `--cap-add=SYS_PTRACE` |
| Attach denied (macOS guest) | Target is hardened/platform binary, SIP on | Run server with sudo; `DevToolsSecurity -enable`; disable SIP for system targets |
| Attach denied (Windows) | Target elevated or protected (PPL) | Start `win64_remote.exe` elevated; PPL processes need a kernel debugger |
| "Wrong debugger" / no reply | Debugger plugin does not match server (e.g. Remote Linux debugger to `win64_remote.exe`) | Pick the debugger from the table in section 1 |
| `exec format error` starting the server | Wrong architecture (x86_64 server on an ARM64 guest) | `uname -m` / `file target`; use `armlinux_server` on aarch64 |
| Android: `android_server` exits at once | Not root, SELinux denial, or wrong ABI | `su -c`; check `getprop ro.product.cpu.abi`; `adb logcat \| grep avc` |
