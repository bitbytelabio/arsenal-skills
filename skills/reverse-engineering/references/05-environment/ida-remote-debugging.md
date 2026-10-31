# IDA Pro Remote Debugging Reference

Comprehensive guide to configuring IDA Pro remote debugging servers across Linux, Windows, Android, Docker containers, and UTM virtual machines.

---

## 1. IDA Pro Debug Server Binaries

IDA Pro bundles standalone debug server binaries inside its installation directory:
- macOS: `$IDADIR/dbgsrv/` or dynamically under `/Applications/IDA*.app/Contents/MacOS/dbgsrv/`
- Custom / Linux install: `$IDADIR/dbgsrv/` or `/opt/ida*/dbgsrv/`
- Windows host: `%IDADIR%\dbgsrv\` or `C:\Program Files\IDA*\dbgsrv\`

### Server Binary Architecture Mapping

| Binary Name | Target OS | Target CPU Architecture | Typical Use Case |
|---|---|---|---|
| `linux_server` | Linux | x86_64 (64-bit) | Standard Linux ELF binaries, Docker containers, x64 VMs |
| `linux_server32` | Linux | x86 (32-bit) | Legacy 32-bit Linux binaries, CTFs |
| `armlinux_server` | Linux | AArch64 (ARM64 64-bit) | Linux on Apple Silicon UTM, Raspberry Pi, ARM servers |
| `armlinux_server32` | Linux | ARM (32-bit ARMv7) | Embedded Linux, IoT devices |
| `armlinux_serverhf32` | Linux | ARM Hard Float (ARMv7 HF) | Embedded Linux with hardware FPU |
| `win64_remote.exe` | Windows | x86_64 (64-bit) | Modern Windows 64-bit PE binaries, malware triage |
| `win32_remote32.exe` | Windows | x86 (32-bit) | 32-bit Windows PE binaries |
| `mac_server` | macOS | x86_64 (64-bit) | Intel macOS binaries |
| `mac_server_arm` | macOS | ARM64 (Apple Silicon) | Native Apple Silicon Mach-O binaries |
| `mac_server_arme` | macOS | ARM64e (PAC-enabled) | Apple Silicon binaries utilizing Pointer Authentication |
| `android_server` | Android | ARM64 / ARMv7 | Android native `.so` shared libraries, JNI reversing |
| `android_server32` | Android | ARM 32-bit | Legacy 32-bit Android native libraries |
| `android_x64_server` | Android | x86_64 | Android Studio x86_64 emulator images |
| `android_x86_server` | Android | x86 | Android Studio 32-bit x86 emulator images |

---

## 2. Docker Container Remote Debugging

Debugging binaries inside Docker containers requires mapping ports, granting kernel tracing capabilities, and configuring inter-process communication (IPC) namespaces.

### Standard Docker Command Template

```bash
docker run --rm -it \
  --name ida_debug_target \
  --ipc=host \
  --pid=host \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -p 23946:23946 \
  -v "$(pwd)":/workspace \
  -w /workspace \
  ubuntu:24.04 /bin/bash
```

### Explaining Critical Container Flags

- **`-p 23946:23946`**: Forwards the default IDA Pro remote debug server port from container to host `127.0.0.1`.
- **`--cap-add=SYS_PTRACE`**: Grants the Linux capability required for `ptrace(2)` system calls. Without this capability, `linux_server` fails to attach to processes or set hardware/software breakpoints.
- **`--security-opt seccomp=unconfined`**: Disables the default Docker seccomp filter which can block tracing and process inspection syscalls.
- **`--ipc=host`**: Shares the host IPC namespace. This enables POSIX shared memory (`shm_open`), sysv IPC semaphores, and inter-process synchronization between debugger tools and target processes.
- **`--pid=host`**: (Optional) Shares the host PID namespace, allowing `linux_server` inside the container to inspect and attach to processes running on the host or in sibling containers.

### Running Debug Server in Container

Copy `linux_server` (or `armlinux_server` if on an ARM64 container) into the container workspace and execute:

```bash
# Make binary executable
chmod +x /workspace/linux_server

# Start debug server listening on port 23946 (with optional password -P<pwd>)
/workspace/linux_server -p23946

# To disable ASLR for repeatable debugging addresses:
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Dockerfile Template for Isolated RE Environments

```dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    build-essential \
    gdb \
    strace \
    ltrace \
    curl \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dbgsrv
COPY linux_server /opt/dbgsrv/linux_server
RUN chmod +x /opt/dbgsrv/linux_server

EXPOSE 23946
CMD ["/opt/dbgsrv/linux_server", "-p23946"]
```

---

## 3. UTM Virtual Machine Remote Debugging

When analyzing samples inside a UTM guest (Windows or Linux), follow the network and guest configuration steps below.

### 1. Shared Network (NAT) Port Forwarding
1. Open UTM VM Settings -> **Network**.
2. Network Mode: **Shared Network**.
3. Under **Port Forwarding**, add a new rule:
   - Protocol: `TCP`
   - Host Port: `23946`
   - Guest Port: `23946`
   - Guest IP: Leave blank.
4. Save and boot the VM.
5. In IDA Pro on macOS, target host is `127.0.0.1` and port is `23946`.

### 2. Bridged Network
1. Set Network Mode to **Bridged (Advanced)**.
2. The VM obtains an IP directly from the local router.
3. Discover the IP address via:
   ```bash
   utmctl ip-address "<VM_NAME_OR_UUID>"
   ```
4. In IDA Pro on macOS, set the hostname to `<guest_ip>` and port to `23946`.

### Guest Configuration: Linux VM
1. Transfer `linux_server` (or `armlinux_server` for ARM64 Linux VM) to the guest.
2. Grant execution permissions:
   ```bash
   chmod +x ./linux_server
   ```
3. Disable ASLR if repeatable memory locations are required:
   ```bash
   echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
   ```
4. Start the server:
   ```bash
   ./linux_server -p23946
   ```

### Guest Configuration: Windows VM
1. Transfer `win64_remote.exe` (or `win32_remote32.exe`) into the Windows guest.
2. Open Windows Firewall port 23946 or run an elevated PowerShell prompt:
   ```powershell
   New-NetFirewallRule -DisplayName "IDA Remote Debugger" -Direction Inbound -LocalPort 23946 -Protocol TCP -Action Allow
   ```
3. Start the debug server with Administrator privileges:
   ```cmd
   win64_remote.exe -p23946
   ```

---

## 4. Android Emulator Setup (`adb forward`)

Debugging native Android code (`.so` libraries, unpackers, anti-tamper mechanisms) using IDA Pro:

### Step 1: Forward Debug Server Port via ADB
```bash
# Forward host TCP port 23946 to Android emulator TCP port 23946
adb forward tcp:23946 tcp:23946
```

### Step 2: Push Server Binary to Android Device
Select the binary matching emulator architecture (`android_server` for ARM/ARM64, or `android_x64_server` for x86_64 Google APIs image):
```bash
# Resolve dbgsrv dynamically or via setup_utm.py ida-server-info
DBGSRV_DIR="${IDADIR:-$(ls -d /Applications/IDA*.app/Contents/MacOS/dbgsrv 2>/dev/null | head -n1)}"
adb push "$DBGSRV_DIR/android_server" /data/local/tmp/android_server
adb shell chmod 755 /data/local/tmp/android_server
```

### Step 3: Run Server as Root via `su`
```bash
adb shell "su -c '/data/local/tmp/android_server -p23946'"
```

---

## 5. IDA Pro GUI Client Configuration

Once the remote server binary is running on the target (Docker, UTM VM, or Android), configure IDA Pro:

### 1. Select the Remote Debugger
1. In the top menu, go to **Debugger -> Select debugger...** (or press `F2`).
2. Choose the appropriate remote debugger engine:
   - For Linux: **Remote Linux debugger**
   - For Windows: **Remote Windows debugger**
   - For Android / ARM Linux: **Remote ARM Linux/Android debugger**
   - For macOS: **Remote Mac OS X debugger**

### 2. Set Process Options
Go to **Debugger -> Process options...**:

| Option | Value / Description |
|---|---|
| **Application** | Absolute path to target executable on the *guest* filesystem (e.g. `/workspace/target_elf` or `C:\malware\sample.exe`). |
| **Input file** | Path to the binary file on the *host* (defaults to current IDB binary path). |
| **Directory** | Working directory on the guest (e.g. `/workspace` or `C:\malware`). |
| **Parameters** | CLI arguments passed to the guest application. |
| **Hostname** | Target IP address (`127.0.0.1` for Docker / NAT port forwarding, or guest LAN IP for Bridged). |
| **Port** | `23946` (or custom port passed to `-p`). |
| **Password** | Leave blank unless `-P<password>` was passed to server binary. |

### 3. Breakpoint & Execution Options
- **Debugger -> Debugger options...**:
  - Check **Suspend on process entry point** to pause before any initialization code runs.
  - Check **Suspend on library load/unload** to capture dynamic loader (`dlopen` / `LoadLibrary`) events.
- Press **F9** to connect to the remote server and start execution.
- Press **Attach to process...** under Debugger menu to attach to an already running PID in the guest.

---

## 6. Verification and Troubleshooting Checklist

1. **Connection Refused (`127.0.0.1:23946`)**:
   - Verify server binary is actively listening on the guest:
     ```bash
     ss -tulpn | grep 23946   # Linux
     netstat -ano | findstr 23946 # Windows
     ```
   - Verify UTM port forwarding rule is saved and active.
   - For Docker, ensure `-p 23946:23946` was specified at `docker run` time.
2. **Permission Denied / Cannot Attach**:
   - Ensure `--cap-add=SYS_PTRACE` was provided for Docker.
   - Ensure debug server was launched with `sudo` / `su` / Administrator rights.
3. **Architecture Mismatch**:
   - Connecting `Remote Linux debugger` to `win64_remote.exe` fails. Match debugger plugin to guest server binary.
   - Verify guest binary architecture via `file <binary>` before selecting `linux_server` (x86_64) vs `armlinux_server` (ARM64).
