# Host And Lab Setup

This is part of the reverse-engineering skill. `scripts/` and `ansible/` are relative to that skill directory, not the sample workspace.

Detect first. Install only after the parent asks to prepare this machine, and
only the one profile that matches the task.

## 1. Detect

On Windows, macOS, and Linux run the same command. Do not call `python3`.
Do not add a shell script, PowerShell script, or batch file.

From this skill's directory:

`uv run scripts/detect_host.py`

Or reference via skill URI:
`uv run scripts/detect_host.py`.
Read the single JSON object on stdout.

- `os` is `linux`, `darwin`, or `windows`.
- `package_manager` is the first of `brew`, `apt-get`, `dnf`, `pacman`, and
  `winget` that exists, or `null`.
- `tools` maps each name to `present` and `path`. Monitored tools include
  `radare2`, `jadx`, `apktool`, `binwalk`, `frida`, `mitmproxy`, `tshark`,
  `adb`, `emulator`, `avdmanager`, `sdkmanager`, `qemu`, `vmrun`,
  `xcrun`, `ida-mcp`, `vphone-cli`, `ipsw`, `utmctl`, `qemu-img`, `ansible`, and `ansible-playbook`.
- `hypervisor.preferred` is `kvm` on Linux, `utm` on macOS, and
  `vmware` on Windows. `hypervisor.present` indicates availability of that hypervisor.
  On macOS, `hypervisor.utm_present`, `hypervisor.utmctl_path`, and
  `hypervisor.qemu_img_present` indicate UTM and QCOW2 tool readiness. UTM also
  supports rich macOS AppleScript (`tell application "UTM"`) automation for disposable
  mode (`start without saving`), network isolation, QEMU Guest Agent execution/file transfer,
  and input automation.
  `hypervisor.qemu_present` is separate. Do not prefer raw QEMU over the platform
  hypervisor.
- `android.su` is `null` unless `--probe-android` was passed.
- `android.setup_script` reports the path to `setup_android_emulator.py`.
- `ios.supported` is true only on macOS. Elsewhere `ios.reason` is
  `iOS tooling runs on macOS only`.
- `ios.simctl` indicates availability of Xcode `simctl`.
- `ios.vphone_present` indicates presence of `vphone` or `vphone-cli`.
- `ios.vphone_preflight_passed` indicates whether `vphone-cli host preflight` succeeded (virtualization host prerequisites and escalator authorization are satisfied).
- `ios.rooted_vm_supported` indicates whether the host architecture supports
  rooted Apple Silicon virtual machines (`arm64`/`aarch64`).
- `ios.rooted_vm_solution` points to `https://github.com/Lakr233/vphone-cli`.
- `proxy_ca.cert_present` indicates whether mitmproxy CA certificate exists (`~/.mitmproxy/mitmproxy-ca-cert.pem`).
- `proxy_ca.subject_hash` and `proxy_ca.hash_filename` report the old subject hash (e.g. `c8750f0d` and `c8750f0d.0`).
- `proxy_ca.script` reports the path to `setup_proxy_ca.py`.
- `kernelsu.status` is `available`.
- `kernelsu.auto_download` is `true`.
- `kernelsu.cache_dir` reports the active cache directory (`~/.cache/android-ksu` or
  `ANDROID_KSU_CACHE_DIR`).
A missing tool is not permission to fetch a random installer.

## 2. Install

Skip this step unless the parent asked. Pass one flag:

- static: `uv run scripts/detect_host.py --install static`
- dynamic: `uv run scripts/detect_host.py --install dynamic`
- android: `uv run scripts/detect_host.py --install android`
- ios: `uv run scripts/detect_host.py --install ios`

The program installs only through the detected package manager, and only
packages that manager already knows. Commands are argument lists inside the
program. It never uses `sudo`. If the manager needs root, it installs nothing
and puts the exact command in `needs_root`. Show that command to the parent.
Do not run it yourself and do not prefix `sudo`.

Then run `uv run scripts/detect_host.py` again with no install flag. Report
what is present, missing, manual, and unsupported.

### Profiles

- static: `radare2`, `apktool`, `mitmproxy`, `tshark`, `binwalk`, `jadx` where
  that OS packages them. Winget ids that are not known are `unmapped`.
- dynamic: on Linux, `qemu-kvm` and `qemu-system-x86` when KVM is the
  preferred hypervisor and those packages exist. On macOS UTM is the sole
  preferred hypervisor. On Windows do not install VMware. The hypervisor is
  `manual`.
- android: `android-platform-tools` on brew, or `adb` on apt, plus an
  emulator package only when the distro package exists.
- ios: if `os` is not `darwin`, the program exits 2, installs nothing, and
  the reason is `iOS tooling runs on macOS only`. On macOS do not install
  Xcode. Report whether `simctl` is missing. For rooted iOS research VMs on
  Apple Silicon, use `vphone-cli` (see section 5).
Never install IDA, `ida-mcp`, or a Frida server binary onto a device.

---

## 3. Android Studio KernelSU Emulator Rooting Procedure

Production-grade Android security analysis (dynamic Frida hooking, Play Integrity API
testing, unmasking root detection) requires root on **Google Play images** rather than
AOSP / Google APIs images via Android Studio KernelSU GKI rooting methodology.

### System Requirements
- Host: Apple Silicon macOS (M1/M2/M3/M4, `arm64-v8a`) or Linux/Windows equivalent.
- Android SDK: Command-line tools (`avdmanager`, `sdkmanager`), platform tools (`adb`), emulator.
- System Image: `system-images;android-36;google_apis_playstore;arm64-v8a` (or `android-37.0`).
- KernelSU Assets: GKI kernel `Image` (or AnyKernel3 zip e.g., `6.6.66-android15-*.zip`, `6.12.58-android16-*.zip`) and `KernelSU_Next_*.apk` automatically downloaded from official GitHub releases to `~/.cache/android-ksu/` (or custom directory specified via `--download-dir`).
### Manual Step-by-Step Procedure

1. **Check Emulator Kernel Version**:
   ```bash
   adb shell uname -r
   # Example: 6.6.66-android15-8 or 6.12.58-android16
   ```

2. **Obtain KernelSU GKI Kernel (`Image`)**:
   Kernel zips are automatically fetched by `setup_android_emulator.py` into `~/.cache/android-ksu/`. If extracted manually from AnyKernel3 zip:
   ```bash
   unzip -p ~/.cache/android-ksu/6.6.66-android15-*.zip Image > /tmp/Image
   ```

3. **Locate and Replace `kernel-ranchu`**:
   The emulator kernel is inside the Android SDK system image directory:
   ```bash
   SYS_IMG="$HOME/Library/Android/sdk/system-images/android-36/google_apis_playstore/arm64-v8a"
   cp "$SYS_IMG/kernel-ranchu" "$SYS_IMG/kernel-ranchu.orig"
   cp /tmp/Image "$SYS_IMG/kernel-ranchu"
   ```

4. **Cold Boot the Emulator**:
   A cold boot is mandatory to bypass emulator kernel caching from quickboot snapshots:
   ```bash
   emulator -avd <AVD_NAME> -no-snapshot-load
   ```

5. **Wait for Device & Boot Completion**:
   ```bash
   adb wait-for-device
   while [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" != "1" ]; do sleep 2; done
   ```

6. **Install KernelSU Manager APK**:
   ```bash
   adb install -r ~/.cache/android-ksu/KernelSU_Next_*.apk
   ```

7. **Verify Root Access**:
   ```bash
   adb shell su -c id
   # Output must be: uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
   ```

## 4. Automated Emulator Setup Script (`setup_android_emulator.py`)

The companion automated script implements the full workflow cleanly:
`uv run scripts/setup_android_emulator.py <subcommand>`
Supported subcommands:
- `list`: Inspects SDK path, tools, installed system images, AVDs, and KernelSU assets in cache directory (`~/.cache/android-ksu/`).
- `download [--kernel-version <ver>] [--apk-only] [--kernel-only]`: Automatically downloads the matching KernelSU GKI kernel AnyKernel3 zip from WildKernels and Manager APK from KernelSU-Next GitHub releases.
- `create-avd [--name <name>] [--system-image <pkg>] [--device <device>]`: Creates AVD with `avdmanager`, finds its `config.ini` (honoring `ANDROID_AVD_HOME`, `ANDROID_USER_HOME`, `ANDROID_SDK_HOME`, and `<sdk>/.android/avd`), and sets `PlayStore.enabled=yes` for a `google_apis_playstore` image. avdmanager leaves it off.
- `patch-kernel [--system-image-path <path>] [--kernel-source <image_or_zip>]`: Returns `already_patched` without changes when `kernel-ranchu` already contains KernelSU (some recent Play images ship one). Otherwise backs up `kernel-ranchu` to `.orig` and replaces it with KernelSU GKI `Image` (auto-downloading matching kernel zip from GitHub releases if missing, extracting `Image`).
- `cold-boot [--avd <name>] [--headless]`: Starts emulator with `-no-snapshot-load` (and optional `-no-window -no-audio`).
- `wait-boot [--serial <serial>] [--timeout <sec>]`: Waits for `sys.boot_completed == 1`.
- `install-apk [--apk <path>] [--serial <serial>]`: Installs `KernelSU_Next_*.apk` via `adb install -r` (auto-downloading Manager APK from GitHub releases if missing), then launches the manager once so it installs `ksud` and the su bridge.
- `verify-root [--serial <serial>]`: Tries `su`, `/system/bin/su`, `/debug_ramdisk/su`, and `/data/adb/ksu/bin/su` with `-c id` and confirms `uid=0`. On failure it returns a `hint`: grant Superuser to Shell in the manager, and on KernelSU-Next turn off **Settings > Umount modules**, which hides `su` from the adb shell.
- `setup-all [--avd <name>] [--headless] [--timeout <sec>]`: Executes end-to-end download/patch, boot, install, and verification.
All subcommands support `--json`, before or after the subcommand name.
---

## 5. iOS Rooted Research Virtual Machine (`vphone-cli`)

For dynamic analysis requiring a rooted iOS environment (kernel/jailbreak-level inspection,
Frida server injection, tweaking system daemons, SSL unpinning):

### Unrooted Simulator vs Rooted Research VM
- **Standard iOS Simulator (`xcrun simctl`)**: Runs simulator Mach-O binaries in macOS userland; unrooted, lacks full iOS kernel/security sandbox isolation, and cannot run arm64e iOS device binaries or substrate-based jailbreak tweaks.
- **Rooted iOS Research VM (`vphone-cli`)**: Bootstrapped by [vphone-cli](https://github.com/Lakr233/vphone-cli) (by Lakr233). Boots virtual iPhone (iOS 26) on Apple Silicon macOS leveraging Apple's `Virtualization.framework` and Private Cloud Compute (PCC) research VM infrastructure.

### Host Prerequisites & Preflight
- **Host**: macOS 15+ running on Apple Silicon (M1/M2/M3/M4, `arm64`).
- **Research Guest Entitlements / AMFI Policy**: Requires enabling research guest capability:
  ```bash
  sudo csrutil allow-research-guests enable
  ```
  (Requires reboot in Recovery OS if prompted by macOS).
- **VPhoneEscalator Authorization**:
  `vphone-cli` utilizes an escalator helper daemon to acquire necessary hypervisor privileges. Authorize the built VM helper:
  ```bash
  sudo VPhoneEscalator allow /path/to/vphone-cli/build/vphone-vm
  ```
  This grants Virtualization.framework entitlements without requiring global SIP disabling.
- **Host Preflight (`vphone_preflight_passed`)**:
  Verify readiness by running `vphone-cli host preflight`. When preflight passes (`vphone-vm can launch`), the host is ready to create and boot the virtual iPhone using `vphone-cli vm create`.

### Firmware Sources (`blacktop/ipsw` & `ipsw.me`)
Acquiring official Apple IPSW firmware files for research VM bootstrapping or kernel/dyld analysis:
- **`blacktop/ipsw` CLI tool** ([blacktop/ipsw](https://github.com/blacktop/ipsw)):
  Comprehensive CLI tool for downloading IPSWs, extracting kernelcache, splitting dyld shared cache, and inspecting Mach-O metadata:
  ```bash
  # Install via Homebrew
  brew install blacktop/tap/ipsw
  # Download IPSW by device model and iOS version
  ipsw download ipsw --device iPhone16,1 --build ...
  # Extract and decompress kernelcache
  ipsw kernel dec <kernelcache>
  # Split dyld shared cache
  ipsw dyld split <dyld_shared_cache> <out_dir>
  ```
- **`https://ipsw.me/` direct portal**:
  Web-based lookup portal ([ipsw.me](https://ipsw.me/)) indexing all signed and unsigned Apple IPSW release links directly hosted on Apple CDN (`updates.cdn-apple.com`). Allows manual browser download filtered by device identifier, release date, and build number.

### Rooted VM Setup & Jailbreak Firmware Patch
- Build or acquire `vphone-cli`:
  ```bash
  git clone https://github.com/Lakr233/vphone-cli.git
  cd vphone-cli
  make
  ```
- Use the **Jailbreak (JB) firmware patch variant** (`make fw_patch_jb` or `JB=1`, 112 patches) which provides:
  - Full root shell access (`ssh root@<vm-ip>`).
  - Sileo package manager and APT repository support.
  - TrollStore integration for installing and resigning arbitrary research payloads.
  - Frida server / dynamic runtime hooking support directly within the virtualized iOS environment.

## 6. Mitmproxy CA Certificate Installation & SSL Pinning Bypass

Dynamic HTTPS traffic inspection requires establishing a trusted root certificate on the
target environment and bypassing application-level certificate pinning.

### Android System CA Requirements
- **Android 7 - 16 CA Behavior**: Starting in Android 7 (Nougat, API 24), apps by default ignore user-installed CAs (`/data/misc/user/0/cacerts-added/`). To intercept traffic from standard and production apps without repacking, the certificate must reside in the system trust store: `/system/etc/security/cacerts/<hash>.0`.
- **Subject Hash Old**: The filename format requires `<hash>.0`, where `<hash>` is computed via:
  ```bash
  openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout
  # Example output: c8750f0d -> filename: c8750f0d.0
  ```
- **Installation Mechanics on Android**:
  1. **KernelSU / Magisk Module (OverlayFS)**: On modern Android (API 34/35/36/37) where system partitions use EROFS / read-only mounts, `setup_proxy_ca.py` automatically generates a module in `/data/adb/modules/mitmproxy-ca/system/etc/security/cacerts/<hash>.0` with `module.prop` and `chmod 644`.
  2. **Direct System Remount**: Attempts `mount -o rw,remount /` or `/system` and copies to `/system/etc/security/cacerts/<hash>.0`.
  3. **Tmpfs Mount Overlay**: Fallback mounting tmpfs over `/system/etc/security/cacerts` copying existing certs plus the proxy CA.

### Global HTTP Proxy Configuration
- Route emulator traffic to host mitmproxy (default emulator gateway is `10.0.2.2`):
  ```bash
  adb shell settings put global http_proxy 10.0.2.2:8080
  ```
- Clear proxy:
  ```bash
  adb shell settings put global http_proxy :0
  ```

### iOS Simulator & Research VM CA Installation
- **iOS Simulator**: Uses macOS `simctl` to inject the CA cert directly into the simulator keychain:
  ```bash
  xcrun simctl keychain booted add-root-cert ~/.mitmproxy/mitmproxy-ca-cert.pem
  ```
- **iOS Research VM (`vphone-cli`)**: Transfer `mitmproxy-ca-cert.pem` via SCP/HTTP, open in Safari to install Configuration Profile, then navigate to `Settings > General > About > Certificate Trust Settings` and enable full trust for root certificates.

### Universal Frida SSL Pinning Bypass
Even with system CA installed, applications using Certificate Pinning (OkHttp3 `CertificatePinner`, TrustKit, Conscrypt, `SecTrustEvaluateWithError`) will abort TLS handshakes. Universal Frida bypass scripts unpin these layers at runtime:

- **Android (`ssl_unpin_android.js`)**:
  - Implements an all-trusting `X509TrustManager` and hooks `SSLContext.init`.
  - Hooks OkHttp3 `CertificatePinner.check(String, List)`, `CertificatePinner.check(String, Cert[])`, and Kotlin mangled `check$okhttp`.
  - Bypasses Conscrypt `TrustManagerImpl.checkTrustedRecursive` and `verifyChain`.
  - Intercepts `WebViewClient.onReceivedSslError` to invoke `handler.proceed()`.
  - Hooks `NetworkSecurityConfig.isCleartextTrafficPermitted`.

- **iOS (`ssl_unpin_ios.js`)**:
  - Hooks Security.framework `SecTrustEvaluateWithError` (returns 1 and clears error).
  - Hooks `SecTrustEvaluate` (sets `kSecTrustResultProceed` / 1, returns 0).
  - Hooks `NSURLSession` delegate challenge handling (`URLSession:didReceiveChallenge:completionHandler:`).
  - Hooks AFNetworking / `AFSecurityPolicy` (`- evaluateServerTrust:forDomain:`).

### Automated Script (`setup_proxy_ca.py`)

The companion automated script implements the full workflow cleanly:
`uv run scripts/setup_proxy_ca.py <subcommand>` (or `uv run scripts/setup_proxy_ca.py <subcommand>`)
Supported subcommands:
- `status`: Checks `~/.mitmproxy/mitmproxy-ca-cert.pem`, computes old subject hash, reports `<hash>.0`.
- `export-ca [--out-dir <dir>]`: Exports formatted `<hash>.0` cert with subject details.
- `set-android-proxy [--host <ip>] [--port <port>] [--serial <serial>]`: Sets global HTTP proxy (defaults to `10.0.2.2:8080`).
- `clear-android-proxy [--serial <serial>]`: Clears global HTTP proxy (`:0`).
- `install-android [--serial <serial>]`: Pushes `<hash>.0` and installs via KernelSU module or system remount.
- `install-ios-sim [--device <udid_or_booted>]`: Adds root CA to iOS Simulator keychain via `simctl`.
- `export-frida-scripts [--out-dir <dir>]`: Generates `ssl_unpin_android.js` and `ssl_unpin_ios.js`.

All subcommands support `--json`, before or after the subcommand name.
---

## 7. UTM Hypervisor & QCOW2 Snapshot Management

On macOS Apple Silicon (`arm64`), UTM provides hardware-accelerated guest virtualization
with near bare-metal performance via Apple's `Virtualization.framework`, alongside QEMU
emulation for cross-architecture targets.

### VM Control & Snapshots (`utmctl` & AppleScript)
- List virtual machines: `utmctl list`
- Inspect status: `utmctl status <vm_uuid_or_name>`
- Create snapshot: `utmctl snapshot create <vm> --name <name>`
- Restore snapshot: `utmctl snapshot restore <vm> --snapshot <name>`
- Query IP: `utmctl ip-address <vm>`
- **Disposable Execution**: `start vm without saving` via AppleScript discards all disk writes upon VM shutdown.
- **Host Isolation & Sandboxing**: `isolate from host of nic to true` blocks guest access to macOS host on shared NAT; use Host-Only network (Section 5.3) for full air-gapped containment.
- **Guest Agent & Input Automation**: Network-less file push/pull, command execution (`cmd_guest_exec`), and display input injection (`send-input`).
### QCOW2 Disk Architecture & Snapshots (`qemu-img`)
- **Copy-On-Write Overlays**: Keep master OS base images read-only (`-b base.qcow2 -F qcow2`) and execute dynamic analysis on disposable differential disks.
- **Internal Snapshots**: Manage ad-hoc checkpoints via `qemu-img snapshot [-c|-a|-d|-l]`.
- Read [`references/utm-hypervisor-and-snapshots.md`](utm-hypervisor-and-snapshots.md) for sandbox lifecycle details, copy-on-write overlays, and networking topologies.

### Automated Script (`setup_utm.py`)
Run helper: `uv run scripts/setup_utm.py <subcommand>`
- `list-vms`: Enumerates registered VMs with UUID and status.
- `start-disposable <vm>`: Starts VM in disposable mode (`start vm without saving` via AppleScript).
- `guest-exec <vm> <cmd> [--timeout N] [--args ...]`: Executes command inside guest via QEMU Guest Agent without network/SSH. Everything after `--args` goes to the guest verbatim, including `-NoProfile` or `/c`, so put `--timeout` and `--json` before `--args`. Example: `guest-exec Win cmd.exe --timeout 120 --args /c powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\setup_winrm.ps1`.
- `guest-push <vm> <host_file> <guest_path>`: Copies file from host to guest via QEMU Guest Agent.
- `guest-pull <vm> <guest_file> <host_path>`: Copies file from guest to host via QEMU Guest Agent.
- `send-input <vm> [--text TEXT] [--click X Y]`: Injects keystrokes or mouse clicks to VM display.
- `snapshot-list <vm>`: Lists snapshots for VM.
- `snapshot-create <vm> <name>`: Creates a snapshot.
- `snapshot-restore <vm> <name>`: Restores a snapshot.
- `qcow2-create <output_path> <size_gb> [--backing <base_path>]`: Creates QCOW2 disk image.
- `qcow2-snapshot <qcow2_path> [--create <n> | --restore <n> | --list | --delete <n>]`: Manages internal QCOW2 snapshots.
- `ida-server-info`: Locates IDA `dbgsrv` and prints Docker/UTM configuration templates.
All subcommands support `--json`.
---

## 8. IDA Pro Remote Debugging (Docker Remote IPC & UTM VM Setup)

Dynamic binary analysis often requires running target binaries in isolated execution
environments (Docker containers or UTM virtual machines) while controlling execution
from IDA Pro on the host.

### Debug Server Binaries (`dbgsrv`)
IDA Pro bundles standalone debug servers inside its installation directory under `dbgsrv/`.
Resolve the directory dynamically via `$IDADIR/dbgsrv`, `/Applications/IDA*.app/Contents/MacOS/dbgsrv`,
or automatically via `uv run scripts/setup_utm.py ida-server-info`:
- `armlinux_server` / `armlinux_server32`: Linux ARM64 / ARMv7
- `win64_remote.exe` / `win32_remote32.exe`: Windows x64 / x86
- `android_server` / `android_x64_server`: Android ARM / x86_64
- `mac_server` / `mac_server_arm`: macOS x86_64 / Apple Silicon

### Docker Remote Debugging with Host IPC
Debugging inside containers requires port mapping, `ptrace(2)` capabilities, and IPC sharing:
```bash
docker run --rm -it \
  --ipc=host \
  --pid=host \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -p 23946:23946 \
  -v "$(pwd)":/workspace \
  <image> /workspace/linux_server -p23946
```

### UTM VM Remote Debugging
- **Shared Network (NAT)**: Add Port Forwarding rule in UTM Network Settings (`Host Port 23946` -> `Guest Port 23946`). In IDA Pro, connect to `127.0.0.1:23946`.
- **Bridged Network**: Obtain guest IP with `utmctl ip-address <vm>`, connect to `<guest_ip>:23946`.
- **Android Emulator**: Forward port via `adb forward tcp:23946 tcp:23946`, push `android_server` to `/data/local/tmp/`, and run via `adb shell su -c ...`.
Read [`references/ida-remote-debugging.md`](ida-remote-debugging.md) for full setup guides, GUI process options, and troubleshooting steps.
---

## 9. Virtual Machine Ansible Provisioning & Tool Catalogs (Windows, Linux, macOS)

For reverse engineering, malware analysis, forensic triage, and live telemetry on guest VMs (under UTM on macOS, KVM on Linux, or VMware on Windows), automated provisioning is provided via Ansible, structured JSON tool catalogs, and a unified helper CLI (`setup_vm.py`).

### Tool Catalogs
- **Windows (`ansible/windows_tools.json`)**: 7 core categories covering `osquery`, `sysmon`, `tshark` / `wireshark`, `fiddler`, `mitmproxy`, `sysinternals` (Procmon, Procexp, Autoruns), `x64dbg`, `ghidra`, `cutter`, `radare2`, `windbg`, `die`, `pestudio`, `pe-bear`, `yara`, `7zip`, `git`, `python3`, `hxd`, `ida_dbgsrv` (port 23946), and `computer-use-mcp` (port 4517).
- **Linux (`ansible/linux_tools.json`)**: Distro packages (APT, DNF, Pacman) covering `osquery`, `tshark`, `tcpdump`, `gdb`, `radare2`, `ghidra`, `strace`, `ltrace`, `binwalk`, `yara`, `checksec`, `upx`, `python3`, `uv`, `git`, `curl`, `7zip`, `ida_dbgsrv` (port 23946), and `computer-use-mcp` (port 4517).
- **macOS (`ansible/macos_tools.json`)**: Homebrew formulae and casks covering `osquery`, `tshark`, `radare2`, `ghidra`, `binwalk`, `yara`, `ipsw`, `jtool2`, `python3`, `uv`, `git`, `p7zip`, `curl`, `ida_dbgsrv` (port 23946), and `computer-use-mcp` (port 4517).

### Helper CLI (`setup_vm.py` / `setup_windows_vm.py`)
Run helper: `uv run scripts/setup_vm.py <subcommand> [--os {windows,linux,macos}]` (or `uv run scripts/setup_vm.py <subcommand>`):
- `summary [--os OS] [--json]`: Show high-level tool counts and category breakdown.
- `list [--os OS] [--category CAT] [--tag TAG] [--enabled-only] [--json]`: Enumerate tools in the specified OS catalog.
- `enable-tool [--os OS] <id>` / `disable-tool [--os OS] <id>`: Toggle tools in the catalog.
- `add-tool [--os OS]`: Add a new tool to catalog with schema validation.
- `winrm-script [-o <path>]`: Print or export `setup_winrm.ps1` for execution on Windows guest VMs.
- `generate-inventory [--os OS] --host <ip> --user <user> [--password <pass>] [--key-file <key>]`: Generate ready-to-use `inventory_<os>.ini`.
- `run-playbook [--os OS] [-i <inv>] [--check] [--tags <t>] [-v]`: Run `playbook_<os>.yml` against guest VM.
- `defender [--action status|disable|enable] [--clear-exclusions] [--exclusions <paths>] [--script-only [-o <path>]] [-i <inv>]`: Manage Windows Defender realtime protection and exclusions locally or remotely (Windows only).
- `mcp-client-config [--os OS] --host <ip> [--port 4517] [--format sse|proxy|ssh]`: Generate Host (macOS/Linux/Agent) MCP client configuration snippet.

### Provisioning Workflows

#### Windows Guests (WinRM)
1. Run `setup_winrm.ps1` in an elevated Administrator PowerShell prompt on the Windows VM.
2. Generate inventory:
   `uv run scripts/setup_vm.py generate-inventory --os windows --host <VM_IP> --user Administrator --password <PASS>`
3. Test connection: `ansible windows_vms -i ansible/inventory_windows.ini -m win_ping`
4. Run playbook: `uv run scripts/setup_vm.py run-playbook --os windows -v`
5. Read [`references/windows-vm-ansible-setup.md`](windows-vm-ansible-setup.md) for detailed WinRM steps, Defender toggle, and troubleshooting.

#### Linux Guests (SSH)
1. Install and start SSH server on guest VM (`sudo apt install -y openssh-server`).
2. Generate inventory:
   `uv run scripts/setup_vm.py generate-inventory --os linux --host <VM_IP> --user <USER> --key-file ~/.ssh/id_ed25519`
3. Test connection: `ansible linux_vms -i ansible/inventory_linux.ini -m ping`
4. Run playbook: `uv run scripts/setup_vm.py run-playbook --os linux -v`
   - Configures `sysctl kernel.yama.ptrace_scope = 0` for debugger process attachment.
   - Opens ports `23946` (IDA) and `4517` (MCP) in UFW / firewalld.
   - Stages `/opt/ida_dbgsrv` and installs tools via APT / DNF / Pacman.
5. Read [`references/linux-vm-ansible-setup.md`](linux-vm-ansible-setup.md) for full distro steps.

#### macOS Guests (SSH on Apple Silicon)
1. Complete setup in UTM and enable **Remote Login** in **System Settings** -> **General** -> **Sharing**.
2. Generate inventory:
   `uv run scripts/setup_vm.py generate-inventory --os macos --host <VM_IP> --user <USER> --key-file ~/.ssh/id_ed25519`
3. Test connection: `ansible macos_vms -i ansible/inventory_macos.ini -m ping`
4. Run playbook: `uv run scripts/setup_vm.py run-playbook --os macos -v`
   - Bootstraps Homebrew if missing.
   - Configures Packet Filter (PF) firewall for ports `23946` (IDA) and `4517` (MCP).
   - Stages `/opt/ida_dbgsrv` and installs formulae and casks.
5. Read [`references/macos-vm-ansible-setup.md`](macos-vm-ansible-setup.md) for full Apple Silicon virtualization steps.
---

## 10. Troubleshooting & Setup Bug Reference

When emulator or rooted-VM setup fails, match the reported symptom before
retrying privileged steps. Common failure modes include macOS AMFI rejecting
`vphone-vm`, `cfw install` lacking host-mount privileges or restore artifacts,
APFS cleanup remaining busy, the upstream `vphoned` read-only completion-marker
bug that removes Irisin executables during rollback, Pyright result-type
shadowing, and workstation-specific cache paths.

Read
[`references/vm-root-troubleshooting.md`](vm-root-troubleshooting.md)
for the exact symptoms, technical root causes, and verified fixes for all seven
Android/iOS setup bugs.

---

## 11. Never

- Do not launch an untrusted malware sample outside isolated sandbox conditions.
- Do not rewrite `mcp.json` or run `rea setup` or `rea doctor`.
- Do not flash a physical connected device with emulator kernels.
