# Host And Lab Setup

This is part of the reverse-engineering skill. `scripts/` and `ansible/` are relative to the skill directory, not the sample workspace. Run every command below from the skill directory.

Detect first. Install only after the parent asks to prepare this machine, and only the one profile that matches the task.

## 1. Detect

Windows, macOS, and Linux use the same command. Do not call `python3`. Do not add a shell, PowerShell, or batch wrapper.

```bash
uv run scripts/detect_host.py
uv run scripts/detect_host.py --probe-android   # also runs adb shell su -c id
```

The script has no `--help`; any unknown flag prints its usage as a JSON error. Read the single JSON object on stdout:

- `os` is `linux`, `darwin`, or `windows`.
- `package_manager` is the first of `brew`, `apt-get`, `dnf`, `pacman`, `winget` that exists, or `null`.
- `tools` maps each name to `present` and `path`: `radare2`, `jadx`, `apktool`, `binwalk`, `frida`, `mitmproxy`, `tshark`, `adb`, `emulator`, `avdmanager`, `sdkmanager`, `qemu`, `vmrun`, `xcrun`, `ida-mcp`, `vphone-cli`, `ipsw`, `utmctl`, `qemu-img`, `ansible`, `ansible-playbook`.
- `hypervisor.preferred` is `kvm` on Linux, `utm` on macOS, `vmware` on Windows. `hypervisor.present` says whether it is installed. On macOS, `utm_present`, `utmctl_path`, and `qemu_img_present` report UTM and QCOW2 readiness. `qemu_present` is separate; do not prefer raw QEMU over the platform hypervisor.
- `android.adb`, `android.emulator`, `android.setup_script`. `android.su` is `null` unless `--probe-android` was passed.
- `ios.supported` is true only on macOS; elsewhere `ios.reason` is `iOS tooling runs on macOS only`. `ios.simctl`, `ios.vphone_present`, `ios.vphone_preflight_passed` (`vphone-cli host preflight` succeeded), `ios.rooted_vm_supported` (host is `arm64`), `ios.rooted_vm_solution` (`https://github.com/Lakr233/vphone-cli`).
- `kernelsu.status`, `kernelsu.auto_download`, `kernelsu.cache_dir` (`~/.cache/android-ksu`, or `$ANDROID_KSU_CACHE_DIR`), `kernelsu.system_image_roots`, `kernelsu.kernel_ranchu` (every emulator kernel found).
- `proxy_ca.cert_present`, `proxy_ca.cert_path`, `proxy_ca.subject_hash` and `proxy_ca.hash_filename` (old subject hash, e.g. `c8750f0d` / `c8750f0d.0`), `proxy_ca.script`.

A missing tool is not permission to fetch a random installer.

## 2. Install

Skip this step unless the parent asked. Pass one profile:

```bash
uv run scripts/detect_host.py --install static
uv run scripts/detect_host.py --install dynamic
uv run scripts/detect_host.py --install android
uv run scripts/detect_host.py --install ios
```

The program installs only through the detected package manager and only packages that manager knows. It never uses `sudo`. If the manager needs root (`apt-get`, `dnf`, `pacman`), it installs nothing and puts the exact command in `needs_root`. Show that command to the parent. Do not run it and do not prefix `sudo`.

Then run `uv run scripts/detect_host.py` again without a flag. Report what is present, missing, manual, and unsupported.

### Profiles

- static: `radare2`, `apktool`, `mitmproxy`, `tshark`, `binwalk`, `jadx` where the OS packages them. Unknown winget ids are reported as `unmapped`.
- dynamic: on Linux, `qemu-kvm` and `qemu-system-x86` when those packages exist. On macOS the hypervisor is UTM. On Windows VMware is `manual`; the program does not install it.
- android: `android-platform-tools` on brew or `adb` on apt, plus an emulator package only when the distro has one.
- ios: if `os` is not `darwin`, exit code 2, nothing installed. On macOS it does not install Xcode; it reports whether `simctl` is missing. For a rooted iOS VM see section 5.

Never install IDA, `ida-mcp`, or a Frida server binary onto a device.

---

## 3. Rooted Android Emulator (KernelSU on a Google Play image)

Play Store images are `user` builds: `adb root` and `-writable-system` do not work there. Google APIs images allow `adb root`, but Play Integrity and many apps behave differently on them. To get root on a Play image, swap the emulator kernel for a KernelSU GKI kernel.

### Requirements

- Android SDK: `cmdline-tools` (`avdmanager`, `sdkmanager`), `platform-tools` (`adb`), `emulator`. macOS default root: `~/Library/Android/sdk`.
- Image: `system-images;android-36;google_apis_playstore;arm64-v8a` (also seen: `android-36.1`, `android-37.0`, and `_ps16k` 16 KB-page variants). Install with `sdkmanager "system-images;android-36;google_apis_playstore;arm64-v8a"`.
- KernelSU assets: an AnyKernel3 zip from `WildKernels/GKI_KernelSU_SUSFS` whose kernel version matches `uname -r` (e.g. `6.6.66-android15-*`, `6.12.58-android16-*`), and the `KernelSU_Next_*.apk` manager. The script downloads both into `~/.cache/android-ksu/` (or `--download-dir`, or `$ANDROID_KSU_CACHE_DIR`).

### Manual procedure

```bash
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
SYS_IMG="$SDK/system-images/android-36/google_apis_playstore/arm64-v8a"
AVD=ksu_playstore

# 1. Kernel version of the running emulator
adb shell uname -r                      # e.g. 6.6.66-android15-8-...

# 2. Extract the GKI Image from the matching AnyKernel3 zip
unzip -p ~/.cache/android-ksu/6.6.66-android15-*.zip Image > /tmp/Image

# 3. Back up and replace kernel-ranchu (shared by every AVD on this image)
cp "$SYS_IMG/kernel-ranchu" "$SYS_IMG/kernel-ranchu.orig"
cp /tmp/Image "$SYS_IMG/kernel-ranchu"

# 4. Cold boot; a Quick Boot snapshot would keep the old kernel
"$SDK/emulator/emulator" -avd "$AVD" -no-snapshot-load

# 5. Wait for boot
adb wait-for-device
until [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = "1" ]; do sleep 2; done

# 6. Install and open the manager once (it installs ksud and the su bridge)
adb install -r ~/.cache/android-ksu/KernelSU_Next_*.apk

# 7. Verify
adb shell su -c id                      # expect uid=0(root) gid=0(root) ... context=u:r:su:s0
```

Restore the stock kernel with `cp "$SYS_IMG/kernel-ranchu.orig" "$SYS_IMG/kernel-ranchu"` and another cold boot. An SDK update of the system image overwrites the patched kernel.

### KernelSU vs Magisk on the emulator

| | KernelSU / KernelSU-Next | Magisk (rootAVD) |
|---|---|---|
| Root lives in | Kernel (GKI `Image` in `kernel-ranchu`) | Patched `ramdisk.img` |
| Kernel version | Must match `uname -r` major.minor and the GKI KMI | Any |
| su domain | `u:r:su:s0` | `u:r:magisk:s0` |
| Modules | `/data/adb/modules`, OverlayFS (or magic mount in KernelSU-Next) | `/data/adb/modules`, magic mount |
| Zygisk | Not built in. Install the Zygisk Next module | Built in (Settings > Zygisk) |
| LSPosed | Needs Zygisk Next (or ReZygisk) + LSPosed (JingMatrix fork) module | Zygisk + LSPosed module |
| Hide root from apps | Per-app "Umount modules" (default on for non-root apps) | DenyList + Shamiko |

## 4. Automated emulator setup (`setup_android_emulator.py`)

```bash
uv run scripts/setup_android_emulator.py [--download-dir DIR] [--json] <subcommand>
```

| Subcommand | Flags | What it does |
|---|---|---|
| `list` | | SDK path, tools, system images, AVDs, cached KernelSU assets |
| `download` | `--kernel-version VER`, `--apk-only`, `--kernel-only` | Fetches the AnyKernel3 zip (WildKernels) and the KernelSU-Next manager APK (falls back to `tiann/KernelSU`) |
| `create-avd` | `--name`, `--system-image PKG`, `--device`, `--force` | `avdmanager create avd`, finds `config.ini` (honors `ANDROID_AVD_HOME`, `ANDROID_USER_HOME`, `ANDROID_SDK_HOME`), sets `PlayStore.enabled=yes` for a `google_apis_playstore` image (avdmanager leaves it off). An existing AVD of the same name is overwritten only with `--force` |
| `patch-kernel` | `--system-image-path DIR`, `--kernel-source IMAGE_OR_ZIP` | Returns `already_patched` when `kernel-ranchu` already has KernelSU. Otherwise writes `kernel-ranchu.orig` and installs the GKI `Image` (downloads the zip if missing) |
| `cold-boot` | `--avd`, `--headless` | `emulator -no-snapshot-load` (`--headless` adds `-no-window -no-audio`) |
| `wait-boot` | `--serial`, `--timeout` (default 180) | Waits for `sys.boot_completed=1` |
| `install-apk` | `--apk`, `--serial` | `adb install -r` the manager (downloads it if missing), launches it once so it installs `ksud` |
| `verify-root` | `--serial` | Tries `su`, `/system/bin/su`, `/debug_ramdisk/su`, `/data/adb/ksu/bin/su` with `-c id`. On failure returns a `hint` |
| `setup-all` | `--avd`, `--device`, `--headless`, `--timeout` | create, patch, cold boot, wait, install, verify |

`--json` works before or after the subcommand. Example:

```bash
uv run scripts/setup_android_emulator.py list
uv run scripts/setup_android_emulator.py setup-all --avd ksu_playstore --headless --timeout 300
uv run scripts/setup_android_emulator.py verify-root --serial emulator-5554 --json
```

### Android troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `adb shell su` → `not found` after patching | Emulator resumed a Quick Boot snapshot with the stock kernel | `cold-boot` (`-no-snapshot-load`). Check `adb shell uname -r` shows the new build |
| Emulator hangs on boot or bootloops after patch | GKI kernel KMI does not match the image (`android15-6.6` zip on an `android16-6.12` image) | Restore `kernel-ranchu.orig`; `download --kernel-version "$(adb shell uname -r)"` |
| `su` works in the manager terminal but not from `adb shell` | Shell not granted Superuser, or KernelSU-Next "Umount modules" hides `su` from that app | Manager > Superuser > Shell > allow; turn off **Umount modules** for Shell |
| `verify-root` passes but an app still detects root | Expected: umount applies per app | Leave "Umount modules" on for the target app; add Zygisk Next + a hiding module only if needed |
| No Play Store on the AVD | `PlayStore.enabled=false` in `config.ini` | Use `create-avd` (sets it) or edit `~/.android/avd/<name>.avd/config.ini`, then cold boot |
| `adb root` → `adbd cannot run as root in production builds` | Play Store image is a `user` build | Use `su -c` through KernelSU instead |
| Zygisk modules (LSPosed, Zygisk-Il2CppDumper) do nothing | KernelSU has no built-in Zygisk | Install the Zygisk Next module, reboot, then the dependent module |
| `kernel-ranchu` reverts after an SDK update | `sdkmanager` replaced the image directory | Run `patch-kernel` again |
| Two emulators, `adb` picks the wrong one | No serial | Pass `--serial emulator-5556` / `adb -s` |

---

## 5. Rooted iOS research VM (`vphone-cli`)

`vphone-cli` ([Lakr233/vphone-cli](https://github.com/Lakr233/vphone-cli)) is a real public project. It runs a virtual iPhone (iPhone17,3 restore IPSW plus a matching PCC cloudOS IPSW) on Apple Silicon through Virtualization.framework PV=3 research guests.

| | iOS Simulator (`xcrun simctl`) | vphone-cli VM |
|---|---|---|
| Runs | Simulator-built arm64 binaries in macOS userland | Real iOS kernel and userland |
| App Store / device IPAs | No | Yes (device builds) |
| Root / patched boot chain | No | Yes (one fixed patch set; variants cannot be chosen) |
| Host | Any Mac with Xcode | Physical Apple Silicon Mac, macOS 15+, not nested in a VM |

### Host setup

1. In macOS Recovery Terminal, choose one:
   - Keep SIP with debug relaxed: `csrutil enable --without debug` then `csrutil allow-research-guests enable`.
   - Fully permissive: `csrutil disable`, `csrutil allow-research-guests enable`, then after reboot `sudo nvram boot-args="amfi_get_out_of_my_way=1 -v"`.
2. Build from source (needs Xcode with the iPhoneOS SDK), or use the notarized `vphone-launchpad` release:
   ```bash
   git clone https://github.com/Lakr233/vphone-cli.git && cd vphone-cli
   xcodebuild -workspace VPhone.xcworkspace -scheme VPhone \
     -configuration Debug -destination 'platform=macOS,arch=arm64' \
     -derivedDataPath .build/XcodeBundle build
   bundle=.build/XcodeBundle/Build/Products/Debug/VPhone.bundle
   ```
3. With SIP kept on, allowlist the signed `vphone-vm` after every build:
   ```bash
   sudo "$bundle/Contents/MacOS/vphone-escalator" allow "$bundle/Contents/MacOS/vphone-vm"
   "$bundle/Contents/MacOS/vphone-cli" host preflight
   ```
4. Create and launch (creation needs `sudo` for the CFW step and network access for the restore ticket):
   ```bash
   vphone-cli vm create myphone \
     --iphone-source /path/to/iPhone17,3_Restore.ipsw \
     --cloudos-source /path/to/cloudOS.ipsw
   vphone-cli vm launch myphone
   ```

The workflow installs `vphoned` (host control socket `<VM bundle>/vphone.sock`). It does not install Sileo, apt, TrollStore, an SSH server, or a VNC server. Add those yourself if a task needs them. Machines live in `~/.vphone/machines/<name>/`. Failure modes: [vm-root-troubleshooting.md](vm-root-troubleshooting.md).

### Firmware sources

- `ipsw` ([blacktop/ipsw](https://github.com/blacktop/ipsw)): `brew install blacktop/tap/ipsw`.
  ```bash
  ipsw download ipsw --device iPhone17,3 --latest
  ipsw extract --kernel iPhone17,3_*.ipsw
  ipsw dyld split dyld_shared_cache_arm64e --output ./dsc_split
  ```
  See [../04-tool-usage/ipsw.md](../04-tool-usage/ipsw.md).
- [ipsw.me](https://ipsw.me/) lists Apple CDN links (`updates.cdn-apple.com`) by device and build.

## 6. Mitmproxy CA and TLS unpinning

### Android trust store

- Since Android 7 (API 24) apps ignore user CAs unless their network security config opts in. Put the CA in the system store as `<subject_hash_old>.0`:
  ```bash
  openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout   # c8750f0d
  ```
- Android 7-13: system store is `/system/etc/security/cacerts/`. A KernelSU/Magisk module (`/data/adb/modules/<id>/system/etc/security/cacerts/<hash>.0`) or a tmpfs overlay works.
- Android 14+ (API 34): the store moved to the Conscrypt APEX, `/apex/com.android.conscrypt/cacerts`. A module overlay on `/system/...` is not enough. Bind a tmpfs copy over the APEX path in init, in each `zygote`/`zygote64` mount namespace, and in every running app's namespace (`nsenter --mount=/proc/<pid>/ns/mnt`). It lasts until reboot. Apps started before the bind keep the old store; force-stop them.

`setup_proxy_ca.py install-android` tries, in order: KernelSU/Magisk module `mitmproxy-ca`, `mount -o rw,remount` and copy, tmpfs over `/system/etc/security/cacerts`, then the APEX bind mount with `nsenter` when `/apex/com.android.conscrypt/cacerts` exists. It needs `su`.

### Proxy

```bash
adb shell settings put global http_proxy 10.0.2.2:8080   # 10.0.2.2 = host loopback from the emulator
adb shell settings put global http_proxy :0               # clear
```

### iOS

- Simulator: `xcrun simctl keychain booted add-root-cert ~/.mitmproxy/mitmproxy-ca-cert.pem`. Restart the app.
- vphone-cli VM: serve `mitmproxy-ca-cert.pem` over HTTP from the host (or browse to `http://mitm.it` through the proxy), install the profile in Settings, then enable it under **Settings > General > About > Certificate Trust Settings**.

### Frida unpinning

`export-frida-scripts` writes `ssl_unpin_android.js` and `ssl_unpin_ios.js`.

- Android: trust-all `X509TrustManager` via `SSLContext.init`; OkHttp3 `CertificatePinner.check` (both overloads and `check$okhttp`); Conscrypt `TrustManagerImpl.checkTrustedRecursive` / `verifyChain`; `WebViewClient.onReceivedSslError` → `proceed()`; `NetworkSecurityConfig.isCleartextTrafficPermitted`.
- iOS: `SecTrustEvaluateWithError` (returns true, clears error), `SecTrustEvaluate` (`kSecTrustResultProceed`), `URLSession:didReceiveChallenge:completionHandler:`, `AFSecurityPolicy evaluateServerTrust:forDomain:`.

Flutter, Cronet with custom verifiers, and native BoringSSL pinning are not covered. See [../02-dynamic-instrumentation/network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md).

### `setup_proxy_ca.py`

```bash
uv run scripts/setup_proxy_ca.py [--json] [--cert-path PEM] <subcommand>
```

| Subcommand | Flags | Action |
|---|---|---|
| `status` | | Cert present, old subject hash, `<hash>.0` |
| `export-ca` | `--out-dir` | Writes `<hash>.0` |
| `set-android-proxy` | `--host` (10.0.2.2), `--port` (8080), `--serial` | `settings put global http_proxy` |
| `clear-android-proxy` | `--serial` | Sets `:0` |
| `install-android` | `--serial` | Installs the CA as above |
| `install-ios-sim` | `--device` (UDID or `booted`) | `simctl keychain <dev> add-root-cert` |
| `export-frida-scripts` | `--out-dir` | Writes both unpinning scripts |

`--json` and `--cert-path` work before or after the subcommand.

---

## 7. UTM and snapshots

UTM runs arm64 guests with hardware acceleration (QEMU+HVF or Apple Virtualization) and other architectures through QEMU TCG. Details: [utm-hypervisor-and-snapshots.md](utm-hypervisor-and-snapshots.md).

```bash
VM="Windows-RE-Lab"          # name or UUID from: utmctl list
utmctl list
utmctl status "$VM"
utmctl ip-address "$VM"      # QEMU backend + guest agent only
utmctl start "$VM" --disposable
utmctl snapshot list "$VM"   # UTM 5.0.8+; older utmctl has no snapshot subcommand
```

`setup_utm.py` wraps utmctl, qemu-img, and AppleScript:

| Subcommand | Arguments |
|---|---|
| `status`, `list-vms` | |
| `snapshot-list` | `vm` |
| `snapshot-create`, `snapshot-restore` | `vm name` (calls `utmctl snapshot`, needs UTM 5.0.8+) |
| `qcow2-create` | `output_path size_gb [--backing BASE]` |
| `qcow2-snapshot` | `qcow2_path (--list \| --create N \| --restore N \| --delete N)` (qemu-img, VM stopped) |
| `ida-server-info` | |
| `start-disposable` | `vm` |
| `guest-exec` | `vm command [--timeout N] [--args ...]` (put `--json`/`--timeout` before `--args`) |
| `guest-push` | `vm host_file guest_path` |
| `guest-pull` | `vm guest_file host_path` |
| `send-input` | `vm [--text T] [--modifiers M] [--click X Y] [--button B]` |

```bash
uv run scripts/setup_utm.py guest-exec "$VM" cmd.exe --timeout 120 \
  --args /c powershell -NoProfile -ExecutionPolicy Bypass -File 'C:\Windows\Temp\setup_winrm.ps1'
```

---

## 8. IDA remote debugging

Servers live in `/Applications/IDA Professional 9.x.app/Contents/MacOS/dbgsrv` (or `$IDADIR/dbgsrv`). `uv run scripts/setup_utm.py ida-server-info` finds it. IDA 9.4 ships:

| Target | Server |
|---|---|
| Linux x86_64 / x86 | `linux_server` / `linux_server32` |
| Linux ARM64 / ARMv7 / ARMv7 hard-float | `armlinux_server` / `armlinux_server32` / `armlinux_serverhf32` |
| Windows x64 / x86 | `win64_remote.exe` / `win32_remote32.exe` |
| macOS x86_64 / arm64 / arm64e | `mac_server` / `mac_server_arm` / `mac_server_arme` |
| Android arm64 / arm32 / x86_64 / x86 | `android_server` / `android_server32` / `android_x64_server` / `android_x86_server` |

Network rules for UTM: **Shared Network** has no port forwarding; connect to the guest IP. **Emulated VLAN** supports port forwards (host `127.0.0.1:23946` → guest `23946`). Android emulator: `adb forward tcp:23946 tcp:23946`. Docker, flags, GUI steps, and troubleshooting: [ida-remote-debugging.md](ida-remote-debugging.md). Drive the debugger from an agent only through the official HexRaysSA `ida-mcp` server: [../04-tool-usage/ida-mcp-remote-debugging.md](../04-tool-usage/ida-mcp-remote-debugging.md).

---

## 9. VM provisioning with Ansible

`setup_vm.py` manages the catalogs and runs the playbooks. `setup_windows_vm.py` is the same CLI (wrapper); `--os` defaults to `windows` in both.

Catalogs (enabled by default):

- Windows (`ansible/windows_tools.json`, 26 entries, `procdot` off): osquery, sysmon, tshark (Wireshark), fiddler, mitmproxy, sysinternals, autoruns, procmon, x64dbg, ghidra, cutter, radare2, windbg, ida_dbgsrv, die, pestudio, pe-bear, yara, 7zip, git, python3 (3.12), hxd, curl, nodejs (LTS), computer-use-mcp.
- Linux (`ansible/linux_tools.json`, 23): osquery, tshark, tcpdump, gdb, radare2, openjdk (21), nodejs, npm, unzip, ghidra, strace, ltrace, binwalk, yara, checksec, upx, python3, uv, git, curl, 7zip, ida_dbgsrv, computer-use-mcp.
- macOS (`ansible/macos_tools.json`, 16): osquery, tshark, radare2, node, ghidra, binwalk, yara, ipsw, jtool2, python3 (3.12), uv, git, p7zip (`sevenzip`), curl, ida_dbgsrv, computer-use-mcp.

Ports: IDA debug server `23946/tcp`, Computer Use MCP `4517/tcp`.

| Subcommand | Flags |
|---|---|
| `list` | `--os`, `--category`, `--tag`, `--enabled-only`, `--json` |
| `summary` | `--os`, `--json` |
| `enable-tool` / `disable-tool` | `--os`, `tool_id` |
| `add-tool` | `--os`, `--id`, `--name`, `--category`, `--binary-path` (required); `--description`, `--service`, `--tags`, `--disabled`, `--choco`, `--winget`, `--npm`, `--apt`, `--dnf`, `--pacman`, `--brew-formula`, `--brew-cask` |
| `winrm-script` | `-o PATH` |
| `generate-inventory` | `--os`, `--host`, `--user` (required); `--password`, `--key-file`, `--become-password`, `--port`, `--transport {ntlm,basic,credssp}`, `-o` |
| `deps` | `--install` (collections + pywinrm into Ansible's own Python) |
| `run-playbook` | `--os`, `-i`, `--check`, `--tags`, `--extra-vars`, `-v` |
| `defender` | `--action {status,disable,enable}`, `--clear-exclusions`, `--exclusions`, `--script-only`, `-o`, `-i`, `-v` |
| `mcp-client-config` | `--os`, `--host`, `--port` (4517), `--format {sse,proxy,ssh}` |

`generate-inventory` writes `ansible/inventory_<os>.ini`. `run-playbook` passes `ida_dbgsrv_src` from `$IDA_DBGSRV`, `$IDADIR`, or the newest `/Applications/IDA*.app` and sets `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` on macOS.

```bash
uv run scripts/setup_vm.py deps --install

# Windows (WinRM)
uv run scripts/setup_vm.py generate-inventory --os windows --host "$VM_IP" --user Administrator --password "$PASS"
OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES ansible windows_vms -i ansible/inventory_windows.ini -m ansible.windows.win_ping
uv run scripts/setup_vm.py run-playbook --os windows -v

# Linux (SSH)
uv run scripts/setup_vm.py generate-inventory --os linux --host "$VM_IP" --user analyst --key-file ~/.ssh/id_ed25519
ansible linux_vms -i ansible/inventory_linux.ini -m ping
uv run scripts/setup_vm.py run-playbook --os linux -v

# macOS (SSH)
uv run scripts/setup_vm.py generate-inventory --os macos --host "$VM_IP" --user analyst --key-file ~/.ssh/id_ed25519 --become-password "$PASS"
ansible macos_vms -i ansible/inventory_macos.ini -m ping
uv run scripts/setup_vm.py run-playbook --os macos -v
```

Per-OS details and troubleshooting: [windows-vm-ansible-setup.md](windows-vm-ansible-setup.md), [linux-vm-ansible-setup.md](linux-vm-ansible-setup.md), [macos-vm-ansible-setup.md](macos-vm-ansible-setup.md).

---

## 10. Troubleshooting index

- Android emulator root: section 4 table above.
- vphone-cli: AMFI refusing `vphone-vm`, CFW install needing root, missing restore tree, APFS unmount `Resource busy`, old `vphoned` Code 642 bootstrap bug: [vm-root-troubleshooting.md](vm-root-troubleshooting.md).
- UTM networking, guest agent, snapshots: [utm-hypervisor-and-snapshots.md](utm-hypervisor-and-snapshots.md).
- IDA connection failures: [ida-remote-debugging.md](ida-remote-debugging.md).

## 11. Never

- Do not run an untrusted sample outside an isolated VM.
- Do not rewrite `mcp.json` or run `rea setup` or `rea doctor`.
- Do not flash a physical device with an emulator kernel.
