# Rooted Android Emulator and iOS VM Troubleshooting

Match the exact symptom before retrying a privileged step. Setup procedures: [host-and-lab-setup.md](host-and-lab-setup.md) sections 3-6.

## A. Android emulator (KernelSU)

| Symptom | Cause | Fix |
|---|---|---|
| `adb shell su -c id` → `su: not found` right after `patch-kernel` | Emulator resumed a Quick Boot snapshot with the stock kernel | `uv run scripts/setup_android_emulator.py cold-boot --avd "$AVD"` (`-no-snapshot-load`); confirm `adb shell uname -r` changed |
| Bootloop or black screen after patch | AnyKernel3 zip for another GKI branch (`android15-6.6` vs `android16-6.12`) | `cp kernel-ranchu.orig kernel-ranchu`; `download --kernel-version "$(adb shell uname -r \| tr -d '\r')"`; `patch-kernel` |
| Manager shows "Not installed" | Kernel not replaced, or wrong system image directory patched (several AVDs, `_ps16k` variant) | `uv run scripts/detect_host.py` lists every `kernel-ranchu`; pass `--system-image-path` explicitly |
| `su` works in the manager, `verify-root` fails from `adb shell` | Shell not granted root, or KernelSU-Next **Umount modules** hides `su` for that uid | Manager > Superuser > Shell: allow; disable Umount modules for Shell (or the global default) |
| `adb root` → `adbd cannot run as root in production builds` | Play Store image is a `user` build | Use `su -c` |
| `adb remount` fails, `-writable-system` ignored | Play Store images do not support writable system | Use a KernelSU module or tmpfs/bind mounts |
| Zygisk-based module (LSPosed, Zygisk-Il2CppDumper, Shamiko-style) inactive | KernelSU has no Zygisk | Install Zygisk Next (or ReZygisk) module, reboot, then the dependent module |
| Module installed, files not visible to the app | Umount modules on for that app (by design), or module mounted after the app started | Disable umount for the app or force-stop and relaunch it |
| No Play Store icon | `PlayStore.enabled=false` in the AVD `config.ini` | `create-avd` sets it; or edit `config.ini` and cold boot |
| Patch lost after an SDK update | `sdkmanager` replaced the system image | `patch-kernel` again |
| Assets downloaded to an unexpected place | Cache resolves to `$ANDROID_KSU_CACHE_DIR`, else `~/.cache/android-ksu` | Set the variable or pass `--download-dir` |

## B. Android system CA (mitmproxy)

| Symptom | Cause | Fix |
|---|---|---|
| CA listed under user credentials, apps still fail TLS | API 24+ apps ignore user CAs | Install as system CA: `uv run scripts/setup_proxy_ca.py install-android` |
| Cert in `/system/etc/security/cacerts`, Android 14+ apps still fail | Android 14 reads `/apex/com.android.conscrypt/cacerts` (Conscrypt APEX, updatable) | Bind a tmpfs copy over the APEX path in init, `zygote`/`zygote64`, and each app namespace with `nsenter --mount=/proc/<pid>/ns/mnt`. `install-android` does this when the APEX dir exists |
| APEX bind works for new apps only | Running apps keep their old mount namespace | `adb shell am force-stop <pkg>` and relaunch, or re-run `install-android` |
| Interception stops after reboot | APEX bind mount and tmpfs are not persistent | Re-run `install-android` after each boot |
| `install-android` → "su or remount failed" | No root, or `su` hidden from Shell | Fix root first (table A) |
| Wrong filename | Used the new subject hash | Use `openssl x509 -subject_hash_old` (`c8750f0d.0` for the default mitmproxy CA) |
| System CA in place, one app still fails | Certificate pinning, or Flutter/Cronet/BoringSSL ignoring the store | `export-frida-scripts`; for Flutter see [../01-static-architectures/flutter-dart.md](../01-static-architectures/flutter-dart.md) |
| No traffic reaches mitmproxy | Proxy not set or app ignores system proxy | `set-android-proxy --host 10.0.2.2 --port 8080`; for proxy-unaware apps use transparent mode or `iptables` redirect |

## C. iOS `vphone-cli` VM

`vphone-cli` is the public [Lakr233/vphone-cli](https://github.com/Lakr233/vphone-cli) project. Its own guide: `Documents/Guides/troubleshooting.md`.

### iOS-1. AMFI refuses `vphone-vm`

Symptom: `vphone-cli host preflight` reports that amfid refused to launch `vphone-vm`, or `vphone-vm` is killed before the window opens.

Cause: `vphone-vm` carries private PV=3 virtualization entitlements. AMFI rejects it unless the host allows research guests and the exact `vphone-vm` cdhash is allowlisted. Every rebuild changes the cdhash. A quarantine attribute on a downloaded bundle can also block it.

Fix:
1. macOS Recovery Terminal (both commands, or `csrutil disable` plus `amfi_get_out_of_my_way=1` boot-arg):
   ```bash
   csrutil enable --without debug
   csrutil allow-research-guests enable
   ```
2. Back in macOS, allowlist the current build:
   ```bash
   bundle=.build/XcodeBundle/Build/Products/Debug/VPhone.bundle
   sudo xattr -dr com.apple.quarantine "$bundle"
   sudo "$bundle/Contents/MacOS/vphone-escalator" allow "$bundle/Contents/MacOS/vphone-vm"
   "$bundle/Contents/MacOS/vphone-escalator" status
   "$bundle/Contents/MacOS/vphone-cli" host preflight
   ```
3. Repeat `allow` after every build. For a distributed bundle, the preflight error prints the exact `vphone-escalator allow` command.

`Virtualization is not available on this hardware` means the host is itself a VM. PV=3 guests cannot nest.

### iOS-2. CFW installation needs root

Symptom: `vphone-cli vm create` stops at the CFW step with `CFW installation needs root. Run this command with sudo.`

Cause: `cfw install` mounts the guest APFS volume on the host and writes `vphoned` and the hooks into it.

Fix: re-run only that step as root and keep the user's machine library:

```bash
sudo vphone-cli cfw install "$VM_NAME" --library-root "$HOME/.vphone/machines"
```

The shell expands `$HOME` before `sudo`. Without `--library-root`, root looks in `/var/root/.vphone/machines`.

### iOS-3. `cfw install` cannot find the restore tree

Symptom: `No prepared iPhone restore tree exists in .../<vm_name>`.

Cause: without `--keep-artifacts`, the restore tree (`iPhone17,3_..._Restore`, with `iPhone-BuildManifest.plist` and Cryptexes) is deleted after the DFU restore. Template builds always delete it.

Fix: rebuild it from the cached IPSWs, then retry iOS-2:

```bash
vphone-cli fw prepare "$VM_NAME" \
  --iphone-source /path/to/iPhone17,3_Restore.ipsw \
  --cloudos-source /path/to/cloudOS.ipsw
vphone-cli fw patch "$VM_NAME"
```

For retries later, create with `--keep-artifacts --no-template`.

### iOS-4. APFS cleanup `Resource busy`

Symptom: `umount(.../system): Resource busy -- try 'diskutil unmount'`.

Cause: Spotlight (`mds`), QuickLook, or Finder opened the freshly mounted guest volume.

Fix:

```bash
mount | grep -i vphone                 # find the mount point and /dev/diskN
sudo umount -f <mount-point>
hdiutil detach -force /dev/diskN
```

Add the machine library to Spotlight privacy (System Settings > Spotlight > Search Privacy) to avoid it.

### iOS-5. Bootstrap fails with `NSCocoaErrorDomain Code=642`

Symptom: **Install Bootstrap** reports Code 642. The bootstrap app icon stays but crashes on launch.

Cause: older `vphoned` builds wrote the completion marker beside `/usr/bin/vphoned` on the sealed read-only system volume (`NSFileWriteVolumeReadOnlyError`). The rollback then deleted the freshly extracted app binaries.

Fix: update the bundle. Current `vphoned` writes the marker to `/private/var/db/vphoned/bootstrap.json` and only reads the legacy path. Reconnect the guest; `vphone-vm` updates `vphoned` on connect. Then run Install Bootstrap again.

### iOS-6. Other

| Symptom | Cause | Fix |
|---|---|---|
| `vm create` printed `vphoned connected`, no VM running | Expected: the verification boot is stopped | `vphone-cli vm launch "$VM_NAME"` |
| Restore or first boot fails | Incompatible iPhone/cloudOS pair, or no network for the restore ticket | Check `Documents/Guides/compatibility.md`; rerun `vm create` with a new name and `-v` |
| Stuck at "Press home to continue" | No VNC/SSH in the guest | VM window **Keys > Home** |
| No SSH into the guest | The workflow installs no SSH server | Install one yourself, or drive the guest through `vphoned` (`<VM bundle>/vphone.sock`) |
| Guest traffic bypasses the host VPN | `nat`/`bridged` leave through the physical NIC | `vphone-cli vm config "$VM_NAME" --network tunnel` (VM stopped) |
