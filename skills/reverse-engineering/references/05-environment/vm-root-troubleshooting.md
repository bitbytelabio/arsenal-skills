# Android/iOS VM Root Setup Troubleshooting

Use this reference when Android emulator rooting or an iOS `vphone-cli`
research VM fails during host preflight, firmware preparation, custom-firmware
installation, guest bootstrap, or setup-script type checking. Match the exact
symptom before applying a fix; the failures below occur at different privilege
and storage layers.

## 1. macOS AMFI refuses `vphone-vm`

### Symptom

`vphone-cli host preflight` fails before any guest can start:

```text
Error: amfid refused to launch vphone-vm, so no guest could start. Binary: .../vphone-vm. CDHash: ...
```

### Technical root cause

On macOS 15 and later, `Virtualization.framework` does not let an ordinary,
retail-policy process use the private PV=3 virtualization entitlements needed
by iOS Private Cloud Compute (PCC) research guests. The binary can be correctly
built and signed while AMFI (`amfid`) still rejects it: the host has not enabled
the research-guest policy and the specific `vphone-vm` CDHash has not been
allowed by `VPhoneEscalator`. A quarantine attribute on the downloaded bundle
can independently keep Gatekeeper/AMFI from accepting the build.

### Verified fix

1. Shut down the Mac, hold the power button to enter **macOS Recovery**, open a
   Recovery terminal, and enable the research-guest policy:

   ```bash
   csrutil allow-research-guests enable
   ```

   On systems where that subcommand is unavailable, use the supported debug
   policy form instead:

   ```bash
   csrutil enable --without debug
   ```

   Reboot into the normal host OS.

2. On the host, authorize the exact VM helper binary that preflight reported:

   ```bash
   sudo /path/to/VPhoneEscalator allow /path/to/vphone-vm
   ```

3. Remove quarantine recursively from the containing bundle:

   ```bash
   sudo xattr -r -d com.apple.quarantine /path/to/VPhone.bundle
   ```

4. Re-run `vphone-cli host preflight`. Success means the same `vphone-vm`
   binary can now launch; authorizing a different build path or a stale CDHash
   does not fix the active binary.

## 2. Custom-firmware installation needs host root

### Symptom

`vphone-cli vm create` reaches step 4 and stops with:

```text
Error: CFW installation needs root. Run this command with sudo.
```

### Technical root cause

Step 4 runs `cfw install`. This is not merely a guest-side file copy: it mounts
the VM's APFS container on host macOS through `/sbin/mount_apfs`, then injects
the jailbreak components `SystemHook`, `launchdhook`, and `vphoned`. Mounting
and modifying that host-visible APFS volume requires macOS administrator
privileges even when all VM files belong to the current user.

### Verified fix

Re-run only the custom-firmware installation with host privileges and preserve
the original user's machine library explicitly:

```bash
sudo vphone-cli cfw install <vm_name> \
  --library-root "$HOME/.vphone/machines"
```

The invoking shell expands `$HOME` before `sudo` starts the command. Without
`--library-root`, the elevated process resolves its home as `/var/root` and
looks in `/var/root/.vphone/machines`, not in the user's existing VM library.

## 3. Re-running `cfw install` cannot find a prepared restore tree

### Symptom

An isolated retry of `cfw install` fails with:

```text
Error: No prepared iPhone restore tree exists in .../<vm_name>
```

### Technical root cause

Firmware preparation creates a restore tree named like
`iPhone17,3_..._Restore`. `cfw install` needs that tree's
`iPhone-BuildManifest.plist` and Cryptex files. Unless the original workflow
used `--keep-artifacts`, the DFU restore step prunes the tree after it consumes
it. The VM and `Disk.img` can therefore still exist while the inputs required
for a later standalone custom-firmware install no longer do.

### Verified fix

Recreate and patch the restore tree from the already cached firmware sources:

```bash
vphone-cli fw prepare <vm_name> \
  --iphone-source /path/to/.ipsw-cache/<iphone-firmware>.ipsw \
  --cloudos-source /path/to/.ipsw-cache/<cloudos-firmware>.ipsw

vphone-cli fw patch <vm_name>
```

Then retry the privileged `cfw install` command from issue 2. Pointing
`--iphone-source` and `--cloudos-source` at the local `.ipsw-cache/` artifacts
avoids another internet download; preparation from those cached IPSWs normally
finishes in seconds. For a future create flow that must support isolated
retries, retain the restore tree with `--keep-artifacts`.

## 4. APFS cleanup reports `Resource busy`

### Symptom

Custom-firmware cleanup reports an error such as:

```text
umount(.../system): Resource busy -- try 'diskutil unmount'
```

### Technical root cause

The installer has mounted the VM's APFS system volume into the host namespace.
macOS background processes—notably Spotlight (`mds`), QuickLook, or Finder—can
open the new mount briefly. A normal unmount then receives `EBUSY` even after
the firmware injector itself has closed its files.

### Verified fix

`VPhoneCustomFirmwareInstaller.swift` must keep cleanup in its `defer` block and
fall back to force operations for both layers:

```bash
/sbin/umount -f <system-mount-point>
hdiutil detach -force <attached-disk-device>
```

Do not leave either the APFS mount or its disk image attachment behind after a
failed normal unmount. After cleanup, verify the custom-firmware snapshot state
with:

```bash
vphone-cli cfw flip-snapshot /path/to/<vm_name>/Disk.img
```

The resulting `Disk.img` must contain the expected renamed original snapshot,
`orig-fs.disabled.rn-`. Treat the unmount warning and the snapshot state as
separate checks: force cleanup releases the host resource, while the snapshot
rename determines which filesystem snapshot the VM will boot.

## 5. Upstream `vphoned` marker bug returns Code 642 and breaks Irisin

### Symptom

Selecting **Install Bootstrap** reports:

```text
Install Bootstrap: Error Domain=NSCocoaErrorDomain Code=642. Bootstrap installation failed.
```

The Irisin icon still appears on the iOS home screen, but tapping it causes an
immediate crash.

### Technical root cause

The failure is an upstream `vphoned` storage-path bug with a destructive
rollback side effect:

1. `GuestIrisinInstaller.swift` constructed its completion marker relative to
   the running executable:

   ```swift
   Bundle.main.executableURL!
       .deletingLastPathComponent()
       .appendingPathComponent(".vphoned-boostrap-completed")
   ```

2. In vphone 2.0, the executable is `/usr/bin/vphoned`, so that expression
   resolves the marker inside `/usr/bin`.
3. `/usr/bin` belongs to the sealed, read-only root filesystem. Creating the
   marker there throws `NSCocoaErrorDomain Code=642`, which is
   `NSFileWriteVolumeReadOnlyError`.
4. The exception enters the rollback in `GuestIrisinInstaller.swift` (the
   `catch` block around lines 289–294):

   ```swift
   for entry in replaced.reversed() {
       try? FileManager.default.removeItem(at: entry.target)
   }
   ```

   This removes the newly extracted `irisin` and `irisind` targets. SpringBoard
   retains the registered icon, but the app bundle no longer contains its
   executable, so launching the icon crashes immediately.

### Verified fix

Move the marker to the read-write Data partition:

```swift
let completionMarker = URL(
    fileURLWithPath: "/private/var/root/.vphoned-bootstrap-completed"
)
```

Rebuild `vphoned` and `VPhone.bundle`, then reconnect the guest. `vphone-vm`
automatically updates `vphoned` over its HTTP/VSOCK connection. With the marker
under `/private/var/root`, bootstrap completion no longer raises Code 642, the
rollback does not run, and the installed `irisin` and `irisind` binaries remain
in place.

## 6. Pyright treats a reused result as `ColdBootResult`

### Symptom

Pyright reports an assignment error in the emulator setup script:

```text
Type "dict[str, Any | str | bool]" is not assignable to declared type "ColdBootResult"
```

### Technical root cause

A declaration such as `res: ColdBootResult` inside one `if` branch of `main()`
does not create a branch-local variable. Python's function scope means Pyright
associates the identifier `res` with `ColdBootResult` throughout `main()`.
Assignments to the same name in another subcommand branch are then checked
against that annotation, even when those branches return a create-AVD or other
result shape.

### Verified fix

Define a dedicated `TypedDict` for each subcommand result (including
`CreateAvdResult`), keep result names distinct, and narrow optional paths before
passing them to functions that require concrete values:

```python
create_res: CreateAvdResult = create_avd(...)
boot_res: ColdBootResult = cold_boot(...)

if def_path and sdk_root:
    # Both operands are narrowed to Path here.
    update_avd_definition(def_path, sdk_root)
```

Do not silence the diagnostic with `Any` or a cast. Distinct names preserve the
actual return contracts and prevent one branch's annotation from shadowing all
other subcommand results in the function scope.

## 7. Automation contains personal absolute paths

### Symptom

A setup command works on its author's workstation but fails on another developer
machine or in CI because it references a path such as:

```text
/Users/<user>/.../android-ksu
```

### Technical root cause

The script encoded a workstation-specific username and directory layout rather
than deriving a user cache directory at runtime. The path is invalid for every
other account, for non-macOS hosts, and often for sandboxed CI users.

### Verified fix

Use the platform-independent home directory and allow an environment override:

```python
import os
from pathlib import Path

cache_dir = Path(
    os.environ.get(
        "ANDROID_KSU_CACHE_DIR",
        str(Path.home() / ".cache" / "android-ksu"),
    )
).expanduser()
```

The default is `~/.cache/android-ksu`; `ANDROID_KSU_CACHE_DIR` supports CI,
shared caches, or another filesystem without editing source. Apply the same
rule to related automation: derive paths from `Path.home()`, explicit CLI
arguments, or documented environment variables, never from a personal
`/Users/<name>/...` prefix.
