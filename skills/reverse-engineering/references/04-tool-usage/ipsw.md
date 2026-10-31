# Apple Firmware & iOS Reverse Engineering Reference (`ipsw` & `vphone-cli`)

## 1. Title & Overview
- **Domain**: Apple iOS and macOS firmware analysis, Mach-O binary triage, kernelcache decryption, dyld shared cache extraction, and rooted Apple Silicon research virtual machines using `blacktop/ipsw` and `vphone-cli`.
- **Scope**: Firmware acquisition via official CDN portals (`ipsw.me`) and CLI automation (`ipsw download`), kernelcache unpacking and symbol recovery, dyld shared cache dissection, Mach-O and entitlement extraction, and local rooted virtual iPhone execution on macOS via Apple's Virtualization.framework and Private Cloud Compute (PCC) research guests.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when:
- Analyzing Apple iOS, iPadOS, or macOS system components, private frameworks, or system daemons (`launchd`, `commcenter`, `amfid`).
- Inspecting encrypted or LZSS/LZFSE-compressed Apple kernelcaches (`kernelcache.release.*`).
- Extracting individual dylibs and private frameworks from the monolithic Apple `dyld_shared_cache`.
- Triaging Mach-O binary structures, dynamic loader load commands (`LC_LOAD_DYLIB`, `LC_CODE_SIGNATURE`), embedded provisioning profiles, or entitlements (`__TEXT,__entitlements`).
- Bootstrapping a fully rooted iOS research guest VM on Apple Silicon macOS to conduct live dynamic analysis without a physical hardware jailbreak.

---

## 3. Tooling & CLI Actions

### Primary Tool Suite
- **`blacktop/ipsw` CLI**: Specialized Swiss-army knife for Apple firmware, available via Homebrew:
  ```bash
  brew install blacktop/tap/ipsw
  ```
- **Firmware Portals**:
  - `https://ipsw.me/`: Direct browser portal cataloging official signed and unsigned Apple CDN firmware links.
  - `ipsw download`: Automated programmatic acquisition from Apple CDN.
- **Rooted iOS Research Hypervisor**:
  - `vphone-cli`: Manages Apple Silicon PCC research guest virtual machines utilizing macOS `Virtualization.framework`.

---

## 4. Firmware Acquisition & Triage

### Acquiring IPSW Firmware
```bash
# Query latest available iOS release for a specific device identifier
ipsw download ipsw --device iPhone16,1 --latest

# Download specific build version directly from Apple CDN
ipsw download ipsw --device iPhone15,2 --build 21E236

# Direct fetch of remote metadata without downloading the full 6GB+ image
ipsw download ipsw --device iPhone16,1 --latest --urls
```

### Inspecting Firmware Contents
An IPSW file is a zip archive containing:
- Restorable disk images (Root filesystem DMG, Recovery DMG).
- `kernelcache.release.*`: The compressed iOS kernel and prelinked kernel extensions (kexts).
- `BuildManifest.plist` & `Restore.plist`: Target device models, build tags, and component digests.

---

## 5. Kernelcache Decryption & Kext Extraction

iOS kernelcaches are packed into IMG4 containers (`IM4P`), often compressed with LZFSE or LZSS, and historically encrypted on older devices.

### Decompressing and Decrypting Kernelcache
```bash
# Decompress and unwrap kernelcache from IMG4 container
ipsw kernel dec kernelcache.release.iPhone16,1 -o ./unpacked_kernel

# Extract all prelinked Kernel Extensions (kexts) into a structured folder
ipsw kernel extract kernelcache.release.iPhone16,1 --kexts -o ./extracted_kexts/

# Diff two kernelcaches to identify security fixes between iOS point releases
ipsw kernel diff kernelcache_21E219.dec kernelcache_21E236.dec
```

### Analyzing Kernel Symbol Tables
Modern kernelcaches omit full symbol tables; `ipsw` parses the GOT, C++ virtual method tables (OSObject vtables), and exported Mach-O structures to recover symbols:
```bash
# Dump all recovered kernel symbols and addresses
ipsw kernel syms ./unpacked_kernel/kernelcache.release.iPhone16,1.dec > kernel_syms.txt

# Inspect Mach-O load commands and sections of the unpacked kernel
ipsw macho info ./unpacked_kernel/kernelcache.release.iPhone16,1.dec
```

---

## 6. Dyld Shared Cache (DSC) Extraction & Splitting

To optimize memory mapping, Apple links all system dynamic libraries and private frameworks into a monolithic `dyld_shared_cache` (located at `/System/Library/Caches/com.apple.dyld/`).

### Extracting DSC from IPSW
```bash
# Extract the dyld_shared_cache directly from the IPSW filesystem DMG
ipsw extract --dyld iPhone16,1_17.4_21E236_Restore.ipsw -o ./dsc_extracted/
```

### Splitting Dylibs from Shared Cache
To reverse engineer a single private framework (e.g. `SpringBoardServices`, `Security`, `WebKit`) in IDA Pro or Ghidra, split it out of the cache:
```bash
# Split entire dyld shared cache into individual Mach-O dylib files
ipsw dyld split ./dsc_extracted/dyld_shared_cache_arm64e ./split_dylibs/

# Extract a specific single dylib without splitting the entire multi-gigabyte cache
ipsw dyld extract ./dsc_extracted/dyld_shared_cache_arm64e /System/Library/Frameworks/Security.framework/Security -o ./Security.dylib
```

---

## 7. Mach-O Inspection, Entitlements & Device Tree

### 1. Entitlements Extraction
Apple security relies heavily on sandboxing and entitlement verification. Inspect entitlements embedded in Mach-O binaries:
```bash
# Extract raw XML/plist entitlements from Mach-O code signature
ipsw macho info target_daemon --ent

# Extract entitlements across an entire directory of system binaries
ipsw macho info /path/to/binaries/ --ent --json > system_entitlements.json
```

### 2. Device Tree Parsing
The DeviceTree contains hardware peripherals, memory mappings, and board-level specifications:
```bash
# Parse and decode DeviceTree file from IPSW
ipsw devicetree DeviceTree.d83.im4p
```

### 3. Class-Dump Objective-C / Swift Headers
Generate clean Objective-C interfaces and Swift declarations directly from Mach-O binaries or dyld caches:
```bash
# Extract Objective-C class declarations from a Mach-O framework
ipsw class-dump ./Security.dylib --output ./Security_Headers/
```

---

## 8. Rooted iOS Research Virtual Machine (`vphone-cli`)

On macOS running on Apple Silicon (M1/M2/M3/M4), `vphone-cli` provisions a fully bootable, rooted virtual iPhone environment using Apple's `Virtualization.framework` and Private Cloud Compute (PCC) research VM infrastructure.

```
+-------------------------------------------------------------------------------+
| macOS Host (Apple Silicon - macOS 15+)                                         |
|                                                                               |
|  1. csrutil allow-research-guests enable (NVRAM security configuration)       |
|  2. sudo VPhoneEscalator allow /usr/local/bin/vphone-vm                       |
|                                                                               |
|  +-------------------------------------------------------------------------+  |
|  | vphone-vm (Apple Virtualization.framework PCC Guest)                    |  |
|  |                                                                         |  |
|  |   +-----------------------------------------------------------------+   |  |
|  |   | Rooted iOS Virtual iPhone Guest (iOS 26 / Custom Firmware)      |   |  |
|  |   | - Jailbreak Patchset (JB=1 / make fw_patch_jb - 112 patches)    |   |  |
|  |   | - Complete Root Access (uid=0)                                  |   |  |
|  |   | - SSH Server (Port 2222)                                        |   |  |
|  |   | - Sileo Package Manager & TrollStore                            |   |  |
|  |   | - frida-server (Dynamic Binary Instrumentation)                 |   |  |
|  |   +-----------------------------------------------------------------+   |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

### Host Prerequisites & Authorization
1. **Enable Research Guests in macOS NVRAM** (Run in macOS Recovery):
   ```bash
   csrutil allow-research-guests enable
   ```
2. **Authorize Escalator Helper**:
   `vphone-cli` requires an escalator helper daemon to acquire hypervisor privileges without disabling System Integrity Protection (SIP):
   ```bash
   sudo VPhoneEscalator allow /path/to/vphone-cli/build/vphone-vm
   ```
3. **Verify Host Readiness**:
   ```bash
   vphone-cli host preflight
   # Output must indicate: [OK] vphone-vm can launch
   ```

### Provisioning the Rooted Virtual iPhone
1. **Prepare Firmware & Custom Jailbreak Patch Set**:
   The jailbreak patch set (`JB=1` / `make fw_patch_jb`) applies 112 patches to provide full root execution, disable signature enforcement on guest userland, and install core research tools:
   ```bash
   # Prepare firmware using cached IPSW images
   vphone-cli fw prepare iOS-Research-VM \
     --iphone-source /path/to/.ipsw-cache/iPhone_Restore.ipsw \
     --cloudos-source /path/to/.ipsw-cache/CloudOS_Restore.ipsw

   # Apply jailbreak patches
   vphone-cli fw patch iOS-Research-VM
   ```

2. **Install Custom Firmware (CFW) with Elevated Privileges**:
   ```bash
   sudo vphone-cli cfw install iOS-Research-VM --library-root "$HOME/.vphone/machines"
   ```

3. **Boot VM & Connect to Root Environment**:
   ```bash
   # Launch the rooted iOS Research VM
   vphone-cli vm start iOS-Research-VM

   # Connect via SSH into root shell
   ssh -p 2222 root@localhost
   # Default password: alpine
   ```

4. **Dynamic Instrumentation inside Research Guest**:
   - The research guest includes Sileo and TrollStore.
   - Stage and run `frida-server` on the guest:
     ```bash
     ssh -p 2222 root@localhost "/usr/bin/frida-server -D"
     ```
   - Connect from host:
     ```bash
     frida-ps -H 127.0.0.1:27042 -ai
     ```

---

## 9. Boundaries & Anti-Patterns
- **Do not mix up iOS Simulator binaries and native iOS device binaries**: Simulator builds run in macOS userland (`x86_64` or `arm64-apple-darwin`), while device firmware runs under strict iOS sandbox profiles and `arm64e` pointer authentication (PAC).
- **Do not attempt to decrypt modern kernelcaches without checking IMG4 tags**: A9+ kernelcaches are unencrypted but compressed with LZFSE; attempting to supply AES keys to an unencrypted container will fail. Use `ipsw kernel dec` directly.
- **Do not run `vphone-cli cfw install` without root privileges**: Modifying APFS volume layouts and container disks for research guests requires `sudo`.
