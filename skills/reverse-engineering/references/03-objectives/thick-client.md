# Thick-Client Reverse Engineering

## When To Open
Open this file for a desktop client that is not only a web page: Qt, WPF, WinForms, Electron, Java Swing, or a native GUI with a local service. Pure protocol work stays in [protocol-recovery.md](protocol-recovery.md). The binary format still uses its architecture reference.

## Trust Boundary First
Draw the boundary before decompiling a random function. A thick client's risk is almost always at a boundary where a less-privileged caller reaches more-privileged code or a stored secret.

- Process tree, helper services, and drivers.
- Listening sockets, especially `0.0.0.0`, and the outbound hosts.
- Local secret stores: `%APPDATA%`, DPAPI blobs, Keychain, plaintext config, SQLite.
- The update URL and whether the downloaded payload is signature-checked.
- IPC: named pipes, COM, XPC, localhost HTTP. Who can connect, and is the caller checked?

A hidden debug menu, a leftover command-line flag, or a config key that disables a check is a lead. Confirm it in the binary before calling it a bypass.

## Enumerate The Boundary (Concrete Commands)

### Processes, services, sockets
- Windows: `tasklist /svc`, `sc query`, `Get-CimInstance Win32_Service | ? {$_.State -eq 'Running'}`, `netstat -anob` (listener → PID → image), `Get-NetTCPConnection -State Listen`.
- macOS: `ps -axo pid,ppid,user,comm`, `launchctl list`, `lsof -iTCP -sTCP:LISTEN -n -P`.
- Linux: `ss -ltnp`, `systemctl list-units --type=service`.

### Named pipes (Windows)
- List pipes with Sysinternals `pipelist.exe` or PowerShell: `[System.IO.Directory]::GetFiles("\\.\pipe\")`.
- Read the pipe's DACL — the real question is who may open it:
  ```cmd
  accesschk.exe -accepteula \pipe\TargetPipe -v
  ```
  A pipe writable by `Everyone`/`Authenticated Users` reached by a SYSTEM service is a privilege boundary. In the binary, find `CreateNamedPipe` and check the `SECURITY_ATTRIBUTES` / `SECURITY_DESCRIPTOR`: a `NULL` DACL means no access control. Confirm whether the server impersonates (`ImpersonateNamedPipeClient`) and whether it authenticates the caller at all.

### COM (Windows)
- Enumerate registered servers under `HKCR\CLSID\*\LocalServer32` / `InprocServer32`; note `AppID` launch/access permissions.
- For an exposed COM server, the boundary is the `IDispatch`/custom-interface methods and whether `CoInitializeSecurity` sets an authentication level. Record the CLSID, interface, and whether a low-IL caller can instantiate it.

### XPC (macOS)
- List helpers in the app bundle: `Contents/XPCServices/*.xpc` and `Contents/Library/LaunchServices` privileged helpers.
- The auth check is in the listener: look for `xpc_connection_set_event_handler` and whether the handler validates the peer with `SecCodeCheckValidity` / `csops` / a code-signing requirement (audit token → `SecTaskCreateWithAuditToken`). A helper that runs work for any connecting process is the finding.

### localhost HTTP / WebSocket
- A client that opens a port on `127.0.0.1` is an IPC boundary any local process (or a browser via a web page) can hit. Check for an `Origin`/token check. Note the port, the routes, and whether the token is predictable or absent.

## DLL Search-Order & Sideloading (Windows)
- A DLL loaded by name (not a full path) is resolved by search order; if the application directory is writable or a dependency is missing, a planted DLL loads first.
- Observe loads with Process Monitor filtered to `Operation is CreateFile` / `Operation is Load Image` and `Result is NAME NOT FOUND` on `*.dll` — a miss in the app directory is the sideload candidate.
- In the binary, find `LoadLibrary`/`LoadLibraryEx` with a bare name and no `SetDefaultDllDirectories`/`LOAD_LIBRARY_SEARCH_*` hardening.
- Record the path and the missing DLL. Do not drop a substitute DLL; documenting the gap is the deliverable.

## Updater Integrity
The update path is a classic boundary: if the download is unsigned or the signature check is skippable, it is remote code execution waiting to happen.
- Capture the update check (mitmproxy, lab egress) and record the URL and whether it is HTTPS with pinning.
- In the binary, find where the downloaded payload is verified: `WinVerifyTrust` / Authenticode (Windows), `SecStaticCodeCheckValidity` (macOS), GPG/minisign/sha256 compare, or a vendor public key. A hash-only check with no signature, or a check whose failure path still executes the payload, is the finding.
- Electron updaters (Squirrel, `electron-updater`) verify a signature or a SHA of the `.nupkg`/zip against a `RELEASES`/`latest.yml` file. Check that the manifest itself is served over a trusted channel.

## Framework Specifics

### Electron
- Code lives in `resources/app.asar` (or `app/`). Extract with `npx @electron/asar extract app.asar out/` (`asar` is the legacy name).
- Read `package.json` `main`, then the main-process code. Flags that matter: `nodeIntegration`, `contextIsolation`, `sandbox`, and `webSecurity`. `nodeIntegration: true` with remote content is a direct boundary break.
- Secrets in renderer code are client-side; treat them as storage, not as a server control. Deobfuscation: [browser-js-wasm.md](../01-static-architectures/browser-js-wasm.md).

### Qt / WinForms / WPF
- Qt: strings and `QObject` metadata survive; `moc`-generated signal/slot tables name the handlers. The logic is native C++ — [native-cpp-abi.md](../01-static-architectures/native-cpp-abi.md).
- WPF/WinForms: managed CIL, often with `BAML` resources. Decompile with `ilspycmd`; [managed-dotnet-jvm.md](../01-static-architectures/managed-dotnet-jvm.md).

### Local storage secrets
- Windows DPAPI: `CryptProtectData`/`CryptUnprotectData` blobs are decryptable only in the user (or machine) context. A Chromium-based client's cookies/passwords use DPAPI over an AES key in `Local State`. Record the storage, not a live credential.
- macOS: Keychain items via `security find-generic-password`; the entitlement/ACL decides which app may read them.

## Worked Example: Confirming An Unauthenticated Named Pipe

The claim "this pipe is an unauthenticated privilege boundary" needs two independent observations (Rule 11): one static (the server does not check the caller) and one on the DACL.

1. **Static anchor.** Find the server loop: xref `CreateNamedPipeW`, then the following `ConnectNamedPipe` and the read/dispatch. Check for an authentication step between accept and action:
   - `ImpersonateNamedPipeClient` + a token/SID check, or
   - `GetNamedPipeClientProcessId` + a signature/path check on the caller, or
   - a shared-secret/HMAC on the first message.
   Their absence (a dispatch that acts on the message with no caller check) is the static observation. Record the function and the dispatch address.
2. **DACL anchor.** `accesschk.exe -accepteula \pipe\<Name> -v`. A DACL granting `FILE_WRITE_DATA` to `Everyone`/`Authenticated Users` while the server runs as SYSTEM is the second observation. In the binary this matches a `NULL` or permissive `SECURITY_DESCRIPTOR` passed to `CreateNamedPipeW`.
3. **Confirm the command surface (lab).** Enumerate the opcodes the dispatch accepts and which reach a sensitive action (file write as SYSTEM, process launch, registry write). A minimal client in a lab VM that sends one opcode and observes the privileged effect promotes the finding; do not weaponize it.

Frida read-only probe of the server's dispatch (lab VM, batch, Rule 5):
```javascript
// frida -p <server_pid> -l pipe_dispatch.js  (detach after capture)
const disp = Module.findExportByName(null, "DispatchPipeCommand"); // renamed from the IDB
Interceptor.attach(disp, {
  onEnter(args) {
    const op = args[1].toInt32();
    const buf = args[2];
    send({ opcode: op, head: buf.readByteArray(16) });
  }
});
```
The same logic applies to COM (is `CoInitializeSecurity` setting `RPC_C_AUTHN_LEVEL_*`, and can a low-IL caller `CoCreateInstance` the CLSID?) and to XPC (does the event handler validate the peer's code signature before serving the request?).

## Where The Code Actually Is
| Client | Open |
|---|---|
| .NET WinForms or WPF | [managed-dotnet-jvm.md](../01-static-architectures/managed-dotnet-jvm.md) |
| Native C/C++ (incl. Qt) | [native-cpp-abi.md](../01-static-architectures/native-cpp-abi.md) |
| Electron or `app.asar` | [browser-js-wasm.md](../01-static-architectures/browser-js-wasm.md) |
| macOS `.app` | [mobile-ios.md](../01-static-architectures/mobile-ios.md) |
| Custom TLS or a pinned certificate | [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md) |

On Windows, a DLL loaded from the application directory before System32 is a search-order lead. Record the path. Do not drop a substitute DLL.

## Boundaries
- Client-side checks are not server-side checks. A patched client does not prove the server accepts the same input.
- Credential material found on disk is evidence of storage, not proof it is still valid.
- An open IPC endpoint is a finding only after you confirm, in the binary, that the caller is not authenticated. A DACL you did not read is an unknown, not a vulnerability.
- Do not send the client's traffic at a production host. Egress is in Rule 6.
