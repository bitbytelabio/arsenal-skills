# Thick-Client Reverse Engineering

## When To Open
Open this file for a desktop client that is not only a web page: Qt, WPF, WinForms, Electron, Java Swing, or a native GUI with a local service. Pure protocol work stays in [protocol-recovery.md](protocol-recovery.md). The binary format still uses its architecture reference.

## Trust Boundary First
Draw the boundary before decompiling a random function:

- Process tree, helper services, and drivers.
- Listening sockets, especially `0.0.0.0`, and the outbound hosts.
- Local secret stores: `%APPDATA%`, DPAPI blobs, Keychain, plaintext config, SQLite.
- The update URL and whether the downloaded payload is signature-checked.
- IPC: named pipes, COM, XPC, localhost HTTP. Who can connect, and is the caller checked?

A hidden debug menu, a leftover command-line flag, or a config key that disables a check is a lead. Confirm it in the binary before calling it a bypass.

## Where The Code Actually Is
| Client | Open |
|---|---|
| .NET WinForms or WPF | [managed-dotnet-jvm.md](../01-static-architectures/managed-dotnet-jvm.md) |
| Native C/C++ | [native-cpp-abi.md](../01-static-architectures/native-cpp-abi.md) |
| Electron or `app.asar` | [browser-js-wasm.md](../01-static-architectures/browser-js-wasm.md) |
| macOS `.app` | [mobile-ios.md](../01-static-architectures/mobile-ios.md) |
| Custom TLS or a pinned certificate | [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md) |

On Windows, a DLL loaded from the application directory before System32 is a search-order lead. Record the path. Do not drop a substitute DLL.

## Boundaries
- Client-side checks are not server-side checks. A patched client does not prove the server accepts the same input.
- Credential material found on disk is evidence of storage, not proof it is still valid.
- Do not send the client's traffic at a production host. Egress is in Rule 6.
