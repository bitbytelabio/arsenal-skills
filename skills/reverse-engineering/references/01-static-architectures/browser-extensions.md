# Browser Extension Architecture & Reverse Engineering

## 1. Title & Overview
- **Domain**: Chromium (Google Chrome, Microsoft Edge, Brave, Opera) and Gecko (Mozilla Firefox) browser extensions packaged as `.crx` or `.xpi` archives.
- **Scope**: Manifest V2 vs Manifest V3 specification differences, CRX2/CRX3 package format unpacking, service workers vs persistent background pages, `declarativeNetRequest` rules versus dynamic `webRequest`, content script execution environments (isolated worlds, DOM sharing vulnerabilities), message-passing IPC boundaries (`chrome.runtime.sendMessage`, `onMessageExternal`, native messaging), professional JavaScript AST deobfuscation pipelines for obfuscated extension payloads (Obfuscator.io string array decoding, proxy function inlining, constant folding, property accessor normalization, control-flow unflattening), and JavaScript Virtual Machine Protection (JSVMP) devirtualization in background workers and content scripts.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing browser extensions, web security add-ons, suspicious browser plugins, or obfuscated extension payloads:

### Package Formats & Magic Bytes
- **Chrome Extension Package (`.crx`)**:
  - Magic bytes: `Cr24` (`\x43\x72\x32\x34` / `0x34327243`).
  - Format versions:
    - CRX2 (Legacy): Version `2` (magic followed by `0x00000002`, public key len, signature len, ZIP payload).
    - CRX3 (Current): Version `3` (magic followed by `0x00000003`, 4-byte header length, protobuf header containing public key proofs, followed directly by standard PKZIP payload).
- **Firefox Extension Package (`.xpi`)**:
  - Standard PKZIP archive (`PK\x03\x04` / `0x04034B50`).
- **Core Manifest File**:
  - `manifest.json` at root directory.
  - Manifest Version indicator: `"manifest_version": 2` or `"manifest_version": 3`.

### Obfuscation & Evasion Indicators in Extensions
- **Obfuscator.io / JavaScript-Obfuscator Patterns**:
  - High entropy `.js` files in `content_scripts` or `background.service_worker`.
  - Scrambled global string array declarations: `var _0x2a1b = ['cookie', 'getAll', ...];`.
  - Self-executing rotation loops with `while (--_0xcount)` or `parseInt` checksums.
  - Hexadecimal identifier mangling: `_0x1a2b`, `_0x4f2a`.
  - Obfuscated API calls designed to evade Chrome Web Store static scanners: `chrome[_0x1a(0x0)][_0x1a(0x1)]` instead of `chrome.cookies.getAll`.
  - Control-Flow Flattening (CFF) state machine dispatch loops: `while (true) switch (_0xorder[_0xidx++])`.
- **JSVMP (JavaScript Virtual Machine Protection) Patterns**:
  - Encrypted bytecode strings or typed byte arrays (`Uint8Array`) embedded in background service workers or content scripts.
  - Custom virtual execution loop containing Virtual PC (`vpc`), operand stack (`stack = []`), and central `switch (opcode)` dispatcher.
  - Virtualized API calls executing dynamic reflection (`window[v1][v2].apply(...)`) to hide credential exfiltration, token theft, and DOM scraping.

---

## 3. Tooling & CLI/MCP Actions

### CRX & XPI Unpackers
- **Python Carving & Unpacking**:
  ```bash
  # Carve embedded ZIP payload from CRX3 package and extract
  python3 unpack_crx.py target_extension.crx
  ```
- **CLI Utilities**:
  ```bash
  # Unzip Firefox XPI archive
  unzip extension.xpi -d ./unpacked_extension
  ```

### AST Deobfuscation Ecosystem
- **Babel AST Toolchain**:
  - `@babel/parser`: Parses obfuscated extension scripts into ESTree AST.
  - `@babel/traverse`: Traverses and manipulates AST paths, scopes, and bindings.
  - `@babel/generator`: Emits clean, readable JavaScript code.
  - `@babel/types`: AST node validation, inspection, and creation.
  ```bash
  npm install --save-dev @babel/parser @babel/traverse @babel/generator @babel/types
  ```
- **Automated Deobfuscators**:
  - `webcrack`: Deobfuscates Obfuscator.io patterns and inlines proxy functions.
    ```bash
    npx webcrack ./unpacked_extension/content.js -o ./deobfuscated_src
    ```
  - `wakaru`: Modern unbundler and decompiler for minified modules.
    ```bash
    npx @wakaru/cli unminify ./unpacked_extension/background.js -o ./clean_bg
    ```
  - `synchrony`: Specialized AST cleaner for JavaScript-Obfuscator rules.
    ```bash
    npx synchrony deobfuscate ./unpacked_extension/payload.js
    ```

### Live Extension Inspection & Dynamic Instrumentation
- **JSHook MCP (`@jshookmcp/jshook`)**: Dedicated automated reverse engineering suite providing CDP session debugging, Chrome Extension background Service Worker inspection (`select_page`, `select_frame`), content script DOM hook injection, and dynamic request initiator tracing. Complete usage patterns, 5-phase workflows, and boundaries are documented in [04-tool-usage/jshook-mcp.md](../04-tool-usage/jshook-mcp.md).
- **Chrome Developer Tools**:
  - Navigate to `chrome://extensions`, enable "Developer mode".
  - Click "Load unpacked" and select the extension directory.
  - Click "Inspect views: service worker" to open dedicated DevTools for background logic.
- **Chrome DevTools Protocol (CDP) & Playwright**:
  - Launch Chromium with extension loaded and remote debugging enabled:
    ```bash
    google-chrome --remote-debugging-port=9222 --load-extension=./unpacked_extension --disable-extensions-except=./unpacked_extension
    ```
  - Attach Playwright or Puppeteer via CDP to capture dynamic JSVMP bytecode traces and decrypt runtime parameters.
---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Manifest V2 vs Manifest V3 Architecture Comparison
Manifest V3 (MV3) fundamentally altered extension persistence and network manipulation capabilities:

| Feature / Capability | Manifest V2 (Legacy) | Manifest V3 (Current Standard) | Security Implication |
| :--- | :--- | :--- | :--- |
| **Background Execution** | Persistent background pages (`background.scripts` / HTML) | Ephemeral background **Service Workers** (`background.service_worker`) | State cannot be stored in global variables; worker terminates after 30s idle timeout |
| **Network Interception** | `chrome.webRequest` (blocking API allows arbitrary inspection/modification) | `chrome.declarativeNetRequest` (DNR: declarative regex rules evaluated by browser) | Extensions cannot inspect request body plaintext unless using non-blocking observation |
| **Remote Code Execution** | Permitted via `eval()`, `new Function()`, or loading external scripts | **Strictly forbidden**; all executable code must be locally packaged in the CRX | Obfuscators cannot dynamically fetch C2 payloads from remote servers; malware relies on JSVMP |
| **Host Permissions** | Combined into `"permissions"` array | Split into `"permissions"` (APIs) and `"host_permissions"` (domains) | Finer privilege scoping |

---

### 4.2 Extension Execution Contexts & The Trust Boundary
An extension operates across multiple isolated contexts with varying privileges:

```text
┌────────────────────────────────────────────────────────┐
│                   Untrusted Web Page                   │
│   (DOM, window, global JavaScript variables, cookies)   │
└───────────────────────────┬────────────────────────────┘
                            │ DOM Events / postMessage
                            ▼
┌────────────────────────────────────────────────────────┐
│                     Content Script                     │
│  - Isolated World (private JS variables, shared DOM)   │
│  - Access to subset of chrome.runtime APIs             │
│  - Can communicate with background service worker      │
└───────────────────────────┬────────────────────────────┘
                            │ chrome.runtime.sendMessage
                            ▼
┌────────────────────────────────────────────────────────┐
│              Background Service Worker                 │
│  - Privileged API access: chrome.cookies, tabs, storage│
│  - declarativeNetRequest rules engine                  │
│  - Arbitrary network requests (fetch / CORS bypass)    │
└───────────────────────────┬────────────────────────────┘
                            │ Native Messaging Host (stdin/stdout)
                            ▼
┌────────────────────────────────────────────────────────┐
│                 Local Host Executable                  │
│   (Native binary running with local user privileges)   │
└────────────────────────────────────────────────────────┘
```

#### The Two Critical Attack Surfaces:
1. **Web Page ↔ Content Script Interface**:
   - Although the Content Script executes in an *Isolated World* (preventing the page from accessing `chrome.*` APIs directly), it shares the same DOM tree and listens to `window.postMessage`.
   - If a content script accepts unvalidated `postMessage` data without verifying `event.origin`, an untrusted web page can trigger content script actions.
2. **Content Script ↔ Background Service Worker Interface**:
   - The content script sends IPC messages to the background worker using `chrome.runtime.sendMessage`.
   - The background worker receives these via `chrome.runtime.onMessage.addListener((message, sender, sendResponse) => { ... })`.
   - **Vulnerability Pattern**: If the background script performs a privileged action (e.g., calling `chrome.cookies.getAll`, deleting files, or making cross-origin requests) based purely on `message.action` without checking `sender.id` or `sender.url`, a malicious web page can exploit the content script to abuse background privileges.

---

### 4.3 Auditing `manifest.json` for Privilege Creep
Always inspect the permissions map before auditing JavaScript source:

```json
{
  "manifest_version": 3,
  "name": "Target Extension",
  "version": "1.0.0",
  "permissions": [
    "cookies",
    "storage",
    "declarativeNetRequest",
    "scripting",
    "nativeMessaging"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [
    {
      "matches": ["https://*/*", "http://*/*"],
      "js": ["content.js"],
      "run_at": "document_idle"
    }
  ],
  "externally_connectable": {
    "matches": ["https://partner-portal.com/*"]
  }
}
```

#### High-Risk Permission Indicators:
- `<all_urls>` or `*://*/*`: Unrestricted cross-origin network access and DOM injection across every visited site.
- `cookies`: Ability to read and exfiltrate authentication session tokens for any domain covered by `host_permissions`.
- `scripting`: Ability to inject arbitrary JavaScript directly into any tab (`chrome.scripting.executeScript`).
- `nativeMessaging`: Ability to spawn and exchange JSON messages with an executable binary installed on the operating system.
- `externally_connectable`: Allows external web pages matching the origin pattern to send direct messages to `chrome.runtime.onMessageExternal`.

---

### 4.4 DeclarativeNetRequest Rules vs `webRequest`
In Manifest V3, blocking network manipulation is defined through JSON rule sets:
- Inspect `manifest.json` for `"declarative_net_request"` rule dictionary.
- Review rule definitions:
  ```json
  [
    {
      "id": 1,
      "priority": 1,
      "action": { "type": "block" },
      "condition": { "urlFilter": "||analytics.tracker.com", "resourceTypes": ["script"] }
    },
    {
      "id": 2,
      "priority": 2,
      "action": {
        "type": "modifyHeaders",
        "requestHeaders": [
          { "header": "Authorization", "operation": "set", "value": "Bearer EXFILTRATED_TOKEN" }
        ]
      },
      "condition": { "urlFilter": "||api.target.com" }
    }
  ]
  ```
- **Reversing Action**: Check rules for header injection, redirection to malicious hosts (`type: "redirect"`), or stripping of security headers (e.g., removing `Content-Security-Policy` or `X-Frame-Options`).

---

### 4.5 Auditing Native Messaging Hosts
Extensions with `nativeMessaging` permissions communicate over standard I/O with a local executable:
1. Locate the Native Messaging Host manifest file:
   - Linux: `~/.config/google-chrome/NativeMessagingHosts/<name>.json`
   - macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<name>.json`
   - Windows: Registry key `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\<name>`
2. Inspect the JSON host manifest:
   ```json
   {
     "name": "com.target.native_host",
     "description": "Native Host Helper",
     "path": "/usr/local/bin/target_host",
     "type": "stdio",
     "allowed_origins": ["chrome-extension://abcdefghijklmnopqrstuvwxyz/"]
   }
   ```
3. Extract and reverse engineer the native binary located at `path` using IDA Pro or Ghidra (`native-cpp-abi.md`). Trace the message framing protocol: 4-byte little-endian message length prefix followed by UTF-8 JSON.

---

### 4.6 Reversing Obfuscated Extension Scripts with Babel AST Pipelines
Malicious extensions bypass Chrome Web Store automated scanners by hiding API invocations behind Obfuscator.io layers. Standard string search for `chrome.cookies` or `fetch` fails because they are represented as `chrome[_0x1a2b(0x10)][_0x1a2b(0x11)]`.

```text
┌────────────────────────────────────────────────────────┐
│            Obfuscated Extension Script                 │
│      (content.js / background.js / injected.js)        │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│             Babel AST Deobfuscation Pipeline           │
│                                                        │
│  1. String Array Extraction & VM Sandbox Rotation      │
│  2. Inlining CallExpression String Lookups             │
│  3. Proxy Function Inlining (Operators & Calls)        │
│  4. Constant Folding & Dead-Code Branch Pruning        │
│  5. Property Accessor Normalization                    │
│     (window['chrome']['cookies'] -> chrome.cookies)    │
│  6. Control-Flow Unflattening (CFF State Machine)      │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│            Deobfuscated JavaScript & API Audit         │
│  - Direct chrome.* API surface mapping                 │
│  - Unmasked C2 exfiltration endpoints & webhooks       │
│  - Clean logic for manual or automated auditing        │
└────────────────────────────────────────────────────────┘
```

#### Key Transformation Phases:
1. **String Array Extraction & Sandbox Rotation**:
   - Top-level array declaration + rotation IIFE + helper lookup function.
   - Run the extracted three nodes inside a Node.js `vm.createContext({})` sandbox.
   - Replace all `CallExpression` occurrences of `_0xget(0x12)` with the concrete string value returned by the sandbox helper.
   - Remove the array, rotation routine, and helper function AST nodes.
2. **Proxy Function Inlining**:
   - Detect functions returning a single binary expression (`a + b`, `a === b`) or call expression (`fn(a, b)`).
   - Inline the operations at all call sites and remove the proxy function declarations.
3. **Dead-Code Pruning & Constant Folding**:
   - Evaluate constant expressions via `path.evaluate()`.
   - Prune dead conditional blocks (`if (false) { ... }`, ternary branches) injected to confuse static analyzers.
4. **Property Accessor Normalization**:
   - Convert bracket access notation `chrome['cookies']['getAll']` into dot notation `chrome.cookies.getAll`.
   - This step is critical for automated security scanning: static pattern matchers and regex rules can now detect sensitive API access.
5. **Control-Flow Unflattening (CFF)**:
   - Identify `while (true) switch (_0xorder[_0xidx++])` state machines.
   - Parse the `'3|1|0|2'.split('|')` execution array.
   - Reorder switch case basic blocks into linear sequential statements.

---

### 4.7 JSVMP (JavaScript Virtual Machine Protection) Devirtualization in Extensions
Advanced extension malware utilizes JSVMP inside background service workers to execute arbitrary logic without violating Manifest V3's strict prohibition against remote `eval()` / `new Function()`. The extension packages an embedded bytecode interpreter and a proprietary bytecode payload.

#### Architectural Components:
1. **Bytecode Stream**: Stored as a packed array or base64 string inside the extension package.
2. **Virtual Registers**: Virtual PC (`vpc`), stack pointer (`vsp`), flag registers.
3. **Operand Stack**: Array managing temporary values and arguments (`stack = []`).
4. **Opcode Dispatcher**: Infinite loop with a `switch` statement executing custom bytecode instructions.

#### 3-Step Devirtualization Workflow:
1. **Step 1: Static Analysis of Interpreter Loop & Opcode Table**:
   - Locate the dispatcher loop in the background script.
   - Map opcode IDs to operations:
     - `0x01`: Push immediate / string constant to stack.
     - `0x02`: Pop two values, perform binary operation (add, concat, compare), push result.
     - `0x03`: Resolve object property (`obj[prop]`).
     - `0x04`: Call function with arguments (`fn.apply(ctx, args)`).
     - `0x05`: Jump / Conditional Jump (`vpc = target`).
2. **Step 2: Dynamic Trace-Based Analysis & JSHook MCP Integration**:
   - **JSHook MCP Session Attachment**: In MV3, background service workers operate in isolated target contexts. Use JSHook MCP to select the service worker target and inspect or hook its execution:
     ```javascript
     // Attach to extension service worker target
     call_tool({
         tool_name: "select_page",
         arguments: { target_id: "service_worker_target_id" }
     });
     // Hook interpreter dispatcher in service worker
     call_tool({
         tool_name: "install_function_hook",
         arguments: {
             page_id: "service_worker_target_id",
             target_object: "self",
             method_name: "vmp_step",
             hook_code: `
                 self.__sw_vmp_trace__ = self.__sw_vmp_trace__ || [];
                 const orig = self.vmp_step;
                 self.vmp_step = function(op, vpc, stack) {
                     self.__sw_vmp_trace__.push({ op, vpc, stackTop: stack ? stack.slice(-2) : [] });
                     return orig.apply(this, arguments);
                 };
             `
         }
     });
     ```
   - **Content Script DOM Hook Injection**: For content scripts executing in isolated worlds, inject stealth hooks via `evaluate_script` or `install_function_hook` to intercept shared DOM access, message-passing boundaries (`chrome.runtime.sendMessage`), and exfiltration triggers.
   - **CDP or Playwright Hooking**: Alternatively, attach via raw CDP to log each `(vpc, opcode, stack, operands)` event to a structured JSON file.
   - Trigger extension functionality (e.g., visit a sensitive website or simulate message IPC).
3. **Step 3: AST Generation from VM Trace**:
   - Feed the dynamic execution trace into a symbolic stack evaluator or JSHook MCP's `VMDeobfuscator`.
   - Reconstruct JavaScript AST nodes for each virtual instruction (pushing literals, building expressions, resolving member access, creating call expressions).
   - Output clean JavaScript demonstrating the exact sequence of actions executed by the virtual machine.

#### Tooling Ecosystem Matrix:
| Tool | Core Capability | Best Suited For | Limitation |
| :--- | :--- | :--- | :--- |
| **`webcrack`** | Webpack unbundling, Obfuscator.io deobfuscation | Extension content scripts, background bundles | Does not devirtualize complex custom JSVMP |
| **`wakaru`** | TypeScript construct recovery, variable un-mangling | Clean output formatting, module restructuring | Target must not use heavy virtualization |
| **`synchrony`** | Semantic AST deobfuscator for Obfuscator.io | Control flow unflattening, string array rotation | Tuned specifically for JS-Obfuscator rules |
| **Babel Custom Script** | Custom AST transformation rules | Tailored extension deobfuscation & API auditing | Requires manual pattern identification |
| **JSHook MCP (`@jshookmcp/jshook`)** | Automated CDP Service Worker inspection, DOM hooking, `VMDeobfuscator` | Full MV2/MV3 dynamic analysis, JSVMP reversing, AST cleaning | Requires Node.js MCP runtime (see [04-tool-usage/jshook-mcp.md](../04-tool-usage/jshook-mcp.md)) |
| **CDP Service Worker Hook** | Dynamic opcode trace extraction | JSVMP bytecode reversing in Service Workers | Requires Chromium runtime environment |

---

## 5. Concrete Code & Script Examples

### Python CRX3 Unpacker & Manifest Security Auditor
```python
import struct
import sys
import zipfile
import io
import json

def unpack_and_audit_crx(crx_path):
    with open(crx_path, "rb") as f:
        data = f.read()

    # Check magic: Cr24 (0x34327243)
    if data[:4] != b"Cr24":
        print("[-] Not a valid CRX package.")
        return

    version = struct.unpack_from("<I", data, 4)[0]
    print(f"[+] Found CRX package (Format Version: {version})")

    # Locate inner ZIP archive (PK\x03\x04)
    zip_offset = data.find(b"PK\x03\x04")
    if zip_offset == -1:
        print("[-] Embedded PKZIP archive not found.")
        return

    print(f"[+] Carving ZIP payload from byte offset 0x{zip_offset:X}...")
    zip_bytes = data[zip_offset:]
    
    try:
        z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as e:
        print(f"[-] Failed to parse carved ZIP: {e}")
        return

    print(f"[+] Successfully opened ZIP archive ({len(z.namelist())} files).")

    # Read and audit manifest.json
    if "manifest.json" in z.namelist():
        manifest_raw = z.read("manifest.json").decode("utf-8", errors="ignore")
        manifest = json.loads(manifest_raw)
        
        print("\n=== EXTENSION MANIFEST AUDIT ===")
        print(f"Name:             {manifest.get('name')}")
        print(f"Manifest Version: {manifest.get('manifest_version')}")
        print(f"Permissions:      {manifest.get('permissions', [])}")
        print(f"Host Permissions: {manifest.get('host_permissions', [])}")
        
        # Check background context
        bg = manifest.get("background", {})
        if "service_worker" in bg:
            print(f"Background:       Service Worker ({bg['service_worker']})")
        elif "scripts" in bg:
            print(f"Background:       Persistent Scripts ({bg['scripts']})")

        # Check content scripts
        cs = manifest.get("content_scripts", [])
        print(f"Content Scripts:  {len(cs)} rule(s) defined")
        for idx, rule in enumerate(cs):
            print(f"  [{idx}] Matches: {rule.get('matches')} -> JS: {rule.get('js')}")

        # Check externally connectable
        ec = manifest.get("externally_connectable", {})
        if ec:
            print(f"[!] Warning: externally_connectable defined: {ec.get('matches')}")

    # Extract all files to disk
    out_dir = "./unpacked_extension"
    z.extractall(out_dir)
    print(f"\n[+] Extracted full extension source tree to: {out_dir}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 unpack_crx.py <extension.crx>")
        sys.exit(1)
    unpack_and_audit_crx(sys.argv[1])
```

---

### Production-Grade Node.js Babel Deobfuscator & Extension API Auditor
This script runs a multi-pass AST deobfuscation pipeline across unpacked extension JavaScript files, normalizes property accessors to reveal hidden `chrome.*` API calls, and reports all unmasked API invocations and network endpoints.

```javascript
/**
 * audit_extension_ast.js
 * Multi-pass AST deobfuscator and API surface auditor for browser extensions.
 * 
 * Dependencies:
 *   npm install @babel/parser @babel/traverse @babel/generator @babel/types
 * 
 * Usage:
 *   node audit_extension_ast.js <path_to_extension_script.js> [output_clean.js]
 */

const fs = require('fs');
const vm = require('vm');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default || require('@babel/traverse');
const generate = require('@babel/generator').default || require('@babel/generator');
const t = require('@babel/types');

function deobfuscateExtensionScript(sourceCode) {
    console.log('[*] Parsing extension script into AST...');
    const ast = parser.parse(sourceCode, {
        sourceType: 'unambiguous',
        plugins: ['jsx']
    });

    // -------------------------------------------------------------------------
    // PASS 1: String Array Unpacking & Sandbox Rotation Decoding
    // -------------------------------------------------------------------------
    console.log('[*] Pass 1: Resolving string array and rotation routine...');
    if (ast.program.body.length >= 3) {
        const candidateNodes = ast.program.body.slice(0, 3);
        const sandboxAst = t.program(candidateNodes);
        const sandboxCode = generate(sandboxAst).code;

        let helperName = null;
        const helperNode = ast.program.body[2];
        if (t.isVariableDeclaration(helperNode) && helperNode.declarations.length > 0) {
            helperName = helperNode.declarations[0].id.name;
        } else if (t.isFunctionDeclaration(helperNode)) {
            helperName = helperNode.id.name;
        }

        if (helperName) {
            try {
                const sandboxContext = vm.createContext({});
                vm.runInContext(sandboxCode, sandboxContext, { timeout: 2000 });

                if (typeof sandboxContext[helperName] === 'function') {
                    let inlined = 0;
                    traverse(ast, {
                        CallExpression(path) {
                            if (t.isIdentifier(path.node.callee, { name: helperName })) {
                                const args = path.node.arguments;
                                if (args.length >= 1 && args.every(a => t.isNumericLiteral(a) || t.isStringLiteral(a))) {
                                    const evaluatedArgs = args.map(a => a.value);
                                    try {
                                        const decrypted = sandboxContext[helperName](...evaluatedArgs);
                                        if (typeof decrypted === 'string') {
                                            path.replaceWith(t.stringLiteral(decrypted));
                                            inlined++;
                                        } else if (typeof decrypted === 'number') {
                                            path.replaceWith(t.numericLiteral(decrypted));
                                            inlined++;
                                        }
                                    } catch (e) {
                                        // Ignore evaluation faults
                                    }
                                }
                            }
                        }
                    });
                    console.log(`[+] Pass 1: Inlined ${inlined} obfuscated string lookups.`);
                    ast.program.body.splice(0, 3);
                }
            } catch (err) {
                console.warn(`[-] Pass 1: Sandbox rotation execution skipped (${err.message}).`);
            }
        }
    }

    // -------------------------------------------------------------------------
    // PASS 2: Proxy Function Inlining
    // -------------------------------------------------------------------------
    console.log('[*] Pass 2: Inlining proxy functions...');
    const proxyFunctions = new Map();

    traverse(ast, {
        FunctionDeclaration(path) {
            const { id, params, body } = path.node;
            if (!id || body.body.length !== 1) return;
            const stmt = body.body[0];
            if (!t.isReturnStatement(stmt)) return;
            const arg = stmt.argument;

            if (t.isBinaryExpression(arg) &&
                t.isIdentifier(arg.left) && t.isIdentifier(arg.right) &&
                params.length === 2 &&
                params[0].name === arg.left.name && params[1].name === arg.right.name) {
                proxyFunctions.set(id.name, { kind: 'binary', operator: arg.operator, path });
            } else if (t.isCallExpression(arg) &&
                t.isIdentifier(arg.callee) &&
                params.length > 0 &&
                params[0].name === arg.callee.name) {
                proxyFunctions.set(id.name, { kind: 'call', path });
            }
        }
    });

    for (const [name, info] of proxyFunctions.entries()) {
        traverse(ast, {
            CallExpression(path) {
                if (t.isIdentifier(path.node.callee, { name })) {
                    if (info.kind === 'binary' && path.node.arguments.length === 2) {
                        path.replaceWith(t.binaryExpression(info.operator, path.node.arguments[0], path.node.arguments[1]));
                    } else if (info.kind === 'call' && path.node.arguments.length >= 1) {
                        const targetFn = path.node.arguments[0];
                        const callArgs = path.node.arguments.slice(1);
                        path.replaceWith(t.callExpression(targetFn, callArgs));
                    }
                }
            }
        });
        info.path.remove();
    }

    // -------------------------------------------------------------------------
    // PASS 3: Constant Folding & Dead-Code Pruning
    // -------------------------------------------------------------------------
    console.log('[*] Pass 3: Folding constants and pruning dead branches...');
    traverse(ast, {
        BinaryExpression(path) {
            const evaluated = path.evaluate();
            if (evaluated.confident) {
                path.replaceWith(t.valueToNode(evaluated.value));
            }
        },
        IfStatement(path) {
            const test = path.get('test');
            const evaluated = test.evaluate();
            if (evaluated.confident) {
                if (evaluated.value) {
                    if (path.node.consequent) path.replaceWith(path.node.consequent);
                    else path.remove();
                } else {
                    if (path.node.alternate) path.replaceWith(path.node.alternate);
                    else path.remove();
                }
            }
        }
    });

    // -------------------------------------------------------------------------
    // PASS 4: Property Accessor Normalization (Unmasking chrome.* APIs)
    // -------------------------------------------------------------------------
    console.log('[*] Pass 4: Normalizing property accessors (window["chrome"] -> window.chrome)...');
    const validIdentifierRegex = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;
    traverse(ast, {
        MemberExpression(path) {
            const prop = path.node.property;
            if (path.node.computed && t.isStringLiteral(prop)) {
                if (validIdentifierRegex.test(prop.value)) {
                    path.node.computed = false;
                    path.node.property = t.identifier(prop.value);
                }
            }
        }
    });

    // -------------------------------------------------------------------------
    // PASS 5: Extension API & Network Indicator Audit
    // -------------------------------------------------------------------------
    console.log('\n=== UNMASKED EXTENSION API AUDIT ===');
    const detectedApis = new Set();
    const detectedEndpoints = new Set();

    traverse(ast, {
        MemberExpression(path) {
            const memberStr = generate(path.node).code;
            if (memberStr.startsWith('chrome.') || memberStr.startsWith('browser.')) {
                detectedApis.add(memberStr);
            }
        },
        StringLiteral(path) {
            const val = path.node.value;
            if (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('ws://') || val.startsWith('wss://')) {
                detectedEndpoints.add(val);
            }
        }
    });

    console.log('Detected Extension APIs:');
    if (detectedApis.size === 0) console.log('  (None detected)');
    for (const api of detectedApis) {
        console.log(`  [!] API: ${api}`);
    }

    console.log('\nDetected Remote Endpoints:');
    if (detectedEndpoints.size === 0) console.log('  (None detected)');
    for (const ep of detectedEndpoints) {
        console.log(`  [!] Endpoint: ${ep}`);
    }

    const cleanCode = generate(ast, { retainLines: false, compact: false }).code;
    return cleanCode;
}

// CLI Execution Entry Point
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        console.log('Usage: node audit_extension_ast.js <script.js> [output.clean.js]');
        process.exit(1);
    }
    const inputPath = args[0];
    const outputPath = args[1] || 'deobfuscated_extension.js';

    const source = fs.readFileSync(inputPath, 'utf-8');
    const cleaned = deobfuscateExtensionScript(source);
    fs.writeFileSync(outputPath, cleaned, 'utf-8');
    console.log(`\n[+] Clean deobfuscated script saved to: ${outputPath}`);
}

module.exports = { deobfuscateExtensionScript };
```

---

### Playwright CDP Script: Tracing JSVMP in Extension Service Worker
```javascript
/**
 * trace_extension_service_worker.js
 * Injects hooks into a browser extension background service worker to capture JSVMP execution.
 * 
 * Dependencies:
 *   npm install playwright
 */

const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

(async () => {
    const extensionPath = path.resolve('./unpacked_extension');
    console.log(`[*] Launching Chromium with extension from: ${extensionPath}`);

    const context = await chromium.launchPersistentContext('', {
        headless: false,
        args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`
        ]
    });

    // Wait for the background service worker to register
    console.log('[*] Waiting for background service worker to initialize...');
    let serviceWorker = context.serviceWorkers()[0];
    if (!serviceWorker) {
        serviceWorker = await context.waitForEvent('serviceworker');
    }
    console.log(`[+] Found Service Worker at: ${serviceWorker.url()}`);

    // Evaluate hook inside the service worker context
    await serviceWorker.evaluate(() => {
        self.__vmp_trace__ = [];
        console.log('[+] Hook installed in extension Service Worker.');

        // Hook dispatcher when VM object is instantiated
        const originalFetch = self.fetch;
        self.fetch = function(...args) {
            console.log('[!] Intercepted fetch call inside worker:', args[0]);
            return originalFetch.apply(this, args);
        };
    });

    // Let the extension run for 10 seconds to collect activity
    await new Promise(r => setTimeout(r, 10000));

    await context.close();
    console.log('[+] Instrumentation complete.');
})();
```

---

## 6. Boundaries & Anti-Patterns
- **Do not assume Content Scripts have access to all `chrome.*` APIs**: Content scripts only have access to a small subset of APIs (e.g., `chrome.runtime.sendMessage`, `chrome.storage`). They cannot directly call `chrome.cookies`, `chrome.tabs`, or `chrome.debugger`. Always look for the message relay to the background worker.
- **Do not overlook DOM-based communication**: A web page cannot read extension variables, but it can mutate the DOM, set custom `data-*` attributes, or trigger click events on elements monitored by the content script.
- **Do not ignore service worker lifecycle timeouts**: In MV3, background service workers terminate after 30 seconds of inactivity. Any long-running state machine or socket connection must use alarms (`chrome.alarms`) or native messaging to stay active.
- **Do not treat `.crx` as a raw ZIP archive without carving**: Directly feeding a `.crx` file into utilities expecting plain ZIP files may fail if the tool does not automatically skip the CRX3 protobuf header. Always strip the header down to `PK\x03\x04` before passing to strict zip libraries.
- **Do not execute untrusted extension scripts directly in the host environment**: Always sandbox string array rotation routines inside `vm.createContext({})` with explicit timeouts. Obfuscated extensions frequently check for Node.js environment variables to detect analysis sandboxes.
