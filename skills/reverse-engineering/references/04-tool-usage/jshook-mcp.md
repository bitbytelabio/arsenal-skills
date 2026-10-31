# JSHook MCP — Advanced JavaScript Reverse Engineering, CDP Debugging & Dynamic Hooking

## 1. Title & Overview
- **Domain**: Advanced client-side JavaScript reverse engineering, browser automation, Chrome DevTools Protocol (CDP) session debugging, stealth dynamic runtime hooking, V8 and TurboFan execution analysis, WebAssembly (WASM) inspection, and automated AST deobfuscation.
- **Package & Architecture**: `@jshookmcp/jshook` (`0.3.5`) deployed as a high-performance Model Context Protocol (MCP) server. It integrates over 600 specialized tools spanning 34 domain modules to automate complete browser and engine-level reverse engineering workflows.
- **Search-First Token Optimization**: Built specifically for token-constrained agent contexts. When running under `MCP_TOOL_PROFILE=search` (configured in `agent/mcp.json`), the server exposes a ultra-lean surface (~3K tokens) driven by meta-tools (`search_tools`, `describe_tool`, `call_tool`, `coverage_report`), eliminating prompt bloat while retaining instantaneous access to the complete 600+ tool suite.
- **Transport Modalities**: Supports local stdio execution for isolated agent processes, as well as high-throughput shared HTTP daemon deployment (`http://127.0.0.1:3000/mcp`) for multi-agent collaboration and persistent browser session reuse.

---

## 2. Trigger Conditions & Detection Indicators
Engage `jshookmcp` whenever dynamic browser instrumentation, runtime JavaScript tracing, or complex client-side obfuscation exceeds the capabilities of static analysis:

### Target Architecture & Runtime Triggers
- **Commercial JavaScript Obfuscators & Encoders**:
  - JScrambler protected scripts (polymorphic obfuscation, control-flow flattening, date/domain locks, self-defending integrity checks).
  - Obfuscator.io (hex variable mangling, rotated string array encryption, dead-code injection, function proxy wrappers).
  - Webpack, Rollup, or Vite minified bundles with hidden entry points and dynamic chunk loading.
- **JSVMP (JavaScript Virtual Machine Protection)**:
  - Custom virtual machines executing proprietary bytecode streams via an embedded interpreter loop (`vpc`, `vsp`, operand stack, instruction dispatcher).
  - Code protection requiring dynamic opcode tracing, bytecode dumping, and semantic devirtualization.
- **Anti-Debugging & Runtime Environment Fingerprinting**:
  - Aggressive `debugger;` statement loops, timing-based breakpoint detectors (`performance.now()`, `console.time()`).
  - Function tampering checks (`Function.prototype.toString` validation).
  - Bot protection and browser fingerprinting (Canvas, WebGL, AudioContext, navigator overrides, DOM integrity checks).
- **Complex Client-Side Cryptography & Network Protocols**:
  - Proprietary request signature generation (e.g., custom HMAC, dynamic token generation, encrypted payload bodies).
  - WebSocket and HTTP/2 framing requiring live frame/message capture and payload inspection before transport encryption.
  - WebAssembly (WASM) cryptographic cores interoperating with JavaScript host wrappers.

---

## 3. Server Architecture, Profiles & Transport

### Operational Modes & Profiles
`jshookmcp` manages its tool registry dynamically using the `MCP_TOOL_PROFILE` environment variable:

| Profile Mode | Token Overhead | Exposed Tool Surface | Operational Behavior |
| :--- | :--- | :--- | :--- |
| **`search` (Default)** | **~3,000 tokens** | **Meta-tools only** (`search_tools`, `describe_tool`, `call_tool`, `coverage_report`) | Tools are discovered on-demand via semantic search and dynamically invoked through `call_tool`. Highly recommended for all agent tasks. |
| **`workflow`** | ~18,000 tokens | Curated high-frequency workflows (~40-60 tools) | Directly exposes core browser navigation, script listing, source retrieval, and dynamic hooking primitives. |
| **`full`** | ~120,000+ tokens | Complete catalog (600+ tools) | Directly exposes all 34 domain modules. Useful only for specialized environments with very large context windows. |

### Transport Configuration

#### 1. Stdio Mode (Configured in `agent/mcp.json`)
```json
{
  "mcpServers": {
    "jshook": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@jshookmcp/jshook@0.3.5"],
      "env": {
        "MCP_TOOL_PROFILE": "search",
        "npm_config_omit": "optional"
      }
    }
  }
}
```

#### 2. Shared HTTP Daemon Mode (`http://127.0.0.1:3000/mcp`)
For long-lived browser sessions, shared debugging contexts across multiple agents, or remote execution:
```bash
# Launch shared daemon with search profile
MCP_TOOL_PROFILE=search npx -y @jshookmcp/jshook@0.3.5 --port 3000 --host 127.0.0.1
```

### Meta-Tools Discovery Protocol (Search Profile)
When operating under `MCP_TOOL_PROFILE=search`, execute tool interactions via the standard 3-step sequence:

```text
┌────────────────┐      1. search_tools(query)      ┌──────────────────┐
│                │ ───────────────────────────────> │  Matched Tool    │
│  Agent Engine  │                                  │  Names & Domain  │
│                │ <─────────────────────────────── └──────────────────┘
│                │
│                │      2. describe_tool(tool_name) ┌──────────────────┐
│                │ ───────────────────────────────> │  JSON Schema &   │
│                │                                  │  Exact Params    │
│                │ <─────────────────────────────── └──────────────────┘
│                │
│                │      3. call_tool(name, params)  ┌──────────────────┐
│                │ ───────────────────────────────> │  Target Tool     │
│                │                                  │  Execution       │
│                │ <─────────────────────────────── └──────────────────┘
└────────────────┘
```

1. **`search_tools`**: Search the 600+ tool index by capability or intent.
   - Example: `search_tools({ query: "websocket intercept" })`
2. **`describe_tool`**: Inspect the full JSON schema, input parameters, and return types.
   - **Rule**: NEVER guess tool parameters; always call `describe_tool` before invocation.
   - Example: `describe_tool({ tool_name: "get_websocket_messages" })`
3. **`call_tool`**: Execute the tool through the meta-dispatcher with validated parameters.
   - Example: `call_tool({ tool_name: "get_websocket_messages", arguments: { page_id: "PAGE_1", limit: 50 } })`
4. **`coverage_report`**: Inspect loaded domain modules and active target connections.

---

## 4. Deep Capability Domains & Tool Matrix

`jshookmcp` organizes its 600+ tools into 34 functional domains. The core domains critical for reverse engineering workflows include:

### 4.1 Browser & CDP Control Domain
Provides fine-grained lifecycle management of Chromium pages, workers, iframes, network pipelines, and source registries via direct Chrome DevTools Protocol sessions:

| Tool Name | Scope & Functionality | Key Parameters |
| :--- | :--- | :--- |
| **`new_page`** | Spawns a new isolated browser context and targets a specified URL. | `url`, `viewport`, `user_agent` |
| **`navigate_page`** | Navigates existing session to target URL with configurable wait triggers (`networkidle`, `domcontentloaded`). | `page_id`, `url`, `wait_until`, `timeout` |
| **`select_page`** | Lists and attaches to an active target page, popup, or background worker. | `page_id` or `target_id` |
| **`select_frame`** | Switches execution context to a specific nested `<iframe>` on the page. | `page_id`, `frame_id` or `frame_selector` |
| **`take_screenshot`** | Captures visual page state or specific DOM element for UI validation. | `page_id`, `full_page`, `selector` |
| **`list_network_requests`** | Retrieves network request history with status codes, headers, and mime types. | `page_id`, `filter_url`, `resource_type` |
| **`get_request_initiator`** | **Critical RE Tool**: Traces a network request directly to the JavaScript call stack and source line that triggered it. | `page_id`, `request_id` |
| **`list_scripts`** | Enumerates all parsed JavaScript and WebAssembly source assets loaded by the page. | `page_id`, `include_inlined` |
| **`get_script_source`** | Retrieves the raw source text or bytecode mapping of a specific loaded script. | `script_id` |
| **`search_in_sources`** | Full-text and regex search across all loaded scripts and source maps. | `page_id`, `query`, `is_regex`, `case_sensitive` |

### 4.2 Dynamic JS Hooking & Debugging Domain
Provides non-invasive runtime observation, automated breakpoint management, and dynamic state evaluation:

| Tool Name | Scope & Functionality | Key Parameters |
| :--- | :--- | :--- |
| **`break_on_xhr`** | Sets an automatic breakpoint matching specific URL substrings on `XMLHttpRequest` and `fetch`. | `url_pattern`, `page_id` |
| **`set_breakpoint_on_text`** | Sets source breakpoints on specific text patterns or function definitions without calculating line offsets. | `page_id`, `pattern`, `script_id` |
| **`get_paused_info`** | Inspects execution state when paused: call frames, local/closure scopes, and `this` binding. | `page_id` |
| **`pause_or_resume`** | Controls execution stepping: resume (`step_continue`), `step_over`, `step_into`, or `step_out`. | `page_id`, `action` |
| **`evaluate_script`** | Evaluates arbitrary JavaScript expressions within the current page, frame, or paused stack frame. | `page_id`, `expression`, `call_frame_id` |
| **`install_function_hook`** | Hooks functions to log, modify, or intercept arguments and return values at runtime. | `page_id`, `target_object`, `method_name`, `hook_code` |
| **`spoof_environment`** | Injects stealth evasion overrides before document execution: spoof `navigator.webdriver`, canvas fingerprint, WebGL vendor, and AudioContext. | `page_id`, `presets`, `custom_overrides` |
| **`suppress_debugger_statements`**| Automatically neuters `debugger;` opcodes and anti-analysis timing traps at the CDP level. | `page_id`, `enable` |

### 4.3 AST Transforms & Deobfuscation Domain
Employs embedded Babel, AST manipulation, and symbolic simplification engines to strip commercial obfuscation layers:

| Tool Name | Scope & Functionality | Target Obfuscation |
| :--- | :--- | :--- |
| **`JScramblerDeobfuscator`** | Analyzes and reverses JScrambler protections: strips self-defending predicates, decodes polymorphic string arrays, inlines function call proxies, and reconstructs linearized control flow. | Commercial JScrambler layers |
| **`VMDeobfuscator`** | **JSVMP Devirtualizer**: Inspects bytecode streams, maps virtual opcode dispatchers, extracts virtual stack operations, and synthesizes high-level JavaScript AST equivalents. | Custom JSVMP / Virtual Machines |
| **`PackerDeobfuscator`** | Detects and unpacks common JavaScript packers: Dean Edwards Packer, `eval(function(p,a,c,k,e,d)...)`, JJencode, AAencode, JSFuck. | Encoded script packers |
| **`unpack_string_array`** | Evaluates string array rotation routines in a secure sandbox and substitutes literal values at all call sites. | Obfuscator.io / Generic string tables |
| **`constant_folding`** | Evaluates static arithmetic expressions (`0x1a + 0x2b` -> `0x45`), boolean logic, and binary operations across AST paths. | General minified & flattened ASTs |
| **`control_flow_unflatten`** | Reconstructs structured loops (`for`, `while`) and `if/else` conditionals from state-machine `switch(dispatcher)` blocks. | Control-Flow Flattening (CFF) |

### 4.4 V8 & TurboFan Internals Domain
Examines the underlying V8 JavaScript engine compilation pipeline, TurboFan optimization graphs, and heap layouts:

| Tool Name | Scope & Functionality | Research Application |
| :--- | :--- | :--- |
| **`turbofan-graph`** | Extracts and visualizes the TurboFan intermediate representation (IR) graph for JIT-compiled functions. | Tracking type feedback, JIT vulnerabilities, speculative optimization |
| **`TurboFanTraceCollector`**| Records optimization phases, node schedules, and machine code generation events for targeted functions. | Identifying JIT optimization bypasses and compiler behavior |
| **`deopt-trace`** | Captures deoptimization triggers (e.g., eager deopt, soft deopt, bailout reasons) caused by polymorphic calls. | Anti-analysis detection that abuses engine bailout behaviors |
| **`track_allocations`** | Tracks real-time memory allocations per function, locating heap buffer churn. | Locating high-throughput cryptographic operations |
| **`parse_heap_snapshot`** | Ingests and queries Chrome V8 heap snapshots (`.heapsnapshot`) to recover retained objects, closures, and keys. | Extracting in-memory decrypted credentials, keys, and tokens |

### 4.5 WASM & Memory Forensics Domain
Inspects WebAssembly modules, garbage collection internals, and native browser memory:

| Tool Name | Scope & Functionality | Research Application |
| :--- | :--- | :--- |
| **`WasmGcInspector`** | Inspects WASM Garbage Collection (WasmGC) struct definitions, array types, and dynamic allocations. | Modern Dart/Kotlin/Go WASM modules |
| **`disassemble_wasm`** | Disassembles loaded `.wasm` bytecode chunks into linear WAT (WebAssembly Text) representation. | Auditing WASM cryptographic algorithms |
| **`HardwareBreakpoint`** | Emulates hardware watchpoints on specific memory addresses within WASM linear memory buffers. | Tracing memory reads/writes to encryption keys |
| **`MemoryScanner`** | Scans browser tab process memory for patterns, byte signatures, and structured strings. | Memory carving of decrypted payloads |
| **`PointerChainEngine`** | Resolves dynamic pointer multi-level offsets inside heap memory to locate volatile structures. | Locating runtime state anchors across refreshes |

### 4.6 Network & Protocol Domain
Direct frame-level interception of encrypted or multiplexed protocols:

| Tool Name | Scope & Functionality | Research Application |
| :--- | :--- | :--- |
| **`http2_frame_builder`** | Parses, reconstructs, and inspects HTTP/2 multiplexed streams, DATA frames, and HEADERS frames. | Bypassing HTTP/1 layer inspection limits |
| **`get_websocket_messages`** | Captures live bidirectional WebSocket frames (text, binary, ping/pong) with millisecond timestamps. | Real-time gaming, financial tickers, C2 feeds |
| **`graphql_inspector`** | Parses GraphQL queries, mutations, subscriptions, and schema introspection endpoints. | Mapping hidden API attack surfaces |
| **`boringssl-inspector`** | Hooks Chromium BoringSSL functions at the native layer to intercept plaintext TLS traffic before encryption. | Universal TLS interception without CA installation |

---

## 5. Five-Phase Reverse Engineering Workflow

Follow the standardized 5-phase methodology when conducting investigations with `jshookmcp`:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   JSHook MCP 5-Phase RE Workflow                       │
├────────────────────────────────────────────────────────────────────────┤
│  Phase 1: OBSERVE    ─► Navigate, enumerate scripts, search sources   │
│  Phase 2: INTERCEPT  ─► Trace request initiators, break on XHR/Fetch   │
│  Phase 3: HOOK       ─► Function interception, argument/return taps   │
│  Phase 4: TRACE      ─► Bytecode dumping, JSVMP tracing, TurboFan IR   │
│  Phase 5: REBUILD    ─► AST deobfuscation, SourceMap, Node.js harness  │
└────────────────────────────────────────────────────────────────────────┘
```

### Phase 1: Observe (`Observe-first`)
*Objective*: Inspect the running application passively without triggering anti-tampering heuristics or debugger detection loops.

1. **Launch Target Session**:
   ```javascript
   // Via call_tool
   call_tool({
     tool_name: "new_page",
     arguments: { url: "https://target-portal.internal/login" }
   });
   ```
2. **Neutralize Anti-Analysis & Fingerprinting**:
   Before scripts execute, inject stealth overrides and suppress `debugger;` loops:
   ```javascript
   call_tool({
     tool_name: "suppress_debugger_statements",
     arguments: { page_id: "PAGE_1", enable: true }
   });
   call_tool({
     tool_name: "spoof_environment",
     arguments: {
       page_id: "PAGE_1",
       presets: ["stealth_desktop_chrome"]
     }
   });
   ```
3. **Inventory Assets & Scripts**:
   ```javascript
   const scripts = call_tool({
     tool_name: "list_scripts",
     arguments: { page_id: "PAGE_1" }
   });
   ```
4. **Search for Cryptographic & Sensitive Indicators**:
   ```javascript
   call_tool({
     tool_name: "search_in_sources",
     arguments: {
       page_id: "PAGE_1",
       query: "(encrypt|signature|token|payload|privateKey)",
       is_regex: true
     }
   });
   ```

### Phase 2: Intercept (`Hook-preferred`)
*Objective*: Pinpoint the exact code path generating suspicious network traffic or processing sensitive parameters.

1. **Inspect Network Request Log**:
   ```javascript
   const reqs = call_tool({
     tool_name: "list_network_requests",
     arguments: {
       page_id: "PAGE_1",
       filter_url: "/api/v2/secure-auth"
     }
   });
   ```
2. **Trace Request Initiator (Call Stack Recovery)**:
   Instead of setting broad breakpoints, trace the request initiator back to the exact script, function, and column:
   ```javascript
   const initiator = call_tool({
     tool_name: "get_request_initiator",
     arguments: {
       page_id: "PAGE_1",
       request_id: reqs[0].request_id
     }
   });
   // Returns exact stack trace:
   // at buildSignature (auth.bundle.js:142:15)
   // at sendEncryptedPayload (auth.bundle.js:210:9)
   ```
3. **Arm Targeted XHR/Fetch Breakpoints**:
   ```javascript
   call_tool({
     tool_name: "break_on_xhr",
     arguments: {
       page_id: "PAGE_1",
       url_pattern: "/api/v2/secure-auth"
     }
   });
   ```

### Phase 3: Hook
*Objective*: Intercept critical parameters, extract intermediate cryptographic keys, and modify return values dynamically without stopping execution.

1. **Install Non-Invasive Function Hook**:
   Hook the recovered signature function to log input arguments and computed results directly:
   ```javascript
   call_tool({
     tool_name: "install_function_hook",
     arguments: {
       page_id: "PAGE_1",
       target_object: "window.AuthClient.prototype",
       method_name: "signRequest",
       hook_code: `
         const orig = window.AuthClient.prototype.signRequest;
         window.AuthClient.prototype.signRequest = function(...args) {
           console.log('[*] signRequest called with args:', JSON.stringify(args));
           const result = orig.apply(this, args);
           console.log('[*] signRequest returned:', result);
           return result;
         };
       `
     }
   });
   ```
2. **Dynamic Argument & State Evaluation**:
   If paused on a breakpoint, query the local activation frame:
   ```javascript
   const frame = call_tool({
     tool_name: "get_paused_info",
     arguments: { page_id: "PAGE_1" }
   });
   const secretKey = call_tool({
     tool_name: "evaluate_script",
     arguments: {
       page_id: "PAGE_1",
       call_frame_id: frame.top_frame_id,
       expression: "localKeyBuffer.toString('hex')"
     }
   });
   ```

### Phase 4: Trace
*Objective*: Deconstruct complex state machines, virtualized bytecode dispatchers, and JIT-optimized functions.

1. **JSVMP Opcode & Bytecode Tracing**:
   When encountering a virtualized dispatcher loop (`while(vpc < len) switch(...)`), attach an opcode execution recorder:
   ```javascript
   call_tool({
     tool_name: "install_function_hook",
     arguments: {
       page_id: "PAGE_1",
       target_object: "window.__vmInterpreter",
       method_name: "step",
       hook_code: `
         window.__vm_traces = window.__vm_traces || [];
         const origStep = window.__vmInterpreter.step;
         window.__vmInterpreter.step = function(op, pc, stack) {
           window.__vm_traces.push({
             pc: pc,
             opcode: op,
             operand: stack[stack.length - 1]
           });
           return origStep.apply(this, arguments);
         };
       `
     }
   });
   ```
2. **Dump Captured Instruction Stream**:
   ```javascript
   const traces = call_tool({
     tool_name: "evaluate_script",
     arguments: {
       page_id: "PAGE_1",
       expression: "JSON.stringify(window.__vm_traces.slice(0, 500))"
     }
   });
   ```
3. **TurboFan Compilation & Deoptimization Auditing**:
   For performance-critical cryptographic routines, inspect TurboFan compilation tiers:
   ```javascript
   call_tool({
     tool_name: "turbofan-graph",
     arguments: {
       page_id: "PAGE_1",
       function_name: "decryptStreamBlock"
     }
   });
   ```

### Phase 5: Rebuild (`Rebuild-oriented`)
*Objective*: Transform analyzed code into clean, human-readable, standalone algorithms executable locally in Node.js or Python.

1. **Automated AST Deobfuscation**:
   Run the raw script through specialized deobfuscation passes:
   ```javascript
   // Unpack string arrays and inline rotation helpers
   const cleanCode = call_tool({
     tool_name: "unpack_string_array",
     arguments: {
       source_code: rawObfuscatedSource,
       sandbox_timeout_ms: 2000
     }
   });

   // Unflatten control-flow state machines
   const structuredCode = call_tool({
     tool_name: "control_flow_unflatten",
     arguments: {
       source_code: cleanCode
     }
   });

   // Fold static constants
   const finalSource = call_tool({
     tool_name: "constant_folding",
     arguments: {
       source_code: structuredCode
     }
   });
   ```
2. **JSVMP Devirtualization**:
   Pass the recorded bytecode and instruction traces to `VMDeobfuscator` to synthesize clean JavaScript AST:
   ```javascript
   const devirtualizedSource = call_tool({
     tool_name: "VMDeobfuscator",
     arguments: {
       bytecode: rawBytecodeBuffer,
       opcode_trace: traces,
       target_runtime: "es2022"
     }
   });
   ```
3. **Local Simulation Harness**:
   Export recovered cryptographic routines into a standalone Node.js script. Mock required browser globals (`window`, `navigator`, `crypto.subtle`) to ensure reproducible execution without an active browser.

---

## 6. Boundaries & Operational Rules

Adhere strictly to the operational hierarchy when executing reverse engineering tasks:

### Operational Hierarchy
```text
Observe-first ──► Hook-preferred ──► Breakpoint-last ──► Rebuild-oriented
```
1. **Observe-first**: Always inspect network requests, loaded scripts, and DOM state passively before injecting code or setting traps. Premature intervention triggers anti-bot and anti-debugging countermeasures.
2. **Hook-preferred**: Favor non-invasive function monkey-patching and wrapper hooks over execution-halting breakpoints. Hooks allow the application to maintain its natural timing and complete asynchronous workflows.
3. **Breakpoint-last**: Use breakpoints (`break_on_xhr`, `set_breakpoint_on_text`) only when an exact call stack or volatile scope object cannot be captured via hooks. Always resume execution promptly to avoid timing out background workers or WebSocket heartbeats.
4. **Rebuild-oriented**: Reverse engineering is not complete until the recovered logic is synthesized into a clean, standalone, testable implementation (AST deobfuscated or local harness).

### Critical Operational Constraints
- **Strict Parameter Discovery**: NEVER guess tool parameters or pass fabricated arguments. When using `MCP_TOOL_PROFILE=search`, ALWAYS execute `describe_tool({ tool_name: "..." })` to obtain the verified JSON schema prior to invocation.
- **Process Isolation**: Treat all untrusted target scripts as potentially hostile. When executing string array un-packing routines, enforce execution timeouts and isolated sandboxing (`sandbox_timeout_ms`).
- **Clean Disconnect**: Always terminate detached pages and release CDP sessions upon task completion to prevent memory exhaustion in the shared Chromium instance.
