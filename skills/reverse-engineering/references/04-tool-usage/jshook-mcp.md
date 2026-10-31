# jshook MCP (`@jshookmcp/jshook`): Browser and JavaScript Reverse Engineering

- **Domain**: Client-side JavaScript reversing through an MCP server: Chromium/Camoufox automation over CDP, script collection and search, network and WebSocket capture, runtime hooks, breakpoints, anti-debug bypass, AST deobfuscation (webcrack, string arrays, control-flow flattening, JSVMP), source maps, WASM, and V8 heap inspection.
- **Package**: `@jshookmcp/jshook` 0.4.3 (npm), repo `vmoranv/jshookmcp`, AGPL-3.0. 735 tools in 36 domains per the package's registry snapshot.
- **Verified**: package metadata with `npm view`; tool names, descriptions, and input schemas by starting the server locally (stdio) and calling `tools/list` under the `search`, `workflow`, and `full` profiles. Tool behavior against live pages was not exercised. Names change between releases: confirm with `search_tools` / `describe_tool` before calling.
- **Related**: static bundle work without a browser is in [../01-static-architectures/browser-js-wasm.md](../01-static-architectures/browser-js-wasm.md) and [../01-static-architectures/browser-extensions.md](../01-static-architectures/browser-extensions.md). Node/Electron static reconstruction is also available through REA ([ghidra.md](ghidra.md) section 7).

---

## 1. When to use it

Static first: download the bundle, run `webcrack`/Babel offline, read source maps. Use jshook when the answer needs the running page:

- A request signature, token, or encrypted body is built at runtime.
- Code arrives dynamically (`eval`, `new Function`, lazy chunks, WASM instantiate).
- The page fights inspection (`debugger;` loops, timing checks, devtools detection).
- Values exist only in memory (decrypted config, keys inside closures).
- A JSVMP interpreter needs its opcode handlers traced.

---

## 2. Install and transports

stdio (one server process per MCP host):

```json
{
  "mcpServers": {
    "jshook": {
      "command": "npx",
      "args": ["-y", "@jshookmcp/jshook@0.4.3"],
      "env": {
        "MCP_TOOL_PROFILE": "search",
        "npm_config_omit": "optional"
      }
    }
  }
}
```

`npm_config_omit=optional` skips the ONNX, Z3, Binaryen, Camoufox, and Playwright extras. Remove it when you need Camoufox, symbolic execution, or `wasm-opt`.

Shared Streamable HTTP daemon (one browser and cache for several agents):

```bash
MCP_TRANSPORT=http MCP_HOST=127.0.0.1 MCP_PORT=3000 MCP_TOOL_PROFILE=search \
  npx -y @jshookmcp/jshook@0.4.3
# clients connect to http://127.0.0.1:3000/mcp
```

| Variable | Default | Effect |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HOST` / `MCP_PORT` | `127.0.0.1` / `3000` | HTTP bind |
| `MCP_AUTH_TOKEN` | unset | Required before binding beyond loopback |
| `MCP_TOOL_PROFILE` | see below | `search`, `workflow`, or `full` |
| `SEARCH_VECTOR_ENABLED` | `true` | `false` keeps tool search lexical (no embedding model) |

Profiles (counts measured with `tools/list` on 0.4.3):

| Profile | Tools exposed at start | Use |
|---|---|---|
| `search` | 8 meta tools | Default for agents. Discover and activate on demand |
| `workflow` | ~360 | Long sessions chaining browser, debugger, network, and deobfuscation tools |
| `full` | ~720 | Only for clients that handle very large tool lists |

---

## 3. Meta tools (search profile)

| Tool | Arguments | Behavior |
|---|---|---|
| `search_tools` | `query`, `top_k` (≤30), `auto_activate` (default `true`) | BM25 + vector search over all tools. Found tools are activated and become directly callable |
| `route_tool` | `task`, `context` | Natural-language task → recommended tools and next steps |
| `describe_tool` | `name` | Full JSON Schema of one tool |
| `activate_tools` | `names`, `precheck` | Register exact tools. `precheck` reports LRU evictions without changing anything |
| `activate_domain` | `domain`, `ttlMinutes`, `precheck` | Register a whole domain (for example `debugger`, `network`, `wasm`) |
| `deactivate_tools` | `names` | Free context |
| `call_tool` | `name`, `args` | Run an already active tool when the client did not refresh its tool list. Does not activate |
| `coverage_report` | none | Which tools were called and which remain |

Loop: `search_tools` with 2–5 keywords → `describe_tool` → call the tool directly (or through `call_tool`). Never guess argument names; schemas below were current for 0.4.3 only.

---

## 4. Verified tool map

| Task | Tools (key arguments) |
|---|---|
| Browser | `browser_launch` (`driver: chrome\|camoufox`, `headless`, `mode: launch\|connect`, `browserURL`, `proxy`, `userDataDir`, `sslKeyLogFile`), `browser_attach` (`browserURL`, `wsEndpoint`), `browser_list_tabs`, `browser_select_tab`, `browser_close` |
| Navigation | `page_navigate` (`url`, `waitUntil: load\|domcontentloaded\|networkidle\|commit`, `enableNetworkMonitoring`), `page_evaluate` (`code`), `page_inject_script` (`script`, runs on every load), `page_screenshot` |
| Scripts | `get_all_scripts` (`includeSource`), `get_script_source` (`scriptId` or `url`, `startLine`, `endLine`), `collect_code` (`url`, `smartMode: summary\|priority\|incremental\|full`), `search_in_scripts` (`keyword`, `isRegex`, `contextLines`, `maxMatches`) |
| Network | `network_enable`, `network_get_requests` (`url`, `urlRegex`, `method`, `tail`, `limit`), `network_get_response_body` (`requestId`), `network_export_har` (`outputPath`, `includeBodies`), `network_replay_request`, `console_inject_fetch_interceptor`, `console_inject_xhr_interceptor` |
| Streams | `ws_monitor` (`action: enable\|disable`, `urlFilter`), `ws_get_frames` (`direction`, `payloadFilter`), `sse_monitor_enable`, `grpc_monitor`, `webrtc_monitor` |
| Proxy / TLS | `proxy_start` (`port`, `useHttps`, `capture`; auto-generates a CA), `proxy_get_requests`, `tls_keylog_enable` |
| Debugger | `debugger_lifecycle` (`action: enable\|disable`), `breakpoint` (`action: set\|remove\|list`, `type: code\|function\|xhr\|event\|event_category\|exception`), `debugger_wait_for_paused` (`timeout`), `debugger_get_paused_state`, `get_call_stack`, `debugger_evaluate` (`context: frame\|global`, `expression`, `callFrameId`), `get_scope_variables_enhanced`, `debugger_step`, `debugger_resume`, `blackbox_add_common` |
| Hooks | `hook_preset` (`preset`/`presets`, `captureStack`, `method: evaluate\|evaluateOnNewDocument`, `listPresets`), `manage_hooks` (`action: create\|list\|records\|clear`, `type: function\|xhr\|fetch\|websocket\|localstorage\|cookie`, `hookAction: log\|block\|modify`), `ai_hook` (`action: inject\|get_data\|list\|clear\|toggle\|export`) |
| Anti-debug / stealth | `antidebug_detect_protections`, `antidebug_bypass` (`types: all\|debugger_statement\|timing\|stack_trace\|console_detect`, `persistent`, `mode: remove\|noop`), `stealth_inject`, `stealth_verify` |
| Deobfuscation | `deobfuscate` (`code`, `engine: auto\|webcrack\|jscrambler\|packer\|vm`, `unpack`, `unminify`, `outputDir`), `js_deobfuscate_pipeline` (`code`, `aggressive`), `analysis_decode_string_array`, `analysis_deflat_control_flow`, `detect_obfuscation`, `detect_crypto`, `webcrack_unpack`, `understand_code` |
| JSVMP | `js_analyze_vm` (`code`, `extractBytecode`, `mapOpcodes`), `js_deobfuscate_jsvmp` (`code`, `extractInstructions`), `js_symbolic_execute_jsvmp` |
| Source maps | `sourcemap_discover`, `sourcemap_fetch_and_parse`, `sourcemap_reconstruct_tree` (`sourceMapUrl`, `outputDir`, `inferMissing`) |
| WASM | `wasm_dump` (`moduleIndex`, `outputPath`), `wasm_disassemble` / `wasm_decompile` (`inputPath`, `outputPath`), `wasm_string_extract`, `wasm_instrument_trace` |
| V8 / heap | `v8_heap_snapshot_capture`, `v8_heap_snapshot_analyze`, `js_heap_search` (`pattern`), `v8_bytecode_extract`, `v8_turbofan_graph`, `v8_deopt_trace` |

`hook_preset` presets in 0.4.3: `eval`, `function-constructor`, `atob-btoa`, `crypto-subtle`, `json-stringify`, `object-defineproperty`, `settimeout`, `setinterval`, `addeventlistener`, `postmessage`, `webassembly`, `proxy`, `reflect`, `history-pushstate`, `location-href`, `navigator-useragent`, `eventsource`, `window-open`, `mutationobserver`, `formdata`, plus composite `anti-debug-bypass`, `crypto-key-capture`, `webassembly-full`.

Other domains exist (Frida bridge, ADB, native emulator `nemu_*`, process memory, syscall hooks). They overlap with dedicated tools in this skill; prefer [frida.md](frida.md) and the native workflows for those targets.

---

## 5. Workflow: request signature recovery

Calls below are MCP tool invocations written as `tool {json args}`. They are not JavaScript.

```text
# 0. Discover and activate
search_tools {"query": "browser launch navigate"}
search_tools {"query": "xhr breakpoint call stack"}

# 1. Observe passively
browser_launch {"driver": "chrome", "headless": true}
page_navigate {"url": "https://target.example/login", "waitUntil": "networkidle", "enableNetworkMonitoring": true}
network_get_requests {"urlRegex": "/api/.*/auth", "tail": 20}
network_get_response_body {"requestId": "<id from previous result>"}
get_all_scripts {"includeSource": false}
search_in_scripts {"keyword": "sign|hmac|nonce|x-signature", "isRegex": true, "contextLines": 3, "maxMatches": 20}

# 2. Defuse anti-debug before breaking
antidebug_detect_protections {}
antidebug_bypass {"types": ["debugger_statement", "timing"], "persistent": true}

# 3. Break where the request is sent and read the stack
debugger_lifecycle {"action": "enable"}
blackbox_add_common {}
breakpoint {"action": "set", "type": "xhr", "urlPattern": "/api/v2/auth"}
page_evaluate {"code": "document.querySelector('form').requestSubmit()"}
debugger_wait_for_paused {"timeout": 15000}
get_call_stack {}
debugger_evaluate {"context": "frame", "callFrameId": "<frame id of the signer>", "expression": "JSON.stringify(arguments)"}
debugger_resume {}

# 4. Replace the breakpoint with a hook and collect many samples
manage_hooks {"action": "create", "type": "function", "target": "window.AuthClient.prototype.sign", "hookAction": "log"}
manage_hooks {"action": "records"}
```

Then pull the signer source with `get_script_source` (narrow `startLine`/`endLine`), deobfuscate it (section 7), and reimplement it in a standalone script. Compare your output against captured requests byte for byte.

---

## 6. Workflow: dynamic code and crypto capture

```text
hook_preset {"presets": ["eval", "function-constructor", "atob-btoa", "crypto-subtle"], "captureStack": true, "method": "evaluateOnNewDocument"}
hook_preset {"preset": "crypto-key-capture", "method": "evaluateOnNewDocument"}   # forces extractable:true on importKey
page_navigate {"url": "https://target.example/", "waitUntil": "networkidle"}
console_get_logs {"limit": 200}
js_heap_search {"pattern": "BEGIN PUBLIC KEY|eyJhbGci"}
```

`evaluateOnNewDocument` installs hooks before page scripts run. `evaluate` only affects code that runs after injection.

WebSocket protocols:

```text
ws_monitor {"action": "enable", "urlFilter": "wss://"}
ws_get_frames {"direction": "sent", "limit": 50}
```

WASM cores:

```text
hook_preset {"preset": "webassembly-full", "method": "evaluateOnNewDocument"}
page_navigate {"url": "https://target.example/app", "waitUntil": "networkidle"}
wasm_dump {"moduleIndex": 0, "outputPath": "/abs/work/mod0.wasm"}
wasm_decompile {"inputPath": "/abs/work/mod0.wasm", "outputPath": "/abs/work/mod0.dcmp"}
```

Analyze the dumped `.wasm` offline afterward (`wasm2wat`, `wasm-decompile`, Ghidra with a WASM loader).

---

## 7. Workflow: deobfuscation and JSVMP

```text
detect_obfuscation {"code": "<source>", "generateReport": true}
deobfuscate {"code": "<source>", "engine": "auto", "unpack": true, "unminify": true, "outputDir": "/abs/work/deob"}
analysis_decode_string_array {"code": "<source>", "removeRotation": true}
analysis_deflat_control_flow {"code": "<source>", "removeDispatcher": true}
js_analyze_vm {"code": "<vm source>", "extractBytecode": true, "mapOpcodes": true}
js_deobfuscate_jsvmp {"code": "<vm source>", "extractInstructions": true}
sourcemap_discover {"includeInline": true}
sourcemap_reconstruct_tree {"sourceMapUrl": "<map url>", "outputDir": "/abs/work/src", "inferMissing": true}
```

Pass large sources by file where a tool accepts `outputDir`/`inputPath`. Pasting a 2 MB bundle into `code` costs the whole context. Prefer running `webcrack` locally on the saved bundle and sending only the hot function to jshook.

For JSVMP, the reliable path is trace first, lift second: hook the dispatcher's handler call (`manage_hooks` with `customCode`, or `ai_hook` `inject`) to log `(pc, opcode, stack top)`, collect a trace for one known input, map opcodes to semantics, then use `js_analyze_vm`/`js_deobfuscate_jsvmp` output as a starting point. Validate any lifted code by replaying the same input and comparing results.

---

## 8. Rules and pitfalls

- **Observe → hook → break → rebuild.** Passive capture first. Hooks keep timing intact. Breakpoints last; resume quickly or heartbeats and workers time out.
- **Schema drift.** Tool names and arguments here match 0.4.3. Call `describe_tool` once per tool per session. Pin the version in the MCP config.
- **`call_tool` does not activate.** Activate with `search_tools` (auto) or `activate_tools` first.
- **Hook timing.** Use `method: "evaluateOnNewDocument"` for anything that must run before page code.
- **Anti-debug side effects.** `antidebug_bypass` patches page globals; some sites detect the patch. Verify with `stealth_verify` and compare behavior with and without it.
- **Isolation.** Treat target pages as hostile. Run the browser in a disposable profile (`userDataDir` under the work dir) and, for malicious pages, inside a VM ([utm-hypervisor.md](utm-hypervisor.md)).
- **HTTP daemon exposure.** Keep `MCP_HOST=127.0.0.1`. Set `MCP_AUTH_TOKEN` before any other bind. The server can drive a browser and read memory.
- **Clean up.** `browser_close` at the end. Export evidence (`network_export_har`, hook records) to files before closing.

---

## 9. Verification checklist

- `search_tools` returns the tool you plan to call, and `describe_tool` shows the arguments you pass.
- Captured request count and bodies match what the page sent (`network_export_har` diff against a mitmproxy capture if needed).
- Reimplemented signer reproduces at least three captured signatures from their inputs.
- Hook records show `captureStack` frames pointing into the script and line you reversed.
