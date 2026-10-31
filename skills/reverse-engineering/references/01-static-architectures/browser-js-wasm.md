# Browser JavaScript & WebAssembly Reverse Engineering

## 1. Title & Overview
- **Domain**: Client-side web applications, Electron desktop frameworks, Node.js packages, browser extensions, and WebAssembly (WASM) modules.
- **Scope**: Reversing bundled and minified JavaScript (Webpack, Vite, Rollup, Turbopack), unpacking Electron ASAR archives, professional Abstract Syntax Tree (AST) deobfuscation pipelines using Babel (string array un-packing, rotation decoding, proxy function inlining, constant folding, dead-code pruning, property accessor normalization, control-flow unflattening), JavaScript Virtual Machine Protection (JSVMP) devirtualization (bytecode extraction, interpreter reversing, dynamic CDP tracing, AST synthesis), and analyzing WebAssembly binaries (`.wasm`) using WABT, Ghidra, and linear memory reconstruction.

---

## 2. Trigger Conditions & Detection Indicators
Engage this reference when analyzing client-side JavaScript, obfuscated web scripts, or WebAssembly targets:

### Binary & Artifact Signatures
- **JavaScript Bundles & Minified Code**:
  - Files named `*.bundle.js`, `chunk-*.js`, `app.*.js`, `vendor.*.js`.
  - Minified single-line files, short identifier mangling (`a`, `b`, `c`), Webpack bootstrap headers: `webpackJsonp`, `__webpack_require__`, `self["webpackChunk..."]`.
  - Vite / Rollup runtime headers: `import.meta.glob`, `__vite_ssr_import__`.
- **Obfuscator.io / JavaScript-Obfuscator Signatures**:
  - Global string array declaration with hex identifiers: `var _0x5a1b = ['string1', 'string2', ...];`.
  - Self-invoking shift/rotation routine containing a `while (--_0xcount)` or `parseInt` arithmetic validation loop:
    ```javascript
    (function(_0xarr, _0xnum) {
        var _0xshift = function(_0xcount) {
            while (--_0xcount) { _0xarr['push'](_0xarr['shift']()); }
        };
        _0xshift(++_0xnum);
    })(_0x5a1b, 0x1f4);
    ```
  - Decryption helper function retrieving items by index offset: `function _0x4f2a(_0xidx) { return _0x5a1b[_0xidx - 0x0]; }`.
  - Bracket notation accessors across standard APIs: `window['document']['location']['href']`, `console['log']`.
  - Proxy wrapper functions returning binary operations: `function _0x1a2b(a, b) { return a + b; }`.
  - Control-flow flattening (CFF): `while (true) switch (_0xorder[_0xidx++]) { ... }`.
- **JSVMP (JavaScript Virtual Machine Protection) Signatures**:
  - Compact custom bytecode stream stored as a long base64 string, hex array, or binary typed array (`Uint8Array`).
  - Virtual program counter (`vpc`), virtual stack pointer (`vsp`), and execution stack array (`stack = []`).
  - Central virtual opcode dispatch loop executing a `while (vpc < bytecode.length)` with a giant `switch (opcode)` or jump table:
    ```javascript
    while (true) {
        switch (bytecode[vpc++]) {
            case 0x01: stack.push(bytecode[vpc++]); break; // PUSH_CONST
            case 0x02: stack.push(stack.pop() + stack.pop()); break; // ADD
            case 0x03: env[bytecode[vpc++]] = stack.pop(); break; // STORE_VAR
            case 0x04: stack.push(env[bytecode[vpc++]]); break; // LOAD_VAR
            case 0x05: var fn = stack.pop(); fn.apply(null, stack.pop()); break; // CALL
            case 0x00: return stack.pop(); // RET
        }
    }
    ```
- **Electron Application Archives**:
  - File: `app.asar` located in `<App>/resources/app.asar` or `<App>.app/Contents/Resources/app.asar`.
  - Header: 4-byte size followed by JSON header describing virtual file system directory tree.
- **WebAssembly Binaries**:
  - File extension: `.wasm`.
  - Magic bytes (first 4 bytes): `\x00asm` (`0x6D736100` in little-endian, bytes `00 61 73 6D`).
  - Version: `0x00000001` (`01 00 00 00`).

---

## 3. Tooling & CLI/MCP Actions

### AST Deobfuscation Ecosystem
- **Babel Toolchain**:
  - `@babel/parser`: Parses JavaScript source code into ESTree / Babel AST.
  - `@babel/traverse`: Traverses and modifies AST nodes, manages scope bindings and path replacements.
  - `@babel/generator`: Serializes transformed AST back into formatted JavaScript.
  - `@babel/types`: Utility functions for building, validating, and testing AST node types.
  ```bash
  npm install --save-dev @babel/parser @babel/traverse @babel/generator @babel/types
  ```
- **Specialized Automated Deobfuscators**:
  - `webcrack`: Deobfuscates Obfuscator.io, unbundles Webpack chunks into original directory structures, un-proxies function calls.
    ```bash
    npx webcrack bundle.js -o ./deobfuscated_src
    ```
  - `wakaru`: Modern unbundler and decompiler; recovers TypeScript modules, inlines helper functions, un-minifies mangled variables.
    ```bash
    npx @wakaru/cli unminify target.min.js -o ./output
    ```
  - `synchrony`: AST deobfuscator specifically tuned for Obfuscator.io variants, unflattening control flow and decoding encrypted strings.
    ```bash
    npx synchrony deobfuscate obfuscated.js
    ```
  - `deobfuscator.io`: Web-based and CLI AST cleaner for common commercial obfuscation patterns.

### Dynamic Tracing & JSVMP Instrumentation
- **JSHook MCP (`@jshookmcp/jshook`)**: Primary automated dynamic RE suite for CDP debugging, runtime hooking, JSVMP opcode tracing, and AST devirtualization. Exposes 600+ tools under token-efficient discovery (`MCP_TOOL_PROFILE=search`). Detailed tool usage, 5-phase workflows, and boundaries are documented in [04-tool-usage/jshook-mcp.md](../04-tool-usage/jshook-mcp.md).
- **Chrome DevTools Protocol (CDP)**: Intercepts service workers, evaluates runtime expressions, sets breakpoints on opcode dispatchers.
- **Playwright / Puppeteer**: Automated browser environment to load obfuscated targets, hook global functions, and stream instruction traces.
- **Dynamic Hooking**:
  ```bash
  # Run target in headless browser with remote debugging enabled
  google-chrome --headless=new --remote-debugging-port=9222 target.html
  ```
### Binary Extraction & WebAssembly Tools
- **Electron ASAR Unpacker**:
  ```bash
  npx asar extract app.asar ./unpacked_app
  npx asar list app.asar
  ```
- **Source Map Recovery**:
  ```bash
  npx restore-source-tree -o ./restored_src target.bundle.js.map
  ```
- **WebAssembly Tools (WABT Suite)**:
  - `wasm2wat`: Translates binary `.wasm` into WebAssembly Text format (`.wat`).
    ```bash
    wasm2wat module.wasm -o module.wat
    ```
  - `wasm-decompile`: Produces high-level C-like pseudocode from WASM bytecode.
    ```bash
    wasm-decompile module.wasm -o module.dcmp
    ```
  - `wasm-objdump`: Inspects sections, imports, exports, and linear memory segments.
    ```bash
    wasm-objdump -x module.wasm
    ```

---

## 4. Core Methodologies & Step-by-Step Technical Workflow

### 4.1 Bundle De-Minification & Module Isolation (Webpack, Vite, Rollup)
Modern frontend applications pack hundreds of modules into single minified files.

#### Webpack Module Layout:
```javascript
(self["webpackChunkapp"] = self["webpackChunkapp"] || []).push([["main"], {
    1042: (module, exports, __webpack_require__) => {
        const api = __webpack_require__(502);
        exports.login = function(user, pass) { ... };
    },
    502: (module, exports) => {
        exports.endpoint = "https://api.target.com/v1";
    }
}]);
```

#### Reversing Workflow:
1. **Source Map Check**: Look at the final line of `.js` files for `//# sourceMappingURL=...`. If an inline base64 source map or external `.map` file exists, decode it using `restore-source-tree` to immediately recover original TypeScript/JavaScript source files, folder hierarchies, and variable names.
2. **Automated Unbundling**: Run `webcrack bundle.js -o ./src`. This identifies module boundaries and writes each module to a separate file matching its imported name or numeric ID.

---

### 4.2 Professional JavaScript AST Deobfuscation Pipeline
Commercial obfuscators (such as JavaScript-Obfuscator / Obfuscator.io) generate multi-layered defenses. Manual renaming is impossible at scale; reversing requires multi-pass AST transformations via `@babel/parser`, `@babel/traverse`, and `@babel/generator`.

```text
┌────────────────────────────────────────────────────────┐
│               Raw Obfuscated JavaScript                │
└───────────────────────────┬────────────────────────────┘
                            │ @babel/parser
                            ▼
┌────────────────────────────────────────────────────────┐
│                      Babel AST                         │
└───────────────────────────┬────────────────────────────┘
                            │ Pass 1
                            ▼
┌────────────────────────────────────────────────────────┐
│      String Array Unpacking & Rotation Decoding        │
│  - Extract Array + Shift IIFE + Decryptor Routine      │
│  - Run shift in isolated Node.js vm.createContext      │
│  - Replace _0x4f2a(0x1a) call sites with StringLiteral │
│  - Remove array, shift, and decryptor AST nodes        │
└───────────────────────────┬────────────────────────────┘
                            │ Pass 2
                            ▼
┌────────────────────────────────────────────────────────┐
│               Proxy Function Inlining                  │
│  - Identify single-operator / single-call wrappers     │
│  - Inline expressions at CallExpression sites          │
│  - Remove proxy function declarations                  │
└───────────────────────────┬────────────────────────────┘
                            │ Pass 3
                            ▼
┌────────────────────────────────────────────────────────┐
│         Dead-Code Pruning & Constant Folding           │
│  - path.evaluate() on Binary/Unary expressions         │
│  - Prune dead IfStatement branches (if (false) ...)    │
│  - Prune dead ternary ConditionalExpressions           │
└───────────────────────────┬────────────────────────────┘
                            │ Pass 4
                            ▼
┌────────────────────────────────────────────────────────┐
│            Property Accessor Normalization             │
│  - window['document']['location'] -> window.document   │
│  - Verify property string is a valid JS identifier     │
└───────────────────────────┬────────────────────────────┘
                            │ Pass 5
                            ▼
┌────────────────────────────────────────────────────────┐
│            Control-Flow Unflattening (CFF)             │
│  - Parse while (true) switch (state) dispatchers       │
│  - Extract execution order array ('3|1|0|2'.split('|'))│
│  - Reorder basic blocks into linear sequential code    │
└───────────────────────────┬────────────────────────────┘
                            │ @babel/generator
                            ▼
┌────────────────────────────────────────────────────────┐
│              Clean Deobfuscated JavaScript             │
└────────────────────────────────────────────────────────┘
```

#### Step-by-Step AST Engineering Details:

1. **String Array Un-packing & Rotation Decoding**:
   - **Structure**: Obfuscator.io splits string storage into three top-level AST nodes:
     1. `VariableDeclaration`: Global array containing strings (often encoded or scrambled).
     2. `ExpressionStatement`: An IIFE that shifts array elements (`push(shift())`) in a loop until a numeric checksum matches.
     3. `FunctionDeclaration` / `VariableDeclaration`: The accessor/decryptor function taking an index argument, adjusting for offset, and returning the string.
   - **Static Extraction**: Extract the code of these three nodes from the AST. Execute them inside a secure Node.js `vm.createContext({})` sandbox to compute the post-rotation state of the helper function.
   - **Call Site Inlining**: Traverse the AST for `CallExpression` nodes where `path.node.callee` matches the helper function name. Extract numeric literal arguments, invoke the sandbox helper function, and replace the `CallExpression` with `t.stringLiteral(result)`.
   - **Pruning**: Delete the initial three AST nodes from `ast.program.body`.

2. **Proxy Function Inlining**:
   - Obfuscators wrap simple operations in proxy functions to defeat signature scanners:
     ```javascript
     function _0x1a2b(a, b) { return a + b; }
     function _0x3c4d(a, b) { return a === b; }
     function _0x5e6f(fn, a, b) { return fn(a, b); }
     ```
   - **Detection**: In `FunctionDeclaration`, inspect `body.body`. If length is 1 and statement is a `ReturnStatement` wrapping a `BinaryExpression` or `CallExpression` referencing the function's own parameters, register the proxy.
   - **Replacement**: Find all call sites referencing the proxy identifier. Replace `_0x1a2b(x, y)` directly with `t.binaryExpression('+', x, y)`. Remove the proxy function declaration.

3. **Dead-Code Pruning & Constant Folding**:
   - Constant expressions: Use Babel's built-in `path.evaluate()`. If `path.evaluate().confident === true`, replace the node with `t.valueToNode(result)`. This converts `"a" + "b"` into `"ab"` and `0x10 ^ 0x15` into `5`.
   - Dead branches: In `IfStatement`, evaluate `path.get('test')`. If confident and truthy, replace the `IfStatement` with its `consequent`. If confident and falsy, replace with `alternate` (or remove if no alternate exists).

4. **Property Accessor Normalization**:
   - Obfuscated code converts clean property access into computed string access: `window['document']['location']['href']`.
   - Traverse `MemberExpression` nodes. If `path.node.computed === true` and `path.node.property` is a `StringLiteral`:
     - Test if the string is a valid JavaScript identifier using `/^[a-zA-Z_$][a-zA-Z0-9_$]*$/` and is not a reserved JavaScript keyword.
     - Set `path.node.computed = false` and replace `path.node.property` with `t.identifier(value)`.
     - Result: `window.document.location.href`.

5. **Control-Flow Unflattening (CFF)**:
   - **Dispatcher Structure**: Linear code is chopped into basic blocks stored as cases in a `switch` statement enclosed in an infinite `while (true)` loop:
     ```javascript
     var _0xorder = '2|0|3|1'.split('|'), _0xidx = 0;
     while (true) {
         switch (_0xorder[_0xidx++]) {
             case '0': stepOne(); continue;
             case '1': stepThree(); break;
             case '2': stepZero(); continue;
             case '3': stepTwo(); continue;
         }
         break;
     }
     ```
   - **Workflow**:
     1. Traverse `WhileStatement` nodes where the test condition is `true` or `1`.
     2. Identify the inner `SwitchStatement`.
     3. Locate the state variable and preceding sequence definition (`'2|0|3|1'.split('|')`).
     4. Build a hash map of `case` values to basic block statements (omitting the trailing `continue` or `break`).
     5. Iterate over the parsed order array `['2', '0', '3', '1']`, collect the matching statements in execution sequence, and replace the entire `WhileStatement` with the restored linear sequence.
     6. Delete the order array declaration and index variable.

---

### 4.3 JSVMP (JavaScript Virtual Machine Protection) Devirtualization
JSVMP represents the highest tier of commercial JavaScript protection. Instead of altering JavaScript AST, JSVMP compiles original JavaScript into a proprietary bytecode format executed by an embedded interpreter in the browser.

#### Architectural Breakdown of JSVMP:
```text
┌────────────────────────────────────────────────────────┐
│                   JSVMP Architecture                   │
│                                                        │
│  Bytecode Stream: [0x12, 0x00, 0x04, 0x3A, 0x9F, ...]  │
│  Virtual Registers / State: vpc (PC), vsp (Stack Top)  │
│  Execution Stack: Array serving as LIFO operand stack  │
│  Scope / Context Table: Local variables and globals    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│                 Interpreter Loop                       │
│                                                        │
│  while (vpc < bytecode.length) {                       │
│      const op = bytecode[vpc++];                       │
│      switch (op) {                                     │
│          case 0x10: // PUSH_IMM                        │
│          case 0x11: // BIN_OP                          │
│          case 0x12: // LOAD_PROP                       │
│          case 0x13: // CALL_FUNC                       │
│          case 0x14: // JUMP_IF                         │
│      }                                                 │
│  }                                                     │
└────────────────────────────────────────────────────────┘
```

#### Step-by-Step Devirtualization Workflow:

#### Step 1: Static Analysis of the Interpreter Loop
1. Locate the entry point: Search for large arrays of numbers, base64 strings, or `Uint8Array` allocations, followed by an immediate call into a closure containing a `while` loop and large `switch`.
2. Map the Virtual Opcode Table:
   - Identify stack manipulation: `stack.push()`, `stack.pop()`.
   - Identify environment manipulation: lookups against an environment object (`env[key]`).
   - Identify JavaScript API reflection: `object[property]`, `func.apply(context, args)`.
   - Classify opcodes:
     - **Stack**: `PUSH`, `POP`, `DUP`.
     - **Arithmetic/Bitwise**: `ADD`, `SUB`, `MUL`, `DIV`, `XOR`, `AND`, `OR`.
     - **Object**: `GET_PROP`, `SET_PROP`.
     - **Control Flow**: `JMP`, `JZ` (jump if zero), `JNZ`, `RET`.
     - **Execution**: `CALL`, `NEW`.

#### Step 2: Dynamic Trace-Based Analysis & JSHook MCP Integration
Pure static analysis of JSVMP can be hindered by encrypted bytecode streams decrypted at runtime. Use dynamic tracing via Chrome DevTools Protocol (CDP), Playwright, or **JSHook MCP** (`@jshookmcp/jshook`) to instrument the dispatcher.

1. **Automated Tracing via JSHook MCP**:
   Leverage JSHook MCP's `install_function_hook` and `evaluate_script` tools (detailed in [04-tool-usage/jshook-mcp.md](../04-tool-usage/jshook-mcp.md)) to dynamically monitor virtual program counter progression and dump opcode traces:
   ```javascript
   // Discover and describe hook tool
   // call_tool({ tool_name: "describe_tool", arguments: { tool_name: "install_function_hook" } })
   call_tool({
       tool_name: "install_function_hook",
       arguments: {
           page_id: "PAGE_1",
           target_object: "window",
           method_name: "_vmp_dispatch",
           hook_code: `
               window.__vmp_trace__ = window.__vmp_trace__ || [];
               const orig = window._vmp_dispatch;
               window._vmp_dispatch = function(op, vpc, stack, env) {
                   window.__vmp_trace__.push({
                       vpc: vpc,
                       opcode: op,
                       stackTop: stack ? stack.slice(-4) : [],
                       timestamp: Date.now()
                   });
                   return orig.apply(this, arguments);
               };
           `
       }
   });
   ```
   Retrieve the complete trace using `evaluate_script` without interrupting asynchronous execution:
   ```javascript
   const traceData = call_tool({
       tool_name: "evaluate_script",
       arguments: {
           page_id: "PAGE_1",
           expression: "JSON.stringify(window.__vmp_trace__)"
       }
   });
   ```
   Feed the captured instruction stream directly into `VMDeobfuscator` (`call_tool({ tool_name: "VMDeobfuscator", arguments: { bytecode: rawBytecode, opcode_trace: traceData } })`) to recover high-level JavaScript statements.

2. **Manual Dispatcher Hooking (Playwright / CDP)**: Hook into the interpreter loop right after the opcode is read:
   ```javascript
   // Injected hook in browser / CDP session
   (function() {
       const originalSwitch = window._vmp_dispatch;
       window.vm_trace = [];
       window._vmp_dispatch = function(op, vpc, stack, env) {
           window.vm_trace.push({
               vpc: vpc,
               opcode: op,
               stackSnapshot: stack.slice(-4), // Top 4 elements
               operands: [/* read next bytecode bytes */]
           });
           return originalSwitch.apply(this, arguments);
       };
   })();
   ```
3. **Execution Tracing**: Trigger the application's target functionality (e.g., clicking a protected button, submitting an encrypted request).
4. **Trace Extraction**: Dump the recorded `vm_trace` array containing the ordered sequence of virtual instructions and runtime operand values.
#### Step 3: AST Generation from VM Trace
1. **Symbolic Stack Reconstruction**:
   - Initialize an empty symbolic stack.
   - For every trace item:
     - `PUSH_CONST(val)`: Push `t.stringLiteral(val)` or `t.numericLiteral(val)` onto the symbolic stack.
     - `BIN_OP('+')`: Pop operand `B`, pop operand `A`, push `t.binaryExpression('+', A, B)`.
     - `GET_PROP`: Pop property `P`, pop target `O`, push `t.memberExpression(O, P, true)`.
     - `CALL(argc)`: Pop `argc` arguments, pop function `F`, pop context `C`, push `t.callExpression(F, args)`.
     - `ASSIGN`: Pop value `V`, pop target `T`, generate `t.expressionStatement(t.assignmentExpression('=', T, V))`.
2. **Linear AST Synthesis**: Append generated statement nodes to a clean Babel `Program` body and serialize with `@babel/generator` to recover readable, un-virtualized JavaScript.

#### Tooling Ecosystem Matrix:
| Tool | Core Capability | Best Suited For | Limitation |
| :--- | :--- | :--- | :--- |
| **`webcrack`** | Webpack unbundling, Obfuscator.io deobfuscation | Production web bundles, single-file bundles | Does not devirtualize complex custom JSVMP |
| **`wakaru`** | TypeScript construct recovery, variable un-mangling | Clean output formatting, modern ES modules | Target must not use heavy virtualization |
| **`synchrony`** | Semantic AST deobfuscator for Obfuscator.io | Control flow unflattening, string array rotation | Tuned specifically for JS-Obfuscator rules |
| **Babel Custom Script** | Custom AST transformation rules | Proprietary obfuscation patterns, custom packers | Requires manual pattern identification |
| **JSHook MCP (`@jshookmcp/jshook`)** | Automated CDP session control, `VMDeobfuscator`, stealth hooks | JSVMP devirtualization, dynamic request initiator tracing, AST deobfuscation | Requires Node.js MCP runtime (see [04-tool-usage/jshook-mcp.md](../04-tool-usage/jshook-mcp.md)) |
| **Dynamic CDP Hook** | Opcode trace extraction | JSVMP bytecode reversing, runtime parameter dumping | Requires browser runtime environment |


---

### 4.4 WebAssembly (`.wasm`) Binary Architecture
WebAssembly is a compact binary format for stack-based virtual machines.

#### WASM Section Structure:
Each section begins with a 1-byte section ID and a LEB128-encoded byte length:
- `ID 0`: Custom Section (often contains DWARF debug info or function names: `name`)
- `ID 1`: Type Section (function signatures)
- `ID 2`: Import Section (external functions, memory, globals imported from JS)
- `ID 3`: Function Section (maps function index to type signature)
- `ID 4`: Table Section (indirect function call tables)
- `ID 5`: Memory Section (linear memory limits)
- `ID 6`: Global Section (global variables)
- `ID 7`: Export Section (functions and memory exported to JS)
- `ID 10`: Code Section (function bodies and bytecode)
- `ID 11`: Data Section (initialized memory segments, strings)

---

### 4.5 WebAssembly Linear Memory & JS Boundary
WASM operates over a contiguous byte array called **Linear Memory**, allocated in 64 KiB pages:

```text
JavaScript Environment
      │
      ▼
WebAssembly.Memory({ initial: 256 })
      │
      ├── Linear Memory [0x00000000 - 0x01000000] (16 MB)
      │    ├── .data / .rodata (Strings, constant structs)
      │    ├── Stack (grows downwards)
      │    └── Heap (managed by custom malloc/dlmalloc/walloc)
      │
      ▼
WASM Exports:
  - memory (ArrayBuffer)
  - malloc(size) -> uint32_t ptr
  - free(ptr)
  - processData(ptr, len) -> uint32_t result
```

#### Reversing the JS-WASM Boundary:
1. Identify JavaScript imports and exports:
   ```javascript
   const wasmInstance = await WebAssembly.instantiate(wasmBytes, {
       env: {
           memory: sharedMemory,
           console_log: (ptr, len) => { ... }
       }
   });
   ```
2. Trace linear memory accesses:
   - When JavaScript passes strings to WASM, it writes UTF-8 bytes into `wasmInstance.exports.memory.buffer` at an address returned by `wasmInstance.exports.malloc(len)`.
   - In WAT disassembly, linear memory loads and stores appear as `i32.load`, `i64.load8_u`, `i32.store`.
3. Recovering Function Names:
   - If the custom section `name` exists, `wasm2wat` automatically recovers function names (`$malloc`, `$crypto_hash`).
   - If stripped, check for standard C runtime function signatures (memcmp, strlen, memcpy) or standard library imports in Section 2.

---

## 5. Concrete Code & Script Examples

### Production-Grade Node.js Babel Deobfuscation Pipeline
The following script is a complete, standalone, runnable deobfuscation engine. It implements string array extraction, sandbox rotation decoding, proxy function inlining, constant folding, dead-code branch pruning, property accessor normalization, and control-flow unflattening.

```javascript
/**
 * deobfuscate_pipeline.js
 * Production-grade AST deobfuscator for Obfuscator.io / JavaScript-Obfuscator.
 * 
 * Dependencies:
 *   npm install @babel/parser @babel/traverse @babel/generator @babel/types
 * 
 * Usage:
 *   node deobfuscate_pipeline.js <input_obfuscated.js> [output_clean.js]
 */

const fs = require('fs');
const vm = require('vm');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default || require('@babel/traverse');
const generate = require('@babel/generator').default || require('@babel/generator');
const t = require('@babel/types');

function runDeobfuscation(sourceCode) {
    console.log('[*] Parsing source code into Babel AST...');
    const ast = parser.parse(sourceCode, {
        sourceType: 'unambiguous',
        plugins: ['jsx']
    });

    // =========================================================================
    // PASS 1: String Array Unpacking & Sandbox Rotation Decoding
    // =========================================================================
    console.log('[*] Pass 1: Extracting and decoding string array rotation...');
    if (ast.program.body.length >= 3) {
        // Obfuscator.io puts the array, rotation IIFE, and helper function at the top
        const candidateNodes = ast.program.body.slice(0, 3);
        const sandboxAst = t.program(candidateNodes);
        const sandboxCode = generate(sandboxAst).code;

        // Determine helper function identifier name
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
                    let inlinedCount = 0;
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
                                            inlinedCount++;
                                        } else if (typeof decrypted === 'number') {
                                            path.replaceWith(t.numericLiteral(decrypted));
                                            inlinedCount++;
                                        }
                                    } catch (e) {
                                        // Ignore evaluation faults on non-standard arguments
                                    }
                                }
                            }
                        }
                    });
                    console.log(`[+] Pass 1: Inlined ${inlinedCount} string array call sites.`);
                    // Remove the three scaffolding nodes from the program body
                    ast.program.body.splice(0, 3);
                }
            } catch (err) {
                console.warn(`[-] Pass 1: Sandbox rotation execution failed (${err.message}). Proceeding.`);
            }
        }
    }

    // =========================================================================
    // PASS 2: Proxy Function Inlining
    // =========================================================================
    console.log('[*] Pass 2: Inlining proxy operator/call wrapper functions...');
    const proxyFunctions = new Map();

    traverse(ast, {
        FunctionDeclaration(path) {
            const { id, params, body } = path.node;
            if (!id || body.body.length !== 1) return;
            const stmt = body.body[0];
            if (!t.isReturnStatement(stmt)) return;
            const arg = stmt.argument;

            // Pattern A: Binary Expression proxy -> function _0x1(a, b) { return a + b; }
            if (t.isBinaryExpression(arg) &&
                t.isIdentifier(arg.left) && t.isIdentifier(arg.right) &&
                params.length === 2 &&
                params[0].name === arg.left.name && params[1].name === arg.right.name) {
                proxyFunctions.set(id.name, {
                    kind: 'binary',
                    operator: arg.operator,
                    path
                });
            }
            // Pattern B: Call Expression proxy -> function _0x2(fn, a) { return fn(a); }
            else if (t.isCallExpression(arg) &&
                t.isIdentifier(arg.callee) &&
                params.length > 0 &&
                params[0].name === arg.callee.name) {
                proxyFunctions.set(id.name, {
                    kind: 'call',
                    path
                });
            }
        }
    });

    let proxyInlinedCount = 0;
    for (const [name, info] of proxyFunctions.entries()) {
        traverse(ast, {
            CallExpression(path) {
                if (t.isIdentifier(path.node.callee, { name })) {
                    if (info.kind === 'binary' && path.node.arguments.length === 2) {
                        path.replaceWith(t.binaryExpression(info.operator, path.node.arguments[0], path.node.arguments[1]));
                        proxyInlinedCount++;
                    } else if (info.kind === 'call' && path.node.arguments.length >= 1) {
                        const targetFn = path.node.arguments[0];
                        const callArgs = path.node.arguments.slice(1);
                        path.replaceWith(t.callExpression(targetFn, callArgs));
                        proxyInlinedCount++;
                    }
                }
            }
        });
        info.path.remove();
    }
    console.log(`[+] Pass 2: Inlined ${proxyInlinedCount} proxy calls across ${proxyFunctions.size} functions.`);

    // =========================================================================
    // PASS 3: Constant Folding & Dead-Code Branch Pruning
    // =========================================================================
    console.log('[*] Pass 3: Constant folding and dead-code pruning...');
    let foldedCount = 0;
    let prunedBranches = 0;

    traverse(ast, {
        // Fold constant binary expressions: 1 + 2 -> 3, "a" + "b" -> "ab"
        BinaryExpression(path) {
            const evaluated = path.evaluate();
            if (evaluated.confident) {
                path.replaceWith(t.valueToNode(evaluated.value));
                foldedCount++;
            }
        },
        // Fold constant unary expressions: ![] -> false, - -1 -> 1
        UnaryExpression(path) {
            const evaluated = path.evaluate();
            if (evaluated.confident) {
                path.replaceWith(t.valueToNode(evaluated.value));
                foldedCount++;
            }
        },
        // Prune dead IfStatement branches
        IfStatement(path) {
            const test = path.get('test');
            const evaluated = test.evaluate();
            if (evaluated.confident) {
                if (evaluated.value) {
                    if (path.node.consequent) {
                        path.replaceWith(path.node.consequent);
                    } else {
                        path.remove();
                    }
                } else {
                    if (path.node.alternate) {
                        path.replaceWith(path.node.alternate);
                    } else {
                        path.remove();
                    }
                }
                prunedBranches++;
            }
        },
        // Prune dead ConditionalExpressions (ternaries)
        ConditionalExpression(path) {
            const test = path.get('test');
            const evaluated = test.evaluate();
            if (evaluated.confident) {
                if (evaluated.value) {
                    path.replaceWith(path.node.consequent);
                } else {
                    path.replaceWith(path.node.alternate);
                }
                prunedBranches++;
            }
        }
    });
    console.log(`[+] Pass 3: Folded ${foldedCount} constant expressions, pruned ${prunedBranches} dead branches.`);

    // =========================================================================
    // PASS 4: Property Accessor Normalization (Bracket to Dot Notation)
    // =========================================================================
    console.log('[*] Pass 4: Normalizing property accessors (window["document"] -> window.document)...');
    let normalizedAccessors = 0;
    const validIdentifierRegex = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;
    const reservedWords = new Set([
        'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger', 'default',
        'delete', 'do', 'else', 'export', 'extends', 'finally', 'for', 'function',
        'if', 'import', 'in', 'instanceof', 'new', 'return', 'super', 'switch',
        'this', 'throw', 'try', 'typeof', 'var', 'void', 'while', 'with', 'yield'
    ]);

    traverse(ast, {
        MemberExpression(path) {
            const prop = path.node.property;
            if (path.node.computed && t.isStringLiteral(prop)) {
                const propName = prop.value;
                if (validIdentifierRegex.test(propName) && !reservedWords.has(propName)) {
                    path.node.computed = false;
                    path.node.property = t.identifier(propName);
                    normalizedAccessors++;
                }
            }
        }
    });
    console.log(`[+] Pass 4: Normalized ${normalizedAccessors} member access expressions.`);

    // =========================================================================
    // PASS 5: Control-Flow Unflattening (CFF)
    // =========================================================================
    console.log('[*] Pass 5: Unflattening control-flow state machines...');
    let unflattenedLoops = 0;

    traverse(ast, {
        WhileStatement(path) {
            const { test, body } = path.node;
            // Target while (true) or while (1)
            const isInfinite = t.isBooleanLiteral(test, { value: true }) || t.isNumericLiteral(test, { value: 1 });
            if (!isInfinite || !t.isBlockStatement(body)) return;

            const switchStmt = body.body.find(stmt => t.isSwitchStatement(stmt));
            if (!switchStmt) return;

            // Locate preceding order array declaration: var _0xorder = "3|1|0|2".split("|")
            const prevSibling = path.getPrevSibling();
            const prevPrevSibling = prevSibling && prevSibling.getPrevSibling ? prevSibling.getPrevSibling() : null;

            const extractOrder = (siblingPath) => {
                if (!siblingPath || !siblingPath.isVariableDeclaration()) return null;
                for (const decl of siblingPath.node.declarations) {
                    if (t.isCallExpression(decl.init) &&
                        t.isMemberExpression(decl.init.callee) &&
                        t.isStringLiteral(decl.init.callee.object) &&
                        t.isIdentifier(decl.init.callee.property, { name: 'split' })) {
                        const sep = decl.init.arguments[0];
                        if (t.isStringLiteral(sep)) {
                            return {
                                order: decl.init.callee.object.value.split(sep.value),
                                path: siblingPath
                            };
                        }
                    }
                }
                return null;
            };

            const orderInfo = extractOrder(prevSibling) || extractOrder(prevPrevSibling);
            if (orderInfo) {
                const caseMap = new Map();
                for (const sc of switchStmt.cases) {
                    if (t.isStringLiteral(sc.test) || t.isNumericLiteral(sc.test)) {
                        const key = String(sc.test.value);
                        // Exclude jump control directives (continue, break) from basic block
                        const stmts = sc.consequent.filter(s => !t.isContinueStatement(s) && !t.isBreakStatement(s));
                        caseMap.set(key, stmts);
                    }
                }

                const linearStatements = [];
                for (const key of orderInfo.order) {
                    const stmts = caseMap.get(key);
                    if (stmts) {
                        linearStatements.push(...stmts);
                    }
                }

                if (linearStatements.length > 0) {
                    path.replaceWithMultiple(linearStatements);
                    orderInfo.path.remove();
                    if (prevPrevSibling && prevPrevSibling.isVariableDeclaration()) {
                        prevPrevSibling.remove();
                    } else if (prevSibling && prevSibling.isVariableDeclaration()) {
                        prevSibling.remove();
                    }
                    unflattenedLoops++;
                }
            }
        }
    });
    console.log(`[+] Pass 5: Unflattened ${unflattenedLoops} state machine dispatch loops.`);

    console.log('[*] Generating clean JavaScript code...');
    const output = generate(ast, {
        retainLines: false,
        compact: false,
        comments: true
    }).code;

    return output;
}

// CLI Execution Entry Point
if (require.main === module) {
    const args = process.argv.slice(2);
    if (args.length === 0) {
        console.log('Usage: node deobfuscate_pipeline.js <input.js> [output.js]');
        process.exit(1);
    }
    const inputPath = args[0];
    const outputPath = args[1] || 'deobfuscated.clean.js';

    const source = fs.readFileSync(inputPath, 'utf-8');
    const cleaned = runDeobfuscation(source);
    fs.writeFileSync(outputPath, cleaned, 'utf-8');
    console.log(`[+] Success! Clean source written to: ${outputPath}`);
}

module.exports = { runDeobfuscation };
```

---

### Dynamic JSVMP Tracing Script (Playwright + CDP)
Use this script to trace JSVMP dispatcher execution, dumping opcode flow and operands at runtime.

```javascript
/**
 * jsvmp_trace_tracer.js
 * Injects a runtime hook into the browser to capture JSVMP virtual execution.
 * 
 * Dependencies:
 *   npm install playwright
 */

const { chromium } = require('playwright');
const fs = require('fs');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    // Hook the virtual machine interpreter before scripts load
    await page.addInitScript(() => {
        window.__jsvmp_trace__ = [];

        // Intercept Function constructor and eval if dynamic compilation is used
        const origFunction = window.Function;
        window.Function = function(...args) {
            console.log('[+] Dynamic Function created with args:', args.slice(0, -1));
            return origFunction.apply(this, args);
        };

        // Utility to attach to custom interpreter dispatchers
        window.__attachVmpHook = function(vmInstance, dispatcherPropName) {
            const originalDispatcher = vmInstance[dispatcherPropName];
            vmInstance[dispatcherPropName] = function(opcode, vpc, stack, env) {
                window.__jsvmp_trace__.push({
                    vpc,
                    opcode,
                    topStack: stack ? stack.slice(-2) : null,
                    timestamp: performance.now()
                });
                return originalDispatcher.apply(this, arguments);
            };
            console.log('[+] Attached hook to VM dispatcher:', dispatcherPropName);
        };
    });

    console.log('[*] Navigating to target application...');
    await page.goto('https://target.local/protected_app.html', { waitUntil: 'networkidle' });

    // Extract captured trace logs
    const trace = await page.evaluate(() => window.__jsvmp_trace__);
    fs.writeFileSync('jsvmp_trace.json', JSON.stringify(trace, null, 2));
    console.log(`[+] Captured ${trace.length} virtual instruction executions. Saved to jsvmp_trace.json`);

    await browser.close();
})();
```

---

## 6. Boundaries & Anti-Patterns
- **Do not execute raw untrusted JavaScript in the host Node environment**: Obfuscated malware and anti-tamper scripts check for the Node.js runtime (`process.versions.node`, `global`) and trigger intentional infinite loops, memory crashes, or malicious child process executions. Always isolate execution inside `vm.createContext({})` with explicit timeouts.
- **Do not blindly replace CallExpression nodes without argument type verification**: When decoding string array lookups (`_0x4f2a(...)`), verify that all parameters are literals (`t.isNumericLiteral` or `t.isStringLiteral`). Passing dynamic identifier expressions to the sandbox helper will throw runtime exceptions or produce corrupt outputs.
- **Do not decompile WASM expecting original high-level C++ or Rust classes**: WASM flattens all memory allocations into index offsets on a raw linear memory array (`i32.load`, `i32.store`). High-level struct declarations and member names are erased unless DWARF debug information was explicitly retained.
- **Do not treat single-file bundles as monolithic code**: Use automated chunk splitters (`webcrack`) before analyzing business logic; reading a 50,000-line single-line bundle by hand is error-prone and inefficient.
- **Do not perform cross-file renames with regex or text search**: In multi-module bundles, short mangled identifiers (`a`, `b`, `c`) repeat hundreds of times in different lexical scopes. Always utilize AST-based scope analysis (`path.scope.rename`) to avoid collisions.
