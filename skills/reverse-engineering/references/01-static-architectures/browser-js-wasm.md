# Browser JavaScript, Electron & WebAssembly Reverse Engineering

## When To Open
Open this file for a web bundle (`*.js`, `chunk-*.js`, `*.map`), an Electron app (`app.asar`), a Node `.jsc` (bytenode), or a `.wasm` module (`00 61 73 6D`). Browser extensions (`Cr24`, `.xpi`, `manifest.json`) are [browser-extensions.md](browser-extensions.md). React Native Hermes bytecode is [react-native-hermes.md](react-native-hermes.md). Live CDP hooking with the jshook MCP server is [jshook-mcp.md](../04-tool-usage/jshook-mcp.md); this file links to it and does not repeat its tool list.

## Order Of Work
Static first. A bundle is read before any page is loaded.

1. **Identify the container.** `file`, the first 64 bytes, and the last line (`//# sourceMappingURL=`). Use the fingerprint table below.
2. **Look for a source map before deobfuscating.** A map with `sourcesContent` is the original source. It ends the job for that file.
3. **Unpack the bundle into modules.** One module per file. Grep module files, not a 3 MB single line.
4. **Deobfuscate only the modules that matter.** Run `webcrack` first. Write a Babel pass only for what webcrack leaves.
5. **Name the boundary.** `fetch`/`XMLHttpRequest`/`WebSocket` callers, `crypto.subtle`, `WebAssembly.instantiate`, and `postMessage`. That is where request signing and key material live.
6. **Go dynamic only when static stalls.** Runtime-decrypted code, JSVMP, or a value computed from the environment. See "Dynamic" below.

## Fingerprints

| Evidence | Meaning |
| :--- | :--- |
| `(self.webpackChunk<name>=self.webpackChunk<name>\|\|[]).push([[id],{...}])` | Webpack 5 chunk. Modules are keyed by numeric or path ID. Webpack 5.1xx emits method shorthand: `{899(e,t,n){...}}`. |
| `n.d(t,{run:()=>e})`, `n.r(t)`, `n.e(899)`, `n.u=t=>t+".js"` | Minified `__webpack_require__` helpers: `.d` define exports, `.r` mark ESM, `.e` load chunk, `.u` chunk URL. |
| `webpackJsonp`, modules as `[function(e,t,n){...}]` array | Webpack 4 or older. |
| `__commonJS`, `__toESM`, `__export`, `__esm(()=>{...})` helpers, `chunk-<HASH>.js` | esbuild (also Vite dev and Vite's dependency pre-bundle). |
| Plain ESM, hoisted top-level declarations, `/*#__PURE__*/`, `assets/index-<hash>.js`, `__vite__mapDeps`, `modulepreload` polyfill | Rollup / Vite production. No runtime module map; scope hoisting merged modules. |
| `parcelRequire`, `parcelRegister`, `$parcel$export` | Parcel. |
| `(globalThis.TURBOPACK = globalThis.TURBOPACK \|\| []).push(...)` | Turbopack (Next.js). |
| `/_next/static/chunks/`, `_buildManifest.js`, `self.__next_f.push` | Next.js. `_buildManifest.js` lists routes; `__next_f` is a React Server Components payload. |
| `require=function r(e,n,t){...}` prelude, `[function(require,module,exports){...},{"./x":3}]` | Browserify. |
| `function _0x5c19(...)`, a self-reassigning `function _0x15fa(){const a=[...];_0x15fa=function(){return a};...}`, `while(!![]){try{...parseInt(...)...}catch{...push(...shift())}}` | obfuscator.io (`javascript-obfuscator`). See the obfuscator.io section. |
| One giant `switch` over a numeric array or decoded byte string, an operand stack array, a program counter | JSVMP (custom JS VM). |
| `app.asar`, `app.asar.unpacked/`, `Electron Framework.framework` | Electron. |
| `.jsc` next to a stub `require('bytenode')` | V8 code cache (bytenode). |
| `00 61 73 6D 01 00 00 00` | WebAssembly binary, version 1. |

Production webpack 5 builds with `concatenateModules` (default in `mode: production`) merge most modules. An unpacker then reports one entry module. That is not a failure.

## Source Maps
Look in three places. The trailing `//# sourceMappingURL=<url>` comment. A `SourceMap:` or `X-SourceMap:` HTTP response header. `<bundle>.js.map` next to the bundle even when the comment was stripped. Inline maps start with `data:application/json;base64,`.

```bash
# Extract every file in sourcesContent. Verified with @wakaru/cli 1.15.0.
npx -y @wakaru/cli@1.15.0 extract "$MAP" -o ./from_map
# Alternative: shuji writes the same files, flattened per map.
npx -y shuji "$MAP" -o ./from_map_shuji
```

- A map without `sourcesContent` still gives original file paths and identifier `names`. Pass it to wakaru for renaming: `npx -y @wakaru/cli@1.15.0 "$BUNDLE" -m "$MAP" -o out.js`.
- `restore-source-tree@0.1.1` processed zero files on a webpack 5 map in testing. Do not use it.
- Paths like `webpack://<name>/src/...` give the project name and the original tree. Paths under `node_modules/` give exact dependency versions.

## Unpack And Unminify

```bash
# webcrack 2.16.0: deobfuscate + unminify + unpack (webpack/browserify). Writes deobfuscated.js,
# and bundle.json plus one file per module when a module map exists.
# Requires Node 22 or 24 (isolated-vm does not build on Node 26). `npx -y node@24 ...` is a workaround.
npx -y webcrack@2.16.0 "$BUNDLE" -o ./wc_out -f

# wakaru 1.15.0 (Rust rewrite, binary `wakaru`): unminify, or split a bundle into modules.
npx -y @wakaru/cli@1.15.0 "$BUNDLE" -o out.js
npx -y @wakaru/cli@1.15.0 "$BUNDLE" --unpack -o ./wk_out          # webpack, browserify, esbuild, scope-hoisted
npx -y @wakaru/cli@1.15.0 "$BUNDLE" --unpack --provenance -o ./wk_out   # provenance.json maps modules to byte ranges
```

Decision table, measured on `javascript-obfuscator` 5.9.0 output (string array + rc4 + wrappers + calls transform + dead code):

| Tool | Result | Use for |
| :--- | :--- | :--- |
| `webcrack@2.16.0` | Clean, runnable output. Also removed self-defending and debug-protection. | First pass for obfuscator.io and webpack/browserify. |
| `@wakaru/cli@1.15.0` | Unminify and unpack. Not an obfuscator.io string-array decoder. | Renaming, ES syntax recovery, Vue/JSX recovery, source-map-guided names. |
| `restringer@2.3.0` | Correct on the basic preset. Produced a broken call on the hard preset. 34 s. | Second opinion on generic string-building obfuscation. |
| `synchrony` (npm `deobfuscator@2.4.6`, `npx -y -p deobfuscator@2.4.6 synchrony deobfuscate in.js -o out.js`) | Broken output on both presets. | Old (pre-2023) obfuscator.io output only. |
| Babel script below | Clean, runnable output on all non-self-defending presets. | Variants that webcrack misses; adapt it. |

Always run the result (in the lab) or diff behavior. A deobfuscator that silently drops a call is worse than none.

## obfuscator.io Anatomy
Current `javascript-obfuscator` (4.x/5.x) output has these parts. Older posts describing `var _0x5a1b=[...]` as the first statement and `while(--n)` rotation are pre-2021 layouts.

1. **String array function.** `function _0x15fa(){const a=['url','log',...];_0x15fa=function(){return a;};return _0x15fa();}`. Hoisted, so it often appears last.
2. **Decoder.** `function _0x5c19(i,k){i=i-0x1d8;const a=_0x15fa();...}`. The offset (`0x1d8`) is per build. With `base64` or `rc4` encoding the decoder caches results on its own properties (`_0x5c19.abcd`). `rc4` passes a key as the second argument.
3. **Rotation IIFE.** `(function(f,target){const a=f();while(!![]){try{const v=parseInt(d(0x1e1))/1*...;if(v===target)break;else a.push(a.shift());}catch(e){a.push(a.shift());}}}(_0x15fa,0x28126));`. It rotates until a checksum of decoded integers matches `target`. Run it; do not solve it.
4. **Decoder aliases and wrappers.** `const _0x436e14=_0x5c19;` per function, and `function _0x291de2(a,b){return _0x5c19(b- -0xb1,a);}` wrappers whose arguments come from constant objects (`stringArrayCallsTransform`).
5. **Proxy objects** (from control-flow flattening). `const o={'SXZVg':function(a,b){return a+b;},'JIEpX':'step'};` then `o.SXZVg(x,1)`.
6. **Dispatcher** (`controlFlowFlattening` on long blocks). `const s='3|0|4|1|2'.split('|');let i=0;while(!![]){switch(s[i++]){case '0':...;continue;}break;}`.
7. **Self-defending / debug protection.** Regex strings `(((.+)+)+)+$` and `function *\( *\)`, `\+\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)`, plus `"debugger"` via `constructor`. Reformatted output is designed to hang or throw. Delete those IIFEs; read the rest statically.

## Babel Deobfuscation Script
Verified on `javascript-obfuscator` 5.9.0 presets: string array with none/base64/rc4 encoding, rotation, index shift, function wrappers (chained), `stringArrayCallsTransform`, `splitStrings`, `numbersToExpressions`, dead-code injection, `transformObjectKeys`, and a hand-written dispatcher. Output ran and printed the same result as the input. Self-defending output keeps the decoder and is for reading only.

The `vm` module is not a security boundary. Run this inside the analysis VM, never on a host that holds credentials.

```bash
mkdir deob && cd deob && npm init -y >/dev/null
npm i @babel/parser @babel/traverse @babel/generator @babel/types
node deob.js "$IN_JS" out.js
```

```javascript
// deob.js: obfuscator.io string-array + wrapper + proxy-object + dispatcher cleanup. Node >= 18.
const fs = require('fs'), vm = require('vm');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

const ast = parser.parse(fs.readFileSync(process.argv[2], 'utf8'), { sourceType: 'unambiguous', errorRecovery: true });
const reparse = () => traverse.cache.clear();      // scopes go stale after large edits

function substitute(expr, params, args) {          // body of `function w(a,b){return D(b-1,a)}` with args bound
  const map = new Map(params.map((p, i) => [p.name, args[i] ?? t.identifier('undefined')]));
  const walk = n => {
    if (t.isIdentifier(n) && map.has(n.name)) return t.cloneNode(map.get(n.name));
    for (const k of t.VISITOR_KEYS[n.type] || []) {
      const v = n[k];
      if (Array.isArray(v)) n[k] = v.map(c => c && walk(c)); else if (v) n[k] = walk(v);
    }
    return n;
  };
  return walk(t.cloneNode(expr));
}
function singleReturn(fn) {                        // `function(a,b){return <expr>}`, each param used once
  if (!(t.isFunctionExpression(fn) || t.isFunctionDeclaration(fn)) || fn.body.body.length !== 1 ||
      !t.isReturnStatement(fn.body.body[0]) || !fn.params.every(q => t.isIdentifier(q))) return null;
  const r = fn.body.body[0].argument, seen = {};
  let ok = !!r;
  traverse(t.file(t.program([t.expressionStatement(t.cloneNode(r))])), { noScope: true,
    Identifier(q) { if (fn.params.some(x => x.name === q.node.name) && ++seen[q.node.name] > 1) ok = false;
                    seen[q.node.name] ??= 1; } });
  return ok ? r : null;
}

// 1. Proxy/storage objects: o = {k:'s', f:function(a,b){return a+b}}; o.j = ...; p = o; p.f(x,y) -> x+y
function inlineObjects() {
  let n = 0; reparse();
  traverse(ast, { VariableDeclarator(p) {
    const { id, init } = p.node;
    if (!t.isIdentifier(id) || !t.isObjectExpression(init)) return;
    const map = new Map(), extra = [];
    const okVal = v => t.isStringLiteral(v) || t.isNumericLiteral(v) || singleReturn(v);
    for (const q of init.properties) {
      if (!t.isObjectProperty(q) || q.computed || !okVal(q.value)) return;
      map.set(q.key.name ?? q.key.value, q.value);
    }
    for (let s = p.parentPath.getNextSibling(); s.node; s = s.getNextSibling()) {   // trailing o.k = v, ...
      if (s.isFunctionDeclaration()) continue;
      if (!s.isExpressionStatement()) break;
      const ex = t.isSequenceExpression(s.node.expression) ? s.node.expression.expressions : [s.node.expression];
      if (!ex.every(e => t.isAssignmentExpression(e, { operator: '=' }) && t.isMemberExpression(e.left) &&
          t.isIdentifier(e.left.object, { name: id.name }) && okVal(e.right))) break;
      ex.forEach(e => map.set(e.left.computed ? e.left.property.value : e.left.property.name, e.right));
      extra.push(s);
    }
    const b = p.scope.getBinding(id.name);
    if (!map.size || !b || b.constantViolations.length) return;
    const refs = [], aliases = [];
    const collect = bind => { for (const r of bind.referencePaths) {
      if (extra.some(s => r.isDescendant(s))) continue;
      if (r.parentPath.isVariableDeclarator({ init: r.node })) {
        const ab = r.scope.getBinding(r.parent.id.name);
        if (!ab || ab.constantViolations.length) throw 0;
        aliases.push(r.parentPath); collect(ab); continue;
      }
      const m = r.parentPath;
      const key = m.isMemberExpression({ object: r.node }) &&
        (m.node.computed ? t.isStringLiteral(m.node.property) && m.node.property.value : m.node.property.name);
      if (!key || !map.has(key) || m.parentPath.isAssignmentExpression({ left: m.node })) throw 0;
      if (!t.isLiteral(map.get(key)) && !m.parentPath.isCallExpression({ callee: m.node })) throw 0;
      refs.push([m, map.get(key)]);
    }};
    try { collect(b); } catch { return; }          // object escapes: leave it alone
    refs.sort((x, y) => (y[0].node.start ?? 0) - (x[0].node.start ?? 0));   // innermost first
    for (const [m, v] of refs) {
      if (t.isLiteral(v)) m.replaceWith(t.cloneNode(v));
      else m.parentPath.replaceWith(substitute(singleReturn(v), v.params, m.parent.arguments));
      n++;
    }
    aliases.reverse().forEach(a => a.removed || a.remove()); extra.forEach(s => s.remove()); p.remove();
  }});
  return n;
}

// 2. String array fn + decoder(s) + rotation IIFE, executed once in a vm context.
function findDecoders() {
  let arrFn = null; const decoders = new Set(), setup = [];
  for (const s of ast.program.body)
    if (t.isFunctionDeclaration(s) && s.body.body.some(x => t.isVariableDeclaration(x) &&
        x.declarations.some(d => t.isArrayExpression(d.init) && d.init.elements.length > 3 &&
          d.init.elements.every(e => t.isStringLiteral(e))))) arrFn = s.id.name;
  if (!arrFn) return null;
  for (const s of ast.program.body) {
    if (t.isFunctionDeclaration(s) && s.id.name !== arrFn && generate(s).code.includes(arrFn + '()')) decoders.add(s.id.name);
    if (t.isFunctionDeclaration(s) && (s.id.name === arrFn || decoders.has(s.id.name))) setup.push(s);
    if (t.isExpressionStatement(s) && t.isCallExpression(s.expression) &&
        t.isIdentifier(s.expression.arguments[0], { name: arrFn })) setup.push(s);
  }
  const ctx = vm.createContext({});
  vm.runInContext(setup.map(s => generate(s).code).join('\n'), ctx, { timeout: 5000 });
  return { ctx, decoders, setup, names: [arrFn, ...decoders] };
}

// 3. Collapse aliases and wrappers into decoder calls; replace literal-argument calls with strings.
function decodeCalls({ ctx, decoders }) {
  let n = 0;
  for (let changed = true; changed;) {
    changed = false; reparse();
    traverse(ast, { CallExpression(p) {
      const c = p.node.callee;
      if (!t.isIdentifier(c)) return;
      const b = p.scope.getBinding(c.name);
      if (decoders.has(c.name) && (!b || b.path.isFunctionDeclaration() && b.path.parentPath.isProgram())) {
        const args = p.get('arguments').map(a => a.evaluate());
        if (!args.every(a => a.confident)) return;
        const v = ctx[c.name](...args.map(a => a.value));
        if (typeof v === 'string') { p.replaceWith(t.stringLiteral(v)); n++; changed = true; }
        return;
      }
      if (!b) return;
      if (b.path.isVariableDeclarator() && t.isIdentifier(b.path.node.init) && decoders.has(b.path.node.init.name)) {
        p.node.callee = t.identifier(b.path.node.init.name); changed = true; return;
      }
      const fn = b.path.node, r = t.isFunctionDeclaration(fn) && singleReturn(fn);
      if (r && t.isCallExpression(r) && t.isIdentifier(r.callee)) {
        p.replaceWith(substitute(r, fn.params, p.node.arguments)); changed = true;
      }
    }});
  }
  return n;
}

// 4. Constant folding, dead branches, dot access.
function fold() {
  reparse();
  traverse(ast, {
    'BinaryExpression|UnaryExpression|LogicalExpression'(p) {
      if (p.isUnaryExpression({ operator: 'void' })) return;
      let e; try { e = p.evaluate(); } catch { return; }
      if (e.confident && ['string', 'number', 'boolean'].includes(typeof e.value) &&
          !(typeof e.value === 'number' && !Number.isFinite(e.value))) p.replaceWith(t.valueToNode(e.value));
    },
    'IfStatement|ConditionalExpression'(p) {
      const e = p.get('test').evaluate();
      if (!e.confident) return;
      const keep = e.value ? p.node.consequent : p.node.alternate;
      if (!keep) p.remove();
      else if (t.isBlockStatement(keep) && p.isStatement()) p.replaceWithMultiple(keep.body);
      else p.replaceWith(keep);
    },
    MemberExpression(p) {
      const k = p.node.property;
      if (p.node.computed && t.isStringLiteral(k) && t.isValidIdentifier(k.value)) {
        p.node.computed = false; p.node.property = t.identifier(k.value);
      }
    },
  });
}

// 5. Dispatcher: const s='2|0|1'.split('|'); let i=0; while(true){switch(s[i++]){...}break;}
function unflatten() {
  let n = 0; reparse();
  traverse(ast, { WhileStatement(p) {
    const body = p.node.body.body;
    if (!t.isBooleanLiteral(p.node.test, { value: true }) || !body || !t.isSwitchStatement(body[0])) return;
    const disc = body[0].discriminant;
    if (!t.isMemberExpression(disc) || !t.isIdentifier(disc.object)) return;
    const b = p.scope.getBinding(disc.object.name), init = b && b.path.node.init;
    if (!init || !t.isCallExpression(init) || !t.isStringLiteral(init.callee.object)) return;
    const order = init.callee.object.value.split(init.arguments[0].value);
    const cases = new Map(body[0].cases.map(c => [String(c.test.value),
      c.consequent.filter(s => !t.isContinueStatement(s) && !t.isBreakStatement(s))]));
    const out = order.flatMap(k => cases.get(k) || []);
    if (!out.length) return;
    const idx = t.isUpdateExpression(disc.property) && p.scope.getBinding(disc.property.argument.name);
    p.replaceWithMultiple(out); b.path.remove(); if (idx) idx.path.remove(); n++;
  }});
  return n;
}

function cleanup() {                               // unreferenced wrappers and aliases
  for (let again = true; again;) {
    again = false; reparse();
    traverse(ast, { Program(p) { p.scope.crawl(); },
      'FunctionDeclaration|VariableDeclarator'(p) {
        const id = p.node.id; if (!t.isIdentifier(id) || p.parentPath.isProgram()) return;
        const b = p.scope.getBinding(id.name);
        const pure = p.isFunctionDeclaration() ? singleReturn(p.node) : t.isIdentifier(p.node.init);
        if (b && !b.referenced && pure) { p.remove(); again = true; }
      } });
  }
}

inlineObjects();
const dec = findDecoders();
if (dec) console.error('[+] decoded', decodeCalls(dec), 'calls via', [...dec.decoders]);
fold();
for (let i = 0; i < 5 && inlineObjects(); i++) fold();
cleanup();
console.error('[+] unflattened', unflatten(), 'dispatchers');
fold();
if (dec) {                                         // keep the decoder if dynamic-argument calls remain
  let used = false;
  traverse(ast, { Identifier(p) {
    if (dec.names.includes(p.node.name) && !dec.setup.some(s => p.findParent(q => q.node === s))) used = true;
  } });
  if (!used) dec.setup.forEach(s => ast.program.body.splice(ast.program.body.indexOf(s), 1));
  else console.error('[!] decoder still referenced; kept');
}
fs.writeFileSync(process.argv[3] || 'out.js', generate(ast, { jsescOption: { minimal: true } }).code);
```

Adapting it. A decoder that is a `var x = function(){}` instead of a declaration needs `findDecoders` extended. Strings decoded inside a closure that is not top-level need the closure source in `setup`. Dispatchers whose order comes from a decoded string work only after pass 3. Rename `_0x` identifiers last with `path.scope.rename(old, new)`; never with regex.

## JSVMP
A JSVMP compiles JS into private bytecode run by an interpreter in the page. There is no AST to clean.

1. **Find the interpreter.** A function with a `while`/`for(;;)` around a `switch` with 50+ numeric cases, an array used as a stack (`s[++p]=`, `s[p--]`), and an index that advances through a byte array or decoded string. The bytecode is usually a long base64 or `\x` string decoded once at start.
2. **Map handlers statically.** For each case, write one line: stack effect, operand width, side effect. Group: push const, load/store var, get/set property, call/new, arithmetic, compare, jump, return, closure create, try/catch.
3. **Disassemble.** With the operand widths known, write a linear disassembler for the decoded bytecode. Jumps give basic blocks.
4. **Trace only to fill gaps.** Log `(pc, opcode, top of stack)` at the dispatch point in the lab. A trace covers one path; the disassembler covers all.
5. **Lift.** Symbolic stack per basic block: `PUSH c` pushes a literal node, `ADD` pops two and pushes `a+b`, `CALL n` pops n args and a callee and emits a call. Emit Babel nodes and print with `@babel/generator`.

Commercial anti-bot VMs re-randomize opcode numbering per build. Key the handler map on handler semantics, not on opcode numbers. For request-signing targets, it is often cheaper to treat the VM as a black box and call it (RPC through the page) than to lift it. Record which one you did.

## Dynamic (When Execution Is Allowed)
Run only in the lab browser profile. The jshook MCP server covers CDP hooks, script search, and JSVMP tracing: [jshook-mcp.md](../04-tool-usage/jshook-mcp.md).

Anti-debug traps and their counters:

| Trap | Counter |
| :--- | :--- |
| `setInterval(()=>(function(){}).constructor("debugger")(),200)` | CDP `Debugger.setSkipAllPauses {skip:true}` or DevTools "Deactivate breakpoints". Do not edit the page. |
| Timing check around `debugger` (`Date.now()`/`performance.now()` delta) | Skip-all-pauses removes the delay. |
| DevTools-open detection via `console.log` of an object with a getter, or window size delta | Headless CDP session, not DevTools UI. |
| `Function.prototype.toString` / `fn.toString().length` integrity checks | Hook with a `Proxy` that preserves `toString`, or patch after the check. |
| Code that re-fetches itself and compares hashes | Serve a local copy through the proxy; see [network-traffic-proxy.md](../02-dynamic-instrumentation/network-traffic-proxy.md). |

Script capture over CDP. Every parsed script, including `eval` and `new Function` output, arrives in `Debugger.scriptParsed`. Verified with `playwright-core` and installed Chrome; it saved an `eval`'d payload and did not stop on `debugger` traps.

```javascript
// dump_scripts.js: npm i playwright-core ; node dump_scripts.js "$URL" ./scripts
const { chromium } = require('playwright-core');
const fs = require('fs'), path = require('path'), crypto = require('crypto');
(async () => {
  const [url, out = 'scripts'] = process.argv.slice(2);
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const page = await (await browser.newContext()).newPage();
  const cdp = await page.context().newCDPSession(page);
  const seen = [];
  cdp.on('Debugger.scriptParsed', async (s) => {
    try {
      const { scriptSource } = await cdp.send('Debugger.getScriptSource', { scriptId: s.scriptId });
      const name = crypto.createHash('sha1').update(scriptSource).digest('hex').slice(0, 12) + '.js';
      fs.writeFileSync(path.join(out, name), scriptSource);
      seen.push({ file: name, url: s.url || '(eval)', sourceMapURL: s.sourceMapURL || '' });
    } catch {}
  });
  await cdp.send('Debugger.enable');
  await cdp.send('Debugger.setSkipAllPauses', { skip: true });
  await page.goto(url, { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  fs.writeFileSync(path.join(out, 'index.json'), JSON.stringify(seen, null, 1));
  await browser.close();
})();
```

Hooks that must run before page code use `page.addInitScript()` (CDP `Page.addScriptToEvaluateOnNewDocument`). Hook `crypto.subtle.importKey`/`encrypt`/`sign`, `TextEncoder.prototype.encode`, `WebAssembly.instantiate`, and `XMLHttpRequest.prototype.send` to catch keys and plaintext at the boundary.

## Electron
An Electron app is Chromium plus Node. The main process has full Node. Renderers have Node only when the app grants it.

```bash
APP="/Applications/Some.app"            # Windows/Linux: <install>/resources/app.asar
ASAR="$APP/Contents/Resources/app.asar"
npx -y @electron/asar@4.3.1 list "$ASAR" | head
npx -y @electron/asar@4.3.1 extract "$ASAR" ./app_src        # also needs app.asar.unpacked/ beside it
npx -y @electron/fuses@2.1.3 read --app "$APP"               # RunAsNode, inspect args, asar integrity, OnlyLoadAppFromAsar
plutil -p "$APP/Contents/Info.plist" | grep -A3 ElectronAsarIntegrity   # macOS header hash
```

- **ASAR layout.** `u32 4`, `u32 header_size`, `u32 pickle_payload_size`, `u32 json_len`, JSON header, then file data at `8 + header_size`. All little-endian. The JSON lists `size`, `offset` (as a string), `unpacked`, and per-file `integrity` (SHA-256 plus 4 MB block hashes). Verified with `@electron/asar` 4.3.1. The npm package `asar` is the deprecated name; use `@electron/asar`.
- **Integrity.** With `EnableEmbeddedAsarIntegrityValidation` on, the header hash is in `Info.plist` (`ElectronAsarIntegrity`) on macOS and in a resource on Windows. A modified asar does not load until that hash is updated. Read-only analysis does not need this.
- **Entry.** `package.json` `main` is the main-process script. Grep it for `new BrowserWindow(` and read `webPreferences`.
- **Trust boundary table.**

| `webPreferences` | Risk |
| :--- | :--- |
| `nodeIntegration: true` | Any XSS in the renderer is code execution. |
| `contextIsolation: false` (default `true` since Electron 12) | Page JS shares globals with the preload; prototype pollution reaches preload APIs. |
| `sandbox: false` (default `true` since Electron 20) | Preload has Node. |
| `preload` + `contextBridge.exposeInMainWorld('api', {...})` | This object is the API surface. Read every exposed function. |
| `webSecurity: false`, `allowRunningInsecureContent` | Same-origin policy off. |
| `ipcMain.handle(channel, ...)` without `event.senderFrame` origin check | Any frame, including an iframe, can call it. |
| `shell.openExternal(url)` with page-controlled `url` | Opens arbitrary protocol handlers. |

- **Main-process debugging** (lab only). `--inspect=9229` works only when `EnableNodeCliInspectArguments` is enabled. `ELECTRON_RUN_AS_NODE=1` works only when `RunAsNode` is enabled. Renderers accept `--remote-debugging-port=9222` unless the app strips it.

## V8 Bytecode (`.jsc`, bytenode, V8 snapshots)
bytenode saves V8 code cache from `vm.Script` `produceCachedData`. Function bodies are bytecode; source text is replaced with placeholders, so `Function.prototype.toString` shows nothing useful.

- The cache is tied to one V8 version and flag set. Get the version from the host binary (`node -p process.versions.v8`, or Electron's version from `Info.plist`/`process.versions`).
- View8 (`suleram/View8`) decompiles serialized V8 objects using a d8 build matched to that version. `ghidra_nodejs` is archived and supports only old Node 8-era bytecode.
- Strings and property names survive in the constant pool. `strings -el`/`strings` on the `.jsc` is a fast first look.
- Electron `LoadBrowserProcessSpecificV8Snapshot` and custom snapshots (`v8_context_snapshot.bin`) can hold app code. Check the fuse before assuming all code is in the asar.

## WebAssembly
Header: `00 61 73 6D` then version `01 00 00 00`. Each section is `id:u8`, `size:LEB128`, payload.

| ID | Section | Why it matters |
| :--- | :--- | :--- |
| 0 | custom | `name` (function/local names), `producers` (clang/rustc/emscripten versions), `target_features`, `.debug_*` DWARF, `sourceMappingURL`, `go:buildid`, `dylink.0` |
| 1 | type | Function signatures |
| 2 | import | The JS/WASI boundary. Names reveal the toolchain. |
| 3 | function | Type index per defined function |
| 4 | table | `funcref` table for `call_indirect` (vtables, function pointers) |
| 5 | memory | Linear memory limits in 64 KiB pages |
| 6 | global | `__stack_pointer` is usually global 0 |
| 7 | export | Entry points called from JS |
| 8 | start | Runs at instantiation |
| 9 | element | Initial table contents: maps indirect-call indices to functions |
| 10 | code | Function bodies |
| 11 | data | Initialized memory. Strings and constant tables at fixed addresses. |
| 12 | datacount | Needed for bulk memory |
| 13 | tag | Exception handling |

```bash
# wabt 1.0.42 and wasm-tools 1.263.0, verified on clang- and Go-built modules.
wasm-objdump -h "$WASM"                       # section list, custom section names
wasm-objdump -x -j Import -j Export "$WASM"   # boundary
wasm-objdump -x -j Data "$WASM"               # data segments with hex/ASCII and load address
wasm-objdump -d "$WASM" > dis.txt             # disassembly with byte offsets
wasm2wat "$WASM" -o mod.wat
wasm-tools print "$WASM" | head; wasm-tools objdump "$WASM"
wasm-tools demangle "$WASM" -o demangled.wasm # Rust/C++ names in the name section
wasm-opt "$WASM" --func-metrics --print-call-graph -o /dev/null   # binaryen version_133
```

- `wasm-decompile` was removed in wabt 1.0.42 (commit "Remove wasm-decompile (#2769)", June 2026). The 1.0.41 release still ships it: `wasm-decompile "$WASM" -o mod.dcmp`. It prints readable pseudo-C with recovered loads (`a[0]`) and data segments.
- Native decompiler path. `wasm2c "$WASM" -o mod.c`, then `clang -c -O2 -I "$WABT/include" mod.c -o mod.o`, then open `mod.o` in IDA (through the HexRaysSA `ida-mcp` server, see [ida-pro.md](../04-tool-usage/ida-pro.md)) or Ghidra. Function names come out as `w2c_<module>_<name>`. Verified compile with wabt 1.0.42.
- Ghidra: `nneonneo/ghidra-wasm-plugin` (v2.4.0, Dec 2025) loads `.wasm` directly with decompilation. Install the release zip that matches the Ghidra version.
- **Toolchain traits** (Go traits verified on a `GOOS=js GOARCH=wasm` build):

| Toolchain | Imports / exports / strings |
| :--- | :--- |
| Emscripten | Imports from `env` and `wasi_snapshot_preview1`. Release builds minify to module `a`, names `a`,`b`,... The glue JS maps them (`var wasmImports={b:_emscripten_resize_heap,...}`). Glue has `Module`, `HEAPU8`, `cwrap`, `ccall`, `UTF8ToString`, `stackAlloc`. |
| Rust + wasm-bindgen | Imports `__wbg_<name>_<hash>`, `__wbindgen_throw`; exports `__wbindgen_malloc`, `__wbindgen_realloc`; panic paths `/rustc/<hash>/library/...` and `src/*.rs` in data. |
| Go (`GOOS=js`) | 19 imports from module `gojs` (`runtime.wasmWrite`, `syscall/js.valueGet`, ...). Exports `run`, `resume`, `getsp`, `mem`. Custom section `go:buildid`. Glue `wasm_exec.js`. Large (2 MB for hello world). |
| AssemblyScript | Import `env.abort`; `~lib/` strings in data. |
| Plain clang `--target=wasm32` | Exports `memory`, `__stack_pointer` global, `.rodata` data segment at 65536 (current wasm-ld places the stack first). Emscripten's default `GLOBAL_BASE` is 1024. |

- **Boundary first.** Read the JS that calls `WebAssembly.instantiate`. Strings cross as `(ptr, len)` in linear memory: JS calls an exported `malloc`, writes bytes into `memory.buffer`, then calls the export. Name exports from their JS call sites before reading any function body.
- **Addresses.** A `i32.const 65536` followed by a load is a pointer into a data segment. Match it against `wasm-objdump -x -j Data` init offsets to read the string.
- **Crypto.** Look for constant tables in data (AES S-box `63 7c 77 7b`, SHA-256 `0x428a2f98`) and `i32.rotl` chains. Confirm by calling the export with a known vector in the lab.

## Pitfalls
- A deobfuscated file is evidence only after it runs (lab) or after a spot check of three decoded strings against a runtime value.
- `path.evaluate()` treats unknown globals as non-confident. Folding stops at `window.x`; that is correct.
- Bracket-to-dot conversion must use `t.isValidIdentifier`; reserved words stay bracketed.
- Do not rename across modules with text search. `a`, `e`, `t` repeat in every scope.
- Do not trust a module ID across builds. Webpack IDs change between releases; match modules by string constants.
- A Vite/Rollup bundle has no module map to recover. Split by the `import`/`export` boundaries of chunk files instead.
- WASM has no types beyond `i32/i64/f32/f64`. Struct layout comes from load offsets, not from the binary.
- Do not run unknown bundles in host Node. Malware checks `process.versions.node` and uses `require('child_process')` when it finds it.
