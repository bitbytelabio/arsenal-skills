# Frida Hooking Methodology

## When To Open
Open this file when a runtime question is cheaper to answer by hooking than by stopping: the arguments of a function called thousands of times, the plaintext entering a cipher, the class a method dispatches to, or which basic blocks one input reaches. It covers what to hook, which Frida primitive to use, and how to prove the hook saw what you think. Device setup, CLI flags, the Python API, Gadget packaging, and TLS unpinning scripts are in [frida.md](../04-tool-usage/frida.md). Stopping-debugger work is in [debugger-workflows.md](debugger-workflows.md).

The sample runs in the lab from [malware-sandbox-isolation.md](malware-sandbox-isolation.md), never on the host. `frida-server` runs in the guest or on the test device. The host runs the client.

## Frida 17 API Baseline
Frida 17 removed long-deprecated statics. Old snippets fail with `TypeError: not a function`. Every snippet in this file was run against Frida 17.17 (Gadget on macOS arm64, own test program).

| Removed (Frida ≤16) | Frida 17 form |
|---|---|
| `Module.findExportByName(null, 'open')` | `Module.findGlobalExportByName('open')` |
| `Module.getExportByName(null, 'open')` | `Module.getGlobalExportByName('open')` |
| `Module.findExportByName('libc.so', 'open')` | `Process.getModuleByName('libc.so').findExportByName('open')` |
| `Module.getExportByName('libc.so', 'open')` | `Process.getModuleByName('libc.so').getExportByName('open')` |
| `Module.findBaseAddress('libx.so')` | `Process.findModuleByName('libx.so')?.base` |
| `Module.enumerateExports('libx.so')` | `Process.getModuleByName('libx.so').enumerateExports()` |
| `Module.findSymbolByName(m, s)` | `Process.getModuleByName(m).findSymbolByName(s)` |
| `Module.ensureInitialized('libx.so')` | `Process.getModuleByName('libx.so').ensureInitialized()` |
| `Memory.readU32(p)`, `Memory.readUtf8String(p)`, `Memory.writeU8(p, v)` | `p.readU32()`, `p.readUtf8String()`, `p.writeU8(v)` |
| `Java`, `ObjC`, `Swift` globals in any script | Still global in the `frida` REPL (`-l`) and `frida-trace`. Absent in scripts created through the Python/Node API or compiled with `frida-compile`. Import `frida-java-bridge`, `frida-objc-bridge`, `frida-swift-bridge` there. |

Checked live: `typeof Memory.readU32`, `typeof Module.findExportByName`, `typeof Module.getExportByName`, and `typeof Module.findBaseAddress` are all `undefined` in 17.17. `Module.load`, `Module.getGlobalExportByName`, and `Module.findGlobalExportByName` exist. In a raw `create_script`, `typeof ObjC` is `undefined`; in the REPL it is `object`.

## Pick The Primitive

| Question | Primitive | Cost | Notes |
|---|---|---|---|
| Arguments and return of a known function | `Interceptor.attach` | One trampoline per call, JS per hit | Default choice. |
| Replace a function's behavior | `Interceptor.replace` + `NativeCallback` | Same | Keep a `NativeFunction` to the original if you call through. |
| Call a function in the target yourself | `NativeFunction` | One native call | Run a recovered decryptor on chosen inputs. |
| Very hot function (millions of hits) | `Interceptor.attach(target, cmodule)` | No JS transition | C callbacks via `CModule`. |
| Which blocks or calls run between two points | `Stalker` | 10–100× slowdown on followed threads | Follow one thread, for a bounded window. |
| Find functions by name pattern | `ApiResolver('module')`, `ApiResolver('objc')`, `ApiResolver('swift')` | Enumeration once | `exports:*!*crypt*`, `imports:app!*`, `-[NSURL* *]`. |
| Name an address | `DebugSymbol.fromAddress` | Symbol lookup | Uses debug info when present. |
| Find a byte pattern or a key in memory | `Memory.scan` / `Memory.scanSync` | Linear in range size | Patterns with `??` wildcards, nibble masks via `:`. |
| Live Java objects | `Java.choose` | Heap walk | REPL global, or import `frida-java-bridge`. |
| Live ObjC objects | `ObjC.choose` | Heap walk | Same rule. |
| Process before `main` / before the app's own init | Spawn mode, spawn gating, child gating | Process is paused until you resume | See early instrumentation. |
| Device with no root / jailbreak | Frida Gadget | Repackage and re-sign | See [frida.md](../04-tool-usage/frida.md). |

Interceptor vs Stalker:
- `Interceptor` rewrites the first instructions of the target with a jump. It costs nothing when the function is not called. It is visible to code that checksums its own prologues.
- `Stalker` recompiles the followed thread's code into a cache, block by block. The original code is not patched, so `.text` checksums still pass. The slowdown and the cache's executable memory are visible to timing checks and memory scans.
- `Interceptor` needs room for its jump at the function start and relocates the displaced instructions. Very short functions, or code that branches back into its first few instructions, can fail with `unable to intercept function` or misbehave. Hook the caller, or use Stalker on a bounded window.

## Resolve The Target
Hook an export by module, an unexported function by RVA, or a symbol by debug info. Write down which. A hook on the wrong overload or the wrong module copy reports nothing and looks like "never called".

```javascript
// resolve.js — run with: frida -p "$PID" -l resolve.js
const MODULE = 'libtarget.so';        // module name as Process.enumerateModules() reports it
const EXPORT = 'parse_record';        // exported symbol, or null
const RVA = 0x1a450;                  // offset from the static image base, used when EXPORT is null

const mod = Process.getModuleByName(MODULE);
const target = EXPORT !== null ? mod.getExportByName(EXPORT) : mod.base.add(RVA);
console.log(`[resolve] ${MODULE} base=${mod.base} size=${mod.size} target=${target}`);
console.log(`[resolve] symbol: ${DebugSymbol.fromAddress(target)}`);
console.log(`[resolve] first insn: ${Instruction.parse(target)}`);
```

The RVA rule: `RVA = static_address − static_image_base`. In IDA that is `ea - idaapi.get_imagebase()`. For ELF that is the address in the disassembler minus the lowest `PT_LOAD` `p_vaddr` (often `0` for PIE, `0x400000` for non-PIE). For Mach-O, subtract the `__TEXT` vmaddr (usually `0x100000000`). On 32-bit ARM, add 1 for a Thumb function.

When the module loads late (a plugin, an `dlopen`ed `.so`, an unpacked payload), wait for it:

```javascript
// late_module.js
const MODULE = 'libtarget.so';
const RVA = 0x1a450;
let hooked = false;
function tryHook() {
    const mod = Process.findModuleByName(MODULE);
    if (mod === null || hooked) return;
    hooked = true;
    Interceptor.attach(mod.base.add(RVA), {
        onEnter(args) { console.log(`[late] hit a0=${args[0]}`); }
    });
    console.log(`[late] hooked ${MODULE}@${mod.base}`);
}
Process.attachModuleObserver({
    onAdded(module) { if (module.name === MODULE) tryHook(); }
});
tryHook();
```

`Process.attachModuleObserver` is Frida 17. On older versions hook `dlopen`/`android_dlopen_ext`/`LoadLibraryExW` and check after `onLeave`.

## Interceptor Patterns

Arguments, return value, and buffers that are filled by the callee. Read output buffers in `onLeave`, not `onEnter`.

```javascript
// decrypt_trace.js — hook void decrypt(const u8 *in, u8 *out, int len, const u8 *key)
const MODULE = 'libtarget.so';
const RVA = 0x1a450;
const target = Process.getModuleByName(MODULE).base.add(RVA);

Interceptor.attach(target, {
    onEnter(args) {
        this.out = args[1];
        this.len = args[2].toInt32();
        this.key = args[3].readByteArray(16);
        this.caller = DebugSymbol.fromAddress(this.returnAddress).toString();
    },
    onLeave(retval) {
        const n = Math.min(this.len, 256);
        send({ fn: 'decrypt', len: this.len, caller: this.caller }, this.out.readByteArray(n));
        console.log(hexdump(this.out, { length: Math.min(n, 64), header: false, ansi: false }));
    }
});
```

- `this` is per invocation and per thread. Store pointers on it in `onEnter`.
- `send(json, bytes)` delivers binary data to the client without hex encoding. `console.log` is fine for small text.
- `this.context` holds registers. `this.returnAddress`, `this.threadId`, and `this.depth` (recursion depth) are available.
- `retval.replace(ptr(1))` changes the return value. `args[0] = ptr(...)` changes an argument in `onEnter`.
- `Thread.backtrace(this.context, Backtracer.ACCURATE)` gives a stack. `ACCURATE` needs unwind info. `FUZZY` scans the stack and lies more often.

Replace a function and still call the original (verified):

```javascript
// replace.js — void xor_buf(u8 *in, u8 *out, int len, const u8 *key)
const target = Process.getModuleByName('libtarget.so').getExportByName('xor_buf');
const original = new NativeFunction(target, 'void', ['pointer', 'pointer', 'int', 'pointer']);
Interceptor.replace(target, new NativeCallback(function (inp, out, len, key) {
    console.log(`[xor_buf] len=${len} key=${hexdump(key, { length: 4, header: false, ansi: false })}`);
    original(inp, out, len, key);
}, 'void', ['pointer', 'pointer', 'int', 'pointer']));
```

Call a recovered routine yourself (an oracle for a hypothesis):

```javascript
// oracle.js — int check_key(const char *s, int len)
const checkKey = new NativeFunction(
    Process.getModuleByName('libtarget.so').getExportByName('check_key'), 'int', ['pointer', 'int']);
rpc.exports = {
    check(s) { return checkKey(Memory.allocUtf8String(s), s.length); }
};
```

From Python, `script.exports_sync.check("MAGICKEY-1234")` returns the target's own answer. Compare it with your reimplementation on many inputs before you claim the algorithm.

Windows note: name the calling convention when it is not the platform default, for example `new NativeFunction(p, 'int', ['pointer'], 'stdcall')` on x86.

## CModule For Hot Paths
JS callbacks cost a few microseconds each. A function hit millions of times needs C. `CModule` compiles C with the built-in TinyCC at load time (verified on macOS arm64):

```javascript
// hot_count.js
const target = Process.getModuleByName('libtarget.so').getExportByName('check_key');
const counters = Memory.alloc(8);
const cm = new CModule(`
#include <gum/guminterceptor.h>
extern volatile int hits;
extern volatile int long_inputs;
void onEnter(GumInvocationContext *ic) {
    int len = (int)(gsize) gum_invocation_context_get_nth_argument(ic, 1);
    hits++;
    if (len > 12) long_inputs++;
}
`, { hits: counters, long_inputs: counters.add(4) });
Interceptor.attach(target, cm);
setInterval(() => console.log(`[hot] hits=${counters.readS32()} long=${counters.add(4).readS32()}`), 1000);
```

A CModule exporting `onEnter`/`onLeave` is passed directly to `Interceptor.attach`. Share state through symbols you pass in the second argument. Read them from JS on a timer.

## Stalker For Coverage And Call Graphs
Follow one thread for a bounded window. Start in `onEnter` of the function you care about and stop in its `onLeave`. Following every thread for the whole run makes a GUI app unusable.

```javascript
// stalk_window.js — basic blocks and calls inside one function's dynamic extent
const mod = Process.getModuleByName('libtarget.so');
const target = mod.getExportByName('parse_record');
const end = mod.base.add(mod.size);
const blocks = new Set();

Interceptor.attach(target, {
    onEnter() {
        this.tid = this.threadId;
        Stalker.follow(this.tid, {
            events: { call: true },
            onCallSummary(summary) {
                for (const [addr, count] of Object.entries(summary)) {
                    const sym = DebugSymbol.fromAddress(ptr(addr));
                    if (sym.moduleName === mod.name) console.log(`[call] ${sym.name} x${count}`);
                }
            },
            transform(iterator) {
                let insn = iterator.next();
                const start = insn.address;
                if (start.compare(mod.base) >= 0 && start.compare(end) < 0) {
                    iterator.putCallout(() => { blocks.add(start.sub(mod.base).toInt32()); });
                }
                do { iterator.keep(); } while ((insn = iterator.next()) !== null);
            }
        });
    },
    onLeave() {
        Stalker.unfollow(this.tid);
        Stalker.flush();
        console.log(`[stalk] unique blocks in ${mod.name}: ${blocks.size}`);
    }
});
```

- Record RVAs, not absolute addresses. They line up with the disassembler.
- `putCallout` runs JS per block. For long windows, use a CModule transform or `events: { compile: true }` (one event per first execution of a block).
- `Stalker.exclude({ base, size })` skips a module, for example libc, to save time.
- Call `Stalker.garbageCollect()` after `unfollow` in long sessions.
- Lighthouse and Cutter load `drcov` files. Convert the RVA set to drcov format, or use `frida-itrace`/Luma when you need instruction traces.

## Enumerate And Search

```javascript
// discover.js
const resolver = new ApiResolver('module');
resolver.enumerateMatches('exports:*!*crypt*').slice(0, 20)
    .forEach(m => console.log(`[export] ${m.name} @ ${m.address}`));
resolver.enumerateMatches('imports:libtarget.so!*')
    .forEach(m => console.log(`[import] ${m.name}`));

const mod = Process.getModuleByName('libtarget.so');
// AES forward S-box prefix; '??' is a full-byte wildcard
for (const hit of Memory.scanSync(mod.base, mod.size, '63 7c 77 7b f2 6b 6f c5')) {
    console.log(`[scan] sbox at RVA 0x${hit.address.sub(mod.base).toString(16)}`);
}
// writable anonymous memory: decrypted strings and configs live here
for (const r of Process.enumerateRanges({ protection: 'rw-', coalesce: true })) {
    if (r.file !== undefined || r.size > 64 * 1024 * 1024) continue;
    try {
        for (const hit of Memory.scanSync(r.base, r.size, '68 74 74 70 73 3a 2f 2f')) {   // "https://"
            console.log(`[scan] ${hit.address}: ${hit.address.readUtf8String(64)}`);
        }
    } catch (e) { /* page vanished or guarded */ }
}
```

- `ApiResolver('module')` patterns are `exports:MODULE!NAME` and `imports:MODULE!NAME`, with `*` and `?` globs. Append `/i` for case-insensitive matching.
- `ApiResolver('objc')` uses `-[Class selector]` / `+[Class selector]` with globs. `ApiResolver('swift')` takes `functions:MODULE!NAME` and needs the Swift bridge loaded.
- `Memory.scanSync` throws on an unreadable page. Wrap per range.
- A scan returns `{address, size}`. Report RVAs for static correlation.

## Java (Android) And Objective-C
In the REPL the bridges are globals. In a compiled agent, `import Java from "frida-java-bridge"`.

```javascript
// android_trace.js — run with: frida -U -f "$PACKAGE_ID" -l android_trace.js
function hex(javaBytes) {   // Java byte[] arrives as a JS array of signed ints
    return Array.from(javaBytes, b => ((b & 0xff) | 0x100).toString(16).slice(1)).join('');
}
Java.perform(() => {
    const Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (input) {
        const out = this.doFinal(input);
        console.log(`[Cipher] ${this.getAlgorithm()} in=${input.length} out=${out.length}`);
        send({ alg: this.getAlgorithm(), input: hex(input).slice(0, 512), output: hex(out).slice(0, 512) });
        return out;
    };
    const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, alg) {
        console.log(`[SecretKeySpec] ${alg} key=${hex(key)}`);
        return this.$init(key, alg);
    };
    Java.choose('com.example.SessionState', {
        onMatch(obj) { console.log(`[choose] token=${obj.token.value}`); },
        onComplete() {}
    });
});
```

- Pick the overload explicitly. `Class.method.implementation = ...` fails when the method is overloaded. List them with `Class.method.overloads.map(o => o.argumentTypes.map(t => t.className))`.
- Field and method name clash: a field shadowed by a method is reached as `obj._name.value`.
- Classes loaded by a non-default class loader are invisible to `Java.use`. Enumerate loaders with `Java.enumerateClassLoadersSync()`, find the one where `loader.findClass(name)` succeeds, and use `Java.ClassFactory.get(loader).use(name)`.
- `Java.perform` runs after the VM is ready. In spawn mode, app classes may not be loaded yet. Hook `java.lang.ClassLoader.loadClass` or retry on a timer.
- Native JNI: `RegisterNatives` maps Java methods to native addresses. Hook `art::JNI::RegisterNatives` (resolve it with `ApiResolver('module')` and `exports:libart.so!*RegisterNatives*`) to learn the addresses.

```javascript
// objc_trace.js — run with: frida -U -f "$BUNDLE_ID" -l objc_trace.js
const sel = '- dataTaskWithRequest:completionHandler:';
const NSURLSession = ObjC.classes.NSURLSession;
Interceptor.attach(NSURLSession[sel].implementation, {
    onEnter(args) {
        // args[0]=self, args[1]=_cmd, args[2]=first ObjC argument
        const req = new ObjC.Object(args[2]);
        console.log(`[NSURLSession] ${req.HTTPMethod()} ${req.URL().absoluteString()}`);
    }
});
const resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[*Crypt* *]').slice(0, 20).forEach(m => console.log(m.name));
ObjC.choose(ObjC.classes.NSURLSessionConfiguration, {
    onMatch(cfg) { console.log(`[choose] proxy=${cfg.connectionProxyDictionary()}`); },
    onComplete() {}
});
```

Swift: mangled names are stable exports only when the symbol is public or not stripped. Find them with `ApiResolver('swift')` (Swift bridge) or `Process.getModuleByName(app).enumerateExports().filter(e => e.name.startsWith('$s'))`. Swift `async` functions and methods using the `swiftself` register (`x20`) or the error register (`x21`) need register-level reads from `this.context`, not `args[n]`.

## Early Instrumentation
Anti-analysis checks and key derivation often run before `main` or in the first `Application.onCreate`. Attach mode misses them.

| Need | Mechanism |
|---|---|
| Hook before the first instruction of the program | `frida -f PROGRAM -l x.js` spawns suspended, loads the script, then resumes. Add `--pause` to keep it paused until `%resume`. |
| Hook a process another process launches | Python: `device.enable_spawn_gating()`, handle `spawn-added`, attach, load, `device.resume(pid)` |
| Follow `fork`/`exec` children of your target | `session.enable_child_gating()`, handle the device's `child-added` signal, then `device.resume(child.pid)` |
| Constructor in a library you cannot reach yet | Hook the loader (`dlopen`, `android_dlopen_ext`, `LoadLibraryExW`) and install on `onLeave` |
| No frida-server possible | Gadget with `"on_load": "wait"` or a `script` interaction, see [frida.md](../04-tool-usage/frida.md) |

Spawn gating in Python:

```python
# gate.py — uv run --with "frida==17.*" python gate.py PROCESS_NAME agent.js
import queue, sys, time, frida

name, agent = sys.argv[1], open(sys.argv[2]).read()
device = frida.get_usb_device(timeout=5)
pending = queue.Queue()
device.on("spawn-added", pending.put)   # signal callbacks must not block; hand off to the main thread
device.enable_spawn_gating()
for spawn in device.enumerate_pending_spawn():   # gated before the handler existed
    pending.put(spawn)

deadline = time.monotonic() + 300
try:
    while time.monotonic() < deadline:
        try:
            spawn = pending.get(timeout=1)
        except queue.Empty:
            continue
        try:
            if spawn.identifier == name or spawn.identifier.endswith("/" + name):
                session = device.attach(spawn.pid)
                script = session.create_script(agent)
                script.on("message", lambda m, d: print(m, d[:32].hex() if d else ""))
                script.load()
                print(f"[gate] instrumented {spawn.identifier} pid={spawn.pid}")
        finally:
            device.resume(spawn.pid)    # always resume, or the gated process hangs
finally:
    device.disable_spawn_gating()
```

Signal callbacks run on Frida's event thread. Calling `attach` or `create_script` inside them can deadlock, so the script queues spawns and handles them on the main thread.

## Detection Vectors
Assume a protected target looks for Frida. Know what it can see, then decide whether to hide or to move the hook.

| Vector | What the target checks | Response |
|---|---|---|
| `frida-server` port | TCP 27042 open on localhost | Run the server on another port: `frida-server -l 127.0.0.1:41337`, client `-H 127.0.0.1:41337` |
| Server binary name | `frida-server` in the process list | Rename the binary |
| Injected agent | `frida-agent` or `frida-gadget` in `/proc/self/maps` or `dyld` image list | Gadget renamed and embedded; strings in the agent remain |
| Named threads | `gum-js-loop`, `gmain`, `gdbus`, `pool-frida` in `/proc/self/task/*/comm` | Hard to remove; hook the reader instead |
| Inline hooks | Function prologue differs from disk bytes | Hook the caller, use Stalker, or hook below the check |
| Named pipes / D-Bus | `linjector` pipes, D-Bus `AUTH` probes | Gadget avoids the injector |
| Memory scan | `LIBFRIDA` or `frida:rpc` strings in RX/RW memory | Strings live in the agent; scanning code can be hooked |
| `ptrace` | Injector briefly ptrace-attaches on Linux/Android | Spawn and instrument before the check, or Gadget |
| Timing | Stalker and hook latency | Narrow the hook window |

Detection code itself is a hook target. Find it (`openat` of `/proc/self/maps`, `strstr` with `frida`, `connect` to 27042), log it, and neutralize it in that order. Record each change. A bypass you cannot name hides the next check.

## Verification
- Before claiming "never called": print `DebugSymbol.fromAddress(target)` and `Instruction.parse(target)` to prove the address is the function's first instruction, and test the hook with a deliberate call (`NativeFunction`) or a known trigger.
- Before claiming an algorithm: drive the target's own function through `rpc.exports` on N inputs and compare with your reimplementation.
- Before claiming a key: show the bytes at the call to the cipher, the algorithm name, and one decrypted plaintext that matches traffic or a file.
- Record Frida client and server versions, the device or guest, the script hash, and every bypass in the evidence ledger.

## Boundaries
- Instrument only software you are authorized to analyze, inside the lab or on a test device.
- Do not `send()` or `console.log` per byte inside a tight loop. Aggregate in JS or C and flush on a timer.
- `recv().wait()` blocks the hooked thread until the client answers. On the UI thread that is an ANR or a watchdog kill.
- Keep observation first. Change return values only to get past a named check, and record it.
