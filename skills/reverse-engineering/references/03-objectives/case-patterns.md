# Field Case Patterns

## When To Open
Open this file when triage is done and the target matches a shape below, or when a straight read of `main` is not producing a falsifiable hypothesis. Each row is a hypothesis. Confirm it with an observation before promoting it. Promotion rules are in [Rule 11](../../rules/11-evidence-sufficiency.md). Comparison direction and decoy compares are in [Rule 7](../../rules/07-hypothesis-driven.md).

Do not paste a solver until the shape matches. Do not treat a file name, a section name, or a function name as the behavior.

## Detection Commands (Run These To Decide Which Shape)

These are the cheap probes that place a target in a section below. All are read-only.

- Carve embedded files and find the overlay: `binwalk target` (signatures), `binwalk -E target` (entropy map). A ZIP/PK blob inside `.rodata` is section 1, row 1.
- Find a known table or magic by bytes: `rafind2 -x 637c777b target` (AES S-box), `rafind2 -s 'expand 32-byte' target` (ChaCha), `rafind2 -x 1337babe target` (nanomite marker).
- Sections, entry, and a lying header: `rabin2 -S target` (sections), `rabin2 -I target` (bin info), `readelf -lh target` (program vs section headers — `e_shoff`/`e_shnum` corruption is section 5).
- Imports and dynamic resolution tell: `rabin2 -i target`. Only `LoadLibrary`/`GetProcAddress`/`dlopen` plus a hash compare is section 5.
- Constructors and exit handlers: `rabin2 -i target | grep -i init`, and check `.init_array`/`.fini_array`/`__cxa_atexit` (section 2, "real work is not in main").
- Signals and anti-debug syscalls: `rabin2 -i target | grep -iE 'ptrace|signal|sigaction|fork|rdtsc'` (section 2).
- Strings for a VM/DSL, a font, or a format-string bytecode: `rabin2 -z target | grep -iE 'opcode|dispatch|%hhn|GSUB|ligature'`.
- Width/sign mismatch to re-check against the decompiler: disassemble the exact range and read `movsx`/`movsxd`/`cdqe` yourself (section 6).

When a probe is rejected (a flag the local tool lacks, a `grep` miss), that is an observation to record, not a negative (Rule 3).

## 1. The Secret Is Already In The File

| You see | It was | Next |
|---|---|---|
| Named blobs such as `EMBEDDED_ZIP`, `ENCRYPTED_MESSAGE`, or `PK\x03\x04` in `.rodata` | License and ciphertext both sit in the file. A date check is a decoy. | Carve the ZIP and XOR offline. Do not run the binary to pass the expiry check. |
| Input is rendered and compared to a pixel buffer | The expected bitmap is the secret, often XOR'd with one constant in `.rdata`. | Carve the buffer, undo the constant, save the image. OCR only after the pixels are real. |
| Input is hex-encoded, then compared to a hex constant | The constant is the secret. | Decode the constant. Do not reverse the encoder. |
| A side-channel cipher (cache, Spectre-style) whose S-boxes and round keys are in the data section | The hardware effect is a disguise. The parameters are static. | Extract tables and keys. Do not require special hardware. |
| `mmap` of a `.rodata` blob, then an XOR loop, then a checker that uses `0x9E3779B9`, `0x85EBCA6B`, or `0xA97288ED` | Stack-string / hash-mix checker. The expected bytes are in the decrypted blob. | Decrypt the blob, then invert the mix. Undo position permutation before the state update. |
| Hundreds of near-identical functions, each touching a few input indexes and branching two ways | An auto-generated decision tree. The leaf holds the real check. | Script the extraction. Do not read the functions one by one. |
| A matrix in `.rodata` whose side is the secret length, XOR row ops, and the constant `0x1b` or `0x11b` | Gaussian elimination over GF(2^8), usually the AES polynomial. Addition is XOR. | Solve the field system. A later AES-GCM wrap is not the secret; the solution vector is. |
| Grouped characters multiplied by large coefficients and compared to 64-bit constants, with a printable-ASCII constraint | A lattice / closest-vector problem. Plain algebra yields non-ASCII solutions. | Use LLL/CVP. Brute force is the wrong scale when a group is `256^4`. |
| A single-line script of walrus or bitwise chains ending in one comparison | A boolean circuit. `(a \| b) & ~(a & b)` is XOR. | Split on separators and solve with Z3. |
| A custom font, or GSUB / ligature tables | The displayed glyph is not the stored character. | Dump the font (`ttx` or equivalent) and read the substitution table. |
| A PNG or texture named like a program, plus a shader that stores into it | The image is the bytecode. GPU parallelism corrupts self-modifying stores. | Emulate the shader sequentially. |
| Square weight matrices, sigmoid or tanh, and a `1/x` on the input | An invertible network. | Invert layer by layer: inverse activation, subtract bias, multiply by the inverse weights, then undo `1/x`. |
| Burrows-Wheeler without a terminator | Every rotation is a candidate. | Keep the candidate that matches a known prefix or framing. |
| Brainfuck that is `,` then a run of `+` or `-` per character | The increment count is the expected byte. | Count the run. A cell reset between commas means each character is independent. |
| Python bytecode the stock decompiler rejects | Opcodes were remapped. | Diff the bundled `opcode` map, or decompile with the sample's own interpreter. Pyarmor 8/9 (`PY` plus six digits, plus `pyarmor_runtime`) is a static unpack, and the disassembly outranks the experimental decompile. |
| A PE whose DOS stub is far larger than a stub | A 16-bit DOS program lives before the PE header. | Load the stub as 16-bit. Look for `int 16h`. |

## 2. The Real Work Is Not In `main`

| You see | It was | Next |
|---|---|---|
| `main` is thin, and `.fini_array` or `__cxa_atexit` is populated | A C++ destructor or atexit handler holds the check. | Read the fini path before concluding the program does nothing. |
| `fork` plus the child calling `ptrace(TRACEME)`, or `WaitForDebugEvent` | Nanomites. The parent is the CPU. Magic markers include `0x1337BABE` and `0xDEADC0DE`. | Log the parent's writes (`PTRACE_POKETEXT` or the debug-event write). The child alone is not the algorithm. |
| `SIGTRAP`, `SIGILL`, `SIGFPE`, or `SIGSEGV` raised on purpose, with a handler installed | The handler is the next instruction, not an error. | Break in the handler. Stepping the faulting instruction skips the real work. |
| Several threads: one does AES-like work then `ud2`, one installs a signal handler, one zeroes a buffer, and `rdtsc` is present | The crashing thread is a decoy. The handler is the algorithm. The eraser exists so a late dump is empty. | Lift the handler. A debugger trip on `rdtsc` corrupts the result. |
| `signal()` or `sigaction` called again only after a character matches | Installing the next handler is the oracle. | Hook `signal` / `sigaction` and see which input advances the chain. |
| `sigaction` with `SA_SIGINFO` and `sigaltstack`, two signals at a time | A binary tree of handlers. A leaf exits. A node installs two children. | Walk it. A wrong leaf means try the sibling. |
| `setsockopt(SO_ATTACH_FILTER)` or a `sock_fprog` blob | Validation is BPF. | Dump with `seccomp-tools`, or JIT the filter (`bpf_jit_enable`) and read the native code when the BPF disassembly is unreadable. Lift comparisons to constraints. |
| A format string made of `%Nc%hhn` | `%hhn` writes the printed count mod 256. The string is a bytecode VM. | Recover each write's address and value, then solve the equations. |
| MFC / `AFX_MSGMAP` | The dialog procedure is not `WinMain`. | Enumerate the message map. |
| A Windows driver whose `DriverEntry` is short | The behavior is in `MajorFunction`, especially `IRP_MJ_DEVICE_CONTROL`. | Build the IOCTL-to-handler table. Record a vulnerable-driver suspicion by name, hash, and capability. Do not write an exploit. |
| A `.ko` that registers a `binfmt` and maps a non-ELF blob | The kernel decrypts a flat binary and jumps to a fixed address. | Take the load address from the `vm_mmap` argument. The key is often an immediate, not a data-section string. |
| GDB and a normal run disagree, `ldd` shows a non-system libc, and the binary is setuid | The debugger dropped the setuid bit, so the backdoored libc took another path. | Diff `strings` of that libc against a stock one. |

## 3. Oracles: Stop Reading When One Byte Moves One Output

| You see | It was | Next |
|---|---|---|
| Changing input byte `i` changes only output byte `i` | No diffusion. A block cipher that behaves this way is a per-byte map. | Build the 256-to-1 map, or match the target byte directly. |
| Repeating-key XOR fits the known prefix, then drifts by about `+1` per index | `cipher[i] = plain[i] ^ key[i % k] ^ i`. | Strip `i` before recovering the key. |
| One digest per prefix, and editing the last character edits only the last digest | Independent prefix hashes. | Recover one character at a time. This is not an HMAC. |
| Runtime grows when the prefix is correct | A timing oracle, often a sleep on match. | Measure in the lab. Do not single-step the checker. |
| Coverage, a branch log, or an `xdebug` dump shows which `chr(N)` branch ran | The branch set leaks the intermediate. | Intersect that set with a known prefix. |
| The program reads more input, or calls `read` again, only when the current character is right | A consume-count oracle. Brainfuck `,` and libc `read` both do this. | Count the reads per candidate. |
| A crash dump or an `int3` sits just after the transform | The core holds the computed buffer. | Patch the stop in a lab copy and read the dump. Do not reverse the transform first. |
| Self-modifying blocks decrypt with the input character, and the next block starts with a known prologue | The prologue is known plaintext. | Recover one key byte per block (`endbr64; push rbp; mov rbp, rsp` is the usual x86-64 prologue). |
| Many binaries, same shape, different immediates | A batch crackme. | Parse the immediates and solve the algebra. Do not emulate each file. |
| Layers that decrypt the next layer, and a wrong key yields garbage code | The oracle is a structural tell in the next layer, such as "exactly two `call read`". | Brute the small key in-process. A Python subprocess per guess will not finish a deep stack. |
| A VM whose blocks are small and each block's output is the next block's key | Intended brute force, in order. | Brute one block. Do not invert a hash. |
| A date or Unix timestamp compared against the clock | The key is the date. | Try `faketime` before a deep read. |

## 4. Virtual Machines And Custom ISA

Dispatch loop plus a bytecode blob: recover the opcode table, write a disassembler, then read the program. Do not start with the algorithm.

| You see | It was | Next |
|---|---|---|
| `switch (opcode)` over registers and a memory array | A textbook stack or register VM. | Name handlers, then lift. |
| Handlers are RVAs, and each handler loads the next RVA | Threaded code, not a switch. | Follow the RVA chain and map handlers. |
| The dispatcher is too tangled to read, and instructions look variable-width | The ISA is recoverable by probing. | Try widths around 6–11 bits. Send one instruction and record register and memory deltas. XOR and ADD can be built from AND/OR/NOT once the ISA is known. |
| A non-standard opcode on an otherwise known ISA (CHIP-8 `FxFF` and similar) | The extra opcode is the real function, often a crypto call. | Disassemble every dispatch arm. Hook the crypto init if the key is runtime-only. |
| 16 threads, futex or channel reads and writes, a base-4 state machine | A pipeline VM. Constants may be a futex return or a thread id. | Label each thread by which channel it reads and which it writes. |
| JS IIFE, `var U=void 0`, a `switch` on `word & 31`, a constant pool `C[n]`, and almost no NUL bytes | A JS DSL VM, not WASM. WASM is `\0asm` or a high NUL ratio. | Map the small-integer aliases, classify opcodes, then find the export in the constant pool. Standard webpack is a different file. |
| `%hhn` format programs, BPF, or a shader texture | The VM is not in a switch. | Use the matching row in section 2 or section 1. |
| Outer packer, then a fetch-decode loop | Unpack first. Virtualized functions stay black boxes until a trace matches input and output. | [unpacking-memory-dump.md](../02-dynamic-instrumentation/unpacking-memory-dump.md), [deobfuscation-anti-analysis.md](../01-static-architectures/deobfuscation-anti-analysis.md). |

Control-flow flattening (`while (1)` plus a state compare such as `i == 0xA57D3848`) is the OLLVM case. Trace the state variable. Do not copy that procedure here.

## 5. Loaders, ELF Lies, And Mixed Mode

| You see | It was | Next |
|---|---|---|
| `file` and the extension disagree (`.sh`, `.txt`, `.jpg`, `.dll`, no suffix) | The extension is camouflage. | Trust magic bytes. A `.dll` may be a .NET assembly. A `.so` may be an encrypted blob. |
| `e_shoff`, `e_shnum`, or `e_shstrndx` is corrupt, and `readelf` or the decompiler crashes, but the file runs | Section headers are for tools. The loader uses program headers. | Parse `PT_LOAD`, or zero the section-header fields and reload. The secret is often past the table, behind a magic marker. |
| `e_shoff == 0` on a stripped ELF | Normal strip, not corruption. | Use program headers and dynamic symbols. |
| Entry calls `mmap` with `PROT_EXEC`, copies, then jumps | The real code is the mapped blob, often XOR'd. | Dump after the copy. A 3-byte rotating XOR is the usual first try. |
| `retf` (`0xCB`) or `retfq` (`0x48 0xCB`) from a 64-bit stub into SSE (`psubb`, `pxor`, `paddb`) | A 32-bit blob. `retf` pops 6 bytes (EIP plus CS), not 8. | Emulate in 32-bit mode and copy GPRs, EFLAGS, and XMM both ways. |
| Zero imports, a hash compare, then `dlopen` | Hash-resolved APIs. | Hook the resolvers and the crypto imports in the lab. Do not rainbow-table the hash first. |
| `LoadLibrary` and `GetProcAddress` only | The same pattern on Windows. | Already the clean-import gate in `SKILL.md`. Break on the resolver. |
| Nested stubs, each XOR-decoding then `call rax` | Multi-stage shellcode. | Dump each stage at the call. The last stage often materializes the secret as immediate `mov` chunks. |
| A name like `DriverLoader` or `Updater` with `ptrace` and `/proc/<pid>/mem`, and no `init_module` | Process injection, not a driver and not an updater. | Follow the inject path. Decrypt the embedded blob before naming the sample. |
| Recursive `execve` of the same binary, subtracting a constant each time | The base case is the answer. | Solve backward from the base case. |

## 6. Decompiler Lies

Check the bytes when the decompiler and the instruction disagree.

| You see | It was | Next |
|---|---|---|
| `movsx`, `movsxd`, or `cdqe` on a value used in XOR or a 64-bit subtract | XOR wants the low byte. A 64-bit add sign-extends. `cdqe` turns `0xFFFFFFFF` into `-1`. | Recompute the width from the instruction, not from the pseudocode type. |
| A loop jumps into its middle, and the next iteration uses the old index | Duff-style or split update. The decompiler merges the iterations. | Mark which iteration uses the pre-increment value. |
| Fisher-Yates from 255 downward, or xorshift shifts `13,17,5` or `12,25,27` times `0x2545F4914F6CDD1D` | The PRNG family is identified. The seed finishes it. | Reimplement the generator. `0x9E3779B97F4A7C15` is the splitmix/golden-ratio constant, not by itself an algorithm. |
| SHA-256 IVs (`0x6A09E667`, …) used as a byte lookup, not a hash | An S-box made from those words. | Treat them as a table. |
| A register incremented on almost every instruction and then mixed into each input byte | An instruction counter is part of the key. | Byte-at-a-time emulation. A closed-form inverse is usually wrong because the counter depends on the path. |

## 7. Platform Shapes That Change The First Tool

| You see | It was | Next |
|---|---|---|
| Java `native` method, `System.loadLibrary`, and no `Java_` symbol | `RegisterNatives` in `JNI_OnLoad`. | Read the `{name, signature, fnPtr}` table. Prefer the x86_64 `.so` for decompilation when several ABIs ship. |
| Native code reads `/proc/self/maps`, `mprotect`s a DEX, and XORs offsets | The static `classes.dex` is not the code that runs. Dalvik-era, not ART. | Apply the same XOR from the `.so`, then fix the DEX checksum before jadx. |
| JNI name encodes the package, and the Java layer is a pile of checks before the native call | The native function is the algorithm. The Java checks are a gate. | Call the native method with a matching class name in a lab harness, or hook it. |
| ESP32 / Xtensa firmware and IDA has no ROM names | The ROM map is public (`esp32.rom.ld` and the ESP-IDF linker scripts). | Load those symbols, then match HTTP and Wi-Fi handlers to the SDK examples. |
| `ioctl` on a custom `/dev` node from a kernel module | The maze, the flag, or the command set is the ioctl protocol. | Probe ioctls from a small static client in a lab VM. A stripped module is slower to read than its ioctl surface. |
| Keyboard `ioctl` `KDSETLED` | Morse or another code on the LED bits. | `strace -e ioctl`. The gap between calls is dot versus dash. |
| HarmonyOS `.hap` with `.abc` inside | Ark bytecode, not DEX. | Decompile the `.abc`. Do not send it to jadx as a DEX. |
| UEFI volume, or a binary whose base is set near the top of the address space | A DXE driver. | Extract with UEFITool and set the base before decompiling. |

## 8. What These Cases Do Not Change

- Packed bytes are still unpacked before a decompiler claim. See [Rule 9](../../rules/09-anti-patterns.md).
- A dynamic hit still has to be re-anchored, or it stays `runtime-only`. See [Rule 4](../../rules/04-static-dynamic-loop.md).
- Crypto constants and modes stay in [algorithm-recovery.md](algorithm-recovery.md). This file only says which shape to test first.
