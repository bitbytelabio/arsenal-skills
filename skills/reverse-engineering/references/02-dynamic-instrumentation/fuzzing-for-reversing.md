# Fuzzing For Reverse Engineering

## When To Open
Open this file when a reversing question is "which input reaches this block, field, or compare", or when obfuscation has made the decompiler untrustworthy and the logic has to be inferred from input and output. Fuzzing here is an oracle for a hypothesis. It is not an exploit workflow. A crash is an address to re-open in the decompiler. Turning that crash into code execution is out of scope. See [vuln-research-patch.md](../03-objectives/vuln-research-patch.md) for the source, sink, and guard bar.

Run the campaign inside the containment in `SKILL.md` and [malware-sandbox-isolation.md](malware-sandbox-isolation.md). A fuzzer executes the target thousands of times per second. `qemu-user` and AFL++ QEMU mode are emulation, not containment. Malware and packers stay offline. Fuzz the decoder, the config parser, or the command parser. Do not let the sample open a real network connection.

## The Question Comes First
Write the hypothesis before the first `afl-fuzz`. A readable function can name a block. An obfuscated function often cannot. Then the hypothesis names a behavior you can measure: a coverage cluster, an API hit, or an input/output pair.

- This parser rejects inputs until a magic and a length agree.
- Byte `N` of the file selects the handler at this switch.
- This compare is the last check, and earlier compares are decoys.
- The embedded sample in `.rodata` is a valid seed for the same parser.
- Mutating only byte 0 splits coverage into a handful of clusters, so byte 0 is an opcode.
- This flattened function is XOR-with-index, because the output matches that transform on a known buffer.

If you cannot say what a new input would confirm or refute, do not start a campaign.

## Input Channel
Name how the program reads bytes. The wrong channel fuzzes nothing and still prints a confident empty result.

| The program reads | Feed it with | Wrong invocation |
|---|---|---|
| A path in `argv` | `afl-fuzz ... -- ./target @@` | No `@@`. The fuzzer writes a file the program never opens. |
| `stdin` | `afl-fuzz ... -- ./target` | `@@`. The file is created and ignored. |
| A fixed path | `afl-fuzz -f /tmp/fixed.cfg ... -- ./target` | `@@` when the path is hard-coded. |
| A socket | A desocket preload (`AFL_PRELOAD` of a `libdesock`-style shim) so `accept`/`read` return the fuzz buffer | Fuzzing the client against a live host. |
| One function you already typed | An in-process harness (`LLVMFuzzerTestOneInput`, AFL persistent loop, or a persistent hook) that calls that function | Fuzzing `main` and hoping to pass the UI. |
| Nothing (no file, argv, or socket) | Do not fuzz. A clean run is not evidence. Read the code. | Any campaign. |

Foreign architectures need a QEMU build of AFL++ for that architecture, or a host harness that calls lifted or reconstructed code. Match endianness, and read it from the ELF header (`file`: `MSB` big, `LSB` little). The vendor does not predict it: Broadcom BCM63xx is big-endian MIPS, BCM47xx/53xx is little-endian. See [firmware-iot.md](../01-static-architectures/firmware-iot.md).

## Pick The Engine

| Situation | Engine | Command shape |
|---|---|---|
| Closed Linux ELF, runs in the container | AFL++ QEMU mode | `afl-fuzz -Q -i seeds -o out -- ./target @@` |
| Same, compares block progress | QEMU + CmpLog on the same binary | `afl-fuzz -Q -c 0 -i seeds -o out -- ./target @@` |
| Same, one function is the target, process start is slow | QEMU persistent mode + input hook | `AFL_QEMU_PERSISTENT_ADDR`, `AFL_QEMU_PERSISTENT_HOOK` (below) |
| Closed ELF, native speed instrumentation, no QEMU | AFL++ FRIDA mode | `afl-fuzz -O -i seeds -o out -- ./target @@` |
| Closed Windows binary | WinAFL (DynamoRIO or TinyInst) or Jackalope | `-instrument_module`, `-target_method` |
| Closed macOS binary | Jackalope (TinyInst), or AFL++ FRIDA mode | same |
| Source or a rebuildable harness | `afl-clang-fast` / `afl-clang-lto` persistent mode, or libFuzzer | `-fsanitize=fuzzer,address` |
| Kernel or a target that needs a whole OS state | Snapshot fuzzing: WTF (Windows), Nyx (`afl-fuzz -X`), LibAFL QEMU system mode | Snapshot after init |
| Custom feedback, odd targets, research | LibAFL (Rust library, build your own fuzzer) | `libafl_qemu`, `libafl_frida`, `libafl_targets` |
| One byte or one enum | A loop that tries every value | No fuzzer needed |

## AFL++ On A Closed Binary
Every command below ran in the `aflplusplus/aflplusplus` image (AArch64) against a small parser built from source and treated as closed. The parser checks a `RCFG` magic, a 16-bit length, and an opcode; opcode 3 has a stack overflow.

Container environment that AFL++ needs in Docker:

```bash
export AFL_SKIP_CPUFREQ=1                       # no cpufreq governor in a container
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  # core_pattern is the host's
export AFL_NO_UI=1                              # line output, safe for logs
```

| Mode | Command | 15 s result (execs / edges / crash) |
|---|---|---|
| QEMU + CmpLog | `afl-fuzz -Q -c 0 -i seeds -o out_q -V 15 -- ./parser @@` | 79.5k / 54 / yes |
| QEMU persistent, no hook | `AFL_QEMU_PERSISTENT_ADDR=... afl-fuzz -Q ... -- ./parser @@` | 799k / 16 / no — every iteration parsed the same buffer |
| QEMU persistent + hook | as below | 1.85M / 27 / yes, 123k exec/s |
| FRIDA mode + dictionary | `afl-fuzz -O -i seeds -o out_f -V 15 -x rcfg.dict -- ./parser @@` | 39.6k / 25 / yes |
| `afl-clang-fast` + ASan | `afl-fuzz -i seeds -o out_s -V 15 -x rcfg.dict -- ./h_afl` | 8.9M / 12 / yes |
| libFuzzer + ASan | `./h_lf -max_total_time=15 -dict=rcfg.dict corpus/` | ASan `stack-buffer-overflow` in `memcpy` |

Read the persistent row carefully. Persistent mode restarts execution at the persistent address with saved registers. If the input is read before that address (here, `main` reads the file and then calls `parse_record`), every iteration sees the first input. Exec/s goes up, coverage stays flat, and nothing is found. A fast campaign with a flat map is the symptom.

### QEMU persistent mode with an input hook
The hook copies each fuzz input into the target's buffer at the persistent address. Verified for AArch64 (`parse_record(buf, len)` takes `x0`, `x1`):

```c
// hook_arm64.c — gcc -shared -fPIC -O2 -o hook.so hook_arm64.c
#include "/AFLplusplus/qemu_mode/qemuafl/qemuafl/api.h"   // path inside the aflplusplus image
#include <string.h>

void afl_persistent_hook(struct arm64_regs *regs, uint64_t guest_base,
                         uint8_t *input_buf, uint32_t input_buf_len) {
    if (input_buf_len > 4096) input_buf_len = 4096;           // size of the target's buffer
    memcpy((void *)(regs->x0 + guest_base), input_buf, input_buf_len);
    regs->x1 = input_buf_len;
}

int afl_persistent_hook_init(void) { return 1; }              // 1 = shared-memory input
```

```bash
OFF="0x$(nm parser | awk '/ T parse_record$/{print $1}')"     # or the RVA from IDA for a stripped binary
export AFL_QEMU_PERSISTENT_ADDR="$(printf '0x%x' $((0x5500000000 + OFF)))"
export AFL_QEMU_PERSISTENT_GPR=1 AFL_QEMU_PERSISTENT_CNT=10000 AFL_QEMU_PERSISTENT_HOOK="$PWD/hook.so"
afl-fuzz -Q -i seeds -o out -V 600 -- ./parser seeds/s1
```

- PIE base under QEMU mode: `0x4000000000` for x86-64, `0x40000000` for 32-bit, usually `0x5500000000` for AArch64. Non-PIE binaries use the absolute address.
- With a shared-memory hook, pass a real seed path instead of `@@`. AFL++ prints `switching to shmem` and removes `@@`. The program must still reach the persistent address on its own.
- x86-64 uses `struct x86_64_regs` and `regs->rdi`/`regs->rsi`. The upstream example is `utils/qemu_persistent_hook/read_into_rdi.c`.
- `AFL_QEMU_PERSISTENT_RET` or `AFL_QEMU_PERSISTENT_RETADDR_OFFSET` tells QEMU where the iteration ends when the function does not return normally.
- FRIDA mode has the same knobs: `AFL_FRIDA_PERSISTENT_ADDR`, `AFL_FRIDA_PERSISTENT_CNT`, `AFL_FRIDA_PERSISTENT_HOOK`, `AFL_FRIDA_PERSISTENT_RET`. Limit instrumentation with `AFL_FRIDA_INST_RANGES` / `AFL_FRIDA_EXCLUDE_RANGES`.
- QEMU mode instruments only the main binary by default. `AFL_INST_LIBS=1` adds libraries. `AFL_QEMU_INST_RANGES` narrows it to the module you care about.

### Compares, dictionaries, and checksums
- CmpLog (`-c 0` with `-Q` or `-O`; `-c ./cmplog_build` for source builds) records compare operands and splices them into inputs. It solved the 4-byte magic here without a dictionary. `-l 2AT` raises CmpLog intensity and adds arithmetic and transform solving.
- `AFL_COMPCOV_LEVEL=2` with `-Q` splits multi-byte compares into byte compares (QEMU's laf-intel equivalent).
- Dictionary file format: one token per line, `name="value"`, hex escapes allowed: `magic="RCFG"`, `op2="\xef\xbe\xad\xde"`. Pass with `-x file` (up to four).
- A CRC or hash over the input does not fall to CmpLog. Patch the check in a lab copy, or recompute the checksum in the hook, and record that the check itself was not tested.

### Seeds
An empty seed of `AAAA` never reaches a parser that demands a header.
- Seed with a real input: a file the binary ships, a carved `.rodata` blob, a minimized PCAP payload, or the smallest sample that passes the first check.
- Grammar or structure-aware mutation is for a format you have already partly recovered. Do not invent a grammar to avoid reading the length field.
- A dumb loop is enough when the space is one byte or one enum and you only need the value that flips a branch.

## Harness For A Recovered Function
When only one function matters and you can call it, an in-process harness is faster and gives sanitizers.

With source or a rebuild:

```c
// harness.c — clang -g -O1 -fsanitize=fuzzer,address harness.c parser.c -o h_lf
#include <stdint.h>
#include <stddef.h>
int parse_record(const uint8_t *buf, size_t n);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1 << 20) return 0;
    parse_record(data, size);
    return 0;
}
```

The same file builds for AFL++ with `afl-clang-fast -g -fsanitize=fuzzer harness.c parser.c -o h_afl` (AFL++ supplies the `main` through its libFuzzer driver) and runs as `afl-fuzz -i seeds -o out -- ./h_afl`. Add `AFL_USE_ASAN=1` at build time for ASan.

Without source, call the function inside the closed binary:
- **Shared library target**: `dlopen` the `.so`, resolve the export or `base + RVA`, cast to the recovered prototype, call it from `LLVMFuzzerTestOneInput`. Instrument with FRIDA mode or QEMU mode (`AFL_INST_LIBS=1` plus `AFL_QEMU_INST_RANGES`), because the library has no compile-time coverage.
- **Executable target**: convert the PIE executable to a loadable library with LIEF (`binary.add_exported_function(rva, "parse_record")`, clear `DF_1_PIE` from `DT_FLAGS_1`, write a new file), then treat it as a library. Global constructors and missing initialization are your problem; call the init routine the binary would have called.
- **Any binary under QEMU**: the persistent hook above, with no rebuild at all.
- Write down the prototype you assumed and how you checked it (decompiler signature, a debugger breakpoint showing the argument registers). A wrong prototype fuzzes garbage.

ASan exists only in rebuilt or harness-linked code. A QEMU or FRIDA campaign on a closed binary detects crashes, not silent corruption. AFL++ `libqasan.so` (`AFL_USE_QASAN=1` with `-Q`) adds heap checking for QEMU mode; in the AArch64 test image it rejected a benign seed as crashing, so run one known-good input through it before a campaign. Say which you ran.

## Other Engines

### libFuzzer
```bash
./h_lf -max_total_time=600 -timeout=5 -rss_limit_mb=2048 -dict=rcfg.dict -artifact_prefix=crashes/ corpus/ seeds/
./h_lf -minimize_crash=1 -runs=10000 -exact_artifact_path=min.bin crashes/crash-HASH
./h_lf -merge=1 corpus_min/ corpus/        # corpus minimization
./h_lf crashes/crash-HASH                  # reproduce one input
```

### honggfuzz
```bash
honggfuzz -i seeds -o corpus --crashdir crashes -t 5 -n 4 --run_time 600 -w rcfg.dict -- ./target ___FILE___
honggfuzz -i seeds -P -- ./target_persistent                  # persistent mode, HF_ITER-based harness
honggfuzz -i seeds --linux_perf_bts_edge -- ./closed_target ___FILE___   # hardware branch tracing, no rebuild
```
`___FILE___` is honggfuzz's input placeholder. `-s` feeds stdin. `--linux_perf_*` and `--linux_perf_ipt_block` need perf access on bare-metal Intel or a VM that passes it through.

### Jackalope (Windows, macOS, Linux; TinyInst)
```bash
./fuzzer -in in -out out -t 1000 -delivery shmem -instrument_module target -target_module harness \
  -target_method fuzz -nargs 1 -iterations 10000 -persist -loop -cmp_coverage -- ./harness -m @@
```
`-instrument_module` is where coverage comes from. `-target_module`/`-target_method` is the function looped in persistent mode. `-delivery shmem` replaces `@@` with a shared-memory name the harness must open. `-cmp_coverage` breaks multi-byte compares. Use `-nthreads N` for parallel workers and `-restore` to resume.

### WTF snapshot fuzzing (Windows user and kernel mode)
1. Put the target VM in the state just before the code you want, under a kernel debugger (KD).
2. `!snapshot C:\wtf\targets\NAME\state` with the `snapshot` extension writes `mem.dmp` and `regs.json`.
3. Write a fuzzer module that inserts each test case into memory and registers, and defines when an iteration ends.
4. Run a server and clients:
```cmd
wtf.exe master --name NAME --max_len=1028 --runs=10000000
wtf.exe fuzz --name NAME --backend=bochscpu --limit 10000000
wtf.exe run --name NAME --input crashes\crash-... --trace-type=rip
```
Develop on the `bochscpu` backend (deterministic, traces, built-in coverage). Move to `whv`/`kvm` for speed after the module is right; those need a coverage breakpoint file generated from IDA (`gen_coveragefile_ida.py`). Snapshot fuzzing skips the whole init path and any anti-analysis that runs there.

### LibAFL
LibAFL is a Rust library, not a binary. Use it when AFL++'s knobs are not enough: custom feedback (an output hash, a handler ID, a register value at a breakpoint), unusual targets, or QEMU system-mode snapshots. Start from the repository's `fuzzers/` examples closest to the target (`qemu_launcher` for closed ELF via QEMU, `frida_*` for in-process FRIDA instrumentation). A custom feedback that rewards new values of the variable you are studying is often a better oracle than edge coverage on obfuscated code.

## Coverage As The Oracle
New coverage is the reversing result. A crash is a second result. Neither is a vulnerability by itself.

```bash
afl-showmap -Q -o seed.map -- ./parser seeds/s1          # edge tuples for one input
afl-showmap -Q -o new.map  -- ./parser out/default/queue/id:000005*
comm -3 <(cut -d: -f1 seed.map | sort) <(cut -d: -f1 new.map | sort)   # edges in one map only (column 1: seed, column 2: new)
afl-cmin -Q -i out/default/queue -o corpus_min -- ./parser @@
afl-tmin -Q -i out/default/crashes/id:000000* -o min.bin -- ./parser @@
cmp -l seeds/s1 min.bin                                  # the bytes that changed are the field you found
```

- `afl-showmap` on QEMU mode produced 41 edge tuples for the seed in the test run. Inputs rejected early hit a subset of the seed's edges, so a reject shows only in column 1. An input that reached a new switch case added an edge in column 2. Map an edge back to blocks with `AFL_QEMU_DEBUG_MAPS` or by recording block addresses with FRIDA mode's `AFL_FRIDA_INST_COVERAGE_FILE` (drcov, loadable in Lighthouse).
- To test "byte `N` is an opcode": mutate only byte `N` across 0–255 with a loop, run `afl-showmap` on each, and cluster the maps. A few stable clusters confirm it.
- To test "this compare is the gate": run the seed with and without the patched compare and diff the maps.

## Deep Campaigns On Obfuscated Code
Flattened control flow, virtualized handlers, mixed boolean-arithmetic, and encrypted strings do not yield to one short run. The decompiler output is a candidate at best. The logic is whatever input/output relation survives. Go deep by stacking bounded runs. Each run has one hypothesis, one stop condition, and a corpus the next run inherits. A flat map after the harness is honest is a dead end. Record it. Do not add hours to the same question.

Do this before trusting any edge count:
- If every input exits immediately, the fuzzer is executing the anti-debug or anti-VM check, not the payload. Neutralize that check in a lab copy, record the patch, and start again. A map of the exit path is not a map of the logic.
- Prefer QEMU mode or a snapshot taken after the checks. A debugger-attached fuzzer trips `rdtsc` and integrity checks and then mutates the wrong program.
- Raw edge counts lie inside bogus control flow. The junk blocks grow the map without revealing the transform. Count hits on the blocks or APIs you named (the consumer `strcmp`, the VM handler table, the crypto call), or count distinct outputs. Do not treat "edges went up" inside a dispatcher as understanding.
- Fuzz one layer. The output of the unpacker or the string decryptor, minimized, is the seed for the next layer. Fuzzing the packer and the payload as one black box mostly rediscovers the stub.

| Hypothesis | What you mutate | Stop when |
|---|---|---|
| Byte or field `i` is an opcode or a type tag | Only that byte, across the whole range | Coverage or the API trace falls into a few stable clusters, or it does not |
| The virtual machine dispatches on this buffer | The bytecode or the buffer at VM entry, not `main` | Each cluster corresponds to one handler. Name the handler by its stack effect or its API, not by a full lift |
| This function is a simple transform (XOR, add, rotate, index mix) | A known buffer, one campaign per candidate transform | The candidate matches the observed output on that buffer. One match is a candidate. A second buffer validates it |
| This loop decrypts | One input bit at a time | One input bit flips one output byte: a stream or XOR. One input bit flips most output bytes: diffusion, stop treating it as XOR |
| Opaque predicates are noise | Do not fuzz the predicate. Evaluate it once | A predicate that is constant on every concrete input is not a branch. Drop it and fuzz the remaining block |
| Strings are encrypted until a consumer | The input that reaches `strcmp`, `dlsym`, or `FindClass` | You have the plaintext. That plaintext is a dictionary token for the next stage |

Virtualized handlers stay black boxes until a trace matches input and output. A deep campaign that lists handlers and their effects is the result. It is not a claim that the VM was fully lifted. The lift, if you still need it, stays in [deobfuscation-anti-analysis.md](../01-static-architectures/deobfuscation-anti-analysis.md).

Write each rejected guess into `dead_ends` before the next stage. The next hypothesis has to be different. Three stages with no new cluster, no new plaintext, and no input/output match are a deadlock under Rule 11.

## Reading The Campaign
- `out/default/fuzzer_stats` holds `execs_done`, `execs_per_sec`, `corpus_count`, `edges_found`, `bitmap_cvg`, `saved_crashes`, `saved_hangs`. Record them at the start and at the stop condition. `afl-whatsup out/` summarizes parallel instances.
- A flat measurement means the seed never entered the function, the harness calls the wrong entry, persistent mode replays one input, or an anti-analysis check swallowed every input.
- When the map grows, minimize the input (`afl-tmin`, libFuzzer `-minimize_crash=1`) and diff it against the seed. The bytes that changed are the field you just discovered.
- Dedup crashes by the top of the stack, not by the input hash. Keep one minimized input per stack.
- Re-anchor before you name the bug. Reproduce the input on the original binary in the lab (plain run, then under the debugger), and open the faulting address in the static image. A crash inside the harness, the hook, the fuzzer runtime, or a lifted copy that does not reproduce on the original bytes is not a finding. Rule 11.

## Boundaries
- A campaign that finds no crash did not prove the parser safe. It proved only that this harness, seed, and time box produced no crash.
- Bound every run: `-V seconds` or `-E execs` for AFL++, `-max_total_time` for libFuzzer, `--run_time` for honggfuzz, plus an outer `timeout`.
- Do not raise the time box to hide a harness that never passes the first check.
- Do not point the fuzzer at a production service. Egress stays `offline` or `lab_only`.
- Do not paste the corpus or a multi-megabyte crash dump into the conversation. Keep the command, the seed hash, the edge delta, and the one minimized input that matters.
