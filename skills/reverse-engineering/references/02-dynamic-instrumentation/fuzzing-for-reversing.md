# Fuzzing For Reverse Engineering

## When To Open
Open this file when a reversing question is "which input reaches this block, field, or compare", or when obfuscation has made the decompiler untrustworthy and the logic has to be inferred from input and output. Fuzzing here is an oracle for a hypothesis. It is not an exploit workflow. A crash is an address to re-open in the decompiler. Turning that crash into code execution is out of scope. See [vuln-research-patch.md](../03-objectives/vuln-research-patch.md) for the source, sink, and guard bar.

Run the campaign inside the containment in `SKILL.md`. A fuzzer executes the target thousands of times. `qemu-user` is not that containment. Malware and packers stay offline. Fuzz the decoder, the config, or the command parser. Do not let the sample open a real network connection.

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
| A socket | A desocket preload (`AFL_PRELOAD` of a `libdesock`-style shim) so `accept`/`read` return the fuzz buffer | Fuzzing the client against a live host. |
| One function you already typed | An in-process harness (`LLVMFuzzerTestOneInput` or a persistent AFL loop) that calls that function | Fuzzing `main` and hoping to pass the UI. |
| Nothing (no file, argv, or socket) | Do not fuzz. A clean run is not evidence. Read the code. | Any campaign. |

Foreign architectures need a qemu build of the fuzzer for that architecture, or a harness compiled for the host that calls lifted or reconstructed code. A stock AFL++ binary fuzzes the host ISA only. Match endianness. MediaTek images are usually little-endian. Broadcom images are usually big-endian. See [firmware-iot.md](../01-static-architectures/firmware-iot.md).

## Harness Shape
Prefer the smallest function that implements the behavior.

1. Skip `main` when it only parses flags and checks a magic. Start at the function that consumes the buffer.
2. A 32-bit magic or a CRC in front of the parser will not fall to bit flips. Patch the check in a lab copy, or compute the checksum inside the harness, and record that the campaign never tested the check itself.
3. One input in, one process out. No network, no GUI, no fork-per-input unless the target itself forks.
4. Bound each run. `afl-fuzz -V 600` is enough for a single readable check. Obfuscated logic uses the staged campaign in the next section, not one unbounded process. A hang is a result: raise `-t` only after you know the slow path is real.

In-process shape when you can compile a caller:

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1 << 20) return 0;
    target_parse(data, size);
    return 0;
}
```

Build that with ASan and UBSan when the source or a rebuild exists. A qemu-mode campaign on a closed binary has no ASan. Say which of the two you ran.

## Seeds And Dictionaries
An empty seed of `AAAA` never reaches a parser that demands a header.

- Seed with a real input: a file the binary ships, a carved `.rodata` blob, a minimized PCAP payload, or the smallest sample that already passes the first check.
- Dictionary tokens are the magic bytes and the short strings at the compares you care about (`PK`, a four-byte magic, `RIFF`). AFL++ reads these from `-x`.
- Coverage-guided mutation (AFL++ `afl-fuzz`, libFuzzer, honggfuzz) is the default when an edge map exists.
- A dumb mutator is enough when the space is one byte or one enum and you only need the value that flips a branch.
- Grammar or structure-aware mutation is for a format you have already partly recovered. Do not invent a grammar to avoid reading the length field.

## What To Run

| Situation | Engine |
|---|---|
| Closed Linux ELF, you can exec it | AFL++ qemu mode (`-Q`) inside the container |
| You built a harness | `afl-clang-fast` persistent mode, or libFuzzer |
| Closed binary, no compiler, and you need an edge map without qemu | A DBI fuzzer (WinAFL, Jackalope, or a Frida coverage loop). Hook the function. Do not stalk every instruction of libc. |
| The interesting state is after a long init | Snapshot or persistent mode from the point after init. Fuzzing from process start repeats the init. |
| macOS or a Mach-O you cannot rebuild | A persistent harness if you can link the function. Otherwise one targeted hook is cheaper than a fuzzer. |

CmpLog, RedQueen, and laf-intel split multi-byte compares so the fuzzer can solve them. Turn them on when the coverage map stalls in front of `memcmp` or an immediate compare. They do not replace fixing a checksum in the harness.

## Deep Campaigns On Obfuscated Code
Flattened control flow, virtualized handlers, mixed boolean-arithmetic, and encrypted strings do not yield to one short run. The decompiler output is a candidate at best. The logic is whatever input/output relation survives. Go deep by stacking bounded runs. Each run has one hypothesis, one stop condition, and a corpus the next run inherits. A flat map after the harness is honest is a dead end. Record it. Do not add hours to the same question.

Do this before trusting any edge count:

- If every input exits immediately, the fuzzer is executing the anti-debug or anti-VM check, not the payload. Neutralize that check in a lab copy, record the patch, and start again. A map of the exit path is not a map of the logic.
- Prefer qemu mode or a snapshot taken after the checks. A debugger-attached fuzzer trips `rdtsc` and integrity checks and then mutates the wrong program.
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
New coverage is the reversing result. A crash is a second result. Neither is a vulnerability by itself.

- Record the measurement you named (edge count, handler hits, or distinct outputs) at the start and at the stop condition. A flat measurement means the seed never entered the function, the harness calls the wrong entry, or an anti-analysis check swallowed every input.
- When the map grows, minimize the input (`afl-tmin`, libFuzzer `-minimize_crash=1`) and diff it against the seed. The bytes that changed are the field you just discovered.
- Dedup crashes by the top of the stack, not by the input hash. Keep one minimized input per stack.
- Re-anchor before you name the bug. Open the faulting address in the static image. A crash inside the harness, the fuzzer runtime, or a lifted copy that does not reproduce on the original bytes is not a finding. Rule 11.

## Boundaries
- A campaign that finds no crash did not prove the parser safe. It proved only that this harness, seed, and time box produced no crash.
- Do not raise the time box to hide a harness that never passes the first check.
- Do not point the fuzzer at a production service. Egress stays `offline` or `lab_only`.
- Do not paste the corpus or a multi-megabyte crash dump into the conversation. Keep the command, the seed hash, the edge delta, and the one minimized input that matters.
