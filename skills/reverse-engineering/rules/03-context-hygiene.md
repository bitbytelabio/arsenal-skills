# Rule 3: Context Hygiene & Scratchpad Discipline

## Mandate
It is **STRICTLY FORBIDDEN** to dump raw decompiler pseudocode, large disassembly blocks, full memory maps, or raw trace logs exceeding 300–400 lines into the main conversational context window.

## Scratchpad Mitigation Procedure
When inspecting functions or trace outputs larger than 300 lines:
1. **Offload Raw Data to Scratchpad**:
   - Write full decompiler pseudocode to `.re_scratch/<func_name>.c` or `.re_scratch/<func_name>.cpp`.
   - Write raw disassembly or basic block graphs to `.re_scratch/<func_name>.asm`.
   - Write dynamic traces or API call captures to `.re_scratch/<func_name>_trace.log`.
2. **Context Retention Window**:
   - In the active conversational context, retain strictly:
     - The function prototype and calling convention.
     - First 50 lines (prologue, argument parsing, stack setup, initial branching).
     - Critical intermediate lines containing relevant string references, crypto constants, or system calls.
     - Last 50 lines (epilogue, return value calculations, error handling).
     - Direct callee invocation summary.
3. **Subagent Delegation for Deep Traces**:
   - For subroutines with excessive cyclomatic complexity or high line counts, delegate step-by-step branch analysis to a bounded subagent operating directly against the `.re_scratch/` file.

## Bounded Commands
Nothing outside this skill clips a tool result. Keep each dump inside a few hundred lines yourself.

- Disassemble one function or one address range. A whole-section dump is not a first action.
- A result that says the output was truncated, or that points at a scratch file instead of the listing, is not the disassembly. Rerun a smaller range.
- A rejected flag is a failed command, not a negative finding. macOS `strings` has no `-e`. macOS `awk` has no `strtonum`. Scan encodings with Python, and use arithmetic the local `awk` has.
- `grep` with no match exits 1. Write `grep … || true` when a miss is an expected result, or the rest of the command never runs.
- An ELF file offset is the VMA minus the `PT_LOAD` that covers that address. A PE file offset uses that section's `PointerToRawData`. One constant for the whole file is wrong when segments differ.

## Prohibited Context Dumps
The following operations are explicitly prohibited from dumping directly into the primary prompt context:
- Monolithic Abstract Syntax Trees (ASTs) or compiler intermediate representations (IR).
- Memory maps (`/proc/<pid>/maps` or VM memory region tables) containing hundreds of mapped pages.
- Raw Frida Stalker traces or instruction-level trace dumps exceeding 1,000 instructions.
- Full binary hex dumps or extensive raw section dumps.
