# Rule 7: Hypothesis-Driven Analysis

## Mandate
Before initiating a deep-dive investigation of any subroutine, dispatcher, or algorithm, the analyst or agent must state an explicit, falsifiable 1–2 sentence hypothesis. Blindly reading disassembly or pseudocode line-by-line without an orienting hypothesis is **STRICTLY FORBIDDEN**.

## Hypothesis Format
The hypothesis statement must follow this standard pattern:
> *"This function is hypothesized to be [purpose/algorithm] because [specific indicators: string cross-reference, callee signature, argument pattern, magic constant, or control-flow topology]."*

### Examples
- **Acceptable**: *"sub_1400021A0 is hypothesized to be an RC4 key-scheduling algorithm (KSA) because it receives a byte buffer with length 16 and initializes a 256-byte array with identity values 0x00 through 0xFF in a loop."*
- **Acceptable**: *"sub_1400085C0 is hypothesized to be a command dispatcher because it receives an integer opcode in ECX and switches across 14 jump targets handling socket write calls."*
- **Prohibited**: *"Let's read sub_1400021A0 from start to finish to see what it does."*

## Cheapest Falsifier
Before reading a routine from start to finish, test the hypothesis with the cheapest oracle that can falsify it. This does not override [Rule 4](04-static-dynamic-loop.md): if the bytes are statically readable, use a string, a constant, a cross-reference, or a bounded read of the compare. Use one hook, or a dump at the deciding compare, only when the value exists only at runtime or static reading is blocked (packing, flattened control flow, or virtualization).

If the artifact matches a known field shape, that shape is the first hypothesis. The catalog is [case-patterns.md](../references/03-objectives/case-patterns.md).

If the question is which input reaches a block, or the function is too obfuscated to read, use [fuzzing-for-reversing.md](../references/02-dynamic-instrumentation/fuzzing-for-reversing.md). Name the input channel before the first campaign. On obfuscated code, run a staged campaign: one hypothesis per run, and the next run inherits the corpus.

### Comparison Direction
Determine which side is the secret before reversing the math:

- `transform(input) == stored` — recover the inverse of `transform`.
- `transform(stored) == input` — apply `transform` to the stored bytes. That output is the accepted value.

When several compares sit in a row, the deciding compare is the last one until an observation shows an earlier compare gates success. Earlier hits are decoys. Dumping the computed buffer at the deciding compare is preferred over reading the whole routine.

## Conclusion Contract
Every subroutine investigation must conclude with an explicit resolution statement:
1. **Confirmation or Refutation**: Formally confirm or refute the initial hypothesis based on verified data flow, recovered constants, or dynamic instrumentation output.
2. **Recorded Evidence**: Note the exact program point (address, instruction, or return value) that confirmed or refuted the claim.
3. **State Update**: Set the hypothesis to `open`, `confirmed`, or `refuted` in `re_state.json`. A confirmed hypothesis is not a validated finding. Create or update the finding and set its status only by [Rule 11](11-evidence-sufficiency.md).
