# DESIGN — pcapng_in_ada

## Why this shape

- One child package per concern (Common / Blocks / Options / SHB / IDB /
  Packet / Reader / Writer) so each unit stays small enough for Silver.
- `Byte_Buffer` with `Positive` index instead of `Stream_Element_Array`:
  avoids `Stream_Element_Offset` proof friction; conversion lives at the
  demo boundary (`examples/`), outside the trusted core.
- Views point into the caller buffer (First/Last offsets, `Valid` flag):
  no heap, no secondary stack copies, no pointers — the prover's happy path.
- Single `Error_Kind` out-parameter (Result pattern) instead of exceptions:
  callers in tools/embedded contexts decide policy; the library never raises.
- Writer is LE-only v1.0: matches what Wireshark/tcpdump accept everywhere
  and halves the proof surface (one endianness on encode).

## Root-manifest note (budgets)

Required root files (§29: README, CHANGELOG, ROADMAP, MAINTAINERS, DESIGN,
SPECIFICATION, SECURITY, AGENTS, renovate.json, .pre-commit-config.yaml,
THIRD_PARTY_NOTICES, LICENSE) plus crate files (alire.toml, .gpr,
.gitignore) intentionally exceed the soft "8 files" budget; grouping them
into `docs/` would break the required discovery paths, so overflow is kept
and documented here. Root dirs: src, tests, examples, .github, config —
within budget.

## Verification story

Build (`alr build`) → unit drivers (`tests.gpr`) → examples (`examples.gpr`)
→ `gnatprove --mode=silver --level=2`. Fuzz/corpus differential testing
against Wireshark is roadmap (see ROADMAP.md).
