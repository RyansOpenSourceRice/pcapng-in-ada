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

Build (`alr build`) → AUnit suite (`alr test`, 15 checks) → examples
(`examples.gpr`) → `gnatprove --mode=silver` + `--mode=gold`
`--level=2` (1088 checks, zero unproved). Fuzz smoke
(`scripts/fuzz-smoke.sh` over `tests/corpus/`) and the Wireshark
differential (`scripts/differential.sh`: dump==stream, capinfos/tshark
oracle when installed) run in the `differential` CI job; AFL++ stays
local-only (`fuzz/`).

## Scanner coverage (§9/§29 — documented skips)

- `pre-commit` job: Betterleaks + Codespell + hygiene via the checked-in
  `.pre-commit-config.yaml` (same file locally and in CI; no parallel jobs).
- `sast` job: OpenGrep over the non-Ada surfaces (scripts, workflows,
  docs). Ada sources are outside OpenGrep's rule coverage; their static
  assurance is GNATprove Silver in `build-test-prove`.
- `container`/Trivy: skipped — the repo ships no container image
  (no Dockerfile/Containerfile/Helm chart).
- `dynamic`/Nyx: skipped — non-runtime library; no probeable service to boot.
- `reliability`/Plumbline: skipped — no LLM/agent code in the repo.
