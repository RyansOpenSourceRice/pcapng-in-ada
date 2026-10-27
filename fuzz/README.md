# Fuzzing

Local-first. Nothing here runs on shared CI runners (see
`scripts/fuzz-afl.sh`, which always degrades to SKIP).

## Smoke (deterministic, also in CI)

```sh
sh scripts/fuzz-smoke.sh
```

Builds `tests/fuzz_harness.adb` and runs it over every file in
`tests/corpus/`. The harness walks all blocks through all typed views
and the option iterator; any Ada exception is a bug (nonzero exit).
`truncated_tail.pcapng` must exit 0 with `blocks: 2` (truncation is data,
not a crash).

## AFL++ (manual, bounded)

```sh
sh scripts/fuzz-afl.sh   # 60s over tests/corpus seeds, needs afl++
```

Rebuilds the harness through `afl-gcc-fast` (`fuzz/afl.cgpr`) and runs
`afl-fuzz -V 60`. Needs a GCC-plugin AFL++ compatible with FSF GNAT;
`libFuzzer`/`gnatfuzz` need GNAT Pro LLVM and are future work.
Check `out/crashes/` afterwards; minimise any crashes back into
`tests/corpus/` via `tests/gen_corpus.adb` patterns.
