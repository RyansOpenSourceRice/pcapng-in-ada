# pcapng_in_ada

SPARK Silver PCAPNG read/write library for Ada, covering the full IETF
`draft-ietf-opsawg-pcapng` block set (SHB `0A0D0D0A` / magic `1A2B3C4D`,
IDB, EPB, SPB, NRB, ISB, Custom, options TLV with unknown-skip).

- Read: little- and big-endian, version 1.0 / 1.2 SHB, section restart.
- Write: little- and big-endian section v1.0 (SHB + IDB + EPB + SPB),
  plus single-option writers (comment, if_name).
- Streaming: `Pcapng_In_Ada.Stream.Consume` parses whole blocks from
  caller-fed chunks (truncated tail is retained, not an error), so a
  multi-GB capture fits in a fixed window — see `streaming_dump`.
- Diagnostics: `Pcapng_In_Ada.Diag` reports byte offset / block index /
  section index alongside `Error_Kind`.
- Contract: `SPARK_Mode => On`, `gnatprove --mode=silver` and
  `--mode=gold` clean (1102 checks, zero unproved), single `Result`-style
  error model (`Error_Kind`), no exceptions on the API path.
- Toolchain (single LTS): GNAT FSF 16 / GNAT Pro 26 family, Ada 2022,
  GNATprove 28.0w-class, Alire 2.x, `ubuntu-24.04`.

## Layout

```text
src/        library (Pcapng_In_Ada + Common/Blocks/Options/SHB/IDB/Packet/NRB/ISB/Diag/Stream/Reader/Writer)
tests/      AUnit suites (reader/malformed/v02) + fuzz_harness + gen_corpus (alr test)
tests/corpus/  8 deterministic captures for smoke/differential/AFL++ seeds
examples/   write_sample / read_dump / convert_summary / streaming_dump / bench
fuzz/       AFL++ config + notes (local only)   scripts/ differential + fuzz smoke
```

## Build / test / prove

```sh
alr build
alr test                        # builds + runs the AUnit suite (15 checks)
alr exec -- gprbuild -P examples/examples.gpr
alr exec -- gnatprove -P pcapng_in_ada.gpr --mode=silver --level=2
alr exec -- gnatprove -P pcapng_in_ada.gpr --mode=gold --level=2
sh scripts/differential.sh      # self-consistency + tshark oracle when installed
sh scripts/fuzz-smoke.sh        # harness over tests/corpus/
```

## Performance

`examples/bench.adb`: 4 MB image of 87,380 14-byte frames (worst-case
per-packet overhead), `-O2`, single runs on a Qubes Linux VM
(GNAT FSF 16.1.0). Reproduce with `./bin/bench`.

| Op | Throughput |
|---|---|
| write (Append_EPB fill) | ~190–390 MB/s |
| cursor walk (`Reader.Next`) | ~790–1,160 MB/s, ~14–24 M packets/s |
| chunked stream (`Stream.Consume`, 64 KiB feeds) | ~670–1,130 MB/s, 87,382 blocks |

VM noise dominates the ranges; the point is order-of-magnitude:
read path ≥ write path, streaming matches cursor speed at constant memory.

## Spec / design

See `SPECIFICATION.md` (behavioral contract) and `DESIGN.md` (rationale,
root-manifest overflow note, verification story).

## License

Apache-2.0 — see `LICENSE`. Third-party notices in `THIRD_PARTY_NOTICES.md`.
