# Changelog

All notable changes to `pcapng_in_ada` are documented here.
Format follows Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Added

- Full AUnit suite (`tests/pcapng_tests-*_suite`, 15 checks) replacing
  the legacy driver mains; `alr test` wired via `scripts/alr-test.sh`.
  New coverage: `caplen < origlen` is normal, cut-mid-payload is
  `Truncated`, LE→BE section-flip walks 6 blocks.
- Fuzz + differential: `tests/fuzz_harness.adb` (never raises; any
  exception is a crash), `tests/gen_corpus.adb` + 8 deterministic
  captures in `tests/corpus/`, `scripts/fuzz-smoke.sh`,
  `scripts/differential.sh` (dump==stream, capinfos/tshark oracle when
  installed), local-only `scripts/fuzz-afl.sh` (`fuzz/afl.cgpr`).
  New `differential` CI job (best-effort tshark install, no schedule).
- `examples/bench.adb` + README performance table (write ~190–390 MB/s,
  walk ~14–24 M packets/s, stream matches at constant memory).
- `Pcapng_In_Ada.NRB` / `ISB` typed views (`Parse_NRB`, `Parse_ISB`)
  with `Reader.Read_NRB_At` / `Read_ISB_At` convenience decoders.
- Option search: `Options.Find_Option` + `Get_Option` on SHB/IDB
  (`shb_hardware/os/userappl`, `if_name/description/tsresol/tsoffset`)
  and `Packet.Get_EPB_Option` (`epb_flags/hash/dropcount`, comment).
- Writer: `Append_*_Ex` byte-order-explicit writers (LE/BE), new
  `Append_SPB_Ex`, single-option writers (`SHB_With_Comment`,
  `IDB_With_Name`, `EPB_With_Comment`); legacy `Append_*` stay LE.
- Streaming: `Pcapng_In_Ada.Stream` (`State`, `Consume`,
  `Complete_Prefix`) for constant-memory chunked parsing + new
  `streaming_dump` example (128 KiB window, slides truncated tail).
- Diagnostics: `Pcapng_In_Ada.Diag` (`Tracker`/`Location`) with byte
  offset + block index + section index per block.
- Tests: AUnit suites (reader/malformed/v02, 15 checks; migrated from
  the `test_reader`/`test_malformed`/`test_v02` drivers);
  `Common.Encode_U64_BE` for BE timestamps.

### Fixed

- Mid-file byte-order flip (LE section → BE section) no longer reports
  `Bad_Length`: `Reader.Next`, `Stream.Consume`, and `Complete_Prefix`
  retry a failed header as SHB (magic decides), keeping the original
  error when it is genuinely corrupt. Found by the new corpus
  (`multi_section.pcapng`); covered by `T_Section_Flip`.
- `Stream.Consume` / `Complete_Prefix` now constrain every fit check to
  the `First .. Last` window (slice rename) instead of the caller's
  larger buffer: previously a block was consumed past the feed edge and
  the next feed restarted mid-block (`BAD_TRAILER`). Found by bench;
  `streaming_dump` now always passes a `Buf'First .. Fill` slice.
- `streaming_dump` truncated-file path reports `truncated tail` with the
  retained byte count instead of misreading zero padding.
- SPB with Total 12..15 or a non-32-bit-aligned body now returns
  `Bad_Length` instead of raising `Constraint_Error` (SPECIFICATION rule 6
  pins down the alignment requirement).
- `Parse_Header` / `Encode_Envelope` postconditions now pin down `Next`
  and the length bounds, closing Silver proof links for all callers.
- Proof hardening (no behavior change on sane inputs): length
  preconditions written addition-first (`Pos + N <= Buf'Last`);
  `Read_*_At` wrappers carry `Pos` preconditions; `Block_Count` rejects
  insane bounds up front and re-checks the cursor before each `Next`;
  `Append_IDB`/`Append_EPB` share `Append_SHB`'s guard shape; `Written`
  returns 0 on insane bounds.

### Proved

- `gnatprove --mode=gold --level=2`: full crate clean (1102 checks),
  same count as Silver; new CI gate after the Silver step.

## [0.1.0] - 2026-10-16

### Added

- Initial SPARK Silver library: SHB/IDB/EPB/SPB/NRB/ISB/Custom/unknown blocks,
  LE+BE read, LE v1.0 write, TLV options with unknown-skip.
- `Pcapng_In_Ada.Reader` forward cursor with section restart.
- `Pcapng_In_Ada.Writer` append API (`Append_SHB/IDB/EPB`).
- Tests (`tests.gpr`), examples (`examples.gpr`), CI + Scorecard workflows.
- Docs: SPECIFICATION, DESIGN, SECURITY, ROADMAP, MAINTAINERS, AGENTS.
