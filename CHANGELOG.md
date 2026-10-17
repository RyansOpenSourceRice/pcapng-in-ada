# Changelog

All notable changes to `pcapng_in_ada` are documented here.
Format follows Keep a Changelog; versioning follows SemVer.

## [Unreleased]

### Fixed

- SPB with Total 12..15 or a non-32-bit-aligned body now returns
  `Bad_Length` instead of raising `Constraint_Error` (SPECIFICATION rule 6
  pins down the alignment requirement).
- `Parse_Header` / `Encode_Envelope` postconditions now pin down `Next`
  and the length bounds, closing Silver proof links for all callers.

## [0.1.0] - 2026-10-16

### Added

- Initial SPARK Silver library: SHB/IDB/EPB/SPB/NRB/ISB/Custom/unknown blocks,
  LE+BE read, LE v1.0 write, TLV options with unknown-skip.
- `Pcapng_In_Ada.Reader` forward cursor with section restart.
- `Pcapng_In_Ada.Writer` append API (`Append_SHB/IDB/EPB`).
- Tests (`tests.gpr`), examples (`examples.gpr`), CI + Scorecard workflows.
- Docs: SPECIFICATION, DESIGN, SECURITY, ROADMAP, MAINTAINERS, AGENTS.
