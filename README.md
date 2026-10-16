# pcapng_in_ada

SPARK Silver PCAPNG read/write library for Ada, covering the full IETF
`draft-ietf-opsawg-pcapng` block set (SHB `0A0D0D0A` / magic `1A2B3C4D`,
IDB, EPB, SPB, NRB, ISB, Custom, options TLV with unknown-skip).

- Read: little- and big-endian, version 1.0 / 1.2 SHB, section restart.
- Write: little-endian section v1.0 (SHB + IDB + EPB).
- Contract: `SPARK_Mode => On`, `gnatprove --mode=silver` clean, single
  `Result`-style error model (`Error_Kind`), no exceptions on the API path.
- Toolchain (single LTS): GNAT FSF 16 / GNAT Pro 26 family, Ada 2022,
  GNATprove 28.0w-class, Alire 2.x, `ubuntu-24.04`.

## Layout

```text
src/        library (Pcapng_In_Ada + Common/Blocks/Options/SHB/IDB/Packet/Reader/Writer)
tests/      round-trip + malformed-input drivers (tests.gpr)
examples/   write_sample / read_dump / convert_summary (examples.gpr)
```

## Build / test / prove

```sh
alr build
gprbuild -P tests/tests.gpr && ./bin/test_reader && ./bin/test_malformed
gprbuild -P examples/examples.gpr
alr with gnatprove && alr exec -- gnatprove -P pcapng_in_ada.gpr --mode=silver --level=2
```

## Spec / design

See `SPECIFICATION.md` (behavioral contract) and `DESIGN.md` (rationale,
root-manifest overflow note, verification story).

## License

Apache-2.0 — see `LICENSE`. Third-party notices in `THIRD_PARTY_NOTICES.md`.
