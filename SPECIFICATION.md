# SPECIFICATION — pcapng_in_ada v0.1.0

Authoritative behavioral contract. `DESIGN.md` explains why; this file says what.

## 1. Scope

Full IETF `draft-ietf-opsawg-pcapng` block coverage on read; LE write v1.0.
Root package `Pcapng_In_Ada`, crate/GPR `pcapng_in_ada`.

## 2. Types

- `Byte_Buffer`: `array (Positive range <>) of Unsigned_8`.
- `Byte_Order`: `(Little_Endian, Big_Endian)`.
- Type codes: SHB `0A0D0D0A`, IDB `1`, SPB `3`, NRB `4`, ISB `5`, EPB `6`,
  CB1 `0BAD`, CB2 `40000BAD`; magic `1A2B3C4D`; version major 1, minor 0/2.
- `Error_Kind`: None, Truncated, Bad_Magic, Bad_Version, Bad_Length,
  Bad_Trailer, Bad_Option, Unsupported, No_Space.
- `Block_Kind`: SHB/IDB/SPB/NRB/ISB/EPB/Custom/Unknown.

## 3. Rules

1. First block of an image (and after EOF) must be SHB; else `Bad_Magic`.
2. Byte order comes from SHB magic bytes (`1A2B3C4D` LE, byte-swapped BE).
3. Every block: leading and trailing total-length must match; else `Bad_Trailer`.
4. Lengths < 12 or > 16#1000000# are `Bad_Length`; short buffer is `Truncated`.
5. SHB major must be 1, minor 0 or 2; else `Bad_Version`.
6. IDB minimum 20 bytes; EPB minimum 32; SPB minimum 16; caplen+pad must fit.
7. Options are `(code:16, len:16, value, pad32)`; code 0 ends; unknown codes skipped.
8. Unknown block types are skipped (`Kind_Unknown`), never an error.
9. A new SHB restarts the section and may flip byte order.
10. Writer emits LE v1.0 only; short destination is `No_Space` (never raises).
11. `Timestamp_64 = high*2**32 + low`; `tsresol` MSB set = binary `2**v` else `10**v`.
12. All API units are `SPARK_Mode On`; Silver (AoRTE + contracts) is required.

## 4. Verification

`alr build`, `tests.gpr` drivers (round-trip + malformed), `examples.gpr`,
`gnatprove --mode=silver --level=2` with zero unproved checks.
