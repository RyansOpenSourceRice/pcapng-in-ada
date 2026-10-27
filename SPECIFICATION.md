# SPECIFICATION — pcapng_in_ada v0.2.0-dev

Authoritative behavioral contract. `DESIGN.md` explains why; this file says what.

## 1. Scope

Full IETF `draft-ietf-opsawg-pcapng` block coverage on read; LE+BE write.
Root package `Pcapng_In_Ada`, crate/GPR `pcapng_in_ada`.

## 2. Types

- `Byte_Buffer`: `array (Positive range <>) of Unsigned_8`.
- `Byte_Order`: `(Little_Endian, Big_Endian)`.
- Type codes: SHB `0A0D0D0A`, IDB `1`, SPB `3`, NRB `4`, ISB `5`, EPB `6`,
  CB1 `0BAD`, CB2 `40000BAD`; magic `1A2B3C4D`; version major 1, minor 0/2.
- `Error_Kind`: None, Truncated, Bad_Magic, Bad_Version, Bad_Length,
  Bad_Trailer, Bad_Option, Unsupported, No_Space.
- `Block_Kind`: SHB/IDB/SPB/NRB/ISB/EPB/Custom/Unknown.
- Diagnostics: `Pcapng_In_Ada.Diag` (`Tracker`/`Location`) reports
  byte offset + block index + section index per `Reader.Next`; the
  core error model is unchanged (no exceptions).
- Typed views: `NRB` (record list, validated), `ISB` (if_index + ts +
  options region), plus `SHB`/`IDB`/`Packet` option search
  (`Get_Option`, `Find_Option`; codes: `opt_comment = 1`,
  `shb_hardware = 2`, `shb_os = 3`, `if_name = 2`, `if_description = 3`,
  `if_tsresol = 9`, `if_tsoffset = 14`, `epb_flags = 2`,
  `epb_hash = 3`, `epb_dropcount = 4`).
- Streaming: `Pcapng_In_Ada.Stream` (`State`, `Consume`, `Complete_Prefix`)
  consumes leading whole blocks from caller-fed slices; a truncated
  tail is not an error (caller slides it forward). Fixed 64–128 KiB
  window parses arbitrarily large captures.

## 3. Rules

1. First block of an image (and after EOF) must be SHB; else `Bad_Magic`.
2. Byte order comes from SHB magic bytes (`1A2B3C4D` LE, byte-swapped BE).
3. Every block: leading and trailing total-length must match; else `Bad_Trailer`.
4. Lengths < 12 or > 16#1000000# are `Bad_Length`; short buffer is `Truncated`.
5. SHB major must be 1, minor 0 or 2; else `Bad_Version`.
6. IDB minimum 20 bytes; EPB minimum 32; SPB minimum 16 with the body
   after orig_len 32-bit aligned; caplen+pad must fit.
7. Options are `(code:16, len:16, value, pad32)`; code 0 ends; unknown codes skipped.
8. Unknown block types are skipped (`Kind_Unknown`), never an error.
9. A new SHB restarts the section and may flip byte order.
10. Writer emits LE v1.0 via legacy `Append_*`; `*_Ex` variants honor
    an explicit `Order` (LE/BE); short destination is `No_Space`
    (never raises). Single-option writers (`SHB_With_Comment`,
    `IDB_With_Name`, `EPB_With_Comment`) append one TLV + endofopt;
    over-long values are `Bad_Length` (`Max_Comment_Len = 512`,
    `Max_Name_Len = 256`).
11. `Timestamp_64 = high*2**32 + low`; `tsresol` MSB set = binary `2**v` else `10**v`.
12. All API units are `SPARK_Mode On`; Silver (AoRTE + contracts) is required.

## 4. Verification

`alr build`, `alr test` (AUnit: 15 checks), `examples.gpr`,
`gnatprove --mode=silver --level=2` and `--mode=gold --level=2` with
zero unproved checks (1088), `scripts/fuzz-smoke.sh` +
`scripts/differential.sh` over `tests/corpus/` in CI.
