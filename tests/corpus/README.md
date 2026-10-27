# Corpus

Small deterministic captures for smoke-fuzzing (`scripts/fuzz-smoke.sh`),
the Wireshark differential (`scripts/differential.sh`), and AFL++ seeds.

All files are generated locally by `tests/gen_corpus.adb`
(`./bin/gen_corpus`) from this repo's own writer plus a few hand-rolled
blocks. No network fetch, no third-party captures, no license burden.

Regenerate after any framing change and re-run both scripts.

| File | Blocks | Covers |
|---|---|---|
| `le_basic.pcapng` (144 B) | SHB, IDB, 2×EPB | LE baseline round-trip |
| `be_basic.pcapng` (84 B) | SHB, IDB, EPB | BE write + order tracking |
| `with_comment.pcapng` (128 B) | SHB+cmt, IDB+name, EPB+cmt | `opt_comment`, `if_name` search |
| `snaplen.pcapng` (92 B) | SHB, IDB, EPB caplen 10 < origlen 1500 | snaplen truncation is normal |
| `nrb_isb.pcapng` (96 B) | SHB, IDB, NRB (IPv4 rec + end), ISB | NRB/ISB typed views |
| `unknown_opt.pcapng` (100 B) | SHB, IDB, EPB + option code 99 | unknown-option skip |
| `multi_section.pcapng` (168 B) | LE SHB/IDB/EPB + BE SHB/IDB/EPB | mid-file endian flip (6 blocks) |
| `truncated_tail.pcapng` (134 B) | SHB, IDB, EPB cut 10 B short | truncated tail → `Truncated`, not a raise |

Expected harness results (`./bin/fuzz_harness <file>` exits 0 on all):
all files `notes: 0` except `truncated_tail.pcapng` (`blocks: 2 notes: 1`).
