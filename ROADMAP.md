# Roadmap

- v0.2.0 (done): NRB/ISB typed views, `opt_comment` + `shb_hardware`/
  `if_name` search helpers, BE writer, SPB writer, streaming
  `Stream.Consume` reader, `Diag` offsets, `streaming_dump` example,
  AUnit suite + `alr test` wiring, fuzz harness + vendored corpus +
  Wireshark differential job in CI, SPARK Gold (full crate), perf table.
- v1.0.0: stabilized API, performance pass follow-ups.
- Left: libFuzzer/gnatfuzz when a Pro LLVM toolchain is available
  (AFL++ smoke is the portable harness until then).

Non-goals (v1): live capture, pcap classic compat layer, decryption.
