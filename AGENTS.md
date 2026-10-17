# AGENTS.md

Instructions for agentic coding contributors (humans: see README.md).

## Commands

```sh
alr build
gprbuild -P tests/tests.gpr && ./bin/test_reader && ./bin/test_malformed
gprbuild -P examples/examples.gpr
alr exec -- gnatprove -P pcapng_in_ada.gpr --mode=silver --level=2
```

## Rules

- Ada 2022, `SPARK_Mode => On` on every `src/` unit; no new exceptions.
- Public API changes require a `SPECIFICATION.md` delta + CHANGELOG entry.
- Keep root files discoverable; document any budget overflow in DESIGN.md.
- After finishing code work: push branch + create/update PR automatically.
- Prefer GitHub MCP for push/PR when CLI git lacks credentials.
