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

## Preferences (canonical skill — read-only, never copy)

- Ryan's personal preferences live in ONE place: the `ryans-preferences`
  skill, `https://gitlab.com/RyansOpenSourceRice/ryans-agentic-coding-preferences`
  (`preferences.md`; machine-readable twin `preferences.ontology.ttl`, Jena
  dataset `ryans-preferences`). Local clone:
  `../ontologies/ryans-agentic-coding-preferences/`.
- How to read it: see the global `ryans-ontology-access` router skill (Jena
  MCP `list_graphs` → `sparql_query_templates` → `execute_sparql_query`;
  fall back to `preferences.md` if Jena is unavailable).
- Never copy any skill file into this repo (a copy here is a bootstrap
  error — remove it). This AGENTS.md is this repo's only orientation anchor.
- Key prefs shaping this repo: §9/§29 CI jobs (`pre-commit` gate incl.
  Betterleaks + Codespell, `test`, `sast`/OpenGrep; Trivy/Nyx/Plumbline only
  when their surface exists, else a DESIGN.md skip reason); no new schedules
  on shared runners (capacity awareness); public API changes need a
  SPECIFICATION.md delta + CHANGELOG entry.
- If a preference needs to change, surface it to Ryan — never edit the
  ontology or skill sources from this repo.
