#!/bin/sh
#  Fuzz smoke: run the harness over every corpus file. Any nonzero exit
#  (Ada exception, e.g. Constraint_Error) is a parser bug. Deterministic,
#  fast, runs in CI via the differential job.
set -eu
cd "$(dirname "$0")/.."
eval "$(alr printenv)" 2>/dev/null || true
gprbuild -P tests/tests.gpr -q
FAIL=0
for f in tests/corpus/*.pcapng; do
  if ./bin/fuzz_harness "$f" >/dev/null 2>&1; then
    echo "ok   $f"
  else
    echo "FAIL $f"
    FAIL=1
  fi
done
#  Truncated tail must be Truncated, not a crash (exit 0 with a note).
OUT=$(./bin/fuzz_harness tests/corpus/truncated_tail.pcapng)
echo "$OUT" | grep -q "blocks: 2" || { echo "FAIL truncated block count: $OUT"; FAIL=1; }
exit $FAIL
