#!/bin/sh
#  AFL++ session (LOCAL ONLY, never CI): instrumented rebuild of the
#  harness + a short bounded run over tests/corpus seeds.
#  Requires: afl++ (`afl-fuzz`, `afl-gcc-fast`). Best-effort: any step
#  that fails prints SKIP instead of failing.
set -eu
cd "$(dirname "$0")/.."
if ! command -v afl-fuzz >/dev/null 2>&1; then
  echo "SKIP: afl-fuzz not installed (sudo apt install afl++)."
  exit 0
fi
if ! command -v afl-gcc-fast >/dev/null 2>&1; then
  echo "SKIP: afl-gcc-fast not installed."
  exit 0
fi
eval "$(alr printenv)" 2>/dev/null || true
mkdir -p bin/afl out
if ! gprbuild --config=fuzz/afl.cgpr -P tests/tests.gpr -q tests/fuzz_harness.adb -o bin/afl/fuzz_harness 2>/dev/null; then
  echo "SKIP: instrumented rebuild failed with this toolchain (needs GCC-plugin AFL++ and FSF GNAT; see fuzz/README)."
  exit 0
fi
echo "Running AFL++ for 60s over tests/corpus seeds..."
afl-fuzz -V 60 -i tests/corpus -o out -- ./bin/afl/fuzz_harness @@ || true
echo "Done. Inspect out/crashes/ (empty = no crashes found in window)."
