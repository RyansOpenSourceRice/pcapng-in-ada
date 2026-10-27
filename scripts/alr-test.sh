#!/bin/sh
#  Test entry point for `alr test` (see alire.toml [[actions]] type=test).
#  Test actions do not inherit the Alire toolchain PATH, so re-hydrate it
#  from `alr printenv`, then build the suite and run it. Fails loudly.
set -eu
eval "$(alr printenv)"
gprbuild -P tests/tests.gpr -q
./bin/aunit_runner
