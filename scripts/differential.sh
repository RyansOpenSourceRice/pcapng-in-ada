#!/bin/sh
#  Differential: our tools vs each other (always) and vs Wireshark's
#  tshark/capinfos when installed (local dev; CI tries to install tshark
#  but stays green on self-consistency alone). Event-driven CI only,
#  fixed tiny corpus, no schedules.
set -eu
cd "$(dirname "$0")/.."
eval "$(alr printenv)" 2>/dev/null || true
gprbuild -P tests/tests.gpr -q
gprbuild -P examples/examples.gpr -q

HAVE_TSHARK=0; command -v tshark >/dev/null 2>&1 && HAVE_TSHARK=1
HAVE_CAPINFOS=0; command -v capinfos >/dev/null 2>&1 && HAVE_CAPINFOS=1
echo "tshark: $HAVE_TSHARK, capinfos: $HAVE_CAPINFOS"

FAIL=0
for f in tests/corpus/*.pcapng; do
  case "$f" in
    *truncated_tail.pcapng)
      #  Truncation must be reported, identically, by both readers.
      R=$(./bin/read_dump "$f" | tail -n 1)
      S=$(./bin/streaming_dump "$f" | head -n 1)
      case "$R" in *TRUNCATED*) echo "ok   $f reader-truncated";; *)
        echo "FAIL $f: $R"; FAIL=1;; esac
      case "$S" in *truncated*) echo "ok   $f stream-truncated";; *)
        echo "FAIL $f: $S"; FAIL=1;; esac
      continue;;
  esac

  RD=$(./bin/read_dump "$f")
  SD_LAST=$(./bin/streaming_dump "$f" | tail -n 1)
  RN=$(printf "%s\n" "$RD" | grep -c "^ *[0-9]")
  SN=$(printf "%s\n" "$SD_LAST" | sed 's/blocks: *\([0-9]*\).*/\1/')
  if [ "$RN" = "$SN" ]; then
    echo "ok   $f blocks=$RN (dump==stream)"
  else
    echo "FAIL $f dump=$RN stream=$SN"; FAIL=1
  fi
  EPB=$(printf "%s\n" "$RD" | grep -c KIND_EPB || true)

  if [ "$HAVE_CAPINFOS" = 1 ]; then
    CN=$(capinfos -c "$f" 2>/dev/null | awk '/Number of packets/ {print $NF}')
    if [ "$CN" = "$EPB" ]; then
      echo "ok   $f packets=$EPB (capinfos agrees)"
    else
      echo "FAIL $f capinfos=$CN ours=$EPB"; FAIL=1
    fi
  fi

  if [ "$HAVE_TSHARK" = 1 ]; then
    if tshark -r "$f" >/dev/null 2>&1; then
      echo "ok   $f tshark reads"
    else
      echo "FAIL $f tshark cannot read"; FAIL=1
    fi
    #  Best-effort oracle: a tshark query failure (old version, odd
    #  build) must not fail the gate under set -e — self-consistency
    #  above is the verdict, tshark is the bonus.
    if BAD=$(tshark -r "$f" \
      -Y 'pcapng.block.lengths_dont_match or pcapng.invalid_option_length' \
      -T fields -e frame.number 2>/dev/null); then
      if [ -z "$BAD" ]; then
        echo "ok   $f no structural complaints"
      else
        echo "FAIL $f tshark flags: $BAD"; FAIL=1
      fi
    else
      echo "(warn $f tshark filter query failed; skipping)"
    fi
  fi
done
if [ "$HAVE_TSHARK" = 0 ]; then
  echo "(oracle checks skipped: install wireshark/tshark locally for full differential)"
fi
exit $FAIL
