#!/bin/sh

set -u
cd "$(dirname "$0")"

PASS=0
FAIL=0

ok()   { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

is_packed()   { tail -c 8 "$1" 2>/dev/null | grep -qa '1KCAPFLE'; }
flag_count()  { strings "$1" 2>/dev/null | grep -o 'here :: [0-9]*' | tail -1; }

check()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# ---- build ----
if [ ! -x ./famine ]; then
	fbuild >/dev/null 2>&1 || { echo "build failed"; exit 1; }
fi

rm -rf showcase
mkdir showcase

echo "== pack a single binary =="
cp binaries/cat showcase/cat
./famine
check "cat is packed"        'is_packed showcase/cat'
check "cat still runs"       'echo hi | showcase/cat | grep -qx hi'
CAT1=$(flag_count showcase/cat)
check "cat has a flag"       '[ -n "$CAT1" ]'

echo "== add a neighbour, run the packed binary =="
cp binaries/ls showcase/ls
check "ls not packed yet"    '! is_packed showcase/ls'
echo hi | showcase/cat >/dev/null
check "ls now packed"        'is_packed showcase/ls'
CAT2=$(flag_count showcase/cat)
check "cat flag changed"     '[ "$CAT1" != "$CAT2" ]'
check "ls runs (lists dir)"  'showcase/ls showcase | grep -q cat'

echo "== idempotent: re-packing skips already-packed =="
BEFORE=$(stat -c%s showcase/cat)
./famine
AFTER=$(stat -c%s showcase/cat)
check "cat size stable"      '[ "$BEFORE" = "$AFTER" ]'

echo "== rotation advances every run =="
A=$(flag_count showcase/cat)
echo hi | showcase/cat >/dev/null
B=$(flag_count showcase/cat)
echo hi | showcase/cat >/dev/null
C=$(flag_count showcase/cat)
check "flag advances"        '[ "$A" != "$B" ] && [ "$B" != "$C" ]'

echo "== exit codes propagate through the payload =="
cp binaries/ret7 showcase/ret7
./famine
showcase/ret7; RC=$?
check "ret7 exits 7"         '[ "$RC" -eq 7 ]'

echo
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
