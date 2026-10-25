#!/usr/bin/env bash
# Regression corpus: every fixture goes through the real scanner end to end
# (git diff -> detection) and the verdict is asserted:
#   fixtures/block/*  MUST block      (exit 1), and no part of the value may be printed
#   fixtures/pass/*   MUST NOT block  (exit 0)
# Plus: a broken environment exits 2 (never 1 or 0), and SECRET_GATE_EXCLUDE skips.
# Runs on bash 3.2 (macOS) and bash 5.
set -uo pipefail
export LC_ALL=C   # byte-wise, like the scanner (fixtures include non-UTF-8 bytes)
HERE=$(cd "$(dirname "$0")" && pwd)
GATE="$HERE/../../secret-gate.sh"
[ -f "$GATE" ] || { echo "FATAL: $GATE not found" >&2; exit 2; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/repo"; cd "$tmp/repo"
git init -q
git config user.name corpus; git config user.email corpus@local
git config core.hooksPath /dev/null
echo seed > .seed; git add .seed; git commit -q -m seed

fails=0; total=0
check() {  # <label> <want> <got>
    total=$((total+1))
    if [ "$3" = "$2" ]; then printf '  ok    %-34s %s\n' "$1" "$3"
    else printf '  FAIL  %-34s got %s, want %s\n' "$1" "$3" "$2"; fails=$((fails+1)); fi
}
run_one() {  # <want-exit> <fixture>
    local want="$1" f="$2" name probe out rc
    name=$(basename "$f")
    cp "$f" ./case.fixture; git add case.fixture; git commit -q -m "case $name"
    out=$(BASE_SHA="HEAD~1" HEAD_SHA="HEAD" bash "$GATE" 2>&1); rc=$?
    check "$name" "$want" "$rc"
    if [ "$want" = 1 ]; then
        # A probe from the middle of the secret VALUE must never appear in output.
        probe=$(head -n 1 "$f" | sed -E 's/^[^:=]*[:=][[:space:]]*//; s/^["'"'"']//' | cut -c5-16)
        case "$out" in *"$probe"*) check "$name (no-leak)" not-printed printed ;; *) check "$name (no-leak)" not-printed not-printed ;; esac
    fi
    git rm -q case.fixture >/dev/null; git commit -q -m rm
}

echo "── block fixtures (want exit 1) ──"
for f in "$HERE"/fixtures/block/*; do run_one 1 "$f"; done
echo "── pass fixtures (want exit 0) ──"
for f in "$HERE"/fixtures/pass/*; do run_one 0 "$f"; done

echo "── exclude + broken environment ──"
mkdir -p fake; cp "$HERE/fixtures/block/github-pat.txt" fake/x.txt; git add fake; git commit -q -m fake
BASE_SHA="HEAD~1" HEAD_SHA="HEAD" SECRET_GATE_EXCLUDE="fake/*" bash "$GATE" >/dev/null 2>&1; check "excluded path is skipped" 0 $?
BASE_SHA="HEAD~1" HEAD_SHA="HEAD" bash "$GATE" >/dev/null 2>&1; check "same path without exclude" 1 $?
( cd "$tmp" && BASE_SHA=x HEAD_SHA=y bash "$GATE" >/dev/null 2>&1 ); check "not a git repo -> exit 2" 2 $?
BASE_SHA="HEAD~1" HEAD_SHA="0123456789abcdef0123456789abcdef01234567" bash "$GATE" >/dev/null 2>&1; check "unreachable head SHA -> exit 2" 2 $?

echo "────────────────────────────────"
if [ "$fails" -eq 0 ]; then echo "secret-gate corpus: $total/$total OK"; else echo "secret-gate corpus: $fails/$total FAILED" >&2; exit 1; fi
