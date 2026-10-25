#!/usr/bin/env bash
# secret-gate: fail a push or PR that adds a committed secret.
#
# Scans only the ADDED lines of a diff range for secret literals: private keys,
# cloud/VCS tokens (AWS, GitHub, GitLab, Slack), JWTs, and a high-entropy value
# assigned to a secret-named key (password, api_key, client_secret, token, ...).
# References are not literals and pass: ${VAR}, EnvironmentFile=, *_FILE=,
# !ENV / !secret tags, and placeholders (changeme, example, <...>, ...).
# A deliberate false positive can be kept with a trailing `# security-gate:allow`.
#
# Findings never print the secret: the log names the file and, for key = value
# lines, the key only.
#
# Range resolution (first non-empty wins):
#   $1 $2                              explicit <base> <head>
#   BASE_SHA / HEAD_SHA                env (the action's inputs)
#   GITHUB_EVENT_BEFORE / GITHUB_SHA   push event
#   fallback                           HEAD (head) / empty tree (base)
# A new-branch push (no before-SHA) is scanned against the default-branch tip
# ($DEFAULT_BRANCH) instead of the empty tree, so a big repo isn't fully rescanned.
#
# SECRET_GATE_EXCLUDE: space-separated path globs to skip (e.g. test fixtures
# that contain intentional fake secrets).
#
# Exit codes are load-bearing and stay distinct:
#   0  clean
#   1  a secret was found in the diff  (a finding about the code)
#   2  the scanner itself is broken    (a finding about the gate)
# An environment fault exits 2, never 1, so a broken gate is never mistaken for a
# real block and "fixed" by deleting the flagged line.
#
# PORTABILITY: bash 3.2 compatible (macOS /bin/bash). No mapfile/readarray,
# declare -A or ${var,,}; and "${arr[@]}" on an EMPTY array is an unbound-variable
# error under `set -u` on 3.2, so use ${arr[@]+"${arr[@]}"}.

set -uo pipefail

# Fail closed on an abort before the scan finishes: exit 2 ("scanner broken"),
# never 0 (false clean) and never 1 (false secret finding).
scan_complete=0
trap '_rc=$?; if [ "$scan_complete" -ne 1 ] && [ "$_rc" -ne 2 ]; then
        echo "::error::secret-gate aborted before completing the scan (exit $_rc) -- failing closed. This is a SCANNER/ENVIRONMENT fault, not a secret finding." >&2
        exit 2
      fi' EXIT

EMPTY_TREE=$(git hash-object -t tree /dev/null)

BASE="${1:-${BASE_SHA:-${GITHUB_EVENT_BEFORE:-}}}"
HEAD="${2:-${HEAD_SHA:-${GITHUB_SHA:-HEAD}}}"

is_new_branch=0
case "$BASE" in
    ""|0000000000000000000000000000000000000000) is_new_branch=1 ;;
esac

if [ "$is_new_branch" = 1 ]; then
    # Diff against the default-branch *tip* (not a merge-base): that needs only the
    # two tip trees, so it stays cheap on shallow/partial clones. Falls back to the
    # empty tree (full scan) if no default-branch ref is present.
    BASE="$EMPTY_TREE"
    cands=()
    [ -n "${DEFAULT_BRANCH:-}" ] && cands+=("origin/${DEFAULT_BRANCH}" "${DEFAULT_BRANCH}")
    cands+=(origin/HEAD origin/main main origin/master master)
    for ref in "${cands[@]}"; do
        if git rev-parse --verify --quiet "${ref}^{commit}" >/dev/null 2>&1; then
            BASE=$(git rev-parse "${ref}^{commit}"); break
        fi
    done
else
    # Provided base: ensure it's reachable in this (possibly shallow) checkout;
    # otherwise scan everything (empty tree).
    git cat-file -e "${BASE}^{commit}" 2>/dev/null || \
    git cat-file -e "${BASE}^{tree}"   2>/dev/null || BASE="$EMPTY_TREE"
fi

echo "secret-gate: scanning ${BASE:0:12}..${HEAD:0:12}"

# Describe a flagged line WITHOUT any of its value: the key name for
# `key = value` / `key: value` lines, else just "token-format match".
secret_label() {
    local re='^[[:space:]]*["'"'"']?([A-Za-z0-9_.-]{1,60})["'"'"']?[[:space:]]*[:=]'
    if [[ "$1" =~ $re ]]; then
        printf 'key %s (value not shown)' "${BASH_REMATCH[1]}"
    else
        printf 'token-format match (value not shown)'
    fi
}

# A failing diff (not a repo, unreachable SHA) must not read as "nothing to scan".
if ! staged_files=$(git diff --name-only --diff-filter=ACM "$BASE" "$HEAD" 2>/dev/null); then
    echo "::error::secret-gate could not diff ${BASE:0:12}..${HEAD:0:12} -- failing closed. This is a SCANNER/ENVIRONMENT fault, not a secret finding." >&2
    exit 2
fi
if [ -z "$staged_files" ]; then
    echo "secret-gate: no added/modified files in range — nothing to scan."
    scan_complete=1
    exit 0
fi

block=0

# Returns 0 if the line looks like a committed secret literal.
#
# Implemented with bash-native [[ =~ ]] regex (NOT grep) so the hot path, run on
# every added line, forks no subprocesses. The single sed below runs only on the
# rare line that already matched a secret keyword.
secret_hit() {
    local line="$1" re
    [[ "$line" == *"security-gate:allow"* ]] && return 1

    # High-precision token formats — near-zero false positive at any length.
    re='-----BEGIN [A-Z ]*PRIVATE KEY-----';            [[ "$line" =~ $re ]] && return 0
    re='AKIA[0-9A-Z]{16}';                              [[ "$line" =~ $re ]] && return 0
    re='(ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}';            [[ "$line" =~ $re ]] && return 0
    re='github_pat_[A-Za-z0-9_]{40,}';                  [[ "$line" =~ $re ]] && return 0
    re='glpat-[A-Za-z0-9_-]{20,}';                      [[ "$line" =~ $re ]] && return 0
    re='xox[baprs]-[A-Za-z0-9-]{10,}';                  [[ "$line" =~ $re ]] && return 0
    re='eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'; [[ "$line" =~ $re ]] && return 0

    # Generic: secret-named key assigned a literal high-entropy value (case-insensitive).
    shopt -s nocasematch
    re='(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)[A-Za-z0-9_]*["'"'"' ]*[:=]'
    if [[ ! "$line" =~ $re ]]; then shopt -u nocasematch; return 1; fi
    # Skip references, not literals: env-file indirection, var refs, placeholders.
    re='environmentfile|_file[:=]'
    if [[ "$line" =~ $re ]]; then shopt -u nocasematch; return 1; fi
    shopt -u nocasematch
    local val
    val=$(sed -E 's/^[^:=]*[:=][[:space:]]*//; s/^["'"'"']//; s/["'"'"',[:space:]].*$//' <<<"$line")
    case "$val" in
        ""|\$*|\{*|\<*|/*|~*|%*|'!ENV'*|'!secret'*) return 1 ;;
    esac
    shopt -s nocasematch
    case "$val" in
        *changeme*|*change_me*|*your_*|*your-*|*example*|*placeholder*|*redacted*|*xxxx*|*dummy*|*sample*|*'<'*|*template*) shopt -u nocasematch; return 1 ;;
    esac
    shopt -u nocasematch
    # Flag a high-entropy literal under a secret-named key. A digit is required to
    # exclude plain words. Then qualify by ANY of: mixed character classes (>=16),
    # long pure-hex (>=32 — e.g. a lowercase client_secret), or any long token
    # (>=24 with a digit — base64/hex tokens that lack upper/special chars).
    if [[ "$val" =~ [0-9] ]]; then
        [[ ${#val} -ge 16 && "$val" =~ [A-Z@#%^*+/=_-] ]] && return 0
        [[ ${#val} -ge 32 && "$val" =~ ^[A-Fa-f0-9]+$ ]] && return 0
        [[ ${#val} -ge 24 ]] && return 0
    fi
    return 1
}

# Fill the global `added` array from stdin, one element per line. THE extraction
# path: the scan loop and the canary below both call it, so a reader that silently
# yields nothing is caught. while-read, not `mapfile` (bash 4+); the
# `|| [ -n "$_l" ]` keeps a final line lacking a trailing newline.
fill_added() {
    added=()
    local _l=""
    while IFS= read -r _l || [ -n "$_l" ]; do
        added+=("$_l")
    done
}

# --- Fail-closed canaries ---------------------------------------------------
# A gate that silently stops detecting is worse than none. Before scanning, prove
# detection still works: a known secret MUST be flagged, a known-clean line MUST
# NOT be, and the line reader must return what it was given.
if ! secret_hit 'selftest_password = aB3xY7zQ9mK2pL5wR8nT1vC4dE6f'; then  # security-gate:allow
    echo "::error::secret-gate canary FAILED — a known secret was NOT detected; failing closed (the scanner is broken)." >&2
    exit 2
fi
if secret_hit 'selftest_log_level = info'; then
    echo "::error::secret-gate canary FAILED — a known-clean line WAS flagged; failing closed (the scanner is broken)." >&2
    exit 2
fi
# Pre-seeded sentinel: if fill_added never assigns, `added` stays set, so the
# comparison below is real rather than silently skipped (bash 3.2).
added=("__canary_did_not_run__")
fill_added < <(printf 'alpha\n\nbeta\n')
if [ "${#added[@]}" -ne 3 ] || [ "${added[0]}" != "alpha" ] \
   || [ -n "${added[1]}" ] || [ "${added[2]}" != "beta" ]; then
    echo "::error::secret-gate canary FAILED — the added-line reader returned ${#added[@]} element(s), expected 3; failing closed (every diff would look clean)." >&2
    exit 2
fi

for f in $staged_files; do
    skip=0
    for g in ${SECRET_GATE_EXCLUDE:-}; do
        # shellcheck disable=SC2254  # glob match on purpose
        case "$f" in $g) skip=1 ;; esac
    done
    [ "$skip" = 1 ] && continue

    # Added lines for this file (strip the leading '+').
    fill_added < <(git diff --diff-filter=ACM -U0 "$BASE" "$HEAD" -- "$f" 2>/dev/null \
        | grep -E '^\+' | grep -vE '^\+\+\+' | sed -E 's/^\+//')

    for l in ${added[@]+"${added[@]}"}; do
        if secret_hit "$l"; then
            echo "::error file=${f}::possible committed secret (line redacted)"
            echo "  ✖ SECRET BLOCKED ${f}: $(secret_label "$l")" >&2
            block=1
        fi
    done
done

# Scan loop finished; from here a non-zero exit is a real verdict, not an abort.
scan_complete=1

if [ "$block" -eq 1 ]; then
    echo "" >&2
    echo "secret-gate FAILED: possible secret(s) committed in this change." >&2
    echo "Move the value to an env file or secret store and reference it, or, for a" >&2
    echo "false positive, append '# security-gate:allow' to the line." >&2
    exit 1
fi
echo "secret-gate: clean."
exit 0
