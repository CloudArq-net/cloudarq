#!/usr/bin/env bash
# Run before every push, and in CI: a commit is local and recoverable; a
# pushed secret is neither.
#
# Every check reports whether it ran, not only whether it found nothing. A
# check that errors on its own arguments and prints "clean" gives false
# confidence, which is worse than no check at all.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
ran=0

say()  { printf '%-38s %s\n' "$1" "$2"; }

# grep_tree runs grep over every tracked file and sets out, err and rc.
# xargs exits non-zero when any grep it ran found nothing, even while another
# found something (123 with GNU xargs, 1 with BSD's), and it reports a grep
# error with the same code; so what was found is read from the output, and
# an error from grep's own message.
grep_tree() {
  local errfile
  errfile=$(mktemp)
  out=$(git ls-files -z | xargs -0 grep -a "$@" --  2>"$errfile")
  rc=$?
  err=$(cat "$errfile")
  rm -f "$errfile"
}
failed_to_run() { [ -n "$err" ] || { [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ] && [ "$rc" -ne 123 ]; }; }

scan() {
  desc="$1"; shift
  ran=$((ran + 1))
  grep_tree -nE -e "$@"
  if failed_to_run; then
    say "$desc" "SCAN ERROR (exit $rc), not a pass"; printf '%s\n' "$err" | sed 's/^/    /'; fail=1
  elif [ -n "$out" ]; then
    say "$desc" "FOUND:"; printf '%s\n' "$out" | sed 's/^/    /'; fail=1
  else
    say "$desc" "pass"
  fi
}

echo "── secrets ──"
files=$(git ls-files | wc -l | tr -d ' ')
if [ "$files" -eq 0 ]; then
  echo "no tracked files: nothing would be examined"; exit 1
fi
scan "aws access key id"     '(AKIA|ASIA)[0-9A-Z]{16}'
scan "github token"          'gh[pousr]_[A-Za-z0-9]{20,}'
scan "private key block"     'BEGIN [A-Z ]*PRIVATE KEY'
scan "slack token"           'xox[abprs]-[A-Za-z0-9-]{10,}'
scan "generic assignment"    '(api[_-]?key|secret|passwd|password|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{12,}'

# Any routable IPv4 literal in the tree. The scan matches the shape of an
# address rather than any particular one: a scanner that contained the
# address it looks for would publish that address to everyone who reads the
# scanner. Two stages, because ERE has no negative lookahead: pull every
# IPv4 literal out with -o, then drop the ranges that are safe to write down
# on purpose: RFC 5737 documentation, RFC 1918 private, loopback,
# link-local and broadcast.
ran=$((ran + 1))
grep_tree -noE -e '([0-9]{1,3}\.){3}[0-9]{1,3}'
if failed_to_run; then
  say "routable ip literal" "SCAN ERROR (exit $rc), not a pass"; printf '%s\n' "$err" | sed 's/^/    /'; fail=1
else
  ip_hits=$(printf '%s\n' "$out" | grep -v '^$' | grep -vE ':(0\.0\.0\.0|255\.255\.255\.255|127\.[0-9]+\.[0-9]+\.[0-9]+|10\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+|169\.254\.[0-9]+\.[0-9]+|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+)$' || true)
  if [ -n "$ip_hits" ]; then
    say "routable ip literal" "FOUND:"; printf '%s\n' "$ip_hits" | sed 's/^/    /'; fail=1
  else
    say "routable ip literal" "pass"
  fi
fi

ran=$((ran + 1))
if git ls-files | grep -qE '(^|/)\.env($|\.)' ; then
  say "no .env tracked" "FOUND"; fail=1
else
  say "no .env tracked" "pass"
fi

echo
echo "── tree ──"
ran=$((ran + 1))
if [ -n "$(git status --porcelain)" ]; then
  say "working tree clean" "DIRTY: commit first"
  git status --short | sed 's/^/    /'
  fail=1
else
  say "working tree clean" "pass"
fi

echo
echo "──────────────────────────────────────"
echo "checks run: $ran, over $files tracked files"
if [ $fail -eq 0 ]; then
  echo "PREFLIGHT PASS: every check ran and passed"
else
  echo "PREFLIGHT FAIL: do not push"
  exit 1
fi
