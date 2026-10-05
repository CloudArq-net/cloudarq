#!/usr/bin/env bash
# Prints the engine's version, one line: the commit as git describes it,
# without the leading v. This is the one place the version is worked out;
# make release and web/engine/build.sh both ask it.
#
#   0.3.0                 the commit carries the release tag v0.3.0
#   0.3.0-2-g1a2b3c4      two commits after v0.3.0
#   1a2b3c4               no release tag in the commit's history
#   ...-dirty             a tracked file differs from the commit
#   0.0.0-dev             not run in a git work tree, as from a source archive
#
# Only a tag written as a release's, v and a digit, names a version. A tag of
# any other kind, such as a backup tag or one that merely begins with v (a
# vendor-x), never does.
#
# usage: scripts/version.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C

# Outside a git work tree the version is 0.0.0-dev. Any other failure of git
# is printed and fails the script, rather than naming a build 0.0.0-dev.
if ! command -v git > /dev/null; then
  echo 0.0.0-dev
  exit 0
fi
if ! inside=$(git rev-parse --is-inside-work-tree 2>&1); then
  case "$inside" in
    *"not a git repository"*)
      echo 0.0.0-dev
      exit 0
      ;;
  esac
  printf 'version.sh: git rev-parse failed: %s\n' "$inside" >&2
  exit 1
fi
if [ "$inside" != true ]; then
  echo 0.0.0-dev
  exit 0
fi

version=$(git describe --tags --always --dirty --match 'v[0-9]*')
echo "${version#v}"
