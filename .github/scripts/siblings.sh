#!/usr/bin/env bash
# Usage: bash .github/scripts/siblings.sh [--check] <name>...
#
# Clones each named sibling pinned in .github/siblings.txt into ../<name>, at its pinned commit,
# with core.autocrlf=false, so a job's sibling is ONE commit and never a moving default branch.
# It refuses, before cloning anything:
#   - a name the file does not pin, or pins twice: an unpinned sibling is the failure this exists
#     for (msgrepo's CI went red on 2026-10-05 on a connect commit nobody there made);
#   - a commit that is not a full 40-hex SHA (a branch name, a short SHA, a placeholder);
#   - a URL outside https://github.com/urnetwork/: upstream CI never fetches from a fork. A
#     commit under review in a fork's pull request is fetched from the upstream repository by
#     its SHA, which GitHub serves once the pull request exists.
# --check validates the named pins and clones nothing. SIBLINGS_FILE overrides the pin file;
# repository.yml uses it for the refusal controls, and nothing else should.
set -euo pipefail
here="$(cd "$(dirname "$0")/../.." && pwd)"
pins="${SIBLINGS_FILE:-$here/.github/siblings.txt}"
check=0
if [ "${1:-}" = "--check" ]; then check=1; shift; fi
if [ "$#" -eq 0 ]; then echo "name at least one sibling"; exit 2; fi
for name in "$@"; do
  matches=$(grep -cE "^${name}[[:space:]]" "$pins" || true)
  if [ "$matches" -ne 1 ]; then echo "siblings.txt pins '$name' $matches times, want exactly once"; exit 1; fi
  line=$(grep -E "^${name}[[:space:]]" "$pins")
  read -r _ url sha extra <<<"$line"
  if [ -n "${extra:-}" ]; then echo "the pin for '$name' has fields after the commit: $extra"; exit 1; fi
  if ! printf '%s\n' "$url" | grep -Eqx 'https://github\.com/urnetwork/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.git' || printf '%s\n' "$url" | grep -q '\.\.'; then
    echo "the pin for '$name' fetches from $url, outside https://github.com/urnetwork/: refusing"; exit 1
  fi
  if ! printf '%s\n' "$sha" | grep -Eqx '[0-9a-f]{40}'; then
    echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1
  fi
  if [ "$check" -eq 1 ]; then echo "$name: $url $sha (checked, not cloned)"; continue; fi
  dir="$here/../$name"
  if [ -e "$dir" ]; then echo "$dir already exists; refusing to build on a checkout this script did not make"; exit 1; fi
  git init -q "$dir"
  git -C "$dir" config core.autocrlf false
  git -C "$dir" fetch -q --depth 1 "$url" "$sha"
  git -C "$dir" checkout -q --detach FETCH_HEAD
  test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
  echo "$name at $sha"
done
