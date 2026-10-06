#!/usr/bin/env bash
# Usage: bash scripts/siblings.sh [--check|--verify] <name>...
#
#   (no flag)  clone each named sibling pinned in scripts/siblings.txt into ../<name>, at its pinned
#              commit, with core.autocrlf=false, so a sibling is ONE commit and never a moving branch;
#   --check    validate the named pins and clone nothing;
#   --verify   require ../<name> to be a git checkout whose HEAD is the pinned commit and whose
#              tracked files are unmodified. test.sh runs this before it builds anything.
#
# It refuses, before cloning or accepting anything:
#   - a name the file does not pin, or pins twice: an unpinned sibling is the failure this exists
#     for (message-server's checks went red on 2026-10-05 on a connect commit nobody there made);
#   - a commit that is not a full 40-hex SHA (a branch name, a short SHA, a placeholder);
#   - a URL outside https://github.com/urnetwork/: a commit under review in a fork's pull request is
#     fetched from the upstream repository by its SHA, which GitHub serves once the pull request
#     exists, never from the fork.
#
# MESSAGE_TEST_UNPINNED, a comma-separated list of names, lets --verify accept those siblings at
# whatever commit they are checked out at, placeholder pin or not. Each is printed as UNPINNED with
# both commits, and test.sh carries the list into its verdict: such a run is not the pinned
# integration run, and says so. SIBLINGS_FILE overrides the pin file; test.sh's control uses it.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
pins="${SIBLINGS_FILE:-$here/scripts/siblings.txt}"
mode=clone
case "${1:-}" in
  --check) mode=check; shift ;;
  --verify) mode=verify; shift ;;
esac
if [ "$#" -eq 0 ]; then echo "name at least one sibling"; exit 2; fi
unpinned=",${MESSAGE_TEST_UNPINNED:-},"
status=0
for name in "$@"; do
  matches=$(grep -cE "^${name}[[:space:]]" "$pins" || true)
  if [ "$matches" -ne 1 ]; then echo "siblings.txt pins '$name' $matches times, want exactly once"; exit 1; fi
  line=$(grep -E "^${name}[[:space:]]" "$pins")
  read -r _ url sha extra <<<"$line"
  if [ -n "${extra:-}" ]; then echo "the pin for '$name' has fields after the commit: $extra"; exit 1; fi
  if ! printf '%s\n' "$url" | grep -Eqx 'https://github\.com/urnetwork/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.git' || printf '%s\n' "$url" | grep -q '\.\.'; then
    echo "the pin for '$name' fetches from $url, outside https://github.com/urnetwork/: refusing"; exit 1
  fi
  pinned=1
  if ! printf '%s\n' "$sha" | grep -Eqx '[0-9a-f]{40}'; then pinned=0; fi
  accept_unpinned=0
  case "$unpinned" in *",$name,"*) accept_unpinned=1 ;; esac
  dir="$here/../$name"
  case "$mode" in
    check)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      echo "$name: $url $sha (checked, not cloned)"
      ;;
    clone)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      if [ -e "$dir" ]; then echo "$dir already exists; refusing to build on a checkout this script did not make"; exit 1; fi
      git init -q "$dir"
      git -C "$dir" config core.autocrlf false
      git -C "$dir" fetch -q --depth 1 "$url" "$sha"
      git -C "$dir" checkout -q --detach FETCH_HEAD
      test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
      echo "$name at $sha"
      ;;
    verify)
      if [ ! -d "$dir" ]; then echo "MISSING $name: $dir is not there"; status=1; continue; fi
      head=$(git -C "$dir" rev-parse --verify -q HEAD || true)
      if [ -z "$head" ]; then echo "MISSING $name: $dir is not a git checkout"; status=1; continue; fi
      dirty=$(git -C "$dir" status --porcelain --untracked-files=no | head -5)
      if [ -n "$dirty" ]; then echo "DIRTY $name: $dir has modified tracked files:"; printf '  %s\n' "$dirty"; status=1; continue; fi
      if [ "$pinned" = 1 ] && [ "$head" = "$sha" ]; then echo "PINNED $name $head"; continue; fi
      if [ "$accept_unpinned" = 1 ]; then echo "UNPINNED $name $head (scripts/siblings.txt pins $sha)"; continue; fi
      if [ "$pinned" = 0 ]; then
        echo "UNPINNABLE $name: scripts/siblings.txt pins '$sha', not a commit; fill the pin in, or name it in MESSAGE_TEST_UNPINNED to run against $head"
      else
        echo "WRONG COMMIT $name: $dir is at $head, scripts/siblings.txt pins $sha"
      fi
      status=1
      ;;
  esac
done
exit $status
