#!/usr/bin/env bash
# Usage: bash scripts/siblings.sh [--check|--verify] <name>...
#        bash scripts/siblings.sh --self-test
#
#   (no flag)    clone each named sibling pinned in scripts/siblings.txt into ../<name>, at its
#                pinned commit, with core.autocrlf=false, so a sibling is ONE commit and never a
#                moving branch;
#   --check      validate the named pins and clone nothing;
#   --verify     require ../<name> to be a git checkout whose HEAD is the pinned commit and whose
#                tracked files are unmodified. test.sh runs this before it builds anything;
#   --self-test  this script's own controls: each refusal below, on pin files written for it.
#
# It refuses, before cloning or accepting anything:
#   - a name the file does not pin, or pins twice: an unpinned sibling is the failure this exists
#     for (message-server's checks went red on 2026-10-05 on a connect commit nobody there made);
#   - a commit that is not a full 40-hex SHA (a branch name, a short SHA, a placeholder);
#   - a fetch source that is neither https://github.com/urnetwork/<repository>.git nor one of the
#     REVIEW SOURCES listed below, exactly.
#
# THE PIN IS THE COMMIT, AND THE URL IS ONLY WHERE IT IS FETCHED FROM. A commit id names its content,
# so no fetch source can change what a pin builds; what the URL rule protects is that the pins can
# be fetched from the project's own repositories by anyone, for good.
#
# REVIEW SOURCES. A set of pull requests that must be built and tested together pins commits of
# one another's branches, and those commits exist on a fork before any of them is merged upstream.
# Such a fork is named in the list below, exactly, and nothing else outside urnetwork/ is accepted:
# not another repository of the same owner, not another owner's fork of the same repository.
# --check and --verify print FORK and the URL beside such a pin, and test.sh carries it into its
# verdict, so a run against a commit the upstream repository does not hold yet says so every time.
#
# THE LIST IS EMPTY. This repository arrived as one of such a set: its import, message-server's
# switch to these packages, and the removals from urnetwork/sdk and urnetwork/connect. Three forks
# were listed here until the set merged, all of it on 2026-10-09, each pull request with a merge
# commit (urnetwork/message 07704991, urnetwork/message-server e9eae67a, urnetwork/sdk b8209d9d,
# urnetwork/connect 847460bb). The three pins are those merge commits now, every pin is fetched
# from urnetwork/, and --self-test holds each of the three former sources to being refused.
#
# WHEN A PULL REQUEST MERGES (with a merge commit, so its commits keep their ids), the pinned
# commit is in the upstream repository: change that sibling's URL in scripts/siblings.txt back to
# https://github.com/urnetwork/..., and delete its line here. With no line left, --self-test has no
# review source to accept, and says so.
#
# MESSAGE_TEST_UNPINNED, a comma-separated list of names, lets --verify accept those siblings at
# whatever commit they are checked out at, placeholder pin or not. Each is printed as UNPINNED with
# both commits, and test.sh carries the list into its verdict: such a run is not the pinned
# integration run, and says so. SIBLINGS_FILE overrides the pin file; --self-test uses it.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
pins="${SIBLINGS_FILE:-$here/scripts/siblings.txt}"

# The forks a commit of a pull request under review may be fetched from, one URL per line. None today.
review_sources="
"

# source_of <url>: prints "upstream" or "fork", or fails for a fetch source this script refuses.
source_of() {
  local url=$1
  if printf '%s\n' "$url" | grep -q '\.\.'; then return 1; fi
  if printf '%s\n' "$url" | grep -Eqx 'https://github\.com/urnetwork/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.git'; then
    echo upstream
    return 0
  fi
  if printf '%s\n' "$review_sources" | grep -qxF -- "$url"; then
    echo fork
    return 0
  fi
  return 1
}

self_test() {
  local tmp failed=0 sha=0123456789abcdef0123456789abcdef01234567 out
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  # expect <pass|fail> <title> <the line a refusal must print, or the word an acceptance must> <pin line...>
  expect() {
    local want=$1 title=$2 needle=$3 got
    shift 3
    printf '%s\n' "$@" > "$tmp/pins"
    if out=$(SIBLINGS_FILE="$tmp/pins" bash "$0" --check one 2>&1); then got=pass; else got=fail; fi
    if [ "$got" = "$want" ] && printf '%s\n' "$out" | grep -qF -- "$needle"; then
      echo "  control: $title -> $got, as it must: $out"
    else
      echo "  CONTROL BROKEN: $title -> $got, want $want with: $needle"
      printf '%s\n' "$out" | sed 's/^/    /'
      failed=1
    fi
  }
  expect pass "a commit of an urnetwork repository" "(checked, not cloned)" "one https://github.com/urnetwork/connect.git $sha"
  local first
  first=$(printf '%s\n' "$review_sources" | grep . | head -n 1)
  if [ -n "$first" ]; then
    expect pass "a commit of a pull request on a listed review source" "FORK $first" "one $first $sha"
  else
    echo "  no review source is listed, so none is accepted: every pin is fetched from urnetwork/"
  fi
  # the three forks this list named until their pull requests merged (2026-10-09), each refused now
  local former
  for former in https://github.com/Ryanmello07/connect.git https://github.com/Ryanmello07/urnetwork-sdk.git https://github.com/Ryanmello07/urnetwork-message-server.git; do
    expect fail "a fork that was a review source until its pull request merged" "fetches from $former, which is neither https://github.com/urnetwork/ nor a listed review source" "one $former $sha"
  done
  expect fail "another repository of the same owner" "neither https://github.com/urnetwork/ nor a listed review source" "one https://github.com/Ryanmello07/unlisted.git $sha"
  expect fail "another owner's fork of a listed repository" "neither https://github.com/urnetwork/ nor a listed review source" "one https://github.com/someone-else/connect.git $sha"
  expect fail "a fork's URL with a path after it" "neither https://github.com/urnetwork/ nor a listed review source" "one https://github.com/Ryanmello07/connect.git/../../someone-else/connect.git $sha"
  expect fail "an urnetwork URL on another host" "neither https://github.com/urnetwork/ nor a listed review source" "one https://github.com.example.invalid/urnetwork/connect.git $sha"
  expect fail "an urnetwork URL that is not https" "neither https://github.com/urnetwork/ nor a listed review source" "one http://github.com/urnetwork/connect.git $sha"
  expect fail "an urnetwork URL that climbs out" "neither https://github.com/urnetwork/ nor a listed review source" "one https://github.com/urnetwork/../someone-else/connect.git $sha"
  expect fail "a short commit" "is not a full commit SHA" "one https://github.com/urnetwork/connect.git 0123456"
  expect fail "a branch name for a commit" "is not a full commit SHA" "one https://github.com/urnetwork/connect.git main"
  expect fail "a placeholder for a commit" "is not a full commit SHA" "one https://github.com/urnetwork/connect.git FILL_IN_THE_HEAD"
  expect fail "a field after the commit" "has fields after the commit" "one https://github.com/urnetwork/connect.git $sha main"
  expect fail "a name pinned twice" "pins 'one' 2 times" "one https://github.com/urnetwork/connect.git $sha" "one https://github.com/urnetwork/sdk.git $sha"
  expect fail "a name not pinned at all" "pins 'one' 0 times" "other https://github.com/urnetwork/connect.git $sha"
  return "$failed"
}

mode=clone
case "${1:-}" in
  --check) mode=check; shift ;;
  --verify) mode=verify; shift ;;
  --self-test)
    echo "the sibling pins' own controls:"
    if self_test; then echo "SIBLINGS SELF-TEST PASS"; exit 0; fi
    echo "SIBLINGS SELF-TEST FAIL"
    exit 1
    ;;
esac
if [ "$#" -eq 0 ]; then echo "name at least one sibling"; exit 2; fi
unpinned=",${MESSAGE_TEST_UNPINNED:-},"
status=0
for name in "$@"; do
  matches=$(grep -cE "^${name}[[:space:]]" "$pins" || true)
  if [ "$matches" -ne 1 ]; then echo "siblings.txt pins '$name' $matches times, want exactly once"; exit 1; fi
  line=$(grep -E "^${name}[[:space:]]" "$pins" | tr -d '\r')
  read -r _ url sha extra <<<"$line"
  if [ -n "${extra:-}" ]; then echo "the pin for '$name' has fields after the commit: $extra"; exit 1; fi
  if ! from=$(source_of "$url"); then
    echo "the pin for '$name' fetches from $url, which is neither https://github.com/urnetwork/ nor a listed review source: refusing"; exit 1
  fi
  note=""
  if [ "$from" = fork ]; then note=" FORK $url"; fi
  pinned=1
  if ! printf '%s\n' "$sha" | grep -Eqx '[0-9a-f]{40}'; then pinned=0; fi
  accept_unpinned=0
  case "$unpinned" in *",$name,"*) accept_unpinned=1 ;; esac
  dir="$here/../$name"
  case "$mode" in
    check)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      echo "$name: $url $sha (checked, not cloned)$note"
      ;;
    clone)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      if [ -e "$dir" ]; then echo "$dir already exists; refusing to build on a checkout this script did not make"; exit 1; fi
      git init -q "$dir"
      git -C "$dir" config core.autocrlf false
      if ! git -C "$dir" fetch -q --depth 1 "$url" "$sha"; then
        echo "the pin for '$name' could not be fetched: $url does not serve $sha (not pushed there yet, or the URL is the wrong repository)"
        rm -rf "$dir"
        exit 1
      fi
      git -C "$dir" checkout -q --detach FETCH_HEAD
      test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
      echo "$name at $sha$note"
      ;;
    verify)
      if [ ! -d "$dir" ]; then echo "MISSING $name: $dir is not there"; status=1; continue; fi
      head=$(git -C "$dir" rev-parse --verify -q HEAD || true)
      if [ -z "$head" ]; then echo "MISSING $name: $dir is not a git checkout"; status=1; continue; fi
      dirty=$(git -C "$dir" status --porcelain --untracked-files=no | head -5)
      if [ -n "$dirty" ]; then echo "DIRTY $name: $dir has modified tracked files:"; printf '  %s\n' "$dirty"; status=1; continue; fi
      if [ "$pinned" = 1 ] && [ "$head" = "$sha" ]; then echo "PINNED $name $head$note"; continue; fi
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
