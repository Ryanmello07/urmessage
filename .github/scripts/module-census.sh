#!/usr/bin/env bash
# Usage: bash .github/scripts/module-census.sh [--rows-only]
#
# --rows-only checks the census rows against the tree, both ways, and builds nothing; with
# CENSUS_PLANT naming a module file, that file is counted as if the tree held it. repository.yml
# uses the two for the census's own control, and nothing else should.
#
# THE MODULE CENSUS. Every go.mod and every alternate modfile (*.go.mod) this repository holds is
# either BUILT, VETTED AND HAS ITS MAIN PACKAGES' TESTS RUN, or it is listed in NOT_YET_WIRED with
# the reason, and the census is held both ways: a module file with no row fails, and so does a row
# whose file is gone. Run from the repository root, on linux, with the siblings
# .github/siblings.txt pins checked out beside it (connect, connect-golden, glog, gvisor).
#
# WHY MAIN PACKAGES' TESTS AND NOT ONLY A BUILD. A defect that shows only when a binary STARTS --
# two copies of message.proto linked into one binary, which protobuf refuses at init -- is
# invisible to build and to vet. `go test` runs a package's init before its first case, so a main
# package with a test is a binary that is started on every run, and a main package without one is
# refused here.
#
# HOW EACH MODULE IS WIRED:
#   build      go build, go vet, and go test of every main package, here;
#   tags:a,b   the same, once per build tag (a module whose files need one to build at all);
#   composed   built only laid over the core SDK's cgo package main: native.yml composes, builds
#              and tests it, and this census holds that native.yml does (it names compose.sh,
#              the c-shared build and `go test`).
# The full suites of each module run in their own workflows (test.yml, sdk.yml, protocol.yml,
# native.yml); this is the census, not a second copy of them.
set -euo pipefail

declare -A wired=(
  [go.mod]="build"
  [sdk/go.mod]="build"
  [sdk/livepeer/go.mod]="build"
  [sdk/liveprobe/go.mod]="build"
  [protocol/testdata/wiregolden/go.mod]="tags:orig,new"
  [sdk/cgo/go.mod]="composed"
)
# The list must be empty by SPLIT-PLAN M7. Each waits on the message server's switch to this
# repository's packages (message-server's own pull request) and, for cp3b, a postgres in CI.
declare -A not_yet_wired=(
  [sdk/cp3b/go.mod]="the cross-process suite runs devices against a real message server and its store: it waits for the message-server switch to merge, then a pinned message-server sibling and postgres:17 in CI"
  [sdk/cgo/loopback.go.mod]="the loopback library runs the message server in process (urnet_message_loopback); same wait"
)

fail=0
rows_only=0
if [ "${1:-}" = "--rows-only" ]; then rows_only=1; fi
found=$( (git ls-files -- 'go.mod' '*/go.mod' '*.go.mod'; if [ -n "${CENSUS_PLANT:-}" ]; then echo "$CENSUS_PLANT"; fi) | sort -u)
test -n "$found" || { echo "FAIL: git ls-files found no module file at all, so the census was asked of nothing"; exit 1; }
echo "module files in the tree:"
printf '  %s\n' $found
for file in $found; do
  if [ -z "${wired[$file]:-}" ] && [ -z "${not_yet_wired[$file]:-}" ]; then
    echo "FAIL: $file has no census row: wire it into CI (build, vet, its main packages' tests) or list it in not_yet_wired with the reason"
    fail=1
  fi
  if [ -n "${wired[$file]:-}" ] && [ -n "${not_yet_wired[$file]:-}" ]; then
    echo "FAIL: $file is both wired and not yet wired"
    fail=1
  fi
done
for file in "${!wired[@]}" "${!not_yet_wired[@]}"; do
  if ! printf '%s\n' $found | grep -qx "$file"; then
    echo "FAIL: the census row for $file names a module file the tree does not hold"
    fail=1
  fi
done

if [ "$rows_only" = 1 ]; then
  if [ "$fail" = 0 ]; then echo "CENSUS ROWS PASS"; else echo "CENSUS ROWS FAIL"; fi
  exit $fail
fi

protobuf_versions=""
check_module() {
  local dir=$1
  shift
  local flags=("$@")
  echo "== $dir ${flags[*]:-}"
  local mains
  # the template prints an empty line for every package that is not main; keep the others
  mains=$(go -C "$dir" list "${flags[@]}" -f '{{if eq .Name "main"}}{{.ImportPath}} {{len .TestGoFiles}} {{len .XTestGoFiles}}{{end}}' ./... | grep . || true)
  if [ -z "$mains" ]; then
    echo "  no main package"
    go -C "$dir" build "${flags[@]}" ./... || return 1
  else
    # -o into a directory of its own: a pattern that matches exactly one main package would
    # otherwise write that command's binary into the checkout
    local out
    out=$(mktemp -d)
    go -C "$dir" build -o "$out/" "${flags[@]}" ./... || { rm -rf "$out"; return 1; }
    rm -rf "$out"
  fi
  go -C "$dir" vet "${flags[@]}" ./... || return 1
  while read -r pkg tests xtests; do
    [ -n "$pkg" ] || continue
    if [ "$tests" = 0 ] && [ "$xtests" = 0 ]; then
      echo "FAIL: main package $pkg has no test, so its binary is never started by CI"
      return 1
    fi
    go -C "$dir" test -count=1 "${flags[@]}" "$pkg" || return 1
  done <<< "$mains"
}
for file in $(printf '%s\n' "${!wired[@]}" | sort); do
  dir=$(dirname "$file")
  how=${wired[$file]}
  case "$how" in
    build)
      check_module "$dir" || { echo "FAIL: $dir"; fail=1; }
      protobuf_versions+="$dir $(go -C "$dir" list -m google.golang.org/protobuf 2>/dev/null | awk '{print $2}')"$'\n'
      ;;
    tags:*)
      for tag in $(printf '%s' "${how#tags:}" | tr ',' ' '); do
        check_module "$dir" -tags "$tag" || { echo "FAIL: $dir -tags $tag"; fail=1; }
      done
      ;;
    composed)
      native=.github/workflows/native.yml
      for needle in "sdk/cgo/compose.sh" "-buildmode=c-shared" "go test"; do
        if ! grep -qF -- "$needle" "$native"; then
          echo "FAIL: $file is composed, and $native does not name '$needle'"
          fail=1
        fi
      done
      echo "== $dir composed: built and tested by $native"
      ;;
    *)
      echo "FAIL: $file has an unknown wiring '$how'"
      fail=1
      ;;
  esac
done

# PROTOBUF EQUALITY: one protobuf version in every module built here, so the schema's generated code
# and the runtime that registers it are the same release in each of them. (native.yml checks the
# composition module against the root.)
echo "protobuf, resolved per module:"
printf '%s' "$protobuf_versions" | sed 's/^/  /'
distinct=$(printf '%s' "$protobuf_versions" | awk 'NF == 2 {print $2}' | sort -u | wc -l)
modules=$(printf '%s' "$protobuf_versions" | awk 'NF == 2' | wc -l)
if [ "$distinct" != 1 ] || [ "$modules" != "$(printf '%s' "$protobuf_versions" | grep -c .)" ]; then
  echo "FAIL: the modules resolve google.golang.org/protobuf to $distinct versions (or a module resolved none)"
  fail=1
fi

echo "NOT_YET_WIRED (must be empty by M7):"
for file in $(printf '%s\n' "${!not_yet_wired[@]}" | sort); do
  echo "  $file: ${not_yet_wired[$file]}"
done
if [ "$fail" = 0 ]; then echo "CENSUS PASS"; else echo "CENSUS FAIL"; fi
exit $fail
