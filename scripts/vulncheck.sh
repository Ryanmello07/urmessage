#!/usr/bin/env bash
# scripts/vulncheck.sh: govulncheck over every module of this repository, each loaded the way
# test.sh builds it, under the pinned toolchain.
#
# IT IS A STEP OF test.sh ONLY WHEN ASKED FOR (MESSAGE_TEST_VULNCHECK=1), and that is deliberate.
# It reads the Go vulnerability database over the network, so its verdict changes when the
# database does, with no commit here; test.sh's verdict is a statement about a tree. A red run of
# this script is therefore attributable to one of two things, and it prints both: the tree's
# commit and the database's own modified time. It is run by hand before a release
# (docs/RELEASING.md).
#
# EVERY MODULE FILE HAS A ROW SAYING HOW IT IS LOADED, and the rows are held both ways against the
# files git tracks, as scripts/module-census.sh holds its own: a module file with no row fails, and
# so does a row whose file is gone. The wirings are the census's. They are written out here because
# a scan that loads a module some other way than test.sh builds it reads some other program:
#
#   plain       go.mod, sdk, sdk/livepeer, sdk/liveprobe, and messagegroup/testdata/nfkdgen, the
#               NFKD table's generator, which test.sh runs (LRI R68): ./... as it stands.
#   tests       sdk/cp3b, the acceptance suite. Every Go file in it is a test, so it is scanned with
#               the tool's -test flag: without it the tool is handed one package holding no file.
#   tags:new    protocol/testdata/wiregolden. It builds under exactly one of two tags (test.sh runs
#               both); `new` is this repository's schema. With no tag it does not compile.
#   composed    sdk/cgo, the native library. Its package main is the core SDK's, laid beside this
#               repository's half by sdk/cgo/compose.sh, and it is cgo: with no C compiler the
#               package has no Go file at all and a scan of it would be a scan of nothing. On linux
#               that is a failure, as it is for test.sh; on any other host it is named in the
#               verdict as not scanned.
#   not-scanned sdk/cgo/loopback.go.mod, with its reason below, named in the verdict on every run.
#
# A MODULE THAT HANDS THE TOOL NO GO FILE FAILS. The packages and the files the scan will read are
# counted and printed before each scan, so a walk that found nothing, a tag that excluded
# everything, or a module of tests scanned without its tests cannot read as a clean answer.
#
# THE TOOL'S OWN EXIT STATUS IS READ, AND ITS TWO FAILURES ARE NOT ONE: 3 is "a vulnerability
# reaches this module's code", and anything else that is not 0 is "the scan did not run".
#
# Usage:  bash scripts/vulncheck.sh
#         MESSAGE_TEST_VULNCHECK=1 ./test.sh               the whole run, with this as its last step
#         GOVULNCHECK=v1.9.0 bash scripts/vulncheck.sh     another version of the tool
#
# The siblings must be on disk at their pins, exactly as for test.sh (scripts/siblings.sh).
# The tool is built into a temporary directory with `go install <module>@<version>`, under the
# pinned toolchain, and never enters a go.mod of this repository. It is run as that binary and not
# through `go run`, which answers 1 whatever the program it ran answered.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off
GOTOOLCHAIN=$(bash scripts/toolchain.sh)
export GOTOOLCHAIN
# v1.9.0: v1.1.4 cannot read go1.27's standard library, and its go/ssa panics on a linux build.
tool="golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK:-v1.9.0}"

declare -A how=(
  [go.mod]="plain"
  [sdk/go.mod]="plain"
  [sdk/cp3b/go.mod]="tests"
  [sdk/livepeer/go.mod]="plain"
  [sdk/liveprobe/go.mod]="plain"
  [messagegroup/testdata/nfkdgen/go.mod]="plain"
  [protocol/testdata/wiregolden/go.mod]="tags:new"
  [sdk/cgo/go.mod]="composed"
  [sdk/cgo/loopback.go.mod]="not-scanned"
)
loopback_reason="the loopback harness's modfile: the composed module plus the message server it runs in process, and nothing built from it ships"

bin=$(mktemp -d)
trap 'rm -rf "$bin"' EXIT
GOBIN="$bin" go install "$tool"
govulncheck=$(ls "$bin"/govulncheck*)

echo "tree:     $(git rev-parse HEAD)"
echo "tool:     $tool under $GOTOOLCHAIN"
echo "database: $(curl -fsS https://vuln.go.dev/index/db.json || echo 'UNREADABLE')"

scanned=0
affected=()
unscanned=()
narrowings=()

# scan <module file> <dir> <files template> [flags the go command and the tool both take]: the
# packages the module loads and the Go files the tool will read, counted first, and then the tool
# over the same pattern with the same flags
scan() {
  local modfile=$1 dir=$2 template=$3 counts packages files code
  shift 3
  local list_flags=() tool_flags=()
  for flag in "$@"; do
    tool_flags+=("$flag")
    if [ "$flag" != -test ]; then list_flags+=("$flag"); fi
  done
  if ! counts=$(go -C "$dir" list "${list_flags[@]}" -f "$template" ./...); then
    echo "    FAIL: go list could not load this module"
    unscanned+=("$modfile")
    return
  fi
  packages=$(echo "$counts" | grep -c . || true)
  files=$(echo "$counts" | awk '{ for (i = 1; i <= NF; i++) total += $i } END { print total + 0 }')
  echo "    packages loaded: $packages, Go files the scan reads: $files"
  if [ "$files" = 0 ]; then
    echo "    FAIL: the scan would read no Go file, so a clean answer would be an answer about nothing"
    unscanned+=("$modfile")
    return
  fi
  code=0
  (cd "$dir" && "$govulncheck" "${tool_flags[@]}" ./...) || code=$?
  case "$code" in
    0) scanned=$((scanned + 1)) ;;
    3) scanned=$((scanned + 1)); affected+=("$modfile") ;;
    *) echo "    FAIL: the tool exited $code, which is not a verdict"; unscanned+=("$modfile") ;;
  esac
}
code_files='{{len .GoFiles}} {{len .CgoFiles}}'
test_files='{{len .GoFiles}} {{len .CgoFiles}} {{len .TestGoFiles}} {{len .XTestGoFiles}}'

seen=()
while IFS= read -r modfile; do
  seen+=("$modfile")
  dir=$(dirname "$modfile")
  wiring=${how[$modfile]:-}
  echo "=== $modfile ($wiring)"
  case "$wiring" in
    plain)
      scan "$modfile" "$dir" "$code_files"
      ;;
    tests)
      scan "$modfile" "$dir" "$test_files" -test
      ;;
    tags:*)
      scan "$modfile" "$dir" "$code_files" -tags "${wiring#tags:}"
      ;;
    composed)
      if [ "$(go env CGO_ENABLED)" != 1 ] || ! command -v "$(go env CC)" > /dev/null 2>&1; then
        if [ "$(go env GOOS)" = linux ]; then
          echo "    FAIL: linux with no C compiler or CGO_ENABLED=0: the native library is cgo, and the full scan needs gcc"
          unscanned+=("$modfile")
        else
          echo "    NOT SCANNED: no C compiler on this $(go env GOOS) host, and the native library is cgo"
          narrowings+=("$modfile: no C compiler on this $(go env GOOS) host")
        fi
        continue
      fi
      bash sdk/cgo/compose.sh
      scan "$modfile" "$dir" "$code_files"
      bash sdk/cgo/compose.sh --clean
      ;;
    not-scanned)
      echo "    NOT SCANNED: $loopback_reason"
      narrowings+=("$modfile: $loopback_reason")
      ;;
    *)
      echo "    FAIL: this module file has no row in scripts/vulncheck.sh saying how it is loaded"
      unscanned+=("$modfile")
      ;;
  esac
done < <(git ls-files -- 'go.mod' '*/go.mod' '*.go.mod' | tr -d '\r' | sort)

for modfile in "${!how[@]}"; do
  found=0
  for one in "${seen[@]:-}"; do
    if [ "$one" = "$modfile" ]; then found=1; fi
  done
  if [ "$found" = 0 ]; then
    echo "=== $modfile"
    echo "    FAIL: scripts/vulncheck.sh has a row for this module file and git tracks no such file"
    unscanned+=("$modfile")
  fi
done

if [ "${#seen[@]}" = 0 ]; then
  echo "VERDICT: FAIL (the walk found no module, so nothing was scanned)"
  exit 1
fi
narrowed=""
if [ "${#narrowings[@]}" != 0 ]; then
  narrowed=", NARROWED: $(printf '%s; ' "${narrowings[@]}" | sed 's/; $//')"
fi
if [ "${#unscanned[@]}" != 0 ] || [ "${#affected[@]}" != 0 ]; then
  echo "VERDICT: FAIL ($scanned of ${#seen[@]} modules scanned; with a finding: ${affected[*]:-none}; could not be scanned: ${unscanned[*]:-none}$narrowed)"
  exit 1
fi
echo "VERDICT: PASS ($scanned of ${#seen[@]} modules scanned, no finding$narrowed)"
