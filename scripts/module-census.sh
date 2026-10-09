#!/usr/bin/env bash
# Usage: bash scripts/module-census.sh --rows               the rows, both ways, against the tree
#        bash scripts/module-census.sh --receipts <file>    the rows, and every row's receipts
#        bash scripts/module-census.sh --self-test          the census's own controls
#
# THE MODULE CENSUS. Every go.mod and every alternate modfile (*.go.mod) this repository holds has a
# row naming how test.sh runs it, and the rows are held both ways: a module file with no row fails,
# and so does a row whose file is gone. There is no "not yet wired" list. It held the acceptance
# suite (sdk/cp3b) and the loopback library (sdk/cgo/loopback.go.mod) while they waited for a message
# server switched to this repository's packages; scripts/siblings.txt pins that switch, both run, and
# a module that cannot run is a failure here, not a row.
#
# A ROW IS A PROMISE; A RECEIPT IS THE EVIDENCE. test.sh appends a receipt after each step it
# completes for a module -- "<module file> <step> <detail>", tab-separated -- and only after the
# step succeeded. --receipts requires every step a row's wiring names, so a step deleted from
# test.sh is a missing receipt here, whatever test.sh's text, comments included, still says. The
# library receipt names the file the c-shared build wrote, and the census reads that file's size
# itself. A main package is a binary only a test starts (two copies of message.proto linked into one
# binary fail at init, which build and vet cannot see), so the "mains" step is written only when every
# main package of the module has a test, and the "test" step only when they ran.
#
# Run --receipts from the repository root after test.sh's steps, before it cleans the native build.
set -euo pipefail

declare -A wiring=(
  [go.mod]="root"
  [sdk/go.mod]="sdk"
  [sdk/livepeer/go.mod]="command"
  [sdk/liveprobe/go.mod]="command"
  [sdk/cp3b/go.mod]="go"
  [protocol/testdata/wiregolden/go.mod]="wiregolden"
  [sdk/cgo/go.mod]="composed"
  [sdk/cgo/loopback.go.mod]="loopback"
)
# The steps each wiring owes, in the order test.sh runs them. "platforms" is every cross build of the
# module passing (the root module's darwin, windows and js/wasm, the SDK's darwin and windows);
# "fuzz" is every fuzz target the codec declares, run for its time; "loopback-library" is the
# loopback library built, exporting its harness while the shipping library's header has none of it.
# "toolchain" is what a build wrote answering the pinned toolchain when asked which one built it
# (scripts/toolchain.sh --artefact): the binaries of a "command" module, the live probes that are
# staged on real hosts, and the native library. A go.mod toolchain line never lowers the compiler,
# so the receipt is what says the pin held on the host that ran.
declare -A steps=(
  [go]="verify tidy build vet mains test protobuf"
  [command]="verify tidy build toolchain vet mains test protobuf"
  [root]="verify tidy build vet mains test protobuf platforms fuzz"
  [sdk]="verify tidy build vet mains test protobuf platforms"
  [wiregolden]="verify test:orig test:new base-pinned cmp-connect-golden cross-decode:new cross-decode:orig"
  [composed]="compose verify tidy def-current library toolchain exports vet test protobuf"
  [loopback]="tidy loopback-library"
)
# What a wiring owes on one kind of host only. The loopback library's C consumer,
# sdk/cgo/ctest/message_abi_test.c, is a Windows program (windows.h, CreateThread), as it was in the
# core SDK, so a Windows run owes "ctest" (sdk/cgo/ctest/run.sh) and any other run says it did not
# run it. The host is test.sh's first receipt: host <tab> goos <tab> <GOOS>.
declare -A host_steps=(
  [loopback:windows]="ctest"
)

# The steps a row owes on the host the receipts name.
owed() {
  local file=$1 goos=$2
  echo "${steps[${wiring[$file]}]} ${host_steps[${wiring[$file]}:$goos]:-}"
}

census_files() {
  (git ls-files -- 'go.mod' '*/go.mod' '*.go.mod'; if [ -n "${CENSUS_PLANT:-}" ]; then echo "$CENSUS_PLANT"; fi) |
    { if [ -n "${CENSUS_DROP:-}" ]; then grep -vx "$CENSUS_DROP"; else cat; fi; } | sort -u
}

# The rows against the tree, both ways. Prints the census and answers 0 or 1.
check_rows() {
  local fail=0 found file
  found=$(census_files)
  if [ -z "$found" ]; then echo "FAIL: git ls-files found no module file at all, so the census was asked of nothing"; return 1; fi
  echo "module files in the tree, and how test.sh runs each:"
  for file in $found; do
    if [ -z "${wiring[$file]:-}" ]; then
      echo "  FAIL: $file has no row: give it a wiring that test.sh runs"
      fail=1
    else
      local only
      only=$(for key in "${!host_steps[@]}"; do case "$key" in "${wiring[$file]}:"*) printf '; on %s also %s' "${key#*:}" "${host_steps[$key]}" ;; esac; done)
      echo "  $file: ${wiring[$file]} (${steps[${wiring[$file]}]}$only)"
    fi
  done
  for file in "${!wiring[@]}"; do
    if ! printf '%s\n' $found | grep -qx "$file"; then
      echo "  FAIL: the row for $file names a module file the tree does not hold"
      fail=1
    fi
  done
  return $fail
}

# The receipts against the rows: every step of every row, the library's file and size, and one
# protobuf version across the modules that report one.
check_receipts() {
  local receipts=$1 fail=0 file step detail versions goos
  goos=$(awk -F'\t' '$1 == "host" && $2 == "goos" {print $3; exit}' "$receipts")
  if [ -z "$goos" ]; then
    echo "  FAIL: the receipts name no host (host, goos, <GOOS>), which test.sh writes before any step"
    fail=1
  else
    echo "  host: $goos"
  fi
  for file in $(printf '%s\n' "${!wiring[@]}" | sort); do
    for step in $(owed "$file" "$goos"); do
      if ! awk -F'\t' -v f="$file" -v s="$step" '$1 == f && $2 == s {found = 1} END {exit !found}' "$receipts"; then
        echo "  FAIL: $file has no '$step' receipt: test.sh did not run that step, or it did not pass"
        fail=1
        continue
      fi
      detail=$(awk -F'\t' -v f="$file" -v s="$step" '$1 == f && $2 == s {print $3; exit}' "$receipts")
      if [ "$step" = library ]; then
        local path bytes actual
        read -r path bytes <<<"$detail"
        if [ ! -f "$path" ]; then
          echo "  FAIL: $file's library receipt names $path, which is not there"
          fail=1
          continue
        fi
        actual=$(wc -c < "$path" | tr -d ' ')
        if [ "$actual" -le 0 ] || [ "$actual" != "$bytes" ]; then
          echo "  FAIL: $file's library $path is $actual bytes, its receipt says $bytes"
          fail=1
          continue
        fi
      fi
      echo "  $file $step: $detail"
    done
  done
  versions=$(awk -F'\t' '$2 == "protobuf" {print $3}' "$receipts" | sort -u)
  if [ "$(printf '%s\n' "$versions" | grep -c .)" != 1 ]; then
    echo "  FAIL: the modules resolve google.golang.org/protobuf to $(printf '%s' "$versions" | tr '\n' ' ')- want exactly one version"
    fail=1
  else
    echo "  protobuf: $versions in every module that reports one"
  fi
  return $fail
}

# Every step of every row, as a run that passed everything would write them, with a library file of
# its own; the self-test plants each fault in a copy of this.
complete_receipts() {
  local out=$1 library=$2 goos=$3 file step
  printf 'host\tgoos\t%s\n' "$goos" > "$out"
  for file in $(printf '%s\n' "${!wiring[@]}" | sort); do
    for step in $(owed "$file" "$goos"); do
      case "$step" in
        library) printf '%s\t%s\t%s %s\n' "$file" "$step" "$library" "$(wc -c < "$library" | tr -d ' ')" ;;
        protobuf) printf '%s\t%s\t%s\n' "$file" "$step" "v1.36.11" ;;
        *) printf '%s\t%s\t%s\n' "$file" "$step" "ok" ;;
      esac
    done >> "$out"
  done
}

self_test() {
  local tmp fail=0
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  printf 'not a library\n' > "$tmp/library.so"
  # a Windows run's receipts, which owe every step there is; a linux run's are checked at the end
  complete_receipts "$tmp/complete" "$tmp/library.so" windows
  # expect <pass|fail> <title> <the line a failure must print, or -> <command...>: a control must
  # fail for its own reason, so a failing one's output must hold that reason's line
  expect() {
    local want=$1 title=$2 needle=$3 got
    shift 3
    if "$@" > "$tmp/out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ] && { [ "$needle" = - ] || grep -qF -- "$needle" "$tmp/out"; }; then
      if [ "$needle" = - ]; then
        echo "  control: $title -> $got, as it must"
      else
        echo "  control: $title -> $got, as it must: $needle"
      fi
    else
      echo "  CONTROL BROKEN: $title -> $got, want $want with: $needle"
      sed 's/^/    /' "$tmp/out"
      fail=1
    fi
  }
  expect pass "the tree's own rows" - check_rows
  expect fail "a module file with no row" "FAIL: sdk/planted/go.mod has no row" \
    env CENSUS_PLANT=sdk/planted/go.mod bash "$0" --rows
  expect fail "a row whose module file is gone" "FAIL: the row for sdk/cp3b/go.mod names a module file the tree does not hold" \
    env CENSUS_DROP=sdk/cp3b/go.mod bash "$0" --rows
  expect pass "every receipt present" - check_receipts "$tmp/complete"
  awk -F'\t' '!($1 == "sdk/cgo/go.mod" && $2 == "library")' "$tmp/complete" > "$tmp/no-library"
  expect fail "the c-shared build deleted from test.sh" "FAIL: sdk/cgo/go.mod has no 'library' receipt" check_receipts "$tmp/no-library"
  awk -F'\t' '!($1 == "sdk/cgo/go.mod" && $2 == "compose")' "$tmp/complete" > "$tmp/no-compose"
  expect fail "the compose step deleted from test.sh" "FAIL: sdk/cgo/go.mod has no 'compose' receipt" check_receipts "$tmp/no-compose"
  awk -F'\t' '!($1 == "sdk/cp3b/go.mod" && $2 == "test")' "$tmp/complete" > "$tmp/no-cp3b"
  expect fail "the acceptance suite's tests not run" "FAIL: sdk/cp3b/go.mod has no 'test' receipt" check_receipts "$tmp/no-cp3b"
  awk -F'\t' '!($1 == "sdk/cgo/loopback.go.mod" && $2 == "ctest")' "$tmp/complete" > "$tmp/no-ctest"
  expect fail "the loopback library's C consumer not run on Windows" "FAIL: sdk/cgo/loopback.go.mod has no 'ctest' receipt" check_receipts "$tmp/no-ctest"
  awk -F'\t' '!($1 == "sdk/cgo/loopback.go.mod" && $2 == "loopback-library")' "$tmp/complete" > "$tmp/no-loopback"
  expect fail "the loopback library not built" "FAIL: sdk/cgo/loopback.go.mod has no 'loopback-library' receipt" check_receipts "$tmp/no-loopback"
  awk -F'\t' '!($1 == "host")' "$tmp/complete" > "$tmp/no-host"
  expect fail "receipts that name no host" "the receipts name no host" check_receipts "$tmp/no-host"
  complete_receipts "$tmp/linux" "$tmp/library.so" linux
  expect pass "a linux run, which does not owe the Windows C consumer" - check_receipts "$tmp/linux"
  if grep -q 'ctest' "$tmp/linux"; then echo "  CONTROL BROKEN: a linux run's complete receipts hold a ctest step"; fail=1; fi
  awk -F'\t' '!($1 == "go.mod" && $2 == "fuzz")' "$tmp/complete" > "$tmp/no-fuzz"
  expect fail "the codec's fuzz targets not run" "FAIL: go.mod has no 'fuzz' receipt" check_receipts "$tmp/no-fuzz"
  awk -F'\t' '!($1 == "sdk/go.mod" && $2 == "platforms")' "$tmp/complete" > "$tmp/no-platforms"
  expect fail "the SDK's platform builds not run" "FAIL: sdk/go.mod has no 'platforms' receipt" check_receipts "$tmp/no-platforms"
  awk -F'\t' '!($1 == "sdk/cgo/go.mod" && $2 == "toolchain")' "$tmp/complete" > "$tmp/no-library-toolchain"
  expect fail "the native library not asked which toolchain built it" "FAIL: sdk/cgo/go.mod has no 'toolchain' receipt" check_receipts "$tmp/no-library-toolchain"
  awk -F'\t' '!($1 == "sdk/liveprobe/go.mod" && $2 == "toolchain")' "$tmp/complete" > "$tmp/no-probe-toolchain"
  expect fail "the live probe's binary not asked which toolchain built it" "FAIL: sdk/liveprobe/go.mod has no 'toolchain' receipt" check_receipts "$tmp/no-probe-toolchain"
  if grep -q "$(printf 'sdk/cp3b/go.mod\ttoolchain')" "$tmp/complete"; then echo "  CONTROL BROKEN: the acceptance suite, which builds no binary, owes a toolchain receipt"; fail=1; fi
  sed "s#$tmp/library.so#$tmp/gone.so#" "$tmp/complete" > "$tmp/gone-library"
  expect fail "a library receipt naming a file that is not there" "gone.so, which is not there" check_receipts "$tmp/gone-library"
  awk -F'\t' 'BEGIN {OFS = "\t"} $1 == "sdk/go.mod" && $2 == "protobuf" {$3 = "v1.36.10"} {print}' "$tmp/complete" > "$tmp/two-protobufs"
  expect fail "two protobuf versions" "want exactly one version" check_receipts "$tmp/two-protobufs"
  return $fail
}

case "${1:-}" in
  --rows)
    if check_rows; then echo "CENSUS ROWS PASS"; else echo "CENSUS ROWS FAIL"; exit 1; fi
    ;;
  --receipts)
    receipts=${2:?--receipts needs the receipts file test.sh wrote}
    fail=0
    check_rows || fail=1
    echo "receipts ($receipts):"
    check_receipts "$receipts" || fail=1
    if [ "$fail" = 0 ]; then echo "CENSUS PASS"; else echo "CENSUS FAIL"; exit 1; fi
    ;;
  --self-test)
    echo "the census's own controls:"
    if self_test; then echo "CENSUS SELF-TEST PASS"; else echo "CENSUS SELF-TEST FAIL"; exit 1; fi
    ;;
  *)
    echo "usage: bash scripts/module-census.sh --rows | --receipts <file> | --self-test" >&2
    exit 2
    ;;
esac
