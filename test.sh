#!/usr/bin/env bash
# test.sh: build and test everything this repository holds, on the machine it runs on.
#
#   ./test.sh                                   from the repository root, or from anywhere
#
# THERE IS NO CI SERVICE. Like connect and the core SDK, this repository is built and tested on the
# maintainers' own hardware (urnetwork/connect e8611390: "We build and test on our own hardware and
# do not use GitHub Actions"), so this script is where every check beyond a plain `go test ./...`
# runs, in this order:
#
#   1. the siblings beside the repository at the commits scripts/siblings.txt pins (a missing one is
#      cloned; a pin fetched from a fork, a pull request head, is named in the verdict), the pin
#      script's own controls, and the checkout's line endings;
#   2. the module census's own controls and its rows against the tree, and the toolchain check's
#      own controls;
#   3. formatting: gofmt over every tracked Go file that is source (fixtures under testdata are not;
#      the loopback harness, which a build overlay compiles from under one, is);
#   4. every module scripts/module-census.sh has a row for, by its wiring:
#        go          go mod verify, go mod tidy -diff, build, vet, every main package has a test,
#                    go test with the race detector (the root module with the core SDK and
#                    connect required beside it: the record gate and the frame code-point names);
#        wiregolden  the corpus's pinned base lines against connect from before the removal, byte
#                    for byte, and each emission decoded into the other build's types;
#        composed    the native library: the core SDK's cgo package main composed under sdk/cgo, the
#                    .def regenerated and unchanged, the library built by sdk/cgo/build.sh (c-shared,
#                    the core's release flags), the toolchain it records, its exports against the
#                    .def both ways, the composed module's tests;
#        command     as go, and the binaries the build wrote record the pinned toolchain (the live
#                    probes, which are staged on real hosts);
#        loopback    the loopback library, built with its harness, on every host; on Windows also its
#                    C consumer (sdk/cgo/ctest/run.sh), which is a Windows program;
#      and the platform builds of the root module (darwin, windows, js/wasm) and the SDK;
#   5. protocol/message.pb.go regenerated with the pinned protoc 35.1 and protoc-gen-go v1.36.11;
#   6. the codec's fuzz targets, 60 s each (a done-when of spec A section 13);
#   7. the census over what ran: every row's receipts that this host owes.
#
# THE WHOLE RUN IS UNDER THE PINNED TOOLCHAIN, whatever go command the host has. The cryptographic
# code is reviewed under one compiler, the `toolchain` line of go.mod (mls/pins_test.go holds every
# test binary to it), and that line is a minimum: a newer go command builds with itself and says
# nothing. So this script reads the pin (scripts/toolchain.sh), exports GOTOOLCHAIN for every go
# command it starts and every one those start, stops with the fix named when the pin cannot be had,
# and asks what it built which toolchain built it: the live probes' binaries, the native library and
# the loopback library. The check's own controls run in step 2.
#
# Every step runs and is reported; the exit status is 0 only if none failed. A step this host cannot
# run is SKIPPED or named as narrower, with its reason, and a module that therefore lacks a receipt
# this host owes fails the census. The full run is two runs: linux with gcc (the race detector, nm,
# the pinned protoc fetched by digest), and Windows from a clone made with core.autocrlf=true (the
# line-ending gates against the checkout they are written for, which step 1 asserts, the Windows
# library, and the loopback library's C consumer).
#
# Environment:
#   MESSAGE_TEST_UNPINNED  comma list of siblings accepted at whatever commit they are checked out at
#                          (scripts/siblings.sh); the verdict names them
#   MESSAGE_TEST_FUZZTIME  per fuzz target (default 60s); any other value is named in the verdict
#   MESSAGE_TEST_FUZZ_WORKERS  the fuzzing engine's worker count (-parallel; default one per CPU).
#                          Each worker is a process of its own: a 24-core Windows host whose page
#                          file could not grow ran out of commit memory in a fuzz leg
#   MESSAGE_TEST_TIMEOUT   per go test invocation (default 3h)
#   PROTOC                 a protoc 35.1 binary, when none is on PATH (linux and Windows on x86-64
#                          fetch the pinned release by digest themselves)
#   WARP_VERSION           the SDK version the native library reports (default 0.0.0-test)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
export GOWORK=off

# The pin, forced before the first go command. A host that cannot have that toolchain stops here:
# nothing after this line would be testing what ships.
if ! pinned_toolchain=$(bash scripts/toolchain.sh); then
  echo "VERDICT: FAIL (go.mod names no toolchain to pin; nothing was run)"
  exit 1
fi
export GOTOOLCHAIN="$pinned_toolchain"
if ! bash scripts/toolchain.sh --check; then
  echo
  echo "VERDICT: FAIL (this host cannot run the pinned toolchain $pinned_toolchain, above; nothing was run)"
  exit 1
fi

work=$(mktemp -d)
receipts="$work/receipts.tsv"
: > "$receipts"
results=()
narrowings=()
composed=0

cleanup() {
  if [ "$composed" = 1 ] && [ -f sdk/cgo/.composed ]; then bash sdk/cgo/compose.sh --clean > /dev/null; fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

record() {
  results+=("$1|$2|$3")
  if [ -n "$3" ]; then echo "-- $1: $2 ($3)"; else echo "-- $1: $2"; fi
}
pass() { record PASS "$1" "${2:-}"; }
fail() { record FAIL "$1" "${2:-}"; }
skip() { record SKIPPED "$1" "$2"; narrowings+=("$1: $2"); }
receipt() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-ok}" >> "$receipts"; }
# run <name> <command...>: runs it, records PASS or FAIL by its exit status, and answers that status
run() {
  local name=$1
  shift
  echo
  echo "== $name"
  echo "   \$ $*"
  if "$@"; then pass "$name"; return 0; fi
  fail "$name"
  return 1
}

goos=$(go env GOOS)
goarch=$(go env GOARCH)
timeout=${MESSAGE_TEST_TIMEOUT:-3h}
fuzztime=${MESSAGE_TEST_FUZZTIME:-60s}
version=${WARP_VERSION:-0.0.0-test}
cc_ok=0
if [ "$(go env CGO_ENABLED)" = 1 ] && command -v "$(go env CC)" > /dev/null 2>&1; then cc_ok=1; fi
race=()
if [ "$cc_ok" = 1 ]; then
  race=(-race)
elif [ "$goos" = linux ]; then
  fail "the race detector" "linux with no C compiler or CGO_ENABLED=0: the full run needs gcc"
else
  skip "the race detector" "no C compiler on this $goos host"
fi
echo "$(go version); $goos/$goarch; C compiler: $([ "$cc_ok" = 1 ] && go env CC || echo none); race: ${race[*]:-off}"
# the census owes some steps on one kind of host only, and reads which host this was from here
receipt host goos "$goos"

# ---------------------------------------------------------------- 1. siblings and line endings
run "sibling pins: the script's own controls" bash scripts/siblings.sh --self-test
siblings=(connect connect-golden sdk message-server glog gvisor goidenticons)
for name in "${siblings[@]}"; do
  if [ ! -e "../$name" ]; then
    run "sibling $name: clone at its pin" bash scripts/siblings.sh "$name"
  fi
done
sibling_report=$(bash scripts/siblings.sh --verify "${siblings[@]}")
sibling_status=$?
echo "$sibling_report"
if [ "$sibling_status" = 0 ]; then pass "siblings at their pins"; else fail "siblings at their pins" "see above"; fi
# What the pinned run is narrower by, named in the verdict: a sibling accepted at some other commit,
# and a sibling whose pin is a pull request head fetched from a fork (scripts/siblings.sh's review
# sources), which is a commit the urnetwork repository does not hold until that pull request merges
while read -r state name rest; do
  if [ "$state" = UNPINNED ]; then narrowings+=("sibling $name is UNPINNED: $rest"); fi
  case "$state $rest" in
    "PINNED "*" FORK "*) narrowings+=("sibling $name is pinned to ${rest%% *}, a pull request head fetched from a fork (${rest##* FORK }): urnetwork's own repository holds it once that pull request merges") ;;
  esac
done <<< "$sibling_report"

# Line endings are read from git's own record of the working tree (`git ls-files --eol`), not by
# grepping for a carriage return: Git Bash's grep was measured answering both ways on one CRLF file.
# mls/GATES.md has no eol attribute, so a CRLF checkout writes it CRLF; the files the line-ending
# gates and the go command read byte for byte (.gitattributes: *.go, go.mod, go.sum, *.sh) must
# stay LF there.
if git ls-files --eol -- mls/GATES.md | grep -q 'w/crlf'; then
  echo "this checkout is CRLF (core.autocrlf=$(git config core.autocrlf))"
  crlf_kept=$(git ls-files --eol -- '*.go' 'go.mod' '*/go.mod' 'go.sum' '*/go.sum' '*.go.mod' '*.go.sum' '*.sh' |
    awk '$2 != "w/lf" {print $NF}' | head -5)
  if [ -z "$crlf_kept" ]; then
    pass "a CRLF checkout keeps every .go, go.mod, go.sum and .sh file LF (.gitattributes, which the gates rely on)"
  else
    fail "a CRLF checkout keeps every .go, go.mod, go.sum and .sh file LF" "not LF: $crlf_kept"
  fi
  crlf=1
else
  crlf=0
  if [ "$goos" = windows ]; then
    skip "the CRLF checkout" "this Windows checkout is LF; clone with core.autocrlf=true to run the line-ending gates against the checkout they are written for"
  fi
fi

# ---------------------------------------------------------------- 2. the census's controls and rows
run "module census: its own controls" bash scripts/module-census.sh --self-test
run "module census: the rows against the tree" bash scripts/module-census.sh --rows
# the toolchain check, on programs built for it: one under the pin is accepted; its copy with the
# recorded version rewritten, and the same program built under another toolchain, are refused
toolchain_controls() { bash scripts/toolchain.sh --self-test "$work/toolchain" 2>&1 | tee "$work/toolchain.log"; return "${PIPESTATUS[0]}"; }
run "toolchain: the check's own controls" toolchain_controls
if grep -q 'TOOLCHAIN CONTROL NOT RUN' "$work/toolchain.log" 2> /dev/null; then
  narrowings+=("the toolchain check's control of a build under ANOTHER toolchain did not run: this host's go command is $pinned_toolchain itself and no other release could be had; the rewritten copy is the control that ran")
fi

# ---------------------------------------------------------------- 3. gofmt
# A directory named testdata holds fixtures, some misformatted on purpose, and they are not held.
# One such directory holds source: the loopback harness, which urnetwork/sdk a7b5db77 moved under
# sdk/cgo/ctest/testdata so that go mod tidy would not read it, and which a build overlay compiles
# into the test library. It is held like any other source, and the step fails if nothing is there
# to hold. internal/layering holds the directory to what the overlay lays down, both ways.
overlaid_source_dir=sdk/cgo/ctest/testdata
gofmt_check() {
  local gofmt control unformatted held overlaid fixtures
  gofmt="$(go env GOROOT)/bin/gofmt"
  control="$work/gofmt-control"
  mkdir -p "$control"
  printf '%s\n' 'package p' 'func  f( ) {}' > "$control/c.go"
  if [ -z "$("$gofmt" -l "$control")" ]; then echo "gofmt -l does not list a misformatted file; the check below would pass anything"; return 1; fi
  git ls-files -z -- '*.go' | tr '\0' '\n' > "$work/gofmt-tracked"
  grep -v '/testdata/' "$work/gofmt-tracked" > "$work/gofmt-held"
  grep "^$overlaid_source_dir/" "$work/gofmt-tracked" > "$work/gofmt-overlaid"
  grep '/testdata/' "$work/gofmt-tracked" | grep -v "^$overlaid_source_dir/" > "$work/gofmt-fixtures"
  held=$(grep -c . "$work/gofmt-held")
  overlaid=$(grep -c . "$work/gofmt-overlaid")
  fixtures=$(grep -c . "$work/gofmt-fixtures")
  echo "gofmt holds $held tracked Go files outside testdata and $overlaid under $overlaid_source_dir, the source a build overlay compiles; not held: $fixtures fixture file(s) under other testdata directories"
  if [ "$held" = 0 ]; then echo "git ls-files named no Go file outside testdata; the scan is broken, not the tree"; return 1; fi
  if [ "$overlaid" = 0 ]; then echo "no tracked Go file under $overlaid_source_dir: the loopback harness is not where this step holds it"; return 1; fi
  unformatted=$(cat "$work/gofmt-held" "$work/gofmt-overlaid" | tr '\n' '\0' | xargs -0 "$gofmt" -l)
  if [ -n "$unformatted" ]; then echo "gofmt would rewrite:"; echo "$unformatted"; return 1; fi
}
# every checkout, a CRLF one too: .gitattributes keeps *.go LF, and step 1 asserted it there
run "gofmt over every tracked Go file that is source" gofmt_check

# ---------------------------------------------------------------- 4. the modules
# go_module <module file> <directory> [environment for go test...]
go_module() {
  local mod=$1 dir=$2 mains bin pkg tests xtests missing=0 version_of
  shift 2
  run "$dir: go mod verify" go -C "$dir" mod verify && receipt "$mod" verify
  run "$dir: go mod tidy -diff" go -C "$dir" mod tidy -diff && receipt "$mod" tidy
  mains=$(go -C "$dir" list -f '{{if eq .Name "main"}}{{.ImportPath}} {{len .TestGoFiles}} {{len .XTestGoFiles}}{{end}}' ./...)
  local list_status=$?
  if [ -n "$(printf '%s' "$mains" | tr -d '[:space:]')" ]; then
    bin="$work/bin/${dir//\//_}/"
    mkdir -p "$bin"
    # -o into a directory of its own: a pattern matching exactly one main package would otherwise
    # write that command's binary into the checkout
    if run "$dir: go build ./..." go -C "$dir" build -o "$bin" ./...; then
      receipt "$mod" build
      # what the build wrote, asked which toolchain built it: these are the binaries that are staged
      # on real hosts
      run "$dir: its binaries record $pinned_toolchain" bash scripts/toolchain.sh --artefact "$bin"* && receipt "$mod" toolchain
    fi
  else
    run "$dir: go build ./..." go -C "$dir" build ./... && receipt "$mod" build
  fi
  run "$dir: go vet ./..." go -C "$dir" vet ./... && receipt "$mod" vet
  # a main package is a binary that only a test starts; one without a test is never started here
  if [ "$list_status" = 0 ]; then
    while read -r pkg tests xtests; do
      [ -n "$pkg" ] || continue
      if [ "$tests" = 0 ] && [ "$xtests" = 0 ]; then echo "main package $pkg has no test, so its binary is never started"; missing=1; fi
    done <<< "$mains"
    if [ "$missing" = 0 ]; then
      pass "$dir: every main package has a test" "$(printf '%s\n' "$mains" | grep -c .)"
      receipt "$mod" mains "$(printf '%s\n' "$mains" | grep -c .)"
    else
      fail "$dir: every main package has a test"
    fi
  else
    fail "$dir: list the main packages"
  fi
  run "$dir: go test ${race[*]:-} ./..." env "$@" go -C "$dir" test -count=1 "${race[@]}" -timeout "$timeout" ./... &&
    receipt "$mod" test "${race[*]:-norace}"
  if version_of=$(go -C "$dir" list -m -f '{{.Version}}' google.golang.org/protobuf 2> /dev/null) && [ -n "$version_of" ]; then
    receipt "$mod" protobuf "$version_of"
  else
    fail "$dir: resolve google.golang.org/protobuf"
  fi
}

# the root module: the record gate requires the core SDK beside the repository, and the frame
# code-point names require connect's frame.proto (both are skipped with a log in a lone checkout)
go_module go.mod . URMESSAGE_REQUIRE_CORE_SDK_ROOT=1 URMESSAGE_REQUIRE_CONNECT_ROOT=1
# the messaging packages are linked into the SDK's js/wasm build and the native libraries for darwin
# and windows; mls/crossplatform_test.go builds nine platforms inside go test, and this is the
# explicit build, and the vet of the js test packages
platforms_ok=1
run "root module: darwin/arm64 build" env GOOS=darwin GOARCH=arm64 go build ./... || platforms_ok=0
run "root module: windows/amd64 build" env GOOS=windows GOARCH=amd64 go build ./... || platforms_ok=0
run "root module: js/wasm build and vet" bash -c 'GOOS=js GOARCH=wasm go build ./... && GOOS=js GOARCH=wasm go vet ./...' || platforms_ok=0
if [ "$platforms_ok" = 1 ]; then receipt go.mod platforms "darwin/arm64 windows/amd64 js/wasm"; fi

# the codec's fuzz targets, each for MESSAGE_TEST_FUZZTIME, derived from the source so a new target
# is fuzzed without anyone listing it here.
#
# One failure shape is the fuzzing engine's and not a finding: the leg reaches its time, reports
# "context deadline exceeded", and records no failing input (measured once, FuzzVarint after 6.7
# million executions, on a shared 6-core linux host while other suites ran). That leg runs once
# more, and the verdict names it. Any other failure, a failing input above all ("Failing input
# written to testdata/fuzz/..."), fails.
fuzz_leg() {
  local target=$1 out status workers=()
  if [ -n "${MESSAGE_TEST_FUZZ_WORKERS:-}" ]; then workers=(-parallel="$MESSAGE_TEST_FUZZ_WORKERS"); fi
  out=$(go test ./syntax -run=NONE -fuzz="^$target\$" -fuzztime="$fuzztime" "${workers[@]}" 2>&1)
  status=$?
  printf '%s\n' "$out" | tail -4
  if [ "$status" != 0 ] && printf '%s\n' "$out" | grep -q 'context deadline exceeded' &&
    ! printf '%s\n' "$out" | grep -q 'Failing input written to'; then
    echo "the leg ended with 'context deadline exceeded' and recorded no failing input; running it once more"
    out=$(go test ./syntax -run=NONE -fuzz="^$target\$" -fuzztime="$fuzztime" "${workers[@]}" 2>&1)
    status=$?
    printf '%s\n' "$out" | tail -4
    if [ "$status" = 0 ]; then narrowings+=("syntax: $target ended once with 'context deadline exceeded' and no failing input, and passed its one re-run"); fi
  fi
  return "$status"
}
fuzz_targets=$(grep -ho '^func Fuzz[A-Za-z0-9_]*' syntax/*_test.go | sed 's/^func //' | sort -u)
if [ -z "$fuzz_targets" ]; then
  fail "syntax: fuzz targets" "found none in syntax/*_test.go; the scan is broken, not the package"
else
  fuzz_ok=1
  for target in $fuzz_targets; do
    run "syntax: $target for $fuzztime" fuzz_leg "$target" || fuzz_ok=0
  done
  if [ "$fuzz_ok" = 1 ]; then receipt go.mod fuzz "$(printf '%s ' $fuzz_targets)for $fuzztime each"; fi
  if [ "$fuzztime" != 60s ]; then narrowings+=("fuzz targets ran $fuzztime each, not 60s"); fi
fi

# the wire corpus against connect from before the removal: the corpus's pinned base lines are what
# connect's copy emits, byte for byte, and each emission decodes into the other build's types. The
# count and digest are read from the test that pins them, so there is one place to change them.
wiregolden() {
  local mod=protocol/testdata/wiregolden/go.mod dir=protocol/testdata/wiregolden lines sha
  lines=$(sed -n 's/^[[:space:]]*wireGoldenBaseLines[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)$/\1/p' protocol/message_wiregolden_test.go)
  sha=$(sed -n 's/^[[:space:]]*wireGoldenBaseSha256[[:space:]]*=[[:space:]]*"\([0-9a-f]\{64\}\)"$/\1/p' protocol/message_wiregolden_test.go)
  if [ -z "$lines" ] || [ -z "$sha" ]; then fail "wire corpus: read the pinned base" "protocol/message_wiregolden_test.go"; return; fi
  run "$dir: go mod verify" go -C "$dir" mod verify && receipt "$mod" verify
  run "$dir: the emitter's tests under connect-golden's schema" go -C "$dir" test -count=1 -tags orig . && receipt "$mod" test:orig
  run "$dir: the emitter's tests under this repository's schema" go -C "$dir" test -count=1 -tags new . && receipt "$mod" test:new
  if ! (cd "$dir" && go run -tags orig . emit > "$work/orig.tsv" && go run -tags new . emit > "$work/new.tsv"); then
    fail "wire corpus: emit under both schemas"
    return
  fi
  head -n "$lines" protocol/testdata/wire-golden.tsv > "$work/base.tsv"
  run "wire corpus: the base's $lines lines hash to the pinned $sha" \
    bash -c "printf '%s  %s\n' '$sha' '$work/base.tsv' | sha256sum -c -" && receipt "$mod" base-pinned "$lines"
  cp "$work/orig.tsv" "$work/orig.control"
  printf 'x' >> "$work/orig.control"
  if cmp -s "$work/base.tsv" "$work/orig.control"; then
    fail "wire corpus: cmp's control" "cmp cannot see a changed byte"
  elif run "wire corpus: connect-golden emits the base byte for byte" cmp "$work/base.tsv" "$work/orig.tsv"; then
    receipt "$mod" cmp-connect-golden
  fi
  run "wire corpus: connect's emission decodes into this repository's types identically" \
    bash -c "cd '$dir' && go run -tags new . check '$work/orig.tsv'" && receipt "$mod" cross-decode:new
  run "wire corpus: the base decodes into connect-golden's types identically" \
    bash -c "cd '$dir' && go run -tags orig . check '$work/base.tsv'" && receipt "$mod" cross-decode:orig
}
wiregolden

# protocol/message.pb.go is generated once from message.proto by the pinned pair; regenerated here
# into a scratch directory and compared, so the committed Go can be neither hand-edited nor stale
regenerate() {
  local protoc="" gen="" cache zip="" digest="" binary=protoc py
  cache="${XDG_CACHE_HOME:-$HOME/.cache}/urnetwork-message"
  for candidate in "${PROTOC:-}" "$(command -v protoc 2> /dev/null)"; do
    if [ -n "$candidate" ] && "$candidate" --version 2> /dev/null | tr -d '\r' | grep -qx 'libprotoc 35.1'; then protoc=$candidate; break; fi
  done
  # no protoc 35.1 on the host: the release's own archive for it, fetched once and held to its
  # digest, on the two hosts the full run is made of
  if [ -z "$protoc" ]; then
    case "$goos/$goarch" in
      linux/amd64) zip=protoc-35.1-linux-x86_64.zip; digest=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7 ;;
      windows/amd64) zip=protoc-35.1-win64.zip; digest=5d3ff218d7d91eea95f7569bcb5a98f3030f8996d44151279d9772edcff76082; binary=protoc.exe ;;
    esac
  fi
  if [ -n "$zip" ]; then
    # unzip where there is one, python's zipfile where there is not (a stock Ubuntu server has none)
    unpack() {
      if command -v unzip > /dev/null 2>&1; then unzip -oq "$1" -d "$2"; return; fi
      for py in python3 python; do
        if command -v "$py" > /dev/null 2>&1; then "$py" -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"; return; fi
      done
      echo "neither unzip nor python is on PATH to unpack $1"
      return 1
    }
    mkdir -p "$cache/protoc-35.1"
    if [ ! -x "$cache/protoc-35.1/bin/$binary" ]; then
      curl -fsSLo "$cache/$zip" "https://github.com/protocolbuffers/protobuf/releases/download/v35.1/$zip" &&
        echo "$digest  $cache/$zip" | sha256sum -c - &&
        unpack "$cache/$zip" "$cache/protoc-35.1" &&
        chmod +x "$cache/protoc-35.1/bin/$binary"
    fi
    if "$cache/protoc-35.1/bin/$binary" --version 2> /dev/null | tr -d '\r' | grep -qx 'libprotoc 35.1'; then protoc="$cache/protoc-35.1/bin/$binary"; fi
  fi
  if [ -z "$protoc" ]; then
    skip "protocol: regenerate message.pb.go" "no protoc 35.1 on this host (set PROTOC; linux and Windows on x86-64 fetch it)"
    return
  fi
  for candidate in "$(dirname "$protoc")/protoc-gen-go" "$(dirname "$protoc")/protoc-gen-go.exe" "$(command -v protoc-gen-go 2> /dev/null)" "$cache/gobin/protoc-gen-go" "$cache/gobin/protoc-gen-go.exe"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ] && "$candidate" --version 2> /dev/null | tr -d '\r' | grep -qxE 'protoc-gen-go(\.exe)? v1\.36\.11'; then gen=$candidate; break; fi
  done
  if [ -z "$gen" ]; then
    GOBIN="$cache/gobin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11 || { fail "protocol: install protoc-gen-go v1.36.11"; return; }
    gen="$cache/gobin/protoc-gen-go"
    [ -x "$gen" ] || gen="$gen.exe"
  fi
  mkdir -p "$work/protoc"
  # the plugin by path rather than through PATH: under Git Bash a Windows path's drive colon would
  # split a PATH entry in two
  local plugin=$gen out_dir="$work/protoc"
  if command -v cygpath > /dev/null 2>&1; then plugin=$(cygpath -m "$gen"); out_dir=$(cygpath -m "$work/protoc"); fi
  if ! (cd protocol && "$protoc" -I=. --plugin=protoc-gen-go="$plugin" --go_out="$out_dir" --go_opt=paths=source_relative message.proto); then
    fail "protocol: regenerate message.pb.go"
    return
  fi
  cp "$work/protoc/message.pb.go" "$work/protoc/control.pb.go"
  printf '// control\n' >> "$work/protoc/control.pb.go"
  if cmp -s "$work/protoc/control.pb.go" protocol/message.pb.go; then fail "protocol: the regeneration's control" "cmp cannot see a changed line"; return; fi
  run "protocol: message.pb.go is exactly what $("$protoc" --version) and $("$gen" --version) generate" \
    cmp "$work/protoc/message.pb.go" protocol/message.pb.go
}
regenerate

# the SDK module, its platforms, and the modules beneath it
go_module sdk/go.mod sdk
# the SDK is linked into the native libraries for darwin and windows, and its stream store carries an
# exclusion file per platform family; each must build
platforms_ok=1
run "sdk: darwin/arm64 build" env GOOS=darwin GOARCH=arm64 go -C sdk build ./... || platforms_ok=0
run "sdk: windows/amd64 build and vet" bash -c 'GOOS=windows GOARCH=amd64 go -C sdk build ./... && GOOS=windows GOARCH=amd64 go -C sdk vet ./...' || platforms_ok=0
if [ "$platforms_ok" = 1 ]; then receipt sdk/go.mod platforms "darwin/arm64 windows/amd64"; fi
go_module sdk/livepeer/go.mod sdk/livepeer
go_module sdk/liveprobe/go.mod sdk/liveprobe
go_module sdk/cp3b/go.mod sdk/cp3b

# the native library: the core SDK's cgo package main with sdk/cgo laid beside it
native() {
  local mod=sdk/cgo/go.mod dir=sdk/cgo library header exports_out
  if ! run "sdk/cgo: compose the core SDK's cgo package main" bash sdk/cgo/compose.sh; then return; fi
  composed=1
  receipt "$mod" compose "$(grep -vc '^#' sdk/cgo/.composed) core files"
  run "sdk/cgo: go mod verify" go -C "$dir" mod verify && receipt "$mod" verify
  # go.mod is tidy over the composed tree, which the loopback harness is not in: it sits under
  # ctest/testdata, where go mod tidy does not read it (urnetwork/sdk a7b5db77). loopback.go.mod,
  # which adds the message server the harness runs, is tidy over the tree WITH the harness laid in
  # by its overlay. The control is the same command without the overlay: it must want to drop the
  # message server, or the overlay is not what brings the harness's imports into the answer
  run "sdk/cgo: go mod tidy -diff, the composed tree" go -C "$dir" mod tidy -diff && receipt "$mod" tidy
  if go -C "$dir" mod tidy -modfile=loopback.go.mod -diff > "$work/loopback-tidy-control" 2>&1 ||
    ! grep -q '^-.*github.com/urnetwork/message-server' "$work/loopback-tidy-control"; then
    fail "sdk/cgo: the loopback tidy's control" "without -overlay, go mod tidy -modfile=loopback.go.mod does not ask to drop the message server, so the step below proves nothing about the harness"
  else
    run "sdk/cgo: go mod tidy -diff -modfile=loopback.go.mod, the harness laid in by its overlay" \
      go -C "$dir" mod tidy -modfile=loopback.go.mod -overlay=ctest/loopback-overlay.json -diff &&
      receipt sdk/cgo/loopback.go.mod tidy
  fi
  # gen rewrites the tracked .def with LF line endings. When its content is the committed one, it is
  # checked out again, so a CRLF checkout is not left with a file git status calls modified; when it
  # is not, the regenerated file stays for the developer to read and commit
  run "sdk/cgo: the .def gen writes is the committed one" \
    bash -c 'cd sdk/cgo && go run ./gen && git diff --exit-code -- include/urnetwork_sdk.def && git checkout -- include/urnetwork_sdk.def' &&
    receipt "$mod" def-current
  if [ "$cc_ok" = 1 ]; then
    case "$goos" in
      windows) library=build/library/URnetworkSdk.dll ;;
      darwin) library=build/library/libURnetworkSdk.dylib ;;
      *) library=build/library/libURnetworkSdk.so ;;
    esac
    header="${library%.*}.h"
    # through sdk/cgo/build.sh, the one place the recipe is written (c-shared, the core SDK's release
    # flags, the pinned toolchain), so the build a consumer runs is the build that is tested here
    if run "sdk/cgo: build URnetworkSdk with sdk/cgo/build.sh (Version=$version)" \
      env WARP_VERSION="$version" bash sdk/cgo/build.sh "$dir/$library"; then
      receipt "$mod" library "$dir/$library $(wc -c < "$dir/$library" | tr -d ' ')"
      run "sdk/cgo: the library records $pinned_toolchain" bash scripts/toolchain.sh --artefact "$dir/$library" && receipt "$mod" toolchain
      exports_out=$(bash scripts/native-exports.sh "$dir" "$dir/$header" "$dir/$library")
      local exports_status=$?
      echo "$exports_out"
      if [ "$exports_status" = 0 ]; then
        pass "sdk/cgo: the library's exports are the .def's names, both ways"
        receipt "$mod" exports "$(printf '%s\n' "$exports_out" | sed -n 's/^header: \([0-9]*\) exports.*/\1/p')"
      else
        fail "sdk/cgo: the library's exports are the .def's names, both ways"
      fi
    fi
  else
    skip "sdk/cgo: the c-shared library and its exports" "no C compiler on this host"
  fi
  run "sdk/cgo: go vet ./..." go -C "$dir" vet ./... && receipt "$mod" vet
  run "sdk/cgo: go test ${race[*]:-} ./..." go -C "$dir" test -count=1 "${race[@]}" -timeout "$timeout" ./... && receipt "$mod" test "${race[*]:-norace}"
  receipt "$mod" protobuf "$(go -C "$dir" list -m -f '{{.Version}}' google.golang.org/protobuf)"
  if [ "$cc_ok" = 1 ]; then
    # on every host: the loopback library builds with its overlay, modfile and tag and exports the
    # harness, and the shipping library's header, built above, declares none of it
    loopback_library() {
      local out="build/loopback/${library##*/}" exported shipped
      rm -rf "$dir/build/loopback"
      mkdir -p "$dir/build/loopback"
      CGO_ENABLED=1 go -C "$dir" build -overlay=ctest/loopback-overlay.json -modfile=loopback.go.mod -tags urnet_message_loopback -buildmode=c-shared -o "$out" . || return 1
      bash scripts/toolchain.sh --artefact "$dir/$out" || return 1
      if [ ! -f "$dir/$header" ]; then echo "the shipping library's header $dir/$header is not there"; return 1; fi
      exported=$(grep -cE '^extern .*\burnet_message_loopback_' "$dir/${out%.*}.h" || true)
      shipped=$(grep -cE 'urnet_message_loopback' "$dir/$header" || true)
      echo "the loopback library exports $exported harness function(s); the shipping library's header names $shipped"
      [ "$exported" -gt 0 ] && [ "$shipped" = 0 ]
    }
    run "sdk/cgo: the loopback library builds and exports the harness, and the shipping library has none of it" loopback_library &&
      receipt sdk/cgo/loopback.go.mod loopback-library
    # the C consumer, sdk/cgo/ctest/message_abi_test.c, is a Windows program (windows.h, CreateThread),
    # as it was in the core SDK; ctest/run.sh builds it against the loopback library and runs it
    if [ "$goos" = windows ]; then
      # run.sh then runs the consumer again against a -race build of the library. When
      # ThreadSanitizer cannot map its shadow memory into the loaded dll, it prints RACE PASS DID NOT
      # RUN ON THIS HOST and does not fail, so the verdict names that pass as not run
      c_consumer() { bash sdk/cgo/ctest/run.sh 2>&1 | tee "$work/ctest.log"; return "${PIPESTATUS[0]}"; }
      run "sdk/cgo: the loopback library's C consumer (ctest/run.sh)" c_consumer && receipt sdk/cgo/loopback.go.mod ctest
      if grep -q 'RACE PASS DID NOT RUN ON THIS HOST' "$work/ctest.log" 2>/dev/null; then
        narrowings+=("the C consumer's second pass, against a -race build of the loopback library, did not run: ThreadSanitizer could not map its shadow memory into the dll (ctest/run.sh); go test -race over sdk/cgo held the handle registry instead")
      fi
    else
      narrowings+=("the loopback library's C consumer (sdk/cgo/ctest/message_abi_test.c) is a Windows program, windows.h and CreateThread: a Windows run builds and runs it")
    fi
  else
    skip "sdk/cgo: the loopback library and its C consumer" "no C compiler on this host"
  fi
}
native

# ---------------------------------------------------------------- 7. the census over what ran
run "module census: every row's receipts" bash scripts/module-census.sh --receipts "$receipts"

# ---------------------------------------------------------------- the verdict
echo
echo "================================================================ summary"
failed=0
for result in "${results[@]}"; do
  IFS='|' read -r status name detail <<< "$result"
  printf '%-8s %s%s\n' "$status" "$name" "${detail:+ ($detail)}"
  if [ "$status" = FAIL ]; then failed=$((failed + 1)); fi
done
if [ "${#narrowings[@]}" -gt 0 ]; then
  echo
  echo "NARROWER THAN THE FULL RUN:"
  printf '  %s\n' "${narrowings[@]}"
fi
echo
if [ "$failed" = 0 ]; then
  if [ "${#narrowings[@]}" -gt 0 ]; then echo "VERDICT: PASS, narrower than the full run (above)"; else echo "VERDICT: PASS"; fi
  exit 0
fi
echo "VERDICT: FAIL ($failed failed)"
exit 1
