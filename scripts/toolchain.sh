#!/usr/bin/env bash
# Usage: bash scripts/toolchain.sh                      print the pinned toolchain (go1.26.5 today)
#        bash scripts/toolchain.sh --check              the go command, forced to the pin, runs it
#        bash scripts/toolchain.sh --artefact <file>... each built file records the pin
#        bash scripts/toolchain.sh --self-test <dir>    this script's own controls, in a scratch dir
#
# THE TOOLCHAIN IS PINNED, AND THE PIN IS FORCED. This repository's cryptographic code was reviewed,
# and its vectors, known answers and guardrails were run, under one compiler: the `toolchain` line
# of the root go.mod, which mls/pins_test.go names too (TestPinnedToolchain reads the version that
# built the test binary). A go.mod toolchain line is a MINIMUM. A host whose go command is newer
# builds with the newer one and says nothing, and connect's own toolchain line moved to go1.27.1
# (urnetwork/connect 062b333e) while every module's `go` line stayed at 1.26. So nothing here
# relies on the line: every build this repository makes sets GOTOOLCHAIN to the pin explicitly
# (test.sh for the whole run, sdk/cgo/build.sh for the native library), and what a build wrote is
# asked which toolchain built it.
#
# The pin is read from go.mod, so there is one place to change it, and it is changed on purpose
# only: following a sibling to a newer toolchain is a reviewed change of its own (go.mod's line and
# mls/pins_test.go's literal together, with the vector, known-answer and guardrail suites run again
# under the new compiler), never a side effect of the go command a host happens to have.
#
# --check fails, naming the fix, when the pinned toolchain cannot be had: the go command downloads
# it when it may (GOPROXY reachable), and uses a go1.26.5 binary on PATH when there is one.
#
# --artefact asks each file with `go version`, which reads the build information the linker wrote
# into it, and fails on any other answer, a file that is not a Go build among them.
#
# --self-test is the controls, and each must go its own way for its own reason:
#   - --check accepts a go command that writes to stderr before it answers the pin (the first run on
#     a host that fetches it), and refuses one that answers another release, by that answer;
#   - a program built under the pin is accepted;
#   - a copy of it with the recorded version rewritten in place is refused, by that version;
#   - the same program built under ANOTHER toolchain is refused, by that toolchain's version. The
#     other toolchain is the host's own go command when it is not the pin, and otherwise the patch
#     release before the pin, which the go command downloads. A host that can get no other toolchain
#     prints "TOOLCHAIN CONTROL NOT RUN" with the reason and passes on the first two; test.sh
#     carries that line into its verdict.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)

pinned=$(tr -d '\r' < "$root/go.mod" | sed -n 's/^toolchain[[:space:]][[:space:]]*\(go[0-9][0-9A-Za-z.]*\)[[:space:]]*$/\1/p')
if [ "$(printf '%s\n' "$pinned" | grep -c .)" != 1 ]; then
  echo "toolchain: $root/go.mod must hold exactly one 'toolchain goX.Y.Z' line, and this is what was read: '$pinned'" >&2
  exit 1
fi

# The go command, forced to the pin, must be the pin.
#
# ITS ANSWER IS WHAT IT WRITES TO STDOUT, AND NOTHING ELSE. The first time a host's go command has to
# fetch the pin it says so on stderr ("go: downloading go1.26.5 (linux/amd64)") and then answers.
# This check read both streams as the answer until a runner whose go was 1.27.1 showed it: two lines
# are not the pin, so a host that HAD just fetched the pin was refused, with the fetch's own line
# quoted as the reason. stderr is kept for the failure message, where it is the diagnosis.
check() {
  local running status=0 said
  said=$(mktemp)
  running=$(GOTOOLCHAIN="$pinned" go env GOVERSION 2> "$said" | tr -d '\r') || status=$?
  if [ "$status" = 0 ] && [ "$running" = "$pinned" ]; then
    rm -f "$said"
    return 0
  fi
  cat >&2 <<EOF
toolchain: this repository builds and tests under $pinned and under nothing else (go.mod's toolchain
line, which mls/pins_test.go holds every test binary to), and the go command on this host could not
run it. GOTOOLCHAIN=$pinned go env GOVERSION answered '$running' (exit status $status), and said:

$(sed 's/^/    /' "$said")

A go.mod toolchain line never lowers the toolchain, so the pin is forced with GOTOOLCHAIN, and the go
command then needs that exact release. Either of these fixes it:
  - let the go command download it: network access to proxy.golang.org, or GOPROXY naming a proxy
    that serves golang.org/toolchain, and GOFLAGS free of -mod=vendor;
  - or install $pinned from https://go.dev/dl/ and put its bin directory first on PATH (a binary
    named $pinned on PATH also serves).
EOF
  rm -f "$said"
  return 1
}

# The toolchain a built file records: what `go version <file>` writes to stdout, after the last
# ": ". Empty when the go command reads no build information from the file.
recorded() {
  local answer
  answer=$(GOTOOLCHAIN="$pinned" go version "$1" 2> /dev/null | head -n 1 | tr -d '\r') || true
  printf '%s\n' "${answer##*: }"
}

artefacts() {
  local file version failed=0
  if [ "$#" = 0 ]; then
    echo "toolchain: --artefact was given no file, so nothing was asked" >&2
    return 1
  fi
  for file in "$@"; do
    if [ ! -f "$file" ]; then
      echo "FAIL: $file is not a file, so it records nothing"
      failed=1
      continue
    fi
    version=$(recorded "$file")
    if [ "$version" = "$pinned" ]; then
      echo "$file: built with $version, the pinned toolchain"
    elif [ -z "$version" ]; then
      echo "FAIL: $file is not a Go build: go version reads no toolchain from it"
      failed=1
    else
      echo "FAIL: $file records '$version', and this repository's builds are $pinned: rebuild it with GOTOOLCHAIN=$pinned (bash scripts/toolchain.sh --check says whether this host can)"
      failed=1
    fi
  done
  return "$failed"
}

self_test() {
  local dir=$1 exe other failed=0 out
  exe=$(GOTOOLCHAIN="$pinned" go env GOEXE)
  mkdir -p "$dir/program" "$dir/rewrite"
  # a module of its own, so no go.mod above it and no sibling decides anything about the build
  printf 'module example.invalid/toolchaincontrol\n\ngo 1.21\n' > "$dir/program/go.mod"
  printf 'package main\n\nfunc main() {}\n' > "$dir/program/main.go"
  printf 'module example.invalid/toolchainrewrite\n\ngo 1.21\n' > "$dir/rewrite/go.mod"
  cat > "$dir/rewrite/main.go" <<'EOF'
// rewrite copies a file with every occurrence of one byte string replaced by another of the same
// length, and fails when there was none: the control's way to plant a recorded toolchain.
package main

import (
	"bytes"
	"fmt"
	"os"
)

func main() {
	from, to := []byte(os.Args[3]), []byte(os.Args[4])
	if len(from) != len(to) || len(from) == 0 {
		fmt.Println("the two strings must be the same, nonzero, length")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	count := bytes.Count(data, from)
	if count == 0 {
		fmt.Printf("%s holds no %q\n", os.Args[1], from)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], bytes.ReplaceAll(data, from, to), 0o755); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%d occurrence(s) of %q rewritten to %q\n", count, from, to)
}
EOF
  # expect <accepted|refused> <title> <needle a refusal must print, or -> <file>
  expect() {
    local want=$1 title=$2 needle=$3 file=$4 got
    if out=$(artefacts "$file" 2>&1); then got=accepted; else got=refused; fi
    if [ "$got" = "$want" ] && { [ "$needle" = - ] || printf '%s\n' "$out" | grep -qF -- "$needle"; }; then
      echo "  control: $title -> $got, as it must: $out"
    else
      echo "  CONTROL BROKEN: $title -> $got, want $want with: $needle"
      printf '%s\n' "$out" | sed 's/^/    /'
      failed=1
    fi
  }
  # a release that is not the pin, to plant: the pin with its last digit changed
  local planted="${pinned%?}"
  case "$pinned" in *9) planted="${planted}8" ;; *) planted="${planted}9" ;; esac

  # --check itself, against a go command planted first on PATH. One that writes to stderr before it
  # answers the pin is accepted: that is the first run on a host that has to fetch the pin, which
  # this check refused until stderr stopped being read as the answer. One that answers another
  # release is refused, by that answer.
  local real_go
  real_go=$(command -v go)
  mkdir -p "$dir/chatty" "$dir/wrong"
  printf '%s\n' '#!/usr/bin/env bash' "echo 'go: downloading $pinned (a line on stderr, planted by the control)' >&2" "exec '$real_go' \"\$@\"" > "$dir/chatty/go"
  printf '%s\n' '#!/usr/bin/env bash' "if [ \"\${1:-} \${2:-}\" = 'env GOVERSION' ]; then echo $planted; exit 0; fi" "exec '$real_go' \"\$@\"" > "$dir/wrong/go"
  chmod +x "$dir/chatty/go" "$dir/wrong/go"
  if out=$(PATH="$dir/chatty:$PATH" bash "$0" --check 2>&1); then
    echo "  control: a go command that writes to stderr before it answers $pinned -> accepted, as it must"
  else
    echo "  CONTROL BROKEN: a go command that writes to stderr before it answers $pinned was refused"
    printf '%s\n' "$out" | sed 's/^/    /'
    failed=1
  fi
  if out=$(PATH="$dir/wrong:$PATH" bash "$0" --check 2>&1); then
    echo "  CONTROL BROKEN: a go command that answers $planted was accepted"
    failed=1
  elif printf '%s\n' "$out" | grep -qF "answered '$planted'"; then
    echo "  control: a go command that answers $planted -> refused, as it must: $(printf '%s\n' "$out" | grep -F "answered '$planted'" | head -n 1)"
  else
    echo "  CONTROL BROKEN: a go command that answers $planted was refused without that answer being named"
    printf '%s\n' "$out" | sed 's/^/    /'
    failed=1
  fi

  if ! (cd "$dir/program" && GOWORK=off GOFLAGS= GOTOOLCHAIN="$pinned" go build -o "$dir/pinned$exe" .); then
    echo "  CONTROL BROKEN: the control program does not build under $pinned"
    return 1
  fi
  expect accepted "a program built under $pinned" - "$dir/pinned$exe"

  # the same bytes with another version written where the linker recorded this one
  if ! (cd "$dir/rewrite" && GOWORK=off GOFLAGS= GOTOOLCHAIN="$pinned" go run . "$dir/pinned$exe" "$dir/planted$exe" "$pinned" "$planted"); then
    echo "  CONTROL BROKEN: the recorded toolchain could not be rewritten in a copy of the control program"
    return 1
  fi
  expect refused "its copy with the recorded toolchain rewritten to $planted" "records '$planted'" "$dir/planted$exe"
  expect refused "a file that is no Go build at all" "is not a Go build" "$dir/program/main.go"

  # another toolchain for real: this host's own go command when it is not the pin, and otherwise the
  # patch release before the pin
  other=local
  if [ "$(GOTOOLCHAIN=local go env GOVERSION 2> /dev/null)" = "$pinned" ]; then
    local patch=${pinned##*.}
    case "$patch" in
      '' | *[!0-9]* | 0) other="" ;;
      *) other="${pinned%.*}.$((patch - 1))" ;;
    esac
  fi
  local other_version=""
  if [ -n "$other" ]; then other_version=$(GOTOOLCHAIN="$other" go env GOVERSION 2> /dev/null) || other_version=""; fi
  if [ -z "$other_version" ] || [ "$other_version" = "$pinned" ]; then
    echo "  TOOLCHAIN CONTROL NOT RUN: a build under another toolchain. This host's go command is $pinned itself, and no other release could be had (GOTOOLCHAIN=${other:-none} go env GOVERSION answered '${other_version}'); the rewritten copy above is the control that ran"
  elif ! (cd "$dir/program" && GOWORK=off GOFLAGS= GOTOOLCHAIN="$other" go build -o "$dir/other$exe" .); then
    echo "  CONTROL BROKEN: the control program does not build under $other_version (GOTOOLCHAIN=$other)"
    failed=1
  else
    expect refused "the same program built under another toolchain, $other_version (GOTOOLCHAIN=$other)" "records '$other_version'" "$dir/other$exe"
  fi
  return "$failed"
}

case "${1:-}" in
  "")
    printf '%s\n' "$pinned"
    ;;
  --check)
    check
    echo "toolchain: $pinned, forced with GOTOOLCHAIN ($(GOTOOLCHAIN="$pinned" go env GOROOT))"
    ;;
  --artefact)
    shift
    check
    artefacts "$@"
    ;;
  --self-test)
    dir=${2:?--self-test needs a scratch directory}
    check
    echo "the toolchain check's own controls:"
    if self_test "$dir"; then echo "TOOLCHAIN SELF-TEST PASS"; else echo "TOOLCHAIN SELF-TEST FAIL"; exit 1; fi
    ;;
  *)
    echo "usage: bash scripts/toolchain.sh [--check | --artefact <file>... | --self-test <dir>]" >&2
    exit 2
    ;;
esac
