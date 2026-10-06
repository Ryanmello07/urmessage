#!/usr/bin/env bash
# Usage: bash .github/scripts/native-exports.sh <sdk/cgo directory> <cgo header of the built library> [<library>]
#
# The composed native library's exports, held both ways against its .def. Run after a
# `go build -buildmode=c-shared` of the composed sdk/cgo, with the header that build writes beside
# the library.
#
#   - The //export functions the cgo-generated header declares are EXACTLY the names
#     include/urnetwork_sdk.def lists, plus, on a unix build, the core's unix-only exports
#     (exports_gen_unix.go), which no .def names because Windows does not build them. A .def name
#     the library lacks is a link error at an MSVC consumer, and so is an export the .def omits.
#   - None of them is the loopback harness's (urnet_message_loopback_*), and none is one of the
#     three generated messaging exports the split retired.
#   - On linux, with nm, every declared export is a defined text symbol of the library itself; the
#     library's other urnet_ symbols are the C callback trampolines of callbacks.c and
#     callbacks_message.c, and they are listed by count.
set -euo pipefail
dir=$1
header=$2
library=${3:-}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tab=$(printf '\t')

grep -E '^extern .*\burnet_[A-Za-z0-9_]+\(' "$header" | grep -oE '\burnet_[A-Za-z0-9_]+\(' | tr -d '(' | sort -u > "$tmp/header"
grep "^$tab" "$dir/include/urnetwork_sdk.def" | tr -d "$tab\r" | sort -u > "$tmp/def"
: > "$tmp/unix"
goos=$(go env GOOS)
if [ "$goos" != windows ] && [ -f "$dir/exports_gen_unix.go" ]; then
  grep -E '^//export ' "$dir/exports_gen_unix.go" | awk '{print $2}' | tr -d '\r' | sort -u > "$tmp/unix"
fi
sort -u "$tmp/def" "$tmp/unix" > "$tmp/want"
printf 'header: %s exports; .def: %s; unix-only (%s): %s\n' "$(wc -l < "$tmp/header")" "$(wc -l < "$tmp/def")" "$goos" "$(wc -l < "$tmp/unix")"
test -s "$tmp/header" || { echo "FAIL: the header declares no urnet_ export, so nothing below is asked"; exit 1; }
test -s "$tmp/def" || { echo "FAIL: the .def names nothing"; exit 1; }

fail=0
if ! diff -u "$tmp/want" "$tmp/header"; then
  echo "FAIL: the library's exports (-) are not the .def's names plus the unix-only ones (+ is the header)"
  fail=1
else
  echo "the library exports exactly the .def's names, plus the unix-only ones on this platform"
fi
if grep -q '^urnet_message_loopback' "$tmp/header"; then
  echo "FAIL: the shipping library exports the loopback harness"
  fail=1
fi
for gone in urnet_new_message_transport urnet_open_stream_store urnet_parse_message_route_mode; do
  if grep -qx "$gone" "$tmp/header" || grep -qx "$gone" "$tmp/def"; then
    echo "FAIL: $gone, a generated messaging export the split retired, is back"
    fail=1
  fi
done
printf 'messaging exports: %s\n' "$(grep -c '^urnet_message_' "$tmp/header" || true)"

if [ -n "$library" ] && [ "$goos" = linux ] && command -v nm > /dev/null; then
  nm -D --defined-only "$library" | awk '$2 == "T" && $3 ~ /^urnet_/ {print $3}' | sort -u > "$tmp/symbols"
  missing=$(comm -23 "$tmp/header" "$tmp/symbols")
  if [ -n "$missing" ]; then
    echo "FAIL: the header declares exports the library does not define:"
    echo "$missing" | head -20
    fail=1
  fi
  others=$(comm -13 "$tmp/header" "$tmp/symbols")
  trampolines=$(printf '%s\n' "$others" | grep -c '^urnet_invoke_' || true)
  strays=$(printf '%s\n' "$others" | grep -v '^urnet_invoke_' | grep -c . || true)
  printf 'library symbols: %s urnet_ text symbols; beyond the exports, %s C callback trampolines (urnet_invoke_*) and %s others\n' \
    "$(wc -l < "$tmp/symbols")" "$trampolines" "$strays"
  if [ "$strays" != 0 ]; then
    echo "FAIL: urnet_ symbols that are neither exports nor trampolines:"
    printf '%s\n' "$others" | grep -v '^urnet_invoke_' | head -20
    fail=1
  fi
fi
exit $fail
