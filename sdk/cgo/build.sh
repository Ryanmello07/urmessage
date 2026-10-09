#!/usr/bin/env bash
# build.sh: build the composed native library, URnetworkSdk, the way it ships.
#
#   WARP_VERSION=<version> bash sdk/cgo/build.sh <output file>
#
#   <output file>   build/library/URnetworkSdk.dll, libURnetworkSdk.so, libURnetworkSdk.dylib, ...;
#                   the go command writes the cgo header beside it, with the same name and .h
#   WARP_VERSION    the SDK version the library reports. Required: the core SDK declares
#                   `var Version string = ""` and its release sets it with -X, so a library built
#                   without it answers an empty version to every caller
#   GOOS, GOARCH, CC, CGO_* as for any cgo build: a cross build sets them
#
# THE TREE MUST BE COMPOSED FIRST (bash sdk/cgo/compose.sh): the library's package main is the core
# SDK's, laid beside this directory's messaging half, and this script refuses a tree it is not in.
#
# THE RECIPE IS THE CORE SDK'S RELEASE RECIPE (urnetwork/sdk cgo/Makefile, build_windows_amd64 and
# its siblings): c-shared, -trimpath, GOEXPERIMENT=greenteagc, stripped (-s -w), no build id, and
# the version by -X. It is written once, here; test.sh builds the library through this script, so
# the recipe a consumer runs is the one that is tested.
#
# THE TOOLCHAIN IS THE PINNED ONE, whatever go command the host has: scripts/toolchain.sh reads the
# pin from the root go.mod, this script forces it with GOTOOLCHAIN and fails, naming the fix, when
# it cannot be had, and the library it wrote is then asked which toolchain built it.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [ "$#" != 1 ] || [ -z "$1" ]; then
  echo "usage: WARP_VERSION=<version> bash sdk/cgo/build.sh <output file>" >&2
  exit 2
fi
if [ -z "${WARP_VERSION:-}" ]; then
  echo "build: WARP_VERSION is not set, and a library built without it reports an empty SDK version; set it to the version being built" >&2
  exit 1
fi
if [ ! -f "$here/.composed" ]; then
  echo "build: $here is not composed, so it holds the messaging half alone and no package main to build; run bash sdk/cgo/compose.sh first" >&2
  exit 1
fi
pinned=$(bash "$root/scripts/toolchain.sh")
bash "$root/scripts/toolchain.sh" --check
export GOTOOLCHAIN="$pinned" GOWORK=off

mkdir -p "$(dirname "$1")"
out="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
rm -f "$out" "${out%.*}.h"
echo "build: $out, Version=$WARP_VERSION, $(go env GOOS)/$(go env GOARCH), $pinned, from $(sed -n '1s/^# //p' "$here/.composed")"
CGO_ENABLED=1 GOEXPERIMENT=greenteagc go -C "$here" build -trimpath -buildmode=c-shared \
  -ldflags "-s -w -X github.com/urnetwork/sdk.Version=$WARP_VERSION -buildid=" -o "$out" .
bash "$root/scripts/toolchain.sh" --artefact "$out"
