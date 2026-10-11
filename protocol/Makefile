# Generates message.pb.go from message.proto. Adapted from connect/protocol/Makefile
# (connect e449f7d8); the generator pair is pinned because the committed Go is checked
# byte for byte by test.sh: protoc 35.1, protoc-gen-go v1.36.11. The plugin is built under
# the repository's pinned toolchain (scripts/toolchain.sh): it formats its output with the
# go/format it was compiled with, so the compiler that built it decides bytes of the file.
PROTOC_GEN_GO_VERSION = v1.36.11

default: build

build:
	protoc -I=. --go_out=. --go_opt=paths=source_relative *.proto

init:
	GOTOOLCHAIN=$$(bash ../scripts/toolchain.sh) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
