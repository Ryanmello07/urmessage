# message

`github.com/urnetwork/message` is URmessage, the URnetwork messaging application:
message records, group sessions, MLS, the shared serialization codec, the messaging
wire schema and the messaging SDK. It runs on top of
[connect](https://github.com/urnetwork/connect); the native library composes its C ABI with
the [core SDK](https://github.com/urnetwork/sdk)'s. Neither connect nor the core SDK depends
on it.

The code moves here from connect and the core SDK with its history, in the stages
of the maintainers' design,
[MESSAGEREVIEW.md at connect e8611390](https://github.com/urnetwork/connect/blob/e8611390466dcded7ccc4fd2d08bc14c297d9f41/MESSAGEREVIEW.md)
(first written at 13ced4c8; e8611390 took CI out of the layout, because the maintainers
build and test on their own hardware).

## Layout and status

Status: stages 1, 2a, 2b and 3 are imported, with their history. This import merges before
the connect and core SDK pull requests that remove the moved code from those repositories, so
the code is in its new home before anything is deleted. Until connect's removal has merged,
build this repository only beside the connect commit [scripts/siblings.txt](scripts/siblings.txt)
pins, never beside connect `main`: `main` still registers `message.proto`, and a binary that
links both copies stops at init. See [docs/HISTORY.md](docs/HISTORY.md).

| Path | Contents | Comes from | Stage |
|---|---|---|---|
| `go.mod`, `docs/`, `test.sh`, `scripts/` | module metadata, documentation, and the test run with its scripts | new | 1 |
| `CODESTYLE.md` | the Go style guide | connect, with its history | 1 |
| `message/` | records, attachments, authentication preimages | `connect/message` | 2a |
| `messagegroup/` | group sessions, ratchets, record encryption, the MLS adapter | `connect/messagegroup` | 2a |
| `mls/` | the MLS implementation | `connect/mls`, without `syntax` | 2a |
| `syntax/` | the shared serialization codec | `connect/mls/syntax`, promoted to a peer | 2a |
| `protocol/` | the messaging protobuf schema | `connect/protocol/message*` | 2b |
| `sdk/` | messaging transports, routes, durable stream store, tunnel; its own module, `github.com/urnetwork/message/sdk` | the core SDK's `message*.go` | 3 |
| `sdk/urmessage/` | device and group orchestration, durable MLS state | the core SDK's `urmessage/` | 3 |
| `sdk/cgo/` | the messaging C ABI, and the native composition that lays it into the core SDK's library; its own module | the core SDK's messaging `cgo/` files | 3 |
| `sdk/livepeer/`, `sdk/liveprobe/` | the live probes, each its own module | the core SDK's `livepeer/`, `liveprobe/` | 3 |
| `sdk/cp3b/` | the cross-process acceptance suite, against a real message server; its own module | the core SDK's `cp3b/` | 3 |

Stage 4 moves messaging onto a connect subprotocol.

The root holds module metadata, documentation and `test.sh` only: no Go package, and no
facade over the directories beneath it.

## Boundary

- The five foundational packages (`message`, `messagegroup`, `mls`, `syntax`,
  `protocol`) never import connect or the core SDK, and the root `go.mod` requires
  neither.
- Neither connect nor the core SDK may depend on this module, directly or
  transitively, including native bindings and release builds.
- `message`, `syntax` and `protocol` are server-safe. Neither `message` nor
  `protocol` imports `mls` or `messagegroup`, and `syntax` uses the standard library
  only. Consumers allow these packages by exact path, never the whole
  `github.com/urnetwork/message` tree.
- A package never imports its own descendants (see [CODESTYLE.md](CODESTYLE.md)).
- `message/sdk` imports connect and this repository's packages, and never the core SDK.
  The native composition (`sdk/cgo`) is the one module that links both SDKs.

[docs/BOUNDARY.md](docs/BOUNDARY.md) maps each rule to the check that holds it.

## Build and test

There is no CI service: like connect and the core SDK, this repository is built and
tested on the maintainers' own hardware, and [test.sh](test.sh) is the whole run.

    git clone -c core.autocrlf=false https://github.com/urnetwork/message.git message
    cd message
    ./test.sh

- `go build ./... && go vet ./... && go test ./...` builds and tests the root module
  with nothing beside it. It logs, and does not fail, where a check needs a sibling
  that is not there (the core SDK under the record gate, connect's `frame.proto`).
- `./test.sh` runs everything else too, and requires the siblings at the commits
  [scripts/siblings.txt](scripts/siblings.txt) pins, cloning a missing one beside the
  checkout: connect, the core SDK, message-server, connect from before the removal, glog,
  gvisor and goidenticons. Three of those pins are commits of the pull requests this
  repository arrives with (the removals from connect and the core SDK, and
  message-server's switch to these packages): each is the commit the set was last built
  and tested at, which a branch that has taken its `main` again since is ahead of. Until
  each has merged, its commit is fetched from the fork it was pushed to, and the verdict
  names it; siblings.txt says which urnetwork URL replaces the fork afterwards.
- It runs every module (the SDK, the commands, the acceptance suite against
  message-server, the native library and its C consumer) with the race detector, the
  wire corpus against the pinned connect, the schema's regeneration, the codec's fuzz
  targets, and the module census over what ran. The full run is two runs, a linux host
  with gcc and a Windows clone made with `core.autocrlf=true` (below), and each prints
  what it did not run.
- Name the directory `message`. The modules find their siblings by relative path
  (`../connect`, `../sdk`, ...), and consumers' local `replace` directives point at
  `../message`.
- Develop with `core.autocrlf=false`: several checks read source files byte for byte.
  The line-ending gates are also written for a CRLF checkout, since the Windows machines
  this project is built on run `core.autocrlf=true`, so run `./test.sh` on Windows from a
  clone made with `-c core.autocrlf=true` as well.
- The native library is the core SDK's cgo package main with `sdk/cgo` laid beside it.
  With a C compiler on the host:

      bash sdk/cgo/compose.sh
      WARP_VERSION=<version> bash sdk/cgo/build.sh <output>/URnetworkSdk.dll
      bash sdk/cgo/compose.sh --clean

  [sdk/cgo/build.sh](sdk/cgo/build.sh) is the one place the recipe is written: the core
  SDK's release recipe (its `cgo/Makefile`: c-shared, `-trimpath`, `greenteagc`, stripped,
  no build id, the version by `-X`), under the pinned toolchain, with the library then
  asked which toolchain built it. It refuses to build without `WARP_VERSION`, because a
  library built without the `-X` reports an empty SDK version. `test.sh` builds the
  library through the same script, so the recipe a consumer runs is the one that is
  tested. `compose.sh --clean` removes what the compose added.

**The toolchain is pinned, and the pin is forced.** The cryptographic code is reviewed, and
its vectors, known answers and guardrails are run, under one compiler: Go 1.26.5, the
`toolchain` line of `go.mod`, which `mls/pins_test.go` holds every test binary to. That
line is a minimum. A newer go command builds with itself and says nothing, and connect's
own toolchain line has moved to go1.27.1 while no module's `go` line asks for more than
1.26. So nothing here relies on the line:

- `./test.sh` reads the pin with [scripts/toolchain.sh](scripts/toolchain.sh), sets
  `GOTOOLCHAIN` to it for the whole run, and stops with the fix named when the host
  cannot have that release. It then asks the live probes' binaries and the native
  library which toolchain built them.
- A build by hand sets it the same way: `export GOTOOLCHAIN=$(bash scripts/toolchain.sh)`.
  `bash scripts/toolchain.sh --artefact <file>...` asks a built file, and fails on any
  other answer.
- Moving the pin is a reviewed change of its own: `go.mod`'s line and
  `mls/pins_test.go`'s literal together, with the vector, known-answer and guardrail
  suites run again under the new compiler. It is never a side effect of the go command
  a host happens to have.

## Contributing

- Work on a branch of your fork and open a pull request against `main`.
- Merge pull requests with **Create a merge commit** only. Squash and rebase merges
  rewrite commits, and the imports here carry their source history commit by
  commit (see [docs/HISTORY.md](docs/HISTORY.md)).
- Never force-push. Update a branch under review by adding commits or by merging
  `main` into it, never with "Update with rebase". To start over, open a new branch
  and a new pull request.
- Follow [CODESTYLE.md](CODESTYLE.md).

## History

Imported files keep their history: each import is a merge whose second parent is
the source repository's history, filtered to the imported paths.
[docs/HISTORY.md](docs/HISTORY.md) lists every import with its pinned source and
commit map, and shows how to re-run the verifier,
[docs/history/verify_split.py](docs/history/verify_split.py).

## Design documents

The URmessage specifications live in
[urnetwork/message-server](https://github.com/urnetwork/message-server) under
`docs/specs/`. They are cited here at commit `6c3153fd`:

- [URmessage protocol design](https://github.com/urnetwork/message-server/blob/6c3153fd2f995ff3f4f5a1041eff153a80d05d87/docs/specs/2026-08-12-urmessage-protocol-design.md)
- [Spec A: protocol, SDK and connect](https://github.com/urnetwork/message-server/blob/6c3153fd2f995ff3f4f5a1041eff153a80d05d87/docs/specs/2026-08-12-spec-a-protocol-sdk-connect.md)
- [Spec B: message server and operator](https://github.com/urnetwork/message-server/blob/6c3153fd2f995ff3f4f5a1041eff153a80d05d87/docs/specs/2026-08-12-spec-b-message-server-operator.md)
- [Spec C: Windows client UI](https://github.com/urnetwork/message-server/blob/6c3153fd2f995ff3f4f5a1041eff153a80d05d87/docs/specs/2026-08-12-spec-c-windows-client-ui.md)

## License

[Mozilla Public License 2.0](LICENSE). Files imported from connect and the core SDK
keep their notices; see [NOTICE](NOTICE).
