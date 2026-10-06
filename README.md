# message

`github.com/urnetwork/message` is URmessage, the URnetwork messaging application:
message records, group sessions, MLS, the shared serialization codec, the messaging
wire schema and, from stage 3, the messaging SDK. It runs on top of
[connect](https://github.com/urnetwork/connect) and the
[core SDK](https://github.com/urnetwork/sdk). Neither of those depends on it.

The code moves here from connect and the core SDK with its history, in the stages
of the maintainers' design,
[MESSAGEREVIEW.md at connect 13ced4c8](https://github.com/urnetwork/connect/blob/13ced4c8d50bf04c518667f2ad4b3948498abe56/MESSAGEREVIEW.md).

## Layout and status

Status: stage 1. The repository holds its module, documentation and CI, and
`CODESTYLE.md` with its history. The other rows are planned.

| Path | Contents | Comes from | Stage |
|---|---|---|---|
| `go.mod`, `docs/`, `.github/workflows/` | module metadata, documentation, CI | new | 1 |
| `CODESTYLE.md` | the Go style guide | connect, with its history | 1 |
| `message/` | records, attachments, authentication preimages | `connect/message` | 2a |
| `messagegroup/` | group sessions, ratchets, record encryption, the MLS adapter | `connect/messagegroup` | 2a |
| `mls/` | the MLS implementation | `connect/mls`, without `syntax` | 2a |
| `syntax/` | the shared serialization codec | `connect/mls/syntax`, promoted to a peer | 2a |
| `protocol/` | the messaging protobuf schema | `connect/protocol/message*` | 2b |
| `sdk/` | messaging transports, routes, durable stream store; its own module | the core SDK's `message*.go` | 3 |
| `sdk/urmessage/` | device and group orchestration, durable MLS state | the core SDK's `urmessage/` | 3 |

Stage 4 moves messaging onto a connect subprotocol and removes the remaining
messaging code from connect and the core SDK.

The root holds module metadata, documentation and CI only: no Go package, and no
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

[docs/BOUNDARY.md](docs/BOUNDARY.md) maps each rule to the check that holds it.

## Build and test

Go 1.26.5, the `toolchain` in `go.mod`.

    git clone -c core.autocrlf=false https://github.com/urnetwork/message.git message
    cd message
    go build ./... && go vet ./... && go test ./...

- On Windows, clone with `core.autocrlf=false`. Several checks read source files
  byte for byte, and a CRLF working tree can make such a check fail, or pass
  without testing anything.
- Name the directory `message`. From stage 2a, integration checks find their
  sibling checkouts (`../sdk`, `../connect`) by relative path, and consumers'
  local `replace` directives point at `../message`.
- Until stage 2a there is no Go package here, so `./...` matches nothing. The
  repository checks in
  [.github/workflows/repository.yml](.github/workflows/repository.yml) run on every
  pull request to `main`.

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
