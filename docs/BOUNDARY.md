# Dependency boundary

These rules are normative. Each names the check that holds it and the stage from
which that check runs. Until a rule's check lands, reviewers hold the rule by hand.

Source: [MESSAGEREVIEW.md at connect 13ced4c8](https://github.com/urnetwork/connect/blob/13ced4c8d50bf04c518667f2ad4b3948498abe56/MESSAGEREVIEW.md),
sections "Final dependency boundary", "Repository layout" and "Preserve the server
and client boundary".

## Rules

| # | Rule | Held by | From |
|---|---|---|---|
| B1 | The repository root holds module metadata, documentation and CI: no Go source, no package, no facade over the directories beneath it. | `repository.yml`, "The repository root holds no Go source", with a planted control | stage 1 |
| B2 | The root module is `github.com/urnetwork/message`. Its `go.mod` requires neither `github.com/urnetwork/connect` nor `github.com/urnetwork/sdk`. | `repository.yml`: the module path; "The root module requires neither connect nor the core SDK", with controls; `go mod verify` | stage 1 |
| B3 | The five foundational packages (`message`, `messagegroup`, `mls`, `syntax`, `protocol`) import neither connect nor the core SDK, in any file, test or build configuration. | `internal/layering`: every file including tests, every GOOS, aliased, blank and dot imports | 2a; `protocol` from 2b |
| B4 | A package never imports its own descendants. Peers may import peers. | `internal/layering`; `syntax`'s own layering test | 2a |
| B5 | `message`, `syntax` and `protocol` are server-safe. Neither `message` nor `protocol` imports `mls` or `messagegroup`, directly or transitively. `syntax` imports the standard library only. | `internal/layering`, the server-safe closure; `syntax`'s layering test | 2a; `protocol` from 2b |
| B6 | Consumers allow the server-safe packages by exact path, never the `github.com/urnetwork/message` tree. The `mls`, `messagegroup` and `sdk` trees stay forbidden to the server. | message-server's dependency gate (`deps_test.go`) | when message-server moves to `message/message` |
| B7 | Neither connect nor the core SDK depends on this module, directly or transitively, including platform-specific files and native bindings. | connect: "connect has no message dependency". Core SDK: no `github.com/urnetwork/message` in `go.mod` or in any import, and `go list -deps` of its builds holds no message package. | each repository's removal change |
| B8 | `message/sdk` imports connect and this repository's packages, never the core SDK, and neither connect nor the core SDK imports it. `sdk/urmessage` imports its parent; the parent never imports it. The native composition (`sdk/cgo`) is the one module that links both SDKs. | `internal/layering`: the SDK packages' rows allow no core SDK import, and no foundational row allows an SDK package; the core SDK's boundary gates (the sdk removal PR) | 3 |
| B9 | A binary links exactly one copy of `message.proto`, and it is `message/protocol`'s. | `TestOneCopyOfMessageProtoIsRegistered` in `message/sdk`; every main package has a test, so its binary starts (the module census); the protobuf runtime refuses a second copy at init | 3 |
| B10 | Authenticated inner bytes stay byte-identical across the move: canonical requests, operation bytes, record preimages, attestation and signature inputs. | the vectors and known-answer tests that move with `mls` and `message`; the `protocol` wire corpus, held append-only by `TestTheWireCorpusIsAppendOnly` and compared byte for byte with a pinned pre-removal connect by `protocol.yml` | 2a; 2b |
| B11 | The SDK module's production code imports exactly the declared standard and x/crypto packages. | `TestThisModulesProductionCryptoImportsAreTheDeclaredOnes` in `message/sdk` | 3 |
| B12 | Every module is built and its main packages' tests run in CI, or listed as not yet wired with the reason; protobuf resolves to one version in every module. | `.github/scripts/module-census.sh` (`repository.yml`), `native.yml` | 3 |

The specifications behind B9 and B10 are pinned in the README's
[Design documents](../README.md#design-documents) section.

## Scope of the root-module guardrails

The `mls` guardrails cover the **root module**, as they covered the connect module.
They are the crypto derivation and its `go list` floor, the forbidden-primitive and
constant-time scans, and the erasure checks. A walk rooted at the module stops at
any directory that holds its own `go.mod`, and the floor is `go list` over the root
module only.

Nested modules (`sdk/` and the modules beneath it, from stage 3) carry their own
gates in their own module. These include a crypto-scope gate that pins every
`crypto/*` and `golang.org/x/crypto/*` import of the module's production code.
Extending the constant-time and erasure guardrails to `message/sdk` is a separate
hardening change, not part of the move.

## One copy of the messaging schema

The schema moved whole at stage 2b: `message/protocol` holds `message.proto`, whose protobuf
package, message names and field numbers are those of connect's copy, with only `go_package`
changed, and the connect removal pull request deletes connect's copy. A binary that linked a
connect still carrying it would register the same names twice, and the protobuf runtime panics
at startup; `TestOneCopyOfMessageProtoIsRegistered` is the check that runs in this repository
(B9). The carrier is unchanged: connect's `Frame` with the MessageType code points 1000-1003,
whose numbers stay in connect's `frame.proto` and whose names are held here against
`message/protocol`'s messages.

There is no freeze. The wire corpus (`protocol/testdata/wire-golden.tsv`) is append-only: a
change to the schema that would re-encode any existing row fails, and new rows are appended.

No version is tagged before the cutover; see [RELEASING.md](RELEASING.md).

## Changing an API that message-server also uses

Once the cp3b acceptance suite is wired into CI (it waits for message-server's switch to this
repository's packages; `.github/scripts/module-census.sh` lists it as not yet wired), it builds
against a pinned message-server,
and message-server pins this module. A breaking change to an API both use cannot
land green in one step. Make it additive:

1. add the new API here, keeping the old one;
2. bump message-server's pin of this module and move message-server to the new API;
3. bump this repository's message-server pin (cp3b);
4. remove the old API.
