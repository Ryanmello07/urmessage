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
| B8 | `message/sdk` may import connect and generic core SDK APIs; neither may import it. `sdk/urmessage` imports its parent; the parent never imports it. | `internal/layering` rows for the nested `sdk` module | 3 |
| B9 | A binary links exactly one copy of `message.proto`. | `TestOneCopyOfMessageProtoIsRegistered` in `message/sdk`; the layering disposition that keeps `message/protocol` out of the sdk module until the cutover | 3; flipped at the cutover |
| B10 | Authenticated inner bytes stay byte-identical across the move: canonical requests, operation bytes, record preimages, attestation and signature inputs. | the vectors and known-answer tests that move with `mls` and `message`; the `protocol` wire-golden corpus and its freeze test | 2a; 2b |

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

## Two copies of the messaging schema, from stage 2b until the cutover

From stage 2b, `message/protocol` holds a generated copy of `message.proto`. Its
protobuf package, message names and field numbers are those of connect's copy in
`connect/protocol`; only `go_package` differs. A binary that links both copies
registers the same names twice, and the protobuf runtime panics at startup. Until
the cutover removes connect's copy:

- nothing here imports `message/protocol` outside that package's own tests and
  test data;
- consumers keep using `connect/protocol`'s types;
- a freeze test holds `message/protocol`'s schema byte-equal to connect's, apart
  from `go_package`, and a CI job checks it against a pinned connect.

No version is tagged before the cutover; see [RELEASING.md](RELEASING.md).

## Changing an API that message-server also uses, from stage 3d

From stage 3d, the cp3b acceptance check builds against a pinned message-server,
and message-server pins this module. A breaking change to an API both use cannot
land green in one step. Make it additive:

1. add the new API here, keeping the old one;
2. bump message-server's pin of this module and move message-server to the new API;
3. bump this repository's message-server pin (cp3b);
4. remove the old API.
