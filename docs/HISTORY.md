# History and provenance

Code arrives here with its history. Each import is a merge commit. Its first
parent is this repository's `main`; its second parent is the source repository's
history, filtered to the imported paths by
[git-filter-repo](https://github.com/newren/git-filter-repo) 2.47.0 with
`--preserve-commit-hashes`. Filtering keeps every commit's author, committer, dates
and message, and changes its id, so each import publishes a commit map: one
`old new` row per imported commit.

## Base

`0d697b0a07fbdee660a90d995c1255673a056bba`: the repository's first commit, `LICENSE`.

The tip's `LICENSE` is not the base's. On 2026-10-09, three minutes after the import merged, the
repository's owner changed its copyright line on `main`, in
`b2da8432fb9114ef71daab63971a90d0d2ec0a36`: `Copyright (c) 2023 UR Foundation` became
`Copyright (c) 2024 BringYour, Inc.`. No other byte differs, and the file is now the core SDK's
`LICENSE` byte for byte (blob `4b028936` here and at urnetwork/sdk `679a836a`).
[adaptations.tsv](history/adaptations.tsv) declares it as the `edit` of a base path: the row pins
the new bytes and names that commit, and the verifier asks the history whether it is the commit
that changed the file (revision 6, below).

## Imports

| Stage | Imported | Source | Filtered tip | Commits | Paths | Import merge |
|---|---|---|---|---|---|---|
| 1 | `CODESTYLE.md` | connect `e449f7d8` | `d3b3b26a` | 24 | 1 | `e52b05a1` |
| 2a | `message/`, `messagegroup/`, `mls/`, `mls/syntax/` as `syntax/`, `.gitattributes`, the codec's workflow | connect `e449f7d8` | `fbbc842d` | 465 | 837 | `a456b1cd` |
| 2b | `protocol/message*` | connect `e449f7d8` | `28a9c4f1` | 10 | 8 | `0ebd54f6` |
| 3 | the core SDK's root `message*.go`, `urmessage/`, `cp3b/`, `livepeer/`, `liveprobe/` and its 11 messaging cgo files, under `sdk/` | sdk `6141b98d` | `e5223830` | 123 | 148 | `0417c59a` |

The four imports reached `main` together, in urnetwork/message pull request 1, merged with a
merge commit on 2026-10-09: `07704991dc89ffeee35a70b4bb7372f588dc9067`, whose parents are the
base and the pull request's head, `66628426`.

### Stage 1: CODESTYLE.md

- Source: `Ryanmello07/connect` `e449f7d8126c0b5748f5083392a8855bac877b32`, which
  that fork tags `split/source-connect-2a`. `CODESTYLE.md` is blob `b8a801d3` there
  and in `urnetwork/connect` `main`.
- Filter: [connect-codestyle-paths.txt](history/connect-codestyle-paths.txt).
- Imported: `d3b3b26ae388ab0d00a4039df2988bdecfb241ae`, 24 commits: the 23 that
  change the file, and the merge of urnetwork/connect#184. Brien Colwell and
  Bitprecipice wrote every line of the file, and the import keeps them its authors.
  Most of these commit messages describe connect work whose other files stay in
  connect; here each commit carries only its `CODESTYLE.md` change.
- Commit map: [connect-codestyle-commit-map.txt](history/connect-codestyle-commit-map.txt),
  24 rows.
- Reproduced: two environments produced the same filtered tip, Windows (git 2.53.0,
  Python 3.14.4) and Ubuntu 24.04 (git 2.43.0, Python 3.12.3).
- Merged by `e52b05a1a7e569e371939d65178712d1d4d3c30b`, whose message carries the
  verifier's summary for that merge.

### Stage 2a: the foundational packages

- Source: the same `Ryanmello07/connect` `e449f7d8`, the URmessage checkpoint. Its message
  paths equal `urnetwork/connect` `7ca8e222` except the codec workflow's branch trigger and
  the test needle that asserts it; the verifier's control is that difference.
- Filter: [connect-core-paths.txt](history/connect-core-paths.txt): `message/`,
  `messagegroup/`, `mls/`, `.gitattributes`, `.github/workflows/mls-syntax.yml`, and the
  rename `mls/syntax/` to `syntax/`. `protocol/message*` is stage 2b's own import, and
  `CODESTYLE.md` stage 1's.
- Imported: `fbbc842d064cc4465e580be396bfdc3363907508`, 465 commits: the 463 that change
  these paths and the merges `197af904` and `1f97ebb2` (the second is fork-only and resolves
  in `Ryanmello07/connect`). 837 files.
- Commit map: [connect-core-commit-map.txt](history/connect-core-commit-map.txt), 465 rows.
- Reproduced: the same filtered tip on Windows and on Ubuntu 24.04, from the source fetched
  by SHA.
- Merged by `a456b1cd068dafceaff788c059dccf18a4ea4c8a`, whose message carries the
  verifier's summary for that merge.
- Adapted by the commits after the merge, each a single reviewable step: the module's
  requirements; the module-path rewrite, made by one run of
  [rewritepaths](history/rewritepaths.go.txt) (kept as `.txt` so it is no package of this
  module); the codec's workflow and paths; mls scanning the promoted codec by name; the
  record gate's roots; the cross-platform scope; the first-party import filter; the
  dependency boundary (`internal/layering`); the third-party notices and their gate
  (`internal/repository`); CI. [2a-scope.md](history/2a-scope.md) records every scope the
  move could have narrowed, measured in connect and here, and who keeps each gate's
  non-moved half.
- Upstream changed some of these paths after `e449f7d8`; see "Upstream's changes after the
  imports" below.

### Stage 2b: the messaging schema

- Source: the same `Ryanmello07/connect` `e449f7d8`. These eight files are blob-identical in
  `urnetwork/connect` `7ca8e222` and `92a657fa`.
- Filter: [connect-protocol-paths.txt](history/connect-protocol-paths.txt):
  `protocol/message*` only; `frame.proto`, `subprotocol.proto` and connect's Makefile stay.
- Imported: `28a9c4f132e3d7a266021e902eee8dc2f2451cea`, the 10 commits that change those
  files. Four of them (`549bf3fc`, `6bbb77cd`, `8ddba71b`, `96e6b461`) also changed stage 2a
  files, so they appear in both imported histories, each time with only its own side's files.
- Commit map: [connect-protocol-commit-map.txt](history/connect-protocol-commit-map.txt),
  10 rows.
- Merged by `0ebd54f6a1a5192d9e9fe44dabbea6c597421c2f`, whose message carries the verifier's
  summary for that merge.
- Adapted by: `go_package` moved and `message.pb.go` regenerated once (a 7-byte diff); the
  tests' imports rewritten; the frame code-point checks split (their numbers stay with
  `frame.proto` in connect; their names are held here, reading `frame.proto` as text); the
  wire corpus and its emitter; the append-only rule over the corpus; the schema's layering row;
  CI.
- The schema moves whole, at the same time connect drops its copy: there is no interim in
  which two copies are linked, and no freeze. The corpus that connect's copy emitted is
  [protocol/testdata/wire-golden.tsv](../protocol/testdata/wire-golden.tsv) (197 items, sha256
  `9b5772b7...`); this package emits the same bytes today, test.sh re-emits the base from a
  pinned connect from before the move and compares it byte for byte, and
  `protocol/message_wiregolden_test.go` holds it append-only: every recorded row must still
  decode and re-encode to its bytes, so the schema can grow and the base stays connect's.
- Scope: `TestNothingHereComputesTheAttestationPreimage` walks the repository root. In
  connect it read 1,587 Go files and here 253, and it finds every label in the same files in
  both (`message/writeauth.go`, `message/attachment.go` and their tests,
  `messagegroup/keysource_test.go`, `protocol/message_op_test.go`; the attestation label in
  none). Connect's remaining files hold none of them; the connect removal PR deletes the test
  there with the code it was about.

### Stage 3: the messaging SDK

- Source: P_sdk, `Ryanmello07/urnetwork-sdk` `6141b98d05bcac98d5ccae11c54c7748919017e6`,
  the fork's `beta/message` after the sync that merged upstream `urnetwork/sdk`; the fork tags
  it `split/source-sdk-3`. It differs from upstream `main` as it was then (`b8e0da26`) in five
  of the 148 files: the three tunnel files carry the fork's 1 s establish hold (the owner's
  ruling "Build the 1 s hold", 2026-10-04), and the loopback modfiles' indirect requirements,
  which upstream has since added itself (`a7b5db77`).
- Filter: [sdk-paths.stage3.txt](history/sdk-paths.stage3.txt): the root `message*.go` files,
  `urmessage/`, `cp3b/`, `livepeer/`, `liveprobe/` and the messaging cgo files, each renamed
  under `sdk/`; `cgo/gen/manual_exports_test.go` stays in the core SDK. A second pass removes
  `sdk/liveprobe/liveprobe.exe`, a 36 MB binary three commits added, changed and deleted.
- Imported: `e522383045379792fec68bb81614fc6be24c6030`, 123 commits, 148 files. One sync merge,
  `990e84ff`, has a single parent here: its upstream side held no messaging file yet.
  Revision 4 of the verifier accepts that case only, and its controls refuse it for every
  merge kept whole.
- Commit map: [sdk-commit-map.txt](history/sdk-commit-map.txt), 123 rows.
- Reproduced: three runs, two on Ubuntu 24.04 and one on Windows, produced one tip.
- Merged by `0417c59a667d11799bbb858d10b3cb524e0e65dc`, whose message carries the verifier's
  summary for that merge.
- Adapted by the commits after the merge: the module-path rewrite (rewritepaths `-stage 3`);
  the schema switch (the message types from `message/protocol`, `Frame` and the transport
  types from `connect/protocol`); the module files (`sdk/go.mod` requires connect and this
  repository, never the core SDK); `connect.NewOperatorClientSettings` in the tunnel;
  explicit service urls in `MessageClientConfig`; the tunnel tests' packet helper and a
  documentation address in place of a real one; every gate the move narrowed or changed the
  subject of, rebuilt with its controls; the record gate over this repository's own `sdk/`;
  the module walks stopping at a nested `go.mod`; the native composition (`sdk/cgo`);
  the commands' tests; the single-registration test; CI. [3-scope.md](history/3-scope.md)
  records every scope the move could have narrowed, measured here and at P_sdk, and who
  keeps each gate's non-moved half.

## Upstream's changes after the imports, and the fork's own

The imports are projections of fork commits, `e449f7d8` and `6141b98d`, and the removal pull
requests deleted the same paths from later upstream commits. Two kinds of difference sit between
the two, and [ported.tsv](history/ported.tsv) declares every one of them.

**Upstream changed imported paths after the imports' sources.** Each upstream commit is ported
here as one commit with its original author, author date and message, followed by
`(cherry picked from commit ...)` and a port note:

| Upstream commit | Paths here | Port |
|---|---|---|
| connect `54b5b106` Bitprecipice, 2026-10-05, "Fix transfer custody and persistent TCP collapse admission" | `message/record_test.go` (the reviewed SDK contexts of the record gate, `TestJoinSDKPacketAndPoolContexts`), and the five fixtures under `message/testdata/reviewed-sdk/` | `3a22cd99` |
| connect `e8611390` Bitprecipice, 2026-10-06, "Remove the GitHub workflows" | `mls/hpke_fuzz_test.go`, `syntax/fuzz_test.go`, `syntax/layering_test.go` (its two workflow tests), and the codec's workflow, deleted | `4be82ed6` |
| connect `f5e1aa1f` Bitprecipice, 2026-10-06, "Require deterministic root cause tests for every bug fix" | `CODESTYLE.md`, which connect keeps too: the two copies are kept in step | `d749b68d` |
| connect `03d82b4e`, `bbe2d568`, `48405dff`, `a3bb8775` Bitprecipice, 2026-10-06: the section "Packet flow and durable state", added and then rewritten three times | `CODESTYLE.md` | `3849bdef`, `fb6ecbc1`, `2a193955`, `de8d5c5e`, one for one |
| connect `5f5a205d` Bitprecipice, 2026-10-07, "Document Redis-only contract packet authorization": the same section, its first four rules rewritten as five and its last rule changed | `CODESTYLE.md` | `cc2b4882` |
| connect `6b86a4c3`, `84fb2386` Bitprecipice, 2026-10-08, "Document caller-owned model transactions" and "Require dependent models to reuse held connections": two rules at the head of "Locking", the first added and then rewritten as two | `CODESTYLE.md` | `5b45d5c7`, `002eb114`, one for one |
| sdk `a7b5db77` Product Builder, 2026-10-06, "Isolate C ABI loopback dependencies from release modules" | the loopback harness, moved to `sdk/cgo/ctest/testdata/`; `sdk/cgo/ctest/loopback-overlay.json`, which lays it back into the package for the test library; `sdk/cgo/ctest/run.sh`; `sdk/cgo/gen/loopback_module_test.go` | `966b77f2` |

The merge of connect#216 (`94453d74`) changed no imported path beyond what `e8611390` then
removed: the codec workflow's trigger and its needle. The merge `89f66cda` brought `f5e1aa1f`
and `03d82b4e` together in connect, and changes `CODESTYLE.md` against each of its parents.
connect `main` took `5f5a205d` by the merge `60f3bd61`, which changes the file against one
parent only. `6b86a4c3` and `84fb2386` were made on `main` itself. The removal did not change
the file, so its merge, `847460bb`, which this repository now pins, left `main`'s copy as it
was: blob `0feba3df`, which is this repository's too.

Five upstream changes needed no commit here, and ported.tsv says why each one stands:

| Upstream commit | Path there | Why nothing was carried |
|---|---|---|
| sdk `a7b5db77` | `cgo/loopback.go.mod`, `cgo/loopback.go.sum`: three indirect requirements | The import already held them, from the fork's `2dc9bf77` (`port-in-source`). |
| sdk `06f33802` Product Builder, 2026-10-06, "Generate runtime license JSON to avoid linking the YAML parser" | `message_stream_adapter_test.go`: one row of the value census renamed, `licenseYml` to `licenseJSON` | The row names a core SDK value. The census here holds this package's values alone ([3-scope.md](history/3-scope.md)), so the row is among the lines this repository removed (`port-void`). |
| sdk `ae5a65fc` Bitprecipice, 2026-10-08, "Preserve regression fixes, memory diagnostics, and test harness evidence" | `message_stream_adapter_test.go`: a census row for the core constant `mobileMemoryTeardownLifetime`, and a new test, `TestStreamAdapterTeardownConstantsHaveCompleteCensus`, 37 lines in all | Both name constants of the core SDK, `mobileMemoryTeardownLifetime` and `mobileMemoryTeardownCapacity`, which its `memory_teardown_observation.go` declares and the sdk removal keeps. This package declares neither, so the lines cannot compile here, and the census here has no core value to hold. carried.py sets them aside by those two names (`port-void`, the same row as `06f33802`). |
| sdk `80f6e365` Bitprecipice, 2026-10-09, "Send the network credential on the SDK's admin calls" | `message_stream_adapter_test.go`: census rows for `ErrNetworkCredentialRequired`, `apiAdminRouteAccess` and `apiAdminRoutePatterns`, and a non-sentinel ruling for the first, 4 lines | All three are values of the core SDK's API client, declared in its `api_network_credential.go`, which the sdk removal keeps. This package declares none of them. carried.py sets the lines aside by those names (`port-void`, the same row). |
| sdk `69c49348` Bitprecipice, 2026-10-09, "List the renewal's package values in the value census" | `message_stream_adapter_test.go`: census rows for `closedNetworkRenewerDone` and the four timing constants `networkRenewalMaxRetryJitter`, `networkRenewalMinRetryTimeout`, `networkRenewalRefusedRetryTimeout` and `networkRenewalRetryJitterBase`, 5 lines | All five are values of the core SDK's credential renewer, declared in its `api_network_credential_renewal.go`, which the sdk removal keeps. This package declares none of them. Set aside by name (`port-void`, the same row). |

`a7b5db77` moved the harness, so the gates that skip `testdata` read that one directory by
name; [3-scope.md](history/3-scope.md), section 5, has each of them before and after.

**The fork carries changes upstream never had.** These commits are reachable only from the
forks, so re-running the verifier fetches from `Ryanmello07/connect` (tag
`split/source-connect-2a`) and `Ryanmello07/urnetwork-sdk` (tag `split/source-sdk-3`). Those
tags are what keep this proof reproducible; neither fork is protected by a ruleset.

| Fork commit | Repository | What it changed |
|---|---|---|
| `1f97ebb2` | connect | the absorb of connect#216, which kept the fork's `beta/message` trigger and needle; `e8611390` removed both, so nothing of it remains |
| `e449f7d8` | connect | the source tip itself; it changes no imported path |
| `c71bb73b` | sdk | per-peer encryption OPPORTUNISTIC, not REQUIRED (the owner's ruling of 2026-10-04): `message_route.go`, `message_tunnel.go`, `message_tunnel_test.go`. It is the fork's commit, not the fork's change: upstream sdk holds the same patch as `98e444e`, merged by urnetwork/sdk#156 |
| `d20d82c1` | sdk | the 1 s establish hold on every window client (the owner's second ruling of 2026-10-04): the same three files |
| `f370a732` | sdk | the SX-0 sync merge of upstream `0c6462f2` |
| `2dc9bf77` | sdk | the loopback modfile's indirect requirements for upstream connect's uTLS dial: `cgo/loopback.go.mod`, `cgo/loopback.go.sum`. Upstream made the same change afterwards, in `a7b5db77` |

Of these, the tunnel's 1 s hold is the one change in behaviour upstream has not reviewed: with
it the three tunnel files differ from sdk `main`, and without it (`d20d82c1`'s parent) they are
sdk `main`'s byte for byte. This repository's pull request 1, the import, names it at its top.
An earlier version of this file listed OPPORTUNISTIC beside it; that change is upstream's too.

**The proof.** [carried.py](history/carried.py) reads what each removal deleted when it merged,
a range it records ("The removals, as they merged", below), and holds the tip to it: every
deleted path is here (or declared deleted in the manifest), the tip contains every upstream
change to it since the merge base of the import's source and the removal's base (a three-way
merge that changes nothing), and every upstream change and fork-only change is declared in
ported.tsv, both ways. Its control is the
tip the review measured, `f3f8f2bd`, before the ports, where it fails for exactly the ported
paths. An imported path is one the import specs (the `*-paths*.txt` files) select, and a
file upstream adds later under a directory an import took whole is one too: carried.py holds its
projections to the specs, so a directory that verify_split.py projects through the files it held
at the source (the sdk's `cgo/ctest/`) still has what upstream adds there measured.

Four more rules came with `a7b5db77`, `06f33802` and `ae5a65fc`, each with a control against the
design it replaces:

- **A path upstream moved.** The harness is a deletion at its old path and a new file at its new
  one, and a new file has no merge base, so an adapted copy could only conflict with it.
  carried.py measures the new path against the old path's blob at the merge base, taking the
  lineage from this repository's own manifest (the rename row verify_split.py holds to the
  import's bytes) and checking that upstream's commits which removed the one are among those
  that added the other. With no lineage it fails for exactly that path.
- **A file upstream added outside every imported directory**, which the removal deletes and this
  repository carries (`cgo/gen/loopback_module_test.go`), has a row in carried.py's `ADDED`. It
  must be absent from the import's source and present upstream; with the row dropped, nothing
  projects the path and the removal's deletion of it is reported.
- **An upstream change to lines this repository removed** (`port-void`). The three-way merge
  conflicts, and is accepted only when every conflict's side here is empty and the merge taken
  this side's way is the tip byte for byte, so every other upstream change is in the tip. The
  lines not carried are printed. A line the tip kept, a line it changed its own way, and a
  second upstream change outside the removed region are each refused.
- **Lines upstream added about a value of the core** (`port-void` too). `ae5a65fc` appends a
  test to `message_stream_adapter_test.go`, where this repository removed nothing, so the rule
  above refuses it; and the test cannot be carried as written, because it names two constants
  the core keeps and this package does not declare. carried.py's `CORE_SUBJECT` names such
  values, path by path. A block of lines upstream added is set aside, before any merge, when a
  line of it names one of them, and each name is held both ways: no Go file of the tip names
  it, a Go file upstream keeps (one the removal does not delete and no import takes) does, and
  a line set aside names it. The lines are pinned by their sha256 and printed. A name the tip
  spells too, a name only the moved file spells, and a name no added line spells are each
  refused, and so is a line planted beside the pinned ones; with the digest unchecked, the
  design it replaces, that planted line is set aside with the rest and nothing reports it. A
  line upstream changed, rather than added, is never set aside. `80f6e365` and `69c49348` then
  added nine more lines, for eight more values of the core, all of them among lines this
  repository removed, where the rule above would have passed them by position. Their values
  are named in `CORE_SUBJECT` too, ten names and 46 pinned lines in all, so each of the nine
  is set aside for the value it names, held both ways, and not for where it merges.

The kind of a row is what carried.py measures, not what the row says: an upstream change the
import's source already held is `port-in-source` and names no commit here, and a `port` row must
name a commit of this repository that changes the path.

## The recorded tip

The proof is a statement about one tree. [verify_split.py](history/verify_split.py) proves
every import against its pinned source and holds every other path of that tree to the manifest,
and [carried.py](history/carried.py) holds the same tree to what the two removals deleted.
While the imports were made it was run at every tip, and each commit kept the manifest in step.
It is now held at ONE commit, the recorded tip, and at no other: the tree in which every
sibling pin had moved to a merged upstream commit and both removals' ranges were final.

It cannot be held at every tip for good. The manifest pins the sha256 of every file that is
not an import's own bytes, so the first commit that changes code fails part E, and a manifest
rewritten for each day's work would stop being a record of the import. So no row is added to
it for later work, and a later tip is held to two rules instead, by
[proof.py](history/proof.py):

1. **The recorded tip is its ancestor.** [recorded-tip.txt](history/recorded-tip.txt), read
   from the tip that is asked about, names one commit by its full id. That commit must be in
   the repository and in the tip's history. A history rewritten after the record (a squash, a
   rebase, a force-push) does not hold it, and fails here.
2. **The proof passes at the recorded tip**, run by that commit's own copies of the two
   scripts over that commit's own records. proof.py reads them out of the commit byte for
   byte, so nothing a later commit does under `docs/history`, and no line-ending setting of a
   checkout, changes what is proven.

A commit cannot hold its own id. So the recorded tip does not hold recorded-tip.txt: the commit
after it adds that file, writes the id into the next sentence, and changes nothing else.
This tree is made to be that tip, and it is proven as one with `--at` (below) before it is recorded.

## Running the proof again

It reads repositories only, and never checks out a file. The clone must hold its whole history
(the check does not pass in a shallow clone). From the root of a checkout of the recorded tip,
or of any later tip:

    git init --bare ../connect-src.git
    git -C ../connect-src.git fetch https://github.com/Ryanmello07/connect.git e449f7d8126c0b5748f5083392a8855bac877b32:refs/heads/main
    git -C ../connect-src.git fetch https://github.com/urnetwork/connect.git 7ca8e222e3496552146f2d97eb09237401662c99:refs/remotes/upstream/control
    git -C ../connect-src.git fetch https://github.com/urnetwork/connect.git 847460bba8aa31fb2e86ce007e9d5443d884544b:refs/remotes/removal/merged
    git init --bare ../sdk-src.git
    git -C ../sdk-src.git fetch https://github.com/Ryanmello07/urnetwork-sdk.git 6141b98d05bcac98d5ccae11c54c7748919017e6:refs/heads/main
    git -C ../sdk-src.git fetch https://github.com/urnetwork/sdk.git b8209d9d7f6d858b2171cd92d4203bdadb758260:refs/remotes/removal/merged
    python3 docs/history/proof.py --connect ../connect-src.git --sdk ../sdk-src.git --controls

It must end with `PASS`. Every fetch names a commit and no command reads a branch, so the
answer for a tip is the same on any day. At a tip that names a recorded tip the command checks
rule 1 and then runs rule 2's two scripts at the recorded tip. The recorded tip itself names
none, so there add `--at HEAD`: that runs the two scripts at the commit given, with that
commit's copies, and it is how a tip is proven before it is recorded.

`--controls` passes `--controls` to both scripts (below), and then runs proof.py's own on
histories it builds in a scratch repository that borrows the checkout's objects, so nothing is
written to the repository measured:

- a later commit that changes an imported file is accepted, and the same commit held to the
  manifest, the design this replaces, is refused for that file;
- a later commit that puts a script that passes anything in carried.py's place and empties the
  manifest is accepted too, and what is run for it is still the recorded tip's copies;
- a rewritten history is refused: the tip's own tree as one commit on the recorded tip's parent,
  which is what a squash merge makes. Recovered the way [RELEASING.md](RELEASING.md) gives, by
  one more merge of the original tip that takes no change, it is accepted again;
- a record that is a name and not a commit id, a record naming a commit the repository does
  not hold, and a record naming a commit that holds no proof are each refused, for that reason.

### What verify_split.py proves

[verify_split.py](history/verify_split.py) proves, for every import the tip holds:

- **D:** the base, and every commit in [verified-tips.txt](history/verified-tips.txt),
  is an ancestor of the tip, so nothing verified earlier was rewritten;
- **A1/A2:** each import merge is its first parent's tree plus the import's tree,
  and the import's tree is the projection of its pinned source, byte for byte;
- **B/C:** each imported commit is a projection of exactly one source commit with
  identical metadata and correspondingly projected parents; no source commit that
  changes an imported path is missing; the published commit map equals the computed
  one, both ways;
- **E:** every other path of the tip is declared in
  [adaptations.tsv](history/adaptations.tsv), and every declaration is needed. A path of the
  base that the tip holds with other bytes is declared too, and its row names every commit that
  changed it since the base (`LICENSE`, by `b2da8432`).

proof.py runs it at the recorded tip, with that tip's copies of the script, of the manifest
and of the four commit maps:

    python3 verify_split.py --sides connect-codestyle,connect-core,connect-protocol,sdk --connect ../connect-src.git --sdk ../sdk-src.git --dst . --dst-rev <the recorded tip> --controls --expect-filtered-tips --commit-map connect-codestyle=connect-codestyle-commit-map.txt --commit-map connect-core=connect-core-commit-map.txt --commit-map connect-protocol=connect-protocol-commit-map.txt --commit-map sdk=sdk-commit-map.txt --manifest adaptations.tsv

`--controls` also runs negative controls that must fire:
the source file one change earlier, and synthetic changes to the expected tree. For the
changed base path it runs part E four more times over the same tip, with the `LICENSE` row
dropped, with its pin replaced by the base's digest, with `b2da8432` taken out of its reason,
and with the base's bytes in the tip again; each must fail for `LICENSE` alone, for its own
reason. The first of the four is what `main` printed between the owner's commit and this
declaration: `E: LICENSE differs from base and is not declared`.
`7ca8e222`, an earlier `urnetwork/connect` `main`, is the control for the stage 2a
import; the sdk side's control is `d20d82c1`, the fork's `beta/message` before its sync, which
the fetch of `6141b98d` brings with its history.

### The removals, as they merged

[carried.py](history/carried.py) holds the tip to what each removal deleted. Both removals have
merged, each with a merge commit, and carried.py records the two ranges beside each import's
source:

| Side | Merged as | Base: the merge's first parent | Merge commit | Deleted |
|---|---|---|---|---|
| connect | urnetwork/connect pull request 219, 2026-10-09 13:44 UTC | `64e433f47cb5ac9f32e71a5b6d5aff659bc00623` | `847460bba8aa31fb2e86ce007e9d5443d884544b` | 848 imported paths |
| sdk | urnetwork/sdk pull request 158, 2026-10-09 12:25 UTC | `679a836a21cf2f597b87d3adae6b91bcdf5aabf3` | `b8209d9d7f6d858b2171cd92d4203bdadb758260` | 150 imported paths |

The base is the last commit of that `main` to hold the moved paths, and the content is measured
there. In both, the pull request's head had merged that same commit and the merge's tree is the
head's, so the range is what the pull request deleted and nothing else. carried.py holds the
record to the shape it relies on: each merge is a merge commit, and each base is its first
parent. proof.py runs it at the recorded tip, with that tip's copies of the script and of
ported.tsv:

    python3 carried.py --dst . --dst-rev <the recorded tip> --ported ported.tsv --connect ../connect-src.git --sdk ../sdk-src.git --controls

**Why the ranges are recorded, and not computed.** While the removals were under review the
command took each removal's base and head as arguments. The base was computed as the merge base
of the removal's head and upstream `main`, and the content was measured at the newest `main` (a
suffix, `@<commit>`), so that a change upstream made meanwhile was caught before the removal
merged it. Once a removal has merged, that merge base is the head itself: the range is empty,
and `main` holds no moved path to measure. At `a0d47bef`, this repository's `main` as pull
request 2 merged, that command prints `PASS` against upstream as it stood before either removal
merged, `FAIL (165)` against upstream once urnetwork/sdk had merged its own, and `FAIL (1021)`
since connect merged too: one tree, three answers. Nothing upstream can change a moved path any
more, so the ranges are final, and they are commits. The controls run the old form on each
side, where it must fail on an empty range, and refuse a recorded base that is not its merge's
first parent. A ported.tsv row whose commits the upstream measured does not hold was printed as
ahead of it while the ranges moved; it is a row nothing needs now, and fails like one.

### Measured while the removals were under review

Each of these ran the command as it then was, with the ranges as arguments. Measured on
2026-10-06 at `a8c84e3c` and again on 2026-10-07 at `2406135e`, with the controls: connect
`6df2fa87..0f2ff669` (848 deletions) against `main` at `6edbaa6f`, and sdk
`06f33802..0f03e27e` (150 deletions) against `main` at `06f33802`, both `PASS`. connect `main`
then took `5f5a205d`: against `main` at `60f3bd61` the command fails for `CODESTYLE.md` without
the port and passes with it. connect's `main` also takes an automated data commit about once an
hour (ten on 2026-10-06, 31 to 163 minutes apart), so a commit named here was soon not the
newest; the command measured whichever was.

Measured again on 2026-10-09 (UTC), with connect `main` at `c2833fcb` and sdk `main` at
`812df82f`. connect `main` had changed `CODESTYLE.md` twice more, and sdk `main` had added 37
lines to `message_stream_adapter_test.go` (`ae5a65fc`); the sdk removal's branch had merged
`main` twice, to the head `af5666ed`. At `4d365abf`, the tip before those changes were
carried, the command fails for those two paths and no other. At the tip that carries them it
passes with the controls, for the pinned sdk commit (`06f33802..0f03e27e`) and for that newer
head (`812df82f..af5666ed`): the same 150 deletions either way.

Measured a third time on 2026-10-09, after the import had merged, with connect `main` at
`64e433f4` and sdk `main` at `679a836a`. sdk `main` had added nine more lines to
`message_stream_adapter_test.go` (`80f6e365`, `69c49348`), and both removal branches had merged
`main` again, connect to the head `4bcc5fd8` and sdk to `0da627ac`. At `b2da8432`, `main`
before those lines were declared, the command fails for that one path: its row names two of
upstream's four commits. At the tip that declares them it passes with the controls, for the
commits this repository pins (connect `6df2fa87..0f2ff669`, sdk `06f33802..0f03e27e`) and for
those newer heads (`64e433f4..4bcc5fd8`, `679a836a..0da627ac`): 848 and 150 deletions either
way.

Measured a fourth time on 2026-10-09, after both removals had merged, with the ranges recorded.
At `7fa04709`, the commit that moved the last sibling pin to a merged upstream commit,
carried.py passes with its controls: the same 848 and 150 deletions. Each recorded range is the
change the third measurement read from the branches' heads, since each merge's tree is its pull
request's head's.

## Files in docs/history

- `verify_split.py`: the verifier, revision 6, sha256
  `352ac42a85c13f6351875cbf43dd8a5798082fa2ab30e0cd97e0e9a8df465299`. Revision 6 adds one rule and
  its four controls: the `edit` row of a base path names every commit that changed the path since
  the base, which the verifier reads from the history (`LICENSE`, the owner's `b2da8432`). On a
  tip whose base paths are unchanged its output is revision 5's line for line, measured at
  `07704991`, the import's merge. Revision 5 (sha256
  `53fc3bc32c1fd879b25d19d09293d78bd26c3fef00cd86670bab74d451605bbe`) added one rule: a
  rename row whose target the tip does not hold fails, where it passed as a declaration before; a
  path renamed on import and later deleted is a `delete` row. Revision 4 (sha256
  `ed620472a7656e889f1f25b9fd50094b9282f312d433f16d87f391cf99106e7e`) verified stage 3. Stages 1 and 2 were
  verified with revision 3 (`85fcadf4916099fcf33bda29070eb970e0dd22749f588809a2cbd238e351571e`),
  whose output revision 4 reproduces line for line on those sides, plus one new control line
  per side. Revision 4 pins the sdk side and adds one rule: an imported merge may keep fewer
  parents than its source only when each dropped parent's side never held a kept path (the
  sdk's sync merge `990e84ff`, whose upstream side had no messaging file yet).
- `connect-codestyle-paths.txt`: the `--paths-from-file` input of the stage 1 filter.
- `connect-codestyle-commit-map.txt`: stage 1's old and new commit ids.
- `connect-core-paths.txt`, `connect-core-commit-map.txt`: the same for stage 2a.
- `connect-protocol-paths.txt`, `connect-protocol-commit-map.txt`: the same for stage 2b.
- `rewritepaths.go.txt`: the module-path rewrite tool, as run by the stage 2a rewrite
  commit.
- `sdk-paths.stage3.txt`, `sdk-commit-map.txt`: the same for stage 3.
- `2a-scope.md`: stage 2a's scope record.
- `3-scope.md`: stage 3's.
- `adaptations.tsv`: every path of the recorded tip that is neither imported unchanged nor an
  unchanged path of the base, with its reason and, for a new or edited file, the sha256 of
  its bytes. It declares itself as `manifest`. It is the import's record and ends at the
  recorded tip: later work adds no row.
- `verified-tips.txt`: the tips the verifier passed on the way to the recorded tip, oldest
  first. Part D holds each to being an ancestor of the tip it verifies.
- `carried.py`: what the removals deleted, as they merged, held to the tip (above).
- `ported.tsv`: every upstream change after an import's source carried here, every path upstream
  deleted, and every fork-only change, each with its commits.
- `proof.py`: the check of a tip. The recorded tip is its ancestor, and the proof passes at the
  recorded tip, by that commit's own scripts and records (above).
- `recorded-tip.txt`: the recorded tip's id, one line. The recorded tip does not hold it; the
  commit after it adds it.

## The set, as it merged

This repository arrived as one of a set of pull requests that were built and tested together.
All of them merged on 2026-10-09, each with a merge commit, so every commit kept its id:

| Repository | Pull request | Merge commit on `main` | Merged (UTC) |
|---|---|---|---|
| urnetwork/message | 1, the import | `07704991dc89ffeee35a70b4bb7372f588dc9067` | 09:07 |
| urnetwork/message-server | 3, its switch to these packages | `e9eae67a4d49f6d192bdd3ae00dca6cac75fd0e3` | 12:22 |
| urnetwork/sdk | 158, the removal of messaging | `b8209d9d7f6d858b2171cd92d4203bdadb758260` | 12:25 |
| urnetwork/connect | 219, the removal of messaging | `847460bba8aa31fb2e86ce007e9d5443d884544b` | 13:44 |

[scripts/siblings.txt](../scripts/siblings.txt) pins the last three, each a commit of its
upstream `main`. Before they merged it pinned a commit of each pull request's branch, fetched
from the fork it was pushed to. The three pins moved the same day, each in a commit of its own
(`0c086237`, `10f10172`, `7fa04709`), after the commit that switched the three URLs
(`a1326929`), and nothing is fetched from a fork any more.

## Changes in connect and the core SDK until the removals merged

An earlier version of this file said the source copies were frozen once imported. Nothing held
that, and upstream changed imported paths in 15 commits between the imports' sources and the
removals (the tables above). Those changes had to arrive here: carried.py was the check, and
ported.tsv is the record. Since the removals merged the paths exist only here, except
`CODESTYLE.md`, which connect keeps: its two copies stay the maintainers' to keep in step, and
nothing here measures connect's copy after `64e433f4`, the last commit of its `main` before the
removal.

The import merged before the two removals (`07704991`, above), so the code was in its new home
before anything was deleted. It could, because it built and tested against the commits
scripts/siblings.txt then pinned on the removals' branches, not against connect or sdk `main`.
Two things followed while the removals waited, and both have ended:

- **This repository was not built beside connect `main`.** Until `847460bb`, `main` still
  registered `message.proto`, so a binary linking both copies stopped at init, and it had no
  `connect.NewOperatorClientSettings`, which `sdk/message_tunnel.go` calls. The pins kept the
  two apart. It is built and tested beside connect `main` and sdk `main` as of those merges now,
  and connect from before the removal stays pinned as connect-golden, the reference the wire
  corpus is compared with and never a build dependency.
- **A change upstream made to a moved path arrived here as a pull request of its own**, a port
  commit with its row in ported.tsv, as the ports above did, and carried.py was run against
  this repository's `main` and the newest connect and sdk `main` before each removal merged.
  The first such pull request, on the day of the import's merge, declared what `80f6e365` and
  `69c49348` added (above); nothing in them was this package's to port. It was also the last:
  each removal merged into the same commit of its `main` that pull request was measured
  against, which is the base carried.py records.
