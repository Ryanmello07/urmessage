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

## Imports

| Stage | Imported | Source | Filtered tip | Commits | Paths | Import merge |
|---|---|---|---|---|---|---|
| 1 | `CODESTYLE.md` | connect `e449f7d8` | `d3b3b26a` | 24 | 1 | `e52b05a1` |
| 2a | `message/`, `messagegroup/`, `mls/`, `mls/syntax/` as `syntax/`, `.gitattributes`, the codec's workflow | connect `e449f7d8` | `fbbc842d` | 465 | 837 | `a456b1cd` |
| 2b | `protocol/message*` | connect `e449f7d8` | `28a9c4f1` | 10 | 8 | `0ebd54f6` |
| 3 | the core SDK's root `message*.go`, `urmessage/`, `cp3b/`, `livepeer/`, `liveprobe/` and its 11 messaging cgo files, under `sdk/` | sdk `6141b98d` | `e5223830` | 123 | 148 | `0417c59a` |

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
requests delete the same paths from later upstream commits. Two kinds of difference sit between
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
| sdk `a7b5db77` Product Builder, 2026-10-06, "Isolate C ABI loopback dependencies from release modules" | the loopback harness, moved to `sdk/cgo/ctest/testdata/`; `sdk/cgo/ctest/loopback-overlay.json`, which lays it back into the package for the test library; `sdk/cgo/ctest/run.sh`; `sdk/cgo/gen/loopback_module_test.go` | `966b77f2` |

The merge of connect#216 (`94453d74`) changed no imported path beyond what `e8611390` then
removed: the codec workflow's trigger and its needle. The merge `89f66cda` brought `f5e1aa1f`
and `03d82b4e` together in connect, and changes `CODESTYLE.md` against each of its parents.

Two upstream changes needed no commit here, and ported.tsv says why each one stands:

| Upstream commit | Path there | Why nothing was carried |
|---|---|---|
| sdk `a7b5db77` | `cgo/loopback.go.mod`, `cgo/loopback.go.sum`: three indirect requirements | The import already held them, from the fork's `2dc9bf77` (`port-in-source`). |
| sdk `06f33802` Product Builder, 2026-10-06, "Generate runtime license JSON to avoid linking the YAML parser" | `message_stream_adapter_test.go`: one row of the value census renamed, `licenseYml` to `licenseJSON` | The row names a core SDK value. The census here holds this package's values alone ([3-scope.md](history/3-scope.md)), so the row is among the lines this repository removed (`port-void`). |

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
sdk `main`'s byte for byte. The message pull request names it at its top. An earlier version of
this file listed OPPORTUNISTIC beside it; that change is upstream's too.

**The proof.** [carried.py](history/carried.py) reads each removal pull request's deletions,
from its base, and holds this tip to them: every deleted path is here (or declared deleted in
the manifest), the tip contains every upstream change to it since the merge base of the
import's source and the removal's base (a three-way merge that changes nothing), and every
upstream change and fork-only change is declared in ported.tsv, both ways. Its control is the
tip the review measured, `f3f8f2bd`, before the ports, where it fails for exactly the ported
paths. An imported path is one the import specs (the `*-paths*.txt` files) select, and a
file upstream adds later under a directory an import took whole is one too: carried.py holds its
projections to the specs, so a directory that verify_split.py projects through the files it held
at the source (the sdk's `cgo/ctest/`) still has what upstream adds there measured.

Three more rules came with `a7b5db77` and `06f33802`, each with a control against the design it
replaces:

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

The kind of a row is what carried.py measures, not what the row says: an upstream change the
import's source already held is `port-in-source` and names no commit here, and a `port` row must
name a commit of this repository that changes the path.

## Re-running the verifier

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
  [adaptations.tsv](history/adaptations.tsv), and every declaration is needed.

It reads repositories only, and never checks out a file. From the root of a
checkout:

    git init --bare ../connect-src.git
    git -C ../connect-src.git fetch https://github.com/Ryanmello07/connect.git e449f7d8126c0b5748f5083392a8855bac877b32:refs/heads/main
    git -C ../connect-src.git fetch https://github.com/urnetwork/connect.git 7ca8e222e3496552146f2d97eb09237401662c99:refs/remotes/upstream/control
    git init --bare ../sdk-src.git
    git -C ../sdk-src.git fetch https://github.com/Ryanmello07/urnetwork-sdk.git 6141b98d05bcac98d5ccae11c54c7748919017e6:refs/heads/main
    python3 docs/history/verify_split.py --sides connect-codestyle,connect-core,connect-protocol,sdk --connect ../connect-src.git --sdk ../sdk-src.git --dst . --dst-rev HEAD --controls --expect-filtered-tips --commit-map connect-codestyle=docs/history/connect-codestyle-commit-map.txt --commit-map connect-core=docs/history/connect-core-commit-map.txt --commit-map connect-protocol=docs/history/connect-protocol-commit-map.txt --commit-map sdk=docs/history/sdk-commit-map.txt --manifest docs/history/adaptations.tsv

It must end with `PASS`. `--controls` also runs negative controls that must fire:
the source file one change earlier, and synthetic changes to the expected tree.
`7ca8e222`, an earlier `urnetwork/connect` `main`, is the control for the stage 2a
import; the sdk side's control is `d20d82c1`, the fork's `beta/message` before its sync, which
the fetch of `6141b98d` brings with its history.

The removals' deletions, against each removal pull request's base and head. Fetch those into
the same two repositories first. A removal's base is the upstream `main` commit its branch last
merged, which is the merge base of its head and `main`. Its head is the commit
[scripts/siblings.txt](../scripts/siblings.txt) pins for that sibling, fetched from the URL
given there: the owner's fork until the pull request has merged, the urnetwork repository after.

    git -C ../connect-src.git fetch https://github.com/urnetwork/connect.git main:refs/remotes/upstream/main
    git -C ../connect-src.git fetch <connect's URL in scripts/siblings.txt> <connect's pin>:refs/remotes/removal/head
    git -C ../sdk-src.git fetch https://github.com/urnetwork/sdk.git main:refs/remotes/upstream/main
    git -C ../sdk-src.git fetch <sdk's URL in scripts/siblings.txt> <sdk's pin>:refs/remotes/removal/head
    python3 docs/history/carried.py --dst . --dst-rev HEAD --ported docs/history/ported.tsv --controls \
        --removal connect=../connect-src.git:$(git -C ../connect-src.git merge-base removal/head upstream/main)..removal/head@upstream/main \
        --removal sdk=../sdk-src.git:$(git -C ../sdk-src.git merge-base removal/head upstream/main)..removal/head@upstream/main

It must end with `PASS`. The suffix `@<commit>` on a removal measures the content against that
upstream commit instead of the removal's base, the newest `main` here, so a change upstream made
after the removal's base is caught before the removal merges it; a ported.tsv row whose commits
that upstream does not yet hold is printed as ahead of it. Measured on 2026-10-06 at `a8c84e3c`,
with the controls: connect `6df2fa87..0f2ff669` (848 deletions) against `main` at `6edbaa6f`, and
sdk `06f33802..0f03e27e` (150 deletions) against `main` at `06f33802`, both `PASS`. connect's
`main` takes an automated data commit about every 45 minutes, so the commit named here is soon
not the newest; the command above measures whichever is.

## Files in docs/history

- `verify_split.py`: the verifier, revision 5, sha256
  `53fc3bc32c1fd879b25d19d09293d78bd26c3fef00cd86670bab74d451605bbe`. Revision 5 adds one rule: a
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
- `adaptations.tsv`: every path of the tip that is neither imported unchanged nor
  part of the base, with its reason and, for a new or edited file, the sha256 of its
  bytes. It declares itself as `manifest`.
- `verified-tips.txt`: every tip the verifier passed, oldest first.
- `carried.py`: the removals' deletions held to this tip (above).
- `ported.tsv`: every upstream change after an import's source carried here, every path upstream
  deleted, and every fork-only change, each with its commits.

## Changes in connect and the core SDK until the removals merge

An earlier version of this file said the source copies were frozen once imported. Nothing held
that, and upstream has changed imported paths in nine commits since the imports' sources (the
tables above). The
copies change until the removal pull requests merge, and changes made there have to arrive here:
carried.py is the check, and ported.tsv the record. After the removals merge, the paths exist
only here, except `CODESTYLE.md`, which connect keeps: its two copies stay the maintainers' to
keep in step.
