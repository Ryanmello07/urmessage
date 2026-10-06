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

Stage 3 (the messaging SDK) adds its row.

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
  `9b5772b7...`); this package emits the same bytes, CI re-emits it from a pinned connect from
  before the move, and `protocol/message_wiregolden_test.go` holds it append-only.
- Scope: `TestNothingHereComputesTheAttestationPreimage` walks the repository root. In
  connect it read 1,587 Go files and here 253, and it finds every label in the same files in
  both (`message/writeauth.go`, `message/attachment.go` and their tests,
  `messagegroup/keysource_test.go`, `protocol/message_op_test.go`; the attestation label in
  none). Connect's remaining files hold none of them; the connect removal PR deletes the test
  there with the code it was about.

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
    python3 docs/history/verify_split.py --sides connect-codestyle,connect-core,connect-protocol --connect ../connect-src.git --dst . --dst-rev HEAD --controls --expect-filtered-tips --commit-map connect-codestyle=docs/history/connect-codestyle-commit-map.txt --commit-map connect-core=docs/history/connect-core-commit-map.txt --commit-map connect-protocol=docs/history/connect-protocol-commit-map.txt --manifest docs/history/adaptations.tsv

It must end with `PASS`. `--controls` also runs negative controls that must fire:
the source file one change earlier, and synthetic changes to the expected tree.
`7ca8e222`, an earlier `urnetwork/connect` `main`, is the control for the stage 2a
import; later stages add their sides to `--sides`.

## Files in docs/history

- `verify_split.py`: the verifier, sha256
  `85fcadf4916099fcf33bda29070eb970e0dd22749f588809a2cbd238e351571e`.
- `connect-codestyle-paths.txt`: the `--paths-from-file` input of the stage 1 filter.
- `connect-codestyle-commit-map.txt`: stage 1's old and new commit ids.
- `connect-core-paths.txt`, `connect-core-commit-map.txt`: the same for stage 2a.
- `connect-protocol-paths.txt`, `connect-protocol-commit-map.txt`: the same for stage 2b.
- `rewritepaths.go.txt`: the module-path rewrite tool, as run by the stage 2a rewrite
  commit.
- `2a-scope.md`: stage 2a's scope record.
- `adaptations.tsv`: every path of the tip that is neither imported unchanged nor
  part of the base, with its reason and, for a new or edited file, the sha256 of its
  bytes. It declares itself as `manifest`.
- `verified-tips.txt`: every tip the verifier passed, oldest first.

## Source copies are frozen

Once a path is imported here, its copy in connect or the core SDK is frozen: it
changes only in the pull request that removes it. Changes go to this repository.
