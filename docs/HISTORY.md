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

Later stages add their rows: 2a (`message/`, `messagegroup/`, `mls/`, `syntax/`),
2b (`protocol/message*`) and 3 (the messaging SDK).

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
    python3 docs/history/verify_split.py --sides connect-codestyle --connect ../connect-src.git --dst . --dst-rev HEAD --controls --expect-filtered-tips --commit-map connect-codestyle=docs/history/connect-codestyle-commit-map.txt --manifest docs/history/adaptations.tsv

It must end with `PASS`. `--controls` also runs negative controls that must fire:
the source file one change earlier, and synthetic changes to the expected tree.
`7ca8e222`, an earlier `urnetwork/connect` `main`, is the control for the stage 2a
import; later stages add their sides to `--sides`.

## Files in docs/history

- `verify_split.py`: the verifier, sha256
  `85fcadf4916099fcf33bda29070eb970e0dd22749f588809a2cbd238e351571e`.
- `connect-codestyle-paths.txt`: the `--paths-from-file` input of the stage 1 filter.
- `connect-codestyle-commit-map.txt`: stage 1's old and new commit ids.
- `adaptations.tsv`: every path of the tip that is neither imported unchanged nor
  part of the base, with its reason and, for a new or edited file, the sha256 of its
  bytes. It declares itself as `manifest`.
- `verified-tips.txt`: every tip the verifier passed, oldest first.

## Source copies are frozen

Once a path is imported here, its copy in connect or the core SDK is frozen: it
changes only in the pull request that removes it. Changes go to this repository.
