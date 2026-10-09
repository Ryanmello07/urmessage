# Releasing

## Tags

- A release is an annotated tag on `main` of `urnetwork/message`, made by a
  maintainer (`git tag -a`). A lightweight tag is not a release.
- No tag before the schema cutover. From stage 2b until the cutover,
  `message/protocol` cannot be linked beside connect's copy of the schema (see
  [BOUNDARY.md](BOUNDARY.md)), so a release would publish a package that panics
  next to connect. The first tag is `v0.1.0`, after the cutover.
- A nested module is tagged with its directory as prefix, as Go requires:
  `sdk/v0.1.0` releases `github.com/urnetwork/message/sdk`.
- Forks never tag. test.sh never tags, releases or publishes.
- Until the first tag, consumers pin a commit: a pseudo-version, or a `replace` to
  a checkout at a pinned commit.

## Merging

Pull requests are merged with **Create a merge commit** only. A squash or rebase
merge rewrites the branch's commits, and an import's commits must stay the ones
its commit map names. Branches under review are never force-pushed; they are
updated by adding commits or by merging `main` into them.

## Recovering from a squash or rebase merge, without force

If an import pull request is merged by squash or rebase, `main` holds its files
but not its history. The import merge and its source commits are not ancestors of
`main`, and the next import refuses to build ("the earlier import ... is not in
main"). Do not rewrite `main`. Restore the history with one more merge:

1. Check that the bad merge changed nothing but history. This must print nothing,
   which holds when `main` had not moved while the pull request was open:

       git diff <bad-merge> <original-branch-tip>

   If it prints anything, stop and ask a maintainer.
2. On a new branch from `main`, merge the original branch tip with the `ours`
   strategy:

       git switch -c recover/<branch> origin/main
       git merge -s ours --no-ff <original-branch-tip>

   `-s ours` keeps `main`'s tree and records the original tip as a second parent,
   so the import merge and its source history become ancestors of `main` again.
3. Open a pull request from that branch and merge it with **Create a merge commit**.
4. Run `docs/history/verify_split.py` on the result (see [HISTORY.md](HISTORY.md)).
   Its import discovery finds the original import merge through the second parent.

A rebase merge also leaves rewritten copies of the commits on `main`. They stay:
removing them would need a force push.
