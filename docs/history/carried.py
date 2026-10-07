#!/usr/bin/env python3
"""carried.py: what the removal pull requests take out of connect and the core SDK is carried here.

The imports took their paths from a pinned source commit, and verify_split.py proves each import
against it. The removal pull requests delete those paths from a LATER commit, their base, and the
maintainers may change a path in between: urnetwork/connect 54b5b106, e8611390 and f5e1aa1f did,
after the import's source e449f7d8, and nothing compared the two until review. This is that
comparison, re-runnable against whatever base each removal pull request finally has, and against
the newest upstream main besides.

For each side, with S its import source, B and H the removal's base and head, U the upstream commit
the content is measured against (B, or a later upstream main given as @U), MB the merge base of S
and U, T this repository's tip, and m() the mechanical import-path rewrite of the path's import:

  1. every path D the removal deletes (B..H, status D) projects onto a path M of the tip, and T holds
     M (or the tip's manifest declares M deleted), unless ported.tsv declares D not-carried;
  2. every imported path at U (deleted by the removal, or kept in the core repository like
     CODESTYLE.md, or added by upstream under a directory an import took whole) has every change
     upstream made to it since MB IN THE TIP: a three-way merge of T:M (ours), m(MB:D) (base) and
     m(U:D) (theirs) is clean and is T:M byte for byte. One other outcome is accepted, and is
     declared (port-void, below): the merge conflicts, every conflict is a region the tip REMOVED
     (the tip's side of it is empty), and taken the tip's way it is T:M byte for byte, so upstream
     changed only lines this repository's adaptation took out and every other change is in the tip;
  3. upstream's changes are declared: when m(U:D) differs from m(MB:D), ported.tsv has a row for D
     naming exactly the upstream commits that changed it (MB..U), of the kind the measurement says:
       port            the tip commit that ported them, an ancestor of the tip that changes M;
       port-in-source  no tip commit: the import's source already held the change (the fork had
                       made it first), shown by the same three-way merge with m(S:D) as ours;
       port-void       no tip commit: step 2's other outcome, nothing of the change lands here;
  4. the fork's changes are declared: when m(S:D) differs from m(MB:D), the import carried changes
     upstream never had, and ported.tsv has a fork-only row naming exactly those commits (MB..S);
  5. a path the import holds that upstream deleted after MB (in MB or S, not in U) is gone from the
     tip, under its name and any name the tip's manifest renamed it to, with a port-delete row
     naming exactly the deleting commits;
  6. every ported.tsv row is needed, unless its commits are not in U at all: such a row is AHEAD of
     the upstream measured, it is printed, and it is checked the day U contains it.

UPSTREAM MOVES A PATH. urnetwork/sdk a7b5db77 moved cgo/loopback_test_world.go to
cgo/ctest/testdata/loopback_test_world.go and edited it in the same commit. Path by path that is a
deletion (step 5) and a new file, and a new file has no merge base, so the tip's copy, which carries
this repository's adaptation of the old one, could only ever conflict with it. The tip's own manifest
says which path the new one continues (its rename row, which verify_split.py holds to the import's
bytes), so step 2 measures the new path against the OLD path's blob at MB and at S, after checking
that upstream's commits which removed the old path are among those that added the new one. The
renamed name then counts as upstream's new path, not as the deleted one kept (step 5).

An imported path is one an import spec selects (docs/history/*-paths*.txt, the git-filter-repo
inputs). verify_split.py's projectors, which this imports, answer that path by path, and for one
directory line, the sdk's cgo/ctest/, they answer it with the two files the directory held at the
import's source: the same set at the source, which is what verify_split.py checks. Upstream adds
files later, under that directory too (urnetwork/sdk a7b5db77 adds cgo/ctest/loopback-overlay.json
and cgo/ctest/testdata/loopback_test_world.go), so this script also projects that line as a
directory, and holds every projection to the specs before it measures anything: each selection line
projects a path under it to where the spec's renames put it. A file upstream adds later OUTSIDE
every such directory, which the removal deletes and this repository carries, has a row in ADDED
(a7b5db77's cgo/gen/loopback_module_test.go, the harness's own test): it is no import spec's, so
it must be absent from the import's source, and upstream must hold it.

The complement is printed: what the removal's head still holds under the imported paths, and what it
changes rather than deletes. Read-only on every repository, like verify_split.py, whose projections,
mechanical rewrite and git helpers this imports.

  python3 docs/history/carried.py --dst . --dst-rev HEAD --ported docs/history/ported.tsv \\
      --removal connect=<repo>:<B>..<H>[@<U>] --removal sdk=<repo>:<B>..<H>[@<U>] [--controls]

--controls runs the same checks against the tip this branch had before the ports (f3f8f2bd, the tip
the review measured), where they must fail for exactly the paths the port and port-delete rows
in U name; then with a row of each kind dropped, which must be reported, and with a row planted,
which must be needed by nothing; then with a file planted in upstream's tree under cgo/ctest/ (in
memory), which must be reported, and again with that directory projected file by file, as
verify_split.py does, where the planted file goes unmeasured and the spec check must report the
directory. Then the three rules upstream's a7b5db77 and 06f33802 made necessary, each against the
design it replaces: a moved path measured with no lineage (an empty merge base), which must fail
for exactly that path; an ADDED row dropped, which must leave its path projected by nothing; and
the removed-region rule on inputs written here, where a line the tip kept, a line the tip changed
its own way, and a second upstream change outside the removed region must each be refused.
"""
import argparse
import difflib
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True  # no __pycache__ beside the files this repository tracks
import verify_split as vs  # noqa: E402

SIDES = {
    "connect": dict(
        source="e449f7d8126c0b5748f5083392a8855bac877b32",
        projectors=[(vs.project_connect_codestyle, None), (vs.project_connect_core, "2a"), (vs.project_connect_protocol, "2b")],
    ),
    "sdk": dict(
        source="6141b98d05bcac98d5ccae11c54c7748919017e6",
        projectors=[(vs.project_sdk, "3")],
    ),
}
# the tip the review measured, before the ports: the controls' tip
PRE_PORT_TIP = "f3f8f2bdd95cf6440935d1c29986c4510c64a534"
# the kinds that declare an upstream change to a path, by what the measurement finds (step 3)
PORT_KINDS = ("port", "port-in-source", "port-void")
KINDS = PORT_KINDS + ("port-delete", "fork-only", "not-carried")
MANIFEST = "docs/history/adaptations.tsv"
# each side's import specs, read at the tip
SPECS = {
    "connect": ["docs/history/connect-codestyle-paths.txt", "docs/history/connect-core-paths.txt",
                "docs/history/connect-protocol-paths.txt"],
    "sdk": ["docs/history/sdk-paths.stage3.txt"],
}
# the directory lines the projectors answer file by file: (directory, where it lands, stage)
DIRECTORIES = {"sdk": [("cgo/ctest/", "sdk/cgo/ctest/", "3")]}
# files upstream added after an import's source, outside every directory an import took whole, that
# the removal deletes and this repository carries: (source path, where it lands, stage). No import
# spec selects them, so each is held to being absent from the import's source and present upstream.
ADDED = {"sdk": [("cgo/gen/loopback_module_test.go", "sdk/cgo/gen/loopback_module_test.go", "3")]}
# whether a path upstream moved is measured against the path it continues (the tip's manifest says
# which); the controls turn it off to run the design it replaces
LINEAGE = True
# a name inside each regex selection line, for the spec check
REGEX_PROBES = {
    r"regex:^message[^/]*\.go$": "message_carried_probe.go",
    r"regex:^protocol/message[^/]*$": "protocol/message_carried_probe",
}
PROBE = "carried_probe"


def project_by_spec(side, path):
    """Where an import spec puts a path: the projectors, and the directory lines taken whole."""
    for projector, stage in SIDES[side]["projectors"]:
        hit = projector(path)
        if hit:
            return hit[1], stage
    for directory, to, stage in DIRECTORIES.get(side, ()):
        if path.startswith(directory):
            return to + path[len(directory):], stage
    return None, None


def project(side, path):
    hit = project_by_spec(side, path)
    if hit[0] is not None:
        return hit
    for added, to, stage in ADDED.get(side, ()):
        if path == added:
            return to, stage
    return None, None


def spec_lines(dst, tip, spec):
    """A spec's selection lines, and its renames as (old, new), in order."""
    text = vs.git(dst, "cat-file", "blob", "%s:%s" % (tip, spec)).decode("utf-8")
    selections, renames = [], []
    for line in text.splitlines():
        line = line.rstrip("\r")
        if not line.strip() or line.startswith("#"):
            continue
        if "==>" in line:
            renames.append(tuple(line.split("==>", 1)))
        else:
            selections.append(line)
    return selections, renames


def renamed(path, renames):
    """Where a spec's renames put a selected path, applied in order, as git-filter-repo does."""
    for old, new in renames:
        if old.startswith("regex:"):
            path = re.sub(old[len("regex:"):], new, path)
        elif path.startswith(old):
            path = new + path[len(old):]
    return path


def spec_problems(dst, tip):
    """The projections held to the specs, both ways: every selection line projects a path under it
    (the line itself, a probe inside a directory line, a probe matching a regex line) to where the
    spec's renames put it, and every DIRECTORIES entry is a directory line of its side's specs."""
    problems = []
    for side, specs in sorted(SPECS.items()):
        directory_lines = set()
        for spec in specs:
            selections, renames = spec_lines(dst, tip, spec)
            for line in selections:
                if line.startswith("regex:"):
                    probe = REGEX_PROBES.get(line)
                    if probe is None or not re.search(line[len("regex:"):], probe):
                        problems.append("%s: no probe in REGEX_PROBES matches %r" % (spec, line))
                        continue
                elif line.endswith("/"):
                    directory_lines.add(line)
                    probe = line + PROBE
                else:
                    probe = line
                want, got = renamed(probe, renames), project_by_spec(side, probe)[0]
                if got != want:
                    problems.append("%s: %s projects to %s, and the spec puts it at %s: what upstream changes or adds there goes unmeasured"
                                    % (spec, probe, got, want))
        for directory, _, _ in DIRECTORIES.get(side, ()):
            if directory not in directory_lines:
                problems.append("DIRECTORIES names %s for %s, which no spec of that side selects as a directory" % (directory, side))
        for added, _, _ in ADDED.get(side, ()):
            if project_by_spec(side, added)[0] is not None:
                problems.append("ADDED names %s for %s, which an import spec already selects: it is an imported path, not an addition" % (added, side))
    return problems


def read_ported(path):
    """TSV: side, kind, source path, commits (comma-separated full SHAs, or -), tip commit (or -),
    reason. '#' starts a comment."""
    rows = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 6 or not parts[5].strip():
                sys.exit("FATAL: %s line %d needs side, kind, path, commits, tip commit and a reason: %r" % (path, n, line))
            side, kind, src, commits, port, reason = parts
            if side not in SIDES or kind not in KINDS:
                sys.exit("FATAL: %s line %d: unknown side %r or kind %r" % (path, n, side, kind))
            if (side, kind, src) in rows:
                sys.exit("FATAL: %s names %s %s %s twice" % (path, side, kind, src))
            listed = [] if commits == "-" else commits.split(",")
            for c in listed + ([] if port == "-" else [port]):
                if len(c) != 40 or any(ch not in "0123456789abcdef" for ch in c):
                    sys.exit("FATAL: %s line %d: %r is not a full commit SHA" % (path, n, c))
            rows[(side, kind, src)] = dict(commits=sorted(listed), port=None if port == "-" else port, reason=reason)
    return rows


def manifest_rows(dst, tip):
    """The tip's own manifest: its renames, projected path -> tip path (a path upstream deleted must be
    gone under the name the import gave it too), and its declared deletions, projected path -> reason
    (a path this repository deliberately did not keep, verify_split.py's part E holds the reason)."""
    r = subprocess.run(["git", "--no-optional-locks", "-C", dst, "cat-file", "blob", "%s:%s" % (tip, MANIFEST)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    renames, deletes = {}, {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 3 or line.startswith("#"):
            continue
        if parts[1].startswith(("rename-to:", "rename+edit-to:")):
            renames[parts[0]] = parts[1].split(":", 1)[1]
        elif parts[1] == "delete":
            deletes[parts[0]] = parts[2]
    return renames, deletes


_logs, _trees, _blobs = {}, {}, {}


def commits_changing(repo, since, until, path):
    """The commits in since..until that change path, by git's default history simplification."""
    key = (repo, since, until, path)
    if key not in _logs:
        _logs[key] = sorted(vs.git(repo, "log", "--format=%H", "%s..%s" % (since, until), "--", path).decode().split())
    return _logs[key]


def tree_of(repo, commit):
    if (repo, commit) not in _trees:
        _trees[(repo, commit)] = vs.ls_tree(repo, commit)
    return _trees[(repo, commit)]


def prefetch(repo, commit, paths):
    """Read the blobs of paths at commit in one cat-file batch, for blob_at."""
    tree = tree_of(repo, commit)
    need = {tree[p][2] for p in paths if p in tree and tree[p][1] == "blob" and (repo, tree[p][2]) not in _blobs}
    if need:
        for oid, data in vs.blobs(repo, sorted(need)).items():
            _blobs[(repo, oid)] = data


def blob_at(repo, commit, path):
    entry = tree_of(repo, commit).get(path)
    if entry is None or entry[1] != "blob":
        return None
    if (repo, entry[2]) not in _blobs:
        prefetch(repo, commit, [path])
    return _blobs[(repo, entry[2])]


def contains(ours, base, theirs):
    """Whether ours already holds the change base->theirs: a clean three-way merge whose result is ours."""
    if theirs == ours or theirs == base:
        return True, "identical" if theirs == ours else "no upstream change"
    with tempfile.TemporaryDirectory() as tmp:
        names = []
        for name, data in (("ours", ours), ("base", base or b""), ("theirs", theirs)):
            p = os.path.join(tmp, name)
            with open(p, "wb") as f:
                f.write(data)
            names.append(p)
        r = subprocess.run(["git", "merge-file", "-p", "--quiet"] + names, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode < 0 or r.returncode > 127:
            sys.exit("FATAL: git merge-file failed: %s" % r.stderr.decode())
        if r.returncode != 0:
            return False, "%d conflict(s) applying upstream's change: the tip lacks it" % r.returncode
        if r.stdout != ours:
            return False, "upstream's change applies cleanly and changes the tip's bytes: the tip lacks it"
        return True, "upstream's change already in the tip"


# conflict markers no source line is: forty of the character, and a label of this script's own
_MARK = 40
_OURS, _BASE, _THEIRS = b"CARRIED-OURS", b"CARRIED-BASE", b"CARRIED-THEIRS"


def removed_here(ours, base, theirs):
    """Whether upstream's change base->theirs conflicts with ours ONLY where ours removed the lines.

    Two readings of one three-way merge, and both must hold:
      - taken ours' way at every conflict (git merge-file --ours) it is ours byte for byte, so
        every upstream change OUTSIDE a conflict is already in ours;
      - with diff3 markers, every conflict's ours side is empty: where upstream changed lines that
        conflict, ours holds none of them. A conflict whose ours side holds a line is ours having
        changed the same lines its own way, which is a port not made, and is refused.
    Answers (holds, why or the number of conflicts, the lines upstream holds in those regions)."""
    with tempfile.TemporaryDirectory() as tmp:
        names = []
        for name, data in (("ours", ours), ("base", base or b""), ("theirs", theirs)):
            p = os.path.join(tmp, name)
            with open(p, "wb") as f:
                f.write(data)
            names.append(p)

        def merge(*flags):
            r = subprocess.run(["git", "merge-file", "-p", "--quiet"] + list(flags) + names, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if r.returncode < 0 or r.returncode > 127:
                sys.exit("FATAL: git merge-file failed: %s" % r.stderr.decode())
            return r

        if merge("--ours").stdout != ours:
            return False, "upstream changed lines outside what the tip removed, and the tip lacks that change", []
        marked = merge("--diff3", "--marker-size=%d" % _MARK, "-L", _OURS.decode(), "-L", _BASE.decode(), "-L", _THEIRS.decode())
        if marked.returncode == 0:
            return False, "the merge is clean, so nothing here is a removed region", []
        opens, splits, middle, closes = (b"<" * _MARK + b" " + _OURS, b"|" * _MARK + b" " + _BASE, b"=" * _MARK, b">" * _MARK + b" " + _THEIRS)
        state, conflicts, upstream_lines = None, 0, []
        for line in marked.stdout.split(b"\n"):
            bare = line.rstrip(b"\r")
            if state is None:
                if bare == opens:
                    state, conflicts = "ours", conflicts + 1
            elif state == "ours":
                if bare == splits:
                    state = "base"
                else:
                    return False, "a conflict where the tip changed the same lines its own way (%r): a port that was not made" % line[:60], []
            elif state == "base":
                if bare == middle:
                    state = "theirs"
            elif state == "theirs":
                if bare == closes:
                    state = None
                else:
                    upstream_lines.append(line)
        if state is not None or conflicts != marked.returncode:
            return False, "the conflict markers do not parse (%d conflicts read, git reports %d)" % (conflicts, marked.returncode), []
        return True, conflicts, upstream_lines


def changed_lines(base, theirs):
    """The lines a change takes out and puts in, as '-...' and '+...', for the log."""
    old = (base or b"").decode("utf-8", "replace").splitlines()
    new = theirs.decode("utf-8", "replace").splitlines()
    return [line for line in difflib.unified_diff(old, new, lineterm="", n=0)
            if line[:1] in "+-" and not line.startswith(("+++", "---"))]


def changes_path(repo, commit, path):
    """Whether a commit changes a path, against any of its parents."""
    return bool(vs.git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-m", "--root", "--no-renames", commit, "--", path).strip())


def check_side(side, removal, dst, tip, rows, used, verbose=True, notes=None):
    """Every failure as (source path, message). notes, when given, is filled with what the run
    measured specially: the paths followed through an upstream move, and those found void."""
    repo, base, head, upstream = removal
    fails = []
    source = vs.rev(repo, SIDES[side]["source"])
    base, head = vs.rev(repo, base), vs.rev(repo, head)
    upstream = vs.rev(repo, upstream or base)
    mb = vs.git(repo, "merge-base", source, upstream).decode().strip()
    tip_tree = tree_of(dst, tip)
    renames, declared_deletes = manifest_rows(dst, tip)
    out = vs.git(repo, "diff", "--no-renames", "--name-status", "-z", base, head).split(b"\0")
    changes = [(out[i].decode(), out[i + 1].decode("utf-8", "surrogateescape")) for i in range(0, len(out) - 1, 2)]
    deleted = sorted(p for s, p in changes if s == "D")
    others = sorted("%s %s" % (s, p) for s, p in changes if s != "D")
    upstream_tree = tree_of(repo, upstream)
    kept = sorted(p for p in upstream_tree if project(side, p)[0] is not None and p not in set(deleted))
    tally = Counter()
    for at in (upstream, source, mb):
        prefetch(repo, at, deleted + kept)
    prefetch(dst, tip, [project(side, p)[0] for p in deleted + kept if project(side, p)[0]])
    if verbose:
        print("side %s: import source %s, removal %s..%s, upstream measured %s, merge base of source and upstream %s"
              % (side, source[:12], base[:12], head[:12], upstream[:12], mb[:12]))
        print("  the removal deletes %d imported paths and changes %d it keeps; upstream holds %d imported paths the removal keeps"
              % (len(deleted), len(others), len(kept)))

    # ADDED: no import spec selects these, so each is held to being upstream's own later addition
    for added, _, _ in ADDED.get(side, ()):
        if added in tree_of(repo, source):
            fails.append((added, "ADDED names %s, which the import's source %s holds: an import spec decides an imported path, and this is not an addition"
                                 % (added, source[:12])))
        if added not in upstream_tree:
            fails.append((added, "ADDED names %s, which upstream does not hold at %s: delete the entry" % (added, upstream[:12])))

    # what upstream's tree projects onto, and the paths upstream MOVED: its new path, to the path the
    # tip's manifest says it continues, when that path is one the merge base or the source holds
    # and upstream no longer does
    upstream_projected = {project(side, p)[0] for p in upstream_tree} - {None}
    renamed_from = {to: old for old, to in renames.items()}
    earlier = {}
    for at in (mb, source):
        for p in tree_of(repo, at):
            if p not in upstream_tree and project(side, p)[0] is not None:
                earlier[project(side, p)[0]] = p
    lineage = {}
    if LINEAGE:
        for d in deleted + kept:
            m = project(side, d)[0]
            if m in renamed_from and renamed_from[m] in earlier and d not in tree_of(repo, mb) and d not in tree_of(repo, source):
                lineage[d] = earlier[renamed_from[m]]
    for at in (source, mb):
        prefetch(repo, at, sorted(lineage.values()))
    void = []
    if notes is not None:
        notes["lineage"], notes["void"] = lineage, void

    def row(kind, path):
        key = (side, kind, path)
        if key in rows:
            used.add(key)
            return rows[key]
        return None

    def mech(stage, path, data):
        return None if data is None or stage is None else vs.mechanical_imports(stage, path, data)

    def mech_all(stage, path, data):
        return None if data is None or stage is None else vs.mechanical_all(stage, path, data)

    def plain(stage, path, data):
        return data if stage is None else mech(stage, path, data)

    for d in deleted + kept:
        where = "deleted by the removal" if d in deleted else "kept in %s" % side
        m, stage = project(side, d)
        if m is None:
            if row("not-carried", d):
                tally["not carried, declared"] += 1
            else:
                fails.append((d, "the removal deletes %s, which no import of this repository projects: carry it, or declare it not-carried" % d))
            continue
        b = blob_at(repo, upstream, d)
        if b is None:
            continue  # deleted upstream after the removal's base: step 5 reads it
        # the path whose blobs are the merge's base and the source's side: d itself, or the path
        # upstream moved to d
        origin = lineage.get(d, d)
        if origin != d:
            left, arrived = commits_changing(repo, mb, upstream, origin), commits_changing(repo, mb, upstream, d)
            if not left or not set(left) <= set(arrived):
                fails.append((d, "the tip's manifest says %s continues %s, and upstream did not move the one to the other: %s changed %s, %s changed %s"
                                 % (m, renamed_from[m], [c[:10] for c in left], origin, [c[:10] for c in arrived], d)))
                continue
            tally["following a path upstream moved"] += 1
            if verbose:
                print("  %s is measured as the continuation of %s, which upstream moved there in %s: the tip's manifest renames %s to %s"
                      % (d, origin, ", ".join(c[:10] for c in left), renamed_from[m], m))
        s, a = blob_at(repo, source, origin), blob_at(repo, mb, origin)
        mb_, ms_, ma_ = plain(stage, d, b), plain(stage, origin, s), plain(stage, origin, a)
        voided = False
        if m not in tip_tree:
            if m in declared_deletes:
                tally["deleted here, declared in the manifest"] += 1
            else:
                fails.append((d, "%s (%s): the tip holds no %s, and the tip's manifest declares no deletion of it" % (d, where, m)))
                continue
        else:
            t = blob_at(dst, tip, m)
            if t in (b, mb_, mech_all(stage, d, b)):
                tally["identical to upstream" if t == b else "the mechanical rewrite of upstream"] += 1
            else:
                # the tip holds every upstream change since the merge base: shown with the import-spec
                # rewrite of both of upstream's sides, or with every literal rewritten too, when the tip's
                # own literal rewrite sits beside an upstream change and only the second can merge it
                pairs = [(ma_, mb_)]
                if stage is not None:
                    pairs.append((mech_all(stage, origin, a), mech_all(stage, d, b)))
                ok, how = contains(t, *pairs[0])
                if not ok and len(pairs) > 1:
                    ok, how_all = contains(t, *pairs[1])
                    if ok:
                        how = how_all + " (with the literal rewrite applied to upstream's two sides)"
                if ok:
                    tally["adapted here, holding every upstream change"] += 1
                else:
                    # step 2's other outcome: every conflict is a region the tip removed
                    why = None
                    for base_, theirs_ in pairs:
                        voided, detail, there = removed_here(t, base_, theirs_)
                        if voided:
                            break
                        why = why or detail
                    if not voided:
                        fails.append((d, "%s -> %s (%s): %s since %s; and it is not confined to lines the tip removed: %s"
                                         % (d, m, where, how, mb[:12], why)))
                        continue
                    void.append(d)
                    tally["adapted here, upstream's change inside what the tip removed"] += 1
                    if verbose:
                        took = changed_lines(ma_, mb_)
                        print("  %s: upstream's change conflicts in %d region(s), each one the tip removed whole (upstream holds %d line(s) there), and every other upstream change is in the tip. NOT CARRIED, %d changed line(s):"
                              % (d, detail, len(there), len(took)))
                        for line in took[:12]:
                            print("      %s" % line)
        if mb_ != ma_:
            changed = commits_changing(repo, mb, upstream, d)
            in_source = ms_ is not None and ms_ != ma_ and contains(ms_, ma_, mb_)[0]
            kind = "port-void" if voided else "port-in-source" if in_source else "port"
            says = {"port": "", "port-void": ": it changed only lines the tip removed",
                    "port-in-source": ": the import's source already held the change"}[kind]
            r = row(kind, d)
            if not r:
                fails.append((d, "upstream changed %s after %s (%s)%s, and ported.tsv has no %s row for it"
                                 % (d, mb[:12], ", ".join(c[:10] for c in changed), says, kind)))
            elif r["commits"] != changed:
                fails.append((d, "the %s row for %s names %s; upstream's commits are %s"
                                 % (kind, d, [c[:10] for c in r["commits"]], [c[:10] for c in changed])))
            elif kind != "port":
                if r["port"]:
                    fails.append((d, "the %s row for %s names a tip commit, and no commit of this repository carried anything: write -" % (kind, d)))
                else:
                    tally["of them %s, declared" % ("void" if voided else "already in the import's source")] += 1
            elif not r["port"] or not vs.is_ancestor(dst, r["port"], tip):
                fails.append((d, "the port row for %s names a tip commit that is not an ancestor of the tip" % d))
            elif m in tip_tree and not changes_path(dst, r["port"], m):
                fails.append((d, "the port row for %s names the tip commit %s, which does not change %s" % (d, r["port"][:10], m)))
            else:
                tally["of them ported, declared"] += 1
        if ms_ != ma_:
            fork = commits_changing(repo, mb, source, origin)
            r = row("fork-only", d)
            if not r:
                fails.append((d, "the import's source changed %s after %s (%s), which upstream never had, and ported.tsv has no fork-only row for it"
                                 % (d, mb[:12], ", ".join(c[:10] for c in fork))))
            elif r["commits"] != fork:
                fails.append((d, "the fork-only row for %s names %s; the fork's commits are %s"
                                 % (d, [c[:10] for c in r["commits"]], [c[:10] for c in fork])))
            else:
                tally["of them fork-only, declared"] += 1
    # the import's paths that upstream deleted after the merge base
    gone = set()
    for at in (mb, source):
        for p in tree_of(repo, at):
            if project(side, p)[0] is not None and p not in upstream_tree:
                gone.add(p)
    for p in sorted(gone):
        m, _ = project(side, p)
        changed = commits_changing(repo, mb, upstream, p)
        if not changed:
            if verbose:
                print("  %s is in the import's source and was never in upstream since %s; reported, not a port" % (p, mb[:12]))
            continue
        r = row("port-delete", p)
        if not r:
            fails.append((p, "upstream deleted %s after %s (%s) and ported.tsv has no port-delete row"
                             % (p, mb[:12], ", ".join(c[:10] for c in changed))))
            continue
        # still held: under its own name, or under the name the tip's manifest renamed it to, unless
        # that name is where upstream itself moved the path (then it is upstream's new path, which
        # the loop above measured)
        held = [x for x in (m, renames.get(m)) if x and x in tip_tree and x not in upstream_projected]
        if r["commits"] != changed:
            fails.append((p, "the port-delete row for %s names %s; upstream's commits are %s"
                             % (p, [c[:10] for c in r["commits"]], [c[:10] for c in changed])))
        elif held:
            fails.append((p, "upstream deleted %s and the tip still holds %s" % (p, ", ".join(held))))
        elif not r["port"] or not vs.is_ancestor(dst, r["port"], tip):
            fails.append((p, "the port-delete row for %s names a tip commit that is not an ancestor of the tip" % p))
        else:
            tally["deleted upstream, and here"] += 1
    if verbose:
        print("  carried: %s" % dict(sorted(tally.items())))
        print("  COMPLEMENT: under the imported paths the removal's head still holds %d: %s"
              % (len([p for p in tree_of(repo, head) if project(side, p)[0] is not None]),
                 sorted(p for p in tree_of(repo, head) if project(side, p)[0] is not None)))
        print("  COMPLEMENT: the removal changes, and does not delete, %d: %s" % (len(others), others))
    return fails


def unneeded(rows, used, removals):
    """Rows nothing needed: a failure when their commits are in the upstream measured, and printed as
    ahead of it otherwise (fork-only and not-carried rows are always failures)."""
    fails, ahead = [], []
    for key in sorted(set(rows) - used):
        side, kind, path = key
        repo, base, _, upstream = removals[side]
        measured = vs.rev(repo, upstream or base)
        commits = rows[key]["commits"]
        if kind in PORT_KINDS + ("port-delete",) and commits and not all(vs.is_ancestor(repo, c, measured) for c in commits):
            ahead.append("%s %s %s (%s not in %s)" % (side, kind, path, ", ".join(c[:10] for c in commits), measured[:12]))
            continue
        fails.append("ported.tsv: the %s row for %s %s is needed by nothing: delete it" % (kind, side, path))
    return fails, ahead


def planted_upstream_file(side, removal, dst, tip, rows, directory):
    """check_side with one file planted in upstream's tree under directory, in memory (the cached
    tree and blob, restored after): the failures that name the planted file."""
    repo, base, _, upstream = removal
    at = vs.rev(repo, upstream or base)
    path, oid = directory + PROBE, "0" * 40
    saved = tree_of(repo, at)
    planted = dict(saved)
    planted[path] = ("100644", "blob", oid)
    _trees[(repo, at)] = planted
    _blobs[(repo, oid)] = b"planted by carried.py's control\n"
    try:
        got = check_side(side, removal, dst, tip, rows, set(), verbose=False)
    finally:
        _trees[(repo, at)] = saved
        del _blobs[(repo, oid)]
    return [msg for p, msg in got if p == path]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dst-rev", required=True)
    ap.add_argument("--removal", action="append", default=[], help="side=<repo>:<base>..<head>[@<upstream>]")
    ap.add_argument("--ported", required=True)
    ap.add_argument("--controls", action="store_true")
    a = ap.parse_args()
    rows = read_ported(a.ported)
    tip = vs.rev(a.dst, a.dst_rev)
    removals = {}
    for spec in a.removal:
        side, _, rest = spec.partition("=")
        rest, _, upstream = rest.partition("@")
        repo, _, span = rest.rpartition(":")
        base, _, head = span.partition("..")
        if side not in SIDES or not repo or not base or not head:
            sys.exit("FATAL: --removal %r must be side=<repo>:<base>..<head>[@<upstream>]" % spec)
        removals[side] = (repo, base, head, upstream or None)
    if set(removals) != set(SIDES):
        sys.exit("FATAL: --removal must name every side: %s" % sorted(SIDES))
    print("tip %s" % tip)
    failures = ["spec: %s" % p for p in spec_problems(a.dst, tip)]
    print("the projections against the import specs: %s" % ("%d problem(s)" % len(failures) if failures else "every selection line projects where its spec puts it"))
    used = set()
    for side in sorted(removals):
        failures += ["%s: %s" % (side, msg) for _, msg in check_side(side, removals[side], a.dst, tip, rows, used)]
    stale, ahead = unneeded(rows, used, removals)
    failures += stale
    for line in ahead:
        print("  AHEAD of the upstream measured, not checked by this run: %s" % line)
    if a.controls:
        print()
        print("controls:")
        pre = vs.rev(a.dst, PRE_PORT_TIP)
        for side in sorted(removals):
            got = {p for p, _ in check_side(side, removals[side], a.dst, pre, rows, set(), verbose=False)}
            measured_used = set()
            check_side(side, removals[side], a.dst, tip, rows, measured_used, verbose=False)
            want = {k[2] for k in measured_used if k[1] in ("port", "port-delete")}
            ok = got == want
            print("  control: %s against %s, the tip before the ports -> fails for %d path(s), the measured port rows' %d%s"
                  % (side, pre[:12], len(got), len(want), "" if ok else "  <-- BROKEN: %s" % sorted(got ^ want)))
            if not ok:
                failures.append("control: %s against the pre-port tip failed for %s, want exactly the ported paths %s" % (side, sorted(got), sorted(want)))
        for kind in PORT_KINDS + ("port-delete", "fork-only"):
            keys = sorted(k for k in used if k[1] == kind)
            if not keys:
                continue
            key = keys[0]
            dropped = {k: v for k, v in rows.items() if k != key}
            got = check_side(key[0], removals[key[0]], a.dst, tip, dropped, set(), verbose=False)
            ok = any(p == key[2] and ("no %s row" % kind) in msg for p, msg in got)
            print("  control: the %s row for %s dropped -> %s" % (kind, key[2], "reported" if ok else "MISSED"))
            if not ok:
                failures.append("control: dropping the %s row for %s went unreported" % (kind, key[2]))
        planted = dict(rows)
        plant = ("connect", "port", "message/record.go")
        planted[plant] = dict(commits=[], port=None, reason="planted: upstream did not change it")
        plant_used = set()
        for side in sorted(removals):
            check_side(side, removals[side], a.dst, tip, planted, plant_used, verbose=False)
        plant_stale, _ = unneeded({plant: planted[plant]}, plant_used & {plant}, removals)
        ok = bool(plant_stale)
        print("  control: a port row planted for message/record.go, which upstream did not change -> %s"
              % ("needed by nothing, reported" if ok else "MISSED"))
        if not ok:
            failures.append("control: the planted port row was not reported")
        for side in sorted(DIRECTORIES):
            for directory, _, _ in list(DIRECTORIES[side]):
                found = planted_upstream_file(side, removals[side], a.dst, tip, rows, directory)
                print("  control: a file planted under %s in upstream's tree -> %s"
                      % (directory, "reported: %s" % found[0] if found else "MISSED"))
                if not found:
                    failures.append("control: a file planted under %s upstream went unreported" % directory)
                # the rejected design: the directory projected only through the files it held at the source
                saved = DIRECTORIES[side]
                DIRECTORIES[side] = [d for d in saved if d[0] != directory]
                try:
                    missed = planted_upstream_file(side, removals[side], a.dst, tip, rows, directory)
                    spec = [p for p in spec_problems(a.dst, tip) if directory + PROBE in p]
                finally:
                    DIRECTORIES[side] = saved
                ok = not missed and len(spec) == 1
                print("  control: %s projected file by file, as verify_split.py does -> the planted file %s, and the spec check %s"
                      % (directory, "goes unmeasured" if not missed else "IS STILL MEASURED",
                         "reports it: %s" % spec[0] if len(spec) == 1 else "MISSED IT (%d lines)" % len(spec)))
                if not ok:
                    failures.append("control: with %s projected file by file, the spec check did not report it alone" % directory)
        # a path upstream moved, measured the way this replaced: no lineage, so an empty merge base
        global LINEAGE
        for side in sorted(removals):
            notes = {}
            check_side(side, removals[side], a.dst, tip, rows, set(), verbose=False, notes=notes)
            if not notes["lineage"]:
                continue
            LINEAGE = False
            try:
                got = {p: msg for p, msg in check_side(side, removals[side], a.dst, tip, rows, set(), verbose=False)}
            finally:
                LINEAGE = True
            ok = set(got) == set(notes["lineage"]) and all("conflict" in msg for msg in got.values())
            print("  control: %s with no lineage, a moved path measured against an empty merge base -> fails for %s%s"
                  % (side, sorted(got), ", exactly the moved path(s), by a conflict" if ok else "  <-- BROKEN, want %s" % sorted(notes["lineage"])))
            if not ok:
                failures.append("control: with no lineage %s failed for %s, want exactly the moved paths %s" % (side, sorted(got), sorted(notes["lineage"])))
        # an ADDED row dropped: nothing projects its path
        for side in sorted(ADDED):
            for entry in list(ADDED[side]):
                saved = ADDED[side]
                ADDED[side] = [e for e in saved if e != entry]
                try:
                    got = check_side(side, removals[side], a.dst, tip, rows, set(), verbose=False)
                finally:
                    ADDED[side] = saved
                ok = any(p == entry[0] and "which no import of this repository projects" in msg for p, msg in got)
                print("  control: the ADDED row for %s dropped -> %s" % (entry[0], "its path is projected by nothing, reported" if ok else "MISSED"))
                if not ok:
                    failures.append("control: dropping the ADDED row for %s went unreported" % entry[0])
        # the removed-region rule, on inputs written here, each refused or accepted for its own reason
        four, changed = b"a\nb\nc\nd\n", b"a\nB\nc\nd\n"
        for name, ours, base_, theirs_, want in (
            ("the tip removed the lines upstream changed", b"a\nd\n", four, changed, None),
            ("the tip removed only the line upstream changed", b"a\nc\nd\n", four, changed, None),
            ("the tip kept the line upstream changed", four, four, changed, "the tip lacks that change"),
            ("the tip changed that line its own way", b"a\nx\nc\nd\n", four, changed, "a port that was not made"),
            ("upstream also changed a line the tip kept", b"a\nd\ne\n", b"a\nb\nc\nd\ne\n", b"a\nB\nc\nd\nE\n", "the tip lacks that change"),
            ("upstream changed nothing the tip lacks", changed, four, changed, "the merge is clean"),
        ):
            holds, detail, _ = removed_here(ours, base_, theirs_)
            ok = holds if want is None else (not holds and want in str(detail))
            print("  control: the removed-region rule, %s -> %s%s"
                  % (name, "accepted" if holds else "refused: %s" % detail, "" if ok else "  <-- BROKEN"))
            if not ok:
                failures.append("control: the removed-region rule, %s: got %s %s" % (name, holds, detail))
    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures[:200]:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
