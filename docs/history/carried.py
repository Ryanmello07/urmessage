#!/usr/bin/env python3
"""carried.py: what the removal pull requests take out of connect and the core SDK is carried here.

The imports took their paths from a pinned source commit, and verify_split.py proves each import
against it. The removal pull requests delete those paths from a LATER commit, their base, and the
maintainers may change a path in between: urnetwork/connect 54b5b106, e8611390 and f5e1aa1f did,
after the import's source e449f7d8, and nothing compared the two until review. This is that
comparison.

BOTH REMOVALS HAVE MERGED (2026-10-09), AND THEIR RANGES ARE RECORDED HERE. While they were under
review this script took each removal's base and head on the command line, and the documented
command computed the base as the merge base of the removal's head and upstream main, so that what
upstream changed meanwhile was measured too. Once a removal has merged, that merge base is the
head itself: the range is empty, and upstream main holds no moved path to measure. The command
went red on this repository's own main the hour urnetwork/sdk merged its removal. Nothing upstream
can change a moved path any more, so the ranges are final, and SIDES records them beside each
import's source: the merge of the removal's pull request on its upstream main, and that merge's
first parent, the last commit of main that holds the moved paths. The content is measured at that
first parent. No branch is read, so the answer for a tip is the same on any day.

For each side, with S its import source, B and H the removal's recorded base and merge, U = B the
upstream commit the content is measured against, MB the merge base of S and U, T the tip measured,
and m() the mechanical import-path rewrite of the path's import:

  1. every path D the removal deletes (B..H, status D) projects onto a path M of the tip, and T holds
     M (or the tip's manifest declares M deleted), unless ported.tsv declares D not-carried;
  2. every imported path at U (deleted by the removal, or kept in the core repository like
     CODESTYLE.md, or added by upstream under a directory an import took whole) has every change
     upstream made to it since MB IN THE TIP: a three-way merge of T:M (ours), m(MB:D) (base) and
     m(U:D) (theirs) is clean and is T:M byte for byte. One other outcome is accepted, and is
     declared (port-void, below): the merge conflicts, every conflict is a region the tip REMOVED
     (the tip's side of it is empty), and taken the tip's way it is T:M byte for byte, so upstream
     changed only lines this repository's adaptation took out and every other change is in the tip.
     Before either merge, the lines upstream ADDED whose subject is a value of the core are set
     aside (CORE_SUBJECT, below): they are measured by what they name, not by where they merge;
  3. upstream's changes are declared: when m(U:D) differs from m(MB:D), ported.tsv has a row for D
     naming exactly the upstream commits that changed it (MB..U), of the kind the measurement says:
       port            the tip commit that ported them, an ancestor of the tip that changes M;
       port-in-source  no tip commit: the import's source already held the change (the fork had
                       made it first), shown by the same three-way merge with m(S:D) as ours;
       port-void       no tip commit: nothing of the change lands here. Every part of it is one
                       of step 2's two exceptions: lines the tip removed, or lines set aside
                       because their subject is the core's;
  4. the fork's changes are declared: when m(S:D) differs from m(MB:D), the import carried changes
     upstream never had, and ported.tsv has a fork-only row naming exactly those commits (MB..S);
  5. a path the import holds that upstream deleted after MB (in MB or S, not in U) is gone from the
     tip, under its name and any name the tip's manifest renamed it to, with a port-delete row
     naming exactly the deleting commits;
  6. every ported.tsv row is needed. While the ranges moved, a row whose commits the upstream
     measured did not hold yet was printed as AHEAD of it and checked on a later day; with the
     ranges recorded there is no later day, and such a row is needed by nothing, like any other.

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

UPSTREAM ADDS LINES ABOUT A VALUE OF THE CORE. In urnetwork/sdk the messaging SDK shared package
sdk with the VPN SDK, so a moved file could name any core value, and the value census in
message_stream_adapter_test.go held the values of both. Here that census holds this package's
values alone (docs/history/3-scope.md), and upstream goes on adding core values to its copy:
urnetwork/sdk ae5a65fc adds a census row for the core constant mobileMemoryTeardownLifetime, and
a test, TestStreamAdapterTeardownConstantsHaveCompleteCensus, of that constant and of
mobileMemoryTeardownCapacity. Neither can be carried as written: this repository declares neither
constant, and the core keeps both. And the removed-region rule alone refuses the change: the row
falls among lines the tip removed, but the test is appended to the file, where the tip removed
nothing. CORE_SUBJECT names such values, path by path. A block of lines upstream ADDED is set
aside when a line of it names one of them (the row and the test both), and every name is held
both ways: no Go file of the tip names it, a Go file upstream keeps (one the removal does not
delete and no import takes) does, and a line set aside names it. The lines set aside are pinned
by their sha256 and printed, so a line upstream adds beside them later is not set aside with
them. A line upstream CHANGED is never set aside, whatever it names: the tip holds the line it
replaces, or removed it, and the merge says which. urnetwork/sdk 80f6e365 and 69c49348 then added
nine more lines for eight more core values, three of the API client's and five of its credential
renewer's. All nine fall among lines the tip removed, so the removed-region rule would have passed
them by where they merge. They are named in CORE_SUBJECT all the same: a line is declared by what
it names, held both ways, wherever it lands.

The complement is printed: what the removal's head still holds under the imported paths, and what it
changes rather than deletes. Read-only on every repository, like verify_split.py, whose projections,
mechanical rewrite and git helpers this imports.

  python3 docs/history/carried.py --dst . --dst-rev <tip> --ported <that tip's ported.tsv> \\
      --connect <repo> --sdk <repo> [--controls]

Each <repo> holds its side's import source and its recorded removal; docs/HISTORY.md has the
fetches. The tip to measure is the recorded tip, and docs/history/proof.py runs this there, with
that tip's own copy of this script and of ported.tsv: a later tip is not held to these records.

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
its own way, and a second upstream change outside the removed region must each be refused. Then
the rule urnetwork/sdk ae5a65fc made necessary: a CORE_SUBJECT entry dropped, which must fail for
exactly its path, by a change outside what the tip removed; a name the tip itself spells, a name
only the moved files spell, and a name no added line spells, each refused for its own reason; a
line planted in upstream's file beside the lines set aside, which the digest must refuse, and
which rides along unmeasured with the digest unchecked (the design it replaces); and the
set-aside on inputs written here, where an added block that names no core value and a CHANGED
line that names one must each stay in the merge. Then the recorded ranges: each side measured the
way this replaces, its base the merge base of the removal's head and a main that has merged it,
which is an empty range and must fail; a recorded base that is not its merge's first parent, which
must be refused; and a row whose commits the upstream measured does not hold, which must be
needed by nothing where it was once printed as ahead.
"""
import argparse
import difflib
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True  # no __pycache__ beside the files this repository tracks
import verify_split as vs  # noqa: E402

# Each side's import source, and ITS REMOVAL AS IT MERGED: (base, merge). The merge is the merge
# commit of the removal's pull request on the side's upstream main; the base is that merge's first
# parent, the last commit of main that holds the moved paths, and the content is measured there.
#   connect  urnetwork/connect pull request 219, merged 2026-10-09 13:44 UTC
#   sdk      urnetwork/sdk pull request 158, merged 2026-10-09 12:25 UTC
# In both, the pull request's head had merged that same first parent, and the merge's tree is the
# head's: base..merge is what the pull request deleted, and nothing else.
SIDES = {
    "connect": dict(
        source="e449f7d8126c0b5748f5083392a8855bac877b32",
        removal=("64e433f47cb5ac9f32e71a5b6d5aff659bc00623", "847460bba8aa31fb2e86ce007e9d5443d884544b"),
        projectors=[(vs.project_connect_codestyle, None), (vs.project_connect_core, "2a"), (vs.project_connect_protocol, "2b")],
    ),
    "sdk": dict(
        source="6141b98d05bcac98d5ccae11c54c7748919017e6",
        removal=("679a836a21cf2f597b87d3adae6b91bcdf5aabf3", "b8209d9d7f6d858b2171cd92d4203bdadb758260"),
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
# values of the core SDK that lines upstream ADDED to an imported path name, and that this
# repository does not declare: source path -> (the names, sha256 of the lines set aside). Such
# lines cannot be carried as written, because what they are about stayed in the core. Each name is
# held both ways (core_subject, below), and the digest is of upstream's own bytes: the lines set
# aside, in the order the file holds them. Here they are every line upstream added to the path
# between the merge base of the import's source and upstream (0c6462f2) and the upstream measured,
# U, but the one line of a row upstream CHANGED (06f33802's "licenseJSON", never set aside):
#   git diff 0c6462f2 <U> -- message_stream_adapter_test.go | grep '^+' | grep -v '^+++' |
#       grep -v '"licenseJSON"' | cut -c2- | sha256sum
# 46 lines, of three commits of urnetwork/sdk: ae5a65fc (37, the two teardown constants), 80f6e365
# (4, the API client's three values) and 69c49348 (5, the credential renewer's five).
# A LIMIT, measured: one name is enough to set a block aside, so a name whose line shares a block
# with another's can be dropped and the run still passes (apiAdminRoutePatterns, beside
# apiAdminRouteAccess). What holds such a line is the digest; what the list adds, name by name, is
# the check both ways. So every core value the lines name is listed, and the list is read with the
# lines when they are pinned.
CORE_SUBJECT = {
    "sdk": {
        "message_stream_adapter_test.go": (
            ("ErrNetworkCredentialRequired", "apiAdminRouteAccess", "apiAdminRoutePatterns",
             "closedNetworkRenewerDone",
             "mobileMemoryTeardownCapacity", "mobileMemoryTeardownLifetime",
             "networkRenewalMaxRetryJitter", "networkRenewalMinRetryTimeout",
             "networkRenewalRefusedRetryTimeout", "networkRenewalRetryJitterBase"),
            "e472b705d22cb7a522790a80043bf544762525d746b173cf6b860367c47db5bd",
        ),
    },
}
# whether the lines set aside are held to that digest; the controls turn it off to run the design
# it replaces, where any added block naming a core value is set aside with whatever sits beside it
PIN_ASIDE = True
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


_naming = {}


def _word(name):
    """A name as a whole identifier: no identifier character before it or after it."""
    return re.compile(rb"(?<![A-Za-z0-9_])" + re.escape(name.encode()) + rb"(?![A-Za-z0-9_])")


def go_files_naming(repo, commit, names):
    """name -> the .go files of a commit's tree that spell it as a whole word, by one git grep.
    The same query answers "no Go file of the tip names it" and "a Go file upstream keeps does",
    so the absence it reports on one tree is beside a presence it reports on the other."""
    missing = sorted(n for n in set(names) if (repo, commit, n) not in _naming)
    if missing:
        for n in missing:
            _naming[(repo, commit, n)] = set()
        args = ["grep", "-z", "-o", "-w", "-F"]
        for n in missing:
            args += ["-e", n]
        out = vs.git(repo, *args, commit, "--", "*.go", ok_codes=(0, 1))
        for line in out.split(b"\n"):
            head, found, match = line.partition(b"\0")
            if not found:
                continue
            path = head.decode("utf-8", "surrogateescape")[len(commit) + 1:]
            _naming.setdefault((repo, commit, match.decode("utf-8", "replace")), set()).add(path)
    return {n: sorted(_naming[(repo, commit, n)]) for n in names}


def set_aside(base, theirs, names):
    """Upstream's change base->theirs without the lines it ADDED that name one of names.

    A block of added lines, between two lines upstream left alone or at either end of the file, is
    set aside whole when a line of it names one of the values. A line upstream CHANGED is never
    set aside, whatever it names. Answers (theirs without those blocks, the lines set aside)."""
    old, new = (base or b"").splitlines(keepends=True), theirs.splitlines(keepends=True)
    words = [_word(n) for n in names]
    kept, aside = [], []
    for tag, _, _, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        block = new[j1:j2]
        if tag == "insert" and any(w.search(line) for w in words for line in block):
            aside.extend(block)
        else:
            kept.extend(block)
    return b"".join(kept), aside


def core_subject(side, path, entry, repo, upstream, deleted, dst, tip, base, theirs):
    """A CORE_SUBJECT entry held both ways. Answers (theirs without the lines set aside, those
    lines, the Go files upstream keeps that name the values, every problem found).

      - no Go file of the tip names the value: one that does has its subject here, and lines
        about it are to be ported, not set aside;
      - a Go file upstream holds, which the removal does not delete and no import takes, names
        it: a value only the moved files name is not the core's;
      - a line set aside names it, and at least one line is set aside: an entry nothing needs is
        a failure, like a ported.tsv row nothing needs;
      - the lines set aside are the ones pinned."""
    names, digest = entry
    kept, aside = set_aside(base, theirs, names)
    here, there = go_files_naming(dst, tip, names), go_files_naming(repo, upstream, names)
    gone = set(deleted)
    keepers, problems = set(), []
    for name in names:
        staying = [p for p in there[name] if p not in gone and project(side, p)[0] is None]
        keepers.update(staying)
        if here[name]:
            problems.append("CORE_SUBJECT names %s for %s, and the tip names it too (%s): its subject is here, so the lines are to be ported, not set aside"
                            % (name, path, ", ".join(here[name][:3])))
        if not staying:
            problems.append("CORE_SUBJECT names %s for %s, and no Go file the core keeps at %s names it (%s): nothing shows its subject stays in the core"
                            % (name, path, upstream[:12], "only %s" % ", ".join(there[name][:3]) if there[name] else "no file names it at all"))
        if not any(_word(name).search(line) for line in aside):
            problems.append("CORE_SUBJECT names %s for %s, and no line upstream added since the merge base names it: delete it" % (name, path))
    if not aside:
        problems.append("CORE_SUBJECT has an entry for %s, and upstream added no line that names its values: delete the entry" % path)
    got = hashlib.sha256(b"".join(aside)).hexdigest()
    if PIN_ASIDE and aside and got != digest:
        problems.append("the lines upstream added to %s that name a core value are not the ones CORE_SUBJECT pins: %d line(s), sha256 %s, pinned %s. Read them before pinning them: a line beside them whose subject is here is to be ported"
                        % (path, len(aside), got, digest))
    return kept, aside, sorted(keepers), problems


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
    void, set_asides = [], {}
    if notes is not None:
        notes["lineage"], notes["void"], notes["aside"], notes["deleted"] = lineage, void, set_asides, set(deleted)

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

    for d in sorted(set(CORE_SUBJECT.get(side, {})) - set(deleted + kept)):
        fails.append((d, "CORE_SUBJECT has an entry for %s, which is no imported path upstream holds at %s: delete the entry" % (d, upstream[:12])))
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
        # the lines upstream added whose subject is a value of the core are set aside before any
        # merge: bk is upstream's file without them, and it is what the tip is held to
        entry, bk, aside = CORE_SUBJECT.get(side, {}).get(d), b, []
        if entry:
            bk, aside, keepers, problems = core_subject(side, d, entry, repo, upstream, deleted, dst, tip, a, b)
            set_asides[d] = (aside, keepers)
            if problems:
                fails.extend((d, problem) for problem in problems)
                continue
            tally["with lines set aside, their subject the core's"] += 1
            if verbose:
                print("  %s: %d line(s) upstream added are set aside (sha256 %s). They name %s, which the core keeps (%s) and no Go file of the tip names. NOT CARRIED:"
                      % (d, len(aside), entry[1], ", ".join(entry[0]), ", ".join(keepers)))
                for line in aside:
                    print("      +%s" % line.decode("utf-8", "replace").rstrip("\r\n"))
        mbk_ = plain(stage, d, bk)
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
                pairs = [(ma_, mbk_)]
                if stage is not None:
                    pairs.append((mech_all(stage, origin, a), mech_all(stage, d, bk)))
                ok, how = contains(t, *pairs[0])
                if not ok and len(pairs) > 1:
                    ok, how_all = contains(t, *pairs[1])
                    if ok:
                        how = how_all + " (with the literal rewrite applied to upstream's two sides)"
                if ok and aside and mbk_ == ma_:
                    # upstream changed nothing but the lines set aside, so nothing of it lands here
                    voided = True
                    void.append(d)
                    tally["adapted here, upstream's whole change set aside"] += 1
                elif ok:
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
                        took = changed_lines(ma_, mbk_)
                        print("  %s: %s conflicts in %d region(s), each one the tip removed whole (upstream holds %d line(s) there), and every other upstream change is in the tip. NOT CARRIED, %d changed line(s):"
                              % (d, "the rest of upstream's change" if aside else "upstream's change", detail, len(there), len(took)))
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


def unneeded(rows, used):
    """Rows nothing needed, each a failure. While the ranges moved, a row whose commits the upstream
    measured did not hold was set apart as ahead of it; the recorded ranges have nothing after them."""
    return ["ported.tsv: the %s row for %s %s is needed by nothing: delete it" % (kind, side, path)
            for side, kind, path in sorted(set(rows) - used)]


def removal_shape(side, repo, base, merge):
    """A removal's recorded range held to its shape: the merge is a merge commit, and the base is
    its first parent. So the range is what the side's upstream main lost in that one merge, and
    the base is the last commit of main that holds the moved paths. Answers every problem."""
    for name, commit in (("base", base), ("merge", merge)):
        r = subprocess.run(["git", "--no-optional-locks", "-C", repo, "cat-file", "-e", commit + "^{commit}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            sys.exit("FATAL: %s does not hold %s, the %s of the %s removal as it merged: fetch it (docs/HISTORY.md has the command)"
                     % (repo, commit, name, side))
    parents = vs.git(repo, "log", "-1", "--format=%P", merge).decode().split()
    if len(parents) < 2:
        return ["the %s removal is recorded as %s, which is not a merge commit: the range is the merge of the removal's pull request on upstream main"
                % (side, merge[:12])]
    if parents[0] != base:
        return ["the %s removal's base is recorded as %s, and its merge %s has the first parent %s: the base is the commit of main the removal merged into"
                % (side, base[:12], merge[:12], parents[0][:12])]
    return []


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
    ap.add_argument("--connect", required=True, help="a repository holding connect's import source and its removal as it merged")
    ap.add_argument("--sdk", required=True, help="a repository holding the sdk's import source and its removal as it merged")
    ap.add_argument("--ported", required=True)
    ap.add_argument("--controls", action="store_true")
    a = ap.parse_args()
    rows = read_ported(a.ported)
    tip = vs.rev(a.dst, a.dst_rev)
    repos = {"connect": a.connect, "sdk": a.sdk}
    # a removal is (repository, base, head, the upstream measured or None for the base): the ranges
    # are SIDES' own, and the controls alone build any other
    removals = {side: (repos[side],) + SIDES[side]["removal"] + (None,) for side in SIDES}
    print("tip %s" % tip)
    failures = []
    for side in sorted(removals):
        repo, base, merge, _ = removals[side]
        problems = removal_shape(side, repo, base, merge)
        print("the %s removal as it merged, recorded: %s..%s, %s" % (side, base[:12], merge[:12], "a merge and its first parent" if not problems else "NOT one merge of its main"))
        failures += ["recorded: %s" % p for p in problems]
    spec = ["spec: %s" % p for p in spec_problems(a.dst, tip)]
    failures += spec
    print("the projections against the import specs: %s" % ("%d problem(s)" % len(spec) if spec else "every selection line projects where its spec puts it"))
    used = set()
    for side in sorted(removals):
        failures += ["%s: %s" % (side, msg) for _, msg in check_side(side, removals[side], a.dst, tip, rows, used)]
    failures += unneeded(rows, used)
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
        plant = ("connect", "port", "message/record.go")
        # the second names a commit the upstream measured does not hold, the removal's own merge:
        # such a row was printed as ahead of the upstream, and passed, while the ranges moved
        for commits, title in (([], "which upstream did not change"),
                               ([removals["connect"][2]], "naming a commit the upstream measured does not hold")):
            planted = dict(rows)
            planted[plant] = dict(commits=commits, port=None, reason="planted: upstream did not change it")
            plant_used = set()
            for side in sorted(removals):
                check_side(side, removals[side], a.dst, tip, planted, plant_used, verbose=False)
            ok = bool(unneeded({plant: planted[plant]}, plant_used & {plant}))
            print("  control: a port row planted for message/record.go, %s -> %s"
                  % (title, "needed by nothing, reported" if ok else "MISSED"))
            if not ok:
                failures.append("control: the port row planted for message/record.go, %s, was not reported" % title)
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
        # the lines upstream added whose subject is the core's: the entry dropped, each refusal for
        # its own reason, and the digest against the design it replaces
        global PIN_ASIDE
        for side in sorted(CORE_SUBJECT):
            repo, base, _, upstream = removals[side]
            at = vs.rev(repo, upstream or base)

            def held(path, entry):
                """check_side's failures with path's entry replaced, or dropped when entry is None."""
                saved = CORE_SUBJECT[side]
                CORE_SUBJECT[side] = {k: v for k, v in saved.items() if k != path}
                if entry is not None:
                    CORE_SUBJECT[side][path] = entry
                try:
                    return check_side(side, removals[side], a.dst, tip, rows, set(), verbose=False)
                finally:
                    CORE_SUBJECT[side] = saved

            def one(control, path, got, needle):
                """A control that must fail for path alone, with one message, which holds needle."""
                ok = len(got) == 1 and got[0][0] == path and needle in got[0][1]
                print("  control: %s -> %s" % (control, "refused: %s" % got[0][1] if ok else "BROKEN: %s" % got))
                if not ok:
                    failures.append("control: %s: want one failure, for %s, saying %r; got %s" % (control, path, needle, got))

            notes = {}
            check_side(side, removals[side], a.dst, tip, rows, set(), verbose=False, notes=notes)
            for path in sorted(CORE_SUBJECT[side]):
                names, digest = CORE_SUBJECT[side][path]
                lines, keepers = notes["aside"].get(path, ([], []))
                if not lines or not keepers:
                    failures.append("control: CORE_SUBJECT's entry for %s sets no line aside, or nothing the core keeps names its values, so its controls have nothing to run on" % path)
                    continue
                one("the CORE_SUBJECT entry for %s dropped" % path, path, held(path, None), "outside what the tip removed")

                # three names, each taken from the source, each wrong in exactly one way
                def stays(found):
                    return any(p not in notes["deleted"] and project(side, p)[0] is None for p in found)
                spelled = sorted({w.decode() for w in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{5,}", b"".join(lines))} - set(names))
                here, there = go_files_naming(a.dst, tip, spelled), go_files_naming(repo, at, spelled)
                both = next((w for w in spelled if here[w] and stays(there[w])), None)
                moved = next((w for w in spelled if not here[w] and there[w] and not stays(there[w])), None)
                beside = sorted({w.decode() for w in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{11,}", blob_at(repo, at, keepers[0]))} - set(spelled) - set(names))[:150]
                absent = go_files_naming(a.dst, tip, beside)
                unnamed = next((w for w in beside if not absent[w]), None)
                if None in (both, moved, unnamed):
                    failures.append("control: the lines set aside from %s and %s offer no name for a control (%s, %s, %s)" % (path, keepers[0], both, moved, unnamed))
                    continue
                one("%s named in CORE_SUBJECT for %s, a name the set-aside lines spell and the tip spells too" % (both, path),
                    path, held(path, (tuple(names) + (both,), digest)), "the tip names it too")
                one("%s named there, a name only the moved file spells" % moved,
                    path, held(path, (tuple(names) + (moved,), digest)), "no Go file the core keeps")
                one("%s named there, a name the core keeps and no added line spells" % unnamed,
                    path, held(path, (tuple(names) + (unnamed,), digest)), "no line upstream added since the merge base names it")

                # the digest: a line planted in upstream's file, beside the lines set aside
                oid = tree_of(repo, at)[path][2]
                real = blob_at(repo, at, path)
                anchor = next((line for line in lines if real.count(line) == 1), None)
                if anchor is None:
                    failures.append("control: no line set aside from %s is unique in upstream's file, so nothing can be planted beside one" % path)
                    continue
                _blobs[(repo, oid)] = real.replace(anchor, anchor + b"// planted by carried.py's control: a line whose subject would be here\n", 1)
                try:
                    one("a line planted in upstream's %s beside the lines set aside" % path, path,
                        held(path, (names, digest)), "are not the ones CORE_SUBJECT pins")
                    PIN_ASIDE = False
                    try:
                        unpinned = held(path, (names, digest))
                    finally:
                        PIN_ASIDE = True
                finally:
                    _blobs[(repo, oid)] = real
                ok = not unpinned
                print("  control: the same planted line with the digest unchecked, the design it replaces -> %s"
                      % ("set aside with the rest, and nothing reports it" if ok else "BROKEN: %s" % unpinned))
                if not ok:
                    failures.append("control: with the digest unchecked the planted line was still reported: %s" % unpinned)
        value = "coreValue"
        three = b"a\nb\nc\n"
        for name, theirs_, want_kept, want_aside in (
            ("an added line that names the value", b"a\nb\ncoreValue()\nc\n", three, [b"coreValue()\n"]),
            ("an added line that names no such value", b"a\nb\nx\nc\n", b"a\nb\nx\nc\n", []),
            ("an added line whose names only contain the value's", b"a\nb\nxcoreValue(coreValues)\nc\n", b"a\nb\nxcoreValue(coreValues)\nc\n", []),
            ("a CHANGED line that names the value", b"a\ncoreValue()\nc\n", b"a\ncoreValue()\nc\n", []),
            ("two added blocks, one of which names the value", b"a\nx\nb\ncoreValue()\nc\n", b"a\nx\nb\nc\n", [b"coreValue()\n"]),
        ):
            got_kept, got_aside = set_aside(three, theirs_, (value,))
            ok = got_kept == want_kept and got_aside == want_aside
            print("  control: the set-aside, %s -> %s%s"
                  % (name, "set aside" if got_aside else "left in the merge", "" if ok else "  <-- BROKEN"))
            if not ok:
                failures.append("control: the set-aside, %s: kept %r, set aside %r" % (name, got_kept, got_aside))
        # the recorded ranges. First the form they replace: a removal's base taken as the merge base
        # of its head and an upstream main, on a day that main has merged it. The head is then its
        # own base, the range is empty, and main holds no moved path to measure. Then the shape
        # SIDES is held to: a base that is not the merge's first parent
        for side in sorted(removals):
            repo, base, merge, _ = removals[side]
            head = vs.git(repo, "log", "-1", "--format=%P", merge).decode().split()[1]
            moving = vs.git(repo, "merge-base", head, merge).decode().strip()
            notes = {}
            got = {p for p, _ in check_side(side, (repo, moving, head, merge), a.dst, tip, rows, set(), verbose=False, notes=notes)}
            ok = moving == head and not notes["deleted"] and bool(got)
            print("  control: %s with its base taken as the merge base of the removal's head and the main that merged it, the form this replaces -> %s..%s, %d deletion(s), and it fails for %d path(s)%s"
                  % (side, moving[:12], head[:12], len(notes["deleted"]), len(got), "" if ok else "  <-- BROKEN"))
            if not ok:
                failures.append("control: %s measured from a merge base with the main that merged it: want an empty range that fails, got %s..%s with %d deletion(s) and %d failing path(s)"
                                % (side, moving[:12], head[:12], len(notes["deleted"]), len(got)))
            earlier = vs.git(repo, "log", "-1", "--format=%P", base).decode().split()[0]
            problems = removal_shape(side, repo, earlier, merge)
            ok = len(problems) == 1 and "has the first parent %s" % base[:12] in problems[0]
            print("  control: %s with its base recorded one commit earlier, %s -> %s"
                  % (side, earlier[:12], "refused: %s" % problems[0] if ok else "BROKEN: %s" % problems))
            if not ok:
                failures.append("control: a recorded base that is not the merge's first parent was not refused for %s: %s" % (side, problems))
    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures[:200]:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
