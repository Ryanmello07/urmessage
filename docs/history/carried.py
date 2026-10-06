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
     CODESTYLE.md) has every change upstream made to it since MB IN THE TIP: a three-way merge of
     T:M (ours), m(MB:D) (base) and m(U:D) (theirs) is clean and is T:M byte for byte;
  3. upstream's changes are declared: when m(U:D) differs from m(MB:D), ported.tsv has a port row
     for D naming exactly the upstream commits that changed it (MB..U) and the tip commit that
     ported them, an ancestor of the tip;
  4. the fork's changes are declared: when m(S:D) differs from m(MB:D), the import carried changes
     upstream never had, and ported.tsv has a fork-only row naming exactly those commits (MB..S);
  5. a path the import holds that upstream deleted after MB (in MB or S, not in U) is gone from the
     tip, under its name and any name the tip's manifest renamed it to, with a port-delete row
     naming exactly the deleting commits;
  6. every ported.tsv row is needed, unless its commits are not in U at all: such a row is AHEAD of
     the upstream measured, it is printed, and it is checked the day U contains it.

The complement is printed: what the removal's head still holds under the imported paths, and what it
changes rather than deletes. Read-only on every repository, like verify_split.py, whose projections,
mechanical rewrite and git helpers this imports.

  python3 docs/history/carried.py --dst . --dst-rev HEAD --ported docs/history/ported.tsv \\
      --removal connect=<repo>:<B>..<H>[@<U>] --removal sdk=<repo>:<B>..<H>[@<U>] [--controls]

--controls runs the same checks against the tip this branch had before the ports (f3f8f2bd, the tip
the review measured), where they must fail for exactly the paths the port and port-delete rows
in U name; then with a row dropped, which must be reported, and with a row planted, which must be
needed by nothing.
"""
import argparse
import os
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
KINDS = ("port", "port-delete", "fork-only", "not-carried")
MANIFEST = "docs/history/adaptations.tsv"


def project(side, path):
    for projector, stage in SIDES[side]["projectors"]:
        hit = projector(path)
        if hit:
            return hit[1], stage
    return None, None


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


def check_side(side, removal, dst, tip, rows, used, verbose=True):
    """Every failure as (source path, message)."""
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
        s, a = blob_at(repo, source, d), blob_at(repo, mb, d)
        mb_, ms_, ma_ = plain(stage, d, b), plain(stage, d, s), plain(stage, d, a)
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
                ok, how = contains(t, ma_, mb_)
                if not ok and stage is not None:
                    ok, how_all = contains(t, mech_all(stage, d, a), mech_all(stage, d, b))
                    if ok:
                        how = how_all + " (with the literal rewrite applied to upstream's two sides)"
                if not ok:
                    fails.append((d, "%s -> %s (%s): %s since %s" % (d, m, where, how, mb[:12])))
                    continue
                tally["adapted here, holding every upstream change"] += 1
        if mb_ != ma_:
            changed = commits_changing(repo, mb, upstream, d)
            r = row("port", d)
            if not r:
                fails.append((d, "upstream changed %s after %s (%s) and ported.tsv has no port row for it"
                                 % (d, mb[:12], ", ".join(c[:10] for c in changed))))
            elif r["commits"] != changed:
                fails.append((d, "the port row for %s names %s; upstream's commits are %s"
                                 % (d, [c[:10] for c in r["commits"]], [c[:10] for c in changed])))
            elif not r["port"] or not vs.is_ancestor(dst, r["port"], tip):
                fails.append((d, "the port row for %s names a tip commit that is not an ancestor of the tip" % d))
            else:
                tally["of them ported, declared"] += 1
        if ms_ != ma_:
            fork = commits_changing(repo, mb, source, d)
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
        held = [x for x in (m, renames.get(p)) if x and x in tip_tree]
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
        if kind in ("port", "port-delete") and commits and not all(vs.is_ancestor(repo, c, measured) for c in commits):
            ahead.append("%s %s %s (%s not in %s)" % (side, kind, path, ", ".join(c[:10] for c in commits), measured[:12]))
            continue
        fails.append("ported.tsv: the %s row for %s %s is needed by nothing: delete it" % (kind, side, path))
    return fails, ahead


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
    used = set()
    failures = []
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
        for kind in ("port", "port-delete", "fork-only"):
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
    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures[:200]:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
