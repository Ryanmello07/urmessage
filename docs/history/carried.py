#!/usr/bin/env python3
"""carried.py: every path a removal pull request deletes from connect or the core SDK is carried here.

The imports took their paths from a pinned source commit, and verify_split.py proves each import
against it. The removal pull requests delete those paths from a LATER commit, their base, and the
maintainers may change a path in between: urnetwork/connect 54b5b106 and e8611390 did, after the
import's source e449f7d8, and nothing compared the two until review. This is that comparison,
re-runnable against whatever base each removal pull request finally has.

For each removal side, with S its import source, B the removal's base, H its head, MB the merge base
of S and B, T this repository's tip, and m() the mechanical import-path rewrite of that side's stage:

  1. every path D the removal deletes (B..H, status D) projects onto a path M of the tip, and T holds
     M, unless ported.tsv declares D not-carried, with the reason;
  2. the tip CONTAINS every change upstream made to D since the merge base: a three-way merge of
     T:M (ours), m(MB:D) (base) and m(B:D) (theirs) is clean and is T:M byte for byte. A change the
     tip lacks is a conflict, or a result that differs from the tip;
  3. upstream's changes are declared: when m(B:D) differs from m(MB:D), ported.tsv has a port row
     for D naming exactly the upstream commits that changed it (MB..B), and the tip commit that
     ported them, an ancestor of the tip;
  4. the fork's changes are declared: when m(S:D) differs from m(MB:D), the import carried changes
     upstream never had, and ported.tsv has a fork-only row naming exactly those commits (MB..S);
  5. a path the import holds that upstream deleted after the merge base (in MB or S, not in B) is
     gone from the tip, under its name and under any name the tip's manifest renamed it to, with a
     port-delete row naming exactly the deleting commits;
  6. every ported.tsv row is needed.

The complement is printed: what the removal's head still holds under the imported paths, and what it
changes rather than deletes. Read-only on every repository, like verify_split.py, whose projections,
mechanical rewrite and git helpers this imports.

  python3 docs/history/carried.py --dst . --dst-rev HEAD --ported docs/history/ported.tsv \\
      --removal connect=<repo holding S, B and H>:<B>..<H> --removal sdk=<repo>:<B>..<H> [--controls]

--controls runs the same checks against the tip this branch had before the ports (f3f8f2bd, the tip
the review measured), where they must fail for exactly the paths the port and port-delete rows
name; then with a row dropped, which must be reported, and with a row planted, which must be unused.
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
    # the connect imports a removal reads (CODESTYLE.md stays in connect; the removal does not delete it)
    "connect": dict(
        source="e449f7d8126c0b5748f5083392a8855bac877b32",
        projectors=[(vs.project_connect_core, "2a"), (vs.project_connect_protocol, "2b")],
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
    repo, base, head = removal
    fails = []
    source = vs.rev(repo, SIDES[side]["source"])
    base, head = vs.rev(repo, base), vs.rev(repo, head)
    mb = vs.git(repo, "merge-base", source, base).decode().strip()
    tip_tree = tree_of(dst, tip)
    renames, declared_deletes = manifest_rows(dst, tip)
    out = vs.git(repo, "diff", "--no-renames", "--name-status", "-z", base, head).split(b"\0")
    changes = [(out[i].decode(), out[i + 1].decode("utf-8", "surrogateescape")) for i in range(0, len(out) - 1, 2)]
    deleted = sorted(p for s, p in changes if s == "D")
    others = sorted("%s %s" % (s, p) for s, p in changes if s != "D")
    for at in (base, source, mb):
        prefetch(repo, at, deleted)
    prefetch(dst, tip, [project(side, d)[0] for d in deleted if project(side, d)[0]])
    tally = Counter()
    if verbose:
        print("side %s: import source %s, removal base %s, head %s, merge base of source and base %s"
              % (side, source[:12], base[:12], head[:12], mb[:12]))
        print("  the removal deletes %d paths, and changes %d it keeps" % (len(deleted), len(others)))

    def row(kind, path):
        key = (side, kind, path)
        if key in rows:
            used.add(key)
            return rows[key]
        return None

    def mech(stage, path, data):
        return None if data is None else vs.mechanical_imports(stage, path, data)

    def mech_all(stage, path, data):
        return None if data is None else vs.mechanical_all(stage, path, data)

    for d in deleted:
        m, stage = project(side, d)
        if m is None:
            if row("not-carried", d):
                tally["not carried, declared"] += 1
            else:
                fails.append((d, "the removal deletes %s, which no import of this repository projects: carry it, or declare it not-carried" % d))
            continue
        b, s, a = blob_at(repo, base, d), blob_at(repo, source, d), blob_at(repo, mb, d)
        mb_, ms_, ma_ = mech(stage, d, b), mech(stage, d, s), mech(stage, d, a)
        if m not in tip_tree:
            if m in declared_deletes:
                tally["deleted here, declared in the manifest"] += 1
            else:
                fails.append((d, "the removal deletes %s and the tip holds no %s, and the tip's manifest declares no deletion of it" % (d, m)))
                continue
        else:
            t = blob_at(dst, tip, m)
            if t in (b, mb_, mech_all(stage, d, b)):
                tally["identical to the removal's base" if t == b else "the mechanical rewrite of the removal's base"] += 1
            else:
                # the tip holds upstream's every change since the merge base: shown with the import-spec
                # rewrite of both sides, or with the rewrite of every literal too, when the tip's own
                # literal rewrite sits beside an upstream change and only the second can merge it
                ok, how = contains(t, ma_, mb_)
                if not ok:
                    ok, how_all = contains(t, mech_all(stage, d, a), mech_all(stage, d, b))
                    if ok:
                        how = how_all + " (with the literal rewrite applied to upstream's two sides)"
                if not ok:
                    fails.append((d, "%s -> %s: %s since %s" % (d, m, how, mb[:12])))
                    continue
                tally["adapted here, holding every upstream change"] += 1
        if mb_ != ma_:
            upstream = commits_changing(repo, mb, base, d)
            r = row("port", d)
            if not r:
                fails.append((d, "upstream changed %s after %s (%s) and ported.tsv has no port row for it"
                                 % (d, mb[:12], ", ".join(c[:10] for c in upstream))))
            elif r["commits"] != upstream:
                fails.append((d, "the port row for %s names %s; upstream's commits are %s"
                                 % (d, [c[:10] for c in r["commits"]], [c[:10] for c in upstream])))
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
    base_tree = tree_of(repo, base)
    gone = set()
    for at in (mb, source):
        for p in tree_of(repo, at):
            if project(side, p)[0] is not None and p not in base_tree:
                gone.add(p)
    for p in sorted(gone):
        m, _ = project(side, p)
        upstream = commits_changing(repo, mb, base, p)
        if not upstream:
            if verbose:
                print("  %s is in the import's source and was never in upstream since %s; reported, not a port" % (p, mb[:12]))
            continue
        r = row("port-delete", p)
        if not r:
            fails.append((p, "upstream deleted %s after %s (%s) and ported.tsv has no port-delete row"
                             % (p, mb[:12], ", ".join(c[:10] for c in upstream))))
            continue
        held = [x for x in (m, renames.get(p)) if x and x in tip_tree]
        if r["commits"] != upstream:
            fails.append((p, "the port-delete row for %s names %s; upstream's commits are %s"
                             % (p, [c[:10] for c in r["commits"]], [c[:10] for c in upstream])))
        elif held:
            fails.append((p, "upstream deleted %s and the tip still holds %s" % (p, ", ".join(held))))
        elif not r["port"] or not vs.is_ancestor(dst, r["port"], tip):
            fails.append((p, "the port-delete row for %s names a tip commit that is not an ancestor of the tip" % p))
        else:
            tally["deleted upstream, and here"] += 1
    if verbose:
        print("  carried: %s" % dict(sorted(tally.items())))
        kept = sorted(p for p in tree_of(repo, head) if project(side, p)[0] is not None)
        print("  COMPLEMENT: under the imported paths the removal's head still holds %d: %s" % (len(kept), kept))
        print("  COMPLEMENT: the removal changes, and does not delete, %d: %s" % (len(others), others))
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dst-rev", required=True)
    ap.add_argument("--removal", action="append", default=[], help="side=<repo>:<base>..<head>")
    ap.add_argument("--ported", required=True)
    ap.add_argument("--controls", action="store_true")
    a = ap.parse_args()
    rows = read_ported(a.ported)
    tip = vs.rev(a.dst, a.dst_rev)
    removals = {}
    for spec in a.removal:
        side, _, rest = spec.partition("=")
        repo, _, span = rest.rpartition(":")
        base, _, head = span.partition("..")
        if side not in SIDES or not repo or not base or not head:
            sys.exit("FATAL: --removal %r must be side=<repo>:<base>..<head>" % spec)
        removals[side] = (repo, base, head)
    if set(removals) != set(SIDES):
        sys.exit("FATAL: --removal must name every side: %s" % sorted(SIDES))
    print("tip %s" % tip)
    used = set()
    failures = []
    for side in sorted(removals):
        failures += ["%s: %s" % (side, msg) for _, msg in check_side(side, removals[side], a.dst, tip, rows, used)]
    for key in sorted(set(rows) - used):
        failures.append("ported.tsv: the %s row for %s %s is needed by nothing: delete it" % (key[1], key[0], key[2]))
    if a.controls:
        print()
        print("controls:")
        pre = vs.rev(a.dst, PRE_PORT_TIP)
        for side in sorted(removals):
            got = {p for p, _ in check_side(side, removals[side], a.dst, pre, rows, set(), verbose=False)}
            want = {k[2] for k in rows if k[0] == side and k[1] in ("port", "port-delete")}
            ok = got == want
            print("  control: %s against %s, the tip before the ports -> fails for %d path(s), the rows' %d%s"
                  % (side, pre[:12], len(got), len(want), "" if ok else "  <-- BROKEN: %s" % sorted(got ^ want)))
            if not ok:
                failures.append("control: %s against the pre-port tip failed for %s, want exactly the ported paths %s" % (side, sorted(got), sorted(want)))
        for kind in ("port", "port-delete", "fork-only"):
            keys = sorted(k for k in rows if k[1] == kind)
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
        ok = plant not in plant_used
        print("  control: a port row planted for message/record.go, which upstream did not change -> %s"
              % ("needed by nothing, reported" if ok else "MISSED"))
        if not ok:
            failures.append("control: the planted port row was used")
    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures[:200]:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
