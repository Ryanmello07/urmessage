#!/usr/bin/env python3
"""proof.py: the import's proof, held at ONE recorded tip.

The proof is two checks of one tree. verify_split.py proves every import against its pinned source
and holds every other path of a tip to the manifest, adaptations.tsv. carried.py holds that tip to
what the two removal pull requests deleted from connect and the core SDK. While this repository
was being imported both were run at every tip, and every commit kept the manifest in step.

That cannot go on for good. The manifest pins the sha256 of every file that is not an import's own
bytes, so the first commit that changes code fails part E, and a manifest rewritten for each day's
work would stop being a record of the import. And both removals have merged, so nothing upstream
can change what was measured.

SO THE PROOF IS HELD AT ONE TIP, the recorded tip: the tree in which every sibling pin had moved to
a merged upstream commit and the removals' ranges were final. A later tip is held to two things,
and to nothing else. No row is added to the manifest for later work.

  1. THE RECORDED TIP IS ITS ANCESTOR. docs/history/recorded-tip.txt, read from the tip asked
     about, names one commit by its full id. That commit must be in the repository and in the
     tip's history: a history rewritten after the record (a squash, a rebase, a force-push) does
     not hold it.
  2. THE PROOF PASSES AT THE RECORDED TIP, run by that commit's own copies of the two scripts
     over that commit's own records (the manifest, ported.tsv, the commit maps). They are read out
     of the commit byte for byte, into a scratch directory, so nothing a later commit does under
     docs/history, and no line-ending setting of a checkout, changes what is proven.

  python3 docs/history/proof.py --connect <repo> --sdk <repo> [--dst .] [--dst-rev HEAD] [--controls]
      the check of a tip that names a recorded tip: 1 and 2.
  python3 docs/history/proof.py --connect <repo> --sdk <repo> [--dst .] --at <commit> [--controls]
      2 alone, at the commit given. This is how a tip is proven before it is recorded. A commit
      cannot hold its own id, so the tip that is recorded holds no recorded-tip.txt: the commit
      after it adds the file.

<repo> for --connect and --sdk holds that side's import source and its removal as it merged;
docs/HISTORY.md has the fetches. Read-only on every repository, like the scripts it runs.

--controls passes --controls to both scripts. For a tip that names a recorded tip it then runs
this script's own, on histories built in a scratch repository that borrows the checkout's objects
(objects/info/alternates), so nothing is written to the repository measured:
  - a later commit that changes an imported file must be ACCEPTED, and the same commit held to the
    manifest (part E at that commit, the design this replaces) must be refused for that file;
  - a later commit that puts a script that passes anything in carried.py's place, and empties the
    manifest, must be accepted too, and what is run for it must be the recorded tip's copies;
  - a rewritten history must be REFUSED: the tip's own tree as one commit on the recorded tip's
    parent, which is what a squash merge makes. The recorded tip is not its ancestor. The same
    history recovered the way docs/RELEASING.md gives, by a merge of the original tip that takes
    no change, must be accepted again;
  - a record that is a name and not a commit id, a record naming a commit the repository does not
    hold, and a record naming a commit that holds no proof (the repository's first commit) must
    each be refused, for that reason.
"""
import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

RECORD = "docs/history/recorded-tip.txt"
HISTORY = "docs/history/"
SIDES = "connect-codestyle,connect-core,connect-protocol,sdk"
# each side's published commit map, under docs/history
MAPS = [("connect-codestyle", "connect-codestyle-commit-map.txt"), ("connect-core", "connect-core-commit-map.txt"),
        ("connect-protocol", "connect-protocol-commit-map.txt"), ("sdk", "sdk-commit-map.txt")]
SCRIPTS = ("verify_split.py", "carried.py")
RECORDS = ("adaptations.tsv", "ported.tsv") + tuple(name for _, name in MAPS)
# who the controls' scratch commits are by; they are never written to the repository measured
SCRATCH = dict(GIT_AUTHOR_NAME="proof.py control", GIT_AUTHOR_EMAIL="control@invalid", GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000",
               GIT_COMMITTER_NAME="proof.py control", GIT_COMMITTER_EMAIL="control@invalid", GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
NOT_A_COMMIT = "0123456789abcdef0123456789abcdef01234567"


def git(repo, *args, ok_codes=(0,), env=None, data=None):
    r = subprocess.run(["git", "--no-optional-locks", "-C", repo, *args], input=data, env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode not in ok_codes:
        sys.exit("FATAL: git %s in %s: %s" % (" ".join(args), repo, r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout


def has_commit(repo, name):
    return subprocess.run(["git", "--no-optional-locks", "-C", repo, "cat-file", "-e", name + "^{commit}"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0


def is_ancestor(repo, a, b):
    return subprocess.run(["git", "--no-optional-locks", "-C", repo, "merge-base", "--is-ancestor", a, b],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0


def tree(repo, commit, under=""):
    """path -> (mode, type, object id) of a commit's tree, or of the part of it under a directory."""
    out = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit, *([under] if under else []))
    entries = {}
    for rec in out.split(b"\0"):
        if rec:
            meta, path = rec.split(b"\t", 1)
            entries[path.decode("utf-8", "surrogateescape")] = tuple(meta.decode().split(" "))
    return entries


def blob(repo, commit, path):
    """A path's bytes at a commit, or None when the commit does not hold it."""
    r = subprocess.run(["git", "--no-optional-locks", "-C", repo, "cat-file", "blob", "%s:%s" % (commit, path)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.stdout if r.returncode == 0 else None


def recorded(repo, tip):
    """The recorded tip a tip names: (commit, None), or (None, why it names none). The record is a
    full commit id and nothing else: a branch or a short id would name another commit another day."""
    data = blob(repo, tip, RECORD)
    if data is None:
        return None, ("%s names no recorded tip: it holds no %s. A tip that is not recorded yet is proven with --at <commit>"
                      % (tip[:12], RECORD))
    lines = [line.strip() for line in data.decode("utf-8", "replace").splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{40}", lines[0]):
        return None, "%s at %s must hold exactly one line that is a full commit id, and holds %r" % (RECORD, tip[:12], lines[:3])
    return lines[0], None


def later_tip(repo, tip):
    """Rule 1. Answers (the recorded tip, every problem): the record is one commit id, the commit
    it names is in the repository, and it is an ancestor of the tip."""
    commit, problem = recorded(repo, tip)
    if problem:
        return None, [problem]
    if not has_commit(repo, commit):
        return commit, ["the recorded tip %s is not in this repository at all: the history was rewritten, or the clone is shallow" % commit]
    if not is_ancestor(repo, commit, tip):
        return commit, ["the recorded tip %s is not an ancestor of %s: the history between them was rewritten" % (commit, tip)]
    return commit, []


def extract(repo, commit, into):
    """Every file a commit holds under docs/history, written byte for byte into a directory.
    Answers (the directory, None), or (None, why the proof cannot be run at that commit)."""
    entries = {p[len(HISTORY):]: v for p, v in tree(repo, commit, HISTORY).items() if v[1] == "blob"}
    missing = [name for name in SCRIPTS + RECORDS if name not in entries]
    if missing:
        return None, "%s holds no %s: the proof cannot be run there" % (commit[:12], ", ".join(HISTORY + name for name in missing))
    for name, (_, _, oid) in entries.items():
        target = os.path.join(into, *name.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(git(repo, "cat-file", "blob", oid))
    return into, None


def subject(repo, tip, into):
    """What rule 2 is run with for a tip: (the recorded tip, the directory that commit's scripts and
    records were read into, every problem). The files are the RECORDED tip's, never the tip's own."""
    commit, problems = later_tip(repo, tip)
    if problems:
        return commit, None, problems
    tools, why = extract(repo, commit, into)
    return commit, tools, [why] if why else []


def run(script, args, capture=False):
    """One of a commit's own scripts, by this interpreter. Answers (exit status, output or None)."""
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    sys.stdout.flush()
    if capture:
        r = subprocess.run([sys.executable, script] + args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return r.returncode, r.stdout.decode("utf-8", "replace")
    return subprocess.run([sys.executable, script] + args, env=env).returncode, None


def prove(repo, commit, tools, a):
    """Rule 2: both checks at a commit, by the scripts and records extracted from it into tools."""
    failures = []
    digests = {}
    for name in SCRIPTS:
        with open(os.path.join(tools, name), "rb") as f:
            digests[name] = hashlib.sha256(f.read()).hexdigest()
    print()
    print("== the proof at %s, by that commit's own scripts and records" % commit)
    print("-- verify_split.py (sha256 %s)" % digests["verify_split.py"])
    args = ["--sides", SIDES, "--connect", a.connect, "--sdk", a.sdk, "--dst", repo, "--dst-rev", commit, "--expect-filtered-tips"]
    for side, name in MAPS:
        args += ["--commit-map", "%s=%s" % (side, os.path.join(tools, name))]
    args += ["--manifest", os.path.join(tools, "adaptations.tsv")] + (["--controls"] if a.controls else [])
    status, _ = run(os.path.join(tools, "verify_split.py"), args)
    print("verify_split.py exited %d" % status)
    if status != 0:
        failures.append("verify_split.py does not pass at %s (exit %d)" % (commit[:12], status))
    print()
    print("-- carried.py (sha256 %s)" % digests["carried.py"])
    args = ["--dst", repo, "--dst-rev", commit, "--ported", os.path.join(tools, "ported.tsv"), "--connect", a.connect, "--sdk", a.sdk]
    status, _ = run(os.path.join(tools, "carried.py"), args + (["--controls"] if a.controls else []))
    print("carried.py exited %d" % status)
    if status != 0:
        failures.append("carried.py does not pass at %s (exit %d)" % (commit[:12], status))
    return failures


def scratch_repository(repo, parent):
    """A bare repository that borrows repo's objects. What the controls write goes here, never to repo."""
    path = os.path.join(parent, "scratch.git")
    subprocess.run(["git", "init", "-q", "--bare", path], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    objects = git(repo, "rev-parse", "--git-path", "objects").decode().strip()
    if not os.path.isabs(objects):
        objects = os.path.join(repo, objects)
    with open(os.path.join(path, "objects", "info", "alternates"), "w", encoding="utf-8", newline="\n") as f:
        f.write(os.path.abspath(objects).replace("\\", "/") + "\n")
    return path


def commit_on(scratch, parents, of, changes, index):
    """A scratch commit on parents whose tree is the commit of's, with changes (path -> (mode, bytes)) laid over it."""
    env = dict(os.environ, GIT_INDEX_FILE=index, **SCRATCH)
    git(scratch, "read-tree", of, env=env)
    for path, (mode, data) in sorted(changes.items()):
        oid = git(scratch, "hash-object", "-w", "--stdin", env=env, data=data).decode().strip()
        git(scratch, "update-index", "--add", "--cacheinfo", "%s,%s,%s" % (mode, oid, path), env=env)
    written = git(scratch, "write-tree", env=env).decode().strip()
    args = [arg for parent in parents for arg in ("-p", parent)]
    return git(scratch, "commit-tree", written, *args, "-m", "a scratch commit of proof.py's controls; never pushed", env=env).decode().strip()


def later_controls(repo, tip, commit, tools, work, a):
    """This script's own controls, for a tip whose recorded tip, commit, has just been proven with
    the files in tools. Each scratch tip is put to subject(), the function the real check uses."""
    failures = []
    scratch = scratch_repository(repo, work)
    index = os.path.join(work, "index")
    count = [0]

    def asked(at):
        """subject() for a scratch tip: (the commit it would be proven at, the files, every problem)."""
        count[0] += 1
        return subject(scratch, at, os.path.join(work, "control-%d" % count[0]))

    def expect(title, accepted, want, detail, needle=""):
        """A control's outcome, which must be the one wanted, for its own reason: needle, in the detail."""
        ok = accepted == want and needle in detail
        print("  control: %s -> %s%s" % (title, ("accepted: " if accepted else "refused: ") + detail, "" if ok else "  <-- BROKEN"))
        if not ok:
            failures.append("control: %s: want it %s%s, and it was %s: %s"
                            % (title, "accepted" if want else "refused", " (%s)" % needle if needle else "", "accepted" if accepted else "refused", detail))

    def same_files(directory):
        """How many of the scripts and records in a directory are, byte for byte, the ones just proven with."""
        same = 0
        for name in SCRIPTS + RECORDS:
            with open(os.path.join(directory, name), "rb") as f, open(os.path.join(tools, name), "rb") as g:
                same += f.read() == g.read()
        return same

    every = len(SCRIPTS + RECORDS)

    # a later commit that changes an imported file: the first .go file of the tip that the recorded
    # tip's manifest has no row for, which part E therefore holds to an import's bytes
    declared = set()
    with open(os.path.join(tools, "adaptations.tsv"), encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) >= 2 and not line.startswith("#"):
                declared.add(parts[0])
                if parts[1].startswith(("rename-to:", "rename+edit-to:")):
                    declared.add(parts[1].split(":", 1)[1])
    at_recorded, at_tip = tree(repo, commit), tree(repo, tip)
    imported = sorted(p for p, v in at_tip.items() if p.endswith(".go") and v[1] == "blob" and p not in declared and at_recorded.get(p) == v)
    if not imported:
        failures.append("control: the tip holds no .go file that the recorded tip's manifest leaves to an import, so there is nothing to change")
        return failures
    path = imported[0]
    mode, _, oid = at_tip[path]
    later = commit_on(scratch, [tip], tip, {path: (mode, git(repo, "cat-file", "blob", oid) + b"\n// a later change, planted by proof.py's control\n")}, index)
    got, files, problems = asked(later)
    if not problems and (got != commit or same_files(files) != every):
        problems = ["it would be proven at %s, with %d of the %d files just proven with" % (got, same_files(files), every)]
    expect("a later commit that changes an imported file (%s, one line added, on the tip)" % path, not problems, True,
           "; ".join(problems) or "the recorded tip is its ancestor, and the proof is the recorded tip's")
    status, out = run(os.path.join(tools, "verify_split.py"),
                      ["--sides", SIDES, "--connect", a.connect, "--sdk", a.sdk, "--dst", scratch, "--dst-rev", later, "--no-history",
                       "--manifest", os.path.join(tools, "adaptations.tsv")], capture=True)
    lines = [line.strip() for line in out.splitlines() if line.strip().startswith("E: %s differs from " % path)]
    expect("the same commit held to the manifest, the design this replaces", status == 0 or not lines, False,
           lines[0] if status != 0 and lines else "verify_split.py exited %d and no line reports %s" % (status, path), "differs from")

    # a later commit that rewrites the proof's own files: what is run for it is still the recorded
    # tip's copies. Rule 2 never reads a script or a record from the tip it is asked about
    hollow_files = {HISTORY + "carried.py": ("100755", b"print('PASS')\n"),
                    HISTORY + "adaptations.tsv": ("100644", b"# emptied by proof.py's control\n")}
    hollow = commit_on(scratch, [tip], tip, hollow_files, index)
    planted = all(blob(scratch, hollow, p) == data for p, (_, data) in hollow_files.items())
    got, files, problems = asked(hollow)
    if not problems and not (planted and got == commit and same_files(files) == every):
        problems = ["%s would be proven at %s, with %d of the %d files just proven with (its own two planted: %s)"
                    % (hollow[:12], got, same_files(files), every, planted)]
    expect("a later commit that puts a script that passes anything in carried.py's place and empties the manifest", not problems, True,
           "; ".join(problems) or "the %d scripts and records run for it are the recorded tip's, byte for byte, and not its own" % every)

    # a rewritten history: the tip's own tree, as one commit on the recorded tip's parent
    parent = git(repo, "log", "-1", "--format=%P", commit).decode().split()[0]
    squashed = commit_on(scratch, [parent], tip, {}, index)
    _, _, problems = asked(squashed)
    expect("a rewritten history (the tip's tree as one commit on %s, the recorded tip's parent, as a squash merge makes it)" % parent[:12],
           not problems, False, "; ".join(problems) or "the recorded tip is its ancestor", "is not an ancestor of")
    # and that history recovered without force, as docs/RELEASING.md gives it: one more merge, of
    # the original tip, that takes no change (git merge -s ours). The recorded tip is an ancestor again
    recovered = commit_on(scratch, [squashed, tip], squashed, {}, index)
    got, files, problems = asked(recovered)
    if not problems and (got != commit or same_files(files) != every):
        problems = ["it would be proven at %s, with %d of the %d files just proven with" % (got, same_files(files), every)]
    expect("that history recovered by a merge of the original tip that takes no change (docs/RELEASING.md)", not problems, True,
           "; ".join(problems) or "the recorded tip is an ancestor again, through the merge's second parent")

    # a record that is a name: HEAD is a commit of every repository, and another one every day
    named = commit_on(scratch, [tip], tip, {RECORD: ("100644", b"HEAD\n")}, index)
    _, _, problems = asked(named)
    expect("the record holding a name, HEAD, where a commit id belongs", not problems, False,
           "; ".join(problems) or "the name was taken for a commit", "exactly one line that is a full commit id")

    # a record naming a commit the repository does not hold
    if has_commit(repo, NOT_A_COMMIT):
        failures.append("control: %s is a commit of this repository, so it cannot stand for one that is not" % NOT_A_COMMIT)
    else:
        unheld = commit_on(scratch, [tip], tip, {RECORD: ("100644", (NOT_A_COMMIT + "\n").encode())}, index)
        _, _, problems = asked(unheld)
        expect("the record naming a commit this repository does not hold", not problems, False,
               "; ".join(problems) or "the record was taken", "is not in this repository at all")

    # a record naming a commit that holds no proof: the repository's first commit, which is in
    # every tip's history, so rule 1 holds and rule 2 is what refuses it
    base = git(repo, "rev-list", "--first-parent", commit).decode().split()[-1]
    proofless = commit_on(scratch, [tip], tip, {RECORD: ("100644", (base + "\n").encode())}, index)
    got, problems = later_tip(scratch, proofless)
    if problems or got != base:
        failures.append("control: a record naming the first commit, %s, must pass rule 1 for rule 2 to be what refuses it: %s" % (base[:12], problems or got))
    else:
        _, _, problems = asked(proofless)
        expect("the record naming %s, this repository's first commit: every tip's ancestor, and it holds no proof" % base[:12],
               not problems, False, "; ".join(problems) or "the proof could be run there", "holds no docs/history/verify_split.py")
    return failures


def remove(path):
    """Remove a scratch directory. Git writes its objects read-only, which Windows will not delete as they are."""
    def writable(function, target, _):
        os.chmod(target, stat.S_IWRITE)
        function(target)
    shutil.rmtree(path, onerror=writable)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--connect", required=True, help="a repository holding connect's import source and its removal as it merged")
    ap.add_argument("--sdk", required=True, help="a repository holding the sdk's import source and its removal as it merged")
    ap.add_argument("--dst", default=".", help="the message repository (default: the current directory)")
    ap.add_argument("--dst-rev", default="HEAD", help="the tip to check: it names the recorded tip (default: HEAD)")
    ap.add_argument("--at", help="run the proof at this commit itself, which need not be recorded")
    ap.add_argument("--controls", action="store_true")
    a = ap.parse_args()
    work = tempfile.mkdtemp(prefix="proof-")
    try:
        if a.at:
            tip = None
            commit = git(a.dst, "rev-parse", "--verify", a.at + "^{commit}").decode().strip()
            print("the proof at %s, as asked (--at): no recorded tip is read" % commit)
            tools, why = extract(a.dst, commit, os.path.join(work, "at"))
            failures = [why] if why else []
        else:
            tip = git(a.dst, "rev-parse", "--verify", a.dst_rev + "^{commit}").decode().strip()
            print("tip %s" % tip)
            commit, tools, failures = subject(a.dst, tip, os.path.join(work, "at"))
            if commit and not failures:
                print("recorded tip %s, named by %s at the tip" % (commit, RECORD))
                print("the recorded tip is an ancestor of the tip, %s commit(s) before it: nothing up to it was rewritten"
                      % git(a.dst, "rev-list", "--count", "%s..%s" % (commit, tip)).decode().strip())
        if not failures:
            failures = prove(a.dst, commit, tools, a)
            if a.controls and tip is not None and not failures:
                print()
                print("controls, of the check of a later tip:")
                failures = later_controls(a.dst, tip, commit, tools, work, a)
    finally:
        remove(work)
    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
