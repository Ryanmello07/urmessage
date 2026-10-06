#!/usr/bin/env python3
"""verify_split.py: the staged byte-level proof for the message repository's imports.

Revision 4 (2026-10-06), two changes and nothing else:
  - the sdk side is pinned from three counted runs over P_sdk (two on Ubuntu 24.04, git 2.43.0,
    Python 3.12.3; one on Windows, git 2.53.0, Python 3.14.4; one tip), its history check
    excludes the one path the second filter pass removed, and its control is the fork's
    beta/message before the SX-0 sync;
  - B/C accepts an imported merge that kept FEWER parents than its source in one case only, the
    merge analogue of the root rule below: every dropped source parent projects onto NOTHING and
    has no imported commit behind it (its side of the history never held a kept path, so it has
    no image for git-filter-repo to point at). The kept parents must match the source's in
    order and pass every ordinary parent check. With --controls, the same rule must refuse to
    drop any parent of every merge that was kept whole.

Revision 3 (2026-10-05), after red-team review. For every import the message repository has
taken so far it proves that
  D   nothing was force-pushed: base, every --previous-tip, and every commit the tip's own
      docs/history/verified-tips.txt lists is an ancestor of the tip;
  A1  each import merge is exactly its first parent's tree plus the import tree;
  A2  each import side is the projection of its pinned fork-main source, byte for byte;
  B/C every imported commit is a 1:1, byte-identical-metadata projection of one source commit,
      AND its parents are the projections of that source commit's parents: the same number in
      the same order, each parent's tree the projection of the source parent's tree, and each
      mapped parent an ancestor-or-self of the source parent. A reordered or re-parented
      history fails here even when every tree, author, committer and message is unchanged.
      No source commit that changes a kept path was dropped, and every published commit map
      (--commit-map side=file) equals the mapping computed here, in both directions;
  E   (optional) the tip tree differs from the projections ONLY by
        - the mechanical module-path rewrite of IMPORT SPECS: a small Go lexer finds the import
          declarations (they can only follow the package clause, so a fixture inside a raw
          string later in the file is never one) and the rewrite is a regex over their path
          literals, independent of rewritepaths' Go tokenizer;
        - what an adaptation manifest declares, in both directions. The same rewrite applied to
          any OTHER string or comment is a 'literal' row with a reviewed reason; a renamed path
          whose bytes changed beyond the mechanical rewrite is a 'rename+edit-to:' row, never a
          'rename-to:' row; and every edit, rename+edit and new row pins the tip blob's sha256,
          so a later change to that path has to be declared again.

Read-only on every repository: ls-tree, cat-file, rev-list, log, rev-parse, merge-base, all with
--no-optional-locks. It never checks out, so autocrlf and .gitattributes cannot influence what it
compares.

Sides (pass the ones the tip should hold with --sides):
  connect-codestyle stage 1:  CODESTYLE.md with its own history (its authors stay its authors)
  connect-core      stage 2a: message/, messagegroup/, mls/ (minus syntax), mls/syntax -> syntax/,
                    .gitattributes, .github/workflows/mls-syntax.yml
  connect-protocol  stage 2b: protocol/message* (8 files)
  sdk               stage 3:  the messaging SDK, root message*.go, urmessage/, cp3b/, livepeer/,
                    liveprobe/ and the cgo message files -> sdk/... (liveprobe.exe dropped)

Exit status 0 only if every assertion holds.
"""
import argparse
import difflib
import hashlib
import os
import re
import subprocess
import sys
import threading
from collections import Counter, defaultdict

LF = b"\n"
CR = b"\r"

# ---------------------------------------------------------------- projections

def project_connect_codestyle(path):
    return ("connect CODESTYLE.md", path) if path == "CODESTYLE.md" else None


def project_connect_core(path):
    if path.startswith("mls/syntax/"):
        return ("connect mls/syntax/ -> syntax/", "syntax/" + path[len("mls/syntax/"):])
    for d in ("message/", "messagegroup/", "mls/"):
        if path.startswith(d):
            return ("connect " + d, path)
    if path == ".gitattributes":
        return ("connect .gitattributes", path)
    if path == ".github/workflows/mls-syntax.yml":
        return ("connect mls-syntax workflow", path)
    return None


def project_connect_protocol(path):
    if path.startswith("protocol/"):
        rest = path[len("protocol/"):]
        if "/" not in rest and rest.startswith("message"):
            return ("connect protocol/message*", path)
    return None


SDK_EXTRA_FILES = {
    # the handwritten message ABI, its callbacks, header, C ABI test and runner
    "cgo/callbacks_message.c", "cgo/callbacks_message.h", "cgo/ctest/message_abi_test.c", "cgo/ctest/run.sh",
    "cgo/exports_message.go", "cgo/exports_message_test.go", "cgo/include/urnetwork_message.h",
    # the loopback acceptance harness and its alternate modfile (it requires message-server)
    "cgo/loopback_test_world.go", "cgo/loopback.go.mod", "cgo/loopback.go.sum",
    # the header text-limit check (cgo/gen/manual_exports_test.go STAYS in core: it tests core's generator)
    "cgo/gen/text_limits_test.go",
}
SDK_EXCLUDED = {"liveprobe/liveprobe.exe"}  # a 36 MB binary that never belonged in the tree


def project_sdk(path):
    if "/" not in path and path.startswith("message") and path.endswith(".go"):
        return ("sdk root message*.go -> sdk/", "sdk/" + path)
    if path.startswith("urmessage/"):
        return ("sdk urmessage/ -> sdk/urmessage/", "sdk/" + path)
    if path in SDK_EXTRA_FILES:
        return ("sdk cgo message files -> sdk/cgo/", "sdk/" + path)
    for d in ("cp3b/", "livepeer/", "liveprobe/"):
        if path.startswith(d) and path not in SDK_EXCLUDED:
            return ("sdk " + d + " -> sdk/" + d, "sdk/" + path)
    return None


SIDES = {
    "connect-codestyle": dict(
        projector=project_connect_codestyle,
        pathspecs=["CODESTYLE.md"],
        rule_counts={"connect CODESTYLE.md": 1},
        # git-filter-repo 2.47.0, connect-codestyle-paths.txt (sha256 bba6931e...8dc1), --preserve-commit-hashes,
        # over e449f7d8: produced twice on 2026-10-05 (Windows, git 2.53.0, Python 3.14.4)
        filtered_tip="d3b3b26ae388ab0d00a4039df2988bdecfb241ae",
        source_rev="e449f7d8126c0b5748f5083392a8855bac877b32",
        commits=24,
        neighbours=["LICENSE", "README.md", ".gitattributes", "layering_test.go", "DESIGNNOTES.md"],
        # the parent of 69a006b3, the last change to the file: must differ in exactly that file
        control=("e0d75562aa2344d13c7967ce402156f4222dc5d2", {"BLOB CODESTYLE.md", "BYTES CODESTYLE.md"}),
        mechanical_stage=None,
    ),
    "connect-core": dict(
        projector=project_connect_core,
        pathspecs=["message", "messagegroup", "mls", ".gitattributes", ".github/workflows/mls-syntax.yml"],
        rule_counts={"connect message/": 96, "connect messagegroup/": 66, "connect mls/": 650,
                     "connect mls/syntax/ -> syntax/": 23, "connect .gitattributes": 1,
                     "connect mls-syntax workflow": 1},
        # git-filter-repo 2.47.0, connect-core-paths.txt (sha256 32c1e6d4...58f2), --preserve-commit-hashes,
        # over e449f7d8: produced twice on 2026-10-05 (Windows, git 2.53.0, Python 3.14.4).
        filtered_tip="fbbc842d064cc4465e580be396bfdc3363907508",
        source_rev="e449f7d8126c0b5748f5083392a8855bac877b32",
        commits=465,
        neighbours=["message_pool.go", "message_framer.go", "framed_message_conn.go",
                    "protocol/subprotocol.proto", "protocol/message.proto", "protocol/Makefile",
                    "CODESTYLE.md", "LICENSE", ".github/workflows/test.yml", "layering_test.go"],
        # upstream main differs from the fork main in exactly the trigger and its needle
        control=("7ca8e222e3496552146f2d97eb09237401662c99",
                 {"BLOB syntax/layering_test.go", "BYTES syntax/layering_test.go",
                  "BLOB .github/workflows/mls-syntax.yml", "BYTES .github/workflows/mls-syntax.yml"}),
        mechanical_stage="2a",
    ),
    "connect-protocol": dict(
        projector=project_connect_protocol,
        pathspecs=[":(glob)protocol/message*"],
        rule_counts={"connect protocol/message*": 8},
        # connect-protocol-paths.txt (sha256 7afbfec9...6017), same run as above
        filtered_tip="28a9c4f132e3d7a266021e902eee8dc2f2451cea",
        source_rev="e449f7d8126c0b5748f5083392a8855bac877b32",
        commits=10,
        neighbours=["protocol/frame.proto", "protocol/frame.pb.go", "protocol/subprotocol.proto",
                    "protocol/Makefile", "protocol/transfer.proto"],
        control=None,
        mechanical_stage="2b",
    ),
    "sdk": dict(
        projector=project_sdk,
        # the history check reads every source commit that changes a kept path; the second filter
        # pass removed liveprobe.exe (36 MB, added, changed and deleted by three commits that each
        # change other kept paths too), so that one path is not a kept path
        pathspecs=[":(glob)message*.go", "urmessage", "cp3b", "livepeer", "liveprobe"] + sorted(SDK_EXTRA_FILES)
        + [":(exclude)liveprobe/liveprobe.exe"],
        rule_counts={"sdk root message*.go -> sdk/": 29, "sdk urmessage/ -> sdk/urmessage/": 61,
                     "sdk cgo message files -> sdk/cgo/": 11, "sdk cp3b/ -> sdk/cp3b/": 39,
                     "sdk livepeer/ -> sdk/livepeer/": 4, "sdk liveprobe/ -> sdk/liveprobe/": 4},
        # git-filter-repo 2.47.0, defaults as for connect: sdk-paths.stage3.txt (sha256
        # 9b685031...d169), then --invert-paths --path sdk/liveprobe/liveprobe.exe on a fresh clone,
        # both --preserve-commit-hashes, over P_sdk: three runs, one tip (2026-10-06)
        filtered_tip="e522383045379792fec68bb81614fc6be24c6030",
        # P_sdk: Ryanmello07/urnetwork-sdk beta/message after the SX-0 sync (upstream sdk 0c6462f2
        # merged in), fork tag split/source-sdk-3
        source_rev="6141b98d05bcac98d5ccae11c54c7748919017e6",
        commits=123,
        neighbours=["subprotocol_rpc_message.go", "cgo/exports_core.go", "cgo/handles.go", "cgo/callbacks.c",
                    "cgo/exports_gen.go", "cgo/include/urnetwork_sdk.def", "cgo/gen/gen.go",
                    "cgo/gen/manual_exports_test.go", "cgo/go.mod",
                    "LICENSE", ".gitattributes", "network_space.go", "device_local_provider.go"],
        # the fork's beta/message BEFORE the SX-0 sync: it lacks three upstream message test files
        # and differs in eight module files and three message tests, and in nothing else here
        control=("d20d82c1da4be370050f9d00c2b658166e024fc0",
                 {"UNEXPECTED in import: sdk/message_stream_adapter_census_extender_native_test.go",
                  "UNEXPECTED in import: sdk/message_stream_adapter_census_extender_other_test.go",
                  "UNEXPECTED in import: sdk/message_transport_fragment_rulings_darwin_test.go"}
                 | {kind + " sdk/" + path for kind in ("BLOB", "BYTES") for path in (
                     "cgo/loopback.go.mod", "cgo/loopback.go.sum", "cp3b/go.mod", "cp3b/go.sum",
                     "livepeer/go.mod", "livepeer/go.sum", "liveprobe/go.mod", "liveprobe/go.sum",
                     "message_stream_adapter_test.go", "message_transport_fragment_rulings_other_test.go",
                     "message_transport_fragment_test.go")}),
        mechanical_stage="3",
    ),
}

# ---------------------------------------------------------------- the mechanical rewrite, re-implemented

_B = r"(?![A-Za-z0-9_.\-])"   # the boundary rewritepaths applies: no identifier or path character follows
MECHANICAL = {
    "2a": [
        (re.compile(rb"github\.com/urnetwork/connect/mls/syntax" + _B.encode()), b"github.com/urnetwork/message/syntax"),
        (re.compile(rb"github\.com/urnetwork/connect/messagegroup" + _B.encode()), b"github.com/urnetwork/message/messagegroup"),
        (re.compile(rb"github\.com/urnetwork/connect/mls" + _B.encode()), b"github.com/urnetwork/message/mls"),
        (re.compile(rb"github\.com/urnetwork/connect/message" + _B.encode()), b"github.com/urnetwork/message/message"),
        (re.compile(rb'"github\.com/urnetwork/connect/`'), b'"github.com/urnetwork/message/`'),
        (re.compile(rb'"github\.com/urnetwork/connect"'), b'"github.com/urnetwork/message"'),
        (re.compile(rb"github\.com/urnetwork/connect/\*"), b"github.com/urnetwork/message/*"),
    ],
    "2b": [
        (re.compile(rb"github\.com/urnetwork/connect/protocol" + _B.encode()), b"github.com/urnetwork/message/protocol"),
    ],
    "3": [
        (re.compile(rb"github\.com/urnetwork/connect/mls/syntax" + _B.encode()), b"github.com/urnetwork/message/syntax"),
        (re.compile(rb"github\.com/urnetwork/connect/messagegroup" + _B.encode()), b"github.com/urnetwork/message/messagegroup"),
        (re.compile(rb"github\.com/urnetwork/connect/mls" + _B.encode()), b"github.com/urnetwork/message/mls"),
        (re.compile(rb"github\.com/urnetwork/connect/message" + _B.encode()), b"github.com/urnetwork/message/message"),
        (re.compile(rb"github\.com/urnetwork/sdk/urmessage" + _B.encode()), b"github.com/urnetwork/message/sdk/urmessage"),
        (re.compile(rb"github\.com/urnetwork/sdk(?![A-Za-z0-9_.\-/])"), b"github.com/urnetwork/message/sdk"),
    ],
}


def _rewrite(stage, data):
    for rx, to in MECHANICAL[stage]:
        data = rx.sub(to, data)
    return data


def mechanical_all(stage, path, data):
    """The rewrite applied to every occurrence: imports, other strings and comments alike."""
    if stage is None or not path.endswith(".go"):
        return data
    return _rewrite(stage, data)


class GoLexError(Exception):
    pass


def import_spec_spans(data):
    """Byte spans of the path literals of a Go file's import specs.

    The import declarations are the run of `import` declarations directly after the package
    clause; the language allows them nowhere else. So the scan stops at the first token after
    the package clause that is not `import`, and an import block written inside a raw-string
    fixture further down the file is never mistaken for one.
    """
    n = len(data)

    def skip(i):
        while i < n:
            c = data[i]
            if c in b" \t\r\n":
                i += 1
            elif data.startswith(b"//", i):
                j = data.find(LF, i)
                i = n if j < 0 else j + 1
            elif data.startswith(b"/*", i):
                j = data.find(b"*/", i + 2)
                if j < 0:
                    raise GoLexError("unterminated block comment")
                i = j + 2
            else:
                break
        return i

    def ident(i):
        j = i
        while j < n and (data[j:j + 1].isalnum() or data[j] == 0x5F or data[j] >= 0x80):
            j += 1
        return j

    def string_end(i):
        q = data[i:i + 1]
        if q == b'"':
            j = i + 1
            while j < n:
                c = data[j:j + 1]
                if c == b"\\":
                    j += 2
                    continue
                if c == b'"':
                    return j + 1
                if c == LF:
                    raise GoLexError("newline inside an interpreted string at byte %d" % i)
                j += 1
            raise GoLexError("unterminated string at byte %d" % i)
        if q == b"`":
            j = data.find(b"`", i + 1)
            if j < 0:
                raise GoLexError("unterminated raw string at byte %d" % i)
            return j + 1
        return None

    spans = []
    i = skip(0)
    j = ident(i)
    if data[i:j] != b"package":
        raise GoLexError("no package clause")
    i = skip(j)
    j = ident(i)
    if j == i:
        raise GoLexError("no package name")
    i = j

    def spec(i):
        if data[i:i + 1] == b".":
            i = skip(i + 1)
        else:
            j = ident(i)
            if j > i:
                i = skip(j)
        e = string_end(i)
        if e is None:
            raise GoLexError("import spec without a path at byte %d" % i)
        spans.append((i, e))
        return e

    while True:
        i = skip(i)
        if data[i:i + 1] == b";":
            i += 1
            continue
        j = ident(i)
        if data[i:j] != b"import":
            break
        i = skip(j)
        if data[i:i + 1] == b"(":
            i += 1
            while True:
                i = skip(i)
                if data[i:i + 1] == b";":
                    i += 1
                    continue
                if data[i:i + 1] == b")":
                    i += 1
                    break
                if i >= n:
                    raise GoLexError("unterminated import block")
                i = spec(i)
        else:
            i = spec(i)
    return spans


def mechanical_imports(stage, path, data):
    """The bytes rewritepaths would have produced if it touched import specs only."""
    if stage is None or not path.endswith(".go"):
        return data
    try:
        spans = import_spec_spans(data)
    except GoLexError as e:
        sys.exit("FATAL: cannot find the import declarations of %s: %s" % (path, e))
    out, at = [], 0
    for s, e in spans:
        out.append(data[at:s])
        out.append(_rewrite(stage, data[s:e]))
        at = e
    out.append(data[at:])
    return b"".join(out)

# ---------------------------------------------------------------- git helpers

def git(repo, *args, ok_codes=(0,)):
    r = subprocess.run(["git", "--no-optional-locks", "-C", repo, *args],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode not in ok_codes:
        sys.exit("FATAL: git %s in %s: %s" % (" ".join(args), repo, r.stderr.decode("utf-8", "replace").strip()))
    return r.stdout


def rev(repo, name):
    return git(repo, "rev-parse", "--verify", name + "^{commit}").decode().strip()


def is_ancestor(repo, a, b):
    return subprocess.run(["git", "--no-optional-locks", "-C", repo, "merge-base", "--is-ancestor", a, b],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0


def ls_tree(repo, commit):
    out = git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    entries = {}
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, oid = meta.decode().split(" ")
        entries[path.decode("utf-8", "surrogateescape")] = (mode, typ, oid)
    return entries


def cat_batch(repo, oids):
    oids = list(dict.fromkeys(oids))
    if not oids:
        return
    p = subprocess.Popen(["git", "--no-optional-locks", "-C", repo, "cat-file", "--batch"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def feed():
        p.stdin.write(LF.join(o.encode() for o in oids) + LF)
        p.stdin.close()
    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    for oid in oids:
        header = p.stdout.readline().decode().split()
        if len(header) != 3 or header[0] != oid:
            sys.exit("FATAL: cat-file header for %s in %s: %r" % (oid, repo, header))
        data = p.stdout.read(int(header[2]))
        p.stdout.read(1)
        yield oid, header[1], data
    writer.join()
    p.wait()


def blobs(repo, oids):
    return {oid: d for oid, t, d in cat_batch(repo, oids)}


def parse_commit(data):
    head, _, message = data.partition(LF + LF)
    headers = defaultdict(list)
    last = None
    for line in head.split(LF):
        if line.startswith(b" ") and last is not None:
            headers[last][-1] += LF + line
            continue
        k, _, v = line.partition(b" ")
        last = k.decode()
        headers[last].append(v)
    return headers, message


def commits_meta(repo, commits):
    return {oid: parse_commit(d) for oid, t, d in cat_batch(repo, commits)}


def unrelated(repo, a, b):
    r = subprocess.run(["git", "--no-optional-locks", "-C", repo, "merge-base", a, b],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return r.returncode != 0 and not r.stdout.strip()

# ---------------------------------------------------------------- checks

def expected_tree(label, repo, commit, proj):
    exp, rules = {}, Counter()
    for path, (mode, typ, oid) in ls_tree(repo, commit).items():
        hit = proj(path)
        if hit is None:
            continue
        rule, new = hit
        rules[rule] += 1
        if new in exp:
            sys.exit("FATAL: two source paths project onto %s" % new)
        exp[new] = (mode, oid, label, path, repo)
    return exp, rules


def compare_trees(exp, act, dst, verbose=True):
    fails = []
    missing = sorted(set(exp) - set(act))
    extra = sorted(set(act) - set(exp))
    fails += ["MISSING in import: %s (from %s:%s)" % (p, exp[p][2], exp[p][3]) for p in missing]
    fails += ["UNEXPECTED in import: %s" % p for p in extra]
    common = sorted(set(exp) & set(act))
    by_repo = defaultdict(list)
    for p in common:
        emode, eoid, label, old, repo = exp[p]
        amode, atyp, aoid = act[p]
        if emode != amode:
            fails.append("MODE %s: source %s, import %s" % (p, emode, amode))
        if eoid != aoid:
            fails.append("BLOB %s: source %s=%s, import %s" % (p, old, eoid[:12], aoid[:12]))
        if atyp == "blob":
            by_repo[repo].append(eoid)
            by_repo[dst].append(aoid)
    digests = {}
    for repo, oids in by_repo.items():
        for oid, d in blobs(repo, oids).items():
            digests[(repo, oid)] = (len(d), hashlib.sha256(d).hexdigest(), CR in d)
    nbytes = cr = 0
    for p in common:
        emode, eoid, label, old, repo = exp[p]
        amode, atyp, aoid = act[p]
        if atyp != "blob":
            continue
        s, d = digests[(repo, eoid)], digests[(dst, aoid)]
        nbytes += d[0]
        cr += d[2]
        if s[:2] != d[:2]:
            fails.append("BYTES %s: source sha256 %s (%d B), import %s (%d B)" % (p, s[1][:16], s[0], d[1][:16], d[0]))
    if verbose:
        print("    compared %d paths, %d bytes, %d holding a CR; missing %d, unexpected %d"
              % (len(common), nbytes, cr, len(missing), len(extra)))
    return fails


def read_commit_map(path):
    rows = set()
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            parts = line.split()
            if not parts or parts == ["old", "new"]:
                continue
            if len(parts) != 2 or not all(re.fullmatch(r"[0-9a-f]{40}", p) for p in parts):
                sys.exit("FATAL: commit map %s line %d is not 'old new': %r" % (path, n, line))
            if set(parts[1]) == {"0"}:
                continue
            rows.add((parts[0], parts[1]))
    return rows


def history_check(label, src_repo, src_tip, dst, side_tip, proj, pathspecs, published_maps, controls=False):
    fails = []
    dst_commits = git(dst, "rev-list", side_tip).decode().split()
    src_commits = git(src_repo, "rev-list", src_tip).decode().split()
    key_to_src, meta_src = defaultdict(list), {}
    for c, (h, m) in commits_meta(src_repo, src_commits).items():
        key_to_src[(LF.join(h["author"]), LF.join(h["committer"]), m)].append(c)
        meta_src[c] = h
    mapping, meta_dst = {}, {}
    for d, (h, m) in commits_meta(dst, dst_commits).items():
        meta_dst[d] = h
        cands = key_to_src.get((LF.join(h["author"]), LF.join(h["committer"]), m), [])
        if len(cands) != 1:
            fails.append("%s: imported %s matches %d source commits" % (label, d[:12], len(cands)))
            continue
        mapping[d] = cands[0]
        if h.get("encoding") != meta_src[cands[0]].get("encoding"):
            fails.append("%s: encoding header changed on %s" % (label, d[:12]))

    projected_cache, dst_cache = {}, {}

    def projected(c):
        if c not in projected_cache:
            out = {}
            for path, (mode, typ, oid) in ls_tree(src_repo, c).items():
                hit = proj(path)
                if hit:
                    out[hit[1]] = (mode, oid)
            projected_cache[c] = out
        return projected_cache[c]

    def dst_tree(c):
        if c not in dst_cache:
            dst_cache[c] = {p: (m, o) for p, (m, t, o) in ls_tree(dst, c).items()}
        return dst_cache[c]

    for d, s in mapping.items():
        exp, act = projected(s), dst_tree(d)
        if exp != act:
            fails.append("%s: tree of %s is not the projection of %s: %s"
                         % (label, d[:12], s[:12], sorted(set(exp.items()) ^ set(act.items()))[:4]))

    # the parents: a reordered or re-parented history keeps every tree and every message and
    # changes only these lines, so they are compared as carefully as the trees are
    parent_checks = 0

    def pair_holds(p, q):
        return p in mapping and dst_tree(p) == projected(q) and is_ancestor(src_repo, mapping[p], q)

    imported_sources = set(mapping.values())

    def side_holds_nothing(q):
        """Revision 4: true when source parent q projects onto no path and no imported commit lies
        behind it, so dropping it can hide no imported history: the merge analogue of the root rule."""
        if projected(q):
            return False
        behind = set(git(src_repo, "rev-list", q).decode().split())
        return not (behind & imported_sources)

    dropped_empty = []
    for d, s in sorted(mapping.items()):
        pd = [p.decode() for p in meta_dst[d].get("parent", [])]
        ps = [p.decode() for p in meta_src[s].get("parent", [])]
        if not pd:
            if ps and projected(ps[0]):
                fails.append("%s: %s is a root, and its source %s's parent %s projects onto %d paths: history was cut"
                             % (label, d[:12], s[:12], ps[0][:12], len(projected(ps[0]))))
            parent_checks += 1
            continue
        if len(pd) < len(ps):
            # the kept parents must be the source's in order; each source parent left over must be
            # a side that never held a kept path, or the history was cut or re-parented
            at, matched, dropped = 0, [], []
            for q in ps:
                if at < len(pd) and pair_holds(pd[at], q):
                    matched.append((pd[at], q))
                    at += 1
                else:
                    dropped.append(q)
            if at != len(pd):
                fails.append("%s: %s has %d parents and its source %s has %d, and the %d kept do not match the source's in order"
                             % (label, d[:12], len(pd), s[:12], len(ps), len(pd)))
                continue
            for q in dropped:
                parent_checks += 1
                if side_holds_nothing(q):
                    dropped_empty.append("%s<-%s dropped %s" % (d[:10], s[:10], q[:10]))
                else:
                    fails.append("%s: %s dropped its source %s's parent %s, whose side holds kept paths or imported "
                                 "history: the history was cut" % (label, d[:12], s[:12], q[:12]))
            pd, ps = [p for p, _ in matched], [q for _, q in matched]
        if len(pd) != len(ps):
            fails.append("%s: %s has %d parents and its source %s has %d" % (label, d[:12], len(pd), s[:12], len(ps)))
            continue
        for i, (p, q) in enumerate(zip(pd, ps)):
            parent_checks += 1
            if p not in mapping:
                fails.append("%s: parent %d of %s (%s) is not an imported commit" % (label, i + 1, d[:12], p[:12]))
                continue
            if dst_tree(p) != projected(q):
                fails.append("%s: parent %d of %s is %s, whose tree is not the projection of the source parent %s of %s: "
                             "the history is reordered or re-parented" % (label, i + 1, d[:12], p[:12], q[:12], s[:12]))
            if not is_ancestor(src_repo, mapping[p], q):
                fails.append("%s: parent %d of %s maps to %s, which is not an ancestor-or-self of the source parent %s"
                             % (label, i + 1, d[:12], mapping[p][:12], q[:12]))

    if dropped_empty:
        print("    %s: %d imported merges dropped a source parent whose side never held a kept path: %s"
              % (label, len(dropped_empty), dropped_empty))
    if controls:
        # the rule must refuse to drop any parent of a merge that was kept whole
        whole = [(d, s) for d, s in sorted(mapping.items()) if len(meta_dst[d].get("parent", [])) > 1]
        accepted = ["%s parent %d" % (d[:10], i + 1) for d, s in whole
                    for i, q in enumerate(p.decode() for p in meta_src[s].get("parent", [])) if side_holds_nothing(q)]
        print("  control: the dropped-parent rule asked about each parent of the %d merges kept whole -> %s"
              % (len(whole), "refused every one" if not accepted else "ACCEPTED %s" % accepted))
        if accepted:
            fails.append("%s: the dropped-parent control accepted %s" % (label, accepted))

    changing = set(git(src_repo, "log", "--full-history", "--no-merges", "--format=%H", src_tip, "--", *pathspecs).decode().split())
    imported = set(mapping.values())
    fails += ["%s: source commit %s changes a kept path and was not imported" % (label, c[:12]) for c in sorted(changing - imported)]
    fails += ["%s: imported non-merge %s changes no kept path" % (label, c[:12])
              for c in sorted(imported - changing) if len(meta_src[c].get("parent", [])) <= 1]
    merges = sorted(c[:10] for c in imported if len(meta_src[c].get("parent", [])) > 1)
    print("    %s: %d imported, %d mapped 1:1, %d parent edges checked; source non-merges changing kept paths %d, dropped %d; source merges kept %s"
          % (label, len(dst_commits), len(mapping), parent_checks, len(changing), len(changing - imported), merges))
    computed = {(s, d) for d, s in mapping.items()}
    for path in published_maps:
        rows = read_commit_map(path)
        miss, extra = sorted(computed - rows), sorted(rows - computed)
        print("    %s: commit map %s: %d rows, %d computed, %d missing from it, %d it holds that were not computed"
              % (label, os.path.basename(path), len(rows), len(computed), len(miss), len(extra)))
        fails += ["%s: the commit map %s lacks %s -> %s" % (label, path, s[:12], d[:12]) for s, d in miss[:20]]
        fails += ["%s: the commit map %s claims %s -> %s, which this run did not compute" % (label, path, s[:12], d[:12]) for s, d in extra[:20]]
    return fails


def find_imports(dst, tip, base):
    """Every merge in base..tip with a parent that shares no history with base is an import
    merge; that parent is the import side. Found anywhere in the graph, so a PR merged upstream
    with a merge commit (the import then on a second-parent path) is still found."""
    imports = []
    for m in git(dst, "rev-list", "--merges", base + ".." + tip).decode().split():
        ps = git(dst, "log", "-1", "--format=%P", m).decode().split()
        related = [p for p in ps if not unrelated(dst, base, p)]
        if not related:
            continue  # a merge INSIDE an imported history (e.g. connect's 197af904): it is checked by B/C
        if ps[0] not in related:
            sys.exit("FATAL: merge %s takes an unrelated history as its FIRST parent; an import is always the second" % m[:12])
        for s in ps[1:]:
            if s not in related:
                imports.append((m, ps[0], s))
    return imports


def classify(dst, side):
    paths = list(ls_tree(dst, side))
    if paths == ["CODESTYLE.md"]:
        return "connect-codestyle"
    if paths and all(p.startswith("protocol/") for p in paths):
        return "connect-protocol"
    if paths and all(p.startswith("sdk/") for p in paths):
        return "sdk"
    return "connect-core"


def union_check(dst, merge, first, side):
    m, f, s = ls_tree(dst, merge), ls_tree(dst, first), ls_tree(dst, side)
    fails = ["UNION %s: %s is in both parents" % (merge[:12], p) for p in sorted(set(f) & set(s))]
    want = dict(f)
    want.update(s)
    if want != m:
        fails.append("UNION %s: merge tree is not first-parent tree plus import tree: %s"
                     % (merge[:12], sorted(set(want.items()) ^ set(m.items()))[:5]))
    return fails, len(f), len(s), len(m)


PINNING_KINDS = ("edit", "new")


def read_manifest(path):
    """TSV: path, kind, reason[, sha256=<hex>]. '#' starts a comment.

    kind is one of
      edit                 a projected or base path whose bytes changed; pins sha256
      new                  a path in no projection and not in base; pins sha256
      literal              a .go path whose only change is the module-path rewrite of a string or
                           comment OUTSIDE its import declarations (each one reviewed: the reason
                           says what the literal means and why the new spelling means the same)
      delete               a projected path the tip does not hold
      manifest             this manifest's own place in the tree: its bytes must equal the --manifest
                           file's (a digest of itself is a fixed point no row could hold)
      rename-to:<p>        a projected path that moved to <p> with identical or mechanical bytes
      rename+edit-to:<p>   a projected path that moved to <p> and whose bytes changed; pins sha256
    """
    entries = {}
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].strip():
                sys.exit("FATAL: manifest line %d needs path, kind and a reason: %r" % (n, line))
            kind = parts[1]
            if not (kind in ("edit", "new", "literal", "delete", "manifest") or kind.startswith(("rename-to:", "rename+edit-to:"))):
                sys.exit("FATAL: manifest line %d has an unknown kind %r" % (n, kind))
            digest = None
            for extra in parts[3:]:
                if extra.startswith("sha256="):
                    digest = extra[len("sha256="):]
                elif extra.strip():
                    sys.exit("FATAL: manifest line %d has an unknown column %r" % (n, extra))
            pins = kind in PINNING_KINDS or kind.startswith("rename+edit-to:")
            if pins and (digest is None or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                sys.exit("FATAL: manifest line %d (%s %s) must pin the tip blob: sha256=<64 hex>" % (n, parts[0], kind))
            if not pins and digest is not None:
                sys.exit("FATAL: manifest line %d (%s %s) pins a digest its kind does not use" % (n, parts[0], kind))
            if parts[0] in entries:
                sys.exit("FATAL: manifest names %s twice" % parts[0])
            entries[parts[0]] = (kind, parts[2], digest)
    return entries


def adaptation_audit(dst, tip, base, sources, manifest, review_out=None, manifest_bytes=None):
    """Part E. Every path of the tip, classified; undeclared differences and unneeded
    declarations both fail."""
    fails = []
    act = ls_tree(dst, tip)
    proj = {}
    for label, (repo, rv, projector, stage) in sources.items():
        exp, _ = expected_tree(label, repo, rv, projector)
        for p, v in exp.items():
            proj[p] = v + (stage,)
    base_tree = ls_tree(dst, base)
    renamed_to = {}
    for k, (kind, reason, digest) in manifest.items():
        if kind.startswith("rename-to:"):
            renamed_to[kind.split(":", 1)[1]] = (k, "rename")
        elif kind.startswith("rename+edit-to:"):
            renamed_to[kind.split(":", 1)[1]] = (k, "rename+edit")
    want_src = defaultdict(list)
    for p in act:
        src_path = renamed_to.get(p, (p, None))[0]
        if src_path in proj:
            want_src[proj[src_path][4]].append(proj[src_path][1])
    src_bytes = {}
    for repo, oids in want_src.items():
        for oid, d in blobs(repo, oids).items():
            src_bytes[(repo, oid)] = d
    dst_bytes = blobs(dst, [v[2] for v in act.values() if v[1] == "blob"])
    tally = Counter()
    used = set()
    review = []

    def pinned(p, row, data):
        got = hashlib.sha256(data).hexdigest()
        if got != row[2]:
            fails.append("E: %s is declared (%s) at sha256 %s and the tip holds %s: a change after the declaration must be declared again"
                         % (p, row[0], row[2][:16], got[:16]))

    for p in sorted(act):
        mode, typ, oid = act[p]
        src_path, rkind = renamed_to.get(p, (p, None))
        decl = manifest.get(src_path) if rkind else manifest.get(p)
        data = dst_bytes.get(oid, b"")
        if decl and decl[0] == "manifest" and rkind is None:
            used.add(p)
            if src_path in proj or p in base_tree:
                fails.append("E: %s is declared the manifest and is also a projected or base path" % p)
            elif data != manifest_bytes:
                fails.append("E: %s is declared the manifest and its bytes are not the manifest this run read" % p)
            else:
                tally["the manifest itself"] += 1
            continue
        if src_path in proj:
            smode, soid, label, old, repo, stage = proj[src_path]
            sdata = src_bytes[(repo, soid)]
            if data == sdata and mode == smode:
                kind = "identical"
            elif mode == smode and data == mechanical_imports(stage, src_path, sdata):
                kind = "mechanical"
            elif mode == smode and data == mechanical_all(stage, src_path, sdata):
                kind = "literal"
            else:
                kind = "changed"
            if rkind:
                used.add(src_path)
                if rkind == "rename":
                    if kind in ("identical", "mechanical"):
                        tally["declared rename (%s)" % kind] += 1
                    else:
                        fails.append("E: %s is renamed from %s by a rename-to row, which allows identical or mechanical bytes only, "
                                     "and its bytes are %s: declare rename+edit-to with the reason and the tip's sha256" % (p, src_path, kind))
                else:
                    if kind in ("identical", "mechanical"):
                        fails.append("E: %s is declared rename+edit-to and its bytes are %s: an entry nothing needs (rename-to)" % (p, kind))
                    else:
                        tally["declared rename+edit"] += 1
                        pinned(p, decl, data)
                        review.append((p, src_path, mechanical_imports(stage, src_path, sdata), data))
                continue
            if kind == "changed":
                if decl and decl[0] == "edit":
                    tally["declared edit"] += 1
                    used.add(p)
                    pinned(p, decl, data)
                    review.append((p, src_path, mechanical_imports(stage, src_path, sdata), data))
                else:
                    fails.append("E: %s differs from %s:%s beyond the mechanical rewrite and the manifest does not declare it" % (p, label, old))
                    if decl:
                        used.add(p)
            elif kind == "literal":
                if decl and decl[0] == "literal":
                    tally["declared literal"] += 1
                    used.add(p)
                    review.append((p, src_path, mechanical_imports(stage, src_path, sdata), data))
                else:
                    fails.append("E: %s rewrites the module path in a string or comment outside its import declarations; that is not mechanical "
                                 "and needs a 'literal' row whose reason says what the literal means" % p)
                    if decl:
                        used.add(p)
            else:
                tally[kind] += 1
                if decl:
                    used.add(p)
                    fails.append("E: the manifest declares %s for %s, which is %s: an entry nothing needs" % (decl[0], p, kind))
        elif p in base_tree:
            if base_tree[p][2] != oid:
                if decl and decl[0] == "edit":
                    tally["declared edit (base)"] += 1
                    used.add(p)
                    pinned(p, decl, data)
                else:
                    fails.append("E: %s differs from base and is not declared" % p)
            else:
                tally["base"] += 1
                if decl:
                    used.add(p)
                    fails.append("E: the manifest declares %s for the unchanged base path %s" % (decl[0], p))
        elif decl and decl[0] == "new":
            tally["declared new"] += 1
            used.add(p)
            pinned(p, decl, data)
        else:
            fails.append("E: %s is in the tip, in no projection and not declared new" % p)
    for p in sorted(set(proj) - set(act)):
        decl = manifest.get(p)
        if decl and (decl[0] == "delete" or decl[0].startswith(("rename-to:", "rename+edit-to:"))):
            used.add(p)
            if decl[0] == "delete":
                tally["declared delete"] += 1
        else:
            fails.append("E: %s (from %s) is missing from the tip and the manifest does not declare it" % (p, proj[p][2]))
    for p in sorted(set(manifest) - used):
        fails.append("E: the manifest declares %s (%s) and nothing in the tip uses the declaration" % (p, manifest[p][0]))
    print("  part E: tip paths by kind %s" % dict(sorted(tally.items())))
    if review_out:
        os.makedirs(review_out, exist_ok=True)
        with open(os.path.join(review_out, "declared-changes.diff"), "w", encoding="utf-8", newline="\n") as f:
            for p, src_path, base_bytes, data in review:
                a = base_bytes.decode("utf-8", "replace").splitlines(keepends=True)
                b = data.decode("utf-8", "replace").splitlines(keepends=True)
                f.writelines(difflib.unified_diff(a, b, "mechanical/" + src_path, "tip/" + p))
        print("  part E: the review surface (every declared change against its mechanical baseline) is in %s"
              % os.path.join(review_out, "declared-changes.diff"))
    return fails

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sides", required=True, help="comma list of the import sides the tip must hold")
    ap.add_argument("--connect", help="a repository holding the connect source commits")
    ap.add_argument("--sdk", help="a repository holding the sdk source commits")
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dst-rev", required=True)
    ap.add_argument("--base", default="0d697b0a07fbdee660a90d995c1255673a056bba")
    ap.add_argument("--previous-tip", action="append", default=[],
                    help="a tip verified earlier; it must be an ancestor of this one (repeatable)")
    ap.add_argument("--commit-map", action="append", default=[],
                    help="side=file: a published old->new commit map, compared both ways (repeatable)")
    ap.add_argument("--controls", action="store_true")
    ap.add_argument("--expect-filtered-tips", action="store_true")
    ap.add_argument("--manifest", help="adaptation manifest; runs part E over the tip")
    ap.add_argument("--review-out", help="directory for part E's review surface")
    ap.add_argument("--no-history", action="store_true")
    a = ap.parse_args()

    wanted = [s.strip() for s in a.sides.split(",") if s.strip()]
    for s in wanted:
        if s not in SIDES:
            sys.exit("FATAL: unknown side %s" % s)
        if SIDES[s]["source_rev"] is None:
            sys.exit("FATAL: side %s is not pinned yet (source_rev, filtered_tip, rule_counts, commits); pin it from a counted run first" % s)
    maps = defaultdict(list)
    for spec in a.commit_map:
        side, _, path = spec.partition("=")
        if side not in wanted or not path:
            sys.exit("FATAL: --commit-map %r must be side=file for a side in --sides" % spec)
        maps[side].append(path)
    repo_of = {"connect-codestyle": a.connect, "connect-core": a.connect, "connect-protocol": a.connect, "sdk": a.sdk}
    failures = []
    tip, base = rev(a.dst, a.dst_rev), rev(a.dst, a.base)
    print("tip %s, base %s, sides %s" % (tip, base, wanted))

    # D
    if not is_ancestor(a.dst, base, tip):
        sys.exit("FAIL topology: base is not an ancestor of the tip; this history could only be published by force")
    earlier = list(a.previous_tip)
    listed = subprocess.run(["git", "--no-optional-locks", "-C", a.dst, "cat-file", "-p", tip + ":docs/history/verified-tips.txt"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if listed.returncode == 0:
        for line in listed.stdout.decode().splitlines():
            fields = line.split()
            if fields and not fields[0].startswith("#"):
                earlier.append(fields[0])
    for e in earlier:
        r = subprocess.run(["git", "--no-optional-locks", "-C", a.dst, "rev-parse", "--verify", "--quiet", e + "^{commit}"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            failures.append("topology: the earlier verified tip %s is not in this repository at all" % e)
        elif not is_ancestor(a.dst, r.stdout.decode().strip(), tip):
            failures.append("topology: the earlier verified tip %s is not an ancestor of the tip: that history was rewritten" % e)
    imports = find_imports(a.dst, tip, base)
    found = defaultdict(list)
    for m, first, side in imports:
        found[classify(a.dst, side)].append((m, first, side))
    print("part D: %d commits over base; %d earlier verified tips are ancestors; import merges %s"
          % (int(git(a.dst, "rev-list", "--count", base + ".." + tip)), len(earlier) - sum("earlier verified tip" in f for f in failures),
             {k: [x[0][:10] for x in v] for k, v in found.items()}))
    for s in wanted:
        if len(found.get(s, [])) != 1:
            failures.append("topology: side %s is imported %d times, want exactly once" % (s, len(found.get(s, []))))
    for s in found:
        if s not in wanted:
            failures.append("topology: the tip holds a %s import that --sides does not name" % s)
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)

    sources = {}
    for s in wanted:
        cfg = SIDES[s]
        repo = repo_of[s]
        rv = rev(repo, cfg["source_rev"])
        m, first, side = found[s][0]
        print("side %s: source %s, import merge %s, import tip %s" % (s, rv[:12], m[:12], side[:12]))
        # A1
        f, nf, ns, nm = union_check(a.dst, m, first, side)
        failures += f
        print("  A1 %d + %d = %d paths %s" % (nf, ns, nm, "OK" if not f else "FAIL"))
        same = side == cfg["filtered_tip"]
        print("  import tip %s the pinned filter-repo tip" % ("IS" if same else "is NOT"))
        if a.expect_filtered_tips and not same:
            failures.append("%s: import tip %s, pinned %s" % (s, side, cfg["filtered_tip"]))
        ncommits = len(git(a.dst, "rev-list", side).split())
        if ncommits != cfg["commits"]:
            failures.append("%s: the import side holds %d commits, pinned %d" % (s, ncommits, cfg["commits"]))
        # A2
        exp, rules = expected_tree(s, repo, rv, cfg["projector"])
        for rule, n in sorted(cfg["rule_counts"].items()):
            print("  rule %-34s matched %4d%s" % (rule, rules[rule], "" if rules[rule] == n else "   <-- pinned %d" % n))
            if rules[rule] != n:
                failures.append("%s rule %s matched %d, pinned %d" % (s, rule, rules[rule], n))
        for rule in sorted(set(rules) - set(cfg["rule_counts"])):
            failures.append("%s rule %s matched %d and is not pinned" % (s, rule, rules[rule]))
        act = ls_tree(a.dst, side)
        failures += compare_trees(exp, act, a.dst)
        src = ls_tree(repo, rv)
        for n in cfg["neighbours"]:
            if n not in src:
                failures.append("control neighbour %s does not exist in the source, so its absence proves nothing" % n)
            if any(v[3] == n for v in exp.values()):
                failures.append("control neighbour %s was projected" % n)
        print("  neighbours: %d live in the source, none projected" % sum(n in src for n in cfg["neighbours"]))
        if a.controls:
            ctl = cfg["control"]
            if ctl:
                e2, _ = expected_tree(s, repo, rev(repo, ctl[0]), cfg["projector"])
                got = compare_trees(e2, act, a.dst, verbose=False)
                keys = {g if g.startswith(("UNEXPECTED", "MISSING")) else " ".join(g.split(" ")[:2]).rstrip(":") for g in got}
                ok = keys == ctl[1]
                print("  control %s -> %s %s" % (ctl[0][:10], sorted(keys), "OK" if ok else "BROKEN, wanted %s" % sorted(ctl[1])))
                if not ok:
                    failures.append("%s: control did not fire as designed" % s)
            some = sorted(exp)[len(exp) // 2]
            others = [p for p in sorted(exp) if exp[p][1] != exp[some][1]]
            muts = [
                ("mode flipped", lambda e: e.__setitem__(some, ("100755" if e[some][0] != "100755" else "100644",) + e[some][1:]), "MODE " + some),
                ("path dropped", lambda e: e.pop(some), "UNEXPECTED in import: " + some),
                ("phantom path", lambda e: e.__setitem__("phantom/x.go", e[some]), "MISSING in import: phantom/x.go"),
            ]
            if others:
                other = others[0]
                muts.insert(0, ("bytes swapped", lambda e: e.__setitem__(some, (e[some][0],) + exp[other][1:]), "BYTES " + some))
            for title, mut, needle in muts:
                e3 = dict(exp)
                mut(e3)
                hit = any(g.startswith(needle) for g in compare_trees(e3, act, a.dst, verbose=False))
                print("  synthetic control %-14s -> %s" % (title, "detected" if hit else "MISSED"))
                if not hit:
                    failures.append("%s: synthetic control missed: %s" % (s, title))
        # B/C
        if not a.no_history:
            failures += history_check(s, repo, rv, a.dst, side, cfg["projector"], cfg["pathspecs"], maps.get(s, []), a.controls)
        sources[s] = (repo, rv, cfg["projector"], cfg["mechanical_stage"])

    if a.manifest:
        with open(a.manifest, "rb") as f:
            manifest_bytes = f.read()
        failures += adaptation_audit(a.dst, tip, base, sources, read_manifest(a.manifest), a.review_out, manifest_bytes)

    print()
    if failures:
        print("FAIL (%d)" % len(failures))
        for f in failures[:200]:
            print("  " + f)
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
