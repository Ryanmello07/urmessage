# livepeer — the second party

`liveprobe` drives BOTH sides of a conversation in one process. `livepeer` drives ONE side, so the
other side can be a different process: the Windows app.

## Why it exists

A solo device cannot open a group. `Group.Open` comes after `AddMember`, the alpha accepts exactly
one `AddMember`, and one credential means one key package — so a client holding a single credential
founds a group at epoch 0 that never opens, and every send is refused. The missing half is a second
party under a **second account**, and this is it.

## The seam: two files, each deleted by whoever consumes it

```
  the app (user1)                              livepeer (user2)
  ───────────────                              ────────────────
  device_key_package() -> -keypackage     →    reads it, deletes it
                                               CreateGroup, AddMember(kp), Open
  reads it, deletes it                    ←    invite.Encode() -> -invite
  device_join(invite)                          Send / SendReply / React / Delete, then fetch in a loop
```

A key package is **single use** — the private halves are taken destructively at the join — so a
stale key-package file read by a later run builds an invite the app *cannot* join, and the failure
lands at the join rather than at the read. Deleting on consumption is what makes "the file is
there" mean "the file is fresh".

## Running it

```
GOTOOLCHAIN=$(bash ../../scripts/toolchain.sh) go build -o livepeer.exe .

./livepeer.exe \
  -jwt        %LOCALAPPDATA%\URmessage\dev\user2.jwt \
  -dir        %LOCALAPPDATA%\URmessage\dev\peer \
  -keypackage %LOCALAPPDATA%\URmessage\dev\app.keypackage \
  -invite     %LOCALAPPDATA%\URmessage\dev\app.invite \
  -serve 4m
```

Then launch the app with `--live`. Order does not matter: each side polls for the other's file.
The app writes its key package when it holds no group, and restores from disk on every later run —
so the handshake happens **once** and a second run of this helper against an app that already
joined will simply wait, because no key package is published.

Between two machines the files become the **codes** the app's dialogs show and take:
`-joincode <code | @FILE>` takes the app's join code, and `-printinvite` prints the invitation for
the person to paste back. `-invitecodeout FILE` writes that invitation code to `FILE` (0600)
instead of printing it, so a run whose output is a log keeps no code in it.

## The join road: the app founds, livepeer joins

```
  the app (founds)                             livepeer -join
  ────────────────                             ──────────────
                                          ←    device.KeyPackage() -> JOIN CODE, printed or -joincodeout
  add dialog: AddMember(code), Open
  invite.Encode() -> INVITE CODE          →    -invitecode @FILE: waits for it, reads it, deletes it
                                               ParseInvite, device.Join(invite)
  send / receive                               Send / SendReply / React / Delete, then fetch in a loop
```

```
./livepeer.exe -jwt <user2 or user3 credential> -dir <this peer's own dir> \
  -join -joincodeout <join code file> -invitecode @<invite code file> -wait 30m -serve 30m
```

It restores first, as the founder road does. Holding no group, it makes its own join code and
writes it to `-joincodeout` (0600, exactly the text the app's join-code box takes; without the
flag it is printed once instead). Give that code to the founder. Paste the invitation their app
makes into the `-invitecode` file: livepeer waits for it up to `-wait`, drops whitespace and line
breaks as the app does, deletes the file the moment it has read it, joins, prints the roster and
talks as the founder road does (`-outbox`, `-quiet`, `-serve`, `-poll`). A restart over the same
`-dir` restores the joined group and goes straight to talking.

`-join` takes none of `-keypackage`, `-joincode`, `-invite`, `-printinvite`, `-invitecodeout`, and
needs `-invitecode`. A refused invitation exits non-zero with the library's own sentence and one
line saying what to do: an invitation made from another join code (`ErrNoJoinCodeForInvite`), one
made by an older build (`ErrInviteVersion`), and a code that is not an invitation, or not all of
one (`ErrInviteDamaged` and the parse's other refusals; this peer's own join code pasted back is
told apart by its octets).

## Its identity

Every group this build founds requires an identity of each member, and a device with no identity
publishes no join code. So on a first run over a `-dir`, once it is connected, livepeer makes its
identity as a person does: the 25 words offered, typed back at once, and the identity made, its
self group founded under the connection. **The words are cleared as soon as they are typed back,
and never printed, logged or written.** A restart over the same `-dir` reads the identity back off
the disk. Either way it prints the identity as digests only: the SHA-256 of its account ID and of
its device ID, never either one.

The roster is printed **by identity**: one line per person, with each of their devices (its leaf,
its role, and the digest of its device ID), this peer's own identity marked. A conversation of two
people reads as two lines however many devices each has.

## Talking, and deletes

On either road, every line appended to the `-outbox` file is sent. A line that is exactly `/delete`
sends nothing: it deletes the line this run last sent from the outbox, with a tombstone. A delete
adds no line of its own: it flips `Deleted` on a line already shown. So each fetch also reads the
log for flips, and prints `<- DELETED: message <id> from <sender>, record <n>, is now deleted=true`
for each line deleted since the last fetch, whichever side deleted it. At the end the report lists
the whole log, one row per line, with its kind, its sender and whether it is deleted.

## Rules that are not style

* **NEVER run this under the app's own account.** Two clients at one `client_id`, or two state
  directories descended from one, is two devices at one MLS leaf: one `sender_handle`, one stream
  counter, therefore a reused `(epoch, sender_handle, stream_index)` — a reused nonce under a reused
  record key, which the spec calls a total break of both AEADs. The app is user1; this is user2;
  each gets its own `-dir`. Two of these talking to each other, a founder and a `-join`, are two
  accounts and two `-dir`s the same way: user2 and user3.
* **The credential is a secret.** It is read from a path and never printed; the only thing said
  about it is its length.
* **Treat the invite as secret.** It carries the Welcome, and it names the group and who is in
  it. It is written 0600, to a path outside any repository, and deleted as soon as it has been
  used. Neither file may ever enter a working tree. Since invite version 3 only the device whose
  join code was added can open it; it still names the group and its members.
* **Keep codes out of logs.** The join code is not a secret, but like the app this keeps it out of
  logs: with `-joincodeout` and `-invitecodeout` the codes go to 0600 files and are not printed.
* **`-dir` must not be inside a repo either** — it holds the durable MLS state.

## What it asserts, and what it does not

It checks the Hello answered `REASON_OK`, that a freshly founded group is at epoch 0, that the
commit adding the app leaves it at epoch 1, and that `Open` actually reports the group open. It
does **not** assert anything about the far side: a member joining is invisible from here, because
the Welcome is opened by the joiner and the server is told nothing. The only signal that the app
joined is that it deleted the invite, and that is reported as a signal rather than as proof.
