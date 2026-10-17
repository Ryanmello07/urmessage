package urmessage

import (
	"sort"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// ITEM 243's CENSUS: pq_secret GOES WHERE THE DISPOSITION BELOW SAYS IT GOES
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY THIS FILE EXISTS, AND IT IS S2-26's FINDING REPEATING ON THE ONE VALUE THE COMMIT BEFORE IT
// WAS ABOUT. `pq_secret` is the only post-quantum material in this system -- ledger item 251
// measured connect/mls's HPKE hard-wired to X25519, so the MLS exporter carries no post-quantum
// contribution at all -- and item 243's step 3 widened it from ONE scalar on a [Group] to a
// 32-entry table plus a list of staged wrap candidates, WITHOUT adding a census. The two dataflow
// gates this package already had could not see it: epochkeygate_test.go's net starts at
// {WriteKey, ReadKey, GetWriteKey, GetReadKey}, and wrapseedgate_test.go's starts at the device's
// X-Wing seed and STOPS at `openWrapToOwnLeaf|return`, whose own disposition entry says the
// payload there "is the caller's to file in [Group.pqSecrets], and is erased by that table's own
// discipline" -- it hands the value off, and nothing picked it up.
//
// MEASURED, on the commit this file repairs. MUTANT ADV-M1: `resolvePqSecretLocked`'s final
// ErrNoWrapForEpoch string was changed to carry `(held %x)`, where `held` is
// `self.pqSecrets[self.epoch]` -- this group's live post-quantum secret, in a production error
// string, in every log that error ever reaches, on an arm reachable for real.
//
//	go test ./urmessage -run '.*' -timeout 1800s -count=1   ->  ok  6.609s      SURVIVED
//
// The control, in the same harness and firing for its own reason: the identical shape planted over
// an EPOCH KEY -- `%x` of `writeKey` in publishCommitLocked's digest error -- went red at
// `epochkeygate_test.go:665: sink site "publishCommitLocked|return" has no entry in the
// disposition`. So the harness and the suite do kill this shape WHEN A GATE COVERS THE VALUE, and
// for `pq_secret` none did.
//
// WHAT THE REPORT CLAIMED AND WHY IT WAS NOT ENOUGH. The step-3 report's section 7 recorded "a
// leak grep over the whole diff with two planted controls, CONTROLS HIT 2 of 2". That is a
// measurement of ONE DIFF and it is not a gate: it cannot refuse the next commit, and the next
// commit is where ADV-M1 lands. This file is the refusal.
//
// THE NET IS DELIBERATELY WIDE AND THE WIDTH IS COVERAGE RATHER THAN CONFUSION. A `pq_secret`
// spends its life inside containers -- a [Group], a [GroupSession], a [GroupRecord], a
// [stagedRotation], a [wrapCandidate], a [restoredPqSecret], an [EpochPqSecret] -- and a walk over
// names cannot tell a derivation from a copy, so `group`, `session`, `record`, `body` and
// `newRoot` are all tainted and all dispositioned. Two of those are worth naming because they
// bring in OTHER key material: `publishCommitLocked`'s `writeKey`/`readKey` are the epoch-key
// gate's subject reached from the pq side, and `sealEpochWrapLocked`'s `body` is a ciphertext.
// They are key material too. They are censused, dispositioned by name, and nothing here pretends
// the walk tells them apart.
//
// IT IS THE OTHER TWO GATES' SHAPE AND IT SHARES THEIR ENGINE RATHER THAN COPYING IT. See
// census_test.go: [runCensus] is the walk, [censusBorneBy] is the one predicate, and the three
// scars those two files were beaten for -- match the VALUE not the field name, ask every landing
// place for an EXPRESSION not an *ast.Ident, follow EVERY binding form -- are inherited here
// mechanically instead of being copied a third time by hand. The mutation table at the foot of
// this file drives all three at `pq_secret`.
//
// WHERE IT DIFFERS FROM BOTH OF THEM: A COUNT OF A SECRET IS NOT A SECRET, and this value is
// counted in NINETEEN places -- every width refusal, every capacity hint, every arity switch in
// the durable record's two codecs. The narrowing is [censusBorneBy]'s refusal to look through the
// builtin `len`, and IT IS ASSERTED AND NOT MERELY PRINTED: every site it removed is collected in
// [pqSecretCountedNotCarriedSites] and held BOTH WAYS, so an excluded site is a site somebody
// weighed and wrote down, and the day the tree stops counting the secret at one of them this file
// goes red. Mutants M3 and M7 drive it from its two opposite sides.

// The names that PRODUCE a pq_secret, in any of the positions a name can produce one: the callee
// of a call, a bare field read, a parameter this function was handed, or a result of a function
// this net already names. This is the SEARCH NET rather than a disposition -- a name here that no
// site uses costs nothing and widens the net, while a producer spelled some other way is a
// blindness this gate cannot see, which is what [pqSecretProducerSites] is held BOTH WAYS for.
//
//   - THE TWO MINTS. `NewPqSecret` is the draw, at the founding and at every rotation.
//     `OpenWrapBody` is connect's opener, whose second result is a wrap's payload -- the other
//     way a secret comes into existence in a member that did not draw it. Seeding at the OPENER
//     and not at `openWrapToOwnLeaf`'s call site is what puts device.go inside this census.
//   - THE READERS. `pqSecretLocked`, `pqSecretAtLocked` and `resolvePqSecretLocked` are the three
//     functions that answer a secret, and `pqSecrets` is the field itself.
//   - THE PERSISTED SPELLINGS. `PqSecret`, `PqSecrets`, `rows`, `table` and `secret` are how the
//     durable record, the restore and the staged candidates spell it. `secret` and `rows` and
//     `table` are wide on purpose: they are the names the value has when it has no name of its
//     own, which is the gap the wrap-seed gate's `parts` entry was added to close.
//   - `into` IS THE INVITE DECODE'S POINTER TABLE, and it is here for one shape: `field.into` is
//     a `*[]byte` aimed at a field of the invite, so a `%x` of `*field.into` in ParseInvite's own
//     refusal would be that field in an error string. Since invite version 3 no field it aims at
//     is a secret in the clear. The name stays, so that a secret field given to an invite later is
//     in this net from the day it is added. Without it that expression carries only `field`,
//     which the refusal is already permitted to format.
//   - `parts` IS THE DURABLE RECORD'S ROAD, in BOTH directions, and it is here because a mutant
//     survived without it. It is seeded as a PARAMETER only -- [groupRecordOf] on the read side,
//     [DurableStateStore.writeRecord] and [encodeStateRecord] on the write side -- which is what
//     keeps the widening off the seven other readers that spell their own record `parts` as a
//     local. See pq-M2 in the mutation table: `%x` of `parts[1]`, the persisted pq_secret itself,
//     inside the group record's own decode, survived the whole suite while that decode was the
//     body of a loop and its record had no name a walk could seed.
var pqSecretProducerNames = map[string]bool{
	"openJoinSeal":          true,
	"decodeJoinSecrets":     true,
	"NewPqSecret":           true,
	"OpenWrapBody":          true,
	"openWrapToOwnLeaf":     true,
	"pqSecretLocked":        true,
	"pqSecretAtLocked":      true,
	"resolvePqSecretLocked": true,
	"restoredPqSecrets":     true,
	"pqSecretsMapOf":        true,
	"pqSecretRecordsLocked": true,
	"encodePqSecretTable":   true,
	"decodePqSecretTable":   true,
	"pqSecrets":             true,
	"PqSecrets":             true,
	"PqSecret":              true,
	"pqSecret":              true,
	"secret":                true,
	"rows":                  true,
	"table":                 true,
	"into":                  true,
	"parts":                 true,
}

// pqSecretSink is one entry in the disposition below: WHICH VALUES a site may receive, and why. A
// disposition keyed on the site alone excuses the site FOREVER, whatever turns up there later, so
// each entry names the exact spellings it weighed and is held both ways on those too. That second
// hold is what makes an entry for a formatting site safe: `restoreOne|call fmt.Errorf` is allowed
// to carry `row` -- it formats `row.epoch` -- and a `%x` of `row.secret` at that same call carries
// a spelling the entry does not list and is refused.
//
// AND EACH ENTRY HOLDS ITS OCCURRENCES (LRI R68, L2-01): every value that lands at the site, spelled
// as the source spells it and without its line, as a multiset. A site is keyed by its function and
// its callee and its carried set is a union, so a second landing of a name the site already carries
// moves neither; it moves the occurrences. `fmt.Errorf("%x", part)` beside a `part[0]` the entry
// already formats carries no new name and is refused here as a new occurrence.
type pqSecretSink struct {
	carries []string
	occurs  []string
	why     string
}

var pqSecretProducerSites = map[string]string{
	"epochKeysDigestOver|parameter pqSecret":   "the candidate a joiner, or the founder, recomputes H(epoch_keys) from.",
	"encodeJoinSecrets|parameter pqSecret":     "the secret of the epoch an add opens, arriving at the payload's encoder.",
	"decodeJoinSecrets|result epochKeysDigest": "the last third, which is the PUBLIC digest. It is in this census because the net takes every result of a producer.",
	"decodeJoinSecrets|result groupHandleKey":  "the second third: the group's handle key, which is secret, and is held to the same dispositions as the secret beside it.",
	"decodeJoinSecrets|result pqSecret":        "the first third of the payload: the secret of the epoch the joiner is admitted at.",
	"decodeJoinSecrets|parameter pqSecret":     "the named result the first third of an opened join_secrets_v1 is answered through.",
	"AddMember|self.pqSecretLocked": "THE FOUNDING EPOCH'S SECRET, READ FOR THE JOIN SEAL. Epoch one's secret travels sealed " +
		"inside [Invite.JoinSeal], to the key the joiner's leaf publishes, because the only other " +
		"member is holding the Welcome and has no leaf to address a wrap to yet.",
	"foundGroupLocked|messagegroup.NewPqSecret": "THE FOUNDING DRAW. The group's first pq_secret, at epoch zero, and the only one drawn " +
		"outside [Group.stageEpochRotationLocked]. One founding body draws it for a conversation " +
		"([Device.CreateGroup]) and for the self group ([Device.ConfirmWords]) alike (identity phase 1's " +
		"Task 12).",
	"ParseInvite|field.into":                        "T",
	"PutGroupRecord|encodePqSecretTable":            "the table as the one octet string part six is.",
	"PutGroupRecord|record.PqSecret":                "the scalar the record still carries, part two.",
	"PutGroupRecord|record.PqSecrets":               "the table, part six, or nil for a caller that built neither.",
	"decodePqSecretTable|result rows":               "the rows read back out of it.",
	"dropPqSecretsBelowWindowLocked|self.pqSecrets": "the window's own pass: every entry PastEpochWindow behind is erased and dropped.",
	"dropWrapCandidatesLocked|candidate.secret":     "every staged candidate for a resolved epoch, on its way to the erase.",
	"encodePqSecretTable|parameter rows":            "the rows arriving at the encoder.",
	"encodePqSecretWitness|parameter rows": "THE WITNESS'S ROWS, AND THEY CARRY DIGESTS AND NOT SECRETS. They are in this census " +
		"because the producer net seeds any parameter named `rows`, which is an " +
		"over-approximation and is the correct one to keep: the day somebody writes a witness " +
		"encoder that takes secrets, it is already inside this gate. What these rows hold is " +
		"[sha256.Size] octets of SHA-256 per epoch -- see [GroupRecord.PqSecretWitness] for why " +
		"the answer to 'have I ever held this' is kept for ever while the secret is not.",
	"sortEpochPqSecretWitness|parameter rows": "the same rows arriving at the sort, seeded for the same reason and carrying the same " +
		"digests.",
	"encodeLeafOccupancy|parameter rows": "THE LEAF LEDGER'S ROWS, AND THEY CARRY LEAF INDICES AND EPOCHS AND NOT SECRETS. In " +
		"this census for the witness encoder's reason one entry up -- the producer net seeds any " +
		"parameter named `rows`, an over-approximation kept on purpose -- and what these hold is " +
		"ledger item 245's part nine: u32(leaf), u64(departed_epoch) and a flags octet. Every " +
		"field of it is a number that is already in the plaintext header of a record the server " +
		"stores, or in the ratchet tree every member holds.",
	"sortLeafOccupancy|parameter rows": "the same rows arriving at the sort, seeded for the same reason and carrying the same " +
		"numbers.",
	"witnessPqSecretLocked|parameter pqSecret": "THE SECRET ARRIVING AT THE WITNESS, and this one IS a pq_secret: the whole point of the " +
		"function is that a value is hashed here and the hash is what is kept. It arrives from " +
		"[Group.filePqSecretLocked] -- the one door a row goes in by -- so there is no site that " +
		"can file a secret without leaving a witness of it.",
	"encodePqSecretTable|result encoded":    "the assembled octet string, which IS the secrets.",
	"encodePqSecretTable|row.PqSecret":      "one row's octets, counted and then appended.",
	"encodeStateRecord|parameter parts":     "THE SECOND, and the last place the record is a Go value before it is octets in a frame.",
	"filePqSecretLocked|parameter pqSecret": "THE TABLE'S WRITE PATH: the value arrives with a name and is COPIED in.",
	"filePqSecretLocked|self.pqSecrets": "the entry about to be replaced, read so that it can be ERASED rather than merely " +
		"overwritten.",
	"groupRecordLocked|self.pqSecretLocked": "the CURRENT epoch's secret, which is part two of the record and what a build from before " +
		"the table reads.",
	"groupRecordLocked|self.pqSecretRecordsLocked": "the table itself, part six.",
	"groupRecordOf|decodePqSecretTable":            "the six-part arm's table decode.",
	"groupRecordOf|parameter parts": "THE READ PATH'S RECORD, AND THE REASON THAT DECODE IS A FUNCTION AT ALL. Inside " +
		"[DurableStateStore.GroupRecords] these were a LOCAL called `parts` -- a generic record " +
		"off a generic read -- and no clause of this walk seeds a local, so `%x` of `parts[1]`, " +
		"the persisted pq_secret itself, was refused by nothing. Mutant pq-M2 measured it " +
		"surviving the whole suite. A parameter has a name to seed.",
	"groupRecordOf|record.PqSecrets": "the decoded table being filed on the record.",
	"ingestCommitLocked|self.pqSecretLocked": "the fallback when that resolution failed: the last secret this device holds, so the " +
		"handle, the table and the session stay in step while [Group.wrapDark] says what " +
		"happened.",
	"ingestCommitLocked|self.resolvePqSecretLocked": "THE RECEIVE LEG'S DECISION: which secret the epoch this commit opens actually runs on, " +
		"judged against the commit's own authenticated H(epoch_keys).",
	"ingestWrapLocked|self.device.openWrapToOwnLeaf": "the payload arriving in this package, one frame out from the mint.",
	"initTables|self.pqSecrets": "THE OWNERSHIP PASS. Every entry is copied so that 'an entry of this table is this " +
		"group's to erase' is true of every construction -- the aliasing hazard the window " +
		"exposed.",
	"openWrapToOwnLeaf|messagegroup.OpenWrapBody": "THE MINT ON THE RECEIVING LEG. connect's opener answers the wrap's payload, which under " +
		"ruling 36 is how a rotated secret reaches another member at all. Seeding at the OPENER " +
		"and not at the call one frame out is what puts device.go inside this census.",
	"pqSecretAtLocked|result secret": "its result, which is the entry itself and not a copy -- see the function's own doc for " +
		"why.",
	"pqSecretAtLocked|self.pqSecrets":      "THE ONE TABLE LOOKUP every other reader in this package goes through.",
	"pqSecretLocked|result secret":         "the same value handed on.",
	"pqSecretLocked|self.pqSecretAtLocked": "the current epoch's entry, through that same one lookup.",
	"pqSecretRecordsLocked|result records": "those rows, handed to the record builder.",
	"pqSecretRecordsLocked|self.pqSecrets": "the table read out into the rows a [GroupRecord] persists.",
	"pqSecretsMapOf|parameter table":       "the restored table arriving as a parameter.",
	"pqSecretsMapOf|result secrets":        "the map a [Group] holds.",
	"pqSecretsMapOf|row.secret":            "one row's octets on the way into the map.",
	"pqSecretsShowRotation|parameter table": "the restored table, read for the ONE fact a restarted device can observe: two different " +
		"values.",
	"pqSecretsShowRotation|table.secret":  "the two octet strings the constant-time comparison is over.",
	"publishCommitLocked|staged.pqSecret": "the staged rotation's secret, taken off the [stagedRotation] this commit was built with.",
	"pqSecretHeldAtLocked|self.pqSecrets": "the whole LIVE table, read row by row by the removal rule's comparison, beside the " +
		"witness that the window does not prune. It is not the current epoch's row, and it is not " +
		"the live table alone either: the member a commit removes keeps every row it ever SAW, and " +
		"this device's window throws rows away. See [Group.pqSecretWitness].",
	"resolvePqSecretLocked|candidate.secret": "one opened wrap's payload, a candidate for this epoch.",
	"resolvePqSecretLocked|result secret": "the resolution's ONE exit taking whichever arm's secret is being answered. Every arm that " +
		"can carry a pq_secret hands it here, which is what the removal rule is attached to. It " +
		"REPLACED `resolvePqSecretLocked|result held`, and this census refusing the stale entry by " +
		"name is the entry-with-no-site direction doing its job: `held` stopped being a result of " +
		"this function the moment the arms stopped returning it themselves.",
	"resolvePqSecretLocked|self.pqSecretAtLocked": "the held secret, which is the compatibility arm's own candidate.",
	"restoreOne|pqSecretsMapOf":                   "the same table as the map the restored group runs on.",
	"restoreOne|restoredPqSecrets":                "the decode of whatever arity the record came back with.",
	"restoreOne|row.secret":                       "one past epoch's secret on its way into connect's own table.",
	"restoredPqSecrets|record.PqSecret":           "the five-part store's scalar -- every group on the deployed alpha.",
	"restoredPqSecrets|record.PqSecrets":          "the six-part store's table, nil when the record was written before it existed.",
	"restoredPqSecrets|result current":            "the entry at the epoch the record names, which the session is constructed with.",
	"restoredPqSecrets|result table":              "the whole restored table.",
	"restoredPqSecrets|row.PqSecret":              "one persisted row's octets.",
	"sealEpochWrapLocked|parameter pqSecret": "the value being sealed into one device wrap body, addressed to one leaf's published " +
		"X-Wing key.",
	"sortEpochPqSecrets|parameter rows": "the rows arriving at the sort, which moves secrets between positions and is why the " +
		"order is part of the value.",
	"stageEpochRotationLocked|messagegroup.NewPqSecret": "THE ROTATION'S DRAW, item 243's own sentence: a fresh secret for the epoch each commit " +
		"opens. Everything else in that function descends from it.",
	"writeRecord|parameter parts": "THE FIRST OF THE TWO CALLS BETWEEN A GROUP RECORD AND THE DISK. Every durable value in " +
		"this package goes through it, the group record among them, and the secret arrives here " +
		"as one of six `parts` with no name of its own left. It is the same entry " +
		"wrapseedgate_test.go added for the seed, seeded by the same clause.",
	"zeroizePqSecretsLocked|self.pqSecrets":        "the whole-table erase at [Group.Close].",
	"zeroizeWrapCandidatesLocked|candidate.secret": "the same, whatever epoch it is for, at Close.",
	"openJoinSeal|self.openWrapToOwnLeaf":          "THE OPEN: the join seal, to this device's own X-Wing key, through the one door every later epoch's wrap is opened through.",
	"openJoinSeal|decodeJoinSecrets":               "the three values cut out of the opened payload.",
	"openJoinSeal|parameter pqSecret":              "the named result the joiner's half answers the secret through.",
	"sealJoinLocked|parameter pqSecret":            "the secret of the epoch the staged commit opens, handed in by whichever adder is sealing.",
	"Join|self.openJoinSeal":                       "THE JOINER'S ARRIVAL SINCE INVITE VERSION 3: the two secrets of the epoch it is admitted at, opened from the invite's join seal inside the join's window. An invite no longer carries either in the clear.",
	"openJoinSeal|result pqSecret":                 "what the joiner's half answers once the seal is authenticated, opened and checked.",
	"openJoinSeal|result groupHandleKey":           "the same, for the group's handle key.",
	// ── R68: SITES THE WALK REACHES INSIDE THIS PACKAGE'S OWN FUNCTIONS. The walk follows a value it holds into
	// the function it is handed to, to a fixpoint (the review of identity phase 1's Tasks 8 to 10, L1-1), and a
	// map's key is a carried value (L2-02); these rows are the sites that brought into view, each with its reason.
	"PutGroupRecord|parameter record":                 "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"abandonJoined|parameter group":                   "Reached by the walk into this package's own functions (LRI R68): a join being abandoned: the Group's id and epoch name the state to erase, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is. A group id and an epoch are public.",
	"alignedEpochKeys|parameter delivery":             "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, delivered to the server beside the commit (ruling 33): the server is handed them on purpose, as the delivery's own rows say, and the commit they are aligned with is a sealed record, ciphertext and public header fields.",
	"alignedEpochKeys|parameter record":               "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, delivered to the server beside the commit (ruling 33): the server is handed them on purpose, as the delivery's own rows say, and the commit they are aligned with is a sealed record, ciphertext and public header fields.",
	"clearPendingLocked|parameter groupId":            "Reached by the walk into this package's own functions (LRI R68): the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	"cloneRefusalLocked|parameter reason":             "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record whose stream index was reused: the reason and the record's header stream index are formatted and kept as the device's sticky refusal, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"cloneRefusalLocked|parameter record":             "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record whose stream index was reused: the reason and the record's header stream index are formatted and kept as the device's sticky refusal, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"commitCarriesItsKeys|parameter record":           "Reached by the walk into this package's own functions (LRI R68): a sealed commit record read for its server attachment's kind: the attachment is public and inside the write_auth preimage. The walk follows the record whole.",
	"decodeJoinSecrets|parameter payload":             "Reached by the walk into this package's own functions (LRI R68): an opened join payload cut into its three values, as copies: the pq_secret, the handle key and the epoch keys digest. The payload was sealed to this device and opened by it; what it answers is installed by the join, whose rows hold it, and the caller erases the payload.",
	"decodeLeafOccupancy|parameter encoded":           "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	"decodePqSecretTable|parameter encoded":           "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	"decodePqSecretWitness|parameter encoded":         "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	"decodeRemoval|parameter part":                    "Reached by the walk into this package's own functions (LRI R68): a group record's removal mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	"decodeWrapDark|parameter part":                   "Reached by the walk into this package's own functions (LRI R68): a group record's wrap-dark mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	"deleteGroupStateAt|parameter epoch":              "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	"deleteGroupStateAt|parameter groupId":            "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	"encodeJoinSecrets|parameter epochKeysDigest":     "Reached by the walk into this package's own functions (LRI R68): the epoch keys digest, public, framed into join_secrets_v1 beside the pq_secret.",
	"encodeRemoval|parameter epoch":                   "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	"encodeRemoval|parameter kind":                    "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	"encodeWrapDark|parameter epoch":                  "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	"encodeWrapDark|parameter kind":                   "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	"epochDir|parameter groupId":                      "Reached by the walk into this package's own functions (LRI R68): a group's epoch directory, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"epochKeyDelivery|parameter readKey":              "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	"epochKeyDelivery|parameter writeKey":             "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	"epochKeysFor|parameter readKey":                  "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	"epochKeysFor|parameter record":                   "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	"epochKeysFor|parameter writeKey":                 "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	"epochRaceRefusal|parameter reason":               "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record that lost an epoch race: the reason, a server code, and the record's header epoch are formatted, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"epochRaceRefusal|parameter record":               "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record that lost an epoch race: the reason, a server code, and the record's header epoch are formatted, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"eraseJoinedRecord|parameter groupId":             "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedState|parameter epoch":                "Reached by the walk into this package's own functions (LRI R68): a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	"eraseJoinedState|parameter groupId":              "Reached by the walk into this package's own functions (LRI R68): a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	"groupDir|parameter groupId":                      "Reached by the walk into this package's own functions (LRI R68): a group's directory, built from its id. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is; a group id is public, and so is the path.",
	"groupRecordPath|parameter groupId":               "Reached by the walk into this package's own functions (LRI R68): a group record's path, built from the group's id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"haltLocked|parameter refusal":                    "Reached by the walk into this package's own functions (LRI R68): the group's halt, a refusal error kept as the reason the group stops; the error is built of public facts about a record, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"holdReplacing|parameter group":                   "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	"hold|parameter group":                            "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	"isEpochWrapRecord|parameter record":              "Reached by the walk into this package's own functions (LRI R68): a sealed record read for whether its public server attachment is an epoch wrap.",
	"joinAuthPreimage|parameter joinSeal":             "Reached by the walk into this package's own functions (LRI R68): the join MAC's preimage: the join seal is ciphertext, hashed with SHA-256, and the hash goes into the preimage, every part of which is public.",
	"matchesEpochDigestLocked|parameter candidate":    "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	"pendingPath|parameter groupId":                   "Reached by the walk into this package's own functions (LRI R68): a group's pending-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"persistGroup|parameter record":                   "Reached by the walk into this package's own functions (LRI R68): the restore path's write of a group record through the store. The record holds the pq_secret table, which the durable store persists by design (the record's own row); persistGroup hands it on and keeps nothing.",
	"pqSecretHeldAtLocked|parameter candidate":        "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret hashed and compared with the digests this device has witnessed: SHA-256 of it, compared in constant time; nothing is kept.",
	"projectionOf|parameter record":                   "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"recordedPath|parameter groupId":                  "Reached by the walk into this package's own functions (LRI R68): a group's recorded-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"refuseRemovalOnHeldSecret|parameter heldAt":      "Reached by the walk into this package's own functions (LRI R68): the refusal of a removal that reuses a secret this device has held: heldAt is the EPOCH it was held at, a number, which the refusal prints so that a stale secret and a replayed one can be told apart.",
	"removeLocked|parameter path":                     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	"sealFoundingJoinLocked|parameter foundingSecret": "Reached by the walk into this package's own functions (LRI R68): the founding seal: the founding secret, a pq_secret, sealed to the joiner and digested as H(epoch_keys), which is public. The seal is ciphertext and the MAC is public.",
	"sealJoinLocked|parameter epochKeysDigest":        "Reached by the walk into this package's own functions (LRI R68): the epoch keys digest a commit publishes, which is public; it goes into the join secrets beside the pq_secret, which the existing rows hold.",
	"sendSealedLocked|parameter record":               "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"sendSealedLocked|parameter send":                 "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"stateEpochName|parameter epoch":                  "Reached by the walk into this package's own functions (LRI R68): an epoch's file name, the epoch in decimal, which is public and is carried as a field of a record that holds the pq_secret table.",
	"stateNameOf|parameter key":                       "Reached by the walk into this package's own functions (LRI R68): a state file's name: the hex of SHA-256 over a key, here a group id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"submitLocked|parameter delivery":                 "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"submitLocked|parameter record":                   "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"syncStateDir|parameter dir":                      "Reached by the walk into this package's own functions (LRI R68): a directory synced after a write or a removal. Its path is built of a group id, public, carried as a field of a record that holds the pq_secret table.",
	"witnessPqSecretLocked|parameter epoch":           "Reached by the walk into this package's own functions (LRI R68): the witness of a pq_secret, kept at its epoch: the map's key is the epoch, a number, carried now that a map's key is a carried value; the value is a digest.",
	"writeRecord|parameter path":                      "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	"zeroizeState|parameter octets":                   "Reached by the walk into this package's own functions (LRI R68): THE ERASE: every octet of a value set to zero. at is the loop's index, tainted by ranging over the value; it is a position.",
}

var pqSecretSinks = map[string]pqSecretSink{
	"publishCommitLocked|call beforeSubmit": {
		carries: []string{"commitDigest", "pqNext"},
		occurs:  []string{"commitDigest.EpochKeysDigest", "pqNext"},
		why:     "THE JOIN SEAL'S HOOK: the rotated secret of the epoch this commit opens, to the closure that seals it to the joiner, before anything of the epoch is submitted. It is the only way that secret can reach a leaf that does not exist yet.",
	},
	"epochKeysDigestOver|return": {
		carries: []string{"digest"},
		occurs:  []string{"digest"},
		why:     "H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes. It is not a key.",
	},
	"epochKeysDigestOver|call message.EpochKeysDigest": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"readKey", "writeKey"},
		why:     "the pair, into the digest.",
	},
	"epochKeysDigestOver|call zeroizeState": {
		carries: []string{"readKey", "root", "writeKey"},
		occurs:  []string{"readKey", "root", "writeKey"},
		why:     "the erase of the root and of both keys, before the digest is answered.",
	},
	"epochKeysDigestOver|call message.ReadKey": {
		carries: []string{"root"},
		occurs:  []string{"root"},
		why:     "the read key off that root, to be digested.",
	},
	"epochKeysDigestOver|call message.WriteKey": {
		carries: []string{"root"},
		occurs:  []string{"root"},
		why:     "the write key off that root, to be digested.",
	},
	"epochKeysDigestOver|call messagegroup.StorageRoot": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "the storage root of the epoch, from the exporter and the candidate secret.",
	},
	"decodeJoinSecrets|return": {
		carries: []string{"epochKeysDigest", "groupHandleKey", "pqSecret"},
		occurs:  []string{"epochKeysDigest", "groupHandleKey", "pqSecret"},
		why:     "the three values, as copies, to the joiner's half.",
	},
	"decodeJoinSecrets|call zeroizeState": {
		carries: []string{"groupHandleKey", "pqSecret"},
		occurs:  []string{"groupHandleKey", "pqSecret"},
		why:     "the erase of both copies on that refusal.",
	},
	"decodeJoinSecrets|call subtle.ConstantTimeCompare": {
		carries: []string{"groupHandleKey", "pqSecret"},
		occurs:  []string{"groupHandleKey", "pqSecret"},
		why:     "the refusal of an all-zero secret, in constant time. It answers an int.",
	},
	"encodeJoinSecrets|return": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why:     "join_secrets_v1, to its one caller, which seals it and erases it.",
	},
	"encodeJoinSecrets|call append": {
		carries: []string{"epochKeysDigest", "payload", "pqSecret"},
		occurs:  []string{"epochKeysDigest", "payload", "payload", "payload", "pqSecret"},
		why: "the payload's assembly, into a buffer of exactly its length." +
			" (R68: the epoch keys digest is carried too, handed by sealJoinLocked; it is public.)",
	},
	"AddMember|assign self.session": {
		carries: []string{"session"},
		occurs:  []string{"session"},
		why:     "that session parked on the group.",
	},
	"AddMember|call messagegroup.NewGroupSession": {
		carries: []string{"foundingSecret"},
		occurs:  []string{"foundingSecret"},
		why:     "the session built over it.",
	},
	"AddMember|call self.filePqSecretLocked": {
		carries: []string{"foundingSecret"},
		occurs:  []string{"foundingSecret"},
		why: "the founding epoch's secret filed at the epoch the handle is standing at, which is where " +
			"the table's first row comes from for a founder that has not yet committed.",
	},
	"foundGroupLocked|call messagegroup.GroupHandleKey": {
		carries: []string{"pqSecret"},
		occurs:  []string{"messagegroup.StorageRoot(...)"},
		why: "the group_handle_key, derived from that root. It carries `pqSecret` because the root " +
			"expression is nested in this call.",
	},
	"foundGroupLocked|call messagegroup.NewGroupSession": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why: "the secret going into connect's own per-epoch table, which is the other half of ruling " +
			"40.",
	},
	"foundGroupLocked|call messagegroup.StorageRoot": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "the founding storage root's post-quantum half.",
	},
	"foundGroupLocked|call self.hold": {
		carries: []string{"group"},
		occurs:  []string{"group"},
		why:     "the whole group going onto the device, tainted through its own table.",
	},
	"foundGroupLocked|literal ?.0": {
		carries: []string{"pqSecret"},
		occurs:  []string{"0: pqSecret"},
		why:     "the sdk-side table's first entry, epoch zero's.",
	},
	"foundGroupLocked|literal Group.founding": {
		carries: []string{"founding"},
		occurs:  []string{"founding"},
		why:     "the session, tainted because it was constructed with the secret.",
	},
	"foundGroupLocked|literal Group.groupHandleKey": {
		carries: []string{"groupHandleKey"},
		occurs:  []string{"groupHandleKey"},
		why: "the handle key, tainted by derivation from the root. It is not itself a secret this gate " +
			"is about; it is censused because the walk cannot tell a derivation from a copy, which is " +
			"the safe direction.",
	},
	"foundGroupLocked|return": {
		carries: []string{"group"},
		occurs:  []string{"group"},
		why:     "the same group handed back.",
	},
	"Join|call self.holdReplacing": {
		carries: []string{"group"},
		occurs:  []string{"group"},
		why: "the group going onto the device, in place of the one a commit removed this device from " +
			"when the join is a re-add. The replaced group is closed, which erases its own table.",
	},
	"Join|call self.persistGroup": {
		carries: []string{"group"},
		occurs:  []string{"group.groupRecordLocked(...)"},
		why:     "the group's first record going to disk.",
	},
	"Join|call self.abandonJoined": {
		carries: []string{"group"},
		occurs:  []string{"group", "group"},
		why: "a join that failed after its commit (Task 57, F3): the group is closed, which erases its " +
			"own table, and the joined epoch's state is erased from the store.",
	},
	"Join|literal Group.session": {
		carries: []string{"session"},
		occurs:  []string{"session"},
		why:     "the session parked on the group.",
	},
	"Join|return": {
		carries: []string{"group"},
		occurs:  []string{"group", "self.abandonJoined(...)", "self.abandonJoined(...)"},
		why:     "the same group handed back.",
	},
	"PutGroupRecord|call encodePqSecretTable": {
		carries: []string{"rows"},
		occurs:  []string{"rows"},
		why:     "the rows going to the encoder.",
	},
	"PutGroupRecord|call self.writeRecord": {
		carries: []string{"dark", "ledger", "record", "record.PqSecret", "removal", "table", "witness"},
		occurs:  []string{"dark", "ledger", "record.GroupHandleKey", "record.GroupId", "record.GroupId", "record.PqSecret", "removal", "self.groupRecordPath(...)", "self.recordedPath(...)", "table", "witness"},
		why: "THE RECORD GOING TO DISK. The secrets are on disk in the clear, like every other secret " +
			"in this store -- S2-24, still open." +
			" (R68: the walk now follows the record whole into this function, so its other parts -- the wrap-dark, ledger, removal and witness encodings and the record itself -- are carried here too; they are public, and the pq_secret table is still the one secret in the write.)",
	},
	"PutGroupRecord|literal ?.PqSecret": {
		carries: []string{"record", "record.PqSecret"},
		occurs:  []string{"record.PqSecret"},
		why: "the one-row table a five-part CALLER's record is turned into before it is written, so " +
			"part six is never absent." +
			" (R68: the record itself is carried too, since the walk follows it whole into this function.)",
	},
	"decodePqSecretTable|call append": {
		carries: []string{"at", "encoded", "rows", "width"},
		occurs:  []string{"encoded[:]", "rows"},
		why: "one decoded row being collected." +
			" (R68: the walk is handed the encoded table now, so its offsets and width are carried; they are numbers.)",
	},
	"decodePqSecretTable|return": {
		carries: []string{"at", "epoch", "rows", "width"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "rows"},
		why: "the decoded table." +
			" (R68: the offsets, the width and the epoch are carried too; they are numbers.)",
	},
	"dropPqSecretsBelowWindowLocked|call delete": {
		carries: []string{"epoch", "self.pqSecrets"},
		occurs:  []string{"epoch", "self.pqSecrets"},
		why: "the map entry being dropped AFTER the erase beside it. What lands here is the table and " +
			"the epoch key, never the secret: a delete takes a key.",
	},
	"dropPqSecretsBelowWindowLocked|call zeroizeState": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is an entry the window has moved past -- erased " +
			"and not merely dropped, because a map entry nobody erased is a live post-quantum secret " +
			"with no owner.",
	},
	"dropWrapCandidatesLocked|call zeroizeState": {
		carries: []string{"candidate.secret"},
		occurs:  []string{"candidate.secret"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is every candidate for a resolved epoch, including " +
			"the orphans.",
	},
	"encodePqSecretTable|call append": {
		carries: []string{"encoded", "row", "row.PqSecret"},
		occurs:  []string{"encoded", "encoded", "encoded", "row.PqSecret"},
		why:     "the frame being assembled: the epoch, the one-octet width, and then the secret itself.",
	},
	"encodePqSecretTable|call binary.BigEndian.PutUint64": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch"},
		why: "the row's EPOCH being written into the frame. It carries `row` because the epoch is a " +
			"field of a tainted struct; eight octets of a uint64 land here.",
	},
	"encodePqSecretTable|call fmt.Errorf": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch"},
		why: "THE ENCODER'S WIDTH REFUSAL, and the operands are `row.Epoch` and `len(row.PqSecret)` -- " +
			"a number and a count. The count is why `encodePqSecretTable|len row.PqSecret` is in the " +
			"counted census below and not here.",
	},
	"encodePqSecretTable|return": {
		carries: []string{"encoded", "row"},
		occurs:  []string{"encoded", "fmt.Errorf(...)"},
		why:     "the assembled octet string, or that refusal.",
	},
	"encodePqSecretWitness|call append": {
		carries: []string{"encoded", "row"},
		occurs:  []string{"encoded", "encoded", "row.Digest"},
		why: "THE WITNESS FRAME being assembled: the epoch, then 32 octets of SHA-256. What is NOT " +
			"in this list is a pq_secret, and that is the whole difference between this encoder and " +
			"the one above it -- `row.Digest` is a digest of a secret and never the secret.",
	},
	"encodePqSecretWitness|call binary.BigEndian.PutUint64": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch"},
		why:     "the row's EPOCH being written into the frame, for its twin's reason one entry up.",
	},
	"encodePqSecretWitness|call fmt.Errorf": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch"},
		why: "THE WITNESS ENCODER'S WIDTH REFUSAL, and the operands are `row.Epoch` and " +
			"`len(row.Digest)` -- a number and a count, which is why that length is in the counted " +
			"census below and not here.",
	},
	"encodePqSecretWitness|return": {
		carries: []string{"encoded", "row"},
		occurs:  []string{"encoded", "fmt.Errorf(...)"},
		why:     "the assembled witness, or that refusal.",
	},
	"sortEpochPqSecretWitness|assign rows[?]": {
		carries: []string{"row", "rows"},
		occurs:  []string{"row", "rows[back]"},
		why: "the witness sort's own moves, for [sortEpochPqSecrets]'s reason: order is part of the " +
			"value, because the part is written by appending each row in turn and a map's iteration " +
			"order would make two writes of one unchanged witness two different files.",
	},
	"witnessPqSecretLocked|call sha256.Sum256": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why: "THE ONE PLACE THE SECRET STOPS BEING ONE. Everything downstream of this call carries a " +
			"digest, which is what makes keeping it for ever acceptable and is why " +
			"[Group.pqSecretWitness] is not inside the window's erase discipline.",
	},
	"witnessPqSecretLocked|call subtle.ConstantTimeCompare": {
		carries: []string{"digest"},
		occurs:  []string{"digest[:]"},
		why: "the already-witnessed check, over DIGESTS. It is ConstantTimeCompare and not " +
			"bytes.Equal for guardrail G8's reason -- these are derived from key material -- even " +
			"though what is compared is a hash.",
	},
	"witnessPqSecretLocked|assign self.pqSecretWitness[epoch]": {
		carries: []string{"digest", "epoch"},
		occurs:  []string{"digest"},
		why: "THE WITNESS ENTRY ITSELF. This is the assignment the removal rule's subject is read " +
			"from, and it is a hash: a table of these survives the window that the table of secrets " +
			"beside it does not." +
			" (R68: a map's key is a carried value now; this key is the epoch, a number.)",
	},
	"filePqSecretLocked|call self.witnessPqSecretLocked": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why: "the secret being witnessed BEFORE the drop below it. The order is load-bearing: a " +
			"witness written after [Group.dropPqSecretsBelowWindowLocked] would miss the value the " +
			"drop just evicted.",
	},
	"initTables|call self.witnessPqSecretLocked": {
		carries: []string{"epoch", "secret"},
		occurs:  []string{"epoch", "secret"},
		why: "the constructor's seeding: every row a constructor filled is a value this group has " +
			"held, so it is a value a removal may not be followed on. [Device.restoreOne] adds the " +
			"rows the record carries for epochs the table no longer covers.",
	},
	"groupRecordOf|call decodePqSecretWitness": {
		carries: []string{"parts"},
		occurs:  []string{"parts[7]"},
		why: "part eight going to the witness decoder, which is in this census for " +
			"`groupRecordOf|parameter parts`'s reason -- the record's parts are seeded whole and " +
			"this walk does not tell one part from another.",
	},
	"groupRecordOf|assign record.PqSecretWitness": {
		carries: []string{"witness"},
		occurs:  []string{"witness"},
		why:     "that decoded witness landing on the record.",
	},
	"groupRecordOf|call decodeLeafOccupancy": {
		carries: []string{"parts"},
		occurs:  []string{"parts[8]"},
		why: "part NINE going to the leaf ledger decoder, for the witness decoder's reason two " +
			"entries up: the record's parts are seeded whole and this walk does not tell one part " +
			"from another. What that part holds is ledger item 245's occupancy table -- leaf " +
			"indices, the epoch each departed at, and one flag octet -- and no key material of " +
			"any kind.",
	},
	"groupRecordOf|assign record.Leaves": {
		carries: []string{"ledger"},
		occurs:  []string{"ledger"},
		why:     "that decoded leaf ledger landing on the record.",
	},
	"groupRecordOf|call decodeRemoval": {
		carries: []string{"parts"},
		occurs:  []string{"parts[9]"},
		why: "part TEN going to ruling 52's removal decoder, for the two decoders above it: the " +
			"record's parts are seeded whole and this walk does not tell one part from another. What " +
			"that part holds is one kind octet and one epoch -- whether a commit removed this device " +
			"and the last epoch it was a member at -- and no key material of any kind.",
	},
	"groupRecordOf|assign record.RemovedKind": {
		carries: []string{"kind"},
		occurs:  []string{"kind"},
		why:     "that decoder's kind octet landing on the record.",
	},
	"groupRecordOf|assign record.RemovedEpoch": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "the epoch beside it.",
	},
	"sortLeafOccupancy|assign rows[?]": {
		carries: []string{"rows", "row"},
		occurs:  []string{"row", "rows[back]"},
		why: "the insertion sort's own two writes, which is what a sort IS. It is in this census " +
			"because the producer net seeds any parameter named `rows`; what moves here is a " +
			"[LeafOccupancy] -- a leaf index, an epoch and a flag.",
	},
	"encodeLeafOccupancy|call binary.BigEndian.PutUint32": {
		carries: []string{"row"},
		occurs:  []string{"row.Leaf"},
		why:     "the leaf index being written into part nine's fixed-width row.",
	},
	"encodeLeafOccupancy|call binary.BigEndian.PutUint64": {
		carries: []string{"row"},
		occurs:  []string{"row.DepartedEpoch"},
		why:     "the epoch that leaf departed at, into the same row.",
	},
	"restoreOne|call messagegroup.SenderHandle": {
		carries: []string{"row", "restored"},
		occurs:  []string{"restored.groupHandleKey", "row.Leaf"},
		why: "THE RESTORED LEAF BECOMING THE HANDLE IT DERIVES, which is ledger item 245's fourth " +
			"piece coming back off the disk. `row` is tainted because the restore's loop variables " +
			"are seeded by this census's `rows` net; what crosses is `row.Leaf`, a u32 index, and " +
			"the key is group_handle_key -- the group's own lifetime value, which every member " +
			"holds and which is not a pq_secret. The handle is DERIVED here rather than stored, so " +
			"part nine can carry no handle and no derivation of one.",
	},
	"restoreOne|assign restored.departedAt[row.Leaf]": {
		carries: []string{"row"},
		occurs:  []string{"row.DepartedEpoch"},
		why: "the same row's departure epoch landing in [Group.departedAt], which is what lets a " +
			"restarted device still resolve the records a removed leaf sealed below the commit " +
			"that removed it.",
	},
	"restoreOne|call copy": {
		carries: []string{"row"},
		occurs:  []string{"row.Digest"},
		why: "THE RESTORED WITNESS ROW being copied into its fixed-width array. `row` is tainted " +
			"because the restore's loop variables are seeded by this census's `rows` net; what is " +
			"copied is `row.Digest`, 32 octets of SHA-256, and the width is refused by name one line " +
			"above rather than truncated here.",
	},
	"encodeStateRecord|call body.Write": {
		carries: []string{"part"},
		occurs:  []string{"part"},
		why: "each part, the secrets among them, going into the *bytes.Buffer the record is assembled " +
			"in.",
	},
	"filePqSecretLocked|assign self.pqSecrets[epoch]": {
		carries: []string{"pqSecret"},
		occurs:  []string{"append(...)"},
		why: "the table entry itself, written from that copy. This is the assignment item 243 is " +
			"about.",
	},
	"filePqSecretLocked|call append": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why: "THE COPY. The caller's array stays the caller's; the table's entry is this group's to " +
			"erase.",
	},
	"filePqSecretLocked|call zeroizeState": {
		carries: []string{"held"},
		occurs:  []string{"held"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is the entry being replaced.",
	},
	"groupRecordLocked|literal GroupRecord.PqSecret": {
		carries: []string{"self.pqSecretLocked"},
		occurs:  []string{"self.pqSecretLocked(...)"},
		why: "THE SCALAR STILL WRITTEN, and it is the CURRENT epoch's. It is what a five-part record " +
			"holds and what a build from before the table reads; the arity switch below it is how the " +
			"two shapes stay distinguishable.",
	},
	"groupRecordLocked|literal GroupRecord.PqSecrets": {
		carries: []string{"self.pqSecretRecordsLocked"},
		occurs:  []string{"self.pqSecretRecordsLocked(...)"},
		why: "THE TABLE, part six, and the one place it becomes durable state. A six-part record with " +
			"an empty table decodes to an empty SLICE and a five-part one to nil, so 'this build " +
			"wrote no rows' and 'there was never a table' stay two states.",
	},
	"groupRecordOf|assign record.PqSecrets": {
		carries: []string{"table"},
		occurs:  []string{"table"},
		why:     "the decoded table landing on the record.",
	},
	"groupRecordOf|call binary.BigEndian.Uint64": {
		carries: []string{"parts"},
		occurs:  []string{"parts[3]"},
		why:     "that epoch being read out of part four.",
	},
	"groupRecordOf|call decodePqSecretTable": {
		carries: []string{"parts"},
		occurs:  []string{"parts[5]"},
		why:     "part six going to the table decoder.",
	},
	"groupRecordOf|literal GroupRecord.Epoch": {
		carries: []string{"parts"},
		occurs:  []string{"binary.BigEndian.Uint64(...)"},
		why:     "part four, eight octets of a uint64.",
	},
	"groupRecordOf|literal GroupRecord.GroupHandleKey": {
		carries: []string{"parts"},
		occurs:  []string{"parts[2]"},
		why: "part three, which IS key material -- it is the group_handle_key -- and is censused here " +
			"as the same `parts`.",
	},
	"groupRecordOf|literal GroupRecord.GroupId": {
		carries: []string{"parts"},
		occurs:  []string{"parts[0]"},
		why: "part one, the group id. It carries `parts` for the same reason and is not a secret; this " +
			"walk cannot tell the six parts apart and does not claim to.",
	},
	"groupRecordOf|literal GroupRecord.Opened": {
		carries: []string{"parts"},
		occurs:  []string{"?"},
		why:     "part five, one octet of a bool.",
	},
	"groupRecordOf|literal GroupRecord.PqSecret": {
		carries: []string{"parts"},
		occurs:  []string{"parts[1]"},
		why: "THE PERSISTED SCALAR COMING BACK: part two, which on the alpha's disk is the group's " +
			"whole pq_secret. It carries `parts` because that is the name it has here.",
	},
	"groupRecordOf|call decodeWrapDark": {
		carries: []string{"parts"},
		occurs:  []string{"parts[6]"},
		why: "part SEVEN going to the wrap_dark decoder. It carries `parts` for the same reason every " +
			"other site here does -- the walk cannot tell one part from another -- and what the decoder " +
			"answers is a kind octet and an epoch, neither of which is key material.",
	},
	"groupRecordOf|assign record.WrapDarkKind": {
		carries: []string{"kind"},
		occurs:  []string{"kind"},
		why: "the restored diagnosis's KIND landing on the record: which of the five ways this device " +
			"could not follow a commit it was. It is tainted because it came out of part seven and the " +
			"walk follows the parts, not because a kind octet is a secret.",
	},
	"groupRecordOf|assign record.WrapDarkEpoch": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "the epoch that diagnosis was taken at, out of the same part and for the same reason.",
	},
	"groupRecordOf|return": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why: "the whole record, or one of the two arity refusals. NEITHER of those refusals formats a " +
			"part: they format the record's directory name and two COUNTS, which is why this entry's " +
			"carries list is `parts` and why pq-M2 is now red.",
	},
	"ingestCommitLocked|assign self.wrapDark": {
		carries: []string{"resolveErr"},
		occurs:  []string{"resolveErr"},
		why: "THE STICKY DIAGNOSIS, which is an ERROR and not a secret. It is censused because the " +
			"walk taints it from the call that produced it, and the carries list is what would refuse " +
			"a repair that put a candidate in its text.",
	},
	"ingestCommitLocked|call self.filePqSecretLocked": {
		carries: []string{"pqNext"},
		occurs:  []string{"pqNext"},
		why:     "the resolved secret filed at the epoch the commit opened.",
	},
	"ingestCommitLocked|call self.session.AdvanceEpoch": {
		carries: []string{"pqNext"},
		occurs:  []string{"pqNext"},
		why:     "the same one value into connect's table, for publishCommitLocked's reason.",
	},
	"ingestCommitLocked|call self.haltLocked": {
		carries: []string{"resolveErr"},
		occurs:  []string{"resolveErr"},
		why: "RULING 41's REFUSAL going to the one place that records and persists it. It carries the " +
			"resolution's ERROR and nothing else -- the halt's whole content is a sentence, an epoch " +
			"and a kind octet, and [refuseRemovalOnHeldSecret]'s own header is why no pq_secret is in " +
			"it: a diagnosis names what happened and never the material it happened to.",
	},
	"ingestCommitLocked|return": {
		carries: []string{"resolveErr"},
		occurs:  []string{"resolveErr", "self.haltLocked(...)"},
		why:     "that same error, said once to this walk's caller.",
	},
	"ingestWrapLocked|call zeroizeState": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is a payload of the wrong width, refused before it " +
			"can become a candidate.",
	},
	"ingestWrapLocked|literal wrapCandidate.secret": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why: "the payload staged as a candidate, under the epoch its envelope names. NOTHING IS " +
			"INSTALLED HERE: the commit decides.",
	},
	"initTables|assign owned[epoch]": {
		carries: []string{"epoch", "secret"},
		occurs:  []string{"append(...)"},
		why: "that copy landing in the group's own table." +
			" (R68: a map's key is a carried value now; this key is the epoch, a number.)",
	},
	"initTables|call append": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why:     "THE OWNERSHIP COPY -- see the function's own header for the aliasing hazard it repairs.",
	},
	"openWrapToOwnLeaf|return": {
		carries: []string{"messagegroup.OpenWrapBody"},
		occurs:  []string{"messagegroup.OpenWrapBody(...)"},
		why: "THE PAYLOAD LEAVING device.go. This is the site the wrap-seed gate's own disposition " +
			"names as the value it hands off and does not follow; this census is the thing that picks " +
			"it up.",
	},
	"pqSecretAtLocked|return": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why:     "the entry handed back, deliberately not copied.",
	},
	"pqSecretLocked|return": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why:     "the same value one call further out.",
	},
	"pqSecretRecordsLocked|call append": {
		carries: []string{"records", "secret"},
		occurs:  []string{"records", "secret"},
		why:     "one row being built for the record, with its own copy of the octets.",
	},
	"pqSecretRecordsLocked|call sortEpochPqSecrets": {
		carries: []string{"records"},
		occurs:  []string{"records"},
		why: "the rows going to the sort, because ascending epoch order is part of what the record " +
			"MEANS.",
	},
	"pqSecretRecordsLocked|literal EpochPqSecret.Epoch": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why: "the row's epoch. It carries `epoch` -- a uint64 loop key the walk taints along with the " +
			"value it ranges beside -- and never the secret.",
	},
	"pqSecretRecordsLocked|literal EpochPqSecret.PqSecret": {
		carries: []string{"secret"},
		occurs:  []string{"append(...)"},
		why:     "that copy landing in the row.",
	},
	"pqSecretRecordsLocked|return": {
		carries: []string{"records"},
		occurs:  []string{"records"},
		why:     "the rows handed to the record builder.",
	},
	"pqSecretsMapOf|assign secrets[row.epoch]": {
		carries: []string{"row", "row.secret"},
		occurs:  []string{"row.secret"},
		why: "the restored table as the map a [Group] holds. The row's own array is filed, which is " +
			"why [Group.initTables] then takes ownership of it.",
	},
	"pqSecretsMapOf|return": {
		carries: []string{"secrets"},
		occurs:  []string{"secrets"},
		why:     "that map.",
	},
	"pqSecretsShowRotation|call subtle.ConstantTimeCompare": {
		carries: []string{"table", "table.secret"},
		occurs:  []string{"table.secret", "table.secret"},
		why: "THE ONE COMPARISON THAT DECIDES ROTATION, and it is over OCTETS and never over a row " +
			"count. ConstantTimeCompare and not bytes.Equal: guardrail G8.",
	},
	"publishCommitLocked|call epochKeysFor": {
		carries: []string{"commitRecord", "readKey", "writeKey"},
		occurs:  []string{"commitRecord", "readKey", "writeKey"},
		why:     "the request's own copy of the epoch keys, ruling 27's sixth kind.",
	},
	"publishCommitLocked|call message.NewEpochDigestAttachment": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"readKey", "writeKey"},
		why:     "H(epoch_keys) -- item 132's binding. The DIGEST leaves; the keys do not.",
	},
	"publishCommitLocked|call message.ReadKey": {
		carries: []string{"newRoot"},
		occurs:  []string{"newRoot"},
		why:     "its read key, the same.",
	},
	"publishCommitLocked|call message.WriteKey": {
		carries: []string{"newRoot"},
		occurs:  []string{"newRoot"},
		why:     "the epoch's write key, derived and dropped inside this function.",
	},
	"publishCommitLocked|call messagegroup.StorageRoot": {
		carries: []string{"pqNext"},
		occurs:  []string{"pqNext"},
		why:     "the storage root of the epoch this commit opens.",
	},
	"publishCommitLocked|call self.filePqSecretLocked": {
		carries: []string{"pqNext"},
		occurs:  []string{"pqNext"},
		why: "the new epoch's secret filed AFTER the server has taken the commit, so a lost CAS race " +
			"leaves no row behind.",
	},
	"publishCommitLocked|call self.session.AdvanceEpoch": {
		carries: []string{"pqNext"},
		occurs:  []string{"pqNext"},
		why: "the same one value going into connect's table; a differing one is " +
			"ErrPqSecretEpochConflict.",
	},
	"publishCommitLocked|call self.submitLocked": {
		carries: []string{"commitRecord", "delivery"},
		occurs:  []string{"commitRecord", "delivery"},
		why:     "the commit and its wraps going to the server, as ciphertext.",
	},
	"publishCommitLocked|call zeroizeState": {
		carries: []string{"newRoot", "pqNext"},
		occurs:  []string{"newRoot", "pqNext"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is the root and the drawn secret on the failure " +
			"arms.",
	},
	"publishCommitLocked|literal message.ServerAttachment.EpochDigest": {
		carries: []string{"commitDigest"},
		occurs:  []string{"commitDigest"},
		why:     "the digest riding on the commit record, tainted by derivation from the keys.",
	},
	"ingestCommitLocked|call errors.Is": {
		carries: []string{"resolveErr"},
		occurs:  []string{"resolveErr"},
		why: "RULING 41's FORK, which is a sentinel comparison and not a secret. `resolveErr` is " +
			"tainted because it is bound in the same statement as `pqNext`; what goes to errors.Is " +
			"is an error value and a package-level sentinel, and what comes back is a bool deciding " +
			"whether this group HALTS or goes dark.",
	},
	"pqSecretHeldAtLocked|call subtle.ConstantTimeCompare": {
		carries: []string{"candidate", "secret", "witness"},
		occurs:  []string{"candidate", "secret", "witness[:]"},
		why: "THE REMOVAL RULE'S COMPARISON ITSELF: a candidate against one row of this group's own " +
			"table. Constant time is guardrail G8's and the header carries why there is no early " +
			"exit. It answers an int and formats nothing." +
			" (R68: the candidate, handed in, and the witness row are carried; both are digests.)",
	},
	"pqSecretHeldAtLocked|return": {
		carries: []string{"at", "found"},
		occurs:  []string{"at", "found"},
		why: "AN EPOCH AND A BOOL, AND THIS IS THE ENTRY THAT SAYS SO. The comparison's answer is " +
			"`(uint64, bool)` -- which row matched and whether one did -- so no octet of either " +
			"input leaves this function. A version that answered the matching secret would land " +
			"here carrying it and would have to be weighed.",
	},
	"resolvePqSecretLocked|call answerSecret": {
		carries: []string{"candidate.secret", "held"},
		occurs:  []string{"candidate.secret", "held", "held"},
		why: "EVERY ARM'S SECRET GOING TO THE ONE EXIT. This is the entry that makes the exit the " +
			"exit: if a fourth arm is added, its value appears in this carries list, and an arm that " +
			"returned around the exit instead would show up as a `return` carrying something this " +
			"census would have to be told about.",
	},
	"resolvePqSecretLocked|call refuseRemovalOnHeldSecret": {
		carries: []string{"heldAt"},
		occurs:  []string{"heldAt"},
		why: "THE REFUSAL, AND WHAT IT IS HANDED IS THE POINT: an epoch, the removed leaf list, the " +
			"epoch the value is already held at, and a clause of English. The secret it refused is " +
			"NOT among them and must never be -- this error reaches a log, and the shape this whole " +
			"gate exists to refuse is the live post-quantum secret in an error string.",
	},
	"resolvePqSecretLocked|call self.matchesEpochDigestLocked": {
		carries: []string{"candidate.secret", "held"},
		occurs:  []string{"candidate.secret", "held"},
		why: "each candidate going to the digest check, which is the only thing that tells the epoch's " +
			"own secret from an orphan.",
	},
	"resolvePqSecretLocked|call self.pqSecretHeldAtLocked": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why: "the exit's own parameter going to the removal rule's comparison: whatever this " +
			"function is about to answer, against the whole table it already holds.",
	},
	"resolvePqSecretLocked|return": {
		carries: []string{"answerSecret", "candidate.secret", "held", "heldAt", "secret"},
		occurs:  []string{"answerSecret(...)", "answerSecret(...)", "answerSecret(...)", "refuseRemovalOnHeldSecret(...)", "secret"},
		why: "the secret the epoch runs on. Every OTHER return of this function is an error, and none " +
			"of them formats a candidate -- which is the property mutant ADV-M1 attacked and this " +
			"entry's carries list is what refuses it. `answerSecret` and `secret` joined the list " +
			"when the three arms were funnelled through one guarded exit; " +
			"TestEveryReturnOfTheResolutionThatCanCarryAPqSecretGoesThroughTheGuardedExit is the " +
			"gate that holds THAT shape, and this one holds what the returns carry.",
	},
	"restoreOne|call fmt.Errorf": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch", "row.epoch"},
		why: "THE RESTORE'S ONE FORMATTING SITE ON THIS PATH, and the operand is `row.epoch` -- a " +
			"uint64 naming which row the install refused, so an operator reading the refusal sees " +
			"which epoch asked. It carries `row` because the epoch is a field of a tainted struct; a " +
			"`%x` of `row.secret` would carry `row.secret`, which this entry does not list, and would " +
			"be refused.",
	},
	"restoreOne|call messagegroup.NewGroupSession": {
		carries: []string{"current"},
		occurs:  []string{"current"},
		why: "the restored session, built at the epoch the record names and with that epoch's own " +
			"secret. A session built over some OTHER epoch's secret is ruling 40's defect arriving " +
			"through the restore door, which is why restoredPqSecrets refuses a table that does not " +
			"cover its own epoch.",
	},
	"restoreOne|call pqSecretsMapOf": {
		carries: []string{"table"},
		occurs:  []string{"table"},
		why:     "the same table as the map the group runs on.",
	},
	"restoreOne|call pqSecretsShowRotation": {
		carries: []string{"table"},
		occurs:  []string{"table"},
		why: "the restored table going to the one question a restarted device can answer about it: are " +
			"there two different values in it.",
	},
	"restoreOne|call session.InstallPqSecret": {
		carries: []string{"row", "row.secret"},
		occurs:  []string{"row.epoch", "row.secret"},
		why: "EACH PAST EPOCH GOING BACK INTO CONNECT'S TABLE. It carries the row's epoch and the " +
			"row's octets, which is exactly what that door takes.",
	},
	"restoreOne|literal Group.pqSecrets": {
		carries: []string{"pqSecretsMapOf", "table"},
		occurs:  []string{"pqSecretsMapOf(...)"},
		why: "that map landing on the restored group, which [Group.initTables] then takes ownership " +
			"of.",
	},
	"restoreOne|literal Group.session": {
		carries: []string{"session"},
		occurs:  []string{"session"},
		why:     "the session parked on the group, tainted because it was constructed with the secret.",
	},
	"restoreOne|return": {
		carries: []string{"restored", "row"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)", "restored"},
		why:     "the restored group, or that per-row refusal.",
	},
	"restoredPqSecrets|call append": {
		carries: []string{"record.PqSecret", "row", "row.PqSecret", "table"},
		occurs:  []string{"record.PqSecret", "row.PqSecret", "table", "table"},
		why: "the copies this decode takes: one per epoch of the five-part record's own window, one " +
			"six-part row, and the table they are appended to. EACH IS ITS OWN ARRAY, because both " +
			"tables these rows reach erase an entry in place when the window moves past it and rows " +
			"sharing one array would blank each other.",
	},
	"restoredPqSecrets|literal restoredPqSecret.epoch": {
		carries: []string{"row"},
		occurs:  []string{"row.Epoch"},
		why: "that row's EPOCH. It carries `row` because `row.Epoch` is a field of a tainted struct; " +
			"what lands is a uint64.",
	},
	"restoredPqSecrets|literal restoredPqSecret.secret": {
		carries: []string{"secret"},
		occurs:  []string{"secret", "secret"},
		why: "one row of the table, on either arm: the five-part record's scalar at one epoch of its " +
			"window, or one six-part row.",
	},
	"restoredPqSecrets|return": {
		carries: []string{"current", "table"},
		occurs:  []string{"current", "current", "table", "table"},
		why: "the table and the entry at the epoch the record names, which is what the session is " +
			"constructed with.",
	},
	"sealEpochWrapLocked|call messagegroup.SealWrapBody": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "THE SEAL. The secret leaves this package here, under one leaf's X-Wing public key.",
	},
	"sealEpochWrapLocked|call self.session.SealRecord": {
		carries: []string{"body"},
		occurs:  []string{"body"},
		why: "the sealed BODY going into a record. It is a ciphertext of the secret and is tainted by " +
			"derivation, correctly.",
	},
	"sealEpochWrapLocked|return": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "that record.",
	},
	"sortEpochPqSecrets|assign rows[?]": {
		carries: []string{"row", "rows"},
		occurs:  []string{"row", "rows[back]"},
		why: "the insertion sort's own moves. Order is part of the value: the record is written by " +
			"appending each entry in turn.",
	},
	"stageEpochRotationLocked|assign staged.wraps": {
		carries: []string{"record", "staged"},
		occurs:  []string{"append(...)"},
		why:     "the same collection.",
	},
	"stageEpochRotationLocked|call append": {
		carries: []string{"record", "staged"},
		occurs:  []string{"record", "staged.wraps"},
		why: "the sealed wrap records being collected. `record` is tainted by derivation -- a wrap " +
			"record IS a ciphertext of the secret.",
	},
	"stageEpochRotationLocked|call self.sealEpochWrapLocked": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "the secret going into one wrap body per target.",
	},
	"stageEpochRotationLocked|call zeroizeState": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret", "pqSecret", "pqSecret"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is the drawn secret on every failure arm, because " +
			"nothing is filed until the server has taken the commit.",
	},
	"stageEpochRotationLocked|literal stagedRotation.pqSecret": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "the drawn secret parked on the staged rotation until publishCommitLocked files it.",
	},
	"stageEpochRotationLocked|return": {
		carries: []string{"staged"},
		occurs:  []string{"staged"},
		why:     "the staged rotation handed to its caller.",
	},
	"writeRecord|call encodeStateRecord": {
		carries: []string{"parts"},
		occurs:  []string{"parts"},
		why:     "the record's parts going to the framing.",
	},
	"writeRecord|call temp.Write": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why: "THE DISK. The framed record -- the pq_secret table inside it -- goes into the *os.File " +
			"this write is committing. The secrets are on disk in the clear, S2-24, still open." +
			" (R68: this census's horizon row for this call, writeRecord|accumulate temp.Write, is gone, and this row is what holds the write. The walk now follows writeRecord's path parameter, built of a group id that is a field of the record, so temp, opened under that path, is a receiver the walk already follows -- and a receiver the walk follows is a sink, not a horizon. Nothing about the call changed; the wrap-seed census, whose net never reaches the path, still lists the horizon row.)",
	},
	"writeRecord|call zeroizeState": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why: "THE SECOND COPY BEING ERASED. The framing assembles another copy of whatever secret it " +
			"carries, and this deferred erase is the only thing that can still reach it once the " +
			"write has returned.",
	},
	"zeroizePqSecretsLocked|call delete": {
		carries: []string{"epoch", "self.pqSecrets"},
		occurs:  []string{"epoch", "epoch", "self.pqSecrets"},
		why: "the map entry being dropped AFTER the erase beside it. What lands here is the table and " +
			"the epoch key, never the secret: a delete takes a key.",
	},
	"zeroizePqSecretsLocked|call zeroizeState": {
		carries: []string{"secret"},
		occurs:  []string{"secret"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is every entry, at Close.",
	},
	"zeroizeWrapCandidatesLocked|call zeroizeState": {
		carries: []string{"candidate.secret"},
		occurs:  []string{"candidate.secret"},
		why: "THE ERASE. [zeroizeState] is this package's one overwrite and it is the only thing that " +
			"can still reach these octets. Here it is every candidate at all, at Close.",
	},
	"sealJoinLocked|call messagegroup.SealWrapBody": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why:     "THE ONE PLACE THE JOIN SECRETS LEAVE THIS DEVICE: sealed to the X-Wing key the joiner's own leaf publishes.",
	},
	"sealJoinLocked|call encodeJoinSecrets": {
		carries: []string{"epochKeysDigest", "pqSecret"},
		occurs:  []string{"epochKeysDigest", "pqSecret"},
		why: "into join_secrets_v1." +
			" (R68: the epoch keys digest is carried too; it is public.)",
	},
	"sealJoinLocked|call joinAuthPreimage": {
		carries: []string{"joinSeal"},
		occurs:  []string{"joinSeal"},
		why:     "the SEALED octets, hashed into the authenticator's preimage. Ciphertext.",
	},
	"sealJoinLocked|return": {
		carries: []string{"joinSeal", "preimage"},
		occurs:  []string{"joinSeal", "self.device.crypto.Mac(...)"},
		why:     "the seal and its authenticator, to the adder that puts them in the invite.",
	},
	"openJoinSeal|return": {
		carries: []string{"groupHandleKey", "pqSecret"},
		occurs:  []string{"groupHandleKey", "pqSecret"},
		why:     "the two secrets, to Join, only once the seal is authenticated, opened and checked.",
	},
	"AddMember|literal Invite.JoinSeal": {
		carries: []string{"joinSeal"},
		occurs:  []string{"joinSeal"},
		why:     "THE INVITE'S FOURTH FIELD SINCE VERSION 3: the two secrets sealed to the joiner's X-Wing key, where they used to stand in the clear.",
	},
	"sealJoinLocked|call zeroizeState": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why:     "the erase of the payload, deferred from the moment it exists.",
	},
	"openJoinSeal|call epochKeysDigestOver": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "THE CHECK: the opened secret must reproduce, under this device's own exporter, the digest sealed beside it.",
	},
	"openJoinSeal|call zeroizeState": {
		carries: []string{"groupHandleKey", "payload", "pqSecret"},
		occurs:  []string{"groupHandleKey", "groupHandleKey", "payload", "pqSecret", "pqSecret"},
		why:     "the erase of the payload always, and of both secrets on every refusal after they were cut out.",
	},
	"AddMember|literal Invite.JoinAuth": {
		carries: []string{"joinAuth"},
		occurs:  []string{"joinAuth"},
		why:     "the invite's authenticator. It is an HMAC over public values under an exporter key, and carries no secret.",
	},
	"AddMember|assign self.foundingJoinDigest": {
		carries: []string{"joinDigest"},
		occurs:  []string{"joinDigest"},
		why:     "the digest the invite was sealed over, kept so that Open can hold what it publishes against it. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes.",
	},
	"sealJoinLocked|call self.device.crypto.Mac": {
		carries: []string{"preimage"},
		occurs:  []string{"preimage"},
		why:     "the authenticator over the preimage, which is public values and three hashes.",
	},
	"AddMember|call self.sealFoundingJoinLocked": {
		carries: []string{"foundingSecret"},
		occurs:  []string{"foundingSecret"},
		why:     "THE FOUNDING ADD'S SEAL. pq_secret[1] goes into the join seal, off the staged commit, and into nothing else of the invite.",
	},
	"openJoinSeal|call decodeJoinSecrets": {
		carries: []string{"payload"},
		occurs:  []string{"payload"},
		why:     "the opened payload, to be cut into its three values.",
	},
	"Join|literal Group.groupHandleKey": {
		carries: []string{"groupHandleKey"},
		occurs:  []string{"groupHandleKey"},
		why:     "the group's handle key, into the joiner's group.",
	},
	"openJoinSeal|call subtle.ConstantTimeCompare": {
		carries: []string{"computed", "sealedDigest"},
		occurs:  []string{"computed", "sealedDigest"},
		why:     "two digests, compared in constant time. H(epoch_keys) is PUBLIC: it is what the commit that opens an epoch publishes.",
	},
	"Join|call append": {
		carries: []string{"pqSecret"},
		occurs:  []string{"pqSecret"},
		why:     "the joiner's own copy for its table, of the secret the seal opened to.",
	},
	"Join|call messagegroup.NewGroupSession": {
		carries: []string{"groupHandleKey", "pqSecret"},
		occurs:  []string{"groupHandleKey", "pqSecret"},
		why:     "the joiner's session, built over the two secrets the seal opened to.",
	},
	"Join|call zeroizeState": {
		carries: []string{"groupHandleKey", "pqSecret"},
		occurs:  []string{"groupHandleKey", "pqSecret"},
		why:     "THE TWO ERASES OF THE JOIN: this function's copy of the epoch's secret when it returns, the group having filed a copy of its own; and the handle key, on a refusal made after the seal opened and before the join committed. Once the join has committed the handle key is the group's.",
	},
	"Join|literal ?.handle.Epoch(...)": {
		carries: []string{"pqSecret"},
		occurs:  []string{"handle.Epoch(...): append(...)"},
		why:     "the one row of the joiner's table: the epoch it is admitted at, and that epoch's secret.",
	},
	// ── R68: SITES THE WALK REACHES INSIDE THIS PACKAGE'S OWN FUNCTIONS. The walk follows a value it holds into
	// the function it is handed to, to a fixpoint (the review of identity phase 1's Tasks 8 to 10, L1-1), and a
	// map's key is a carried value (L2-02); these rows are the sites that brought into view, each with its reason.
	"PutGroupRecord|call binary.BigEndian.PutUint64": {
		carries: []string{"record"},
		occurs:  []string{"record.Epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call encodeLeafOccupancy": {
		carries: []string{"record"},
		occurs:  []string{"record.Leaves"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call encodePqSecretWitness": {
		carries: []string{"record"},
		occurs:  []string{"record.PqSecretWitness"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call encodeRemoval": {
		carries: []string{"record"},
		occurs:  []string{"record.RemovedEpoch", "record.RemovedKind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call encodeWrapDark": {
		carries: []string{"record"},
		occurs:  []string{"record.WrapDarkEpoch", "record.WrapDarkKind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call fmt.Errorf": {
		carries: []string{"record", "recordedErr"},
		occurs:  []string{"record.Epoch", "record.GroupId", "recordedErr"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call os.Lstat": {
		carries: []string{"record"},
		occurs:  []string{"self.recordedPath(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call self.clearPendingLocked": {
		carries: []string{"record"},
		occurs:  []string{"record.GroupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call self.groupRecordPath": {
		carries: []string{"record"},
		occurs:  []string{"record.GroupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|call self.recordedPath": {
		carries: []string{"record"},
		occurs:  []string{"record.GroupId", "record.GroupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|literal ?.Epoch": {
		carries: []string{"record"},
		occurs:  []string{"record.Epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"PutGroupRecord|return": {
		carries: []string{"record", "recordedErr"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	},
	"abandonJoined|call eraser.eraseJoinedRecord": {
		carries: []string{"group"},
		occurs:  []string{"group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a join being abandoned: the Group's id and epoch name the state to erase, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is. A group id and an epoch are public.",
	},
	"abandonJoined|call self.eraseJoinedState": {
		carries: []string{"group"},
		occurs:  []string{"group.epoch", "group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a join being abandoned: the Group's id and epoch name the state to erase, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is. A group id and an epoch are public.",
	},
	"alignedEpochKeys|call commitCarriesItsKeys": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, delivered to the server beside the commit (ruling 33): the server is handed them on purpose, as the delivery's own rows say, and the commit they are aligned with is a sealed record, ciphertext and public header fields.",
	},
	"alignedEpochKeys|literal []*protocol.EpochKeyDelivery.element 0": {
		carries: []string{"delivery"},
		occurs:  []string{"delivery"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, delivered to the server beside the commit (ruling 33): the server is handed them on purpose, as the delivery's own rows say, and the commit they are aligned with is a sealed record, ciphertext and public header fields.",
	},
	"clearPendingLocked|call self.pendingPath": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	},
	"clearPendingLocked|call self.removeLocked": {
		carries: []string{"groupId"},
		occurs:  []string{"self.pendingPath(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	},
	"clearPendingLocked|return": {
		carries: []string{"groupId"},
		occurs:  []string{"self.removeLocked(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	},
	"cloneRefusalLocked|assign self.identityInUse": {
		carries: []string{"reason", "record"},
		occurs:  []string{"fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record whose stream index was reused: the reason and the record's header stream index are formatted and kept as the device's sticky refusal, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"cloneRefusalLocked|call fmt.Errorf": {
		carries: []string{"reason", "record"},
		occurs:  []string{"reason", "record.Header.StreamIndex"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record whose stream index was reused: the reason and the record's header stream index are formatted and kept as the device's sticky refusal, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"commitCarriesItsKeys|call message.ParseEpochDigestAttachment": {
		carries: []string{"record"},
		occurs:  []string{"record.Header.ServerAttachment"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed commit record read for its server attachment's kind: the attachment is public and inside the write_auth preimage. The walk follows the record whole.",
	},
	"decodeJoinSecrets|call append": {
		carries: []string{"payload"},
		occurs:  []string{"payload[:]", "payload[:]", "payload[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): an opened join payload cut into its three values, as copies: the pq_secret, the handle key and the epoch keys digest. The payload was sealed to this device and opened by it; what it answers is installed by the join, whose rows hold it, and the caller erases the payload.",
	},
	"decodeLeafOccupancy|call append": {
		carries: []string{"rows"},
		occurs:  []string{"rows"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|call binary.BigEndian.Uint32": {
		carries: []string{"encoded"},
		occurs:  []string{"encoded[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|call binary.BigEndian.Uint64": {
		carries: []string{"encoded"},
		occurs:  []string{"encoded[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|call fmt.Errorf": {
		carries: []string{"flags"},
		occurs:  []string{"flags"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|literal LeafOccupancy.DepartedEpoch": {
		carries: []string{"encoded"},
		occurs:  []string{"binary.BigEndian.Uint64(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|literal LeafOccupancy.Leaf": {
		carries: []string{"encoded"},
		occurs:  []string{"binary.BigEndian.Uint32(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|literal LeafOccupancy.Own": {
		carries: []string{"flags"},
		occurs:  []string{"?"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodeLeafOccupancy|return": {
		carries: []string{"flags", "rows"},
		occurs:  []string{"fmt.Errorf(...)", "rows"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	},
	"decodePqSecretTable|call binary.BigEndian.Uint64": {
		carries: []string{"at", "encoded"},
		occurs:  []string{"encoded[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	},
	"decodePqSecretTable|call fmt.Errorf": {
		carries: []string{"at", "epoch", "width"},
		occurs:  []string{"?", "?", "epoch", "epoch", "width"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	},
	"decodePqSecretTable|call int": {
		carries: []string{"at", "encoded"},
		occurs:  []string{"encoded[?]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	},
	"decodePqSecretTable|literal EpochPqSecret.Epoch": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	},
	"decodePqSecretTable|literal EpochPqSecret.PqSecret": {
		carries: []string{"at", "encoded", "width"},
		occurs:  []string{"append(...)"},
		why:     "THE PQ_SECRET, copied out of the decoded table into its row: the restore's purpose. The rows go to the restored group, whose install holds them, and the encoded table is the store's own read buffer.",
	},
	"decodePqSecretWitness|call append": {
		carries: []string{"encoded", "rows"},
		occurs:  []string{"encoded[:]", "rows"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	},
	"decodePqSecretWitness|call binary.BigEndian.Uint64": {
		carries: []string{"encoded"},
		occurs:  []string{"encoded[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	},
	"decodePqSecretWitness|literal EpochPqSecretWitness.Digest": {
		carries: []string{"encoded"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	},
	"decodePqSecretWitness|literal EpochPqSecretWitness.Epoch": {
		carries: []string{"encoded"},
		occurs:  []string{"binary.BigEndian.Uint64(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	},
	"decodePqSecretWitness|return": {
		carries: []string{"rows"},
		occurs:  []string{"rows"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	},
	"decodeRemoval|call binary.BigEndian.Uint64": {
		carries: []string{"part"},
		occurs:  []string{"part[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's removal mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"decodeRemoval|call fmt.Errorf": {
		carries: []string{"part"},
		occurs:  []string{"part[0]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's removal mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"decodeRemoval|return": {
		carries: []string{"part"},
		occurs:  []string{"binary.BigEndian.Uint64(...)", "fmt.Errorf(...)", "part[0]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's removal mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"decodeWrapDark|call binary.BigEndian.Uint64": {
		carries: []string{"part"},
		occurs:  []string{"part[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's wrap-dark mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"decodeWrapDark|call fmt.Errorf": {
		carries: []string{"part"},
		occurs:  []string{"part[0]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's wrap-dark mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"decodeWrapDark|return": {
		carries: []string{"part"},
		occurs:  []string{"binary.BigEndian.Uint64(...)", "fmt.Errorf(...)", "part[0]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's wrap-dark mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	},
	"deleteGroupStateAt|call delete": {
		carries: []string{"key"},
		occurs:  []string{"key"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call filepath.Join": {
		carries: []string{"epoch", "groupId"},
		occurs:  []string{"self.epochDir(...)", "stateEpochName(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call fmt.Sprintf": {
		carries: []string{"epoch", "groupId"},
		occurs:  []string{"epoch", "groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call os.Remove": {
		carries: []string{"groupId"},
		occurs:  []string{"self.epochDir(...)", "self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call self.epochDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId", "groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call self.removeLocked": {
		carries: []string{"epoch", "groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call stateEpochName": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"deleteGroupStateAt|call zeroizeState": {
		carries: []string{"key"},
		occurs:  []string{"self.groupStates[key]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	},
	"encodeRemoval|call append": {
		carries: []string{"encoded", "kind"},
		occurs:  []string{"encoded", "encoded", "kind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeRemoval|call binary.BigEndian.PutUint64": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeRemoval|call fmt.Errorf": {
		carries: []string{"kind"},
		occurs:  []string{"kind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeRemoval|return": {
		carries: []string{"encoded", "kind"},
		occurs:  []string{"append(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the removal mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeWrapDark|call append": {
		carries: []string{"encoded", "kind"},
		occurs:  []string{"encoded", "encoded", "kind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeWrapDark|call binary.BigEndian.PutUint64": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeWrapDark|call fmt.Errorf": {
		carries: []string{"kind"},
		occurs:  []string{"kind"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"encodeWrapDark|return": {
		carries: []string{"encoded", "kind"},
		occurs:  []string{"append(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the wrap-dark mark encoded: a kind and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"epochDir|call filepath.Join": {
		carries: []string{"groupId"},
		occurs:  []string{"self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's epoch directory, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"epochDir|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's epoch directory, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"epochDir|return": {
		carries: []string{"groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's epoch directory, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"epochKeyDelivery|call append": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"readKey", "writeKey"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	},
	"epochKeyDelivery|literal protocol.EpochKeyDelivery.ReadKey": {
		carries: []string{"readKey"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	},
	"epochKeyDelivery|literal protocol.EpochKeyDelivery.WriteKey": {
		carries: []string{"writeKey"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	},
	"epochKeysFor|call commitCarriesItsKeys": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	},
	"epochKeysFor|call epochKeyDelivery": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"readKey", "writeKey"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	},
	"epochKeysFor|return": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"epochKeyDelivery(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the epoch keys a commit opens, made into the delivery the server is handed on purpose (ruling 33), and the sealed commit they belong to.",
	},
	"epochRaceRefusal|call fmt.Errorf": {
		carries: []string{"reason", "record"},
		occurs:  []string{"reason", "record.Header.Epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record that lost an epoch race: the reason, a server code, and the record's header epoch are formatted, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"epochRaceRefusal|call isEpochWrapRecord": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record that lost an epoch race: the reason, a server code, and the record's header epoch are formatted, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"epochRaceRefusal|return": {
		carries: []string{"reason", "record"},
		occurs:  []string{"fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a refusal of a sealed record that lost an epoch race: the reason, a server code, and the record's header epoch are formatted, both public. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"eraseJoinedRecord|call os.ReadDir": {
		carries: []string{"groupId"},
		occurs:  []string{"self.epochDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call os.Remove": {
		carries: []string{"groupId"},
		occurs:  []string{"self.epochDir(...)", "self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.clearPendingLocked": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.epochDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId", "groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.groupRecordPath": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.recordedPath": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedRecord|call self.removeLocked": {
		carries: []string{"groupId"},
		occurs:  []string{"self.groupRecordPath(...)", "self.recordedPath(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	},
	"eraseJoinedState|call eraser.deleteGroupStateAt": {
		carries: []string{"epoch", "groupId"},
		occurs:  []string{"epoch", "groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	},
	"eraseJoinedState|call fmt.Errorf": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	},
	"eraseJoinedState|return": {
		carries: []string{"epoch", "groupId"},
		occurs:  []string{"eraser.deleteGroupStateAt(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	},
	"groupDir|call filepath.Join": {
		carries: []string{"groupId"},
		occurs:  []string{"stateNameOf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's directory, built from its id. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is; a group id is public, and so is the path.",
	},
	"groupDir|call stateNameOf": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's directory, built from its id. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is; a group id is public, and so is the path.",
	},
	"groupDir|return": {
		carries: []string{"groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's directory, built from its id. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is; a group id is public, and so is the path.",
	},
	"groupRecordPath|call filepath.Join": {
		carries: []string{"groupId"},
		occurs:  []string{"self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's path, built from the group's id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"groupRecordPath|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's path, built from the group's id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"groupRecordPath|return": {
		carries: []string{"groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group record's path, built from the group's id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"haltLocked|assign self.halted": {
		carries: []string{"refusal"},
		occurs:  []string{"refusal"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the group's halt, a refusal error kept as the reason the group stops; the error is built of public facts about a record, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"holdReplacing|assign self.groups[string(...)]": {
		carries: []string{"group"},
		occurs:  []string{"group"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	},
	"holdReplacing|call delete": {
		carries: []string{"group"},
		occurs:  []string{"string(...)", "string(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	},
	"holdReplacing|call fmt.Errorf": {
		carries: []string{"group"},
		occurs:  []string{"group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	},
	"holdReplacing|call string": {
		carries: []string{"group"},
		occurs:  []string{"group.id", "group.id", "group.id", "group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	},
	"holdReplacing|return": {
		carries: []string{"group"},
		occurs:  []string{"fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table in place of the one judged, by its id, as hold does.",
	},
	"hold|assign self.groups[string(...)]": {
		carries: []string{"group"},
		occurs:  []string{"group"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	},
	"hold|call delete": {
		carries: []string{"group"},
		occurs:  []string{"string(...)", "string(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	},
	"hold|call fmt.Errorf": {
		carries: []string{"group"},
		occurs:  []string{"group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	},
	"hold|call string": {
		carries: []string{"group"},
		occurs:  []string{"group.id", "group.id", "group.id", "group.id"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	},
	"hold|return": {
		carries: []string{"group"},
		occurs:  []string{"fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a Group held in the device's table by its id. The Group holds the pq_secret table, and holding it is the table's job: the map keeps the live group, keyed by its public id, and the refusal formats the id.",
	},
	"isEpochWrapRecord|call message.ParseServerAttachment": {
		carries: []string{"record"},
		occurs:  []string{"record.Header.ServerAttachment"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record read for whether its public server attachment is an epoch wrap.",
	},
	"isEpochWrapRecord|return": {
		carries: []string{"attachment"},
		occurs:  []string{"?"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record read for whether its public server attachment is an epoch wrap.",
	},
	"joinAuthPreimage|call sha256.Sum256": {
		carries: []string{"joinSeal"},
		occurs:  []string{"joinSeal"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the join MAC's preimage: the join seal is ciphertext, hashed with SHA-256, and the hash goes into the preimage, every part of which is public.",
	},
	"joinAuthPreimage|call writer.WriteOpaqueLP": {
		carries: []string{"sealHash"},
		occurs:  []string{"sealHash[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the join MAC's preimage: the join seal is ciphertext, hashed with SHA-256, and the hash goes into the preimage, every part of which is public.",
	},
	"matchesEpochDigestLocked|call message.EpochKeysDigest": {
		carries: []string{"readKey", "writeKey"},
		occurs:  []string{"readKey", "writeKey"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|call message.ReadKey": {
		carries: []string{"root"},
		occurs:  []string{"root"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|call message.WriteKey": {
		carries: []string{"root"},
		occurs:  []string{"root"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|call messagegroup.StorageRoot": {
		carries: []string{"candidate"},
		occurs:  []string{"candidate"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|call subtle.ConstantTimeCompare": {
		carries: []string{"computed"},
		occurs:  []string{"computed"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|call zeroizeState": {
		carries: []string{"readKey", "root", "writeKey"},
		occurs:  []string{"readKey", "root", "writeKey"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"matchesEpochDigestLocked|return": {
		carries: []string{"computed"},
		occurs:  []string{"?"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	},
	"pendingPath|call filepath.Join": {
		carries: []string{"groupId"},
		occurs:  []string{"self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's pending-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"pendingPath|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's pending-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"pendingPath|return": {
		carries: []string{"groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's pending-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"persistGroup|call store.PutGroupRecord": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the restore path's write of a group record through the store. The record holds the pq_secret table, which the durable store persists by design (the record's own row); persistGroup hands it on and keeps nothing.",
	},
	"persistGroup|return": {
		carries: []string{"record"},
		occurs:  []string{"store.PutGroupRecord(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the restore path's write of a group record through the store. The record holds the pq_secret table, which the durable store persists by design (the record's own row); persistGroup hands it on and keeps nothing.",
	},
	"pqSecretHeldAtLocked|call sha256.Sum256": {
		carries: []string{"candidate"},
		occurs:  []string{"candidate"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret hashed and compared with the digests this device has witnessed: SHA-256 of it, compared in constant time; nothing is kept.",
	},
	"projectionOf|assign projection.RecoveryHandle": {
		carries: []string{"attachment"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|assign projection.WrapTargetHandle": {
		carries: []string{"attachment"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|call append": {
		carries: []string{"attachment", "header"},
		occurs:  []string{"attachment.Recovery.RecoveryHandle", "attachment.Wrap.WrapTargetHandle", "header.BlobId", "header.BodyHash[:]", "header.SenderHandle[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|call message.EncodeRecord": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|call message.ParseServerAttachment": {
		carries: []string{"header"},
		occurs:  []string{"header.ServerAttachment"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|call message.RetentionClassWire": {
		carries: []string{"header"},
		occurs:  []string{"header.EphBucket", "header.RetentionClass"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|call uint32": {
		carries: []string{"header", "retentionWire"},
		occurs:  []string{"header.SizeBucket", "retentionWire"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.BlobId": {
		carries: []string{"header"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.BodyHash": {
		carries: []string{"header"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.Epoch": {
		carries: []string{"header"},
		occurs:  []string{"header.Epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.ExpireAtMs": {
		carries: []string{"header"},
		occurs:  []string{"header.ExpireAt"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.IsCommit": {
		carries: []string{"header"},
		occurs:  []string{"header.IsCommit"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.RecordBytes": {
		carries: []string{"recordBytes"},
		occurs:  []string{"recordBytes"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.RetentionClass": {
		carries: []string{"retentionWire"},
		occurs:  []string{"uint32(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.SenderHandle": {
		carries: []string{"header"},
		occurs:  []string{"append(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.SizeBucket": {
		carries: []string{"header"},
		occurs:  []string{"uint32(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|literal protocol.Record.StreamIndex": {
		carries: []string{"header"},
		occurs:  []string{"header.StreamIndex"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"projectionOf|return": {
		carries: []string{"projection"},
		occurs:  []string{"projection"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record projected into the wire's protocol.Record: its bytes are ciphertext and macs, and every other field is a public header field the server verifies against them (Spec B section 5.1). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"recordedPath|call filepath.Join": {
		carries: []string{"groupId"},
		occurs:  []string{"self.groupDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's recorded-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"recordedPath|call self.groupDir": {
		carries: []string{"groupId"},
		occurs:  []string{"groupId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's recorded-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"recordedPath|return": {
		carries: []string{"groupId"},
		occurs:  []string{"filepath.Join(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a group's recorded-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"refuseRemovalOnHeldSecret|call fmt.Errorf": {
		carries: []string{"heldAt"},
		occurs:  []string{"heldAt"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the refusal of a removal that reuses a secret this device has held: heldAt is the EPOCH it was held at, a number, which the refusal prints so that a stale secret and a replayed one can be told apart.",
	},
	"refuseRemovalOnHeldSecret|return": {
		carries: []string{"heldAt"},
		occurs:  []string{"fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the refusal of a removal that reuses a secret this device has held: heldAt is the EPOCH it was held at, a number, which the refusal prints so that a stale secret and a replayed one can be told apart.",
	},
	"removeLocked|call filepath.Dir": {
		carries: []string{"path"},
		occurs:  []string{"path"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"removeLocked|call fmt.Errorf": {
		carries: []string{"path"},
		occurs:  []string{"path", "path"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"removeLocked|call os.Remove": {
		carries: []string{"path"},
		occurs:  []string{"path"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"removeLocked|call os.Stat": {
		carries: []string{"path"},
		occurs:  []string{"path"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"removeLocked|call syncStateDir": {
		carries: []string{"path"},
		occurs:  []string{"filepath.Dir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"removeLocked|return": {
		carries: []string{"path"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a file removed by its path, and its directory synced. The path is built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table.",
	},
	"restoreOne|assign restored.ownHandles[messagegroup.SenderHandle(...)]": {
		carries: []string{"restored", "row"},
		occurs:  []string{"true"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a restored row's witness and own handles filed in the restored group. The row is carried whole; the witness is a digest, and a sender handle is public.",
	},
	"restoreOne|assign restored.pqSecretWitness[row.Epoch]": {
		carries: []string{"row"},
		occurs:  []string{"witness"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a restored row's witness and own handles filed in the restored group. The row is carried whole; the witness is a digest, and a sender handle is public.",
	},
	"sealFoundingJoinLocked|call epochKeysDigestOver": {
		carries: []string{"foundingSecret"},
		occurs:  []string{"foundingSecret"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the founding seal: the founding secret, a pq_secret, sealed to the joiner and digested as H(epoch_keys), which is public. The seal is ciphertext and the MAC is public.",
	},
	"sealFoundingJoinLocked|call self.sealJoinLocked": {
		carries: []string{"foundingSecret", "joinDigest"},
		occurs:  []string{"foundingSecret", "joinDigest"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the founding seal: the founding secret, a pq_secret, sealed to the joiner and digested as H(epoch_keys), which is public. The seal is ciphertext and the MAC is public.",
	},
	"sealFoundingJoinLocked|return": {
		carries: []string{"joinAuth", "joinDigest", "joinSeal"},
		occurs:  []string{"joinAuth", "joinDigest", "joinSeal"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the founding seal: the founding secret, a pq_secret, sealed to the joiner and digested as H(epoch_keys), which is public. The seal is ciphertext and the MAC is public.",
	},
	"sendSealedLocked|call epochRaceRefusal": {
		carries: []string{"reason", "record", "retryReason"},
		occurs:  []string{"reason", "record", "record", "retryReason"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|call fmt.Errorf": {
		carries: []string{"reason", "retryReason"},
		occurs:  []string{"reason", "reason", "reason", "reason", "retryReason"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|call projectionOf": {
		carries: []string{"record"},
		occurs:  []string{"record", "record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|call self.cloneRefusalLocked": {
		carries: []string{"reason", "record", "retryReason"},
		occurs:  []string{"reason", "record", "record", "retryReason"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|call send": {
		carries: []string{"projection", "retryProjection"},
		occurs:  []string{"projection", "retryProjection"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|call session.ReauthRecord": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"sendSealedLocked|return": {
		carries: []string{"lost", "reason", "recordId", "refusal", "retryReason", "retryRecordId"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "lost", "lost", "recordId", "refusal", "refusal", "retryRecordId"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"stateEpochName|call fmt.Sprintf": {
		carries: []string{"epoch"},
		occurs:  []string{"epoch"},
		why:     "Reached by the walk into this package's own functions (LRI R68): an epoch's file name, the epoch in decimal, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"stateEpochName|return": {
		carries: []string{"epoch"},
		occurs:  []string{"fmt.Sprintf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): an epoch's file name, the epoch in decimal, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"stateNameOf|call hex.EncodeToString": {
		carries: []string{"sum"},
		occurs:  []string{"sum[:]"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a state file's name: the hex of SHA-256 over a key, here a group id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"stateNameOf|call sha256.Sum256": {
		carries: []string{"key"},
		occurs:  []string{"key"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a state file's name: the hex of SHA-256 over a key, here a group id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"stateNameOf|return": {
		carries: []string{"sum"},
		occurs:  []string{"hex.EncodeToString(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a state file's name: the hex of SHA-256 over a key, here a group id, which is public and is carried as a field of a record that holds the pq_secret table.",
	},
	"submitLocked|call alignedEpochKeys": {
		carries: []string{"delivery", "record"},
		occurs:  []string{"delivery", "record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"submitLocked|call self.sendSealedLocked": {
		carries: []string{"record"},
		occurs:  []string{"record"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"submitLocked|literal protocol.SubmitRequest.EpochKeys": {
		carries: []string{"aligned"},
		occurs:  []string{"aligned"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"submitLocked|return": {
		carries: []string{"body", "record", "response"},
		occurs:  []string{"body.GetResults(...).GetReason(...)", "body.GetResults(...).GetRecordId(...)", "response.GetReason(...)", "self.sendSealedLocked(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	},
	"syncStateDir|call fmt.Errorf": {
		carries: []string{"dir"},
		occurs:  []string{"dir", "dir"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a directory synced after a write or a removal. Its path is built of a group id, public, carried as a field of a record that holds the pq_secret table.",
	},
	"syncStateDir|call os.Open": {
		carries: []string{"dir"},
		occurs:  []string{"dir"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a directory synced after a write or a removal. Its path is built of a group id, public, carried as a field of a record that holds the pq_secret table.",
	},
	"syncStateDir|return": {
		carries: []string{"dir"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): a directory synced after a write or a removal. Its path is built of a group id, public, carried as a field of a record that holds the pq_secret table.",
	},
	"writeRecord|call filepath.Dir": {
		carries: []string{"path"},
		occurs:  []string{"path"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call fmt.Errorf": {
		carries: []string{"dir", "path", "syncErr", "tempPath"},
		occurs:  []string{"dir", "dir", "path", "syncErr", "tempPath", "tempPath", "tempPath", "tempPath", "tempPath"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call os.CreateTemp": {
		carries: []string{"dir"},
		occurs:  []string{"dir"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call os.MkdirAll": {
		carries: []string{"dir"},
		occurs:  []string{"dir"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call os.Remove": {
		carries: []string{"tempPath"},
		occurs:  []string{"tempPath"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call os.Rename": {
		carries: []string{"path", "tempPath"},
		occurs:  []string{"path", "tempPath"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|call syncStateDir": {
		carries: []string{"dir"},
		occurs:  []string{"dir"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"writeRecord|return": {
		carries: []string{"dir", "path", "syncErr", "tempPath"},
		occurs:  []string{"fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "fmt.Errorf(...)", "syncStateDir(...)"},
		why:     "Reached by the walk into this package's own functions (LRI R68): the store's one write path, by its PATH this time: the path, its directory and the temporary file's name are built of a group id and an epoch, public, carried as fields of a record that holds the pq_secret table. What goes to the disk is the existing rows' subject (writeRecord|call temp.Write).",
	},
	"zeroizeState|assign octets[at]": {
		carries: []string{"at"},
		occurs:  []string{"0"},
		why:     "Reached by the walk into this package's own functions (LRI R68): THE ERASE: every octet of a value set to zero. at is the loop's index, tainted by ranging over the value; it is a position.",
	},
}

var pqSecretCountedNotCarriedSites = map[string]string{
	"encodeJoinSecrets|len pqSecret":     "the encoder's width check and its refusal text: three 32 octet values or nothing.",
	"PutGroupRecord|len record.PqSecret": "the durable writer's 'this record carries neither' refusal.",
	"PutGroupRecord|len rows":            "the arity of the table about to be written.",
	"encodePqSecretTable|len row.PqSecret": "THE ENCODER'S WIDTH, at the one place a secret's own length is read and formatted. It is " +
		"the site the ADV-M1 shape would attack from: one edit turns the count into the value, " +
		"and the sink census refuses it.",
	"encodePqSecretTable|len rows": "the capacity hint for the frame.",
	"encodePqSecretWitness|len row.Digest": "THE WITNESS ENCODER'S FIXED WIDTH, which is the one place this part is spelled " +
		"differently from the table beside it: a digest's width is this package's own, so a row of " +
		"any other width is refused rather than length-prefixed.",
	"encodePqSecretWitness|len rows":    "the capacity hint for the witness frame.",
	"sortEpochPqSecretWitness|len rows": "the witness sort's bound.",
	"encodeLeafOccupancy|len rows":      "the capacity hint for part nine's frame.",
	"sortLeafOccupancy|len rows":        "the leaf ledger sort's bound.",
	"witnessPqSecretLocked|len pqSecret": "the witness's own emptiness guard: an empty value is not witnessed, because " +
		"[Group.pqSecretHeldAtLocked] answers false for an empty candidate and a witness row of " +
		"H(nothing) would make 'this device holds nothing' read as 'this device has already held it'.",
	"encodeStateRecord|len part": "the framing's per-part width. On a group record this is the length of the pq_secret and " +
		"of each table row, and the refusal beside it formats that length.",
	"encodeStateRecord|len parts": "the framing's own arity: the 255 refusal, and the part count written into the frame's " +
		"header as one byte.",
	"groupRecordOf|len parts": "the reader's arity switch and its refusal text: five parts or six, and anything else is " +
		"a record this build cannot read.",
	"groupRecordOf|len parts[3]": "the epoch part's own width. It is a site of its own rather than part of the entry above " +
		"because this census spells the index: `len(parts)` counts the record and `len(parts[3])` " +
		"counts one part inside it, and a disposition that called those one site would excuse the " +
		"second by having weighed the first.",
	"groupRecordOf|len parts[4]": "the opened flag's width, for the same reason and as its own site.",
	"ingestWrapLocked|len payload": "THE WRAP PAYLOAD'S WIDTH, checked before a payload can become a candidate. A payload of " +
		"the wrong width is erased and counted, never formatted.",
	"initTables|len self.pqSecrets":            "the ownership copy's capacity hint.",
	"pqSecretRecordsLocked|len self.pqSecrets": "the row slice's capacity hint.",
	"pqSecretsMapOf|len table":                 "the map's capacity hint.",
	"pqSecretsShowRotation|len table": "the rotation check's loop bound -- a COUNT that decides nothing, which is the whole " +
		"point of that function's header: rotation is decided on the octets.",
	"publishCommitLocked|len targets": "expected_wrap_count and the marker's wrap_count, which item 132's client half makes ONE " +
		"expression. `targets` is tainted only because it is bound in the same statement as " +
		"`staged.pqSecret`; what is counted is a list of leaves.",
	"restoreOne|len row.Digest": "THE RESTORED WITNESS ROW'S WIDTH, refused by name before the copy below it. A short " +
		"digest copied into a fixed array would leave zero octets in the tail and make one witness " +
		"row match a value nobody ever held; the refusal formats that COUNT and never the row.",
	"restoredPqSecrets|len record.PqSecret": "the five-part arm's 'neither a table nor a scalar' refusal.",
	"restoredPqSecrets|len record.PqSecrets": "the six-part arm's row count, and the refusal text for a table that does not cover its " +
		"own epoch.",
	"sortEpochPqSecrets|len rows": "the sort's bound.",
	"sealJoinLocked|len joinSeal": "the seal's exact length, asserted before it is handed on, and that refusal's text. A count of ciphertext.",
	// ── R68: SITES THE WALK REACHES INSIDE THIS PACKAGE'S OWN FUNCTIONS. The walk follows a value it holds into
	// the function it is handed to, to a fixpoint (the review of identity phase 1's Tasks 8 to 10, L1-1), and a
	// map's key is a carried value (L2-02); these rows are the sites that brought into view, each with its reason.
	"PutGroupRecord|len record.GroupHandleKey":             "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"PutGroupRecord|len record.GroupId":                    "Reached by the walk into this package's own functions (LRI R68): the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"decodeJoinSecrets|len payload":                        "Reached by the walk into this package's own functions (LRI R68): an opened join payload cut into its three values, as copies: the pq_secret, the handle key and the epoch keys digest. The payload was sealed to this device and opened by it; what it answers is installed by the join, whose rows hold it, and the caller erases the payload.",
	"decodeLeafOccupancy|len encoded":                      "Reached by the walk into this package's own functions (LRI R68): a group record's leaf occupancy part decoded. The record's parts are carried whole, the pq_secret table among them, and the walk cannot tell them apart; the occupancy is leaf numbers, epochs and a flag, all public.",
	"decodePqSecretTable|len encoded":                      "Reached by the walk into this package's own functions (LRI R68): the group record's pq_secret table decoded into its rows. THE PQ_SECRET ITSELF lands here: each row's secret is copied out of the encoded table into EpochPqSecret.PqSecret, which is the restore's purpose (the table's own rows say where it goes next). The epoch and the offsets are numbers.",
	"decodePqSecretWitness|len encoded":                    "Reached by the walk into this package's own functions (LRI R68): a group record's witness part decoded: each row is an epoch and SHA-256 of a pq_secret this device has held, which is not the secret.",
	"decodeRemoval|len part":                               "Reached by the walk into this package's own functions (LRI R68): a group record's removal mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	"decodeWrapDark|len part":                              "Reached by the walk into this package's own functions (LRI R68): a group record's wrap-dark mark decoded: a kind and an epoch, public. The record's parts are carried whole, the pq_secret table among them.",
	"encodeJoinSecrets|len epochKeysDigest":                "Reached by the walk into this package's own functions (LRI R68): the epoch keys digest, public, framed into join_secrets_v1 beside the pq_secret.",
	"epochKeyDelivery|len readKey":                         "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	"epochKeyDelivery|len writeKey":                        "Reached by the walk into this package's own functions (LRI R68): the epoch keys copied into the delivery the server is handed on purpose (ruling 33; the copy is what keeps a deferred Destroy from emptying it).",
	"eraseJoinedRecord|len epochs":                         "Reached by the walk into this package's own functions (LRI R68): the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"isEpochWrapRecord|len record.Header.ServerAttachment": "Reached by the walk into this package's own functions (LRI R68): a sealed record read for whether its public server attachment is an epoch wrap.",
	"matchesEpochDigestLocked|len candidate":               "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret tried against an epoch's published digest: the storage root, and the epoch's write and read keys, are derived from it and the epoch's mls secret inside this call and erased in it (zeroizeState), and only H(epoch_keys) is compared, in constant time. The keys are the pair item 244 removed from the wire, and they never leave this function.",
	"pqSecretHeldAtLocked|len candidate":                   "Reached by the walk into this package's own functions (LRI R68): a candidate pq_secret hashed and compared with the digests this device has witnessed: SHA-256 of it, compared in constant time; nothing is kept.",
	"submitLocked|len body.GetResults(...)":                "Reached by the walk into this package's own functions (LRI R68): a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
}

var pqSecretAccumulatorSites = map[string]string{
	"foundGroupLocked|accumulate self.hold": "THE DEVICE. A group whose table holds the founding secret goes into [Device.groups], and " +
		"what that map does with it afterwards is not a thing this walk over names can follow. It " +
		"is bounded: the group's own table is censused wherever it is read.",
	"Join|accumulate self.holdReplacing": "the same, for a joiner.",
	"Join|accumulate self.abandonJoined": "A JOIN THAT FAILED AFTER ITS COMMIT (Task 57, F3), and a horizon by the letter " +
		"of the rule rather than a blind spot in fact: [Device.abandonJoined] is in this census's own " +
		"sources, and what it does with the group is close it -- the session, the handle and the " +
		"table's erase -- and erase the joined epoch's state from the store. It keeps nothing.",
	"Join|accumulate self.persistGroup": "THE DISK, one frame out. [Device.persistGroup] hands the record to the store, whose own " +
		"write path IS censused -- PutGroupRecord, and the two calls under it -- so the blindness " +
		"here is bounded by one function body.",
	"encodeStateRecord|accumulate body.Write": "THE FRAME. Each part goes into the *bytes.Buffer the record is assembled in, and the " +
		"walk does not follow it into the buffer -- so `body.Bytes()` reads back a value this " +
		"census does not know carries the secret. The value comes back out as `writeRecord`'s " +
		"`record`, which IS censused, so the blindness is bounded by one function body.",
	"ingestCommitLocked|accumulate self.haltLocked": "RULING 41's REFUSAL, and it is a horizon by the letter of the rule -- a method on this " +
		"same group -- rather than a blind spot in fact. [Group.haltLocked] is in this census's own " +
		"sources: its whole body sets two fields from the ERROR it was handed and writes the group " +
		"record through [Group.groupRecordLocked], which is censused above. What crosses this call " +
		"is a sentence, never a secret.",
	"ingestCommitLocked|accumulate self.session.AdvanceEpoch": "the same door on the receive leg.",
	"publishCommitLocked|accumulate self.session.AdvanceEpoch": "CONNECT'S OWN TABLE. The secret enters [messagegroup.GroupSession], which holds it under " +
		"its own erase discipline and its own gates. This package cannot see inside it and does " +
		"not claim to.",
	"publishCommitLocked|accumulate self.submitLocked": "THE WIRE. The commit and its wrap records go to the server as ciphertext.",
	"resolvePqSecretLocked|accumulate self.matchesEpochDigestLocked": "THE DIGEST CHECK, which is a method on this same group and is therefore a horizon rather " +
		"than a sink by the letter of the rule. It is not a blind spot in fact: " +
		"matchesEpochDigestLocked is in this census's own sources and its two derived keys are " +
		"dropped inside it.",
	"resolvePqSecretLocked|accumulate self.pqSecretHeldAtLocked": "THE REMOVAL RULE'S COMPARISON, at the resolution's one guarded exit. A horizon by the " +
		"letter of the rule -- a method on this same group -- and not a blind spot in fact: " +
		"[Group.pqSecretHeldAtLocked] is in this census's own sources, it COPIES nothing, it " +
		"keeps nothing and it derives nothing; its whole body is a ConstantTimeCompare of the " +
		"candidate against rows of a table this census already covers, and what it answers is an " +
		"epoch number and a bool. Its header carries why the subject is the whole table.",
	"sealEpochWrapLocked|accumulate self.session.SealRecord": "the session's sealer, taking the wrap body that is already a ciphertext of the secret.",
	"sealJoinLocked|accumulate self.device.crypto.Mac":       "the MAC's input. What goes in is the preimage, which is public values and three hashes; the provider keeps nothing of it.",
	"AddMember|accumulate self.sealFoundingJoinLocked":       "THE FOUNDING SEAL, one frame out. The secret goes into [Group.sealJoinLocked], whose own body IS censused, so the blindness here is bounded by one call.",
	// ── R68: HORIZONS AT THE CALLS THE WALK NOW REACHES. Twenty-four are methods of this package's own, which
	// stay horizons by the letter of the rule -- the receiver is not followed -- while the walk follows the value
	// into the method's body as well (L1-1); two are objects of other packages, each named in its row.
	"PutGroupRecord|accumulate self.clearPendingLocked":     "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"PutGroupRecord|accumulate self.groupRecordPath":        "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"PutGroupRecord|accumulate self.recordedPath":           "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the durable store's write of a group record, which holds the pq_secret table by design, handed whole by persistGroup. Here the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is: the group id, the epoch, the handle key, the leaf occupancy, the removal and wrap-dark marks and the witness digests are read into their encodings, the record's paths and the refusal text, all of them public; the table itself is the existing rows' subject.",
	"abandonJoined|accumulate eraser.eraseJoinedRecord":     "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a join being abandoned: the Group's id and epoch name the state to erase, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is. A group id and an epoch are public.",
	"abandonJoined|accumulate self.eraseJoinedState":        "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a join being abandoned: the Group's id and epoch name the state to erase, and the walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is. A group id and an epoch are public.",
	"clearPendingLocked|accumulate self.pendingPath":        "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	"clearPendingLocked|accumulate self.removeLocked":       "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's pending mark, removed by its path. The path is built from the group id, a field of a record that also holds the pq_secret table; a group id is public and so is a path built of it.",
	"deleteGroupStateAt|accumulate self.epochDir":           "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	"deleteGroupStateAt|accumulate self.groupDir":           "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	"deleteGroupStateAt|accumulate self.removeLocked":       "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: one epoch's state erased, in either store, by its group id and epoch. They are public, and carried because they are fields of a Group that holds the pq_secret table; the map entry and the file are erased (zeroizeState, os.Remove).",
	"epochDir|accumulate self.groupDir":                     "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a group's epoch directory, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"eraseJoinedRecord|accumulate self.clearPendingLocked":  "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedRecord|accumulate self.epochDir":            "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedRecord|accumulate self.groupDir":            "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedRecord|accumulate self.groupRecordPath":     "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedRecord|accumulate self.recordedPath":        "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedRecord|accumulate self.removeLocked":        "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the store's erase of a join's group record and folders, by the group id. The id is a field of a record that also holds the pq_secret table, and the walk cannot tell the fields apart; the id is public, and so are the paths built of it.",
	"eraseJoinedState|accumulate eraser.deleteGroupStateAt": "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a join's epoch state erased by its group id and epoch, both public, which the walk carries because they are fields of a Group that holds the pq_secret table.",
	"groupRecordPath|accumulate self.groupDir":              "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a group record's path, built from the group's id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"joinAuthPreimage|accumulate writer.WriteOpaqueLP":      "THE PREIMAGE'S WRITER (reached since LRI R68, which follows the join seal into joinAuthPreimage): SHA-256 of the join seal, which is ciphertext, goes into the syntax writer join_auth's 181-octet preimage is built in. Every part of that preimage is public, and the writer keeps nothing past the preimage it answers.",
	"pendingPath|accumulate self.groupDir":                  "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a group's pending-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"persistGroup|accumulate store.PutGroupRecord":          "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: the restore path's write of a group record through the store. The record holds the pq_secret table, which the durable store persists by design (the record's own row); persistGroup hands it on and keeps nothing.",
	"recordedPath|accumulate self.groupDir":                 "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a group's recorded-mark path, built from its id, which is public and is carried as a field of a record that holds the pq_secret table.",
	"sendSealedLocked|accumulate self.cloneRefusalLocked":   "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a sealed record sent to the server, and its refusals: the projection is ciphertext and public header fields, and the reasons are server codes. The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
	"sendSealedLocked|accumulate session.ReauthRecord":      "THE SESSION'S RE-MAC, S2-2's recovery (reached since LRI R68, which follows the record into sendSealedLocked): the sealed record goes back into [messagegroup.GroupSession] to have its write_auth recomputed under the session's own keys. The record is ciphertext and public header fields; the session holds its keys under its own erase discipline, as the AdvanceEpoch rows say.",
	"submitLocked|accumulate self.sendSealedLocked":         "A HORIZON BY THE LETTER OF THE RULE, as Join|accumulate self.abandonJoined's row has it: a method of this package's own, on a receiver the walk does not follow. Since LRI R68 the walk follows the value into the method's body as well, where its sites are rows of their own, so what this row leaves unfollowed is the receiver's state after the call and not the body. Here: a sealed record submitted with the epoch keys its commit opens, which the server is handed on purpose (ruling 33). The walk follows a record, a Group or a store row whole, and cannot tell its fields apart, so a field that is not the secret is carried as one that is.",
}

func TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes(t *testing.T) {
	census := runCensus(t, pqSecretProducerNames)

	// ── THE COMPLEMENT, PRINTED: what this search covered and what it left out ────────────────
	t.Logf("production sources read (%d): %v", len(census.sources), census.sources)
	t.Logf("producer net (a name whose call, field read, parameter or result is taken to be a "+
		"pq_secret): %v", epochKeySortedKeys(pqSecretProducerNames))
	t.Logf("producer sites found (%d):", len(census.producers))
	for _, site := range epochKeySortedMap(census.producers) {
		t.Logf("    %s  at %v", site, census.producers[site])
	}
	t.Logf("sink sites found (%d), each with THE VALUES IT CARRIES and each OCCURRENCE, which are "+
		"what the disposition is held against a second and a third time:", len(census.sinks))
	for _, site := range epochKeySortedMap(census.sinks) {
		occurs := append([]string(nil), census.occurrences[site]...)
		sort.Strings(occurs)
		t.Logf("    %s  carries %v  occurs [%s]  at %v", site,
			epochKeySortedKeys(census.carried[site]), strings.Join(occurs, " | "), census.sinks[site])
	}
	t.Logf("COUNTED AND NOT CARRIED (%d) -- the sites the one narrowing removed, which are "+
		"asserted below and not merely printed:", len(census.counted))
	for _, site := range epochKeySortedMap(census.counted) {
		t.Logf("    %s  at %v", site, census.counted[site])
	}
	t.Logf("THE WALK'S HORIZON (%d) -- the calls at which a pq_secret enters an object this "+
		"census does not follow it into, which is where this gate stops knowing:",
		len(census.accumulated))
	for _, site := range epochKeySortedMap(census.accumulated) {
		t.Logf("    %s  at %v", site, census.accumulated[site])
	}
	t.Logf("EXCLUDED, and excluded is not the same as absent -- tainted values that reach no sink "+
		"in their own function, so nothing carried them anywhere: %v", census.unspent)

	// ── AND ASSERTED, IN BOTH DIRECTIONS, AGAINST FOUR WRITTEN-DOWN DISPOSITIONS ──────────────
	censusHold(t, "producer site", census.producers, pqSecretProducerSites,
		"A name that produces a pq_secret is where this gate's whole search begins. A site with no "+
			"entry is a secret coming from somewhere nobody weighed; an entry with no site is this "+
			"gate having gone BLIND -- the producer was respelled, and every sink clause below is "+
			"now searching a value nothing tainted, which passes by finding nothing.")

	sinkWhy := map[string]string{}
	for site, entry := range pqSecretSinks {
		sinkWhy[site] = entry.why
	}
	sinkNarrowing := "pq_secret is the ONLY post-quantum material in this system -- ledger item " +
		"251 measured connect/mls's HPKE hard-wired to X25519 -- and the shape this gate exists to " +
		"refuse is `fmt.Errorf(\"%x\", secret)`: the group's live post-quantum secret in an error " +
		"string, in every log that error ever reaches. It was MEASURED possible on the commit " +
		"before this file (mutant ADV-M1, `ok 6.609s`, the whole ./urmessage suite green), with " +
		"the identical shape over an epoch key as the control that DID go red. A site with no " +
		"entry is a secret landing somewhere nobody weighed, and `Detail: held[:]` fails here " +
		"exactly as `fmt.Errorf(\"%x\", held)` does. An entry with no site is a disposition that " +
		"has stopped describing the code."
	censusHold(t, "sink site", census.sinks, sinkWhy, sinkNarrowing)

	// ── THE SECOND NARROWING: NOT ONLY WHERE, BUT WHICH VALUE ─────────────────────────────────
	for _, site := range epochKeySortedMap(census.sinks) {
		entry, dispositioned := pqSecretSinks[site]
		if !dispositioned {
			continue // already refused above, by name
		}
		allowed := map[string]bool{}
		for _, spelled := range entry.carries {
			allowed[spelled] = true
		}
		for _, spelled := range epochKeySortedKeys(census.carried[site]) {
			if !allowed[spelled] {
				t.Errorf("sink site %q carries %q and its disposition entry does not list it "+
					"(it lists %v).\n%s", site, spelled, entry.carries, sinkNarrowing)
			}
		}
		for _, spelled := range entry.carries {
			if !census.carried[site][spelled] {
				t.Errorf("the disposition says sink site %q carries %q and the census finds only "+
					"%v there. A value that has stopped arriving is either a fix nobody deleted "+
					"the entry for or a rename this gate is now blind to.\n%s",
					site, spelled, epochKeySortedKeys(census.carried[site]), sinkNarrowing)
			}
		}
	}

	// ── THE THIRD: HOW MANY TIMES, AND IN WHAT SPELLING (LRI R68, L2-01) ─────────────────────
	occursListed := map[string][]string{}
	for site, entry := range pqSecretSinks {
		occursListed[site] = entry.occurs
	}
	censusHoldOccurrences(t, census.occurrences, occursListed, sinkNarrowing)

	// ── AND THE ONE NARROWING'S OWN COMPLEMENT, ASSERTED THE SAME WAY ─────────────────────────
	censusHold(t, "counted-not-carried site", census.counted, pqSecretCountedNotCarriedSites,
		"A COUNT OF A pq_secret IS NOT A pq_secret -- `len(payload)` is an int -- and that single "+
			"exclusion is what keeps nineteen width refusals, arity switches and capacity hints OUT "+
			"of the sink disposition, so that an entry for one of them can never become a standing "+
			"permit to format the value itself at the same call. The exclusion is therefore a "+
			"narrowing, and this is the assertion that holds it: every site it removed is named "+
			"here. A site with no entry is a count nobody weighed; an entry with no site means the "+
			"tree stopped counting the secret there, which is a change this file has to be read "+
			"against before it is deleted.")

	// ── AND WHERE THE CENSUS ENDS, ASSERTED RATHER THAN LEFT TO BE INFERRED ───────────────────
	censusHold(t, "accumulator site", census.accumulated, pqSecretAccumulatorSites,
		"A TAINT WALK OVER NAMES STOPS WHERE A VALUE IS HANDED TO A METHOD AND LIVES ON INSIDE THE "+
			"RECEIVER, and this census is that stopping place written down. For pq_secret the three "+
			"that matter are connect's own [messagegroup.GroupSession] (AdvanceEpoch), the durable "+
			"store's write path, and the wire. A site with no entry is a NEW blind spot -- the "+
			"secret put into a buffer, a hasher or a writer nobody weighed -- and the sink clause "+
			"above will have censused the call while knowing nothing about what the object does "+
			"with it afterwards. An entry with no site is a limit that has been lifted or moved.")
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE MUTATION TABLE, MEASURED
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// EVERY ROW VARIES A DIFFERENT MECHANISM, which is the discipline four gates in this track were
// beaten for want of: a table whose every entry varies the same attribute -- a different
// destination for the same bare identifier -- cannot see a CHANGE OF MECHANISM, and a change of
// mechanism is what defeats a gate. So M1 is the finding's own mutant at the producer it walks
// from, M2 puts the same shape where the value has no name of its own, M3 and M7 come at the one
// narrowing from its two opposite sides, M4 varies the SPELLING, M5 varies the BINDING FORM, M6
// does not attack the gate at all but AVOIDS it, and M8 attacks the carries list rather than the
// site list. A SURVIVING MUTANT IS FIRST A CLAIM ABOUT THE QUERY, so each row names the failure
// text it produced rather than the word "killed".
//
// Applied one at a time by a python edit that ASSERTS count == 1, and reverted by a byte copy of a
// snapshot taken before the run whose sha256 is verified equal after: no `git checkout --`, no
// stash. Run as `go test ./urmessage -run
// 'TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes' -timeout 600s -count=1`.
//
//	M1  THE FINDING'S OWN MUTANT, at the arm it was reached on for real: `(held %x)` added to
//	    resolvePqSecretLocked's final ErrNoWrapForEpoch string, where `held` is
//	    self.pqSecrets[self.epoch]
//	    -> sink site "resolvePqSecretLocked|call fmt.Errorf" has no entry in the disposition
//	M2  THE SAME SHAPE WHERE THE VALUE HAS NO NAME OF ITS OWN: `%x` of `parts[1]` -- the persisted
//	    pq_secret -- in the durable group record's own "not one this build wrote" refusal.
//	    IT SURVIVED THE FIRST VERSION OF THIS FILE, `ok 6.6s`, with this gate PASS, because that
//	    decode was the body of a loop in [DurableStateStore.GroupRecords] and its record was a
//	    LOCAL called `parts`, which no clause of this walk seeds. A SURVIVING MUTANT IS FIRST A
//	    CLAIM ABOUT THE QUERY: the repair is in production -- the decode is now [groupRecordOf] and
//	    the record is its PARAMETER -- and `parts` joined the net as a parameter only.
//	    -> sink site "groupRecordOf|call fmt.Errorf" has no entry in the disposition
//	    -> AND sink site "groupRecordOf|return" carries "parts" and its entry does not list it
//	M3  THE ONE NARROWING, from the side that would make it a permit: `len(row.PqSecret)` ->
//	    `row.PqSecret` inside encodePqSecretTable's own width refusal, the exact call a
//	    length-carrying census would have had to excuse
//	    -> sink site "encodePqSecretTable|call fmt.Errorf" carries "row.PqSecret" and its
//	       disposition entry does not list it (it lists [row])
//	    -> AND "encodePqSecretTable|return" the same, independently
//	M4  THE SPELLING: `candidates[0].secret[:]` added to the ErrOrphanWrap refusal -- an
//	    *ast.SliceExpr through an *ast.IndexExpr, where a census wanting an *ast.Ident sees nothing
//	    -> producer site "resolvePqSecretLocked|candidates.secret" has no entry in the disposition
//	    -> AND sink site "resolvePqSecretLocked|call fmt.Errorf" has no entry
//	    -> AND "resolvePqSecretLocked|return" carries "candidates.secret", not listed -- three
//	       clauses, independently
//	M5  THE BINDING FORM, AND A REAL DEFECT: `var parked = pqSecret` and
//	    `self.pqSecrets[epoch] = parked` -- the caller's array ALIASED into the table instead of
//	    copied, which is the hazard filePqSecretLocked's own doc is about, bound with the keyword
//	    that bound nothing when the fixpoint read *ast.AssignStmt alone
//	    -> sink site "filePqSecretLocked|assign self.pqSecrets[epoch]" carries "parked" and its
//	       entry does not list it (it lists [pqSecret])
//	    -> AND the disposition says "filePqSecretLocked|call append" is allowed and the census does
//	       not find it -- the copy having vanished, reported from the other direction
//	M6  A CHANGE OF MECHANISM RATHER THAN AN ATTACK: the rotation's draw moved behind
//	    `self.drawPqSecret()`, which is how a gate is AVOIDED rather than defeated. Every direction
//	    fires at once, which is the gate reporting that it has gone blind:
//	    -> producer site "drawPqSecret|messagegroup.NewPqSecret" has no entry
//	    -> AND the disposition says "stageEpochRotationLocked|messagegroup.NewPqSecret" is allowed
//	       and the census does not find it
//	    -> AND sink site "drawPqSecret|return" has no entry, and stageEpochRotationLocked's four
//	       sinks all go stale
//	M7  THE COUNTED CENSUS'S SECOND DIRECTION: `_ = len(pqSecret)` added to sealEpochWrapLocked, a
//	    function that counts the secret nowhere today
//	    -> counted-not-carried site "sealEpochWrapLocked|len pqSecret" has no entry
//	M8  THE CARRIES LIST RATHER THAN THE SITE LIST: restoreOne's permitted `fmt.Errorf` changed
//	    from `row.epoch` to `%x` of `row.secret`. The SITE is dispositioned, so a census keyed on
//	    sites alone would pass this
//	    -> sink site "restoreOne|call fmt.Errorf" carries "row.secret" and its entry does not list
//	       it (it lists [row])
//	    -> AND "restoreOne|return" the same, independently
//
// The clean tree was re-run after every revert and answered
// `ok github.com/urnetwork/message/sdk/urmessage`.

// ══════════════════════════════════════════════════════════════════════════════════════════════
// AND RE-MEASURED ON LRI R68'S ENGINE, WITH ONE ROW MORE
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// THE ENGINE THIS GATE RUNS ON CHANGED UNDER IT (LRI R68, from the review of identity phase 1's
// Tasks 8 to 10): the walk follows a value into this package's own functions (L1-1), a sink holds
// its OCCURRENCES (L2-01), and a map's key is a carried value (L2-02). So the eight rows above were
// run again, each as its prose has it, one at a time in an overlay worktree by exact replacements,
// as `go test ./urmessage/ -count=1 -v -run
// 'TestEveryPqSecretInThisPackageGoesWhereTheDispositionSaysItGoes|TestEveryWrapSeedInThis…'`; the
// clean overlay passed. Every one is still KILLED. M9 is new, and it is the occurrence's own row.
//
//	M1  -> sink site "resolvePqSecretLocked|call fmt.Errorf" has no entry, AND
//	       "resolvePqSecretLocked|return" occurs as a fmt.Errorf(...) more than it lists
//	M2  -> sink site "groupRecordOf|call fmt.Errorf" has no entry, AND "groupRecordOf|return"
//	       carries "parts", not listed, and occurs as a fmt.Errorf(...) more -- in this census AND
//	       in the wrap-seed census, which the walk now brings to the same decoder
//	M3  -> sink site "encodePqSecretTable|call fmt.Errorf" carries "row.PqSecret", not listed, and
//	       occurs as ["row.Epoch" "row.PqSecret"] where it lists ["row.Epoch"]; AND
//	       "encodePqSecretTable|return" carries it too
//	M4  -> producer site "resolvePqSecretLocked|candidates.secret" has no entry, AND sink site
//	       "resolvePqSecretLocked|call fmt.Errorf" has no entry, AND "resolvePqSecretLocked|return"
//	       carries "candidates.secret", not listed
//	M5  -> the disposition says "filePqSecretLocked|call append" is allowed and the census does not
//	       find it, AND "filePqSecretLocked|assign self.pqSecrets[epoch]" carries "parked", not
//	       listed, no longer carries "pqSecret", and occurs as ["parked"] where it lists
//	       ["append(...)"]
//	M6  -> producer site "drawPqSecret|messagegroup.NewPqSecret" has no entry, AND producer site
//	       "stageEpochRotationLocked|messagegroup.NewPqSecret" is allowed and not found, AND sink site
//	       "drawPqSecret|return" has no entry, AND six of stageEpochRotationLocked's sinks go stale
//	M7  -> counted-not-carried site "sealEpochWrapLocked|len pqSecret" has no entry
//	M8  -> sink site "restoreOne|call fmt.Errorf" carries "row.secret", not listed, and occurs as
//	       ["row.Epoch" "row.secret"] where it lists ["row.Epoch" "row.epoch"]; AND
//	       "restoreOne|return" carries it too
//	M9  THE OCCURRENCE (L2-01): restoreOne's permitted `fmt.Errorf` given the whole row beside its
//	    epoch, `%v` of `row` -- the epoch AND the secret, in an error string. It carries "row", which
//	    the entry already lists for `row.epoch`, so the site and its carried set both stand still,
//	    and before R68 this gate PASSED it:
//	    -> sink site "restoreOne|call fmt.Errorf" occurs as ["row" "row.Epoch" "row.epoch"] and its
//	       disposition lists ["row.Epoch" "row.epoch"] -- the occurrence clause, and it alone
