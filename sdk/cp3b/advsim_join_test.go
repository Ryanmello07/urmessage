package cp3b

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE JOIN PATH UNDER ITS ADVERSARIES. Every scenario here drives real devices against the real
// server, lets an adversary do what its definition allows, and hands what it got to [advJudge].

// advJoin is one founding join, with everything a recorder on its paste channel kept.
type advJoin struct {
	world   *world
	ctx     context.Context
	paste   *advPaste
	groupId []byte

	alice      *persona
	bob        *persona
	aliceGroup *urmessage.Group
	bobGroup   *urmessage.Group

	// the two artefacts as they crossed the paste channel
	joinCode []byte
	invite   []byte
	// a copy of bob's state directory taken after he minted the join code and before he joined
	bobBeforeJoin string
	// every canary sealed so far, with the epoch it was sealed at
	canaries map[string]uint64
}

// advFounding founds a group on alice, adds bob through the paste channel and opens it. With
// join set, bob joins, reads a canary alice sealed in the join epoch and answers with his own, so
// that the epoch holds a canary from each honest member and each was read by the other.
func advFounding(t *testing.T, join bool) *advJoin {
	t.Helper()
	world := newWorldWith(t, worldOptions{recordWire: true})
	ctx := context.Background()
	scene := &advJoin{world: world, ctx: ctx, paste: &advPaste{}, groupId: newGroupId(t), canaries: map[string]uint64{}}
	scene.alice = world.newPersona(t, "alice")
	scene.bob = world.newPersona(t, "bob")
	for _, who := range []*persona{scene.alice, scene.bob} {
		if err := who.device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	aliceGroup, err := scene.alice.device.CreateGroup(ctx, scene.groupId)
	if err != nil {
		advHarness(t, "alice's CreateGroup: %v", err)
	}
	scene.aliceGroup = aliceGroup
	joinCode, err := scene.bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's KeyPackage: %v", err)
	}
	scene.joinCode = scene.paste.carry(joinCode)
	scene.bobBeforeJoin = filepath.Join(t.TempDir(), "bob-before-the-join")
	copyAppData(t, scene.bob.stateDir, scene.bobBeforeJoin)
	invite, err := aliceGroup.AddMember(scene.joinCode)
	if err != nil {
		advHarness(t, "alice's AddMember: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	scene.invite = scene.paste.carry(encoded)
	if err := aliceGroup.Open(ctx); err != nil {
		advHarness(t, "alice's Open: %v", err)
	}
	scene.say(t, "alice", aliceGroup)
	if !join {
		return scene
	}
	carried, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(ctx, carried)
	if err != nil {
		advHarness(t, "bob's Join over the honest invite: %v", err)
	}
	scene.bobGroup = bobGroup
	scene.hear(t, "bob", bobGroup)
	scene.say(t, "bob", bobGroup)
	scene.hear(t, "alice", aliceGroup)
	return scene
}

// say seals one fresh canary in a group and files it under the epoch the group stands at.
func (self *advJoin) say(t *testing.T, who string, group *urmessage.Group) string {
	t.Helper()
	canary := advCanary(t)
	if _, err := group.Send(self.ctx, canary); err != nil {
		advHarness(t, "%s's Send of a canary: %v", who, err)
	}
	self.canaries[canary] = group.Epoch()
	return canary
}

// hear is one Receive that must hand back at least one canary: the precondition that an honest
// member READ what the adversary is about to be measured against.
func (self *advJoin) hear(t *testing.T, who string, group *urmessage.Group) {
	t.Helper()
	received, err := group.Receive(self.ctx)
	if err != nil {
		advHarness(t, "%s's Receive: %v", who, err)
	}
	for _, one := range received {
		if _, isCanary := self.canaries[one.Text]; isCanary && one.Gap == "" {
			return
		}
	}
	advHarness(t, "%s received %d message(s) and none is a canary, so no honest member read what the adversary is measured against", who, len(received))
}

// advSettle fetches on one group until it stands at the epoch the scene needs. A walk crosses the
// commits it is served and no more, so one Receive is not "caught up"; and a group that does not
// get there is a harness fault, never a verdict.
func advSettle(t *testing.T, ctx context.Context, who string, group *urmessage.Group, epoch uint64) {
	t.Helper()
	for round := 0; round < 16 && group.Epoch() < epoch; round += 1 {
		if _, err := group.Receive(ctx); err != nil {
			advHarness(t, "%s's Receive on the way to epoch %d: %v", who, epoch, err)
		}
	}
	if got := group.Epoch(); got != epoch {
		advHarness(t, "%s stands at epoch %d after its walks, want %d", who, got, epoch)
	}
}

// recordOf is the durable record one persona holds for the scene's group.
func (self *advJoin) recordOf(t *testing.T, who *persona) *urmessage.GroupRecord {
	t.Helper()
	records, err := who.stateStore.GroupRecords()
	if err != nil {
		advHarness(t, "%s's GroupRecords: %v", who.name, err)
	}
	for _, record := range records {
		if bytes.Equal(record.GroupId, self.groupId) {
			return record
		}
	}
	return nil
}

// advHarvest is the recorder's whole attack on one join: the Shor grant over what was captured,
// the scrape of the haystack, and the read. It answers the epochs it read.
func advHarvest(t *testing.T, world *world, groupId []byte, captured [][]byte, haystack []byte,
	joinCode []byte, beforeJoin string, invite []byte, canaries map[string]uint64, grants ...func(*advShadow)) []string {

	t.Helper()
	version, fields := advInviteFields(t, invite)
	if len(fields) < 3 {
		advHarness(t, "an invite at version %#04x with %d fields carries no welcome and tree to join from", version, len(fields))
	}
	shadow, granted := advShor(t, captured, joinCode, beforeJoin, fields[1], fields[2])
	if !granted {
		t.Logf("the recorder captured no init key, so the CRQC inverts nothing and the shadow does not exist")
		return []string{}
	}
	for _, grant := range grants {
		grant(shadow)
	}
	scraped := advScrape(t, world, groupId, shadow, haystack)
	if scraped.pqSecret == nil && len(fields) == 5 {
		// NOTHING IN THE CLEAR, SO THE SEAL: opened with the X-Wing key the shadow holds, which is
		// a useless one unless a grant above replaced it.
		if pqSecret, groupHandleKey, opened := advOpenSeal(t, shadow, groupId, fields[3]); opened {
			return advRead(t, world, shadow, pqSecret, groupHandleKey, canaries)
		}
	}
	if scraped.pqSecret == nil {
		shadow.handle.Close()
		return []string{}
	}
	if scraped.groupHandleKey == nil {
		// HALF A RECOVERY IS REPORTED AS WHAT IT IS, NEVER AS NOTHING. The recorder holds the storage
		// root of the join epoch, confirmed against the server's own digest, and lacks only the key
		// the production opener maps a sender handle to a leaf with.
		shadow.handle.Close()
		return []string{fmt.Sprintf("storage-root:%d", shadow.epoch)}
	}
	return advRead(t, world, shadow, scraped.pqSecret, scraped.groupHandleKey, canaries)
}

// ── P1: harvest now, decrypt later ───────────────────────────────────────────────────────────

func TestAdvSimHarvestNowDecryptLaterReadsTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, scene.paste.haystack(),
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-hndl-founding", observed)
}

// advLiveAdd is one LIVE add with everything a recorder kept of it: the group is open, the founder
// adds a third device over the paste channel, the add's commit rotates pq_secret, and the joiner
// reads a canary the founder seals at the epoch it was admitted at.
type advLiveAdd struct {
	scene      *advJoin
	paste      *advPaste
	joinCode   []byte
	beforeJoin string
	invite     []byte
	canaries   map[string]uint64
}

func advLiveAddScene(t *testing.T) *advLiveAdd {
	t.Helper()
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	if err := carol.device.Connect(scene.ctx); err != nil {
		advHarness(t, "carol's Connect: %v", err)
	}
	paste := &advPaste{}
	joinCode, err := carol.device.KeyPackage()
	if err != nil {
		advHarness(t, "carol's KeyPackage: %v", err)
	}
	joinCode = paste.carry(joinCode)
	beforeJoin := filepath.Join(t.TempDir(), "carol-before-the-join")
	copyAppData(t, carol.stateDir, beforeJoin)
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.aliceGroup.Epoch(); epoch != 2 {
		advHarness(t, "the live add left the group at epoch %d, want 2", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	carolGroup, err := carol.device.Join(scene.ctx, carried)
	if err != nil {
		advHarness(t, "carol's Join: %v", err)
	}
	canaries := map[string]uint64{}
	canary := advCanary(t)
	if _, err := scene.aliceGroup.Send(scene.ctx, canary); err != nil {
		advHarness(t, "alice's Send at epoch 2: %v", err)
	}
	canaries[canary] = scene.aliceGroup.Epoch()
	gcReceiveText(t, scene.ctx, "carol", carolGroup, canary)
	return &advLiveAdd{scene: scene, paste: paste, joinCode: joinCode, beforeJoin: beforeJoin, invite: encoded, canaries: canaries}
}

// The same recorder against a LIVE add: the group is open, the add's commit rotates pq_secret, and
// the invitation must deliver the rotated value. It is a second scenario because it is a second
// code path on the adder (AddMemberAndPublish and the staged rotation) and a second secret.
func TestAdvSimHarvestNowDecryptLaterReadsALiveAddsEpoch(t *testing.T) {
	live := advLiveAddScene(t)
	observed := advHarvest(t, live.scene.world, live.scene.groupId, live.paste.captured, live.paste.haystack(),
		live.joinCode, live.beforeJoin, live.invite, live.canaries)
	advJudge(t, "P1-hndl-live-add", observed)
}

// The same recorder against an add made by an ADMIN who is not the founder, in a group of four. It
// is a scenario of its own because it is the one world in which the adder hands on secrets it was
// itself handed: its group_handle_key arrived in its own invitation, and its pq_secret of the epoch
// it adds at arrived in a device wrap.
func TestAdvSimHarvestNowDecryptLaterReadsAnAdminsAddEpoch(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if err := scene.aliceGroup.SetRole(scene.ctx, rolesIdentityOf(t, scene.bobGroup), "admin"); err != nil {
		advHarness(t, "alice's SetRole(bob, admin): %v", err)
	}
	// bob and carol follow the two commits: an admin commits from the epoch the group stands at
	advSettle(t, scene.ctx, "bob", scene.bobGroup, 3)
	advSettle(t, scene.ctx, "carol", carolGroup, 3)
	dave := scene.world.newPersona(t, "dave")
	if err := dave.device.Connect(scene.ctx); err != nil {
		advHarness(t, "dave's Connect: %v", err)
	}
	paste := &advPaste{}
	joinCode, err := dave.device.KeyPackage()
	if err != nil {
		advHarness(t, "dave's KeyPackage: %v", err)
	}
	joinCode = paste.carry(joinCode)
	beforeJoin := filepath.Join(t.TempDir(), "dave-before-the-join")
	copyAppData(t, dave.stateDir, beforeJoin)
	invite, err := scene.bobGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "the admin's AddMemberAndPublish: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.bobGroup.Epoch(); epoch != 4 {
		advHarness(t, "the admin's add left the group at epoch %d, want 4", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	daveGroup, err := dave.device.Join(scene.ctx, carried)
	if err != nil {
		advHarness(t, "dave's Join: %v", err)
	}
	canaries := map[string]uint64{}
	canary := advCanary(t)
	if _, err := scene.bobGroup.Send(scene.ctx, canary); err != nil {
		advHarness(t, "the admin's Send at epoch 4: %v", err)
	}
	canaries[canary] = scene.bobGroup.Epoch()
	gcReceiveText(t, scene.ctx, "dave", daveGroup, canary)

	observed := advHarvest(t, scene.world, scene.groupId, paste.captured, paste.haystack(),
		joinCode, beforeJoin, encoded, canaries)
	advJudge(t, "P1-hndl-admin-add", observed)
}

// The fourth world: A SECOND DEVICE OF ONE IDENTITY, added by the member that holds the identity,
// who here is neither the founder nor an admin. An urmessage.Device mints one identity per state
// store, so the second device is a seam member whose credential claims the first's identity. It
// has no device store for the quantum grant to be worked from, so this scenario measures the half
// of the recorder that needs none. The grant is the classical join itself: the exporter of the join
// epoch, which a quantum computer rebuilds from the join code's init key, read here off the second
// device's own joined state and granted only if that init key was captured. With it the recorder
// scrapes the pasted invitation for the epoch's secret and for the group's handle key.
//
// IT DOES NOT READ A CANARY, and its registry line says so. "storage-root:N" is the storage root
// of epoch N, confirmed against the digest the server holds: the root every record of that epoch
// is sealed under.
func TestAdvSimASecondDevicesInvitationCarriesTheJoinEpochsSecrets(t *testing.T) {
	scene := advFounding(t, true)
	laptop := scene.world.seamMemberClaiming(t, scene.ctx, "bob-laptop", rolesIdentityOf(t, scene.bobGroup))
	paste := &advPaste{}
	joinCode := paste.carry(laptop.keyPackage(t))
	invite, err := scene.bobGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "bob's AddMemberAndPublish of his own second device: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the invite: %v", err)
	}
	encoded = paste.carry(encoded)
	if epoch := scene.bobGroup.Epoch(); epoch != 2 {
		advHarness(t, "the second device's add left the group at epoch %d, want 2", epoch)
	}
	carried, err := urmessage.ParseInvite(encoded)
	if err != nil {
		advHarness(t, "parsing the invite: %v", err)
	}
	laptop.join(t, carried)

	// THE GRANT RULE, as [advShor] states it: the init key is among the captured octets
	if !bytes.Contains(paste.haystack(), advKeyPackageInitKey(t, joinCode)) {
		advHarness(t, "the recorder holds both pasted codes and the join code's init key is not among their octets")
	}
	exporter, err := laptop.handle.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		advHarness(t, "the exporter of the epoch the second device joined: %v", err)
	}
	shadow := &advShadow{exporter: exporter, epoch: laptop.handle.Epoch(), ownLeaf: laptop.handle.OwnLeafIndex()}
	observed := []string{}
	scraped := advScrape(t, scene.world, scene.groupId, shadow, encoded)
	if scraped.groupHandleKey != nil {
		observed = append(observed, "ghk")
	}
	if scraped.pqSecret != nil {
		observed = append(observed, fmt.Sprintf("storage-root:%d", shadow.epoch))
	}
	// THE CONTROL, IN THE SAME QUERY: the same scrape over the same invitation with the two true
	// values planted after its last octet. A scrape that went blind finds nothing here either, and
	// that is a harness fault and not a closed gap.
	record := scene.recordOf(t, scene.bob)
	if record == nil || len(record.PqSecret) != 32 || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the adder's durable record does not hold the two values to plant")
	}
	planted := append(append(append([]byte(nil), encoded...), record.PqSecret...), record.GroupHandleKey...)
	control := advScrape(t, scene.world, scene.groupId, shadow, planted)
	if !bytes.Equal(control.pqSecret, record.PqSecret) || !bytes.Equal(control.groupHandleKey, record.GroupHandleKey) {
		advHarness(t, "the scrape did not find the two true values planted after the invitation, so a verdict of nothing found would be a scrape that cannot see")
	}
	advJudge(t, "P1-second-device-invitation", observed)
}

// CONTROL: the invitation alone. The init key is in the join code and nowhere else, so a recorder
// that missed the join code has no public key to invert. This can fail: an invitation that ever
// carried the init key would be granted.
func TestAdvSimTheInvitationAloneReadsNothing(t *testing.T) {
	scene := advFounding(t, true)
	observed := advHarvest(t, scene.world, scene.groupId, [][]byte{scene.invite}, scene.invite,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c1-invite-alone", observed)
}

// CONTROL: both codes and the group's TRUE group_handle_key handed to the recorder, with 32 random
// octets where the control below hands it the true pq_secret. The read is causal in that one value.
func TestAdvSimAReplacedPqSecretReadsNothing(t *testing.T) {
	scene := advFounding(t, true)
	record := scene.recordOf(t, scene.alice)
	if record == nil || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the founder's durable record does not hold the group_handle_key to inject")
	}
	replaced := make([]byte, 32)
	if _, err := rand.Read(replaced); err != nil {
		advHarness(t, "drawing the replacement: %v", err)
	}
	haystack := append(scene.paste.haystack(), replaced...)
	haystack = append(haystack, record.GroupHandleKey...)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, haystack,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c2-replaced-pq", observed)
}

// CONTROL: both codes, and the two true secrets handed to the recorder, read off the founder's own
// durable record. The pipeline then reads exactly the join epoch. Once the invitation carries no
// secret in the clear, this is what says the scrape and the read still work.
func TestAdvSimInjectedSecretsReadExactlyTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	record := scene.recordOf(t, scene.alice)
	if record == nil || len(record.PqSecret) != 32 || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the founder's durable record does not hold the two secrets to inject")
	}
	haystack := append(scene.paste.haystack(), record.PqSecret...)
	haystack = append(haystack, record.GroupHandleKey...)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, haystack,
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries)
	advJudge(t, "P1-c3-injected-secrets", observed)
}

// ── S2: sender anonymity against a paste observer ────────────────────────────────────────────

// (a) A CLASSICAL observer of one pasted invitation, holding the server's rows and no MLS secret.
func TestAdvSimAPasteObserverRecoversTheGroupHandleKey(t *testing.T) {
	scene := advFounding(t, true)
	observed := []string{}
	if key, at := advScrapeHandleKey(t, scene.world, scene.groupId, scene.invite); key != nil {
		t.Logf("group_handle_key recovered at octet %d of a %d octet invitation", at, len(scene.invite))
		observed = append(observed, "ghk")
	}
	// THE CONTROL, IN THE SAME QUERY: the same scrape over the same invitation with the group's
	// true handle key planted after its last octet. A scrape that went blind finds nothing here
	// either, and that is a harness fault and not a closed gap.
	record := scene.recordOf(t, scene.alice)
	if record == nil || len(record.GroupHandleKey) != 32 {
		advHarness(t, "the founder's durable record does not hold the group_handle_key to plant")
	}
	planted := append(append([]byte(nil), scene.invite...), record.GroupHandleKey...)
	key, at := advScrapeHandleKey(t, scene.world, scene.groupId, planted)
	if !bytes.Equal(key, record.GroupHandleKey) {
		advHarness(t, "the scrape did not find the true group_handle_key planted at octet %d, so a verdict of nothing found would be a scrape that cannot see", len(scene.invite))
	}
	t.Logf("%d windows of the invitation read; the planted control was found at octet %d of %d",
		len(scene.invite)-31, at, len(planted))
	advJudge(t, "S2a-ghk-paste-observer", observed)
}

// (b) THE DOCUMENTED BREACH. With no key at all, the same observer links the founder and this
// paste's joiner to their handles by the order the handles first appear in the server's rows: the
// founding commit is the first row and is the founder's, and the next new handle is the joiner's.
// Sealing the secrets does not change this. It is pinned so that only a deliberate fix moves it.
func TestAdvSimFirstAppearanceLinksThisPastesMembersToTheirHandles(t *testing.T) {
	scene := advFounding(t, true)
	order := [][]byte{}
	for _, row := range scene.world.allRows(t, scene.groupId) {
		seen := false
		for _, earlier := range order {
			seen = seen || bytes.Equal(earlier, row.SenderHandle)
		}
		if !seen {
			order = append(order, append([]byte(nil), row.SenderHandle...))
		}
	}
	if len(order) != 2 {
		advHarness(t, "the server holds rows under %d handles for a two member group", len(order))
	}
	// the truth, read off what each device opened of the other's
	founder := senderHandleOf(t, scene.bobGroup)
	joiner := senderHandleOf(t, scene.aliceGroup)
	linked := 0
	if bytes.Equal(order[0], founder) {
		linked += 1
	}
	if bytes.Equal(order[1], joiner) {
		linked += 1
	}
	advJudge(t, "S2b-first-appearance-link", []string{fmt.Sprintf("linked:%d/2", linked)})
}

// ── S3: an active attacker on the paste channel ──────────────────────────────────────────────

// The attacker rewrites the invitation in flight so that it carries a pq_secret and a
// group_handle_key IT chose, and recomputes the checksum. Two forgeries, and neither may install
// anything: the plaintext format, which this build no longer reads; and a version 3 invitation
// whose seal the attacker made itself, to the joiner's published X-Wing key, under the honest
// invitation's own authenticator. The second must be refused BY THE AUTHENTICATOR, before the seal
// is opened: a refusal by anything later is reported, because it means a forged seal was opened.
func TestAdvSimAnAttackerChosenSecretIsNotInstalled(t *testing.T) {
	scene := advFounding(t, false)
	version, fields := advInviteFields(t, scene.invite)
	if version != 0x0003 || len(fields) != 5 {
		advHarness(t, "the honest invitation is version %#04x with %d fields, so there is no seal to forge", version, len(fields))
	}
	chosenPq := bytes.Repeat([]byte{0xA7}, 32)
	chosenGhk := bytes.Repeat([]byte{0x5E}, 32)

	observed := []string{}
	plaintext := advEncodeInvite(0x0002, [][]byte{fields[0], fields[1], fields[2], chosenPq, chosenGhk})
	parsed, err := urmessage.ParseInvite(plaintext)
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, parsed)
	}
	t.Logf("the forged plaintext invitation was answered: %v", err)

	// the joiner is the second leaf of a group its founder is the first of
	forgedSeal := advForgedSeal(t, scene.groupId, fields[2], 1, chosenPq, chosenGhk)
	parsed, err = urmessage.ParseInvite(advEncodeInvite(version, [][]byte{fields[0], fields[1], fields[2], forgedSeal, fields[4]}))
	if err != nil {
		advHarness(t, "the forged version 3 invitation does not parse, so the join was never reached: %v", err)
	}
	_, err = scene.bob.device.Join(scene.ctx, parsed)
	t.Logf("the forged sealed invitation was answered: %v", err)
	if err != nil && !errors.Is(err, urmessage.ErrJoinSealUnauthenticated) {
		observed = append(observed, "forged-seal-opened")
	}
	if record := scene.recordOf(t, scene.bob); record != nil {
		if bytes.Equal(record.PqSecret, chosenPq) || bytes.Equal(record.GroupHandleKey, chosenGhk) {
			observed = append(observed, "installed:attacker-secret")
		} else {
			observed = append(observed, "installed:something")
		}
	}
	advJudge(t, "S3-chosen-secret", observed)
}

// An invitation that is refused must not cost the joiner its join code. The attacker changes the
// group id the invitation names and recomputes the checksum; the honest invitation follows.
func TestAdvSimARefusedInvitationDoesNotSpendTheJoinCode(t *testing.T) {
	scene := advFounding(t, false)
	version, fields := advInviteFields(t, scene.invite)
	fields[0] = newGroupId(t)
	bent, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err != nil {
		advHarness(t, "the bent invitation does not parse, so the join was never reached: %v", err)
	}
	if _, err := scene.bob.device.Join(scene.ctx, bent); err == nil {
		advHarness(t, "an invitation naming one group and carrying another's welcome was accepted")
	} else {
		t.Logf("the bent invitation was refused: %v", err)
	}
	observed := []string{}
	honest, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(scene.ctx, honest)
	if err != nil {
		t.Logf("the honest invitation after the refused one: %v", err)
		observed = append(observed, "join-code-spent")
	} else {
		scene.bobGroup = bobGroup
		scene.hear(t, "bob", bobGroup)
	}
	advJudge(t, "S3-refusal-spends-join-code", observed)
}

// The same property as the refused invitation above, at the OTHER place a refusal is made: after
// the engine has joined. The attacker flips one bit of the authenticator and recomputes the
// checksum. The welcome is the right group's and the key that judges the authenticator is the
// joined epoch's own, so this refusal cannot be made any earlier than it is.
func TestAdvSimAnInvitationRefusedAfterTheEngineJoinedDoesNotSpendTheJoinCode(t *testing.T) {
	scene := advFounding(t, false)
	version, fields := advInviteFields(t, scene.invite)
	if len(fields) != 5 || len(fields[4]) != 32 {
		advHarness(t, "the invite carries %d fields, so there is no authenticator to bend", len(fields))
	}
	fields[4][0] ^= 0x01
	observed := []string{}
	bent, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err != nil {
		advHarness(t, "the bent invitation does not parse, so the join was never reached: %v", err)
	}
	if _, err = scene.bob.device.Join(scene.ctx, bent); err == nil {
		advHarness(t, "an invitation with one bit of its authenticator flipped was accepted")
	}
	t.Logf("the bent invitation was refused: %v", err)
	honest, err := urmessage.ParseInvite(scene.invite)
	if err != nil {
		advHarness(t, "parsing the honest invite: %v", err)
	}
	bobGroup, err := scene.bob.device.Join(scene.ctx, honest)
	if err != nil {
		t.Logf("the honest invitation after the refused one: %v", err)
		observed = append(observed, "join-code-spent")
	} else {
		scene.bobGroup = bobGroup
		scene.hear(t, "bob", bobGroup)
	}
	advJudge(t, "S3-late-refusal-spends-join-code", observed)
}

// MG-1, pinned: a swapper substitutes its own join code for the victim's. The founder adds the
// swapper believing it is the victim, nothing anywhere says so, and the swapper reads what the
// founder sends. Sealing the join secret seals it TO THE SWAPPER. R, the IDs-and-requests build,
// closes this: it carries T2's labels, which identity phase 1's plan moved there.
func TestAdvSimASubstitutedJoinCodeAdmitsTheSwapper(t *testing.T) {
	world := newWorldWith(t, worldOptions{recordWire: true})
	ctx := context.Background()
	alice := world.newPersona(t, "alice")
	mallory := world.newPersona(t, "mallory")
	for _, who := range []*persona{alice, mallory} {
		if err := who.device.Connect(ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	aliceGroup, err := alice.device.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "alice's CreateGroup: %v", err)
	}
	// the victim's join code never arrives: this is the one alice is handed in its place
	swapped, err := mallory.device.KeyPackage()
	if err != nil {
		advHarness(t, "mallory's KeyPackage: %v", err)
	}
	invite, err := aliceGroup.AddMember(swapped)
	if err != nil {
		advHarness(t, "alice's AddMember of the join code she was handed: %v", err)
	}
	if err := aliceGroup.Open(ctx); err != nil {
		advHarness(t, "alice's Open: %v", err)
	}
	canary := advCanary(t)
	if _, err := aliceGroup.Send(ctx, canary); err != nil {
		advHarness(t, "alice's Send: %v", err)
	}
	observed := []string{}
	malloryGroup, err := mallory.device.Join(ctx, gcReencodeInvite(t, invite))
	if err == nil {
		received, err := malloryGroup.Receive(ctx)
		if err != nil {
			advHarness(t, "mallory's Receive: %v", err)
		}
		for _, one := range received {
			if one.Text == canary {
				observed = append(observed, fmt.Sprintf("swapper-read:%d", aliceGroup.Epoch()))
			}
		}
	}
	advJudge(t, "S3-mg1-join-code-substitution", observed)
}

// ── S4: a copied device ──────────────────────────────────────────────────────────────────────

// A copy of the joiner's whole state directory, taken after the join. It reads the group record
// in the clear (keys at rest are plaintext) and opens what the founder seals next. This is the
// positive control for the read: it does not depend on what an invitation carries.
func TestAdvSimACopiedStateDirectoryReadsTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	thiefDir := filepath.Join(t.TempDir(), "thief")
	copyAppData(t, scene.bob.stateDir, thiefDir)
	// sealed AFTER the copy: the copy holds the founder's ratchet where bob left it
	scene.say(t, "alice", scene.aliceGroup)

	store, err := urmessage.OpenDurableStateStore(thiefDir)
	if err != nil {
		advHarness(t, "the thief's copy does not open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	signerPub, signerPriv, leafKeys, _, err := store.GetDeviceIdentity()
	if err != nil {
		advHarness(t, "the thief's copy holds no identity: %v", err)
	}
	records, err := store.GroupRecords()
	if err != nil || len(records) != 1 {
		advHarness(t, "the thief's copy holds %d group record(s): %v", len(records), err)
	}
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		advHarness(t, "the crypto provider: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, store, mls.SignaturePrivateKey(signerPriv),
		mls.BasicCredential(signerPub), leafKeys)
	if err != nil {
		advHarness(t, "the thief's engine: %v", err)
	}
	handle, err := engine.LoadGroup(records[0].GroupId, records[0].Epoch)
	if err != nil {
		advHarness(t, "the thief's LoadGroup: %v", err)
	}
	shadow := &advShadow{handle: handle, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex()}
	observed := advRead(t, scene.world, shadow, records[0].PqSecret, records[0].GroupHandleKey, scene.canaries)
	advJudge(t, "S4-state-thief", observed)
}

// THE RESIDUAL, PINNED ON PURPOSE. The same recorder as the harvest scenarios, and this time the
// joiner's X-Wing seed as well, out of a copy of its state directory taken BEFORE the join. It
// joins the recorded Welcome, opens the recorded seal and reads the join epoch: the seal is to a
// static key, so whoever holds that key and the paste holds the epoch. It is also the harvest
// scenarios' control, because the seed is the only thing they withhold.
func TestAdvSimTheJoinersSeedAndTheRecordingReadTheJoinEpoch(t *testing.T) {
	scene := advFounding(t, true)
	observed := advHarvest(t, scene.world, scene.groupId, scene.paste.captured, scene.paste.haystack(),
		scene.joinCode, scene.bobBeforeJoin, scene.invite, scene.canaries, advTrueSeed(t, scene.bobBeforeJoin))
	advJudge(t, "S4-seed-plus-recorder", observed)
}

// THE SAME RESIDUAL ON THE LIVE ROAD, where the sealed secret is the rotated one. It is the control
// for the live add's harvest row: that row reads nothing since the seal, and this one shows the
// recorder reading the same epoch through the same pipeline once it holds the one thing that row
// withholds.
func TestAdvSimTheJoinersSeedAndTheRecordingReadALiveAddsEpoch(t *testing.T) {
	live := advLiveAddScene(t)
	observed := advHarvest(t, live.scene.world, live.scene.groupId, live.paste.captured, live.paste.haystack(),
		live.joinCode, live.beforeJoin, live.invite, live.canaries, advTrueSeed(t, live.beforeJoin))
	advJudge(t, "S4-seed-plus-recorder-live-add", observed)
}

// ── S7: an invitation over a group the device already holds ──────────────────────────────────

// advHostile is an attacker's own group founded under the SAME group id the victim holds, with an
// invitation into it addressed to a join code the victim published. CreateGroup takes the id from
// its caller and AddMember reaches no server, so this costs the attacker nothing but that id and
// one of the victim's join codes.
func advHostile(t *testing.T, scene *advJoin, victim *urmessage.Device) []byte {
	t.Helper()
	mallory := scene.world.newPersona(t, "mallory")
	if err := mallory.device.Connect(scene.ctx); err != nil {
		advHarness(t, "mallory's Connect: %v", err)
	}
	hostile, err := mallory.device.CreateGroup(scene.ctx, scene.groupId)
	if err != nil {
		advHarness(t, "mallory's CreateGroup under the held id: %v", err)
	}
	joinCode, err := victim.KeyPackage()
	if err != nil {
		advHarness(t, "the victim's second KeyPackage: %v", err)
	}
	invite, err := hostile.AddMember(joinCode)
	if err != nil {
		advHarness(t, "mallory's AddMember of the victim's join code: %v", err)
	}
	encoded, err := invite.Encode()
	if err != nil {
		advHarness(t, "encoding the hostile invite: %v", err)
	}
	return encoded
}

// advHeldGroupOutcome is what an invitation did to a group the victim held: which of its files
// changed, and whether the group still comes back and reads the real founder after a restart.
func advHeldGroupOutcome(t *testing.T, scene *advJoin, before map[string][]byte) []string {
	t.Helper()
	if len(before) == 0 {
		advHarness(t, "the victim held no file for this group before the invitation, so nothing could have been replaced")
	}
	after := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	observed := []string{}
	for name, content := range before {
		changed := !bytes.Equal(after[name], content)
		switch {
		case changed && name == "meta":
			observed = append(observed, "record-replaced")
		case changed && strings.HasPrefix(name, "epoch/"):
			observed = append(observed, "epoch-state-replaced")
		case changed:
			observed = append(observed, "changed:"+name)
		}
	}
	// and the property itself: the group restores, and reads what the REAL founder seals next
	canary := scene.say(t, "alice", scene.aliceGroup)
	scene.bob = scene.world.restart(t, scene.bob)
	lost := func(why string, err error) []string {
		t.Logf("the held group did not come back: %s: %v", why, err)
		return advSet(append(observed, "restore-lost"))
	}
	if err := scene.bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	restored, err := scene.bob.device.Restore(scene.ctx)
	if err != nil || len(restored) != 1 {
		return lost(fmt.Sprintf("Restore answered %d group(s)", len(restored)), err)
	}
	received, err := restored[0].Receive(scene.ctx)
	if err != nil {
		return lost("Receive", err)
	}
	for _, one := range received {
		if one.Text == canary && one.Gap == "" {
			return advSet(observed)
		}
	}
	return lost("the founder's canary was not among what it read", nil)
}

func TestAdvSimAValidInvitationUnderAHeldGroupIdReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	hostile := advHostile(t, scene, scene.bob.device)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = scene.bob.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7a-held-id-valid-invite", advHeldGroupOutcome(t, scene, before))
}

// The same invitation with one bit of its authenticator flipped: a refusal that, without the gate,
// arrives AFTER the engine has joined.
func TestAdvSimAnInvitationRefusedLateUnderAHeldGroupIdReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	version, fields := advInviteFields(t, advHostile(t, scene, scene.bob.device))
	if len(fields) != 5 || len(fields[4]) != 32 {
		advHarness(t, "the hostile invite carries %d fields", len(fields))
	}
	fields[4][0] ^= 0x01
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err != nil {
		advHarness(t, "the bent hostile invitation does not parse, so the join was never reached: %v", err)
	}
	if _, err = scene.bob.device.Join(scene.ctx, parsed); err == nil {
		advHarness(t, "an invitation with one bit of its authenticator flipped was accepted")
	}
	t.Logf("the bent invitation was answered: %v", err)
	advJudge(t, "S7b-held-id-refused-late", advHeldGroupOutcome(t, scene, before))
}

// The invitation NAMES a fresh group id and CARRIES the hostile welcome for the held one.
func TestAdvSimAFreshIdOverAHeldGroupsWelcomeReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	version, fields := advInviteFields(t, advHostile(t, scene, scene.bob.device))
	fields[0] = newGroupId(t)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(advEncodeInvite(version, fields))
	if err == nil {
		_, err = scene.bob.device.Join(scene.ctx, parsed)
	}
	if err == nil {
		advHarness(t, "an invitation naming one group and carrying another's welcome was accepted")
	}
	t.Logf("the invitation under a fresh id was answered: %v", err)
	advJudge(t, "S7c-fresh-id-held-welcome", advHeldGroupOutcome(t, scene, before))
}

// The victim has restarted and has NOT restored: the group is on its disk and not in its memory.
func TestAdvSimAnInvitationOverAGroupHeldOnlyOnDiskReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	scene.bob = scene.world.restart(t, scene.bob)
	if err := scene.bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	if held := len(scene.bob.device.Groups()); held != 0 {
		advHarness(t, "the restarted victim holds %d group(s) in memory before any Restore", held)
	}
	hostile := advHostile(t, scene, scene.bob.device)
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = scene.bob.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7d-held-on-disk-only", advHeldGroupOutcome(t, scene, before))
}

// The victim joined ABOVE epoch one, so it holds no epoch state at the epoch the hostile welcome
// stands at. Nothing about the state on its disk is in the way of this one; it is the scenario
// only the held-group gate itself closes.
func TestAdvSimAnInvitationAtAnEpochTheVictimHoldsNoStateForReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	if epoch := carolGroup.Epoch(); epoch != 2 {
		advHarness(t, "the victim joined at epoch %d, want 2", epoch)
	}
	scene.say(t, "alice", scene.aliceGroup)
	scene.hear(t, "carol", carolGroup)
	// from here the victim is carol
	scene.bob = carol
	hostile := advHostile(t, scene, carol.device)
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		advHarness(t, "the victim holds a state at epoch 1, so this is the same-epoch scenario again")
	}
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = carol.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7e-held-id-unheld-epoch", advHeldGroupOutcome(t, scene, before))
}

// Both at once: the victim joined above epoch one, has restarted and has not restored. The group is
// on its disk and not in its memory, and it holds no state at the hostile welcome's epoch, so
// neither the device's map nor the state already on the disk is in the way. Only the gate's reading
// of the RECORDS on the disk is.
func TestAdvSimAnInvitationOverAGroupOnDiskAtAnEpochItHoldsNoStateForReplacesNothing(t *testing.T) {
	scene := advFounding(t, true)
	carol := scene.world.newPersona(t, "carol")
	carolGroup := hsAddAndJoin(t, scene.ctx, scene.aliceGroup, carol)
	scene.say(t, "alice", scene.aliceGroup)
	scene.hear(t, "carol", carolGroup)
	carol = scene.world.restart(t, carol)
	if err := carol.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted victim's Connect: %v", err)
	}
	if held := len(carol.device.Groups()); held != 0 {
		advHarness(t, "the restarted victim holds %d group(s) in memory before any Restore", held)
	}
	scene.bob = carol
	hostile := advHostile(t, scene, carol.device)
	before := advGroupFiles(t, carol.stateDir, scene.groupId)
	if _, held := before["epoch/0000000000000001"]; held {
		advHarness(t, "the victim holds a state at epoch 1, so this is the same-epoch scenario again")
	}
	parsed, err := urmessage.ParseInvite(hostile)
	if err != nil {
		advHarness(t, "the hostile invite does not parse: %v", err)
	}
	_, err = carol.device.Join(scene.ctx, parsed)
	t.Logf("the hostile invitation was answered: %v", err)
	advJudge(t, "S7f-on-disk-unheld-epoch", advHeldGroupOutcome(t, scene, before))
}

// A GROUP A COMMIT REMOVED THIS DEVICE FROM IS STILL A GROUP IT HOLDS: its record is on the disk,
// its history still opens, and it reads as removed. This is what an invitation from a SECOND
// FOUNDER does to it, into a group of its own under the same group id. The second founder runs
// against a server of its own, so that its group stands ABOVE the epoch of the removal; an
// invitation is octets and crosses between the two.
//
// OPEN UNTIL R, the IDs-and-requests build, which carries T2's re-add proof since identity phase
// 1's plan moved T2's work there. Being added back is a join over a held id and is the repair the
// removal itself names, so it is honoured; and an invitation authenticates nobody, so nothing in
// a join can tell the group that removed this device from another founder's.
func TestAdvSimASecondFoundersInvitationOverAGroupTheDeviceWasRemovedFrom(t *testing.T) {
	scene := advFounding(t, true)
	if err := scene.aliceGroup.RemoveMember(scene.ctx, rolesIdentityOf(t, scene.bobGroup)); err != nil {
		advHarness(t, "alice's RemoveMember of bob: %v", err)
	}
	if _, err := scene.bobGroup.Receive(scene.ctx); !errors.Is(err, urmessage.ErrRemovedFromGroup) {
		advHarness(t, "the removed device's Receive answered %v, want ErrRemovedFromGroup", err)
	}
	removedAt, removal := scene.bobGroup.Removal()
	if removal == nil {
		advHarness(t, "bob does not read as removed, so there is no removed group to measure")
	}
	before := advGroupFiles(t, scene.bob.stateDir, scene.groupId)
	if len(before["meta"]) == 0 {
		advHarness(t, "the removed group has no record on bob's disk, so it is not a group he holds")
	}

	other := newWorld(t)
	mallory := other.newPersona(t, "mallory")
	helper := other.newPersona(t, "helper")
	for _, who := range []*persona{mallory, helper} {
		if err := who.device.Connect(scene.ctx); err != nil {
			advHarness(t, "%s's Connect: %v", who.name, err)
		}
	}
	hostileGroup, _ := openPair(t, scene.ctx, mallory, helper, scene.groupId)
	joinCode, err := scene.bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's KeyPackage: %v", err)
	}
	invite, err := hostileGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "the second founder's AddMemberAndPublish: %v", err)
	}
	if epoch := hostileGroup.Epoch(); epoch <= removedAt {
		advHarness(t, "the second founder's group stands at epoch %d and bob was removed at %d, so this is the stale re-add and not this scenario", epoch, removedAt)
	}
	_, err = scene.bob.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	t.Logf("the second founder's invitation over the removed group was answered: %v", err)

	observed := []string{}
	if after := advGroupFiles(t, scene.bob.stateDir, scene.groupId); !bytes.Equal(after["meta"], before["meta"]) {
		observed = append(observed, "record-replaced")
	}
	held := scene.bob.device.Groups()
	if len(held) != 1 || !bytes.Equal(held[0].Id(), scene.groupId) {
		advHarness(t, "bob holds %d group(s) after the invitation, want the one under this id", len(held))
	}
	if _, removal := held[0].Removal(); removal == nil {
		observed = append(observed, "removal-forgotten")
	}
	advJudge(t, "S7g-removed-group-second-founder", observed)
}

// CONTROL: A GROUP WHOSE RECORD IS ON THE DISK AND WHICH DOES NOT RESTORE CAN STILL BE LEFT AND
// JOINED AGAIN. The damage is every epoch state the device holds for the group, cut to half its
// length while it is stopped; its record stays. (R33 changed this case truthfully: the epoch states
// were REMOVED, and an absence is no longer proof that a group will never read, so a group whose
// files are missing is not left; bytes that do not decode are.) The three verbs a person has over such a group are
// then driven in order: Restore, ForgetGroup, and the founder's repair (the stranded leaf out, a
// fresh join code in, Join).
//
// It is a control and not a gap: it holds today, because today nothing refuses a join over a held
// group. It is here so that the gate which does refuse one cannot leave this state with no way out.
func TestAdvSimAGroupThatDoesNotRestoreIsLeftAndJoinedAgain(t *testing.T) {
	scene := advFounding(t, true)
	bobId := rolesIdentityOf(t, scene.bobGroup)
	scene.bob.kill()
	advDamageEpochStates(t, scene.bob.stateDir, scene.groupId)
	if record := advGroupFiles(t, scene.bob.stateDir, scene.groupId)["meta"]; len(record) == 0 {
		advHarness(t, "bob's record of the group is not on the disk, so this is not a group he holds")
	}
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(scene.ctx); err != nil {
		advHarness(t, "the restarted bob's Connect: %v", err)
	}
	restored, restoreErr := bob.device.Restore(scene.ctx)
	if len(restored) != 0 || restoreErr == nil {
		advHarness(t, "the damaged group restored (%d group(s), %v), so this is not a group that does not restore", len(restored), restoreErr)
	}
	t.Logf("Restore: %v", restoreErr)
	forgetErr := bob.device.ForgetGroup(scene.groupId)
	t.Logf("ForgetGroup: %v", forgetErr)

	if err := scene.aliceGroup.RemoveMember(scene.ctx, bobId); err != nil {
		advHarness(t, "alice's RemoveMember of the stranded leaf: %v", err)
	}
	joinCode, err := bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's fresh KeyPackage: %v", err)
	}
	invite, err := scene.aliceGroup.AddMemberAndPublish(scene.ctx, joinCode)
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish of the fresh join code: %v", err)
	}
	observed := []string{}
	rejoined, joinErr := bob.device.Join(scene.ctx, gcReencodeInvite(t, invite))
	t.Logf("Join over the founder's fresh invitation: %v", joinErr)
	if joinErr != nil {
		observed = append(observed, "wedged")
	} else {
		scene.bob, scene.bobGroup = bob, rejoined
		scene.say(t, "alice", scene.aliceGroup)
		scene.hear(t, "bob", rejoined)
		observed = append(observed, "rejoined")
	}
	advJudge(t, "S7-c1-unrestorable-rejoins", observed)
}

// advHeard is one Receive that answers whether a canary came back opened. It fails nothing: in a
// scenario whose subject is what still works, what a group read is a fact for the verdict.
func advHeard(ctx context.Context, group *urmessage.Group, canary string) bool {
	received, err := group.Receive(ctx)
	if err != nil {
		return false
	}
	for _, one := range received {
		if one.Gap == "" && one.Text == canary {
			return true
		}
	}
	return false
}

// CONTROL: ONE RECORD THAT DOES NOT READ COSTS ITS OWN GROUP AND NO OTHER. Bob holds two groups,
// the scene's and one of carol's founding. He is stopped, the scene's record on his disk is cut
// to half its length, and he is started again. Then everything a person can do is driven in
// order: Restore; an invitation into a third group; a founding under a fresh id; the two calls
// that must be REFUSED while the damaged record stands (a founding under its group's id, and the
// founder's own fresh invitation into its group); ForgetGroup; and that same invitation again.
//
// It is a control and not a gap. It is here because the held-group gate reads the disk: asked for
// every record the store holds instead of for the one group, a single record that did not read
// refused every invitation, every founding and every leave on the device, and no call cleared it.
func TestAdvSimOneRecordThatDoesNotReadCostsItsOwnGroupAndNoOther(t *testing.T) {
	scene := advFounding(t, true)
	ctx := scene.ctx
	bobId := rolesIdentityOf(t, scene.bobGroup)
	carol := scene.world.newPersona(t, "carol")
	if err := carol.device.Connect(ctx); err != nil {
		advHarness(t, "carol's Connect: %v", err)
	}
	otherId := newGroupId(t)
	carolGroup, _ := openPair(t, ctx, carol, scene.bob, otherId)

	scene.bob.kill()
	advDamageRecord(t, scene.bob.stateDir, scene.groupId)
	bob := scene.world.durablePersona(t, scene.bob.name, scene.bob.stateDir, scene.bob.streamDir)
	if err := bob.device.Connect(ctx); err != nil {
		advHarness(t, "the restarted bob's Connect: %v", err)
	}
	if _, err := bob.stateStore.GroupRecord(scene.groupId); !errors.Is(err, urmessage.ErrGroupRecordDamaged) {
		advHarness(t, "bob's record of the scene's group answers %v, so this is not a record that does not read", err)
	}
	observed := []string{}

	// RESTORE: the other group comes back and reads, and the damage is reported
	restored, restoreErr := bob.device.Restore(ctx)
	t.Logf("Restore: %d group(s), %v", len(restored), restoreErr)
	if len(restored) == 1 && bytes.Equal(restored[0].Id(), otherId) {
		canary := advCanary(t)
		if _, err := carolGroup.Send(ctx, canary); err != nil {
			advHarness(t, "carol's Send: %v", err)
		}
		if advHeard(ctx, restored[0], canary) {
			observed = append(observed, "others-restored")
		}
	}
	if errors.Is(restoreErr, urmessage.ErrRestore) && errors.Is(restoreErr, urmessage.ErrGroupRecordDamaged) {
		observed = append(observed, "damage-reported")
	}

	// ANOTHER GROUP STILL JOINS, and a fresh id still founds
	dave := scene.world.newPersona(t, "dave")
	if err := dave.device.Connect(ctx); err != nil {
		advHarness(t, "dave's Connect: %v", err)
	}
	daveGroup, err := dave.device.CreateGroup(ctx, newGroupId(t))
	if err != nil {
		advHarness(t, "dave's CreateGroup: %v", err)
	}
	joinCode, err := bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's KeyPackage for the third group: %v", err)
	}
	third, err := daveGroup.AddMember(joinCode)
	if err != nil {
		advHarness(t, "dave's AddMember: %v", err)
	}
	if err := daveGroup.Open(ctx); err != nil {
		advHarness(t, "dave's Open: %v", err)
	}
	joinedThird, err := bob.device.Join(ctx, gcReencodeInvite(t, third))
	t.Logf("Join of a third group, with the damaged record standing: %v", err)
	if err == nil {
		canary := advCanary(t)
		if _, err := daveGroup.Send(ctx, canary); err != nil {
			advHarness(t, "dave's Send: %v", err)
		}
		if advHeard(ctx, joinedThird, canary) {
			observed = append(observed, "other-group-joined")
		}
	}
	_, err = bob.device.CreateGroup(ctx, newGroupId(t))
	t.Logf("CreateGroup under a fresh id, with the damaged record standing: %v", err)
	if err == nil {
		observed = append(observed, "fresh-id-founded")
	}

	// WHILE THE DAMAGED RECORD STANDS, ITS OWN GROUP ID IS REFUSED: a founding under it, and the
	// founder's fresh invitation into it. Neither may read a record that does not read as "not held".
	_, err = bob.device.CreateGroup(ctx, scene.groupId)
	t.Logf("CreateGroup under the damaged group's id: %v", err)
	switch {
	case errors.Is(err, urmessage.ErrGroupAlreadyHeld):
		observed = append(observed, "damaged-id-not-founded")
	case err == nil:
		observed = append(observed, "founded-over-the-damaged-record")
	}
	if err := scene.aliceGroup.RemoveMember(ctx, bobId); err != nil {
		advHarness(t, "alice's RemoveMember of the stranded leaf: %v", err)
	}
	joinCode, err = bob.device.KeyPackage()
	if err != nil {
		advHarness(t, "bob's fresh KeyPackage: %v", err)
	}
	fresh, err := scene.aliceGroup.AddMemberAndPublish(ctx, joinCode)
	if err != nil {
		advHarness(t, "alice's AddMemberAndPublish of the fresh join code: %v", err)
	}
	_, err = bob.device.Join(ctx, gcReencodeInvite(t, fresh))
	t.Logf("Join over the founder's fresh invitation, with the damaged record standing: %v", err)
	switch {
	case errors.Is(err, urmessage.ErrGroupAlreadyHeld):
		observed = append(observed, "damaged-invite-refused")
	case err == nil:
		observed = append(observed, "joined-over-the-damaged-record")
	}

	// THE REMEDY THAT REFUSAL NAMES, and then the same invitation again: the refusal cost nothing
	forgetErr := bob.device.ForgetGroup(scene.groupId)
	t.Logf("ForgetGroup of the damaged group: %v", forgetErr)
	rejoined, joinErr := bob.device.Join(ctx, gcReencodeInvite(t, fresh))
	t.Logf("Join over the same invitation after ForgetGroup: %v", joinErr)
	if joinErr != nil {
		observed = append(observed, "wedged")
	} else {
		scene.bob, scene.bobGroup = bob, rejoined
		scene.say(t, "alice", scene.aliceGroup)
		scene.hear(t, "bob", rejoined)
		observed = append(observed, "rejoined")
	}
	advJudge(t, "S7-c2-unreadable-record-costs-one-group", observed)
}
