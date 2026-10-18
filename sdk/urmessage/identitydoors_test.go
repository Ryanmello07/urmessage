package urmessage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
)

// THE DOORS AND THE HEADS (identity phase 1's Task 13; Properties 4, 5 and 9). The Add door judges a
// join code before anything is staged, against this device's own heads; the Join door judges the tree
// a Welcome hands over, inside T1's window; and the heads only rise, this identity's own only from its
// self group.

// keyPackageUnder is a key package of a device of the seed given, under an identity key, carrying a
// list: what a further device of that identity publishes.
func keyPackageUnder(t *testing.T, root string, identityKey []byte, seed mls.SignaturePrivateKey,
	list messagegroup.ExtensionBytes) []byte {

	t.Helper()
	dev := openCrossProcessDevice(t, root)
	t.Cleanup(dev.close)
	engine, err := messagegroup.NewConnectMlsEngine(dev.crypto, dev.store, seed, mls.BasicCredential(identityKey), dev.leafKeys)
	if err != nil {
		t.Fatalf("the engine under %x: %v", identityKey, err)
	}
	keyPackage, err := engine.NewBoundKeyPackage([]messagegroup.ExtensionBytes{list})
	if err != nil {
		t.Fatalf("a key package under %x: %v", identityKey, err)
	}
	return keyPackage
}

// identifiedAnsweringDevice is a connected device with an identity of its own.
func identifiedAnsweringDevice(t *testing.T, name string) *Device {
	t.Helper()
	device, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte(name+"'s nonce"))
	testIdentify(t, device)
	if err := device.Connect(t.Context()); err != nil {
		t.Fatalf("%s's Connect: %v", name, err)
	}
	return device
}

// verifiedListOf is a list as the binding check answers it, for the device key it names.
func verifiedListOf(t *testing.T, identityKey []byte, deviceKey []byte, list messagegroup.ExtensionBytes) *messagegroup.VerifiedIdentity {
	t.Helper()
	verified, err := messagegroup.VerifyLeafBinding(identityKey, deviceKey, []messagegroup.ExtensionBytes{list})
	if err != nil {
		t.Fatalf("the list does not bind %x: %v", deviceKey, err)
	}
	return verified
}

// freshGroupId is a group id no other group of the test holds.
func freshGroupId(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, GroupIdBytes)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// addRefusedNothingStaged holds a refused founding add to its promise: the refusal names its sentinel,
// and the founder's handle is at epoch zero with nothing staged.
func addRefusedNothingStaged(t *testing.T, what string, group *Group, joinCode []byte, want error) {
	t.Helper()
	if _, err := group.AddMember(joinCode); !errors.Is(err, want) {
		t.Fatalf("%s answered %v, want %v", what, err, want)
	}
	if epoch := group.handle.Epoch(); epoch != 0 {
		t.Fatalf("%s left the founder's handle at epoch %d", what, epoch)
	}
	if _, err := group.handle.PendingEpoch(); err == nil {
		t.Fatalf("%s left a commit staged on the founder", what)
	}
}

// THE ADD DOOR REFUSES A JOIN CODE WHOSE LIST THIS DEVICE KNOWS IS OLDER, AND ONE BOUND TO NO
// IDENTITY, BEFORE ANYTHING IS STAGED (Property 5). Bob's laptop is named by his base 2; his base 3
// drops it. A founder that has not seen base 3 adds the laptop's join code -- THE CONTROL: the door
// refuses on what this device knows, and nothing else -- and one that has seen it refuses the same
// join code with nothing staged, on both adds: the founding one, and the live one, where nothing
// reaches the server either. A join code whose list is older than the head and which the head still
// names, Bob's own, is added. A join code with no 0xF005 under a credential that is not its key, and
// one of the profile-1 shape, are refused as bound to no identity.
func TestTheAddDoorRefusesAKeyPackageWhoseListThisDeviceKnowsIsOlder(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	founder := identifiedAnsweringDevice(t, "the founder")
	bob := identifiedAnsweringDevice(t, "bob")
	bobKey := bytes.Clone(bob.identity.record.Root)
	bobPub := bytes.Clone(bob.devicePub)
	laptopSeed, laptopPub := testDeviceKey("bob's laptop, which his base 3 drops")
	laptopList, _ := testSiblingList(t, bobKey, laptopSeed, laptopPub)
	laptop := keyPackageUnder(t, filepath.Join(dir, "bob-laptop"), bobKey, laptopSeed, laptopList)
	base3 := testNextList(t, bobKey, bob.signer, bobPub, bobPub)

	// THE CONTROL: a founder that has not seen base 3 adds the laptop
	if _, err := founder.CreateGroup(ctx, freshGroupId(t)); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	unaware, err := founder.CreateGroup(ctx, freshGroupId(t))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if _, err := unaware.AddMember(laptop); err != nil {
		t.Fatalf("CONTROL FAILED: a founder that holds no newer list of Bob's refused his laptop: %v", err)
	}

	// THE FOUNDER LEARNS BASE 3, and the door refuses the laptop with nothing staged
	if err := founder.raiseHeadsFrom([]*messagegroup.VerifiedIdentity{verifiedListOf(t, bobKey, bobPub, base3)}, false); err != nil {
		t.Fatalf("the founder's heads: %v", err)
	}
	aware, err := founder.CreateGroup(ctx, freshGroupId(t))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	addRefusedNothingStaged(t, "the laptop's join code", aware, laptop, ErrKeyPackageListStale)

	// THE TWO JOIN CODES BOUND TO NO IDENTITY
	unbound := claimingKeyPackage(t, filepath.Join(dir, "a claimant"), bytes.Repeat([]byte{0x6c}, 32))
	addRefusedNothingStaged(t, "a join code with no 0xF005 under another credential", aware, unbound, ErrKeyPackageUnbound)
	profileOne := keyPackageListing(t, engineCapabilitiesForTests())
	addRefusedNothingStaged(t, "a join code of the profile-1 shape", aware, profileOne, ErrKeyPackageUnbound)

	// A JOIN CODE OLDER THAN THE HEAD THAT THE HEAD STILL NAMES: Bob's own, under base 1
	own, err := bob.KeyPackage()
	if err != nil {
		t.Fatalf("bob's KeyPackage: %v", err)
	}
	if _, err := aware.AddMember(own); err != nil {
		t.Fatalf("bob's own join code, which his newest list names, was refused: %v", err)
	}

	// THE LIVE ADD: the door refuses at AddMemberAndPublish too, and nothing reaches the server. Bob's
	// identity is in no tree of this group, so by the trees his laptop would be current; the refusal is
	// the door's, on what the adder knows
	world := newRoleWorld(t, "alice", "carol")
	alice := world.member("alice")
	client := world.connect(alice)
	testHoldIdentity(t, alice.group.device, alice.dev.identityPub, alice.dev.extension, alice.dev.signer)
	if err := alice.group.device.raiseHeadsFrom([]*messagegroup.VerifiedIdentity{verifiedListOf(t, bobKey, bobPub, base3)}, false); err != nil {
		t.Fatalf("alice's heads: %v", err)
	}
	livePackage := laptop
	epoch, answered := alice.group.Epoch(), client.answered()
	if _, err := alice.group.AddMemberAndPublish(ctx, livePackage); !errors.Is(err, ErrKeyPackageListStale) {
		t.Fatalf("the live add of the dropped laptop answered %v, want ErrKeyPackageListStale", err)
	}
	if got := client.answered(); got != answered {
		t.Fatalf("the refused live add sent %d request(s) to the server", got-answered)
	}
	if got := alice.group.Epoch(); got != epoch {
		t.Fatalf("the refused live add moved alice to epoch %d, from %d", got, epoch)
	}
	if _, err := alice.handle.PendingEpoch(); err == nil {
		t.Fatal("the refused live add left a commit staged")
	}
}

// engineCapabilitiesForTests is the capability list this build's leaves carry, for a key package made
// by hand.
func engineCapabilitiesForTests() []mls.ExtensionType {
	return []mls.ExtensionType{
		mls.ExtensionTypeUrmessageGroupPolicy,
		mls.ExtensionTypeUrmessageLeafKeys,
		mls.ExtensionTypeUrmessageJoinSeal,
		mls.ExtensionTypeUrmessageIdentity,
		mls.ExtensionTypeUrmessageGroupPurpose,
	}
}

// hostileFoundingInvite is a founding add that no Add door judged: the founder's group admits the join
// code and the others beside it in one commit, and the joiner's invite is sealed off that staged
// commit as [Group.AddMember] seals one. The founder keeps nothing of it.
func hostileFoundingInvite(t *testing.T, group *Group, joinCode []byte, alongside ...[]byte) *Invite {
	t.Helper()
	group.mutex.Lock()
	defer group.mutex.Unlock()
	joiner, err := group.device.joinerOf(joinCode)
	if err != nil {
		t.Fatalf("the joiner's join code: %v", err)
	}
	_, welcome, ratchetTree, err := group.handle.CommitAdd(append(append([][]byte{}, alongside...), joinCode))
	if err != nil {
		t.Fatalf("the hostile founding add: %v", err)
	}
	defer group.handle.ClearPendingCommit()
	joinSeal, joinAuth, _, err := group.sealFoundingJoinLocked(joiner, welcome, ratchetTree, group.pqSecretLocked())
	if err != nil {
		t.Fatalf("the hostile founding add's seal: %v", err)
	}
	return &Invite{
		GroupId:     bytes.Clone(group.id),
		Welcome:     bytes.Clone(welcome),
		RatchetTree: bytes.Clone(ratchetTree),
		JoinSeal:    joinSeal,
		JoinAuth:    joinAuth,
	}
}

// storeFiles is every file under a store's directory with its octets, but the store's lock, which a
// running store holds and no write of this test's concern touches.
func storeFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Name() == "single-writer.lock" {
			return nil
		}
		octets, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(dir, path)
		files[filepath.ToSlash(relative)] = string(octets)
		return nil
	})
	if err != nil {
		t.Fatalf("listing %s: %v", dir, err)
	}
	return files
}

// testIdentifyAsSibling gives a device the identity of another device the tests made, as a further
// device of it: the identity's next list, naming the other's devices and this one, under the same
// root. It is what the link (Task 23) will make; nothing is written.
func testIdentifyAsSibling(t *testing.T, device *Device, of *Device) {
	t.Helper()
	root := bytes.Clone(of.identity.record.Root)
	signer, devicePub := device.deviceSigner()
	defer zeroizeState(signer)
	list, known := testSiblingList(t, root, signer, devicePub)
	if !known {
		t.Fatalf("no test made the identity %x", root)
	}
	parsed, err := messagegroup.ParseUrmessageIdentity(list)
	if err != nil {
		t.Fatal(err)
	}
	state, err := newDeviceIdentityState(IdentityRecord{Root: root, CurrentKey: root, Salt: of.identity.record.Salt}, parsed, devicePub)
	if err != nil {
		t.Fatalf("the sibling's identity: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(device.crypto, device.joinStage, signer, mls.BasicCredential(root), device.leafKeys)
	if err != nil {
		t.Fatalf("the sibling's engine: %v", err)
	}
	device.identityLock.Lock()
	defer device.identityLock.Unlock()
	device.engine = engine
	device.identityPub = root
	device.identity = state
	device.heads = map[string][]byte{string(root): bytes.Clone(list.Data)}
}

// foundSystemGroup founds a system group on a connected device, as the self group is founded.
func foundSystemGroup(t *testing.T, device *Device) *Group {
	t.Helper()
	nonce, nonceEpoch, err := device.nonce()
	if err != nil {
		t.Fatalf("the founder's nonce: %v", err)
	}
	device.admitMutex.Lock()
	defer device.admitMutex.Unlock()
	group, err := device.foundGroupLocked(freshGroupId(t), true, nonce, nonceEpoch)
	if err != nil {
		t.Fatalf("founding a system group: %v", err)
	}
	return group
}

// EVERY JOIN DOOR REFUSAL WRITES NOTHING AND KEEPS THE JOIN CODE (Property 5; T1's window). Three
// invitations whose trees every member's rules would refuse, each built past the Add door by a founding
// add of its own: a leaf bound to no identity, two lists of one identity that fork, and a self group
// holding a stranger. Each is refused inside the window with its own sentinel under [ErrJoinRefused];
// the joiner's store is the same file for file; it holds no group; and the honest invitation that
// follows joins over the same join code.
func TestEveryJoinDoorRefusalWritesNothingAndKeepsTheJoinCode(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	founder := identifiedAnsweringDevice(t, "the founder")

	// a leaf bound to no identity
	unbound := claimingKeyPackage(t, filepath.Join(dir, "unbound"), bytes.Repeat([]byte{0x75}, 32))
	// two lists of one identity, at base 2, that fork
	xavier := identifiedAnsweringDevice(t, "xavier")
	xavierKey, xavierPub := bytes.Clone(xavier.identity.record.Root), bytes.Clone(xavier.devicePub)
	phrase := testPhraseOf(t, xavierKey)
	forkOneSeed, forkOnePub := testDeviceKey("xavier's first fork")
	forkTwoSeed, forkTwoPub := testDeviceKey("xavier's second fork")
	forkOne := keyPackageUnder(t, filepath.Join(dir, "fork-one"), xavierKey, forkOneSeed,
		testBaseList(t, phrase, 2, forkOneSeed, forkOnePub, xavierPub, forkOnePub))
	forkTwo := keyPackageUnder(t, filepath.Join(dir, "fork-two"), xavierKey, forkTwoSeed,
		testBaseList(t, phrase, 2, forkTwoSeed, forkTwoPub, xavierPub, forkTwoPub))
	phrase.Erase()
	// a stranger, bound to an identity of its own
	stranger := identifiedAnsweringDevice(t, "a stranger")
	strangerCode, err := stranger.KeyPackage()
	if err != nil {
		t.Fatalf("the stranger's KeyPackage: %v", err)
	}

	for _, row := range []struct {
		name      string
		sibling   bool
		alongside [][]byte
		want      error
	}{
		{"a leaf bound to no identity", false, [][]byte{unbound}, ErrGroupLeafUnbound},
		{"two lists of one identity that fork", false, [][]byte{forkOne, forkTwo}, ErrDeviceListEquivocation},
		{"a self group holding a stranger", true, [][]byte{strangerCode}, ErrSystemGroupViolation},
	} {
		t.Run(row.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "joiner")
			joiner := newAnsweringDeviceOver(t, openTestStore(t, stateDir), []byte("the joiner's nonce"))
			if row.sibling {
				testIdentifyAsSibling(t, joiner, founder)
			} else {
				testIdentify(t, joiner)
			}
			joinCode, err := joiner.KeyPackage()
			if err != nil {
				t.Fatalf("the joiner's KeyPackage: %v", err)
			}
			founding := func() *Group {
				if row.sibling {
					return foundSystemGroup(t, founder)
				}
				group, err := founder.CreateGroup(ctx, freshGroupId(t))
				if err != nil {
					t.Fatalf("CreateGroup: %v", err)
				}
				return group
			}
			hostile := hostileFoundingInvite(t, founding(), joinCode, row.alongside...)
			before := storeFiles(t, stateDir)
			_, err = joiner.Join(ctx, hostile)
			if !errors.Is(err, ErrJoinRefused) || !errors.Is(err, row.want) {
				t.Fatalf("the join answered %v, want ErrJoinRefused wrapping %v", err, row.want)
			}
			if errors.Is(err, ErrJoinCodeSpent) {
				t.Fatalf("the refusal says the join code is spent: %v", err)
			}
			after := storeFiles(t, stateDir)
			if len(after) != len(before) {
				t.Fatalf("the refused join left %d file(s) where there were %d", len(after), len(before))
			}
			for name, octets := range before {
				if after[name] != octets {
					t.Fatalf("the refused join changed %s", name)
				}
			}
			joiner.mutex.Lock()
			held := len(joiner.groups)
			joiner.mutex.Unlock()
			if held != 0 {
				t.Fatalf("the refused join left the joiner holding %d group(s)", held)
			}
			// THE JOIN CODE IS KEPT: the honest invitation joins over it
			honest, err := founding().AddMember(joinCode)
			if err != nil {
				t.Fatalf("the honest founding add: %v", err)
			}
			joined, err := joiner.Join(ctx, honest)
			if err != nil {
				t.Fatalf("the honest invitation after the refusal answered %v, so the refusal spent the join code", err)
			}
			if joined.system != row.sibling {
				t.Fatalf("the joined group reads system = %v, and it is %v", joined.system, row.sibling)
			}
		})
	}
}

// A LIST OF MINE SEEN ONLY IN A CONVERSATION MOVES NOTHING OF MINE (Property 9; REDTEAM M4; M5 TR8). A
// copy of Alice -- a further leaf of her identity, holding her words -- commits a base into a
// conversation only. Alice follows it, as the trees allow, and her own head stays where it was, in
// memory and in her store, so a restart reads her own list back unchanged.
//
// TWO CONTROLS, so the head is seen to move where it should: Bob's next base, brought into the same
// conversation, raises Alice's head of Bob's; and the same kind of base of Alice's, brought into her
// self group, raises her own.
func TestAListOfMineSeenOnlyInAConversationMovesNothingOfMine(t *testing.T) {
	copyOf := func(of **crossProcessDevice) func(name string, dev *crossProcessDevice) {
		return func(name string, dev *crossProcessDevice) {
			switch name {
			case "alice":
				*of = dev
			case "alice-copy":
				list, known := testSiblingList(t, (*of).identityPub, dev.signer, testPublicOf(dev.signer))
				if !known {
					t.Fatal("alice's words are not kept")
				}
				claimIdentity(t, dev, (*of).identityPub, list)
			}
		}
	}
	nextBaseOf := func(copier *roleMember, aliceKey []byte, alicePub []byte) messagegroup.ExtensionBytes {
		copyPub := testPublicOf(copier.dev.signer)
		return testNextList(t, aliceKey, copier.dev.signer, copyPub, alicePub, copyPub)
	}

	// THE CONVERSATION
	var aliceDev *crossProcessDevice
	world := newRoleWorldWith(t, roleWorldOptions{prepare: copyOf(&aliceDev)}, "alice", "bob", "alice-copy")
	alice, bob, copier := world.member("alice"), world.member("bob"), world.member("alice-copy")
	testHoldIdentity(t, alice.group.device, alice.dev.identityPub, alice.dev.extension, alice.dev.signer)
	alicePub := testPublicOf(alice.dev.signer)
	ownBefore, storedBefore := testHeadOf(t, alice.group.device, alice.dev.identityPub)
	if !bytes.Equal(ownBefore, alice.dev.extension.Data) || !bytes.Equal(storedBefore, alice.dev.extension.Data) {
		t.Fatal("CONTROL FAILED: alice's own head is not her own list before the copy commits")
	}
	record := world.ownLeafCommit(copier, nextBaseOf(copier, alice.dev.identityPub, alicePub))
	world.ingest(alice, copier, record)
	world.ingest(bob, copier, record)
	if own, stored := testHeadOf(t, alice.group.device, alice.dev.identityPub); !bytes.Equal(own, ownBefore) || !bytes.Equal(stored, storedBefore) {
		t.Fatal("a list of alice's seen only in a conversation moved her own head")
	}

	// THE FIRST CONTROL: Bob's next base, in the same conversation, raises alice's head of Bob's
	bobPub := testPublicOf(bob.dev.signer)
	bobNext := testNextList(t, bob.dev.identityPub, bob.dev.signer, bobPub, bobPub)
	record = world.ownLeafCommit(bob, bobNext)
	world.ingest(alice, bob, record)
	if held, stored := testHeadOf(t, alice.group.device, bob.dev.identityPub); !bytes.Equal(held, bobNext.Data) || !bytes.Equal(stored, bobNext.Data) {
		t.Fatal("CONTROL FAILED: bob's next base did not raise alice's head of bob's, so the raise is not running")
	}

	// THE SECOND CONTROL: the same of alice's, in her self group, raises her own head
	var selfAliceDev *crossProcessDevice
	selfWorld := newRoleWorldWith(t, roleWorldOptions{
		prepare: copyOf(&selfAliceDev),
		context: func(founder *crossProcessDevice) []messagegroup.ExtensionBytes {
			purpose, err := selfGroupPurpose(founder.identityPub)
			if err != nil {
				t.Fatal(err)
			}
			return []messagegroup.ExtensionBytes{purpose}
		},
	}, "alice", "alice-copy")
	selfAlice, selfCopy := selfWorld.member("alice"), selfWorld.member("alice-copy")
	testHoldIdentity(t, selfAlice.group.device, selfAlice.dev.identityPub, selfAlice.dev.extension, selfAlice.dev.signer)
	next := nextBaseOf(selfCopy, selfAlice.dev.identityPub, testPublicOf(selfAlice.dev.signer))
	record = selfWorld.ownLeafCommit(selfCopy, next)
	selfWorld.ingest(selfAlice, selfCopy, record)
	if own, stored := testHeadOf(t, selfAlice.group.device, selfAlice.dev.identityPub); !bytes.Equal(own, next.Data) || !bytes.Equal(stored, next.Data) {
		t.Fatal("CONTROL FAILED: alice's next base, in her self group, did not raise her own head")
	}
}

// A STORED HEAD NEVER GOES BACKWARD (Property 4), in memory or in the store, whatever lists arrive and
// in whatever order: an older list leaves it, a fork of it leaves it, and only a newer one moves it.
// The trees raise heads through this one call, so its order is the whole of the property.
func TestAStoredHeadOnlyRises(t *testing.T) {
	device := newAnsweringDeviceOver(t, openTestStore(t, filepath.Join(t.TempDir(), "device")), []byte("the device's nonce"))
	testIdentify(t, device)
	xavier := identifiedAnsweringDevice(t, "xavier")
	key, pub := bytes.Clone(xavier.identity.record.Root), bytes.Clone(xavier.devicePub)
	phrase := testPhraseOf(t, key)
	defer phrase.Erase()
	otherSeed, otherPub := testDeviceKey("xavier's other device")
	lists := map[string]messagegroup.ExtensionBytes{
		"base 1":           xavier.identity.extension,
		"base 2":           testBaseList(t, phrase, 2, xavier.signer, pub, pub),
		"a fork of base 2": testBaseList(t, phrase, 2, otherSeed, otherPub, pub, otherPub),
		"base 3":           testBaseList(t, phrase, 3, xavier.signer, pub, pub),
	}
	for _, step := range []struct {
		raise string
		want  string
	}{
		{"base 2", "base 2"},
		{"base 1", "base 2"},
		{"a fork of base 2", "base 2"},
		{"base 3", "base 3"},
		{"base 2", "base 3"},
		{"base 1", "base 3"},
	} {
		if err := device.raiseHeadsFrom([]*messagegroup.VerifiedIdentity{verifiedListOf(t, key, pub, lists[step.raise])}, false); err != nil {
			t.Fatalf("raising %s: %v", step.raise, err)
		}
		held, stored := testHeadOf(t, device, key)
		if !bytes.Equal(held, lists[step.want].Data) || !bytes.Equal(stored, lists[step.want].Data) {
			t.Fatalf("after %s the head is not %s, in memory (%v) or in the store (%v)", step.raise, step.want,
				bytes.Equal(held, lists[step.want].Data), bytes.Equal(stored, lists[step.want].Data))
		}
	}
}
