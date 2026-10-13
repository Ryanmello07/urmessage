package cp3b

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/message/message"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE ADVERSARY'S OWN TOOLS. Nothing in this file is the code under test's reading of its own
// formats: the invite and the key package are read here by offsets written from their grammar, so
// an adversary that finds a secret finds it in the OCTETS and not in a field the production
// decoder chose to hand over.

// ── the paste channel ────────────────────────────────────────────────────────────────────────

// advPaste is the out-of-band channel two people move a join code and an invitation over. Every
// artefact a scenario moves goes through carry, which is what a recorder on that channel keeps.
type advPaste struct {
	captured [][]byte
}

func (self *advPaste) carry(octets []byte) []byte {
	self.captured = append(self.captured, append([]byte(nil), octets...))
	return append([]byte(nil), octets...)
}

// haystack is everything the recorder kept, end to end: what a scrape reads.
func (self *advPaste) haystack() []byte {
	return bytes.Join(self.captured, nil)
}

// advCanary is a text no other source produces: "cnry-" and 32 hex digits.
func advCanary(t *testing.T) string {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("drawing a canary: %v", err)
	}
	return "cnry-" + hex.EncodeToString(random)
}

// ── the invite and the join code, read by their grammar ──────────────────────────────────────

// advInviteFields reads an encoded invite as what it is on the wire: a u16 version, fields each
// under a u32 length, and the SHA-256 of everything before it. It asserts the checksum, so a
// caller that re-encodes one knows the original was whole.
func advInviteFields(t *testing.T, encoded []byte) (uint16, [][]byte) {
	t.Helper()
	if len(encoded) < 2+sha256.Size {
		advHarness(t, "an invite of %d octets is shorter than a version and a checksum", len(encoded))
	}
	body := encoded[:len(encoded)-sha256.Size]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], encoded[len(encoded)-sha256.Size:]) {
		advHarness(t, "the invite's last 32 octets are not the SHA-256 of the octets before them")
	}
	version := binary.BigEndian.Uint16(body[:2])
	fields := [][]byte{}
	at := 2
	for at < len(body) {
		if len(body)-at < 4 {
			advHarness(t, "the invite ends inside a length prefix at octet %d", at)
		}
		length := int(binary.BigEndian.Uint32(body[at : at+4]))
		at += 4
		if len(body)-at < length {
			advHarness(t, "the invite's field at octet %d claims %d octets and %d remain", at, length, len(body)-at)
		}
		fields = append(fields, append([]byte(nil), body[at:at+length]...))
		at += length
	}
	return version, fields
}

// advEncodeInvite is the active attacker's tool: the same grammar written back, with the checksum
// recomputed. The checksum is not an authentication, and this is the function that shows it.
func advEncodeInvite(version uint16, fields [][]byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	for _, field := range fields {
		body = binary.BigEndian.AppendUint32(body, uint32(len(field)))
		body = append(body, field...)
	}
	sum := sha256.Sum256(body)
	return append(body, sum[:]...)
}

// advKeyPackageInitKey reads the HPKE init public key out of an encoded RFC 9420 KeyPackage:
// u16 version (mls10 = 1), u16 cipher suite (3), then init_key<V>, whose 32 octets stand under a
// one-octet variable-length prefix.
func advKeyPackageInitKey(t *testing.T, keyPackage []byte) []byte {
	t.Helper()
	if len(keyPackage) < 37 || keyPackage[0] != 0x00 || keyPackage[1] != 0x01 ||
		keyPackage[2] != 0x00 || keyPackage[3] != 0x03 || keyPackage[4] != 0x20 {
		advHarness(t, "these %d octets do not begin as an mls10 key package at suite 0x0003 with a 32 octet init key", len(keyPackage))
	}
	return append([]byte(nil), keyPackage[5:37]...)
}

// ── the Shor oracle ──────────────────────────────────────────────────────────────────────────

// advShadow is what a recorder with a quantum computer holds of one join: the MLS group state of
// the epoch the Welcome admitted the joiner at, rebuilt from the joiner's CLASSICAL private keys.
type advShadow struct {
	handle   messagegroup.GroupHandle
	exporter []byte
	epoch    uint64
	ownLeaf  uint32
}

// advShor is the grant rule and the grant.
//
// THE RULE: a quantum computer inverts a classical public key it HOLDS. The Welcome is sealed to
// the HPKE init key of one key package, and that key is published in the join code and nowhere
// else, so the oracle grants the joiner's classical private keys if and only if the init key
// occurs in the octets the recorder captured. An invitation alone grants nothing.
//
// THE GRANT: a copy of the joiner's state directory taken BEFORE the join, opened as a store, and
// the production engine joining the recorded Welcome over it. Every key that join uses is
// classical: the init key, the leaf's X25519 key and the Ed25519 signer.
//
// WHAT IS WITHHELD: the X-Wing seed. ML-KEM-768 is what the quantum computer does not break, so
// the seed in the copy is OVERWRITTEN with 32 random octets before anything else reads the store.
// A shadow that reached for the seed would open nothing with it.
func advShor(t *testing.T, captured [][]byte, joinCode []byte, preJoinStateDir string,
	welcome []byte, ratchetTree []byte) (*advShadow, bool) {

	t.Helper()
	initKey := advKeyPackageInitKey(t, joinCode)
	if !bytes.Contains(bytes.Join(captured, nil), initKey) {
		return nil, false
	}
	shadowDir := filepath.Join(t.TempDir(), "shadow")
	copyAppData(t, preJoinStateDir, shadowDir)
	store, err := urmessage.OpenDurableStateStore(shadowDir)
	if err != nil {
		advHarness(t, "the shadow's copy of the joiner's store does not open: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	signerPub, signerPriv, leafKeys, seed, err := store.GetDeviceIdentity()
	if err != nil {
		advHarness(t, "the shadow's copy holds no device identity: %v", err)
	}
	if len(seed) != messagegroup.XwingSeedSize {
		advHarness(t, "the joiner's store holds a %d octet x-wing seed, so there was nothing to withhold", len(seed))
	}
	if _, err := rand.Read(seed); err != nil {
		advHarness(t, "drawing the replacement seed: %v", err)
	}
	if err := store.PutDeviceIdentity(signerPub, signerPriv, leafKeys, seed); err != nil {
		advHarness(t, "withholding the x-wing seed from the shadow: %v", err)
	}
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		advHarness(t, "the crypto provider: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, store, mls.SignaturePrivateKey(signerPriv),
		mls.BasicCredential(signerPub), leafKeys)
	if err != nil {
		advHarness(t, "the shadow's engine: %v", err)
	}
	handle, err := engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		advHarness(t, "the shadow holds the joiner's classical keys and the recorded Welcome did not open: %v", err)
	}
	exporter, err := handle.Export("URmessage/v1/storage", nil, 32)
	if err != nil {
		advHarness(t, "the shadow's exporter: %v", err)
	}
	return &advShadow{handle: handle, exporter: exporter, epoch: handle.Epoch(), ownLeaf: handle.OwnLeafIndex()}, true
}

// THE INIT KEY READER'S OWN CONTROL. The grant rule turns on thirty-two octets read by offset, so
// they are held against the one thing that cannot be argued with: the private half the store keeps
// for that key package, pushed through X25519 by the standard library.
func TestAdvSimTheInitKeyReaderReadsTheKeyTheStoreHoldsThePrivateHalfOf(t *testing.T) {
	world := newWorld(t)
	bob := world.newPersona(t, "bob")
	joinCode, err := bob.device.KeyPackage()
	if err != nil {
		t.Fatalf("bob's KeyPackage: %v", err)
	}
	initKey := advKeyPackageInitKey(t, joinCode)
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("the crypto provider: %v", err)
	}
	ref, err := mls.MakeKeyPackageRef(crypto, joinCode)
	if err != nil {
		t.Fatalf("the key package's reference: %v", err)
	}
	// a copy, because the take is destructive and bob's own store must keep its key package
	copyDir := filepath.Join(t.TempDir(), "copy")
	copyAppData(t, bob.stateDir, copyDir)
	store, err := urmessage.OpenDurableStateStore(copyDir)
	if err != nil {
		t.Fatalf("opening the copy: %v", err)
	}
	defer store.Close()
	_, initPrivate, _, err := store.TakeKeyPackage(ref)
	if err != nil {
		t.Fatalf("the copy holds no key package under the join code's reference: %v", err)
	}
	private, err := ecdh.X25519().NewPrivateKey(initPrivate)
	if err != nil {
		t.Fatalf("the stored init private key is not an X25519 scalar: %v", err)
	}
	if !bytes.Equal(private.PublicKey().Bytes(), initKey) {
		t.Fatalf("octets 5..37 of the join code are %x, and the init private key the store holds has public half %x",
			initKey, private.PublicKey().Bytes())
	}
	// and the two places the grant rule reads: in the join code, never in an invitation built from it
	if !bytes.Contains(joinCode, initKey) {
		t.Fatal("the init key is not in the join code it was read from")
	}
}

// ── what the server holds ────────────────────────────────────────────────────────────────────

// advPublishedDigest is H(epoch_keys) of the commit that opened one epoch, read off the server's
// own rows: the value every reader of the group is served, and the one a candidate secret is
// confirmed against.
func advPublishedDigest(t *testing.T, world *world, groupId []byte, epoch uint64) []byte {
	t.Helper()
	for _, row := range world.allRows(t, groupId) {
		if !row.IsCommit || len(row.ServerAttachment) == 0 {
			continue
		}
		attachment, err := message.ParseServerAttachment(row.ServerAttachment)
		if err != nil || attachment.Kind != message.AttachmentEpochDigest || attachment.EpochDigest == nil {
			continue
		}
		if attachment.EpochDigest.Epoch == epoch {
			return append([]byte(nil), attachment.EpochDigest.EpochKeysDigest...)
		}
	}
	advHarness(t, "the server holds no commit whose kind 0x0005 attachment opens epoch %d, so no candidate secret can be confirmed", epoch)
	return nil
}

// advServerHandles is every sender_handle the server holds a row under.
func advServerHandles(t *testing.T, world *world, groupId []byte) map[[16]byte]bool {
	t.Helper()
	handles := map[[16]byte]bool{}
	for _, row := range world.allRows(t, groupId) {
		if len(row.SenderHandle) == 16 {
			handles[[16]byte(row.SenderHandle)] = true
		}
	}
	if len(handles) == 0 {
		advHarness(t, "the server holds no sender_handle for this group, so no handle key can be confirmed")
	}
	return handles
}

// ── the scrape ───────────────────────────────────────────────────────────────────────────────

type advScraped struct {
	pqSecret       []byte
	pqAt           int
	groupHandleKey []byte
	ghkAt          int
}

// advScrapeHandleKey slides a 32 octet window over the haystack and confirms a group_handle_key
// by what only that key does: it expands to a sender_handle the server holds a row under. It needs
// no MLS secret, which is why a classical observer can run it.
func advScrapeHandleKey(t *testing.T, world *world, groupId []byte, haystack []byte) ([]byte, int) {
	t.Helper()
	handles := advServerHandles(t, world, groupId)
	for at := 0; at+32 <= len(haystack); at += 1 {
		window := haystack[at : at+32]
		for leaf := uint32(0); leaf < 16; leaf += 1 {
			if handles[messagegroup.SenderHandle(window, leaf)] {
				return append([]byte(nil), window...), at
			}
		}
	}
	return nil, -1
}

// advScrapePqSecret slides the same window and confirms a pq_secret against the epoch's published
// digest: storage_root = Extract(exporter, window), the two server keys off that root, and
// H(epoch_keys) over them. A hit is the adversary holding storage_root of that epoch.
func advScrapePqSecret(t *testing.T, world *world, groupId []byte, shadow *advShadow, haystack []byte) ([]byte, int) {
	t.Helper()
	published := advPublishedDigest(t, world, groupId, shadow.epoch)
	group := [32]byte(groupId)
	for at := 0; at+32 <= len(haystack); at += 1 {
		window := haystack[at : at+32]
		root := messagegroup.StorageRoot(shadow.exporter, window)
		digest, err := message.EpochKeysDigest(group, shadow.epoch, message.WriteKey(root), message.ReadKey(root))
		if err != nil {
			advHarness(t, "H(epoch_keys) over a candidate: %v", err)
		}
		if bytes.Equal(digest, published) {
			return append([]byte(nil), window...), at
		}
	}
	return nil, -1
}

// advScrape runs both, and says where each was found.
func advScrape(t *testing.T, world *world, groupId []byte, shadow *advShadow, haystack []byte) advScraped {
	t.Helper()
	scraped := advScraped{pqAt: -1, ghkAt: -1}
	scraped.pqSecret, scraped.pqAt = advScrapePqSecret(t, world, groupId, shadow, haystack)
	scraped.groupHandleKey, scraped.ghkAt = advScrapeHandleKey(t, world, groupId, haystack)
	t.Logf("scraped %d octets (%d windows): pq_secret at %d, group_handle_key at %d",
		len(haystack), max(len(haystack)-31, 0), scraped.pqAt, scraped.ghkAt)
	return scraped
}

// ── reading ──────────────────────────────────────────────────────────────────────────────────

// advRead opens the group's application records of the shadow's epoch through the PRODUCTION
// opener, with the two secrets the adversary recovered, and answers one "epoch:N" fact per canary
// it recovered. An adversary has read an epoch if and only if it produces a canary sealed there.
//
// The records are the ones the clients submitted, off the wire tap: the octets a recorder of the
// server's rows holds. The shadow stands at the joiner's leaf, and a member cannot open its own
// frames, so the joiner's own records are skipped; the founder's are what it reads.
func advRead(t *testing.T, world *world, shadow *advShadow, pqSecret []byte, groupHandleKey []byte,
	canaries map[string]uint64) []string {

	t.Helper()
	if world.wire == nil {
		advHarness(t, "this world records no wire, so there is no submitted record to open")
	}
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		advHarness(t, "the shadow's stream store: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	session, err := messagegroup.NewGroupSession(shadow.handle, pqSecret, groupHandleKey,
		sdk.NewStreamIndexReserver(streamStore), func() int64 { return time.Now().UnixMilli() },
		[]byte("the shadow never writes, so this nonce authenticates nothing"))
	if err != nil {
		advHarness(t, "the shadow's session over the recovered secrets: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	own := messagegroup.SenderHandle(groupHandleKey, shadow.ownLeaf)
	tracked := map[string]bool{}
	read := []string{}
	opened, refused := 0, 0
	for _, octets := range advSubmittedRecords(world.wire) {
		parsed, err := message.ParseRecord(octets)
		if err != nil {
			continue
		}
		header := &parsed.Header
		if header.Epoch != shadow.epoch || header.IsCommit || len(header.ServerAttachment) != 0 {
			continue
		}
		if header.SenderHandle == own {
			continue
		}
		leaf, found := uint32(0), false
		for candidate := uint32(0); candidate < 16; candidate += 1 {
			if messagegroup.SenderHandle(groupHandleKey, candidate) == header.SenderHandle {
				leaf, found = candidate, true
				break
			}
		}
		if !found {
			continue
		}
		ladder := fmt.Sprintf("%d/%d/%d/%d", leaf, header.RetentionClass, header.EphBucket, header.EphWindow)
		if !tracked[ladder] {
			if err := session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, 0); err != nil {
				advHarness(t, "tracking leaf %d: %v", leaf, err)
			}
			tracked[ladder] = true
		}
		_, body, err := session.OpenRecord(parsed)
		if err != nil {
			refused += 1
			continue
		}
		opened += 1
		for canary, epoch := range canaries {
			if bytes.Contains(body, []byte(canary)) {
				read = append(read, fmt.Sprintf("epoch:%d", epoch))
			}
		}
	}
	t.Logf("the shadow opened %d application record(s) of epoch %d and was refused %d", opened, shadow.epoch, refused)
	return advSet(read)
}

// advSubmittedRecords is the octets of every record a client submitted through the tap, in order.
func advSubmittedRecords(tap *wireTap) [][]byte {
	tap.mutex.Lock()
	defer tap.mutex.Unlock()
	records := [][]byte{}
	for _, request := range tap.submits {
		for _, record := range request.GetRecords() {
			records = append(records, append([]byte(nil), record.GetRecordBytes()...))
		}
	}
	return records
}

// ── what a device holds of one group, as files ───────────────────────────────────────────────

// advGroupFiles is every file a durable store holds for one group, by its path under the group's
// directory. The directory is named by the SHA-256 of the group id, which is all this reads of the
// store's layout.
func advGroupFiles(t *testing.T, stateDir string, groupId []byte) map[string][]byte {
	t.Helper()
	sum := sha256.Sum256(groupId)
	name := hex.EncodeToString(sum[:])
	files := map[string][]byte{}
	err := filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(stateDir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		marker := "/" + name + "/"
		at := bytes.Index([]byte(relative), []byte(marker))
		if at < 0 {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[relative[at+len(marker):]] = content
		return nil
	})
	if err != nil {
		advHarness(t, "reading the group's files under %s: %v", stateDir, err)
	}
	return files
}

// advRemoveEpochStates removes every epoch state a durable store holds for one group, and leaves
// its record: what "the group's MLS state did not survive" is on the disk.
func advRemoveEpochStates(stateDir string, groupId []byte) error {
	sum := sha256.Sum256(groupId)
	marker := "/" + hex.EncodeToString(sum[:]) + "/epoch/"
	return filepath.WalkDir(stateDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if bytes.Contains([]byte(filepath.ToSlash(path)), []byte(marker)) {
			return os.Remove(path)
		}
		return nil
	})
}
