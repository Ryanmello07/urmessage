// The identity extensions and the checks over them (identity phase 1's plan, Task 11): Properties
// 1, 2, 3, 5, 6 and 7, the known answers, the size known answer, and Ed25519's edge vectors.
//
// THE KNOWN ANSWERS WERE NOT READ OUT OF THE CODE THEY CHECK. A script that shares no code with
// this package wrote every encoding from the plan's Task 11 and Spec A A-36, with Python's standard
// library, and signed with the OpenSSL command line, after OpenSSL reproduced RFC 8032's own
// vectors. The keys are the frozen known answers of Task 10: phrase A's IRK and ISK_1 and phrase
// B's IRK, plus a third identity key and the device keys of the seeds 01 x 32, 02 x 32, and so on.
package messagegroup

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/urnetwork/message/mls"
	"github.com/urnetwork/message/syntax"
)

// One test key: its private and public halves.
type deviceListTestKey struct {
	private ed25519.PrivateKey
	public  []byte
}

func deviceListKeyOfSeed(seed []byte) deviceListTestKey {
	private := ed25519.NewKeyFromSeed(seed)
	return deviceListTestKey{private: private, public: append([]byte(nil), private[ed25519.SeedSize:]...)}
}

func deviceListRepeatedSeed(octet byte) []byte {
	seed := make([]byte, 32)
	for at := range seed {
		seed[at] = octet
	}
	return seed
}

// The fixed keys of the known answers.
type deviceListKeys struct {
	irkA, iskA1, irkB, irkC deviceListTestKey
	devices                 map[int]deviceListTestKey
}

func deviceListFixedKeys(t *testing.T) deviceListKeys {
	t.Helper()
	keys := deviceListKeys{
		irkA:    deviceListKeyOfSeed(phraseHexOctets(t, phraseKnownAnswersFrozen["A"].irkSeed)),
		iskA1:   deviceListKeyOfSeed(phraseHexOctets(t, phraseKnownAnswersFrozen["A"].iskSeeds[1][0])),
		irkB:    deviceListKeyOfSeed(phraseHexOctets(t, phraseKnownAnswersFrozen["B"].irkSeed)),
		irkC:    deviceListKeyOfSeed(deviceListRepeatedSeed(0x0c)),
		devices: map[int]deviceListTestKey{},
	}
	for n := 1; n <= 30; n++ {
		keys.devices[n] = deviceListKeyOfSeed(deviceListRepeatedSeed(byte(n)))
	}
	return keys
}

// The known answers, from the script.
const (
	deviceListKnownIrkC          = "0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d"
	deviceListKnownCertTbs       = "000100012043c9207a8cb3a38a4b656f677de518a0f3c97c0ab005e5d9f33c428498cd940820c02125b01fb02c19cedb0fc3804d53304eb5f761e571410bc67312e72a564da400000001"
	deviceListKnownCertSignature = "ef067627b354d6f277edbaf09056d3b8c26d6113a564538503f503ce2624eb4ef6c7023496c85acd99c2d925fe3b901a828733f779d8bf417691fe852416db03"
	deviceListKnownBaseTbs       = "000100012043c9207a8cb3a38a4b656f677de518a0f3c97c0ab005e5d9f33c428498cd94080000000100000000000000010000019b76daa8000022208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c01208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
	deviceListKnownBaseAuthorSig = "74b4b1f8e18621ab3a3b0857044b48e8def0d0759f53adb788de5bad38cea79a23ca57469a69da592ecb8a8eda01590d10483741da0334b8d13036f7315a1804"
	deviceListKnownBaseSignature = "37d0835471645c708ad046a6ccc76aa0d98d607c78f4b0d7c1ba1c06f783ec078c6d72854198165f26979aa7972174ec0354fbd580f4f222078e22f03a981c04"
	deviceListKnownBaseHash      = "0e31eb696b2d7fdc3eed47cf60bb5e4a665409c94bfbd2c6c8129065176a1e39"
	deviceListKnownAdditionSig   = "191d920058ca688af757aa7b8165fc6fc74f18e6df58a897a460f3656e8aa81218479ee7a3562179d5ffb410b0f180a00342a95fabe01debbd4926d974b3ce0f"
	deviceListKnownAdditionHash  = "7662059752a6125b0ab26679b336a6446e8cf5433653d54c30a90d4f720940e6"
	deviceListKnownRemovalSig    = "0e7c925634afd07c99a1782820f7dbcf375a8a8d269b4865d001d974f2c6f8af63166537907209b3b9677d19defdc860607d11e0fbe0e263562c4fb8b3c6b60c"
	deviceListKnownRemovalHash   = "b103068bce54efaf657f0a480274f3bc5aec62418fbefac8dbed2e899d524063"
	deviceListKnownBodyOctets    = 789
	deviceListKnownBodySha256    = "cb15ea916f0e70bf7373477ac01a49947f028a2ba9c8082ce796157a2ac8c487"
	deviceListKnownStepAB        = "92196b69a6f5eb98d69afc03ffd02d57164980978136520a89cfe69f0440dc8f7a38f0d885f20f0c2657a8062f8fe6fb72079d116ecffe28ec93cd9e7874c70d"
	deviceListKnownStepBC        = "472a8fe1413904252a70309bac25f29bcd08b540c8dec7994f1e0d64fca39469aec2ec4ae2ff8f258a4997d9be55b129b0eafca94d5b1d53c752cf3890560e07"
	deviceListKnownPurposeSelfA  = "0001012043c9207a8cb3a38a4b656f677de518a0f3c97c0ab005e5d9f33c428498cd9408"
	// the largest 0xF005 I1 can make: a base of 10 devices, 8 self-removals and 8 additions in
	// turn, and 4 steps
	deviceListKnownLargestOctets = 4231
	// R68's new known answers, from the same script: phrase A's IskCert(2), and D2 IL8's derivation
	// under "inboxown/v1" over phrase A's IRK, HKDF-Expand(IRK's seed, "inboxown/v1", 32) as an
	// Ed25519 seed, its public half
	deviceListKnownCert2Signature = "9d7f5bafb73512ad00913d4be803da62ab67bdc96ef138990c3a877224a7a797a5a7a70e53bef43623505bb832b880e81b8f8717dc195305dfda386a36fd690d"
	deviceListKnownOwnerKey       = "05bcb14f6ff6cf792dc83a27bb3fa0e20feb8dd7e9d72cdb9231f80de121ea4d"
	// 2026-01-01T00:00:00Z, the known answers' issued_at_ms
	deviceListKnownIssuedAtMs uint64 = 1767225600000
)

// A test's own signer over a raw tbs, under any label, for the inputs that the production signers
// refuse to make: an 11-device base, a base out of order, a step signed by the wrong key.
func deviceListRawSign(t *testing.T, key ed25519.PrivateKey, label string, tbs []byte) []byte {
	t.Helper()
	signature, err := identitySign(key, label, tbs)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

func deviceListTbs(t *testing.T, encode func(w *syntax.Writer)) []byte {
	t.Helper()
	tbs, err := identityEncoding(encode)
	if err != nil {
		t.Fatal(err)
	}
	return tbs
}

// A base's two signatures, made raw: whatever the base holds is signed.
func deviceListRawSignBase(t *testing.T, isk ed25519.PrivateKey, author ed25519.PrivateKey, base *DeviceListBase) {
	t.Helper()
	base.AuthorKey = append([]byte(nil), author[ed25519.SeedSize:]...)
	tbs := deviceListTbs(t, func(w *syntax.Writer) { encodeBaseTbs(w, base) })
	base.AuthorSignature = deviceListRawSign(t, author, deviceListAuthorLabel, tbs)
	base.Signature = deviceListRawSign(t, isk, deviceListLabel, tbs)
}

// A base's two signatures through the two signers production has, the author's and ISK_g's, the
// base's author key set to the author's first.
func deviceListSignBase(isk ed25519.PrivateKey, author ed25519.PrivateKey, base *DeviceListBase) error {
	base.AuthorKey = append([]byte(nil), author[ed25519.SeedSize:]...)
	if err := SignBaseAuthor(base, author); err != nil {
		return err
	}
	return signBaseByPhraseKey(isk, base)
}

// An identity of one key: IskCert(g), a base of number baseNumber naming devices (the author a
// phrase device), signed, and no amendment. The chain is given; the identity key is its end.
func deviceListIdentity(t *testing.T, irk deviceListTestKey, isk deviceListTestKey, g uint32, baseNumber uint64,
	author deviceListTestKey, others []deviceListTestKey, chain []IdentityStep) *UrmessageIdentity {

	t.Helper()
	cert := IskCert{IdentityKey: irk.public, IskPub: isk.public, KeyNumber: g}
	if err := signIskCert(irk.private, &cert); err != nil {
		t.Fatal(err)
	}
	devices := []DeviceEntry{{DeviceKey: author.public, Flags: DeviceFlagPhraseDevice}}
	for _, other := range others {
		devices = append(devices, DeviceEntry{DeviceKey: other.public})
	}
	slices.SortFunc(devices, func(left DeviceEntry, right DeviceEntry) int { return compareKeys(left.DeviceKey, right.DeviceKey) })
	base := DeviceListBase{IdentityKey: irk.public, KeyNumber: g, BaseNumber: baseNumber,
		IssuedAtMs: deviceListKnownIssuedAtMs, Devices: devices}
	if err := deviceListSignBase(isk.private, author.private, &base); err != nil {
		t.Fatal(err)
	}
	return &UrmessageIdentity{IskCert: cert, Base: base, Chain: chain}
}

// identity with one more amendment.
func deviceListWith(t *testing.T, identity *UrmessageIdentity, amendment *Amendment, err error) *UrmessageIdentity {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	next := *identity
	next.Amendments = append(slices.Clone(identity.Amendments), *amendment)
	return &next
}

// identity with the one more amendment makeOne answers.
func deviceListAppend(t *testing.T, identity *UrmessageIdentity, makeOne func() (*Amendment, error)) *UrmessageIdentity {
	t.Helper()
	amendment, err := makeOne()
	return deviceListWith(t, identity, amendment, err)
}

// The leaf extensions a leaf carrying identity has, after its 0xF002.
func deviceListLeafExtensions(t *testing.T, identity *UrmessageIdentity) []ExtensionBytes {
	t.Helper()
	encoded, err := identity.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return []ExtensionBytes{{Type: uint16(mls.ExtensionTypeUrmessageLeafKeys), Data: []byte{0}}, encoded}
}

// A chain of steps through keys, each signed by the key before it.
func deviceListChain(t *testing.T, keys ...deviceListTestKey) []IdentityStep {
	t.Helper()
	chain := []IdentityStep{}
	for at := 0; at+1 < len(keys); at++ {
		step, err := signIdentityStep(keys[at].private, keys[at+1].public)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, *step)
	}
	return chain
}

func TestTheIdentityExtensionsAreTheKnownAnswers(t *testing.T) {
	keys := deviceListFixedKeys(t)
	if phraseHexText(keys.irkC.public) != deviceListKnownIrkC {
		t.Fatalf("the third identity key is %x", keys.irkC.public)
	}
	identity := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], nil, nil)
	certTbs := deviceListTbs(t, func(w *syntax.Writer) { encodeIskCertTbs(w, &identity.IskCert) })
	baseTbs := deviceListTbs(t, func(w *syntax.Writer) { encodeBaseTbs(w, &identity.Base) })
	baseHash, err := deviceListBaseHash(&identity.Base)
	if err != nil {
		t.Fatal(err)
	}
	identity = deviceListAppend(t, identity, func() (*Amendment, error) {
		return NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[2].public}, keys.devices[1].private, deviceListKnownIssuedAtMs+60000)
	})
	addition := identity.Amendments[0]
	identity = deviceListAppend(t, identity, func() (*Amendment, error) {
		return NewSelfRemoval(identity, keys.devices[2].private, deviceListKnownIssuedAtMs+120000)
	})
	removal := identity.Amendments[1]
	additionHash, _ := amendmentHash(&addition)
	removalHash, _ := amendmentHash(&removal)
	body, err := identity.Encode()
	if err != nil {
		t.Fatal(err)
	}
	bodyHash := sha256.Sum256(body.Data)
	for _, pair := range [][3]string{
		{"IskCert(1)'s tbs", phraseHexText(certTbs), deviceListKnownCertTbs},
		{"IskCert(1)'s signature", phraseHexText(identity.IskCert.Signature), deviceListKnownCertSignature},
		{"base 1's tbs", phraseHexText(baseTbs), deviceListKnownBaseTbs},
		{"base 1's author signature", phraseHexText(identity.Base.AuthorSignature), deviceListKnownBaseAuthorSig},
		{"base 1's signature", phraseHexText(identity.Base.Signature), deviceListKnownBaseSignature},
		{"base 1's hash", phraseHexText(baseHash[:]), deviceListKnownBaseHash},
		{"the addition's signature", phraseHexText(addition.Signature), deviceListKnownAdditionSig},
		{"the addition's hash", phraseHexText(additionHash[:]), deviceListKnownAdditionHash},
		{"the self-removal's signature", phraseHexText(removal.Signature), deviceListKnownRemovalSig},
		{"the self-removal's hash", phraseHexText(removalHash[:]), deviceListKnownRemovalHash},
		{"the 0xF005 body's SHA-256", phraseHexText(bodyHash[:]), deviceListKnownBodySha256},
	} {
		if pair[1] != pair[2] {
			t.Errorf("%s is %s, want %s", pair[0], pair[1], pair[2])
		}
	}
	if len(body.Data) != deviceListKnownBodyOctets || body.Type != 0xF005 {
		t.Errorf("the 0xF005 body is %d octets under type %#04x, want %d under 0xf005", len(body.Data), body.Type, deviceListKnownBodyOctets)
	}
	// it reads back to itself, and binds a leaf of device 1
	parsed, err := ParseUrmessageIdentity(body)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := parsed.Encode()
	if string(again.Data) != string(body.Data) {
		t.Error("the 0xF005 body does not read back to itself")
	}
	verified, err := VerifyLeafBinding(keys.irkA.public, keys.devices[1].public, []ExtensionBytes{body})
	if err != nil {
		t.Fatalf("the known body does not bind device 1's leaf: %v", err)
	}
	if verified.Version != (ListVersion{Step: 0, KeyNumber: 1, Base: 1, Count: 2}) || len(verified.Devices) != 1 ||
		!sameOctets(verified.Root, keys.irkA.public) {
		t.Errorf("the binding answered version %+v over %d devices", verified.Version, len(verified.Devices))
	}
	// 0xF006
	purpose := GroupPurpose{Purpose: GroupPurposeSelf, IdentityRoot: keys.irkA.public}
	encoded, err := purpose.Encode()
	if err != nil || phraseHexText(encoded.Data) != deviceListKnownPurposeSelfA || encoded.Type != 0xF006 {
		t.Errorf("0xF006 over IRK A is %x under %#04x, %v; want %s", encoded.Data, encoded.Type, err, deviceListKnownPurposeSelfA)
	}
	if read, err := ParseGroupPurpose(encoded); err != nil || read.Purpose != GroupPurposeSelf || !sameOctets(read.IdentityRoot, keys.irkA.public) {
		t.Errorf("0xF006 reads back as %+v, %v", read, err)
	}
	for _, bad := range []GroupPurpose{{Purpose: 3, IdentityRoot: keys.irkA.public}, {Purpose: GroupPurposeLink, IdentityRoot: keys.irkA.public[:31]}} {
		if _, err := bad.Encode(); !errors.Is(err, ErrGroupPurposeEncoding) {
			t.Errorf("0xF006 %+v encodes: %v", bad, err)
		}
	}
}

// THE SIZE KNOWN ANSWER (PLAN Task 11, Step 3): the largest 0xF005 I1 can make -- a base of 10
// devices, 16 amendments that never take the list past 10, and a chain of 4 steps -- and that a
// two-member link invitation carrying it fits the link deposit's M bucket. T1 measured a
// two-member invitation of version 3 at 4,667 octets (T1 section 2.1) with no 0xF005 in it; the
// existing device's leaf adds its 0xF005 to the ratchet tree once. The deposit holds u32(len) and
// the invitation in 16,384 octets (Spec A A-36, the link box), so it fits even counted twice.
func TestTheLargestIdentityExtensionIsTheKnownSizeAndFitsTheLinkDeposit(t *testing.T) {
	keys := deviceListFixedKeys(t)
	others := []deviceListTestKey{}
	for n := 2; n <= 10; n++ {
		others = append(others, keys.devices[n])
	}
	chainKeys := []deviceListTestKey{keys.devices[21], keys.devices[22], keys.devices[23], keys.devices[24], keys.irkA}
	identity := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], others, deviceListChain(t, chainKeys...))
	identity.Base.PrevHash = make([]byte, 32)
	if err := deviceListSignBase(keys.iskA1.private, keys.devices[1].private, &identity.Base); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 8; round++ {
		leaving, joining := keys.devices[2+round], keys.devices[11+round]
		identity = deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewSelfRemoval(identity, leaving.private, deviceListKnownIssuedAtMs)
		})
		identity = deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewAddition(identity, DeviceEntry{DeviceKey: joining.public}, keys.devices[1].private, deviceListKnownIssuedAtMs)
		})
	}
	body, err := identity.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != deviceListKnownLargestOctets {
		t.Errorf("the largest 0xF005 is %d octets, want the known %d", len(body.Data), deviceListKnownLargestOctets)
	}
	if IdentityExtensionMaxOctets < len(body.Data) {
		t.Errorf("the largest 0xF005, %d octets, is over the bound %d", len(body.Data), IdentityExtensionMaxOctets)
	}
	if _, err := VerifyLeafBinding(keys.irkA.public, keys.devices[1].public, []ExtensionBytes{body}); err != nil {
		t.Errorf("the largest 0xF005 does not bind: %v", err)
	}
	const twoMemberInviteV3, depositPlaintext, lengthPrefix = 4667, 16384, 4
	if depositPlaintext < lengthPrefix+twoMemberInviteV3+2*len(body.Data) {
		t.Errorf("a two-member link invitation carrying it twice is %d octets, over the deposit's %d",
			lengthPrefix+twoMemberInviteV3+2*len(body.Data), depositPlaintext)
	}
}

// Property 1: each refusal step of the leaf binding is reached by an input that fails at it and
// passes every step before it -- each answers its own step's sentinel, and the steps run in order.
func TestEveryRefusalStepOfTheLeafBindingIsReached(t *testing.T) {
	keys := deviceListFixedKeys(t)
	irk, isk, device1, device2 := keys.irkA, keys.iskA1, keys.devices[1], keys.devices[2]
	fresh := func() *UrmessageIdentity {
		return deviceListIdentity(t, irk, isk, 1, 1, device1, []deviceListTestKey{device2}, nil)
	}
	bind := func(identity *UrmessageIdentity, credential []byte, signatureKey []byte) error {
		_, err := VerifyLeafBinding(credential, signatureKey, deviceListLeafExtensions(t, identity))
		return err
	}
	// the control: a leaf every step passes
	if err := bind(fresh(), irk.public, device2.public); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	cases := []struct {
		name  string
		want  error
		check func() error
	}{
		{"1: no 0xF005", ErrBindingExtension, func() error {
			_, err := VerifyLeafBinding(irk.public, device1.public, []ExtensionBytes{{Type: uint16(mls.ExtensionTypeUrmessageLeafKeys)}})
			return err
		}},
		{"1: 0xF005 twice", ErrBindingExtension, func() error {
			extensions := deviceListLeafExtensions(t, fresh())
			_, err := VerifyLeafBinding(irk.public, device1.public, append(extensions, extensions[1]))
			return err
		}},
		{"1: over 6,144 octets", ErrBindingExtension, func() error {
			extensions := deviceListLeafExtensions(t, fresh())
			extensions[1].Data = append(extensions[1].Data, make([]byte, IdentityExtensionMaxOctets)...)
			_, err := VerifyLeafBinding(irk.public, device1.public, extensions)
			return err
		}},
		{"1: a trailing octet", ErrBindingExtension, func() error {
			extensions := deviceListLeafExtensions(t, fresh())
			extensions[1].Data = append(extensions[1].Data, 0)
			_, err := VerifyLeafBinding(irk.public, device1.public, extensions)
			return err
		}},
		{"2: the certificate is another key's", ErrBindingCertificate, func() error {
			return bind(fresh(), keys.irkB.public, device1.public)
		}},
		{"2: the certificate's signature", ErrBindingCertificate, func() error {
			identity := fresh()
			identity.IskCert.Signature[0] ^= 1
			return bind(identity, irk.public, device1.public)
		}},
		{"3: a chain that does not end at the key", ErrBindingChain, func() error {
			identity := fresh()
			identity.Chain = deviceListChain(t, keys.irkB, keys.irkC)
			return bind(identity, irk.public, device1.public)
		}},
		{"4: the base signed by another key than ISK_g", ErrBindingList, func() error {
			identity := fresh()
			deviceListRawSignBase(t, keys.irkC.private, device1.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"4: the author's signature", ErrBindingList, func() error {
			identity := fresh()
			identity.Base.AuthorSignature[0] ^= 1
			return bind(identity, irk.public, device1.public)
		}},
		{"4: an author the base does not name as a phrase device", ErrBindingList, func() error {
			identity := fresh()
			deviceListRawSignBase(t, isk.private, device2.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"4: another key number in the base", ErrBindingList, func() error {
			identity := fresh()
			identity.Base.KeyNumber = 2
			deviceListRawSignBase(t, isk.private, device1.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"4: an amendment by a device the list does not name", ErrBindingList, func() error {
			identity := fresh()
			amendment, err := NewSelfRemoval(identity, device1.private, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := SignAmendment(amendment, keys.devices[3].private); err != nil {
				t.Fatal(err)
			}
			return bind(deviceListWith(t, identity, amendment, nil), irk.public, device1.public)
		}},
		{"4: an amendment's signature", ErrBindingList, func() error {
			identity := fresh()
			identity = deviceListAppend(t, identity, func() (*Amendment, error) {
				return NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[3].public}, device1.private, 0)
			})
			identity.Amendments[0].Signature[0] ^= 1
			return bind(identity, irk.public, device1.public)
		}},
		{"5: eleven devices", ErrBindingWellFormed, func() error {
			identity := fresh()
			for n := 3; n <= 11; n++ {
				identity.Base.Devices = append(identity.Base.Devices, DeviceEntry{DeviceKey: keys.devices[n].public})
			}
			slices.SortFunc(identity.Base.Devices, func(l DeviceEntry, r DeviceEntry) int { return compareKeys(l.DeviceKey, r.DeviceKey) })
			deviceListRawSignBase(t, isk.private, device1.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"5: out of order", ErrBindingWellFormed, func() error {
			identity := fresh()
			slices.Reverse(identity.Base.Devices)
			deviceListRawSignBase(t, isk.private, device1.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"5: an unknown flag", ErrBindingWellFormed, func() error {
			identity := fresh()
			for at := range identity.Base.Devices {
				if sameOctets(identity.Base.Devices[at].DeviceKey, device2.public) {
					identity.Base.Devices[at].Flags = 0x04
				}
			}
			deviceListRawSignBase(t, isk.private, device1.private, &identity.Base)
			return bind(identity, irk.public, device1.public)
		}},
		{"5: an addition of a device listed already", ErrBindingWellFormed, func() error {
			identity := fresh()
			amendment, err := NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[3].public}, device1.private, 0)
			if err != nil {
				t.Fatal(err)
			}
			amendment.Entry.DeviceKey = device2.public
			if err := SignAmendment(amendment, device1.private); err != nil {
				t.Fatal(err)
			}
			return bind(deviceListWith(t, identity, amendment, nil), irk.public, device1.public)
		}},
		{"6: a signature key the list does not name", ErrBindingSignatureKey, func() error {
			return bind(fresh(), irk.public, keys.devices[3].public)
		}},
		{"7: the phrase key is the identity key", ErrBindingKeyReuse, func() error {
			identity := deviceListIdentity(t, irk, irk, 1, 1, device1, []deviceListTestKey{device2}, nil)
			return bind(identity, irk.public, device1.public)
		}},
		{"7: the signature key is the identity key", ErrBindingKeyReuse, func() error {
			identity := deviceListIdentity(t, irk, isk, 1, 1, device1, []deviceListTestKey{irk}, nil)
			return bind(identity, irk.public, irk.public)
		}},
	}
	steps := []error{ErrBindingExtension, ErrBindingCertificate, ErrBindingChain, ErrBindingList,
		ErrBindingWellFormed, ErrBindingSignatureKey, ErrBindingKeyReuse}
	reached := map[error]bool{}
	for _, refusal := range cases {
		err := refusal.check()
		if !errors.Is(err, refusal.want) {
			t.Errorf("%s: the binding answers %v, want step %v", refusal.name, err, refusal.want)
			continue
		}
		for _, other := range steps {
			if other != refusal.want && errors.Is(err, other) {
				t.Errorf("%s: the refusal also matches %v", refusal.name, other)
			}
		}
		reached[refusal.want] = true
	}
	for _, step := range steps {
		if !reached[step] {
			t.Errorf("no input reached %v", step)
		}
	}
}

// Property 2: a higher key number retires every list under a lower one, whatever the base numbers;
// and under one key number a higher base retires a lower one.
func TestAHigherKeyNumberRetiresEveryListUnderALowerOne(t *testing.T) {
	keys := deviceListFixedKeys(t)
	iskA2 := deviceListKeyOfSeed(phraseHexOctets(t, phraseKnownAnswersFrozen["A"].iskSeeds[2][0]))
	underOne := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 9, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	underOne = deviceListAppend(t, underOne, func() (*Amendment, error) {
		return NewAddition(underOne, DeviceEntry{DeviceKey: keys.devices[3].public}, keys.devices[1].private, 0)
	})
	underTwo := deviceListIdentity(t, keys.irkA, iskA2, 2, 1, keys.devices[1], nil, nil)
	if order, err := VerifyDeviceList(underOne, underTwo); err != nil || order != ListNewer {
		t.Errorf("key number 2, base 1 against key number 1, base 9: %v, %v; want newer", order, err)
	}
	if order, err := VerifyDeviceList(underTwo, underOne); err != nil || order != ListOlder {
		t.Errorf("key number 1, base 9 against key number 2, base 1: %v, %v; want older", order, err)
	}
	baseTen := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 10, keys.devices[1], nil, nil)
	if order, err := VerifyDeviceList(underOne, baseTen); err != nil || order != ListNewer {
		t.Errorf("base 10 against base 9 with an amendment: %v, %v; want newer", order, err)
	}
	if order, err := VerifyDeviceList(underOne, underOne); err != nil || order != ListSame {
		t.Errorf("a list against itself: %v, %v", order, err)
	}
	if (ListVersion{KeyNumber: 2, Base: 1}).Compare(ListVersion{KeyNumber: 1, Base: 9, Count: 16}) != 1 {
		t.Error("ListVersion orders the base number before the key number")
	}
}

// Property 2: on one base a chain of amendments only extends; anything else is a fork, a longer
// chain that leaves a change out included.
func TestOnOneBaseAChainOnlyExtendsAndAnythingElseIsAFork(t *testing.T) {
	keys := deviceListFixedKeys(t)
	base := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	add := func(identity *UrmessageIdentity, n int) *UrmessageIdentity {
		return deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[n].public}, keys.devices[1].private, 0)
		})
	}
	one := add(base, 3)
	stored := add(one, 4)
	for _, candidate := range []struct {
		name  string
		list  *UrmessageIdentity
		order ListOrder
		fork  bool
	}{
		{"the same list", stored, ListSame, false},
		{"one more change", add(stored, 5), ListNewer, false},
		{"one change fewer", one, ListOlder, false},
		{"the base alone", base, ListOlder, false},
		{"a second change that is another", add(one, 5), ListSame, true},
		{"a longer chain that leaves the second change out", add(add(one, 5), 6), ListSame, true},
	} {
		order, err := VerifyDeviceList(stored, candidate.list)
		switch {
		case candidate.fork && !errors.Is(err, ErrDeviceListFork):
			t.Errorf("%s: %v, %v; want a fork", candidate.name, order, err)
		case !candidate.fork && (err != nil || order != candidate.order):
			t.Errorf("%s: %v, %v; want %v", candidate.name, order, err, candidate.order)
		}
	}
}

// Property 2: two lists of one identity at one version with different octets are a fork.
func TestEqualListVersionsWithDifferentOctetsAreAFork(t *testing.T) {
	keys := deviceListFixedKeys(t)
	first := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 3, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	second := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 3, keys.devices[1], []deviceListTestKey{keys.devices[3]}, nil)
	if first.Version() != second.Version() {
		t.Fatalf("the two lists are at %+v and %+v", first.Version(), second.Version())
	}
	if _, err := VerifyDeviceList(first, second); !errors.Is(err, ErrDeviceListFork) {
		t.Errorf("two bases of one number with different devices: %v, want a fork", err)
	}
	timed := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 3, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	timed.Base.IssuedAtMs++
	if err := deviceListSignBase(keys.iskA1.private, keys.devices[1].private, &timed.Base); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDeviceList(first, timed); !errors.Is(err, ErrDeviceListFork) {
		t.Errorf("two bases of one number one millisecond apart: %v, want a fork", err)
	}
	withA := deviceListAppend(t, first, func() (*Amendment, error) {
		return NewAddition(first, DeviceEntry{DeviceKey: keys.devices[4].public}, keys.devices[1].private, 0)
	})
	withB := deviceListAppend(t, first, func() (*Amendment, error) {
		return NewAddition(first, DeviceEntry{DeviceKey: keys.devices[5].public}, keys.devices[1].private, 0)
	})
	if _, err := VerifyDeviceList(withA, withB); !errors.Is(err, ErrDeviceListFork) {
		t.Errorf("one base, one count, two additions: %v, want a fork", err)
	}
	// two certificates of one key number: the identity key signs two phrase keys for g = 1
	otherCert := deviceListIdentity(t, keys.irkA, keys.devices[29], 1, 3, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	if _, err := VerifyDeviceList(first, otherCert); !errors.Is(err, ErrDeviceListFork) {
		t.Errorf("two certificates of key number 1: %v, want a fork", err)
	}
}

// Property 3: a list of 11 devices, or one with 17 amendments, can be neither signed nor verified.
func TestTheListHoldsTenDevicesAndSixteenChangesAndNoMore(t *testing.T) {
	keys := deviceListFixedKeys(t)
	nine := []deviceListTestKey{}
	for n := 2; n <= 10; n++ {
		nine = append(nine, keys.devices[n])
	}
	full := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], nine, nil)
	if _, err := VerifyLeafBinding(keys.irkA.public, keys.devices[10].public, deviceListLeafExtensions(t, full)); err != nil {
		t.Fatalf("a list of 10 devices does not bind: %v", err)
	}
	// eleven devices: the signer refuses, and so does the binding when the test signs it raw
	eleven := full.Base
	eleven.Devices = append(slices.Clone(full.Base.Devices), DeviceEntry{DeviceKey: keys.devices[11].public})
	slices.SortFunc(eleven.Devices, func(l DeviceEntry, r DeviceEntry) int { return compareKeys(l.DeviceKey, r.DeviceKey) })
	eleven.AuthorKey = append([]byte(nil), keys.devices[1].public...)
	if err := SignBaseAuthor(&eleven, keys.devices[1].private); !errors.Is(err, ErrDeviceListShape) {
		t.Errorf("a base of 11 devices was signed by its author: %v", err)
	}
	if err := signBaseByPhraseKey(keys.iskA1.private, &eleven); !errors.Is(err, ErrDeviceListShape) {
		t.Errorf("a base of 11 devices was signed by ISK_g: %v", err)
	}
	deviceListRawSignBase(t, keys.iskA1.private, keys.devices[1].private, &eleven)
	if _, err := VerifyLeafBinding(keys.irkA.public, keys.devices[1].public,
		deviceListLeafExtensions(t, &UrmessageIdentity{IskCert: full.IskCert, Base: eleven})); !errors.Is(err, ErrBindingWellFormed) {
		t.Errorf("a base of 11 devices binds: %v", err)
	}
	if _, err := NewAddition(full, DeviceEntry{DeviceKey: keys.devices[11].public}, keys.devices[1].private, 0); !errors.Is(err, ErrDeviceListFull) {
		t.Errorf("an eleventh device was added: %v", err)
	}
	// sixteen changes, then no seventeenth
	identity := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	for n := 3; len(identity.Amendments) < DeviceListMaxAmendments; n++ {
		identity = deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[n].public}, keys.devices[1].private, 0)
		})
		if len(identity.Amendments) < DeviceListMaxAmendments {
			identity = deviceListAppend(t, identity, func() (*Amendment, error) {
				return NewSelfRemoval(identity, keys.devices[n].private, 0)
			})
		}
	}
	if _, err := VerifyLeafBinding(keys.irkA.public, keys.devices[1].public, deviceListLeafExtensions(t, identity)); err != nil {
		t.Fatalf("a list with 16 changes does not bind: %v", err)
	}
	if _, err := NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[20].public}, keys.devices[1].private, 0); !errors.Is(err, ErrDeviceListFull) {
		t.Errorf("a seventeenth change was made: %v", err)
	}
	seventeen, err := NewSelfRemoval(identity, keys.devices[2].private, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyLeafBinding(keys.irkA.public, keys.devices[1].public,
		deviceListLeafExtensions(t, deviceListWith(t, identity, seventeen, nil))); !errors.Is(err, ErrBindingWellFormed) {
		t.Errorf("a list with 17 changes binds: %v", err)
	}
}

// Property 3: a self-removal is never refused for want of a place (M5 TR12). With 16 changes
// waiting it is still made and signed, as the 17th, and waits for the next base.
func TestASelfRemovalIsNeverRefusedForWantOfAPlace(t *testing.T) {
	keys := deviceListFixedKeys(t)
	identity := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	for n := 3; len(identity.Amendments) < DeviceListMaxAmendments; n++ {
		identity = deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[n].public}, keys.devices[1].private, 0)
		})
		identity = deviceListAppend(t, identity, func() (*Amendment, error) {
			return NewSelfRemoval(identity, keys.devices[n].private, 0)
		})
	}
	if _, err := NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[25].public}, keys.devices[1].private, 0); !errors.Is(err, ErrDeviceListFull) {
		t.Errorf("an addition found a place among 16 waiting changes: %v", err)
	}
	removal, err := NewSelfRemoval(identity, keys.devices[2].private, 0)
	if err != nil {
		t.Fatalf("a self-removal was refused while 16 changes wait: %v", err)
	}
	last, _ := amendmentHash(&identity.Amendments[len(identity.Amendments)-1])
	tbs := deviceListTbs(t, func(w *syntax.Writer) { encodeAmendmentTbs(w, removal) })
	if removal.Index != 17 || !sameOctets(removal.PrevHash[:], last[:]) || removal.Op != AmendmentSelfRemoval ||
		!identityVerify(keys.devices[2].public, deviceAmendmentLabel, tbs, removal.Signature) {
		t.Errorf("the waiting self-removal is index %d, op %d, and its place or signature does not hold", removal.Index, removal.Op)
	}
	// it is refused only for the reasons that are not a place: an author the list does not name
	if _, err := NewSelfRemoval(identity, keys.devices[29].private, 0); !errors.Is(err, ErrDeviceListShape) {
		t.Errorf("a stranger's self-removal: %v", err)
	}
}

// Property 7: the device key signs in two domains that never meet (Task 2's T2-M1). Every list and
// amendment preimage is LP(its label) ‖ tbs, so it begins with 0x00 and is never an MLS
// SignContent, which begins with the varint length of "MLS 1.0 " and a label. A known answer both
// ways: the device key's signatures over the known base and amendment are the script's, and a
// signature in either domain verifies in neither other.
func TestADeviceKeySignsTwoDomainsThatNeverMeet(t *testing.T) {
	keys := deviceListFixedKeys(t)
	identity := deviceListIdentity(t, keys.irkA, keys.iskA1, 1, 1, keys.devices[1], nil, nil)
	if phraseHexText(identity.Base.AuthorSignature) != deviceListKnownBaseAuthorSig {
		t.Errorf("device 1's author signature over base 1 is %x, want %s", identity.Base.AuthorSignature, deviceListKnownBaseAuthorSig)
	}
	addition, err := NewAddition(identity, DeviceEntry{DeviceKey: keys.devices[2].public}, keys.devices[1].private, deviceListKnownIssuedAtMs+60000)
	if err != nil {
		t.Fatal(err)
	}
	if phraseHexText(addition.Signature) != deviceListKnownAdditionSig {
		t.Errorf("device 1's signature over the addition is %x, want %s", addition.Signature, deviceListKnownAdditionSig)
	}
	baseTbs := deviceListTbs(t, func(w *syntax.Writer) { encodeBaseTbs(w, &identity.Base) })
	for _, label := range []string{iskCertLabel, deviceListLabel, deviceListAuthorLabel, deviceAmendmentLabel, identitySuccessionLabel} {
		preimage, err := identityPreimage(label, baseTbs)
		if err != nil || preimage[0] != 0x00 {
			t.Errorf("the %s preimage begins with %#02x, %v", label, preimage[0], err)
		}
		// the bare tbs is not the preimage: a signature over it does not verify under the label
		bare := ed25519.Sign(keys.devices[1].private, baseTbs)
		if identityVerify(keys.devices[1].public, label, baseTbs, bare) {
			t.Errorf("a signature over the bare tbs verifies under %s", label)
		}
	}
	// MLS's side: a SignWithLabel of the same octets by the same key is no list signature, and no
	// list signature is an MLS one
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	devicePrivate := mls.SignaturePrivateKey(keys.devices[1].private.Seed())
	for _, mlsLabel := range []string{"LeafNodeTBS", "KeyPackageTBS", "FramedContentTBS"} {
		mlsSignature, err := crypto.SignWithLabel(devicePrivate, mlsLabel, baseTbs)
		if err != nil {
			t.Fatal(err)
		}
		if identityVerify(keys.devices[1].public, deviceListAuthorLabel, baseTbs, mlsSignature) {
			t.Errorf("an MLS %s signature verifies as a list author's", mlsLabel)
		}
		if crypto.VerifyWithLabel(mls.SignaturePublicKey(keys.devices[1].public), mlsLabel, baseTbs, identity.Base.AuthorSignature) == nil {
			t.Errorf("a list author's signature verifies as an MLS %s", mlsLabel)
		}
		content := syntax.NewWriter()
		content.WriteOpaque([]byte("MLS 1.0 " + mlsLabel))
		prefix, _ := content.Bytes()
		if prefix[0] == 0x00 {
			t.Errorf("MLS's SignContent for %s begins with 0x00", mlsLabel)
		}
	}
}

// Property 5, and the known answers for one step and for a chain of two: every step of the chain
// is signed by the key before it, from the root to the key.
func TestEveryStepOfTheChainIsSignedByTheKeyBeforeIt(t *testing.T) {
	keys := deviceListFixedKeys(t)
	a, b, c := keys.irkA, keys.irkB, keys.irkC
	chain := deviceListChain(t, a, b, c)
	if phraseHexText(chain[0].Signature) != deviceListKnownStepAB || phraseHexText(chain[1].Signature) != deviceListKnownStepBC {
		t.Errorf("the steps A to B and B to C are signed %x and %x, want the known answers", chain[0].Signature, chain[1].Signature)
	}
	if err := VerifyIdentityChain(a.public, chain, c.public); err != nil {
		t.Errorf("the chain A, B, C does not verify: %v", err)
	}
	if err := VerifyIdentityChain(a.public, chain[:1], b.public); err != nil {
		t.Errorf("the step A to B does not verify: %v", err)
	}
	if err := VerifyIdentityChain(a.public, nil, a.public); err != nil {
		t.Errorf("an empty chain from A to A does not verify: %v", err)
	}
	// a step signed by the key it names as next: B signs its own succession from A
	selfSigned := IdentityStep{OldKey: a.public, Form: IdentityStepForm1,
		Signature: deviceListRawSign(t, b.private, identitySuccessionLabel, func() []byte { tbs, _ := identityStepTbs(b.public); return tbs }())}
	foreign := IdentityStep{OldKey: a.public, Form: IdentityStepForm1,
		Signature: deviceListRawSign(t, keys.devices[7].private, identitySuccessionLabel, func() []byte { tbs, _ := identityStepTbs(b.public); return tbs }())}
	for _, refused := range []struct {
		name  string
		root  []byte
		chain []IdentityStep
		key   []byte
	}{
		{"a step signed by its next key", a.public, []IdentityStep{selfSigned}, b.public},
		{"a step signed by a stranger", a.public, []IdentityStep{foreign}, b.public},
		{"a chain from another root", b.public, chain, c.public},
		{"a chain to another key", a.public, chain, keys.devices[8].public},
		{"an empty chain between two keys", a.public, nil, b.public},
		{"a chain that returns to its root", a.public, deviceListChain(t, a, b, a), a.public},
		{"five steps", a.public, deviceListChain(t, a, b, c, keys.devices[11], keys.devices[14], keys.devices[15]), keys.devices[15].public},
		{"the steps swapped", a.public, []IdentityStep{chain[1], chain[0]}, c.public},
	} {
		if err := VerifyIdentityChain(refused.root, refused.chain, refused.key); !errors.Is(err, ErrIdentityChain) {
			t.Errorf("%s: %v, want a refusal", refused.name, err)
		}
	}
	// four steps is the bound, and verifies
	if err := VerifyIdentityChain(a.public, deviceListChain(t, a, b, c, keys.devices[11], keys.devices[14]), keys.devices[14].public); err != nil {
		t.Errorf("a chain of four steps does not verify: %v", err)
	}
}

// Property 5: a form-2 step is refused, D2 VID2's rejected design, by the pure check and in a leaf.
func TestAFormTwoStepIsRefused(t *testing.T) {
	keys := deviceListFixedKeys(t)
	chain := deviceListChain(t, keys.irkA, keys.irkB)
	chain[0].Form = 2
	if err := VerifyIdentityChain(keys.irkA.public, chain, keys.irkB.public); !errors.Is(err, ErrIdentityStepForm) {
		t.Errorf("a form-2 step with a good signature: %v, want ErrIdentityStepForm", err)
	}
	identity := deviceListIdentity(t, keys.irkB, keys.iskA1, 1, 1, keys.devices[1], nil, chain)
	body, err := identity.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseUrmessageIdentity(body); !errors.Is(err, ErrIdentityStepForm) {
		t.Errorf("a 0xF005 body with a form-2 step reads: %v", err)
	}
	if _, err := VerifyLeafBinding(keys.irkB.public, keys.devices[1].public, []ExtensionBytes{body}); !errors.Is(err, ErrBindingExtension) {
		t.Errorf("a leaf with a form-2 step binds: %v", err)
	}
}

// Property 6: a list under a later key of one root's chain is newer than every list under an
// earlier key, whatever their key numbers, and two chains that part at one step are a fork.
func TestALaterKeyOfTheChainIsNewerAndAPartedChainIsAFork(t *testing.T) {
	keys := deviceListFixedKeys(t)
	underRoot := deviceListIdentity(t, keys.irkA, keys.iskA1, 3, 7, keys.devices[1], []deviceListTestKey{keys.devices[2]}, nil)
	underB := deviceListIdentity(t, keys.irkB, keys.devices[26], 1, 1, keys.devices[1], nil, deviceListChain(t, keys.irkA, keys.irkB))
	underC := deviceListIdentity(t, keys.irkC, keys.devices[27], 1, 1, keys.devices[1], nil, deviceListChain(t, keys.irkA, keys.irkB, keys.irkC))
	partedB := deviceListIdentity(t, keys.devices[28], keys.devices[26], 1, 1, keys.devices[1], nil, deviceListChain(t, keys.irkA, keys.devices[28]))
	partedAfterB := deviceListIdentity(t, keys.devices[30], keys.devices[27], 1, 1, keys.devices[1], nil, deviceListChain(t, keys.irkA, keys.irkB, keys.devices[30]))
	for _, pair := range []struct {
		name              string
		stored, candidate *UrmessageIdentity
		order             ListOrder
		fork              bool
	}{
		{"key B, number 1, against the root's number 3", underRoot, underB, ListNewer, false},
		{"the root's number 3 against key B", underB, underRoot, ListOlder, false},
		{"key C against key B", underB, underC, ListNewer, false},
		{"key C against the root", underRoot, underC, ListNewer, false},
		{"a chain that parts at its first step", underB, partedB, ListSame, true},
		{"a chain that parts at its second step", underC, partedAfterB, ListSame, true},
	} {
		order, err := VerifyDeviceList(pair.stored, pair.candidate)
		switch {
		case pair.fork && !errors.Is(err, ErrDeviceListFork):
			t.Errorf("%s: %v, %v; want a fork", pair.name, order, err)
		case !pair.fork && (err != nil || order != pair.order):
			t.Errorf("%s: %v, %v; want %v", pair.name, order, err, pair.order)
		}
	}
	other := deviceListIdentity(t, keys.irkB, keys.iskA1, 1, 1, keys.devices[1], nil, nil)
	if _, err := VerifyDeviceList(underRoot, other); !errors.Is(err, ErrDeviceListRoot) {
		t.Errorf("two roots: %v, want ErrDeviceListRoot", err)
	}
	if (ListVersion{Step: 1, KeyNumber: 1, Base: 1}).Compare(ListVersion{Step: 0, KeyNumber: 3, Base: 7}) != 1 {
		t.Error("ListVersion orders the key number before the chain's step")
	}
}

// F1's Ed25519 edge vectors (F1:451). crypto/ed25519 refuses a non-canonical S and accepts a
// forgery under a key of small order; so every key of this file is refused when it is of small
// order, and the set refused is derived here from the curve.
func TestTheEdgeVectorsOfEd25519AreRefused(t *testing.T) {
	// the set of small-order encodings, derived: y = 0, 1, p-1, the two y of the order-8 points,
	// and the non-canonical p and p+1
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	d := new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p)), p)
	sqrt := func(value *big.Int) *big.Int {
		root := new(big.Int).Exp(value, new(big.Int).Div(new(big.Int).Add(p, big.NewInt(3)), big.NewInt(8)), p)
		if new(big.Int).Mod(new(big.Int).Mul(root, root), p).Cmp(new(big.Int).Mod(value, p)) != 0 {
			i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(4)), p)
			root.Mod(root.Mul(root, i), p)
		}
		if new(big.Int).Mod(new(big.Int).Mul(root, root), p).Cmp(new(big.Int).Mod(value, p)) != 0 {
			return nil
		}
		return root
	}
	// the order-8 points: y^2 = (-1 +- sqrt(1 + d)) / d, the root that is a square
	s := sqrt(new(big.Int).Add(d, big.NewInt(1)))
	if s == nil {
		t.Fatal("1 + d has no square root")
	}
	ys := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Set(p), new(big.Int).Add(p, big.NewInt(1))}
	inverseD := new(big.Int).ModInverse(d, p)
	for _, sign := range []int64{1, -1} {
		ySquared := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(big.NewInt(-1), new(big.Int).Mul(big.NewInt(sign), s)), inverseD), p)
		if y := sqrt(ySquared); y != nil {
			ys = append(ys, y, new(big.Int).Sub(p, y))
		}
	}
	derived := map[string]bool{}
	for _, y := range ys {
		encoded := make([]byte, 32)
		y.FillBytes(encoded)
		slices.Reverse(encoded)
		derived[string(encoded)] = true
	}
	listed := map[string]bool{}
	for _, small := range ed25519SmallOrderEncodings {
		listed[string(small[:])] = true
	}
	if len(derived) != 7 || len(listed) != 7 {
		t.Fatalf("%d small-order encodings derived and %d listed, want 7 and 7", len(derived), len(listed))
	}
	for encoding := range derived {
		if !listed[encoding] {
			t.Errorf("the small-order encoding %x is derived and not listed", encoding)
		}
	}
	// each is refused with either sign bit, and under each the forgery crypto/ed25519 accepts is
	// found: S = 0 and R one of these points
	message := []byte("URmessage edge vector")
	for _, small := range ed25519SmallOrderEncodings {
		for _, signBit := range []byte{0, 0x80} {
			key := small
			key[31] |= signBit
			if ed25519KeyIsUsable(key[:]) {
				t.Errorf("the small-order key %x is usable", key)
			}
		}
	}
	identity := ed25519SmallOrderEncodings[1]
	forged := append(append([]byte(nil), identity[:]...), make([]byte, 32)...)
	if !ed25519.Verify(ed25519.PublicKey(identity[:]), message, forged) {
		t.Error("crypto/ed25519 refuses the forgery under the neutral point: this refusal list may have stopped being needed")
	}
	if identityVerify(identity[:], deviceListLabel, message, forged) {
		t.Error("the forgery under the neutral point verifies here")
	}
	// a non-canonical S, S + L, is refused by both
	keys := deviceListFixedKeys(t)
	signature := ed25519.Sign(keys.devices[1].private, message)
	order := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), mustDecimal(t, "27742317777372353535851937790883648493"))
	sValue := new(big.Int).SetBytes(slices.Clone(reversed(signature[32:])))
	sValue.Add(sValue, order)
	bumped := make([]byte, 32)
	sValue.FillBytes(bumped)
	nonCanonical := append(append([]byte(nil), signature[:32]...), reversed(bumped)...)
	if ed25519.Verify(ed25519.PublicKey(keys.devices[1].public), message, nonCanonical) {
		t.Error("crypto/ed25519 accepts S + L")
	}
}

func reversed(octets []byte) []byte {
	out := slices.Clone(octets)
	slices.Reverse(out)
	return out
}

func mustDecimal(t *testing.T, text string) *big.Int {
	t.Helper()
	value, ok := new(big.Int).SetString(text, 10)
	if !ok {
		t.Fatalf("%q is not decimal", text)
	}
	return value
}

// The contract LRI R68 settled for R65 item 4, held with a known answer for each method:
// messagegroup signs, and no private half leaves the package. Under the frozen parameters, phrase
// A's one ceremony over the set {1, 2} answers IRK, ISK_1 and ISK_2 and isk_seed[1], and signs
// IskCert(1) and IskCert(2), the step to phrase B's IRK, base 1's ISK_1 signature (with its author's
// beside it through SignBaseAuthor), and D2 IL8's derivation under "inboxown/v1". A key number
// outside the set, and a base under another key number, are refused; and once the ceremony is over
// every method answers ErrPhraseKeysErased.
//
// The answers were computed with no Go code (Python's hmac for HKDF and the OpenSSL command line for
// Ed25519, after RFC 8032's and RFC 5869's vectors): IskCert(2) and the derivation are new here, and
// the rest are this file's known answers for the same octets, which the ceremony must reproduce.
func TestTheCeremonySignsTheCertificateTheStepAndTheBaseAndNothingAfterIt(t *testing.T) {
	fixed := deviceListFixedKeys(t)
	phrase := phraseOfKnownAnswers(t, phraseKnownAnswersFrozen["A"])
	known := phraseKnownAnswersFrozen["A"]
	var kept *PhraseKeys
	err := WithPhraseKeys(phrase, []uint32{2, 1}, func(keys *PhraseKeys) error {
		kept = keys
		if got := keys.KeyNumbers(); !slices.Equal(got, []uint32{1, 2}) {
			t.Errorf("the ceremony's set is %v, want [1 2], ascending", got)
		}
		if phraseHexText(keys.IdentityKey()) != known.irk {
			t.Errorf("IRK is %x, want %s", keys.IdentityKey(), known.irk)
		}
		for _, keyNumber := range []uint32{1, 2} {
			phraseKey, err := keys.PhraseKey(keyNumber)
			if err != nil || phraseHexText(phraseKey) != known.iskSeeds[keyNumber][1] {
				t.Errorf("ISK_%d is %x, %v; want %s", keyNumber, phraseKey, err, known.iskSeeds[keyNumber][1])
			}
			seed, err := keys.PhraseKeySeed(keyNumber)
			if err != nil || phraseHexText(seed) != known.iskSeeds[keyNumber][0] {
				t.Errorf("isk_seed[%d] is %x, %v", keyNumber, seed, err)
			}
		}
		for keyNumber, want := range map[uint32]string{1: deviceListKnownCertSignature, 2: deviceListKnownCert2Signature} {
			cert, err := keys.SignIskCert(keyNumber)
			if err != nil || phraseHexText(cert.Signature) != want || cert.KeyNumber != keyNumber {
				t.Errorf("IskCert(%d) is %+v, %v; want the signature %s", keyNumber, cert, err, want)
			}
		}
		step, err := keys.SignIdentityStep(fixed.irkB.public)
		if err != nil || phraseHexText(step.Signature) != deviceListKnownStepAB {
			t.Errorf("the step to phrase B's IRK is %+v, %v; want the signature %s", step, err, deviceListKnownStepAB)
		}
		base := DeviceListBase{IdentityKey: keys.IdentityKey(), KeyNumber: 1, BaseNumber: 1, IssuedAtMs: deviceListKnownIssuedAtMs,
			Devices: []DeviceEntry{{DeviceKey: fixed.devices[1].public, Flags: DeviceFlagPhraseDevice}}, AuthorKey: fixed.devices[1].public}
		if err := keys.SignBase(1, &base); err != nil || phraseHexText(base.Signature) != deviceListKnownBaseSignature {
			t.Errorf("base 1's ISK_1 signature is %x, %v; want %s", base.Signature, err, deviceListKnownBaseSignature)
		}
		if err := SignBaseAuthor(&base, fixed.devices[1].private); err != nil || phraseHexText(base.AuthorSignature) != deviceListKnownBaseAuthorSig {
			t.Errorf("base 1's author signature is %x, %v; want %s", base.AuthorSignature, err, deviceListKnownBaseAuthorSig)
		}
		owner, err := keys.DeriveIdentityKeyed("inboxown/v1")
		if err != nil || phraseHexText(owner) != deviceListKnownOwnerKey {
			t.Errorf("IL8's derivation under inboxown/v1 is %x, %v; want %s", owner, err, deviceListKnownOwnerKey)
		}
		// the refusals
		if _, err := keys.PhraseKey(3); !errors.Is(err, ErrPhraseKeyNumber) {
			t.Errorf("ISK_3, outside the set: %v", err)
		}
		if _, err := keys.SignIskCert(3); !errors.Is(err, ErrPhraseKeyNumber) {
			t.Errorf("IskCert(3), outside the set: %v", err)
		}
		if err := keys.SignBase(2, &base); !errors.Is(err, ErrIdentitySigningKey) {
			t.Errorf("a base of key number 1 signed under 2: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if kept.IdentityKey() != nil || len(kept.KeyNumbers()) != 0 {
		t.Errorf("the keys outlived the ceremony")
	}
	if _, err := kept.SignIskCert(1); !errors.Is(err, ErrPhraseKeysErased) {
		t.Errorf("a certificate was signed after the ceremony: %v", err)
	}
	if _, err := kept.SignIdentityStep(fixed.irkB.public); !errors.Is(err, ErrPhraseKeysErased) {
		t.Errorf("a step was signed after the ceremony: %v", err)
	}
	if err := kept.SignBase(1, &DeviceListBase{}); !errors.Is(err, ErrPhraseKeysErased) {
		t.Errorf("a base was signed after the ceremony: %v", err)
	}
	if _, err := kept.DeriveIdentityKeyed("inboxown/v1"); !errors.Is(err, ErrPhraseKeysErased) {
		t.Errorf("a key was derived after the ceremony: %v", err)
	}
	if _, err := kept.PhraseKeySeed(1); !errors.Is(err, ErrPhraseKeysErased) {
		t.Errorf("isk_seed[1] was answered after the ceremony: %v", err)
	}
}

// The test this replaced, kept below as the body of the old contract's one assertion that is not a
// known answer: what the ceremony signs binds and verifies.
func TestWhatTheCeremonySignsBindsAndVerifies(t *testing.T) {
	keys := deviceListFixedKeys(t)
	phrase := phraseOfKnownAnswers(t, phraseKnownAnswersSeam["A"])
	var cert *IskCert
	var step *IdentityStep
	base := DeviceListBase{BaseNumber: 1, Devices: []DeviceEntry{{DeviceKey: keys.devices[1].public, Flags: DeviceFlagPhraseDevice}},
		AuthorKey: keys.devices[1].public, KeyNumber: 1}
	err := withPhraseKeys(phrase, []uint32{1}, phraseStretchForTests, func(ceremony *PhraseKeys) error {
		var err error
		if cert, err = ceremony.SignIskCert(1); err != nil {
			return err
		}
		if step, err = ceremony.SignIdentityStep(keys.irkB.public); err != nil {
			return err
		}
		base.IdentityKey = ceremony.IdentityKey()
		if err := ceremony.SignBase(1, &base); err != nil {
			return err
		}
		return SignBaseAuthor(&base, keys.devices[1].private)
	})
	if err != nil {
		t.Fatal(err)
	}
	irk := phraseHexOctets(t, phraseKnownAnswersSeam["A"].irk)
	identity := &UrmessageIdentity{IskCert: *cert, Base: base}
	if _, err := VerifyLeafBinding(irk, keys.devices[1].public, deviceListLeafExtensions(t, identity)); err != nil {
		t.Errorf("the ceremony's certificate and base do not bind: %v", err)
	}
	if err := VerifyIdentityChain(irk, []IdentityStep{*step}, keys.irkB.public); err != nil {
		t.Errorf("the ceremony's step does not verify: %v", err)
	}
}
