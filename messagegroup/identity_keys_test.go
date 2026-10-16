// The keys and the two IDs (identity phase 1's plan, Task 10): Properties 2, 3 and 4, and the
// source gate that holds the stretch's test seam out of production.
//
// THE KNOWN ANSWERS ARE NORMATIVE FROM THIS COMMIT ON, and Task 40 writes them into Spec A. They
// were not read out of the code they check: they were computed by a script that shares no code
// with this package -- Python's hashlib and hmac for SHA-256 and HKDF-SHA256, written out by RFC
// 5869's two steps, and the OpenSSL 3.5.5 command line for Argon2id and for the Ed25519 public
// key of a seed -- after each outside primitive reproduced its RFC's own vector (RFC 9106 section
// 5.3, RFC 8032 section 7.1 test 1, RFC 5869 A.1). This package then reproduced every one.
package messagegroup

import (
	"crypto/ed25519"
	"errors"
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The stretch's TEST SEAM: the cheapest Argon2id there is, one pass over 64 KiB in one lane. Every
// test of this package stretches through it but one, which runs the frozen parameters. It is
// declared here, in a _test.go file, and handed to withPhraseKeys as an argument;
// TestProductionStretchesWithTheFrozenParametersOnly holds that production never names it and
// never builds anything like it.
var phraseStretchForTests = phraseStretchParameters{time: 1, memoryKiB: 64, lanes: 1}

// One phrase's known answers under one set of stretch parameters.
type phraseKnownAnswers struct {
	p34       string
	stretched string
	masterKey string
	irkSeed   string
	irk       string
	iskRoot   string
	// key number -> isk_seed[g] and ISK_g's public half
	iskSeeds map[uint32][2]string
}

// Under the frozen parameters, t = 3, m = 262,144 KiB, p = 4.
var phraseKnownAnswersFrozen = map[string]phraseKnownAnswers{
	"A": {
		p34:       phraseAP34Hex,
		stretched: "2e2666f1275eec3508720dd6e65f89d8f4fa656708a460bfdbb387a49b868d7c",
		masterKey: "457394bba20a6fa795acf6ba7e29d4378186b659f52b9586eb142a524e27eead",
		irkSeed:   "3eab5d6b01e0d04c4f71063e882629a7c39185c1c672c6304e2eef6064fc08a5",
		irk:       "43c9207a8cb3a38a4b656f677de518a0f3c97c0ab005e5d9f33c428498cd9408",
		iskRoot:   "019ba1bf1130c97057c0823dbdf62d604da8cf94d66fa62f4321ba8188e98f9e",
		iskSeeds: map[uint32][2]string{
			1: {"74e0e07f506f9168240f9c527b708abf0cd7404e1762a3379f64e37c674340e2",
				"c02125b01fb02c19cedb0fc3804d53304eb5f761e571410bc67312e72a564da4"},
			2: {"400540e65f7ebc7b45ada8e4a383280a3ea3c55e52f77f173134957108ba9135",
				"b867854c7ee509d76705abe03dcf793f5d085e62e321c58c80fc1f874bb02b32"},
			4294967295: {"7cbfc244be76356a44c9c401111575a5380507540c8322d546a1d7b092229eff",
				"51d33bdd24aa737f8a0554c12a1c2d773b7c0b3d084ac841199f33f6f192d3b5"},
		},
	},
	"B": {
		p34:       phraseBP34Hex,
		stretched: "2e52065ad9e293d9dacac41bd4f2804d142e9ef046c7fa9cb7e9ea70e8a9df7b",
		masterKey: "f3e3ecf7e96d950923692d968a5433ecdebcefa398f9f546ed3d77dcf9295dcc",
		irkSeed:   "7cc957a1d9ccab04a7d298050c23f9d89d204675d61dea69cfdeec253b641849",
		irk:       "90ba4eaab7fc384b75c39d218aadee849e0a7adf0aaf362fef65777badec5877",
		iskRoot:   "9c7d22b4b7c00577c168f6619438c6944c672c7e5048ca84084a72096b5cfdde",
		iskSeeds: map[uint32][2]string{
			1: {"d69d6923e55579c1f3a0f4c54936334720e98017044102aefaeb9ff1d5714657",
				"ef4e69d146b2082f974d8f851dd473af7fbac12bd7dee6d53c9989b6188fa116"},
			2: {"699808d63aeed9975d467706775b359094097235b69aa09236895e4b86a9bea9",
				"0f5add280eca4ce842c2dffb477ce905cba773886587bd94cd34fd5867d2f9d6"},
			4294967295: {"6cf779348ba84909eda3711337025ff133ddd95aa7d5a4d0c8a896623e9d025b",
				"27ed6c81003336788b10c942ae6a55eb563ac905f13a2d8c749e043fc0ec7627"},
		},
	},
}

// Under the test seam, t = 1, m = 64 KiB, p = 1. They are the same script's, and they are not
// normative: they exist so that the tests that stretch through the seam check answers too.
var phraseKnownAnswersSeam = map[string]phraseKnownAnswers{
	"A": {
		p34:       phraseAP34Hex,
		stretched: "573f44d79600dc3e245d28aa2ce51705a43c6aacbdc2896a1707603bb5264072",
		masterKey: "428b757871d72b11ca52ee64827b98438a029df23bc9e6ddba9d6127f166e3c4",
		irkSeed:   "08c741d2587362d3567e4ab49c98352d7ecb1975f6def4f0592c9f0e8645bfa9",
		irk:       "8f44d3acbaaef524d95f257f251babbf2a4bcca47165b76d4a46600756d29465",
		iskRoot:   "8cd4ef1712af5e4bdccae0409b7a047f01ed1aa400cff6812ea79c37e68ff6df",
		iskSeeds: map[uint32][2]string{
			1: {"bbe7a2ede724a68b66156ba80bc2e54a70fb1946677c80401007163d71997854",
				"da0e2fb5eea0ec1657af085972fc7a22e71ad10dba6a4d47665c40b32f1fc206"},
			2: {"eeae72d025c2eb89c03b22aac09b5ff6d76e1872ce2212d9b269a822d2f10a1d",
				"cfe6e434bb868e7d9ad729c07f4001d68a8390d525b4435e2387db68e56ab39e"},
			4294967295: {"bd0d6d2a4e52cb38ba1123c31d1487da1e7e50c2170ac8735f1d7bedebcf45fa",
				"55f542af4f143c1496f78f9974b0a80725dc03819e5be5583741d04c2676ce22"},
		},
	},
	"B": {
		p34:       phraseBP34Hex,
		stretched: "37b99f5073bb61c8c6b5a3a63dc82d252f1e39e28646c64ce14f25d8bd7ca8b7",
		masterKey: "b2481726ed7a50111a6a38526ccbc4e7d2f432b1a56e4d61a15da81a32536992",
		irkSeed:   "83cc81a242908a54da14b035c139afd3cbee81633add0f911270d4c179747a86",
		irk:       "a7ed4a36b2246abe70f4eda6ed53dd68d78492131e7510d16fb2340d5847c4c0",
		iskRoot:   "b346e11c0564718c5735d80e8fd20dad51c4e524e9a59897e6db5e63bc8d7767",
		iskSeeds: map[uint32][2]string{
			1: {"295170f91f8e2612e6e014175a437ecf9b6daa970922ddd82d389ec81ee4284c",
				"a4f43b6475e12981a6d3757ae97a382f734707f9dda99febafeda16e3e9d64c3"},
			2: {"9fb4ef9e15e8461dba3709366cccd306be811af937e55dbca1421358a01ef773",
				"b27d5a4e9aca242b0ac988260a8ceae0abfbda5fad47185b38c871534b4ccc07"},
			4294967295: {"43c9b2c07d5d35da2c521f19659c9ea92c4d64bf1b611909647a272afe0c19d7",
				"b9ff46fe5525e827711ecc49366f923512be5730cd402c4a5f1d82984e206b00"},
		},
	},
}

// The phrase a set of known answers is for.
func phraseOfKnownAnswers(t *testing.T, known phraseKnownAnswers) *RecoveryPhrase {
	t.Helper()
	phrase := &RecoveryPhrase{}
	copy(phrase.p34[:], phraseHexOctets(t, known.p34))
	return phrase
}

// One ceremony's view of its keys, copied out while it runs: per key number of its set, ISK_g and
// isk_seed[g].
type phraseCeremonyView struct {
	keyNumbers []uint32
	irk        string
	isk        map[uint32]string
	iskSeed    map[uint32]string
	keys       *PhraseKeys
}

func phraseCeremonyUnder(t *testing.T, phrase *RecoveryPhrase, keyNumbers []uint32,
	parameters phraseStretchParameters) phraseCeremonyView {

	t.Helper()
	view := phraseCeremonyView{isk: map[uint32]string{}, iskSeed: map[uint32]string{}}
	err := withPhraseKeys(phrase, keyNumbers, parameters, func(keys *PhraseKeys) error {
		view.keyNumbers, view.irk, view.keys = keys.KeyNumbers(), phraseHexText(keys.IdentityKey()), keys
		for _, keyNumber := range keyNumbers {
			phraseKey, err := keys.PhraseKey(keyNumber)
			if err != nil {
				return err
			}
			seed, err := keys.PhraseKeySeed(keyNumber)
			if err != nil {
				return err
			}
			view.isk[keyNumber], view.iskSeed[keyNumber] = phraseHexText(phraseKey), phraseHexText(seed)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// Property 2, under the frozen parameters: the one test of this package that runs them.
//
// Each phrase is checked twice over. Step by step, through the package's own functions, so a
// wrong answer names the step it went wrong at: S, master_key, IRK's seed and public half,
// isk_root, and isk_seed[g] and ISK_g for three key numbers. And through WithPhraseKeys, the one
// production path, so a composition that skipped or reordered a step -- MI8's HKDF straight over
// the bits -- answers keys these are not.
func TestTheKeysAreTheKnownAnswersForTwoPhrases(t *testing.T) {
	if phraseStretchFrozen() != (phraseStretchParameters{time: 3, memoryKiB: 262144, lanes: 4}) {
		t.Fatalf("the frozen parameters are %+v, want MASTER section 5.2's t = 3, m = 262,144 KiB, p = 4", phraseStretchFrozen())
	}
	for _, name := range []string{"A", "B"} {
		known := phraseKnownAnswersFrozen[name]
		phrase := phraseOfKnownAnswers(t, known)
		stretched := stretchPhrase(phrase.p34[:], phraseStretchFrozen())
		masterKey := keyScheduleExtract([]byte(phraseMasterKeySalt), stretched)
		irkSeed := keyScheduleExpand(masterKey, []byte(identityKeyInfo), phraseKeyOctets)
		iskRoot := keyScheduleExpand(masterKey, []byte(iskRootInfo), phraseKeyOctets)
		for step, pair := range [][2]string{
			{phraseHexText(stretched), known.stretched},
			{phraseHexText(masterKey), known.masterKey},
			{phraseHexText(irkSeed), known.irkSeed},
			{phraseTestPublicKeyOf(irkSeed), known.irk},
			{phraseHexText(iskRoot), known.iskRoot},
		} {
			if pair[0] != pair[1] {
				t.Errorf("phrase %s, step %d of S, master_key, IRK's seed, IRK, isk_root: %s, want %s", name, step, pair[0], pair[1])
			}
		}
		for keyNumber, want := range known.iskSeeds {
			seed := iskSeedOf(iskRoot, keyNumber)
			if phraseHexText(seed) != want[0] {
				t.Errorf("phrase %s: isk_seed[%d] is %x, want %s", name, keyNumber, seed, want[0])
			}
			if got := phraseTestPublicKeyOf(seed); got != want[1] {
				t.Errorf("phrase %s: ISK_%d is %s, want %s", name, keyNumber, got, want[1])
			}
		}
		// EVERY KEY NUMBER OF THE SET IN ONE STRETCH (LRI R68, L3-3): one ceremony over the three
		// known key numbers answers each one's known seed and key
		view := phraseCeremonyUnder(t, phrase, []uint32{1, 2, 4294967295}, phraseStretchFrozen())
		if view.irk != known.irk || !slices.Equal(view.keyNumbers, []uint32{1, 2, 4294967295}) {
			t.Errorf("phrase %s through WithPhraseKeys: IRK %s over the set %v; want %s over [1 2 4294967295]", name, view.irk, view.keyNumbers, known.irk)
		}
		for keyNumber, want := range known.iskSeeds {
			if view.isk[keyNumber] != want[1] || view.iskSeed[keyNumber] != want[0] {
				t.Errorf("phrase %s through WithPhraseKeys: ISK_%d %s and isk_seed %s; want %s and %s",
					name, keyNumber, view.isk[keyNumber], view.iskSeed[keyNumber], want[1], want[0])
			}
		}
		// and WithPhraseKeys itself, the exported entry, answers the same keys
		err := WithPhraseKeys(phrase, []uint32{1}, func(keys *PhraseKeys) error {
			if phraseHexText(keys.IdentityKey()) != known.irk {
				return errors.New("WithPhraseKeys answered another IRK")
			}
			return nil
		})
		if err != nil {
			t.Errorf("phrase %s: %v", name, err)
		}
	}
}

// Property 3: isk_seed[g] depends only on isk_root and g, and no isk_seed equals isk_root or IRK's
// seed. Through the seam, and against the same script's answers under the seam.
func TestEveryKeyNumbersSeedIsTheKnownAnswerAndNoneIsTheRoot(t *testing.T) {
	for _, name := range []string{"A", "B"} {
		known := phraseKnownAnswersSeam[name]
		phrase := phraseOfKnownAnswers(t, known)
		seeds := map[string]uint32{}
		for keyNumber, want := range known.iskSeeds {
			view := phraseCeremonyUnder(t, phrase, []uint32{keyNumber}, phraseStretchForTests)
			if view.iskSeed[keyNumber] != want[0] || view.isk[keyNumber] != want[1] {
				t.Errorf("phrase %s, key number %d: isk_seed %s and ISK %s, want %s and %s",
					name, keyNumber, view.iskSeed[keyNumber], view.isk[keyNumber], want[0], want[1])
			}
			if view.irk != known.irk {
				t.Errorf("phrase %s, key number %d: IRK %s, want %s: the identity key does not depend on g", name, keyNumber, view.irk, known.irk)
			}
			// a function of isk_root and g alone: the same seed out of the known isk_root, with no
			// phrase and no stretch in sight
			if direct := phraseHexText(iskSeedOf(phraseHexOctets(t, known.iskRoot), keyNumber)); direct != view.iskSeed[keyNumber] {
				t.Errorf("phrase %s, key number %d: isk_seed from isk_root alone is %s and the ceremony's is %s", name, keyNumber, direct, view.iskSeed[keyNumber])
			}
			for _, root := range []string{known.iskRoot, known.irkSeed, known.masterKey, known.stretched} {
				if view.iskSeed[keyNumber] == root {
					t.Errorf("phrase %s: isk_seed[%d] is one of S, master_key, IRK's seed or isk_root", name, keyNumber)
				}
			}
			if other, seen := seeds[view.iskSeed[keyNumber]]; seen {
				t.Errorf("phrase %s: key numbers %d and %d have one seed", name, other, keyNumber)
			}
			seeds[view.iskSeed[keyNumber]] = keyNumber
			// and the keys the ceremony was handed are blank once it is over
			if view.keys.irk != nil || view.keys.numbers != nil {
				t.Errorf("phrase %s, key number %d: the keys outlived the ceremony", name, keyNumber)
			}
		}
	}
	// a ceremony that fails still ends with its keys erased, and its error is answered as it is
	refused := errors.New("the ceremony refused")
	var kept *PhraseKeys
	err := withPhraseKeys(phraseOfKnownAnswers(t, phraseKnownAnswersSeam["B"]), []uint32{7, 8}, phraseStretchForTests,
		func(keys *PhraseKeys) error {
			kept = keys
			return refused
		})
	if err != refused || kept == nil || kept.irk != nil || kept.numbers != nil {
		t.Errorf("a failed ceremony answered %v and left its keys", err)
	}
	if err := WithPhraseKeys(nil, []uint32{1}, func(*PhraseKeys) error { return nil }); !errors.Is(err, ErrPhraseKeysCeremony) {
		t.Errorf("no phrase: %v", err)
	}
	if err := WithPhraseKeys(phraseOfKnownAnswers(t, phraseKnownAnswersSeam["A"]), []uint32{1}, nil); !errors.Is(err, ErrPhraseKeysCeremony) {
		t.Errorf("no ceremony: %v", err)
	}
	// a set that is empty, holds 0, or names a number twice is refused before anything is stretched
	for _, refusedSet := range [][]uint32{nil, {}, {0}, {1, 0}, {2, 2}, {1, 2, 1}} {
		ran := false
		err := withPhraseKeys(phraseOfKnownAnswers(t, phraseKnownAnswersSeam["A"]), refusedSet, phraseStretchForTests,
			func(*PhraseKeys) error { ran = true; return nil })
		if !errors.Is(err, ErrPhraseKeyNumber) || ran {
			t.Errorf("the set %v answered %v, the ceremony ran: %v", refusedSet, err, ran)
		}
	}
}

// The account IDs and device IDs, over the frozen roots of phrases A and B.
var (
	accountIdKnownAnswers = map[[2]string]string{
		{"A", "00..0f"}: "1283569c-2de9-8110-a50a-cd9777c9bbcf",
		{"A", "0f..00"}: "d7c2f408-a5e5-8dee-8e5e-439911a49c10",
		{"B", "00..0f"}: "d5c83566-d338-8b8a-8261-542c247311f8",
		{"B", "0f..00"}: "3ab380e7-01a0-8e22-a249-ae878820a0b1",
	}
	// the device keys are the Ed25519 keys of the seeds 01 x 32 and 02 x 32
	deviceKeyKnown = map[string]string{
		"1": "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
		"2": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
	}
	deviceIdKnownAnswers = map[[2]string]string{
		{"A", "1"}: "cec0-4d32-a6ab-55c1",
		{"A", "2"}: "0d6d-bf8a-a6da-7d24",
		{"B", "1"}: "a398-48f7-8d39-da38",
		{"B", "2"}: "b363-4c4c-ca69-1e2a",
	}
)

// Property 4: the account ID is the known answer, changes with the salt and with the root, and is
// a UUIDv8 of 36 characters; the device ID changes with the device key and with the root, and
// with nothing else (D2 DID3).
func TestTheAccountIdIsTheKnownAnswerAndMovesWithTheSalt(t *testing.T) {
	salts := map[string][AccountIdSaltSize]byte{}
	var ascending, descending [AccountIdSaltSize]byte
	for at := range ascending {
		ascending[at] = byte(at)
		descending[at] = byte(AccountIdSaltSize - 1 - at)
	}
	salts["00..0f"], salts["0f..00"] = ascending, descending
	seen := map[string][2]string{}
	for which, want := range accountIdKnownAnswers {
		root := ed25519.PublicKey(phraseHexOctets(t, phraseKnownAnswersFrozen[which[0]].irk))
		id, err := AccountIdOf(root, salts[which[1]])
		if err != nil {
			t.Fatal(err)
		}
		text := id.String()
		if text != want {
			t.Errorf("the account ID over root %s and salt %s is %s, want %s", which[0], which[1], text, want)
		}
		if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' ||
			text[14] != '8' || !strings.ContainsRune("89ab", rune(text[19])) ||
			strings.Trim(text, "0123456789abcdef-") != "" {
			t.Errorf("%s is not a UUID of version 8 and RFC 9562's variant, written 8-4-4-4-12 in lowercase", text)
		}
		if other, twice := seen[text]; twice {
			t.Errorf("%v and %v have one account ID", other, which)
		}
		seen[text] = which
	}
	if len(seen) != 4 {
		t.Errorf("four roots and salts make %d account IDs: an ID moves with the salt and with the root", len(seen))
	}
	if _, err := AccountIdOf(make(ed25519.PublicKey, 31), ascending); !errors.Is(err, ErrIdentityPublicKeyLength) {
		t.Errorf("a 31-octet root: %v", err)
	}

	seenDevices := map[string][2]string{}
	for which, want := range deviceIdKnownAnswers {
		root := ed25519.PublicKey(phraseHexOctets(t, phraseKnownAnswersFrozen[which[0]].irk))
		device := ed25519.PublicKey(phraseHexOctets(t, deviceKeyKnown[which[1]]))
		id, err := DeviceIdOf(root, device)
		if err != nil {
			t.Fatal(err)
		}
		text := id.String()
		if text != want {
			t.Errorf("the device ID over root %s and device key %s is %s, want %s", which[0], which[1], text, want)
		}
		if len(text) != 19 || text[4] != '-' || text[9] != '-' || text[14] != '-' || strings.Trim(text, "0123456789abcdef-") != "" {
			t.Errorf("%s is not four groups of four lowercase hex characters", text)
		}
		seenDevices[text] = which
	}
	if len(seenDevices) != 4 {
		t.Errorf("two roots and two device keys make %d device IDs", len(seenDevices))
	}
	// the device keys' public halves are the seeds' own, so the answers above are over real keys
	for name, want := range deviceKeyKnown {
		seed := make([]byte, 32)
		for at := range seed {
			seed[at] = name[0] - '0'
		}
		if got := phraseTestPublicKeyOf(seed); got != want {
			t.Errorf("device key %s is %s, want %s", name, got, want)
		}
	}
	// "with nothing else": the device ID is a function of the root and the device key and takes
	// no third input -- not the salt, not the key number, not a name
	if kind := reflect.TypeOf(DeviceIdOf); kind.NumIn() != 2 {
		t.Errorf("DeviceIdOf takes %d inputs; D2 DID3: a device ID changes with the device key and the root and nothing else", kind.NumIn())
	}
	if kind := reflect.TypeOf(AccountIdOf); kind.NumIn() != 2 || kind.In(1) != reflect.TypeOf([AccountIdSaltSize]byte{}) {
		t.Errorf("AccountIdOf is %v; ID1 takes the root and a 16-octet salt", kind)
	}
	if _, err := DeviceIdOf(make(ed25519.PublicKey, 32), make(ed25519.PublicKey, 33)); !errors.Is(err, ErrIdentityPublicKeyLength) {
		t.Errorf("a 33-octet device key: %v", err)
	}
}

// Property 2's last sentence, "production reads no other parameters", held as a SOURCE GATE over
// the seam (MI9). Five clauses, each over every production file of this package:
//
//  1. the one Argon2id call is stretchPhrase's, and it reads its parameters off its argument;
//  2. the one phraseStretchParameters value production spells is the literal phraseStretchFrozen
//     answers, and phraseStretchFrozen is a FUNCTION whose whole body returns it;
//  3. so the parameters are unwritable by construction: there is no variable to write, and no
//     production body writes, steps or takes the address of a parameter of the type, or of a field
//     of one, and the type declares no method;
//  4. every production call of a function taking the parameters passes phraseStretchFrozen() or
//     forwards its own parameter, and the exported entry passes phraseStretchFrozen();
//  5. the seam's name appears in no production file.
//
// So the seam's cheap parameters can reach a stretch only from a test file. The review of Tasks 8
// to 10 lightened the variable this gate used to hold, through a pointer-receiver method (its M3,
// beside the plan's MI9) and with -- (its M3b), and both passed clause 3 as it was (L2-03); neither
// can be written against a function, and clause 3 now holds the parameters' own copies as well.
func TestProductionStretchesWithTheFrozenParametersOnly(t *testing.T) {
	fileSet, sources := messagegroupProductionSources(t)
	const parametersType = "phraseStretchParameters"
	const frozen = "phraseStretchFrozen"

	// the functions that take the parameters, read off their signatures
	taking := map[string]int{}
	for _, source := range sources {
		for _, declaration := range source.parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction {
				continue
			}
			position := 0
			for _, field := range function.Type.Params.List {
				names := max(1, len(field.Names))
				if identifier, isName := field.Type.(*ast.Ident); isName && identifier.Name == parametersType {
					taking[function.Name.Name] = position
				}
				position += names
			}
		}
	}
	if !slices.Equal(slices.Sorted(func(yield func(string) bool) {
		for name := range taking {
			if !yield(name) {
				return
			}
		}
	}), []string{"derivePhraseKeys", "stretchPhrase", "withPhraseKeys"}) {
		t.Errorf("the functions taking %s are %v, want derivePhraseKeys, stretchPhrase and withPhraseKeys", parametersType, taking)
	}

	argon2Calls, literals, frozenPasses, frozenBodies := 0, 0, 0, 0
	for _, source := range sources {
		text := source.path
		if strings.Contains(messagegroupSourceText(t, source.path), "phraseStretchForTests") {
			t.Errorf("%s names phraseStretchForTests, the test seam", text)
		}
		for _, declaration := range source.parsed.Decls {
			switch typed := declaration.(type) {
			case *ast.GenDecl:
				ast.Inspect(typed, func(node ast.Node) bool {
					if literal, isLiteral := node.(*ast.CompositeLit); isLiteral {
						if identifier, isName := literal.Type.(*ast.Ident); isName && identifier.Name == parametersType {
							literals += 1
							t.Errorf("%s declares a %s outside a function: %s", text, parametersType, phraseNodeText(t, fileSet, literal))
						}
					}
					return true
				})
			case *ast.FuncDecl:
				if typed.Body == nil {
					continue
				}
				// the type declares no method: one with a pointer receiver could rewrite a copy
				if typed.Recv != nil && strings.Contains(phraseNodeText(t, fileSet, typed.Recv.List[0].Type), parametersType) {
					t.Errorf("%s declares a method %s on %s", text, typed.Name.Name, parametersType)
				}
				// the one literal is the frozen function's whole body
				if typed.Name.Name == frozen {
					frozenBodies += 1
					if typed.Recv != nil || len(typed.Body.List) != 1 ||
						phraseNodeText(t, fileSet, typed.Body) != "{\n\treturn phraseStretchParameters{time: 3, memoryKiB: 262144, lanes: 4}\n}" {
						t.Errorf("%s is %s", frozen, phraseNodeText(t, fileSet, typed))
					}
				}
				// the function's own parameter of the type, which it may forward
				own := ""
				for _, field := range typed.Type.Params.List {
					if identifier, isName := field.Type.(*ast.Ident); isName && identifier.Name == parametersType && len(field.Names) == 1 {
						own = field.Names[0].Name
					}
				}
				ast.Inspect(typed.Body, func(node ast.Node) bool {
					switch shape := node.(type) {
					case *ast.CompositeLit:
						if identifier, isName := shape.Type.(*ast.Ident); isName && identifier.Name == parametersType {
							literals += 1
							if typed.Name.Name != frozen {
								t.Errorf("%s builds a %s in %s: %s", text, parametersType, typed.Name.Name, phraseNodeText(t, fileSet, shape))
							}
						}
					case *ast.AssignStmt:
						for _, left := range shape.Lhs {
							if spelled := phraseNodeText(t, fileSet, left); own != "" && (spelled == own || strings.HasPrefix(spelled, own+".")) {
								t.Errorf("%s writes %s in %s", text, spelled, typed.Name.Name)
							}
						}
					case *ast.IncDecStmt:
						if spelled := phraseNodeText(t, fileSet, shape.X); own != "" && strings.HasPrefix(spelled, own) {
							t.Errorf("%s steps %s in %s", text, spelled, typed.Name.Name)
						}
					case *ast.UnaryExpr:
						if spelled := phraseNodeText(t, fileSet, shape.X); shape.Op == token.AND && own != "" && strings.HasPrefix(spelled, own) {
							t.Errorf("%s takes the address of %s in %s", text, spelled, typed.Name.Name)
						}
					case *ast.CallExpr:
						callee := phraseNodeText(t, fileSet, shape.Fun)
						if callee == "argon2.IDKey" {
							argon2Calls += 1
							if typed.Name.Name != "stretchPhrase" || len(shape.Args) != 6 ||
								phraseNodeText(t, fileSet, shape.Args[2]) != own+".time" ||
								phraseNodeText(t, fileSet, shape.Args[3]) != own+".memoryKiB" ||
								phraseNodeText(t, fileSet, shape.Args[4]) != own+".lanes" ||
								phraseNodeText(t, fileSet, shape.Args[1]) != "[]byte(phraseStretchSalt)" ||
								phraseNodeText(t, fileSet, shape.Args[5]) != "phraseKeyOctets" {
								t.Errorf("%s calls argon2.IDKey in %s as %s", text, typed.Name.Name, phraseNodeText(t, fileSet, shape))
							}
						}
						position, takes := taking[callee]
						if !takes || len(shape.Args) <= position {
							return true
						}
						passed := phraseNodeText(t, fileSet, shape.Args[position])
						switch {
						case passed == frozen+"()":
							frozenPasses += 1
							if typed.Name.Name != "WithPhraseKeys" {
								t.Errorf("%s passes %s to %s from %s; only the exported entry chooses the parameters", text, frozen, callee, typed.Name.Name)
							}
						case own != "" && passed == own:
						default:
							t.Errorf("%s passes %s to %s from %s; production stretches with %s and nothing else", text, passed, callee, typed.Name.Name, frozen)
						}
					}
					return true
				})
			}
		}
	}
	if argon2Calls != 1 || literals != 1 || frozenPasses != 1 || frozenBodies != 1 {
		t.Errorf("%d argon2.IDKey calls, %d %s literals, %d passes of %s() and %d declarations of it; want 1, 1, 1 and 1",
			argon2Calls, literals, parametersType, frozenPasses, frozen, frozenBodies)
	}
}

// The public half of the Ed25519 key a seed makes, in hex, computed here with crypto/ed25519 and
// not through the package. A seed that is not thirty two octets answers "" rather than taking the
// test binary down: ed25519.NewKeyFromSeed panics on one, and a panic would hide every other
// test's verdict behind this one's.
func phraseTestPublicKeyOf(seed []byte) string {
	if len(seed) != ed25519.SeedSize {
		return ""
	}
	return phraseHexText(ed25519.NewKeyFromSeed(seed)[ed25519.SeedSize:])
}

// The text of one production file, for the clause that reads names rather than syntax.
func messagegroupSourceText(t *testing.T, path string) string {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(text)
}

// One node as go/printer writes it.
func phraseNodeText(t *testing.T, fileSet *token.FileSet, node ast.Node) string {
	t.Helper()
	var text strings.Builder
	if err := printer.Fprint(&text, fileSet, node); err != nil {
		t.Fatalf("print a node: %v", err)
	}
	return text.String()
}
