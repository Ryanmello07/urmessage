package urmessage

import (
	"sort"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE PHRASE-SECRET CENSUS OF THIS PACKAGE: EVERY PHRASE SECRET THE DEVICE HOLDS GOES WHERE ITS
// DISPOSITION SAYS
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// Identity phase 1's Task 12, with LRI R68's third addition: the phrase-secret census of
// sdk/urmessage, starting here. messagegroup/phrasesecretgate_test.go holds the phrase's secrets
// inside the package that derives them; this census holds them on the device's side of the call,
// on the same engine (census_test.go) and held the same ways: the producer sites; the sink sites,
// the values each carries and each value's occurrences there; the counted-not-carried sites the one
// narrowing removes; and the horizon where the walk stops knowing. Every one in both directions.
//
// ITS NET IS THE FOUR THINGS R68 NAMES. The RecoveryPhrase -- the draw that offers it, the field
// that holds it until it is typed back, the words it shows, the typed words and the parse of them;
// the WithPhraseKeys ceremonies; PhraseKeySeed, isk_seed[g], the one phrase secret that outlives a
// ceremony; and the kind-13 record it goes to, written and read back.
//
// AN ERASE THAT IS A METHOD OF THE VALUE IS NOT A SITE, AND IS HELD ELSEWHERE. A RecoveryPhrase is
// erased by its own method, phrase.Erase(), and this engine counts a value a call is HANDED, never
// the receiver it is called on; so the two erases of a phrase on this side -- the offered phrase's,
// at ConfirmWords and at Close, and the parsed phrase's, when ConfirmWords returns -- are no site
// here. They are held by TestTheWordsLeaveTheDeviceOnceTheIdentityStandsAndAtClose, which reads the
// phrase the device held and finds it blank, and Erase itself by messagegroup's census ("Erase|call
// zeroize"). isk_seed[g]'s erase is a call it is handed, zeroizeState(seed), and is a site below.
//
// WHAT IT DOES NOT FOLLOW, AND WHY THAT IS NOT A HOLE. The ceremony's keys object, PhraseKeys, is
// the parameter of a function literal, which no binding form of this engine seeds; what the device
// takes out of it is a call this net names (PhraseKeySeed) or a public value (the identity key, a
// certificate, a signed base). A PhraseKeys kept past its ceremony holds nothing: WithPhraseKeys
// erases every key in it when the ceremony returns, whatever the ceremony did, and messagegroup's
// census and TestTheCeremonySignsTheCertificateTheStepAndTheBaseAndNothingAfterIt hold that.

// The names that produce a phrase secret on this side of the call.
var sdkPhraseSecretProducerNames = map[string]bool{
	// THE RECOVERY PHRASE: the draw, the parse, the field that holds the offered one, its words,
	// and the typed words
	"NewRecoveryPhrase":   true,
	"ParseRecoveryPhrase": true,
	"offered":             true,
	"Words":               true,
	"phraseTyped":         true,
	// THE CEREMONIES, AND THE ONE SECRET THAT LEAVES ONE
	"WithPhraseKeys": true,
	"PhraseKeySeed":  true,
	// THE KIND-13 RECORD, READ BACK. Nothing in production reads it yet: the stored-seed signer that
	// does is Tasks 31 and 33's (LRI R72), and the net names the read so that its first caller is a
	// site of this census rather than a road nobody weighed
	"PhraseKey": true,
}

var sdkPhraseSecretProducerSites = map[string]string{
	"Close|self.offered":                            "the offered phrase, read at Close to be erased and dropped",
	"ConfirmWords|messagegroup.ParseRecoveryPhrase": "THE PARSE: the typed words read back into a phrase, which ConfirmWords erases when it returns",
	"ConfirmWords|parameter phraseTyped":            "THE TYPED WORDS, as the app hands them in: the caller's string, which Go cannot erase",
	"ConfirmWords|self.offered":                     "the offered phrase: read to be compared with the typed words and, once the identity stands, erased and dropped",
	"CreateIdentity|messagegroup.NewRecoveryPhrase": "THE DRAW: the new identity's phrase, held as the offered phrase until it is typed back, and never stored",
	"CreateIdentity|self.offered":                   "the offered phrase, held so that Back shows the same words",
	"CreateIdentity|self.offered.Words":             "THE WORDS, answered for the screen that shows them",
	"PutPhraseKey|parameter record":                 "the kind-13 record, handed by putIdentityRecords with isk_seed[1] in it",
	"encodeStateRecord|parameter parts":             "the record's parts, isk_seed[1] among them, handed by writeRecord to be framed",
	"makeIdentity|keys.PhraseKeySeed":               "ISK_SEED[1], copied out of the ceremony for the one place it may go: a phrase device's phrase key record, store kind 13",
	"makeIdentity|messagegroup.WithPhraseKeys":      "THE CEREMONY over key number 1. The call is in the net so that every ceremony this package runs is a site; it answers an error",
	"makeIdentity|parameter parsed":                 "the parsed phrase, handed by ConfirmWords to the making",
	"putIdentityRecords|parameter seed":             "isk_seed[1], handed by makeIdentity, for the phrase key record of a phrase device",
	"writeRecord|parameter parts":                   "the record's parts, handed by PutPhraseKey",
	"zeroizeState|parameter octets":                 "every phrase secret this package erases by handing it over: isk_seed[1] when makeIdentity returns, and the framed record writeRecord erases",
}

type sdkPhraseSecretSink struct {
	carries []string
	occurs  []string
	why     string
}

var sdkPhraseSecretSinks = map[string]sdkPhraseSecretSink{
	"ConfirmWords|call fmt.Errorf":                       {carries: []string{"differing"}, occurs: []string{"differing"}, why: "THE POSITIONS of the words that differ, from 1, in the refusal: numbers and never a word (Spec A A-36 section 7.2). The walk follows them because WordsDiffering was handed the typed words"},
	"ConfirmWords|call messagegroup.ParseRecoveryPhrase": {carries: []string{"phraseTyped"}, occurs: []string{"phraseTyped"}, why: "the typed words read into a phrase"},
	"ConfirmWords|call offered.WordsDiffering":           {carries: []string{"phraseTyped"}, occurs: []string{"phraseTyped"}, why: "the typed words compared, position by position, with the words shown"},
	"ConfirmWords|call parsed.Equal":                     {carries: []string{"offered"}, occurs: []string{"offered"}, why: "the parsed phrase compared with the offered one, in constant time"},
	"ConfirmWords|call self.makeIdentity":                {carries: []string{"parsed"}, occurs: []string{"parsed"}, why: "the parsed phrase into the making, which hands it to the ceremony and keeps it nowhere"},
	"ConfirmWords|return":                                {carries: []string{"differing"}, occurs: []string{"fmt.Errorf(...)"}, why: "the refusal naming the positions"},
	"CreateIdentity|assign self.offered":                 {carries: []string{"phrase"}, occurs: []string{"phrase"}, why: "THE OFFERED PHRASE, HELD IN A FIELD until it is typed back or the device closes: the one phrase secret this package keeps past a call, never stored, and erased at ConfirmWords and at Close (TestTheWordsLeaveTheDeviceOnceTheIdentityStandsAndAtClose)"},
	"CreateIdentity|return":                              {carries: []string{"self.offered.Words"}, occurs: []string{"self.offered.Words(...)"}, why: "THE WORDS, to the screen that shows them; the caller clears the slice once they are off the screen"},
	"PutPhraseKey|call binary.BigEndian.PutUint32":       {carries: []string{"record"}, occurs: []string{"record.KeyNumber"}, why: "the key number into its part: a number"},
	"PutPhraseKey|call self.writeRecord":                 {carries: []string{"record"}, occurs: []string{"record.IdentityKey", "record.Seed"}, why: "THE PHRASE KEY GOING TO DISK: store kind 13, the identity key, the key number and isk_seed[1], on a phrase device only (Property 4), in the clear as the device's own keys are"},
	"PutPhraseKey|return":                                {carries: []string{"record"}, occurs: []string{"self.writeRecord(...)"}, why: "the write's error"},
	"encodeStateRecord|call body.Write":                  {carries: []string{"part"}, occurs: []string{"part"}, why: "each part into the frame; see the horizon"},
	"makeIdentity|call messagegroup.WithPhraseKeys":      {carries: []string{"parsed"}, occurs: []string{"parsed"}, why: "the parsed phrase into the ceremony, which derives the keys of key number 1 from it and erases them when it returns"},
	"makeIdentity|call self.putIdentityRecords":          {carries: []string{"seed"}, occurs: []string{"seed"}, why: "isk_seed[1] to the records' writer, which writes it on a phrase device only"},
	"makeIdentity|call zeroizeState":                     {carries: []string{"seed"}, occurs: []string{"seed"}, why: "ERASED: isk_seed[1], when the making returns, whatever it answered"},
	"putIdentityRecords|literal PhraseKeyRecord.Seed":    {carries: []string{"seed"}, occurs: []string{"seed"}, why: "isk_seed[1] into the kind-13 record"},
	"writeRecord|call encodeStateRecord":                 {carries: []string{"parts"}, occurs: []string{"parts"}, why: "the parts into one framed record"},
	"writeRecord|call temp.Write":                        {carries: []string{"record"}, occurs: []string{"record"}, why: "the framed record into the file being committed; see the horizon"},
	"writeRecord|call zeroizeState":                      {carries: []string{"record"}, occurs: []string{"record"}, why: "ERASED: the framed record, once written"},
	"zeroizeState|assign octets[at]":                     {carries: []string{"at"}, occurs: []string{"0"}, why: "ERASED: the zero written over each octet; at is the loop's index, tainted by ranging over the secret"},
}

var sdkPhraseSecretCountedNotCarriedSites = map[string]string{
	"ConfirmWords|len differing":          "whether any position differs",
	"PutPhraseKey|len record.IdentityKey": "the record's width refusal for the identity key, which formats nothing of the record",
	"PutPhraseKey|len record.Seed":        "the record's width refusal for the seed, 32 octets, which formats nothing of the record",
	"encodeStateRecord|len part":          "the framing's per-part width, and its refusal of a part a uint32 cannot count",
	"encodeStateRecord|len parts":         "the framing's part count",
}

var sdkPhraseSecretAccumulatorSites = map[string]string{
	"ConfirmWords|accumulate self.makeIdentity":       "the parsed phrase handed to a method of the device. The walk follows it in (makeIdentity|parameter parsed), and the making keeps it in no field of the receiver",
	"makeIdentity|accumulate self.putIdentityRecords": "isk_seed[1] handed to a method of the device, followed in (putIdentityRecords|parameter seed): it goes to the store and into no field",
	"PutPhraseKey|accumulate self.writeRecord":        "the record handed to the store's own write, followed in (writeRecord|parameter parts)",
	"encodeStateRecord|accumulate body.Write":         "THE FRAME: each part into the *bytes.Buffer the record is assembled in, which the walk does not follow; writeRecord erases what it gets back",
	"writeRecord|accumulate temp.Write":               "THE DISK: the framed record, isk_seed[1] inside it, into the file being committed. What happens to those octets after this call is the filesystem's",
}

func TestEveryPhraseSecretThisDeviceHoldsGoesWhereTheDispositionSaysItGoes(t *testing.T) {
	census := runCensus(t, sdkPhraseSecretProducerNames)

	// ── THE COMPLEMENT, PRINTED: what this search covered and what it left out ────────────────
	t.Logf("production sources read (%d): %v", len(census.sources), census.sources)
	t.Logf("producer net: %v", epochKeySortedKeys(sdkPhraseSecretProducerNames))
	t.Logf("producer sites found (%d):", len(census.producers))
	for _, site := range epochKeySortedMap(census.producers) {
		t.Logf("    %s  at %v", site, census.producers[site])
	}
	t.Logf("sink sites found (%d), each with THE VALUES IT CARRIES and each OCCURRENCE:", len(census.sinks))
	for _, site := range epochKeySortedMap(census.sinks) {
		occurs := append([]string(nil), census.occurrences[site]...)
		sort.Strings(occurs)
		t.Logf("    %s  carries %v  occurs [%s]  at %v", site, epochKeySortedKeys(census.carried[site]),
			strings.Join(occurs, " | "), census.sinks[site])
	}
	t.Logf("COUNTED AND NOT CARRIED (%d):", len(census.counted))
	for _, site := range epochKeySortedMap(census.counted) {
		t.Logf("    %s  at %v", site, census.counted[site])
	}
	t.Logf("THE WALK'S HORIZON (%d):", len(census.accumulated))
	for _, site := range epochKeySortedMap(census.accumulated) {
		t.Logf("    %s  at %v", site, census.accumulated[site])
	}
	t.Logf("EXCLUDED, and excluded is not the same as absent -- tainted values that reach no sink "+
		"in their own function: %v", census.unspent)

	// ── AND ASSERTED, IN BOTH DIRECTIONS ──────────────────────────────────────────────────────
	censusHold(t, "producer site", census.producers, sdkPhraseSecretProducerSites,
		"A name that produces a phrase secret is where this census begins. A site with no entry is a "+
			"phrase secret coming from somewhere nobody weighed; an entry with no site is this census "+
			"gone BLIND, a producer respelled, and every sink clause below searching a value nothing "+
			"tainted.")
	sinkWhy := map[string]string{}
	for site, entry := range sdkPhraseSecretSinks {
		sinkWhy[site] = entry.why
	}
	sinkNarrowing := "A recovery phrase is the root of an identity: whoever holds the words holds the " +
		"identity key, every key number's phrase key, and so the power to sign a device list that " +
		"names any device at all. On this side of the call the shape this census exists to refuse is " +
		"the words, the parsed phrase or isk_seed[g] kept past the call that needed them -- in a field, " +
		"in an error string, in a log -- an erase that ends one going missing, and isk_seed[g] reaching " +
		"anything but the phrase key record. A site with no entry is a phrase secret landing somewhere " +
		"nobody weighed. An entry with no site is a disposition that has stopped describing the code."
	censusHold(t, "sink site", census.sinks, sinkWhy, sinkNarrowing)
	occursListed := map[string][]string{}
	for site, entry := range sdkPhraseSecretSinks {
		occursListed[site] = entry.occurs
	}
	censusHoldOccurrences(t, census.occurrences, occursListed, sinkNarrowing)
	for _, site := range epochKeySortedMap(census.sinks) {
		entry, dispositioned := sdkPhraseSecretSinks[site]
		if !dispositioned {
			continue
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
					"%v there. A value that has stopped arriving is a fix nobody deleted the entry for, "+
					"a rename this census is blind to, or an erase that went missing.\n%s",
					site, spelled, epochKeySortedKeys(census.carried[site]), sinkNarrowing)
			}
		}
	}
	censusHold(t, "counted-not-carried site", census.counted, sdkPhraseSecretCountedNotCarriedSites,
		"A COUNT OF A PHRASE SECRET IS NOT A PHRASE SECRET, and that single exclusion is a narrowing: "+
			"every site it removed is named here, so a count nobody weighed fails, and so does a count "+
			"the tree no longer takes.")
	censusHold(t, "accumulator site", census.accumulated, sdkPhraseSecretAccumulatorSites,
		"A TAINT WALK OVER NAMES STOPS WHERE A VALUE IS HANDED TO A METHOD AND LIVES ON INSIDE THE "+
			"RECEIVER, and this is that stopping place written down. A site with no entry is a new "+
			"blind spot; an entry with no site is a limit lifted or moved.")
}
