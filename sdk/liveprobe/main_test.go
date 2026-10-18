package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message/messagegroup"
	"github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
	"google.golang.org/protobuf/proto"
)

// THIS PACKAGE HAS TESTS SO THAT ITS TEST BINARY EXISTS AND STARTS. A main package with no test is
// built and vetted by test.sh and never run, and a defect that shows only when a binary starts -- two
// copies of message.proto linked into one binary, which protobuf refuses at init -- is invisible to
// build and to vet. `go test` runs this package's init before its first case, so every run of these
// cases is also that check; the module census requires every main package to have one. What
// the cases themselves hold is the probe's own instruments: the credential scan over its transcript,
// the difference it reports when a text comes back changed, and, from identity phase 1's Task 15,
// how a party's identity is made, the needles its words are, and the key packages the seam binds.

func TestTheTranscriptCountsANeedleAndAnnouncesItOnce(t *testing.T) {
	log := &transcriptLog{}
	writer := log.tee(io.Discard)
	fmt.Fprintf(writer, "a line with %s in it, and %s again\n", credentialNeedle, credentialNeedle)
	held, announce := log.count(credentialNeedle)
	if held != 2 || !announce {
		t.Fatalf("count answered %d, announce %v; want 2 and the first caller announcing", held, announce)
	}
	held, announce = log.count(credentialNeedle)
	if held != 2 || announce {
		t.Fatalf("a second count answered %d, announce %v; want 2 and no second announcement", held, announce)
	}
	if want := len(fmt.Sprintf("a line with %s in it, and %s again\n", credentialNeedle, credentialNeedle)); log.octets() != want {
		t.Errorf("octets() = %d, want %d", log.octets(), want)
	}
	clean := &transcriptLog{}
	fmt.Fprint(clean.tee(io.Discard), "nothing secret here\n")
	if held, announce := clean.count(credentialNeedle); held != 0 || announce {
		t.Errorf("a clean transcript answered %d, announce %v", held, announce)
	}
}

// the scan's control is a fabricated value its needle finds, so "no credential in the log" is a
// measurement and not the silence of a scanner that matches nothing
func TestTheCredentialControlIsWhatTheScanLooksFor(t *testing.T) {
	if !strings.HasPrefix(credentialControl, credentialNeedle) {
		t.Fatalf("the control %q does not begin with the needle, so it cannot show the scan works", credentialControl)
	}
}

func TestFirstDifferencePointsAtTheFirstOctetThatDiffers(t *testing.T) {
	for _, row := range []struct {
		want, got string
		at        int
	}{
		{"same", "same", -1},
		{"abc", "abd", 2},
		{"abc", "ab", 2},
		{"ab", "abc", 2},
		{"", "x", 0},
		{"x", "y", 0},
	} {
		if at := firstDifference(row.want, row.got); at != row.at {
			t.Errorf("firstDifference(%q, %q) = %d, want %d", row.want, row.got, at, row.at)
		}
	}
}

// ── the parties' identities (identity phase 1's Task 15) ─────────────────────────────────────

// fixedWords are the needle's cases' phrase: the list's first 25 words, the same on every run. A random
// phrase would put the cases' own prose below at the needle's measured rate of firing on honest text.
var fixedWords = strings.Fields("abandon ability able about above absent absorb abstract absurd abuse access " +
	"accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt")

// THE NEEDLE (LRI R83): any two consecutive words of a phrase, with one to four characters that are not
// letters between them, or half of its words as words of the text; and never one word alone, since the
// list is English and so is everything this probe prints.
func TestThePhraseNeedleIsTwoWordsInARowOrHalfOfThemAndNeverOneWord(t *testing.T) {
	words := fixedWords
	reversed := slices.Clone(words)
	slices.Reverse(reversed)
	numbered := ""
	for at, word := range words {
		numbered += fmt.Sprintf("%d. %s\n", at+1, word)
	}
	asJson, err := json.Marshal(words)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		text  string
		fires bool
	}{
		{"the phrase as the device answers it, joined by spaces", strings.Join(words, " "), true},
		{"the phrase as %v formats the slice", fmt.Sprintf("%v", words), true},
		{"the phrase as %q formats the slice", fmt.Sprintf("%q", words), true},
		{"the phrase as json", string(asJson), true},
		{"the phrase in capitals", strings.ToUpper(strings.Join(words, " ")), true},
		{"a numbered column, a word a line", numbered, true},
		{"two words in a row inside a sentence", "the text was \"" + words[12] + ", " + words[13] + "\" and nothing else", true},
		{"two words in a row across a line break", "it ends with " + words[20] + "\n" + words[21] + " begins the next", true},
		{"two words four characters apart", words[2] + " -- " + words[3], true},
		{"half the words, 13, in reverse order", strings.Join(reversed[:13], " | "), true},
		{"half the words, 13, never two in a row", strings.Join(words[:13], " and the "), true},
		// the shapes that do not fire, each at the needle's edge
		{"one word of the phrase alone", "the " + words[4] + " line was read", false},
		{"12 words, never two in a row", strings.Join(words[:12], " and the "), false},
		{"two words five characters apart", words[2] + " --- " + words[3], false},
		{"two words of the phrase out of their order", words[8] + " " + words[7], false},
		{"honest prose holding several of the words, never two in a row", "an account of the action, and about the actor", false},
	} {
		how := phraseHeld(words, c.text)
		if (how != "") != c.fires {
			t.Errorf("%s: phraseHeld answered %q, want it to fire: %v", c.name, how, c.fires)
		}
		if how != "" && phraseHeld(words, how) != "" {
			t.Errorf("%s: what phraseHeld answers, %q, carries the words it found", c.name, how)
		}
	}
}

// THE TRANSCRIPT HOLDS EVERY PARTY'S WORDS AS NEEDLES (Property 1; MI37's killer). A party's words, once
// held, are found where they are planted -- two of them in a row, and the whole phrase -- and an honest
// transcript holding single words of them is not; the disclosure is announced once; and the needles are
// the transcript's own copy.
func TestTheTranscriptHoldsEveryPartysWordsAsNeedles(t *testing.T) {
	log := &transcriptLog{}
	writer := log.tee(io.Discard)
	words := slices.Clone(fixedWords)
	log.holdPhrase("A", words)
	clear(words)
	if log.phraseCount() != 1 || !slices.Equal(log.phraseOf("A"), fixedWords) {
		t.Fatalf("the transcript holds needles for %d parties, and A's are %q: want A's words, its own copy",
			log.phraseCount(), log.phraseOf("A"))
	}
	fmt.Fprintf(writer, "an honest line: the action, and the actor, and %s alone\n", fixedWords[5])
	if found, announce := log.phrasesHeld(); len(found) != 0 || announce {
		t.Fatalf("an honest transcript holding single words of the phrase answered %v, %v", found, announce)
	}
	// THE CONTROLS: a two-word run, planted
	fmt.Fprintf(writer, "a line that carries %s %s by mistake\n", fixedWords[5], fixedWords[6])
	found, announce := log.phrasesHeld()
	if found["A"] == "" || !announce {
		t.Fatalf("two of A's words in a row, planted, answered %v, %v: want A found and announced", found, announce)
	}
	if _, again := log.phrasesHeld(); again {
		t.Errorf("the disclosure was announced twice")
	}
	// and the whole phrase, planted in a transcript of its own
	whole := &transcriptLog{}
	whole.holdPhrase("B", fixedWords)
	fmt.Fprint(whole.tee(io.Discard), strings.Join(fixedWords, " "))
	if found, _ := whole.phrasesHeld(); found["B"] == "" {
		t.Errorf("B's whole phrase, planted, answered %v", found)
	}
}

// THE FAILURE PATH READS ITS OWN LINE FOR THE WORDS, as it does for the credentials: every failure ends
// in os.Exit, so a scan only the last step made would never read the line a failing run ends on. Driven
// in a child process, both ways: a FAIL line carrying two of A's words is disclosed, and one carrying
// none is not.
func TestTheFailurePathReadsItsOwnLineForTheWords(t *testing.T) {
	if line := os.Getenv("LIVEPROBE_TEST_FAIL_LINE"); line != "" {
		transcript.holdPhrase("A", fixedWords)
		fail("%s", line)
	}
	for _, c := range []struct {
		name      string
		line      string
		disclosed bool
	}{
		{"a FAIL line carrying two of A's words", "the typed text was " + fixedWords[9] + " " + fixedWords[10], true},
		{"a FAIL line carrying none", "the server answered REASON_NOT_FOUND", false},
	} {
		child := exec.Command(os.Args[0], "-test.run=^TestTheFailurePathReadsItsOwnLineForTheWords$")
		child.Env = append(os.Environ(), "LIVEPROBE_TEST_FAIL_LINE="+c.line)
		output, err := child.CombinedOutput()
		// the child's output carries the planted words, so a failure names its size and never prints it
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("%s: the child answered %v, want fail's exit status 1 (%d octets of output)", c.name, err, len(output))
		}
		disclosed := strings.Contains(string(output), "PHRASE DISCLOSURE")
		if disclosed != c.disclosed {
			t.Errorf("%s: disclosed %v, want %v (%d octets of output)", c.name, disclosed, c.disclosed, len(output))
		}
		if disclosed && !strings.Contains(string(output), "the words of A") {
			t.Errorf("%s: the disclosure does not name the party (%d octets of output)", c.name, len(output))
		}
	}
}

// A PARTY'S IDENTITY IS MADE AS A PERSON MAKES ONE (LRI R81): connected, the words offered, typed back,
// and the identity made. The words are the transcript's needles BEFORE they are typed back -- a device
// that is not connected refuses the typing back, and its words are held all the same -- and what is
// printed of the identity is digests only (Property 1).
func TestAPartysIdentityIsMadeAsAPersonMakesOne(t *testing.T) {
	ctx := context.Background()
	device := probeDevice(t, &helloClient{})
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	identity, words, err := identify(ctx, "T-connected", device)
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if len(words) != messagegroup.RecoveryPhraseWordCount || !slices.Equal(transcript.phraseOf("T-connected"), words) {
		t.Fatalf("identify answered %d words, and the transcript holds %d as the party's needles: want the same 25",
			len(words), len(transcript.phraseOf("T-connected")))
	}
	if len(identity.AccountId) != 36 || len(identity.DeviceId) != 19 || !identity.PhraseDevice ||
		len(identity.Devices) != 1 || !identity.Devices[0].ThisDevice {
		t.Fatalf("the identity is %d and %d characters, phrase device %v, %d device(s): want a first device's",
			len(identity.AccountId), len(identity.DeviceId), identity.PhraseDevice, len(identity.Devices))
	}
	if held, err := device.Identity(); err != nil || held.AccountId != identity.AccountId {
		t.Fatalf("the device's own identity is %v (%v), and identify answered another", held, err)
	}
	line := identityLine("T-connected", identity)
	// a failure names the line by its size and digest and never prints it, since a line that carried
	// the words would put them in the log (LRI R84 item 6; review X-LIB-7)
	for _, digest := range []string{digestOf([]byte(identity.AccountId)), digestOf([]byte(identity.DeviceId))} {
		if digest == "" || !strings.Contains(line, digest) {
			t.Errorf("the identity's line (%d octets, %s) does not carry the digest %s", len(line), digestOf([]byte(line)), digest)
		}
	}
	for at, plain := range []string{identity.AccountId, identity.DeviceId} {
		if strings.Contains(line, plain) {
			t.Errorf("the identity's line (%d octets) carries its ID %d itself, and not its digest", len(line), at)
		}
	}
	if how := phraseHeld(words, line); how != "" {
		t.Errorf("the identity's line carries the words: %s", how)
	}

	unconnected := probeDevice(t, &helloClient{})
	if _, _, err := identify(ctx, "T-unconnected", unconnected); err == nil {
		t.Fatalf("an unconnected device's identity was made")
	}
	if len(transcript.phraseOf("T-unconnected")) != messagegroup.RecoveryPhraseWordCount {
		t.Errorf("the words of a typing back that was refused are not needles: the transcript holds %d",
			len(transcript.phraseOf("T-unconnected")))
	}
}

// digestOf is a SHA-256 digest, marked, and only that.
func TestADigestIsTheValuesSha256AndNothingOfTheValue(t *testing.T) {
	value := []byte("ab12cd34-0000-8000-8000-0123456789ab")
	digest := digestOf(value)
	sum := sha256.Sum256(value)
	if digest != "sha256:"+hex.EncodeToString(sum[:8]) {
		t.Errorf("digestOf answered %q", digest)
	}
}

// A ROSTER ROW NAMES ITS IDENTITY BY DIGEST, as everything this probe prints of an identity does.
func TestARosterRowNamesItsIdentityByDigest(t *testing.T) {
	identityPub := bytes.Repeat([]byte{0xAB}, 32)
	row := rosterRow(urmessage.Member{LeafIndex: 3, IdentityPub: identityPub, Role: "member"})
	if want := "leaf3/" + digestOf(identityPub) + "/member"; row != want {
		t.Errorf("the row is %q, want %q", row, want)
	}
	if strings.Contains(row, hex.EncodeToString(identityPub[:4])) {
		t.Errorf("the row %q carries the identity key's own octets", row)
	}
}

// THE SEAM'S KEY PACKAGES ARE BOUND (identity phase 1's Task 15): the stranger's, an identity of its
// own, and C's second device, a further device of an identity whose list a device of it publishes.
// Every receiver reads them as it reads a join code's leaf, and its control is words that make another
// identity, which the further device is refused for.
func TestTheSeamsKeyPackagesAreBound(t *testing.T) {
	fast := messagegroup.FastPhraseStretchForTests()
	newPhrase := func() *messagegroup.RecoveryPhrase {
		phrase, err := messagegroup.NewRecoveryPhrase()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(phrase.Erase)
		return phrase
	}
	again := func(phrase *messagegroup.RecoveryPhrase) *messagegroup.RecoveryPhrase {
		words := phrase.Words()
		parsed, _, err := messagegroup.ParseRecoveryPhrase(strings.Join(words, " "))
		clear(words)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(parsed.Erase)
		return parsed
	}

	// an identity of its own: a first base naming this leaf alone, as a phrase device
	own := newPhrase()
	first, err := seamKeyPackage(own, nil, fast)
	if err != nil {
		t.Fatalf("an identity of its own: %v", err)
	}
	firstList, firstCredential, err := keyPackageList(first)
	if err != nil {
		t.Fatalf("its key package does not bind: %v", err)
	}
	if firstList.Identity.Base.BaseNumber != 1 || len(firstList.Devices) != 1 ||
		firstList.Devices[0].Flags&messagegroup.DeviceFlagPhraseDevice == 0 || !bytes.Equal(firstCredential, firstList.IdentityKey) {
		t.Fatalf("an identity of its own: base %d naming %d device(s), credential is the identity key %v",
			firstList.Identity.Base.BaseNumber, len(firstList.Devices), bytes.Equal(firstCredential, firstList.IdentityKey))
	}

	// a further device of that identity, from the same words: the next base, naming both
	second, err := seamKeyPackage(again(own), firstList.Identity, fast)
	if err != nil {
		t.Fatalf("a further device: %v", err)
	}
	secondList, secondCredential, err := keyPackageList(second)
	if err != nil {
		t.Fatalf("the further device's key package does not bind: %v", err)
	}
	if !bytes.Equal(secondCredential, firstCredential) || !bytes.Equal(secondList.Root, firstList.Root) ||
		secondList.Identity.Base.BaseNumber != 2 || len(secondList.Devices) != 2 {
		t.Fatalf("the further device: the same identity %v and root %v, base %d naming %d device(s); want base 2 naming two",
			bytes.Equal(secondCredential, firstCredential), bytes.Equal(secondList.Root, firstList.Root),
			secondList.Identity.Base.BaseNumber, len(secondList.Devices))
	}
	for _, device := range secondList.Devices {
		if device.Flags&messagegroup.DeviceFlagPhraseDevice == 0 {
			t.Errorf("the further device's list names %x without the phrase device mark", device.DeviceKey[:4])
		}
	}
	named := false
	for _, device := range secondList.Devices {
		if bytes.Equal(device.DeviceKey, firstList.Devices[0].DeviceKey) {
			named = true
		}
	}
	if !named {
		t.Errorf("the further device's list does not name the device whose list it follows")
	}

	// THE CONTROL: words that make another identity do not make a further device of this one
	if _, err := seamKeyPackage(newPhrase(), firstList.Identity, fast); err == nil {
		t.Errorf("a further device was made from words that make another identity")
	}
}

// helloClient is a connect client whose server answers Hello, with a nonce, and nothing else: the
// smallest thing a device can be connected through, livepeer's own test double one module over. The
// answer is delivered on another goroutine, because the transport is still inside its own send when the
// request leaves it.
type helloClient struct {
	mutex   sync.Mutex
	receive connect.ReceiveFunction
}

func (self *helloClient) AddReceiveCallback(receive connect.ReceiveFunction) func() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.receive = receive
	return func() {}
}

func (self *helloClient) SendWithTimeout(frame *connectprotocol.Frame, destination connect.Id,
	ack connect.AckFunction, timeout time.Duration, opts ...any) bool {

	if frame.GetMessageType() != connectprotocol.MessageType_MessageMessageServerRequest {
		return true
	}
	request := &protocol.MessageServerRequest{}
	if proto.Unmarshal(frame.GetMessageBytes(), request) != nil || request.GetHello() == nil {
		return false
	}
	self.mutex.Lock()
	receive := self.receive
	self.mutex.Unlock()
	if receive == nil {
		return false
	}
	encoded, err := proto.Marshal(&protocol.MessageServerResponse{
		RequestId: request.GetRequestId(),
		Reason:    protocol.Reason_REASON_OK,
		Body: &protocol.MessageServerResponse_Hello{
			Hello: &protocol.HelloResponse{ServerNonce: []byte("liveprobe's test server nonce")},
		},
	})
	if err != nil {
		return false
	}
	go receive(connect.TransferPath{}, []*connectprotocol.Frame{{
		MessageType:  connectprotocol.MessageType_MessageMessageServerResponse,
		MessageBytes: encoded,
	}}, connect.Peer{})
	return true
}

// probeDevice is a real urmessage.Device over durable stores in a temp directory and a transport over
// the client given, under the test seam's stretch (LRI R76 item 10).
func probeDevice(t *testing.T, client sdk.MessageTransportClient) *urmessage.Device {
	t.Helper()
	root := t.TempDir()
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client: client, Server: connect.NewId(), ProtocolVersion: 1, Timeout: time.Second,
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	for _, sub := range []string{"stream", "state"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	streamStore, err := sdk.OpenStreamStore(filepath.Join(root, "stream"))
	if err != nil {
		t.Fatalf("OpenStreamStore: %v", err)
	}
	stateStore, err := urmessage.OpenDurableStateStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatalf("OpenDurableStateStore: %v", err)
	}
	device, err := urmessage.NewDevice(urmessage.DeviceConfig{
		Transport:     transport,
		Reserver:      sdk.NewStreamIndexReserver(streamStore),
		StateStore:    stateStore,
		PhraseStretch: messagegroup.FastPhraseStretchForTests(),
	})
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() {
		device.Close()
		stateStore.Close()
		streamStore.Close()
		transport.Close()
	})
	return device
}

// EVERY IDENTITY KEY IS A NEEDLE OF THE TRANSCRIPT (LRI R84 item 5; review X-LIB-3). An identity key is
// made from its party's words, and this probe prints a SHA-256 digest of an identity and nothing
// else of it; the library formats a refused leaf's identity in hex. A held key is found where its hex
// is planted, in either case and whether whole or its first octets alone, and an honest transcript of
// digests is not; the disclosure is announced once.
func TestEveryIdentityKeyIsANeedleOfTheTranscript(t *testing.T) {
	key := bytes.Repeat([]byte{0xC3, 0x5A, 0x91, 0x0E}, 8)
	log := &transcriptLog{}
	writer := log.tee(io.Discard)
	log.holdKey("C", key)
	fmt.Fprintf(writer, "an honest line: identity %s, epoch 4, group %x\n", digestOf(key), []byte("a group id"))
	if found, announce := log.keysHeld(); len(found) != 0 || announce {
		t.Fatalf("an honest transcript answered %v, %v", found, announce)
	}
	// THE CONTROLS: the whole key, in hex, as the library's refusal formats it
	fmt.Fprintf(writer, "leaf 3 (%x) added by a member\n", key)
	found, announce := log.keysHeld()
	if !slices.Equal(found, []string{"C"}) || !announce {
		t.Fatalf("a key printed whole answered %v, %v: want C found and announced", found, announce)
	}
	if _, again := log.keysHeld(); again {
		t.Error("the disclosure was announced twice")
	}
	// and its first octets alone, in capitals, in a transcript of their own
	prefix := &transcriptLog{}
	prefix.holdKey("A", key)
	fmt.Fprintf(prefix.tee(io.Discard), "row leaf0/%X/owner\n", key[:4])
	if found, _ := prefix.keysHeld(); !slices.Equal(found, []string{"A"}) {
		t.Errorf("a key's first four octets in capitals answered %v", found)
	}
}

// A REFUSAL THE STEPS EXPECT IS PRINTED BY ITS CLASS (LRI R84 item 5; review X-LIB-3): the sentinels it
// wraps, and never its text, which names the refused identity by its key in hex.
func TestARefusalIsPrintedByItsClassAndNeverItsText(t *testing.T) {
	key := bytes.Repeat([]byte{0x6D}, 32)
	refusal := fmt.Errorf("%w: %w: leaf 2 (%x) added by a member", urmessage.ErrCommitUnauthorized, urmessage.ErrCommitAddByNonAdmin, key)
	class := refusalClass(refusal)
	if class != "ErrCommitUnauthorized wrapping ErrCommitAddByNonAdmin" {
		t.Errorf("the refusal's class is %q", class)
	}
	if strings.Contains(strings.ToLower(class), hex.EncodeToString(key[:4])) {
		t.Error("the class carries the refused identity's key")
	}
	if got := refusalClass(errors.New("a refusal of no known class")); strings.Contains(got, "a refusal of no known class") {
		t.Errorf("a refusal of no class this probe names is printed by its text: %q", got)
	}
}
