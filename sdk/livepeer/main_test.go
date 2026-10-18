package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
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
// the cases themselves hold is the file handshake the peers rest on: the invite is written so a
// poller never reads half of it, and the waits see it arrive and see it go. And the JOIN ROAD's
// rules: which flags a run may take together, a code read as the app writes and pastes one, and the
// one line each refusal of a join adds to the library's own sentence.

// runMainEnv makes this test binary run livepeer's own main instead of its cases, so that the flag
// rules are held the way a person meets them: a command line in, a refusal and an exit status out.
const runMainEnv = "LIVEPEER_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runLivepeer runs main in a child process with these arguments, and answers its exit status and
// everything it wrote.
func runLivepeer(t *testing.T, args ...string) (int, string) {
	t.Helper()
	command := exec.Command(os.Args[0], args...)
	command.Env = append(os.Environ(), runMainEnv+"=1")
	output, err := command.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exited *exec.ExitError
	if !errors.As(err, &exited) {
		t.Fatalf("livepeer %v did not run: %v", args, err)
	}
	return exited.ExitCode(), string(output)
}

func TestAnInviteIsWrittenWholeAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "invite")
	content := []byte("an invite, all of it")
	if err := writeSecret(path, content); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read back %q, %v; want %q", got, err, content)
	}
	if _, err := os.Stat(path + ".partial"); !os.IsNotExist(err) {
		t.Errorf("the temp file is still there after the rename: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("the invite is mode %o, want 600", mode)
		}
	}
}

func TestTheWaitsSeeAFileArriveAndGo(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "invite")
	if _, err := awaitFile(ctx, path, 50*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Fatal("awaitFile answered for a file that never appeared")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		writeSecret(path, []byte("arrived"))
	}()
	got, err := awaitFile(ctx, path, 5*time.Second, 10*time.Millisecond)
	if err != nil || string(got) != "arrived" {
		t.Fatalf("awaitFile answered %q, %v; want the content once it stopped changing", got, err)
	}
	if awaitGone(ctx, path, 30*time.Millisecond, 10*time.Millisecond) {
		t.Fatal("awaitGone answered true for a file that is still there")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		os.Remove(path)
	}()
	if !awaitGone(ctx, path, 5*time.Second, 10*time.Millisecond) {
		t.Fatal("awaitGone did not see the file go")
	}
}

func TestTheReportShortensIdentitiesAndClipsText(t *testing.T) {
	if got := short(nil); got != "-" {
		t.Errorf("short(nil) = %q, want -", got)
	}
	if got := short([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); got != "0102030405060708" {
		t.Errorf("short of ten octets = %q, want the first eight in hex", got)
	}
	long := strings.Repeat("x", 150)
	if got := clip(long); !strings.HasPrefix(got, strings.Repeat("x", 100)) || !strings.HasSuffix(got, "(150 octets)") {
		t.Errorf("clip of 150 octets = %q", got)
	}
	if got := clip("short"); got != "short" {
		t.Errorf("clip changed a short text: %q", got)
	}
}

// ── the join road ────────────────────────────────────────────────────────────────────────────

// THE TWO REFUSALS THE BRIEF NAMES, THROUGH main ITSELF. A joining peer makes its own join code,
// so a run that also hands it somebody else's -- the founder road's input -- is a run that cannot
// say which road it is on. It is refused before the credential is read and before -dir is made:
// the credential path below does not exist and the refusal must not be about it.
func TestAJoinThatCarriesAFoundersInputIsRefusedBeforeAnythingIsRead(t *testing.T) {
	for _, one := range []struct {
		name string
		args []string
	}{
		{"-join with -joincode", []string{"-join", "-joincode", "AAEC", "-invitecode", "@invite.code"}},
		{"-join with -keypackage", []string{"-join", "-keypackage", "app.keypackage", "-invitecode", "@invite.code"}},
	} {
		t.Run(one.name, func(t *testing.T) {
			dir := t.TempDir()
			state := filepath.Join(dir, "peer")
			args := append([]string{"-jwt", filepath.Join(dir, "no-such-credential"), "-dir", state}, one.args...)
			status, output := runLivepeer(t, args...)
			if status != 1 || !strings.Contains(output, "-join takes no -keypackage or -joincode") {
				t.Fatalf("%s exited %d and said:\n%s\nwant exit status 1 and the join road's refusal of a founder's input", one.name, status, output)
			}
			if strings.Contains(output, "read jwt") {
				t.Errorf("the refusal came after the credential was read:\n%s", output)
			}
			if _, err := os.Stat(state); !os.IsNotExist(err) {
				t.Errorf("the refused run made its -dir %s: %v", state, err)
			}
		})
	}
}

// EVERY RUN TAKES ONE ROAD IN AND ONE ROAD OUT, and the join road takes none of the founder's.
func TestEveryRunTakesOneRoadInAndOneRoadOut(t *testing.T) {
	for _, one := range []struct {
		name  string
		roads roads
		// "" for a run the rules let through; otherwise a fragment of the refusal
		want string
	}{
		{"the founder road by files", roads{keyPackage: "app.keypackage", invite: "app.invite"}, ""},
		{"the founder road by codes", roads{joinCode: "@join.code", printInvite: true}, ""},
		{"the founder road, its invite code to a file", roads{joinCode: "@join.code", inviteCodeOut: "invite.code"}, ""},
		{"the join road", roads{join: true, inviteCode: "@invite.code"}, ""},
		{"the join road, its join code to a file", roads{join: true, inviteCode: "@invite.code", joinCodeOut: "join.code"}, ""},
		{"-join with -joincode", roads{join: true, joinCode: "@join.code", inviteCode: "@invite.code"}, "-join takes no -keypackage or -joincode"},
		{"-join with -keypackage", roads{join: true, keyPackage: "app.keypackage", inviteCode: "@invite.code"}, "-join takes no -keypackage or -joincode"},
		{"-join with -invite", roads{join: true, invite: "app.invite", inviteCode: "@invite.code"}, "-join makes no invitation"},
		{"-join with -printinvite", roads{join: true, printInvite: true, inviteCode: "@invite.code"}, "-join makes no invitation"},
		{"-join with -invitecodeout", roads{join: true, inviteCodeOut: "invite.code", inviteCode: "@other.code"}, "-join makes no invitation"},
		{"-join with no -invitecode", roads{join: true, joinCodeOut: "join.code"}, "-join needs -invitecode"},
		{"-invitecode without -join", roads{joinCode: "@join.code", printInvite: true, inviteCode: "@invite.code"}, "add -join"},
		{"-joincodeout without -join", roads{joinCode: "@join.code", printInvite: true, joinCodeOut: "join.code"}, "add -join"},
		{"a founder with nothing in", roads{printInvite: true}, "one of -keypackage or -joincode"},
		{"a founder with nothing out", roads{joinCode: "@join.code"}, "one of -invite or -printinvite"},
	} {
		err := one.roads.check()
		switch {
		case one.want == "" && err != nil:
			t.Errorf("%s was refused: %v", one.name, err)
		case one.want != "" && err == nil:
			t.Errorf("%s was let through; want a refusal saying %q", one.name, one.want)
		case one.want != "" && !strings.Contains(err.Error(), one.want):
			t.Errorf("%s was refused with %q; want it to say %q", one.name, err, one.want)
		}
	}
}

// A CODE IS READ AS THE APP WRITES IT AND AS A PERSON PASTES IT: the app's own encoder's text, and
// that text after a mail client or a chat window has been at it.
func TestACodeIsReadAsTheAppWritesItAndAPersonPastesIt(t *testing.T) {
	octets := make([]byte, 1000) // 1000 is 1 past a multiple of 3, so the code ends in "=="
	for at := range octets {
		octets[at] = byte(at*7 + 3)
	}
	code := appEncodeBase64(octets)
	wrapped := wrapEvery(code, 76, "\r\n")
	for _, one := range []struct{ name, text string }{
		{"as the app writes it", code},
		{"wrapped by a mail client, CRLF every 76 characters", wrapped},
		{"pasted with spaces, tabs and blank lines around it", " \t" + wrapped + " \n\n"},
		{"with its padding lost on the way", strings.TrimRight(code, "=")},
	} {
		got, err := decodeCode(one.text)
		if err != nil || !bytes.Equal(got, octets) {
			t.Errorf("%s: decoded %d octets, %v; want the %d the app encoded", one.name, len(got), err, len(octets))
		}
	}
	for _, one := range []struct{ name, text string }{
		{"text that is not base64", "this is not a code!"},
		{"nothing", ""},
		{"only whitespace", " \r\n\t "},
	} {
		if got, err := decodeCode(one.text); err == nil {
			t.Errorf("%s decoded to %d octets with no error; want a refusal", one.name, len(got))
		}
	}
}

// AN INVITE CODE FILE IS WAITED FOR, READ, AND DELETED: the invite is secret, and a file that is
// left behind is an invitation anybody who reads the disk later holds.
func TestAnInviteCodeFileIsWaitedForReadAndDeleted(t *testing.T) {
	ctx := context.Background()
	octets := []byte("an invitation, as octets, longer than one line once it is wrapped")
	path := filepath.Join(t.TempDir(), "invite.code")
	go func() {
		time.Sleep(30 * time.Millisecond)
		os.WriteFile(path, []byte(wrapEvery(appEncodeBase64(octets), 8, "\n")+"\n"), 0o600)
	}()
	got, err := readInviteCode(ctx, "@"+path, 5*time.Second, 10*time.Millisecond)
	if err != nil || !bytes.Equal(got, octets) {
		t.Fatalf("read %q, %v from the file; want %q", got, err, octets)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the invite code file is still there after it was read: %v", err)
	}

	// A CODE ON THE COMMAND LINE IS THE CODE, and no file is looked for.
	got, err = readInviteCode(ctx, appEncodeBase64(octets), time.Millisecond, time.Millisecond)
	if err != nil || !bytes.Equal(got, octets) {
		t.Errorf("read %q, %v from the command line; want %q", got, err, octets)
	}

	// A FILE THAT NEVER COMES is a refusal once the wait is over, and not a hang.
	never := filepath.Join(t.TempDir(), "never.code")
	if got, err := readInviteCode(ctx, "@"+never, 50*time.Millisecond, 10*time.Millisecond); err == nil {
		t.Errorf("a file that never appeared answered %d octets and no error", len(got))
	}
}

// THE JOIN CODE IS THE TEXT THE APP'S ADD DIALOG TAKES. The key package is a real one, from a real
// Device with an identity, over a transport whose server answers Hello and nothing else (KeyPackage is
// local; the identity's self group is founded under the connection). Its join code must be
// byte for byte the text the app's own encoder makes of the same octets, must decode under the
// app's own reader, and must be written to -joincodeout exactly, with nothing around it.
func TestTheJoinCodeIsTheTextTheAppsAddDialogTakes(t *testing.T) {
	keyPackage, err := identifiedDevice(t).KeyPackage()
	if err != nil {
		t.Fatalf("KeyPackage: %v", err)
	}
	path := filepath.Join(t.TempDir(), "codes", "join.code")
	code, err := handOverJoinCode(keyPackage, path)
	if err != nil {
		t.Fatalf("handOverJoinCode: %v", err)
	}
	if code != appEncodeBase64(keyPackage) {
		t.Errorf("the join code (%d characters) is not the text the app's encoder makes of the same %d octets", len(code), len(keyPackage))
	}
	if back, ok := appDecodeBase64(code); !ok || !bytes.Equal(back, keyPackage) {
		t.Errorf("the app's add dialog reads %d octets, %v back from the join code; want the %d of the key package", len(back), ok, len(keyPackage))
	}
	written, err := os.ReadFile(path)
	if err != nil || string(written) != code {
		t.Errorf("-joincodeout holds %d octets, %v; want exactly the %d characters of the code", len(written), err, len(code))
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("-joincodeout is %v, %v; want mode 600", info, err)
		}
	}
	// WITH NO FILE, the code is answered for main to print, and nothing is written.
	if printed, err := handOverJoinCode(keyPackage, ""); err != nil || printed != code {
		t.Errorf("with no -joincodeout the code was %d characters, %v; want the same %d", len(printed), err, len(code))
	}
	// AND THE ENCODING AGREES WITH THE APP'S AT EVERY LENGTH, so every padding case is held. Neither
	// text is printed on a failure: a code is said by its length, here as everywhere else.
	for length := 0; length <= 48; length += 1 {
		got, err := handOverJoinCode(keyPackage[:length], "")
		if want := appEncodeBase64(keyPackage[:length]); err != nil || got != want {
			t.Errorf("at %d octets the join code is %d characters, %v, and not the %d the app writes", length, len(got), err, len(want))
		}
	}
}

// EACH REFUSAL OF THE JOIN ROAD SAYS WHAT TO DO, by the library's own class, and each line is a
// different instruction. The invitation addressed to another key package is Device.Join's
// refusal, wrapped here the way group.go's Join wraps the engine's (a Join needs a connection
// before it reaches its window, so the live run is what drives the real one); the rest are
// ParseInvite's own refusals of real octets.
func TestEachRefusalOfTheJoinRoadSaysWhatToDo(t *testing.T) {
	ownJoinCode, err := identifiedDevice(t).KeyPackage()
	if err != nil {
		t.Fatalf("KeyPackage: %v", err)
	}
	versionTwo := inviteAtVersionTwo()
	damaged := []byte{0x00, 0x03, 0x01, 0x02, 0x03}
	// version 3 under a checksum that covers it, and no field after the version: refused by a
	// sentence that carries no sentinel ("an invite with no group_id")
	noFields := withChecksum([]byte{0x00, 0x03})

	_, older := urmessage.ParseInvite(versionTwo)
	_, ownCode := urmessage.ParseInvite(ownJoinCode)
	_, notWhole := urmessage.ParseInvite(damaged)
	_, empty := urmessage.ParseInvite(noFields)
	anotherKeyPackage := fmt.Errorf("%w: %w", urmessage.ErrNoJoinCodeForInvite,
		errors.New("messagegroup: no key package in this store is the one this welcome is addressed to"))
	refusedInsideTheWindow := fmt.Errorf("%w: %w", urmessage.ErrJoinRefused, urmessage.ErrJoinSealUnauthenticated)

	if !errors.Is(older, urmessage.ErrInviteVersion) {
		t.Fatalf("an invitation at version 2 answered %v, want ErrInviteVersion", older)
	}
	// A JOIN CODE PASTED WHERE THE INVITATION GOES IS REFUSED BY VERSION TOO: a key package begins
	// with MLS's own version, 0x0001. Which is why that case is told apart by its octets, below.
	if !errors.Is(ownCode, urmessage.ErrInviteVersion) {
		t.Fatalf("this peer's own join code, parsed as an invitation, answered %v, want ErrInviteVersion", ownCode)
	}
	if !errors.Is(notWhole, urmessage.ErrInviteDamaged) {
		t.Fatalf("five octets at version 3 answered %v, want ErrInviteDamaged", notWhole)
	}
	if empty == nil || errors.Is(empty, urmessage.ErrInviteDamaged) || errors.Is(empty, urmessage.ErrInviteVersion) {
		t.Fatalf("a version and a checksum and nothing else answered %v, want a refusal with no sentinel", empty)
	}

	rows := []struct {
		name   string
		advice string
		want   string
	}{
		{"an invitation made from another join code", joinAdvice(anotherKeyPackage), "another join code"},
		{"an invitation made by an older build", parseAdvice(older, versionTwo, ownJoinCode), "older URmessage"},
		{"this peer's own join code pasted as the invitation", parseAdvice(ownCode, ownJoinCode, ownJoinCode), "OWN join code"},
		{"a code that is not an invitation", parseAdvice(notWhole, damaged, ownJoinCode), "not an invitation"},
		{"a join refused for another reason", joinAdvice(refusedInsideTheWindow), "the library's own reason"},
	}
	if got := parseAdvice(empty, noFields, ownJoinCode); got != parseAdvice(notWhole, damaged, ownJoinCode) {
		t.Errorf("a parse refused with no sentinel is told %q; want what a damaged one is told", got)
	}
	seen := map[string]string{}
	for _, row := range rows {
		if !strings.Contains(row.advice, row.want) {
			t.Errorf("%s: the advice is %q; want it to say %q", row.name, row.advice, row.want)
		}
		if earlier, twice := seen[row.advice]; twice {
			t.Errorf("%s and %s are told the same thing: %q", earlier, row.name, row.advice)
		}
		seen[row.advice] = row.name
	}
}

// ── deletes ──────────────────────────────────────────────────────────────────────────────────

// A DELETE IS SHOWN, ONCE, WHEN A LINE ALREADY SEEN FLIPS. The owner's session on build 03 (S1)
// found that a delete printed nothing: converse printed each line once, when it arrived, and a
// tombstone adds no line of its own -- it flips Deleted on a line already shown.
func TestADeleteIsShownOnceWhenALineAlreadySeenFlips(t *testing.T) {
	known := map[string]bool{}
	// the log as a run starts: one line, and one deleted before the run; neither is a flip
	if got := deletionFlips(known, []*urmessage.Message{logLine(1, 5, false), logLine(2, 6, true)}); len(got) != 0 {
		t.Fatalf("the first reading of the log answered records %v; want none: nothing changed under this run", records(got))
	}
	// line 1 is deleted, and line 3 arrives deleted already: only line 1 flipped
	flipped := deletionFlips(known, []*urmessage.Message{logLine(1, 5, true), logLine(2, 6, true), logLine(3, 9, true)})
	if len(flipped) != 1 || flipped[0].RecordId != 5 {
		t.Fatalf("after line 1's delete the flips are records %v; want exactly record 5", records(flipped))
	}
	// and it is said once: the same log read again answers nothing
	if got := deletionFlips(known, []*urmessage.Message{logLine(1, 5, true), logLine(2, 6, true), logLine(3, 9, true)}); len(got) != 0 {
		t.Errorf("the same log read again answered records %v; want none", records(got))
	}
	// the line it prints names the line's short id, its sender and its record
	shown := deletionLine(flipped[0])
	for _, want := range []string{"DELETED", short(flipped[0].MessageId), "from " + short(flipped[0].SenderHandle), "record 5", "deleted=true"} {
		if !strings.Contains(shown, want) {
			t.Errorf("the delete is shown as %q, which does not say %q", shown, want)
		}
	}
}

// THE REPORT LISTS THE WHOLE LOG, A ROW A LINE, each with whether it is deleted, its kind and who
// sent it, so a delete that arrived while nobody watched is still on the record at the end.
func TestTheReportListsTheWholeLogWithEachLinesDeletedFlag(t *testing.T) {
	kept := logLine(1, 5, false)
	gone := logLine(2, 7, true)
	gone.Kind = urmessage.KindReply
	gone.Mine = true
	rows := logRows([]*urmessage.Message{kept, gone})
	if len(rows) != 2 {
		t.Fatalf("the report has %d row(s) for a log of 2: %q", len(rows), rows)
	}
	for at, want := range [][]string{
		{"record 5", short(kept.MessageId), "from " + short(kept.SenderHandle), "kind=" + kept.Kind.String(), "deleted=false", "mine=false"},
		{"record 7", short(gone.MessageId), "from " + short(gone.SenderHandle), "kind=" + gone.Kind.String(), "deleted=true", "mine=true"},
	} {
		for _, fragment := range want {
			if !strings.Contains(rows[at], fragment) {
				t.Errorf("row %d is %q, which does not say %q", at, rows[at], fragment)
			}
		}
	}
}

// AN OUTBOX LINE THAT IS EXACTLY /delete DELETES, whitespace aside; any other line is sent.
func TestOnlyAnOutboxLineThatIsExactlyDeleteDeletes(t *testing.T) {
	for _, line := range []string{"/delete", "  /delete\r", "\t/delete "} {
		if !isDeleteDirective(line) {
			t.Errorf("%q was not taken as /delete", line)
		}
	}
	for _, line := range []string{"/delete that one", "please /delete", "/Delete", "/deleted", ""} {
		if isDeleteDirective(line) {
			t.Errorf("%q was taken as /delete; it is a line to send", line)
		}
	}
}

// logLine is one line of a log: a text from a member, at a record, deleted or not.
func logLine(id byte, record uint64, deleted bool) *urmessage.Message {
	return &urmessage.Message{
		RecordId:     record,
		MessageId:    bytes.Repeat([]byte{id}, 16),
		SenderHandle: bytes.Repeat([]byte{0xa0 | id}, 16),
		Kind:         urmessage.KindText,
		Deleted:      deleted,
	}
}

func records(messages []*urmessage.Message) []uint64 {
	ids := []uint64{}
	for _, one := range messages {
		ids = append(ids, one.RecordId)
	}
	return ids
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────

// THE APP'S OWN CODEC, PORTED LINE FOR LINE, so that "the form the app takes" is a test and not a
// reading of somebody else's source: urnetwork/message-windows 39df6d92,
// app/src/App/Live/LiveMesh.cpp, EncodeBase64 (lines 640-660) and DecodeBase64 (666-694). Out:
// RFC 4648 base64 with padding and no line breaks. In: whitespace skipped, padding optional, any
// other character, and data after padding, refused.
func appEncodeBase64(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := []byte{}
	at := 0
	for ; at+2 < len(data); at += 3 {
		v := uint32(data[at])<<16 | uint32(data[at+1])<<8 | uint32(data[at+2])
		out = append(out, alphabet[(v>>18)&63], alphabet[(v>>12)&63], alphabet[(v>>6)&63], alphabet[v&63])
	}
	if at < len(data) {
		two := at+1 < len(data)
		v := uint32(data[at]) << 16
		if two {
			v |= uint32(data[at+1]) << 8
		}
		out = append(out, alphabet[(v>>18)&63], alphabet[(v>>12)&63])
		if two {
			out = append(out, alphabet[(v>>6)&63])
		} else {
			out = append(out, '=')
		}
		out = append(out, '=')
	}
	return string(out)
}

func appDecodeBase64(text string) ([]byte, bool) {
	value := func(c byte) int {
		switch {
		case 'A' <= c && c <= 'Z':
			return int(c - 'A')
		case 'a' <= c && c <= 'z':
			return int(c-'a') + 26
		case '0' <= c && c <= '9':
			return int(c-'0') + 52
		case c == '+':
			return 62
		case c == '/':
			return 63
		}
		return -1
	}
	out := []byte{}
	var acc uint32
	bits, pad := 0, 0
	for at := 0; at < len(text); at += 1 {
		c := text[at]
		if c == ' ' || c == '\r' || c == '\n' || c == '\t' {
			continue
		}
		if c == '=' {
			pad += 1
			continue
		}
		if pad != 0 {
			return nil, false
		}
		v := value(c)
		if v < 0 {
			return nil, false
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if 8 <= bits {
			bits -= 8
			out = append(out, byte(acc>>bits))
		}
	}
	if 2 < pad {
		return nil, false
	}
	return out, len(out) != 0
}

// wrapEvery breaks text into lines of width characters, the way a mail client wraps a long line.
func wrapEvery(text string, width int, newline string) string {
	lines := []string{}
	for width < len(text) {
		lines = append(lines, text[:width])
		text = text[width:]
	}
	return strings.Join(append(lines, text), newline)
}

// inviteAtVersionTwo is an invitation in version two's shape, which an older build wrote: the
// version, five fields each under this corpus's one length prefix (a big-endian uint32, as
// syntax.Writer.WriteOpaqueLP writes it) -- group_id, welcome, ratchet_tree, and the two join
// secrets in the clear that version three seals -- and the SHA-256 of all of it, so that what is
// refused is the version and not a damaged paste.
func inviteAtVersionTwo() []byte {
	encoded := binary.BigEndian.AppendUint16(nil, 0x0002)
	for _, field := range [][]byte{
		bytes.Repeat([]byte{0x11}, 32),
		[]byte("a welcome"),
		[]byte("a ratchet tree"),
		bytes.Repeat([]byte{0x22}, 32),
		bytes.Repeat([]byte{0x33}, 32),
	} {
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(field)))
		encoded = append(encoded, field...)
	}
	return withChecksum(encoded)
}

// withChecksum is the octets followed by the SHA-256 of them, as an invitation ends.
func withChecksum(octets []byte) []byte {
	sum := sha256.Sum256(octets)
	return append(append([]byte(nil), octets...), sum[:]...)
}

// helloClient is a connect client whose server answers Hello, with a nonce, and nothing else: the
// smallest thing a device can be connected through. The answer is delivered on another goroutine,
// because the transport is still inside its own send when the request leaves it.
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
			Hello: &protocol.HelloResponse{ServerNonce: []byte("livepeer's test server nonce")},
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

// identifiedDevice is a real urmessage.Device over durable stores in a temp directory, connected
// through a [helloClient], with the identity a person sets up: the words offered, typed back, and the
// identity made (identity phase 1's Task 12). A device with no identity publishes no join code.
func identifiedDevice(t *testing.T) *urmessage.Device {
	t.Helper()
	device := deviceOver(t, &helloClient{})
	ctx := context.Background()
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	words, err := device.CreateIdentity()
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	typed := strings.Join(words, " ")
	clear(words)
	if err := device.ConfirmWords(ctx, typed); err != nil {
		t.Fatalf("ConfirmWords: %v", err)
	}
	return device
}

// deviceOver is a real urmessage.Device over durable stores in a temp directory and a transport over
// the client given.
func deviceOver(t *testing.T, client sdk.MessageTransportClient) *urmessage.Device {
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
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: stateStore,
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

// ── the peer's identity (identity phase 1's Task 15) ──────────────────────────────────────────

// THE PEER MAKES ITS IDENTITY AS A PERSON DOES (LRI R81): connected, the words offered, typed back, and
// the identity made, its self group founded under the connection; and a second call, as a restart
// over the same -dir makes, reads it back and makes nothing. A device that is not connected makes
// none. What it prints is digests only, in a line whose whole shape is fixed, so that no word of the
// phrase has room in it (Property 1).
func TestAPeerMakesItsIdentityAsAPersonDoes(t *testing.T) {
	ctx := context.Background()
	device := deviceOver(t, &helloClient{})
	if _, _, err := ensureIdentity(ctx, device); err == nil {
		t.Fatalf("a device that is not connected made an identity")
	}
	if _, err := device.Identity(); !errors.Is(err, urmessage.ErrNoIdentity) {
		t.Fatalf("after the refused typing back the device's identity answers %v, want ErrNoIdentity", err)
	}
	if err := device.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	line, made, err := ensureIdentity(ctx, device)
	if err != nil || !made {
		t.Fatalf("ensureIdentity answered made %v, %v", made, err)
	}
	identity, err := device.Identity()
	if err != nil || len(identity.AccountId) != 36 || len(identity.DeviceId) != 19 || !identity.PhraseDevice {
		t.Fatalf("the identity made is %v (%v)", identity, err)
	}
	digests := "account " + digestOf([]byte(identity.AccountId)) + ", device " + digestOf([]byte(identity.DeviceId))
	shape := regexp.MustCompile(`^an identity, made as a person makes one: account sha256:[0-9a-f]{16}, device sha256:[0-9a-f]{16}; its words typed back and cleared$`)
	// a failure names the line by its size and digest and never prints it: a line that carried the
	// words would put them in the log (LRI R84 item 6; review X-LIB-7)
	if !shape.MatchString(line) || !strings.Contains(line, digests) {
		t.Errorf("the line (%d octets, %s) is not exactly %q with the identity's digests", len(line), digestOf([]byte(line)), shape)
	}
	again, made, err := ensureIdentity(ctx, device)
	if err != nil || made {
		t.Fatalf("a second call answered made %v, %v: want the identity read back", made, err)
	}
	if want := "this peer's identity, read back: " + digests; again != want {
		t.Errorf("the second line (%d octets, %s) is not the read-back line with the identity's digests", len(again), digestOf([]byte(again)))
	}
}

// THE ROSTER IS PRINTED BY IDENTITY: a line per identity, in the order of its first leaf, with its
// devices, each its leaf, role and device ID's digest; this peer's own identity marked; a leaf no
// identity binds said to be one; digests only.
func TestTheRosterIsPrintedByIdentity(t *testing.T) {
	alice, bob := bytes.Repeat([]byte{0xA1}, 32), bytes.Repeat([]byte{0xB0}, 32)
	members := []urmessage.Member{
		{LeafIndex: 0, IdentityPub: []byte("alice's key"), Role: "owner", Identity: alice, DeviceId: "aaaa-aaaa-aaaa-aaa1"},
		{LeafIndex: 1, IdentityPub: []byte("bob's key"), Role: "member", Mine: true, Identity: bob, DeviceId: "bbbb-bbbb-bbbb-bbb1"},
		{LeafIndex: 2, IdentityPub: []byte("alice's key"), Role: "owner", Identity: alice, DeviceId: "aaaa-aaaa-aaaa-aaa2"},
		{LeafIndex: 3, IdentityPub: []byte("a key"), Role: "member"},
	}
	want := []string{
		"identity " + digestOf(alice) + ": 2 devices: leaf 0 owner device " + digestOf([]byte("aaaa-aaaa-aaaa-aaa1")) +
			", leaf 2 owner device " + digestOf([]byte("aaaa-aaaa-aaaa-aaa2")),
		"identity " + digestOf(bob) + " (this peer): 1 device: leaf 1 member device " + digestOf([]byte("bbbb-bbbb-bbbb-bbb1")),
		"a leaf no identity binds: leaf 3 member",
	}
	lines := rosterByIdentity(members)
	if !slices.Equal(lines, want) {
		t.Fatalf("the roster by identity is\n%q\nwant\n%q", lines, want)
	}
	for _, line := range lines {
		for _, plain := range []string{fmt.Sprintf("%x", alice[:4]), fmt.Sprintf("%x", bob[:4]), "aaaa-aaaa", "bbbb-bbbb"} {
			if strings.Contains(line, plain) {
				t.Errorf("the line %q carries %q itself, and not its digest", line, plain)
			}
		}
	}
}
