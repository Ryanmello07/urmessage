package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/message/messagegroup"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
	"github.com/urnetwork/message/sdk/urmessage"
)

// THE IDENTITY EXPORTS (identity phase 1's Task 14; Spec A section 9.3a), driven at the Go level over a
// real Device. The C consumer drives the same exports through a real server; what is here is what C
// cannot hold on this host: the race detector, and the properties read off every answer.
//
//   - Property 1: no export answers a system group.
//   - Property 2: no export answers a phrase secret. The words leave urnet_message_device_create_identity
//     and nothing else, and no other export carries them.

// identityAnsweringClient answers every Hello with a nonce, from inside SendWithTimeout: the smallest
// thing that can connect a Device, so that ConfirmWords founds the self group under a connection. It
// is urmessage's own test client, spelled here because a test file of package main cannot import it.
type identityAnsweringClient struct {
	mutex   sync.Mutex
	receive connect.ReceiveFunction
}

func (self *identityAnsweringClient) AddReceiveCallback(receiveCallback connect.ReceiveFunction) func() {
	self.mutex.Lock()
	self.receive = receiveCallback
	self.mutex.Unlock()
	return func() {}
}

func (self *identityAnsweringClient) SendWithTimeout(frame *connectprotocol.Frame, destination connect.Id,
	ackCallback connect.AckFunction, timeout time.Duration, opts ...any) bool {

	if frame.GetMessageType() != connectprotocol.MessageType_MessageMessageServerRequest {
		return true
	}
	request := &messageprotocol.MessageServerRequest{}
	if proto.Unmarshal(frame.GetMessageBytes(), request) != nil {
		return false
	}
	self.mutex.Lock()
	receive := self.receive
	self.mutex.Unlock()
	if receive == nil {
		return false
	}
	response := &messageprotocol.MessageServerResponse{
		RequestId: request.GetRequestId(),
		Reason:    messageprotocol.Reason_REASON_OK,
		Body: &messageprotocol.MessageServerResponse_Hello{
			Hello: &messageprotocol.HelloResponse{ServerNonce: []byte("the identity exports' server nonce")},
		},
	}
	encoded, err := proto.Marshal(response)
	if err != nil {
		return false
	}
	go receive(connect.TransferPath{}, []*connectprotocol.Frame{{
		MessageType:  connectprotocol.MessageType_MessageMessageServerResponse,
		MessageBytes: encoded,
	}}, connect.Peer{})
	return true
}

// identityDevice is one connected Device over a durable store in a directory of the test's, as a
// handle the exports take, with the test seam's stretch (LRI R76 item 10).
type identityDevice struct {
	device *urmessage.Device
	handle uint64
	dir    string
	store  *urmessage.DurableStateStore
	// closes the device and its two stores, once, so that a restart can open the directory again
	close func()
}

func newIdentityDevice(t *testing.T, dir string) *identityDevice {
	t.Helper()
	return newIdentityDeviceDrawingFrom(t, dir, nil)
}

// newIdentityDeviceDrawingFrom is newIdentityDevice whose device draws its randomness from the reader
// given: its keys, at NewDevice, and its account ID's salt, when its identity is made.
func newIdentityDeviceDrawingFrom(t *testing.T, dir string, random io.Reader) *identityDevice {
	t.Helper()
	return newIdentityDeviceOver(t, dir, random, nil)
}

// newIdentityDeviceOver is newIdentityDeviceDrawingFrom whose device keeps its state through the
// armed store given, when it is not nil: the durable store opened in dir, wrapped. The identityDevice's
// store is the durable store itself either way.
func newIdentityDeviceOver(t *testing.T, dir string, random io.Reader, armed *armedPanicStore) *identityDevice {
	t.Helper()
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          &identityAnsweringClient{},
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("the transport: %v", err)
	}
	t.Cleanup(transport.Close)
	streamStore, err := sdk.OpenStreamStore(filepath.Join(dir, "stream"))
	if err != nil {
		t.Fatalf("the stream store: %v", err)
	}
	stateStore, err := urmessage.OpenDurableStateStore(filepath.Join(dir, "state"))
	if err != nil {
		streamStore.Close()
		t.Fatalf("the state store: %v", err)
	}
	config := urmessage.DeviceConfig{
		PhraseStretch: messagegroup.FastPhraseStretchForTests(),
		Transport:     transport,
		Reserver:      sdk.NewStreamIndexReserver(streamStore),
		StateStore:    stateStore,
		Random:        random,
		Connect:       urmessage.ConnectPolicy{Budget: 30 * time.Second, AttemptTimeout: 2 * time.Second},
	}
	if armed != nil {
		armed.DurableStateStore = stateStore
		config.StateStore = armed
	}
	device, err := urmessage.NewDevice(config)
	if err != nil {
		streamStore.Close()
		stateStore.Close()
		t.Fatalf("NewDevice: %v", err)
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			device.Close()
			streamStore.Close()
			stateStore.Close()
		})
	}
	t.Cleanup(closeAll)
	if err := device.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	handle := newHandle(device)
	t.Cleanup(func() { handleRelease(handle) })
	return &identityDevice{device: device, handle: handle, dir: dir, store: stateStore, close: closeAll}
}

// exportOutError is a char** out_error as a test passes one, and what was written through it.
type exportOutError struct {
	at unsafe.Pointer
}

func (self *exportOutError) pointer() unsafe.Pointer {
	return unsafe.Pointer(&self.at)
}

// take answers the text written through it, and frees it.
func (self *exportOutError) take(t *testing.T) string {
	t.Helper()
	if self.at == nil {
		return ""
	}
	text := goStringAt(self.at)
	callExportNil(t, urnet_free_string, self.at)
	self.at = nil
	return text
}

// createIdentity calls urnet_message_device_create_identity as a C caller does, sizing first, and
// answers the words, or the out_error it wrote.
func createIdentity(t *testing.T, handle uint64) ([]string, string) {
	t.Helper()
	var length int32
	var outError exportOutError
	callExportNil(t, urnet_message_device_create_identity, handle, nil, unsafe.Pointer(&length), outError.pointer())
	if failure := outError.take(t); failure != "" {
		return nil, failure
	}
	if length <= 0 {
		t.Fatalf("create_identity sized the words at %d octets", length)
	}
	buffer := make([]byte, length)
	if !callExportNil(t, urnet_message_device_create_identity, handle, unsafe.Pointer(&buffer[0]),
		unsafe.Pointer(&length), outError.pointer())[0].Bool() {
		t.Fatalf("create_identity did not fill a buffer of the size it named: %s", outError.take(t))
	}
	return strings.Split(string(buffer[:length]), " "), ""
}

// confirmWords calls urnet_message_device_confirm_words with the words typed back, and answers the
// kind, the positions handed back and the out_error.
func confirmWords(t *testing.T, handle uint64, typed string) (int32, []int32, string) {
	t.Helper()
	kind, positions, count, failure := confirmWordsInto(t, handle, typed, 25)
	if int(count) != len(positions) {
		t.Fatalf("confirm_words counted %d positions past a capacity of 25", count)
	}
	return kind, positions, failure
}

// confirmWordsInto is confirmWords with a positions buffer of the capacity given. It answers the
// positions copied, and *inout_count as the export left it, which may be more.
func confirmWordsInto(t *testing.T, handle uint64, typed string, capacity int) (int32, []int32, int32, string) {
	t.Helper()
	// one octet past the words, so that no typed input is an empty buffer to take the address of
	octets := append([]byte(typed), 0)
	positions := make([]int32, capacity+1)
	count := int32(capacity)
	var outError exportOutError
	kind := int32(callExportNil(t, urnet_message_device_confirm_words, handle, uint64(0), unsafe.Pointer(&octets[0]),
		int32(len(typed)), unsafe.Pointer(&positions[0]), unsafe.Pointer(&count), outError.pointer())[0].Int())
	if count < 0 {
		t.Fatalf("confirm_words counted %d positions", count)
	}
	if positions[capacity] != 0 {
		t.Fatalf("confirm_words wrote past the capacity of %d it was handed", capacity)
	}
	return kind, positions[:min(int(count), capacity)], count, outError.take(t)
}

// identityJson calls urnet_message_device_identity and answers the json and the out_error.
func identityJson(t *testing.T, handle uint64) (string, string) {
	t.Helper()
	var outError exportOutError
	answer := callExportNil(t, urnet_message_device_identity, handle, outError.pointer())[0]
	failure := outError.take(t)
	if answer.IsNil() {
		return "", failure
	}
	text := goStringAt(answer.UnsafePointer())
	callExportNil(t, urnet_free_string, answer.UnsafePointer())
	return text, failure
}

// checkWord calls urnet_message_device_check_word over one typed word.
func checkWord(t *testing.T, word string) bool {
	t.Helper()
	octets := append([]byte(word), 0)
	return callExportNil(t, urnet_message_device_check_word, unsafe.Pointer(&octets[0]), int32(len(word)))[0].Bool()
}

// THE IDENTITY IS MADE THROUGH THE EXPORTS, AS A C CALLER MAKES IT, AND A WRONG WORD IS NAMED BY ITS
// POSITION. Before anything: the identity json says there is none, and a confirm with no words offered
// is NOT_OFFERED. create_identity answers 25 words, the same ones asked again (Back). Typed back with
// one word replaced by another list word, and with one left out, the confirm is WRONG and names the
// position, and nothing is made. Typed back right, it is OK, and the identity json is the device's own
// Identity, field for field. After it: create_identity refuses, and a confirm is IDENTITY_EXISTS.
func TestTheIdentityExportsMakeTheIdentityAndNameAWrongWord(t *testing.T) {
	one := newIdentityDevice(t, t.TempDir())
	before, failure := identityJson(t, one.handle)
	if failure != "" || !strings.Contains(before, `"has_identity":false`) {
		t.Fatalf("before any identity the identity json (%d octets) does not say has_identity false (%s)", len(before), failure)
	}
	if kind, _, _ := confirmWords(t, one.handle, "abandon"); kind != messageWordsNotOffered {
		t.Fatalf("a confirm with no words offered answered kind %d, want NOT_OFFERED", kind)
	}

	words, failure := createIdentity(t, one.handle)
	if failure != "" || len(words) != 25 {
		t.Fatalf("create_identity answered %d words (%s), want 25", len(words), failure)
	}
	again, _ := createIdentity(t, one.handle)
	if !slices.Equal(again, words) {
		t.Fatal("create_identity asked again before the identity is made answered other words, and Back must show the same")
	}

	// A WRONG WORD, NAMED BY ITS POSITION: the seventh replaced by another list word
	wrong := slices.Clone(words)
	wrong[6] = "zoo"
	if words[6] == "zoo" {
		wrong[6] = "abandon"
	}
	if kind, positions, _ := confirmWords(t, one.handle, strings.Join(wrong, " ")); kind != messageWordsWrong || !slices.Equal(positions, []int32{7}) {
		t.Fatalf("a confirm with the seventh word wrong answered kind %d naming %v, want WRONG naming [7]", kind, positions)
	}
	// AND A WORD LEFT OUT: every position from the gap on is named
	if kind, positions, _ := confirmWords(t, one.handle, strings.Join(words[:24], " ")); kind != messageWordsWrong || !slices.Contains(positions, 25) {
		t.Fatalf("a confirm with the last word left out answered kind %d naming %v, want WRONG naming 25", kind, positions)
	}
	if _, err := one.device.Identity(); err == nil {
		t.Fatal("a wrong confirm made an identity")
	}

	// RIGHT: the identity is made, and the json is the device's own Identity
	if kind, positions, failure := confirmWords(t, one.handle, strings.ToUpper(strings.Join(words, "  "))); kind != messageWordsOk {
		t.Fatalf("the words typed back answered kind %d naming %v (%s), want OK", kind, positions, failure)
	}
	made, err := one.device.Identity()
	if err != nil {
		t.Fatalf("the device's Identity after OK: %v", err)
	}
	text, failure := identityJson(t, one.handle)
	if failure != "" {
		t.Fatalf("the identity json after OK: %s", failure)
	}
	var decoded deviceIdentityInfo
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("the identity json (%d octets) does not decode: %v", len(text), err)
	}
	if !decoded.HasIdentity || decoded.AccountId != made.AccountId || decoded.DeviceId != made.DeviceId ||
		decoded.PhraseDevice != made.PhraseDevice || len(decoded.Devices) != len(made.Devices) {
		t.Fatalf("the identity json is %+v, and the device's Identity is %+v", decoded, made)
	}
	for at, device := range made.Devices {
		row := decoded.Devices[at]
		if row.DeviceId != device.DeviceId || row.PhraseDevice != device.PhraseDevice || row.ThisDevice != device.ThisDevice {
			t.Errorf("device %d of the json is %+v, and of the Identity %+v", at, row, device)
		}
	}
	if len(decoded.AccountId) != 36 || len(decoded.DeviceId) != 19 {
		t.Errorf("the account ID is %d characters and the device ID %d, want 36 and 19", len(decoded.AccountId), len(decoded.DeviceId))
	}

	// AFTER IT
	if words, failure := createIdentity(t, one.handle); words != nil || failure == "" {
		t.Fatal("create_identity answered words after the identity was made")
	}
	if kind, _, _ := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsIdentityExists {
		t.Fatalf("a confirm after the identity was made answered kind %d, want IDENTITY_EXISTS", kind)
	}
}

// THE SINGLE-WORD CHECK IS THE LIST'S OWN, THROUGH THE PHRASE'S FOLD (LRI R68's L3-10): a list word,
// in any case and with spaces about it, is a word; anything else is not, two words included.
func TestTheCheckWordExportIsTheListsOwnCheck(t *testing.T) {
	for _, row := range []struct {
		typed string
		want  bool
	}{
		{"abandon", true},
		{"zoo", true},
		{"  Abandon  ", true},
		{"ABANDON", true},
		{"abandonn", false},
		{"", false},
		{"abandon zoo", false},
		{"not-a-word", false},
	} {
		if got := checkWord(t, row.typed); got != row.want {
			t.Errorf("check_word(%q) answered %v, want %v", row.typed, got, row.want)
		}
	}
}

// THE MEMBER JSON CARRIES THE DEVICE ID AND THE IDENTITY (Spec A section 9.3a): a founder's own row
// in a conversation names its device ID and its identity's root, the values the identity json and the
// device's Identity carry.
func TestTheMemberJsonCarriesTheDeviceIdAndTheIdentity(t *testing.T) {
	one := newIdentityDevice(t, t.TempDir())
	words, _ := createIdentity(t, one.handle)
	if kind, _, failure := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsOk {
		t.Fatalf("confirm_words answered kind %d (%s)", kind, failure)
	}
	made, err := one.device.Identity()
	if err != nil {
		t.Fatal(err)
	}
	group, err := one.device.CreateGroup(context.Background(), bytes.Repeat([]byte{0x14}, urmessage.GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	members, err := group.Members()
	if err != nil || len(members) != 1 {
		t.Fatalf("the founder's roster holds %d members (%v)", len(members), err)
	}
	list := newHandle(&memberList{members: members})
	defer handleRelease(list)
	row := callExport(t, urnet_message_member_list_info, list, 0)[0]
	if row.IsNil() {
		t.Fatal("the founder's row answered NULL")
	}
	text := goStringAt(row.UnsafePointer())
	callExportNil(t, urnet_free_string, row.UnsafePointer())
	var decoded map[string]any
	if err := json.Unmarshal([]byte(text), &decoded); err != nil {
		t.Fatalf("the row %q: %v", text, err)
	}
	if decoded["device_id"] != made.DeviceId {
		t.Errorf("the row's device_id is %v, and the device's own ID is %s", decoded["device_id"], made.DeviceId)
	}
	if decoded["identity"] != hex.EncodeToString(members[0].IdentityPub) {
		t.Errorf("the row's identity is %v, and the identity key the leaf names is %x", decoded["identity"], members[0].IdentityPub)
	}
}

// NO EXPORT ANSWERS A SYSTEM GROUP (Property 1). A device with an identity holds its self group, a
// system group, and one conversation; the group list export answers the conversation and nothing
// else, and so does the restore's, which restores the self group and answers none of it.
//
// THE CONTROL: the device does hold the self group -- the store holds one group record, which is not
// the conversation's, since a conversation at epoch 0 writes none, and the restart restores it -- so
// the lists leaving it out is the exports leaving it out, not its absence.
func TestTheGroupListExportAnswersConversationsOnly(t *testing.T) {
	dir := t.TempDir()
	one := newIdentityDevice(t, dir)
	words, _ := createIdentity(t, one.handle)
	if kind, _, failure := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsOk {
		t.Fatalf("confirm_words answered kind %d (%s)", kind, failure)
	}
	groupId := bytes.Repeat([]byte{0x15}, urmessage.GroupIdBytes)
	if _, err := one.device.CreateGroup(context.Background(), groupId); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	ids := groupListIds(t, callExport(t, urnet_message_device_groups, one.handle)[0].Uint())
	if len(ids) != 1 || !bytes.Equal(ids[0], groupId) {
		t.Fatalf("the group list export answers %d group(s), want the conversation alone", len(ids))
	}

	// THE RESTORE'S LIST, over the same store: the self group comes back and is answered by nothing
	one.close()
	restarted := newIdentityDevice(t, dir)
	var outError exportOutError
	restored := callExportNil(t, urnet_message_device_restore, restarted.handle, uint64(0), outError.pointer())[0].Uint()
	if failure := outError.take(t); failure != "" {
		t.Fatalf("the restore: %s", failure)
	}
	if ids := groupListIds(t, restored); len(ids) != 0 {
		t.Fatalf("the restore export answers %d group(s), and the store holds no conversation it could restore", len(ids))
	}
	if ids := groupListIds(t, callExport(t, urnet_message_device_groups, restarted.handle)[0].Uint()); len(ids) != 0 {
		t.Fatalf("after the restore the group list export answers %d group(s)", len(ids))
	}
	// THE CONTROL: the store holds the self group's record, by its own id: the one record it holds,
	// and not the conversation's
	if _, err := restarted.device.KeyPackage(); err != nil {
		t.Fatalf("CONTROL FAILED: the restarted device has no identity: %v", err)
	}
	records, err := restarted.store.GroupRecords()
	if err != nil || len(records) != 1 || bytes.Equal(records[0].GroupId, groupId) {
		t.Fatalf("CONTROL FAILED: the store holds %d group record(s) (%v), want the self group's alone", len(records), err)
	}
}

// groupListIds reads a group list handle's groups' ids, and releases it.
func groupListIds(t *testing.T, list uint64) [][]byte {
	t.Helper()
	if list == 0 {
		return nil
	}
	defer handleRelease(list)
	ids := [][]byte{}
	count := int(callExport(t, urnet_message_group_list_count, list)[0].Int())
	for at := 0; at < count; at += 1 {
		group := callExport(t, urnet_message_group_list_at, list, at)[0].Uint()
		id := make([]byte, urmessage.GroupIdBytes)
		length := int32(len(id))
		if !callExportNil(t, urnet_message_group_id, group, unsafe.Pointer(&id[0]), unsafe.Pointer(&length))[0].Bool() {
			t.Fatalf("group %d of the list answers no id", at)
		}
		handleRelease(group)
		ids = append(ids, id[:length])
	}
	return ids
}

// NO EXPORT ANSWERS A PHRASE SECRET (Property 2). The words leave create_identity; after the identity
// is made, every export that answers text about this device, its identity or a group of it is asked,
// and none carries the words: not two of them in a row, whatever lies between, and not half of them in
// any order.
//
// THE CONTROL: the reader finds the words where they are -- in create_identity's own answer.
func TestNoExportAnswersAPhraseSecret(t *testing.T) {
	one := newIdentityDevice(t, t.TempDir())
	words, failure := createIdentity(t, one.handle)
	if failure != "" {
		t.Fatalf("create_identity: %s", failure)
	}
	if leaked := phraseIn(words, strings.Join(words, " ")); leaked == "" {
		t.Fatal("CONTROL FAILED: the reader does not find the words in create_identity's own answer")
	}
	answers := map[string]string{}
	before, _ := identityJson(t, one.handle)
	answers["the identity json before the identity"] = before
	// a 25th word that is not the 25th word shown, so that this confirm is wrong on every phrase
	other := "zoo"
	if words[24] == other {
		other = "abandon"
	}
	_, _, wrongFailure := confirmWords(t, one.handle, strings.Join(append(slices.Clone(words[:24]), other), " "))
	answers["a wrong confirm's out_error"] = wrongFailure
	kind, _, okFailure := confirmWords(t, one.handle, strings.Join(words, " "))
	if kind != messageWordsOk {
		t.Fatalf("confirm_words answered kind %d (%s)", kind, okFailure)
	}
	answers["the right confirm's out_error"] = okFailure
	after, _ := identityJson(t, one.handle)
	answers["the identity json"] = after
	group, err := one.device.CreateGroup(context.Background(), bytes.Repeat([]byte{0x16}, urmessage.GroupIdBytes))
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	groupHandle := newHandle(group)
	defer handleRelease(groupHandle)
	members, err := group.Members()
	if err != nil {
		t.Fatal(err)
	}
	list := newHandle(&memberList{members: members})
	defer handleRelease(list)
	for at := range members {
		row := callExport(t, urnet_message_member_list_info, list, at)[0]
		answers[fmt.Sprintf("member %d's json", at)] = goStringAt(row.UnsafePointer())
		callExportNil(t, urnet_free_string, row.UnsafePointer())
	}
	for name, fn := range map[string]any{
		"the group's stats":   urnet_message_group_stats,
		"the group's removal": urnet_message_group_removal,
	} {
		answer := callExport(t, fn, groupHandle)[0]
		answers[name] = goStringAt(answer.UnsafePointer())
		callExportNil(t, urnet_free_string, answer.UnsafePointer())
	}
	var roleError exportOutError
	role := callExportNil(t, urnet_message_group_my_role, groupHandle, roleError.pointer())[0]
	answers["the group's role"] = goStringAt(role.UnsafePointer())
	callExportNil(t, urnet_free_string, role.UnsafePointer())
	answers["the role's out_error"] = roleError.take(t)
	var createError exportOutError
	callExportNil(t, urnet_message_device_create_identity, one.handle, nil, unsafe.Pointer(new(int32)), createError.pointer())
	answers["create_identity's refusal after the identity"] = createError.take(t)

	read := 0
	for name, answer := range answers {
		if answer != "" {
			read += 1
		}
		if leaked := phraseIn(words, answer); leaked != "" {
			// the shape and the size, and never the text, which carries the words
			t.Errorf("%s carries the words (%s), in %d octets", name, leaked, len(answer))
		}
	}
	if read < 6 {
		t.Fatalf("only %d of the answers held any text, so the reader read almost nothing", read)
	}
	t.Logf("%d answers read, none carrying the words", read)
}

// phraseIn answers how an answer carries a phrase's words, or "": two consecutive words with no more
// than four characters that are not letters between them, or at least half of the words as words of
// the answer, in any order.
func phraseIn(words []string, answer string) string {
	lower := strings.ToLower(answer)
	for at := 0; at+1 < len(words); at += 1 {
		pair := regexp.MustCompile(`\b` + regexp.QuoteMeta(words[at]) + `[^a-z]{1,4}` + regexp.QuoteMeta(words[at+1]) + `\b`)
		if pair.MatchString(lower) {
			return "words " + strconv.Itoa(at+1) + " and " + strconv.Itoa(at+2) + " in a row"
		}
	}
	tokens := map[string]bool{}
	for _, token := range regexp.MustCompile(`[a-z]+`).FindAllString(lower, -1) {
		tokens[token] = true
	}
	found := 0
	for _, word := range words {
		if tokens[word] {
			found += 1
		}
	}
	if len(words)/2 <= found {
		return strconv.Itoa(found) + " of the words"
	}
	return ""
}

// THE IDENTITY JSON CARRIES EVERY FIELD urmessage.Identity KEEPS, and every field of a device row
// urmessage.IdentityDevice keeps, by name: a field added there and not here reaches a C caller as
// nothing at all. has_identity is the json's own, beside them.
func TestTheIdentityJsonCarriesEveryFieldUrmessageKeeps(t *testing.T) {
	identity := &urmessage.Identity{
		AccountId:    "an account id",
		DeviceId:     "a device id",
		PhraseDevice: true,
		Devices:      []urmessage.IdentityDevice{{DeviceId: "a device id", PhraseDevice: true, ThisDevice: true}},
	}
	for _, pair := range []struct {
		kept    reflect.Type
		fixture reflect.Value
		carried reflect.Type
		value   reflect.Value
	}{
		{reflect.TypeOf(urmessage.Identity{}), reflect.ValueOf(*identity), reflect.TypeOf(deviceIdentityInfo{}),
			reflect.ValueOf(*deviceIdentityInfoOf(identity))},
		{reflect.TypeOf(urmessage.IdentityDevice{}), reflect.ValueOf(identity.Devices[0]), reflect.TypeOf(deviceIdentityDevice{}),
			reflect.ValueOf(deviceIdentityInfoOf(identity).Devices[0])},
	} {
		names := map[string]bool{}
		for at := 0; at < pair.carried.NumField(); at += 1 {
			names[pair.carried.Field(at).Name] = true
			if pair.value.Field(at).IsZero() {
				t.Errorf("%s.%s is declared and never assigned", pair.carried.Name(), pair.carried.Field(at).Name)
			}
		}
		for at := 0; at < pair.kept.NumField(); at += 1 {
			if pair.fixture.Field(at).IsZero() {
				t.Fatalf("this case's fixture leaves %s.%s at its zero value", pair.kept.Name(), pair.kept.Field(at).Name)
			}
			if name := pair.kept.Field(at).Name; !names[name] {
				t.Errorf("urmessage.%s keeps %s and the identity json does not carry it", pair.kept.Name(), name)
			}
		}
	}
}

// THE HEADER'S DOCUMENTED IDENTITY JSON IS THE JSON'S OWN, KEY FOR KEY AND IN ORDER, and so is its
// device row's: the member json's gate, over the identity.
func TestTheHeaderDocumentsExactlyTheIdentityJsonKeys(t *testing.T) {
	documented := headerJsonKeys(t, "char* urnet_message_device_identity(", "this device's identity as json:")
	carried := jsonKeysOf(t, &deviceIdentityInfo{Devices: []deviceIdentityDevice{}})
	if !reflect.DeepEqual(documented, carried) {
		t.Fatalf("the header documents the identity keys as\n  %v\nand the json carries\n  %v", documented, carried)
	}
	documentedRow := headerJsonKeys(t, "char* urnet_message_device_identity(", "the newest list's devices, each")
	carriedRow := jsonKeysOf(t, &deviceIdentityDevice{})
	if !reflect.DeepEqual(documentedRow, carriedRow) {
		t.Fatalf("the header documents a device row's keys as\n  %v\nand the json carries\n  %v", documentedRow, carriedRow)
	}
}

// THE HEADER'S URNET_MESSAGE_WORDS_* DEFINES ARE THE LIBRARY'S KINDS, BY NAME AND BY VALUE, both ways.
func TestTheHeaderDefinesExactlyTheWordsKinds(t *testing.T) {
	header, err := os.ReadFile("include/urnetwork_message.h")
	if err != nil {
		t.Fatalf("reading the header: %v", err)
	}
	defined := map[string]int32{}
	for _, match := range regexp.MustCompile(`(?m)^#define URNET_MESSAGE_WORDS_([A-Z_]+)\s+(\d+)`).FindAllStringSubmatch(string(header), -1) {
		value, err := strconv.ParseInt(match[2], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		defined[match[1]] = int32(value)
	}
	constants := map[string]int32{
		"OK":              messageWordsOk,
		"WRONG":           messageWordsWrong,
		"NOT_OFFERED":     messageWordsNotOffered,
		"IDENTITY_EXISTS": messageWordsIdentityExists,
		"FAILED":          messageWordsFailed,
	}
	if len(defined) < 2 {
		t.Fatalf("the header defines %d URNET_MESSAGE_WORDS_* kinds; the positive control is not met", len(defined))
	}
	if !reflect.DeepEqual(defined, constants) {
		t.Fatalf("the header defines the words kinds as %v and the library's constants are %v", defined, constants)
	}
}

// A PANIC INSIDE CONFIRM_WORDS ANSWERS FAILED, AND NO POSITION (LRI R84 item 3; review X-LIB-1).
// cgoGuard recovers a panic, and an unnamed result then answers its zero value, which is
// URNET_MESSAGE_WORDS_OK: an identity a caller is told exists, and *inout_count left at the
// capacity it passed in. The panic is real and inside the making: the device's own randomness, which
// the identity's account ID salt is drawn from, panics once armed.
//
// THE CONTROL: the same words, the reader disarmed, make the identity -- so the FAILED was the panic,
// and the words were still offered after it.
func TestAPanicInsideConfirmWordsAnswersFailedAndNoPosition(t *testing.T) {
	random := &armedPanicReader{}
	one := newIdentityDeviceDrawingFrom(t, t.TempDir(), random)
	words, failure := createIdentity(t, one.handle)
	if failure != "" {
		t.Fatalf("create_identity: %s", failure)
	}
	random.arm(true)
	kind, positions, count, _ := confirmWordsInto(t, one.handle, strings.Join(words, " "), 25)
	random.arm(false)
	if kind != messageWordsFailed {
		t.Errorf("a panic inside the identity's making answered kind %d, want FAILED (%d)", kind, messageWordsFailed)
	}
	if count != 0 || len(positions) != 0 {
		t.Errorf("a panic inside the identity's making left *inout_count at %d: it is set to none before anything", count)
	}
	if _, err := one.device.Identity(); !errors.Is(err, urmessage.ErrNoIdentity) {
		t.Fatalf("CONTROL FAILED: the panic left an identity behind (%v), so it was not inside the making", err)
	}
	if !random.panicked() {
		t.Fatal("CONTROL FAILED: the armed reader was never read, so nothing panicked")
	}
	if kind, _, failure := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsOk {
		t.Fatalf("CONTROL FAILED: the same words, the reader disarmed, answered kind %d (%s)", kind, failure)
	}
}

// A PANIC INSIDE ENSURE_SUBSCRIBED ANSWERS -1, NOT "ALREADY CURRENT" (LRI R84 item 3). Its 0 says the
// subscription is current, which a recovered panic must never say. The group handle is a group no
// device made, whose subscribe panics inside.
//
// THE CONTROL: the same subscribe, called outside the export, panics -- so the -1 was the recovered
// panic's, and not a refusal's.
func TestAPanicInsideEnsureSubscribedAnswersThatItDidNotSubscribe(t *testing.T) {
	group := newHandle(&urmessage.Group{})
	defer handleRelease(group)
	if got := callExportNil(t, urnet_message_group_ensure_subscribed, group, uint64(0), nil)[0].Int(); got != -1 {
		t.Errorf("a panic inside ensure_subscribed answered %d, want -1: 0 says the subscription is current and 1 that it was made", got)
	}
	panicked := func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		(&urmessage.Group{}).EnsureSubscribed(context.Background())
		return false
	}()
	if !panicked {
		t.Fatal("CONTROL FAILED: a group no device made subscribed without a panic, so the -1 was not a recovered panic's")
	}
}

// A PANIC INSIDE FORGET_GROUP ANSWERS UNKNOWN, NEVER OK AND NEVER "NOT HELD" (LRI R84 item 3, R89 item
// 7; review X-D2-3). Its result is preset to UNKNOWN, as every kind-answering export's is to its failure
// (gen's TestEveryKindAnsweringExportPresetsItsFailure): an unpreset result answers its zero value,
// URNET_MESSAGE_FORGET_OK, a group a caller is told is gone, and FAILED would say no such group is
// held, which the app also reads as left. A panic may come before anything changed or after the group
// was closed, so the answer is that its state is unknown, and out_error says so. The panic is real and
// inside the leave: the device's durable store panics once armed, at the first question a leave asks.
//
// THE CONTROL: the armed store was asked, so the UNKNOWN was the panic's; and the same call disarmed,
// for a group this device does not hold, answers FAILED.
func TestAPanicInsideForgetGroupAnswersUnknownNeverOkOrNotHeld(t *testing.T) {
	store := &armedPanicStore{}
	one := newIdentityDeviceOver(t, t.TempDir(), nil, store)
	var failure exportOutError
	store.arm(true)
	got := callExportNil(t, urnet_message_device_forget_group, one.handle, nil, int32(0), failure.pointer())[0].Int()
	store.arm(false)
	why := failure.take(t)
	if int32(got) != messageForgetUnknown {
		t.Errorf("a panic inside forget_group answered kind %d, want UNKNOWN (%d): %d is OK, a group a caller is told is gone, and %d is FAILED, a group not held",
			got, messageForgetUnknown, messageForgetOk, messageForgetFailed)
	}
	if !strings.Contains(why, "unknown") {
		t.Errorf("a panic inside forget_group set out_error to %d octets that do not say the group's state is unknown", len(why))
	}
	if !store.panicked() {
		t.Fatal("CONTROL FAILED: the armed store was never asked, so nothing panicked")
	}
	var notHeld exportOutError
	if got := callExportNil(t, urnet_message_device_forget_group, one.handle, nil, int32(0), notHeld.pointer())[0].Int(); int32(got) != messageForgetFailed {
		t.Errorf("CONTROL FAILED: with nothing armed, a group this device does not hold answered kind %d, want FAILED", got)
	}
	notHeld.take(t)
}

// THE IDENTITY'S STATE TELLS AN UNREADABLE IDENTITY FROM NONE (LRI R89 item 1; review D2L-1, L-D1,
// G-D1). urnet_message_device_identity_state answers NONE before an identity, MADE after it, and,
// with the identity record moved away, UNREADABLE -- urmessage's ErrIdentityUnreadable -- with
// out_error naming the records that stand. Over that, urnet_message_device_identity answers NULL with
// out_error, as for any identity that cannot be read, and create_identity refuses: no setup is offered
// over a live identity. An unknown handle answers FAILED with out_error NULL.
//
// THE CONTROL: the record put back, the state is MADE again.
func TestTheIdentityStateTellsAnUnreadableIdentityFromNone(t *testing.T) {
	dir := t.TempDir()
	state := func(handle uint64) (int32, string) {
		t.Helper()
		var why exportOutError
		got := callExportNil(t, urnet_message_device_identity_state, handle, why.pointer())[0].Int()
		return int32(got), why.take(t)
	}
	one := newIdentityDevice(t, dir)
	if got, _ := state(one.handle); got != messageIdentityNone {
		t.Fatalf("a device with no identity answered state %d, want NONE (%d)", got, messageIdentityNone)
	}
	words, failure := createIdentity(t, one.handle)
	if failure != "" {
		t.Fatalf("create_identity: %s", failure)
	}
	if kind, _, failure := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsOk {
		t.Fatalf("confirm_words answered kind %d (%s)", kind, failure)
	}
	if got, _ := state(one.handle); got != messageIdentityMade {
		t.Fatalf("a device with its identity answered state %d, want MADE (%d)", got, messageIdentityMade)
	}
	one.close()

	// THE IDENTITY RECORD MOVED AWAY
	record := identityRecordUnder(t, dir)
	aside := filepath.Join(t.TempDir(), "quarantined")
	if err := os.Rename(record, aside); err != nil {
		t.Fatal(err)
	}
	two := newIdentityDevice(t, dir)
	got, why := state(two.handle)
	if got != messageIdentityUnreadable {
		t.Errorf("with the identity record away the state is %d, want UNREADABLE (%d): NONE sends the app to setup over a live identity", got, messageIdentityUnreadable)
	}
	if !strings.Contains(why, "phrase-key") || !strings.Contains(why, "identity-heads") {
		t.Errorf("the UNREADABLE state's out_error (%d octets) does not name the records that stand", len(why))
	}
	var identityWhy exportOutError
	if json := callExportNil(t, urnet_message_device_identity, two.handle, identityWhy.pointer())[0]; !json.IsNil() {
		t.Errorf("with the identity record away urnet_message_device_identity answered json: has_identity false would send the app to setup")
	}
	if identityWhy.take(t) == "" {
		t.Errorf("with the identity record away urnet_message_device_identity answered NULL and no out_error")
	}
	if _, failure := createIdentity(t, two.handle); failure == "" {
		t.Errorf("with the identity record away create_identity offered words")
	}
	if got, why := state(uint64(1) << 62); got != messageIdentityFailed || why != "" {
		t.Errorf("an unknown handle answered state %d with %d octets of out_error, want FAILED and none", got, len(why))
	}
	two.close()

	// THE CONTROL: put back, the identity is MADE again
	if err := os.Rename(aside, record); err != nil {
		t.Fatal(err)
	}
	three := newIdentityDevice(t, dir)
	if got, _ := state(three.handle); got != messageIdentityMade {
		t.Errorf("CONTROL FAILED: with the identity record back the state is %d, want MADE", got)
	}
}

// identityRecordUnder answers the path of the identity record of the durable store under dir.
func identityRecordUnder(t *testing.T, dir string) string {
	t.Helper()
	found := ""
	filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() && entry.Name() == "identity" {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no identity record under %s", dir)
	}
	return found
}

// THE HEADER'S URNET_MESSAGE_IDENTITY_* DEFINES ARE THE LIBRARY'S STATES, BY NAME AND BY VALUE, both
// ways (LRI R89 item 1).
func TestTheHeaderDefinesExactlyTheIdentityStates(t *testing.T) {
	header, err := os.ReadFile("include/urnetwork_message.h")
	if err != nil {
		t.Fatalf("reading the header: %v", err)
	}
	defined := map[string]int32{}
	for _, match := range regexp.MustCompile(`(?m)^#define URNET_MESSAGE_IDENTITY_([A-Z_]+)\s+(\d+)`).FindAllStringSubmatch(string(header), -1) {
		value, err := strconv.ParseInt(match[2], 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		defined[match[1]] = int32(value)
	}
	constants := map[string]int32{
		"NONE":       messageIdentityNone,
		"MADE":       messageIdentityMade,
		"UNREADABLE": messageIdentityUnreadable,
		"FAILED":     messageIdentityFailed,
	}
	if len(defined) < 2 {
		t.Fatalf("the header defines %d URNET_MESSAGE_IDENTITY_* states; the positive control is not met", len(defined))
	}
	if !reflect.DeepEqual(defined, constants) {
		t.Fatalf("the header defines the identity states as %v and the library's constants are %v", defined, constants)
	}
}

// MORE POSITIONS THAN THE CAPACITY ARE COUNTED, AND THE FIRST ARE COPIED (LRI R84 item 4; review
// X-LIB-2). Typed back with every word doubled, 50 words name more than 25 positions. A capacity of 25
// answers the first 25 of them and counts them all; a capacity of the count answers every one, the
// first 25 the same; and a WRONG changes nothing, so the words typed right then make the identity.
func TestMorePositionsThanTheCapacityAreCountedAndTheFirstAreCopied(t *testing.T) {
	one := newIdentityDevice(t, t.TempDir())
	words, failure := createIdentity(t, one.handle)
	if failure != "" {
		t.Fatalf("create_identity: %s", failure)
	}
	doubled := make([]string, 0, 2*len(words))
	for _, word := range words {
		doubled = append(doubled, word, word)
	}
	kind, first, count, _ := confirmWordsInto(t, one.handle, strings.Join(doubled, " "), 25)
	if kind != messageWordsWrong || count <= 25 || len(first) != 25 {
		t.Fatalf("50 words typed back answered kind %d, %d position(s) counted and %d copied: want WRONG, more than 25, and 25",
			kind, count, len(first))
	}
	for at := 1; at < len(first); at += 1 {
		if first[at-1] < 1 || first[at] <= first[at-1] {
			t.Fatalf("the positions copied are not the first ones in order: %v", first)
		}
	}
	kind, all, again, _ := confirmWordsInto(t, one.handle, strings.Join(doubled, " "), int(count))
	if kind != messageWordsWrong || again != count || len(all) != int(count) || !slices.Equal(all[:25], first) {
		t.Fatalf("with a capacity of %d the same words answered kind %d, %d counted and %d copied, the first 25 the same: %v",
			count, kind, again, len(all), len(all) >= 25 && slices.Equal(all[:25], first))
	}
	if kind, _, failure := confirmWords(t, one.handle, strings.Join(words, " ")); kind != messageWordsOk {
		t.Fatalf("after the WRONG answers the right words answered kind %d (%s)", kind, failure)
	}
}

// armedPanicReader is a device's randomness that panics once armed, and is crypto/rand before.
type armedPanicReader struct {
	mutex   sync.Mutex
	armed   bool
	reached bool
}

func (self *armedPanicReader) arm(armed bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.armed = armed
}

func (self *armedPanicReader) panicked() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.reached
}

func (self *armedPanicReader) Read(octets []byte) (int, error) {
	self.mutex.Lock()
	armed := self.armed
	if armed {
		self.reached = true
	}
	self.mutex.Unlock()
	if armed {
		panic("the test's armed randomness, read inside the identity's making")
	}
	return rand.Read(octets)
}

// armedPanicStore is a device's durable state store whose GroupBeingForgotten -- the first question a
// leave asks a durable store -- panics once armed, and is the durable store's before.
type armedPanicStore struct {
	*urmessage.DurableStateStore
	mutex   sync.Mutex
	armed   bool
	reached bool
}

func (self *armedPanicStore) arm(armed bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.armed = armed
}

func (self *armedPanicStore) panicked() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.reached
}

func (self *armedPanicStore) GroupBeingForgotten(groupId []byte) (bool, error) {
	self.mutex.Lock()
	armed := self.armed
	if armed {
		self.reached = true
	}
	self.mutex.Unlock()
	if armed {
		panic("the test's armed store, asked inside forget_group")
	}
	return self.DurableStateStore.GroupBeingForgotten(groupId)
}
