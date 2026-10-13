package urmessage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/message/mls"
	messageprotocol "github.com/urnetwork/message/protocol"
	"github.com/urnetwork/message/sdk"
)

// THE HELD-GROUP GATE AND THE DISK: what the device asks its store about ONE group, and what it
// does with each of the three things a store can answer that are not a record: "I hold none", "the
// record I hold does not read", and no answer at all.

// ONE RECORD THAT DOES NOT READ IS ONE GROUP'S, AT THE STORE. Three groups are on the disk and one
// record is cut to half its length. The list still answers the other two, and reports the third
// beside them by its directory; the one-id read answers "does not read" for that group and for no
// other. Then the states that are NOT damage, and one more that is: a group that was never there,
// a group being left, a record that reads and names another group, and a store that cannot answer.
//
// WHAT WOULD GO RED: answer an error and no list over one record that does not read, and a device
// loses every group it holds at its next Restore; hold a record under a directory it does not
// name, and the list holds a group the one-id read answers "not held" for.
func TestOneRecordThatDoesNotReadIsReportedByTheListAndAnsweredOnlyForItsOwnGroup(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	whole := bytes.Repeat([]byte{0x41}, GroupIdBytes)
	damaged := bytes.Repeat([]byte{0x42}, GroupIdBytes)
	other := bytes.Repeat([]byte{0x43}, GroupIdBytes)
	for _, groupId := range [][]byte{whole, damaged, other} {
		if err := store.PutGroupRecord(&GroupRecord{
			GroupId: groupId, PqSecret: bytes.Repeat([]byte{0x2A}, 32), GroupHandleKey: bytes.Repeat([]byte{0x5C}, 32), Epoch: 1, Opened: true,
		}); err != nil {
			t.Fatalf("PutGroupRecord: %v", err)
		}
	}
	if records, err := store.GroupRecords(); err != nil || len(records) != 3 {
		t.Fatalf("CONTROL FAILED: before any damage the list answers %d record(s), %v", len(records), err)
	}
	path := store.groupRecordPath(damaged)
	octets, err := os.ReadFile(path)
	if err != nil || len(octets) < 2 {
		t.Fatalf("reading the record about to be damaged: %d octets, %v", len(octets), err)
	}
	if err := os.WriteFile(path, octets[:len(octets)/2], 0o600); err != nil {
		t.Fatalf("cutting the record to half its length: %v", err)
	}
	idsOf := func(records []*GroupRecord) string {
		ids := []string{}
		for _, record := range records {
			ids = append(ids, string(record.GroupId[:1]))
		}
		return strings.Join(ids, "")
	}

	// THE LIST: the two that read, and the third reported beside them by its directory
	records, err := store.GroupRecords()
	if !errors.Is(err, ErrGroupRecordDamaged) {
		t.Fatalf("the list over one record that does not read answered %v, want an error carrying ErrGroupRecordDamaged", err)
	}
	if got := idsOf(records); got != "AC" && got != "CA" {
		t.Fatalf("the list answered the records of %q beside its report, want the two that read", got)
	}
	if !strings.Contains(err.Error(), stateNameOf(damaged)) || strings.Contains(err.Error(), stateNameOf(whole)) ||
		strings.Contains(err.Error(), stateNameOf(other)) {
		t.Errorf("the report does not name the directory of the record that does not read, and that one alone: %v", err)
	}

	// THE ONE-ID READ: "does not read" for that group, the record for the others, "none" for a fourth
	if _, err := store.GroupRecord(damaged); !errors.Is(err, ErrGroupRecordDamaged) || errors.Is(err, ErrStateNotFound) {
		t.Errorf("the one-id read of the damaged group answered %v, want ErrGroupRecordDamaged", err)
	}
	for _, groupId := range [][]byte{whole, other} {
		if record, err := store.GroupRecord(groupId); err != nil || !bytes.Equal(record.GroupId, groupId) {
			t.Errorf("the one-id read of a group whose record reads answered %v, beside another group's damage", err)
		}
	}
	if _, err := store.GroupRecord(bytes.Repeat([]byte{0x44}, GroupIdBytes)); !errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read of a group this store never held answered %v, want ErrStateNotFound", err)
	}

	// A GROUP BEING LEFT is not one this store holds a record for, by its id or in the list
	if err := store.MarkGroupForgetting(other); err != nil {
		t.Fatalf("MarkGroupForgetting: %v", err)
	}
	if _, err := store.GroupRecord(other); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the one-id read of a group being left answered %v, want ErrStateNotFound", err)
	}
	if records, _ := store.GroupRecords(); idsOf(records) != "A" {
		t.Errorf("the list answers the records of %q with one group being left and one damaged, want the one that is neither", idsOf(records))
	}

	// A RECORD THAT READS AND NAMES ANOTHER GROUP IS DAMAGE TOO. The whole group's record is copied
	// into the damaged group's directory. Answered by the list, it would be a second record of the
	// whole group, in a directory the one-id read reaches by another id.
	copied, err := os.ReadFile(store.groupRecordPath(whole))
	if err != nil {
		t.Fatalf("reading the whole group's record: %v", err)
	}
	if err := os.WriteFile(path, copied, 0o600); err != nil {
		t.Fatalf("copying it into the other group's directory: %v", err)
	}
	if _, err := store.GroupRecord(damaged); !errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read of a directory holding another group's record answered %v, want ErrGroupRecordDamaged", err)
	}
	if records, err := store.GroupRecords(); !errors.Is(err, ErrGroupRecordDamaged) || idsOf(records) != "A" {
		t.Errorf("the list over a directory holding another group's record answered the records of %q and %v, want one record and the damage reported", idsOf(records), err)
	}

	// AND A STORE THAT CANNOT ANSWER says neither "none" nor "does not read"
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := store.GroupRecord(whole); !errors.Is(err, ErrStateStoreState) || errors.Is(err, ErrStateNotFound) || errors.Is(err, ErrGroupRecordDamaged) {
		t.Errorf("the one-id read on a closed store answered %v, want ErrStateStoreState and neither of the two answers a caller acts on", err)
	}
}

// newAnsweringDeviceOver is [newAnsweringDevice] over a state store of the caller's, connected.
func newAnsweringDeviceOver(t *testing.T, store mls.StateStore, nonce []byte) *Device {
	t.Helper()
	client := &answeringClient{reason: messageprotocol.Reason_REASON_OK, nonce: nonce}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client,
		Server:          connect.NewId(),
		ProtocolVersion: 1,
	})
	if err != nil {
		t.Fatalf("sdk.NewMessageTransport: %v", err)
	}
	t.Cleanup(transport.Close)
	streamStore, err := sdk.OpenStreamStore(t.TempDir())
	if err != nil {
		t.Fatalf("sdk.OpenStreamStore: %v", err)
	}
	t.Cleanup(func() { streamStore.Close() })
	device, err := NewDevice(DeviceConfig{
		Transport:  transport,
		Reserver:   sdk.NewStreamIndexReserver(streamStore),
		StateStore: store,
		Connect: ConnectPolicy{
			Budget:         30 * time.Second,
			AttemptTimeout: 2 * time.Second,
			FirstBackoff:   200 * time.Millisecond,
			MaxBackoff:     200 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}
	t.Cleanup(func() { device.Close() })
	if err := device.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return device
}

// deafStore is a durable store that cannot answer for ONE group id: its one-id read fails there,
// as a disk that will not be read does, and is the store's own for every other id.
type deafStore struct {
	*DurableStateStore
	deafTo []byte
}

func (self *deafStore) GroupRecord(groupId []byte) (*GroupRecord, error) {
	if bytes.Equal(groupId, self.deafTo) {
		return nil, errors.New("the store this test sits on cannot answer for this group")
	}
	return self.DurableStateStore.GroupRecord(groupId)
}

// A STORE THAT CANNOT ANSWER IS A REFUSAL, FOR THAT GROUP AND FOR NO OTHER. "Not held" is the one
// answer that lets a join or a founding write, so a store that fails to answer must never be read
// as it. An honest invite into the group the store cannot answer for is refused before the join
// code is touched; a founding under its id is refused before mls writes an epoch zero; and the
// same device, over the same store, joins another group and founds under a third id.
//
// WHAT WOULD GO RED: read any answer but a record as "not held", in the gate or in the founding's
// question, and a group held only on the disk is written over whenever the read of it fails.
func TestAStoreThatCannotAnswerRefusesTheJoinAndTheFoundingOfThatGroupAndOfNoOther(t *testing.T) {
	ctx := context.Background()
	durable := openTestStore(t, t.TempDir())
	store := &deafStore{DurableStateStore: durable}
	device := newAnsweringDeviceOver(t, store, []byte("the device's nonce"))
	inviteInto := func(groupId []byte) *Invite {
		founder, _ := newAnsweringDevice(t, messageprotocol.Reason_REASON_OK, []byte("a founder's nonce"))
		if err := founder.Connect(ctx); err != nil {
			t.Fatalf("a founder's Connect: %v", err)
		}
		group, err := founder.CreateGroup(ctx, groupId)
		if err != nil {
			t.Fatalf("a founder's CreateGroup: %v", err)
		}
		joinCode, err := device.KeyPackage()
		if err != nil {
			t.Fatalf("the device's KeyPackage: %v", err)
		}
		invite, err := group.AddMember(joinCode)
		if err != nil {
			t.Fatalf("a founder's AddMember: %v", err)
		}
		return invite
	}
	deaf := bytes.Repeat([]byte{0x47}, GroupIdBytes)
	store.deafTo = deaf
	honest := inviteInto(deaf)

	// THE JOIN: refused as a store that could not answer, and nothing of the group was written
	_, err := device.Join(ctx, honest)
	if err == nil || errors.Is(err, ErrGroupAlreadyHeld) || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("an invite into a group the store cannot answer for answered %v, want a refusal that says it could not be read and does not say the group is held", err)
	}
	if held := len(device.Groups()); held != 0 {
		t.Errorf("the refused join left the device holding %d group(s)", held)
	}
	if _, err := durable.GetGroupState(deaf, 1); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the refused join left an epoch state on the disk for the group it refused: %v", err)
	}
	// THE FOUNDING: refused, and before mls wrote an epoch zero under the id
	if _, err := device.CreateGroup(ctx, deaf); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("a founding under an id the store cannot answer for answered %v, want a refusal that says it could not be read", err)
	}
	if _, err := durable.GetGroupState(deaf, 0); !errors.Is(err, ErrStateNotFound) {
		t.Errorf("the refused founding left an epoch-zero state on the disk: %v", err)
	}

	// THE CONTROL, which is also the other half of the property: no other group is refused by it
	if _, err := device.Join(ctx, inviteInto(bytes.Repeat([]byte{0x48}, GroupIdBytes))); err != nil {
		t.Fatalf("CONTROL FAILED: an invite into another group, over the same store, answered %v", err)
	}
	if _, err := device.CreateGroup(ctx, bytes.Repeat([]byte{0x49}, GroupIdBytes)); err != nil {
		t.Fatalf("CONTROL FAILED: a founding under another id, over the same store, answered %v", err)
	}
	// AND THE REFUSAL COST NOTHING: once the store answers, the same invite joins
	store.deafTo = nil
	if _, err := device.Join(ctx, honest); err != nil {
		t.Errorf("the same invite, once the store answers for its group, answered %v: the refusal spent the join code", err)
	}
}
