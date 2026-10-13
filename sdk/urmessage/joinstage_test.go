package urmessage

import (
	"bytes"
	"errors"
	"testing"
)

// A staged join reaches the store only at its commit, and the commit never writes over a state
// that is already there.
//
// WHAT WOULD GO RED: forward PutGroupState during a join and the first assertion fails; drop the
// probe from commit and the hostile state replaces the first; zeroize the probe's answer and the
// first state reads back as zeros.
func TestAStagedJoinReachesTheStoreOnlyAtCommitAndNeverOverAStateAlreadyThere(t *testing.T) {
	store := NewMemoryStateStore()
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	bystander := bytes.Repeat([]byte{0x72}, GroupIdBytes)
	first := []byte("the epoch state the first join wrote")

	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 3, first); err != nil {
		t.Fatalf("PutGroupState during the join: %v", err)
	}
	if _, err := store.GetGroupState(joined, 3); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("the store answered %v for the joined group before the commit, want ErrStateNotFound: the join wrote through", err)
	}
	// the engine's own view of what it just wrote
	if staged, err := stage.GetGroupState(joined, 3); err != nil || !bytes.Equal(staged, first) {
		t.Fatalf("the stage answered %q, %v for the state it holds", staged, err)
	}
	// another group's write during the join is that group's own, and goes straight through
	if err := stage.PutGroupState(bystander, 9, []byte("a live group sealing")); err != nil {
		t.Fatalf("a bystander's PutGroupState: %v", err)
	}
	if _, err := store.GetGroupState(bystander, 9); err != nil {
		t.Fatalf("a bystander's write did not reach the store during a join: %v", err)
	}
	if err := stage.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if written, err := store.GetGroupState(joined, 3); err != nil || !bytes.Equal(written, first) {
		t.Fatalf("after the commit the store holds %q, %v", written, err)
	}

	// A SECOND JOIN INTO THE SAME GROUP AND EPOCH: refused, and the first state is intact.
	if err := stage.begin(joined); err != nil {
		t.Fatalf("the second begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 3, []byte("a hostile welcome's epoch state")); err != nil {
		t.Fatalf("the second PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over a held state answered %v, want ErrJoinWouldOverwrite", err)
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if kept, err := store.GetGroupState(joined, 3); err != nil || !bytes.Equal(kept, first) {
		t.Fatalf("after the refused commit the store holds %q, %v; the held state was replaced or erased", kept, err)
	}
	// and the stage is a plain forward again
	if err := stage.PutGroupState(joined, 4, []byte("the group's own next epoch")); err != nil {
		t.Fatalf("PutGroupState after the join: %v", err)
	}
	if _, err := store.GetGroupState(joined, 4); err != nil {
		t.Fatalf("a write after the join did not reach the store: %v", err)
	}
}

// A join that is refused after the engine took the join code puts it back, byte for byte.
func TestAnAbortedJoinPutsTheJoinCodeBack(t *testing.T) {
	store := NewMemoryStateStore()
	stage := newJoinStage(store)
	ref := []byte("the key package's reference")
	if err := store.PutKeyPackage(ref, []byte("kp"), []byte("init private"), []byte("leaf private")); err != nil {
		t.Fatalf("PutKeyPackage: %v", err)
	}
	if err := stage.begin(bytes.Repeat([]byte{0x71}, GroupIdBytes)); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, _, _, err := stage.TakeKeyPackage(ref); err != nil {
		t.Fatalf("TakeKeyPackage through the stage: %v", err)
	}
	if _, _, _, err := store.TakeKeyPackage(ref); err == nil {
		t.Fatal("CONTROL FAILED: the store still holds the key package after the take, so the put-back below proves nothing")
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	kp, initPrivate, leafPrivate, err := store.TakeKeyPackage(ref)
	if err != nil {
		t.Fatalf("the join code is gone after an aborted join: %v", err)
	}
	if string(kp) != "kp" || string(initPrivate) != "init private" || string(leafPrivate) != "leaf private" {
		t.Fatalf("the join code came back as %q %q %q", kp, initPrivate, leafPrivate)
	}
}

// unreadableStore answers a failed read, which is neither "held" nor "not held".
type unreadableStore struct {
	*MemoryStateStore
	puts int
}

func (self *unreadableStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	return nil, errors.New("the disk this store sits on answered EIO")
}

func (self *unreadableStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.puts += 1
	return self.MemoryStateStore.PutGroupState(groupId, epoch, state)
}

// Only ErrStateNotFound means "nothing is there". A store that cannot say is not written over.
func TestACommitOverAStoreThatCannotAnswerIsRefused(t *testing.T) {
	store := &unreadableStore{MemoryStateStore: NewMemoryStateStore()}
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 1, []byte("staged")); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over an unreadable store answered %v, want ErrJoinWouldOverwrite", err)
	}
	if store.puts != 0 {
		t.Fatalf("the refused commit wrote %d state(s) into a store that could not say what it held", store.puts)
	}
}

// ownArrayStore answers GetGroupState with ITS OWN ARRAY, which is what [mls.StateStore] permits a
// store to do and what the stores this package ships happen not to.
type ownArrayStore struct {
	*MemoryStateStore
	state []byte
}

func (self *ownArrayStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	return self.state, nil
}

// The create-only probe reads whether the store ANSWERED and nothing else. An erase of what it
// answered would be an erase of the held group's state, through the store's own array.
func TestTheCreateOnlyProbeLeavesTheStoresOwnArrayAlone(t *testing.T) {
	held := []byte("the held group's epoch state")
	store := &ownArrayStore{MemoryStateStore: NewMemoryStateStore(), state: bytes.Clone(held)}
	stage := newJoinStage(store)
	joined := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	if err := stage.begin(joined); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := stage.PutGroupState(joined, 1, []byte("a hostile welcome's epoch state")); err != nil {
		t.Fatalf("PutGroupState: %v", err)
	}
	if err := stage.commit(); !errors.Is(err, ErrJoinWouldOverwrite) {
		t.Fatalf("a commit over a held state answered %v, want ErrJoinWouldOverwrite", err)
	}
	if err := stage.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if !bytes.Equal(store.state, held) {
		t.Fatalf("the store's own array reads %q after the probe and held %q before it", store.state, held)
	}
}
