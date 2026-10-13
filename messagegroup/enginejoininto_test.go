package messagegroup

import (
	"bytes"
	"fmt"
	"testing"
)

// JoinFromWelcomeInto is JoinFromWelcome with the caller's group id matched inside connect/mls,
// AHEAD of the persist. The property is what a refused Welcome leaves behind: no epoch state, and
// the key package still in the store.
//
// WHAT WOULD GO RED: build the join's mls.GroupConfig without GroupId and the first call below
// joins and writes a state under the Welcome's own id, which is the defect this door closes.
func TestJoinFromWelcomeIntoRefusesAWelcomeForAnotherGroupBeforeAnythingIsWritten(t *testing.T) {
	fixture := newEngineJoinFixture(t, "the-bound-join", true)
	real := fixture.handle.GroupId()
	statesBefore := len(fixture.joiner.store.groupStates)
	asked := bytes.Repeat([]byte{0x5D}, len(real))

	refused, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, asked)
	if err == nil {
		t.Fatal("a welcome describing one group joined under another group's id")
	}
	if refused != nil {
		t.Error("the refused join answered a handle beside its error")
	}
	if got := len(fixture.joiner.store.groupStates); got != statesBefore {
		t.Errorf("the refused join left %d group state(s) in the store and there were %d before it", got, statesBefore)
	}
	if _, held := fixture.joiner.store.keyPackages[fmt.Sprintf("%x", fixture.joinerRef)]; !held {
		t.Fatalf("the joiner's key package is gone after a refused join, so the honest welcome can never be opened")
	}

	// THE CONTROL, and the other half of the property: the same welcome under the id it does
	// describe joins, over the key package the refusal put back.
	joined, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, real)
	if err != nil {
		t.Fatalf("the welcome under its own group id: %v", err)
	}
	defer joined.Close()
	if !bytes.Equal(joined.GroupId(), real) {
		t.Errorf("the bound join answered group %x and was asked for %x", joined.GroupId(), real)
	}
	if got := len(fixture.joiner.store.groupStates); got != statesBefore+1 {
		t.Errorf("the join left %d group state(s) in the store, want the %d before it and one more", got, statesBefore)
	}
}

// An empty id is refused by name before the key package is touched: it is the one value that would
// turn the intent match off and make this door the unbound one.
func TestJoinFromWelcomeIntoRefusesAnEmptyGroupId(t *testing.T) {
	fixture := newEngineJoinFixture(t, "the-bound-join-empty-id", true)
	for _, empty := range [][]byte{nil, {}} {
		refused, err := fixture.joiner.engine.JoinFromWelcomeInto(fixture.welcome, fixture.ratchetTree, empty)
		if !errorIs(err, ErrEngineJoinGroupId) {
			t.Errorf("an empty group id answered %v, want ErrEngineJoinGroupId", err)
		}
		if refused != nil {
			t.Error("the refused join answered a handle beside its error")
		}
	}
	if _, held := fixture.joiner.store.keyPackages[fmt.Sprintf("%x", fixture.joinerRef)]; !held {
		t.Fatal("the joiner's key package was taken by a join that was refused for its arguments")
	}
}
