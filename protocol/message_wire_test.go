package protocol_test

// Wire code points and enum numbering for the URmessage control plane.
//
// message_op_test.go gates the numbers that live inside a MAC. This file gates the
// numbers that live on the wire outside one: the four `MessageType` frame code
// points of Spec B §4.2 / Spec A §10.1, and the value numbering of every enum in
// message.proto.
//
// Neither class had any test at all. That matters most for the frame code points,
// because their enum value NAMES are deliberately diverged from both specs — see
// frame.proto, where the domain prefix is repeated to dodge a proto3 scoping
// collision with the messages of the same name — so after that divergence the
// NUMBERS are the only thing still tying the block to the normative text. A
// renumbered code point is not a MAC failure; it is worse. Two peers simply stop
// recognising each other's frames, and the frame is discarded as an unknown
// message type, which is precisely the behaviour a forward-compatible enum is
// supposed to have for a code point that does not exist yet.
//
// As everywhere else in this package, the class is DERIVED from the descriptor and
// only the numbering is transcribed.
//
// The frame code points are frame.proto's, and frame.proto stays in connect: it is
// connect's transport enum, and the messaging schema here imports no other proto
// file. So the two checks of their NUMBERS (TestUrmessageCodePointsMatchTheSpecs and
// TestUrmessageCodePointsStayInsideTheReservedBlock) stay in connect beside it, and
// this repository keeps the check of their NAMES, which needs both schemas:
// message_codepoint_names_test.go reads connect's frame.proto as text from the pinned
// sibling, so this binary registers message.proto once and nothing twice.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/message/protocol"
)

// ── Enum value numbering in message.proto ────────────────────────────────────

// specBEnums transcribes every enum Spec B declares for the control plane:
// `Reason` from §4.5 and `Direction` from §4.3.10.
//
// Reason's numbers are not MAC inputs and both ends of the URnetwork Go world link
// this same generated code, so a renumbering here stays self-consistent inside Go.
// They are still protocol constants: Spec B §4.5 numbers them normatively, Spec C
// surfaces them in the Windows client, and Spec A §11.1 plans shared test vectors
// across implementations. Direction's ARE MAC inputs — BlobGrantRequest.direction
// is inside canonical_request_bytes — and message_op_test.go's
// TestMacInputEnumsAreTranscribed asserts that any enum reachable from an
// authenticated request body appears in this map.
var specBEnums = map[string]map[string]int{
	// Spec B §4.5.
	//
	// RECORDED HAZARD, NOT A DEVIATION — REASON_OK = 0.
	//
	// Under proto3 implicit presence a `reason` field that was never set, or that
	// was lost to a truncated or hand-rolled encoder, decodes as 0, and 0 here
	// means success. MessageServerResponse.reason, SubmitResult.reason and
	// SubscriptionAck.reason are all plain fields, so a partially-built
	// SubmitResult in a batch reads as REASON_OK rather than as "unspecified".
	// Failing toward success is a poor default anywhere, and it is a worse one on a
	// surface whose whole design — §4.5's deliberately non-specific
	// REASON_REJECTED, §5.1's padded-latency reject path — is built around refusals
	// being uninformative but unambiguous. This same file gets the sentinel right
	// one enum down: Direction reserves 0 for DIRECTION_UNSPECIFIED.
	//
	// It is transcribed exactly as §4.5 declares it, because it IS §4.5: this is a
	// spec-level default, not an implementation slip, and changing the numbering
	// unilaterally would renumber all eighteen values against a normative table
	// that Spec C and the §11.1 vectors also read. It needs a Spec B ruling.
	// Recorded here, pinned by this test, and raised as a spec divergence so the
	// ruling is asked for rather than assumed.
	"Reason": {
		"REASON_OK":                     0,
		"REASON_REJECTED":               1,
		"REASON_EPOCH_STALE":            2,
		"REASON_COMMIT_LOST":            3,
		"REASON_STREAM_INDEX_REUSED":    4,
		"REASON_STREAM_INDEX_REGRESSED": 5,
		"REASON_OVERSIZE":               6,
		"REASON_QUOTA_EXCEEDED":         7,
		"REASON_RATE_LIMITED":           8,
		"REASON_RETENTION_CLAMPED":      9,
		"REASON_BLOB_UNKNOWN":           10,
		"REASON_BLOB_INCOMPLETE":        11,
		"REASON_UNSUPPORTED_VERSION":    12,
		"REASON_INTERNAL":               13,
		"REASON_EPOCH_INCOMPLETE":       14,
		"REASON_WRAP_TARGET_UNKNOWN":    15,
		"REASON_CARD_RETIRED":           16,
		"REASON_CARD_RATE_LIMITED":      17,
	},
	// Spec B §4.3.10, declared on one line.
	"Direction": {
		"DIRECTION_UNSPECIFIED": 0,
		"DIRECTION_UPLOAD":      1,
		"DIRECTION_DOWNLOAD":    2,
	},
}

// messageProtoEnums returns every enum declared in message.proto, top level and
// nested, keyed by simple name. Derived, so a new enum is gated the moment it is
// added rather than when somebody remembers it.
func messageProtoEnums(t *testing.T) map[string]protoreflect.EnumDescriptor {
	t.Helper()
	fd := (*protocol.MessageServerRequest)(nil).ProtoReflect().Descriptor().ParentFile()
	out := map[string]protoreflect.EnumDescriptor{}
	var collectEnums func(protoreflect.EnumDescriptors)
	collectEnums = func(eds protoreflect.EnumDescriptors) {
		for i := 0; i < eds.Len(); i++ {
			ed := eds.Get(i)
			out[string(ed.Name())] = ed
		}
	}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			collectEnums(md.Enums())
			walk(md.Messages())
		}
	}
	collectEnums(fd.Enums())
	walk(fd.Messages())
	return out
}

// TestMessageProtoEnumSetMatchesSpecB is the key-set equality that keeps the
// numbering assertions below from going stale, the same construction
// TestRequestArmSetMatchesSpecA57 uses for the arms.
func TestMessageProtoEnumSetMatchesSpecB(t *testing.T) {
	enums := messageProtoEnums(t)
	if len(enums) == 0 {
		t.Fatal("message.proto declares no enum at all; the descriptor walk is wrong")
	}
	for name := range enums {
		if _, ok := specBEnums[name]; !ok {
			t.Errorf("message.proto declares enum %s, which is not transcribed in specBEnums. "+
				"An enum's value numbers go on the wire; record them against the spec rather "+
				"than letting them default.", name)
		}
	}
	for name := range specBEnums {
		if _, ok := enums[name]; !ok {
			t.Errorf("specBEnums transcribes enum %s, which message.proto no longer declares", name)
		}
	}
}

// TestEnumValueNumbersMatchSpecB compares every value of every enum in
// message.proto against the transcription, in both directions.
func TestEnumValueNumbersMatchSpecB(t *testing.T) {
	enums := messageProtoEnums(t)
	names := make([]string, 0, len(enums))
	for name := range enums {
		names = append(names, name)
	}
	sort.Strings(names)

	checked := 0
	for _, name := range names {
		ed := enums[name]
		want, ok := specBEnums[name]
		if !ok {
			// Reported by TestMessageProtoEnumSetMatchesSpecB.
			continue
		}
		t.Run(name, func(t *testing.T) {
			values := ed.Values()
			seen := map[string]bool{}
			for i := 0; i < values.Len(); i++ {
				v := values.Get(i)
				vname := string(v.Name())
				seen[vname] = true
				checked++
				spec, ok := want[vname]
				if !ok {
					t.Errorf("%s.%s = %d is not in Spec B's declaration of the enum. A value the "+
						"spec does not define is a code point no other implementation will "+
						"recognise.", name, vname, v.Number())
					continue
				}
				if int(v.Number()) != spec {
					t.Errorf("%s.%s = %d; Spec B numbers it %d. Enum values are encoded as their "+
						"numbers: a renumbering means one implementation's %s decodes as a "+
						"different value entirely on the other side.", name, vname, v.Number(), spec, vname)
				}
			}
			for vname, n := range want {
				if !seen[vname] {
					t.Errorf("Spec B declares %s.%s = %d, which message.proto does not", name, vname, n)
				}
			}
			if values.Len() != len(want) {
				t.Errorf("%s has %d values, Spec B declares %d", name, values.Len(), len(want))
			}
		})
	}
	if checked == 0 {
		t.Fatal("compared no enum values at all")
	}
	t.Logf("compared %d enum values across %d enums against Spec B", checked, len(names))
}

// TestEnumZeroValuesAreDistinct is a small structural check that costs nothing and
// makes the REASON_OK hazard above legible instead of invisible: it reports, for
// every enum in message.proto, which value owns 0. proto3 gives an unset or
// truncated field that value, so it is the value every decoder falls back to.
func TestEnumZeroValuesAreDistinct(t *testing.T) {
	enums := messageProtoEnums(t)
	names := make([]string, 0, len(enums))
	for name := range enums {
		names = append(names, name)
	}
	sort.Strings(names)

	var report []string
	for _, name := range names {
		ed := enums[name]
		zero := ed.Values().ByNumber(0)
		if zero == nil {
			t.Errorf("enum %s has no value 0; proto3 requires the first value to be zero", name)
			continue
		}
		if want, ok := specBEnums[name]; ok {
			if got, ok := want[string(zero.Name())]; !ok || got != 0 {
				t.Errorf("enum %s: value 0 is %s, which Spec B does not number 0", name, zero.Name())
			}
		}
		report = append(report, fmt.Sprintf("%s=%s", name, zero.Name()))
	}
	t.Logf("the value an unset or truncated field decodes as, per enum: %s", strings.Join(report, " "))
}
