package protocol_test

// The names of the four URmessage frame code points, held against this package's messages.
//
// frame.proto carries the messaging frames under MessageType values 1000-1003 (Spec B
// section 4.2, Spec A section 10.1), and connect keeps the checks of those NUMBERS beside it.
// Their NAMES diverge from both specs on purpose: proto3 scopes an enum value's name to the
// enum's parent, so `MessageServerRequest = 1000` in package bringyour would claim
// `bringyour.MessageServerRequest`, which the message of that name in message.proto holds,
// and protoc refuses the pair. The enum side repeats its domain prefix instead
// (`MessageMessageServerRequest`, as `IpIpPing` does for `IpPing`).
//
// That reason spans the two repositories now: the messages live here, the enum in connect.
// This holds it from this side, without linking connect's schema: frame.proto is read as TEXT
// from the pinned connect sibling, and the messages come from this package's own registry, so
// the test binary registers message.proto once and frame.proto not at all. For each of the
// four code points it asserts that frame.proto's name differs from the spec's name, ends with
// it, and that the spec's name is a message in this package, which is what makes the
// divergence necessary. If message.proto renamed its envelopes, the collision would dissolve
// and the divergence would want revisiting; this fails then.
//
// The sibling is connect checked out beside this repository at the commit
// scripts/siblings.txt pins. test.sh requires it (URMESSAGE_REQUIRE_CONNECT_ROOT); a run
// without it skips, and says so.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/message/protocol"
)

// The four code points as both specs give them: number and normative name.
var urmessageCodePointSpecNames = map[int]string{
	1000: "MessageServerRequest",
	1001: "MessageServerResponse",
	1002: "MessageServerPush",
	1003: "MessageServerFragment",
}

// connect's frame.proto, relative to this package: the sibling checkout beside the repository.
const connectFrameProto = "../../connect/protocol/frame.proto"

var frameEnumValue = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?[0-9]+)\s*;`)

// The values of `enum MessageType` in a frame.proto text, by number.
func frameMessageTypeValues(text string) (map[int]string, error) {
	values := map[int]string{}
	inside := false
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(text, "\r\n", "\n")))
	for scanner.Scan() {
		line := scanner.Text()
		if code, _, _ := strings.Cut(line, "//"); !inside {
			if strings.Contains(code, "enum MessageType") && strings.Contains(code, "{") {
				inside = true
			}
			continue
		}
		code, _, _ := strings.Cut(line, "//")
		if strings.Contains(code, "}") {
			return values, nil
		}
		match := frameEnumValue.FindStringSubmatch(code)
		if match == nil {
			continue
		}
		number, err := strconv.Atoi(match[2])
		if err != nil {
			return nil, err
		}
		if previous, taken := values[number]; taken {
			return nil, fmt.Errorf("MessageType numbers %d twice (%s and %s)", number, previous, match[1])
		}
		values[number] = match[1]
	}
	if !inside {
		return nil, fmt.Errorf("no `enum MessageType {` in the text")
	}
	return nil, fmt.Errorf("enum MessageType is not closed")
}

// What is wrong with frame.proto's names for the four code points, given this package's
// registry.
func codePointNameProblems(frameText string, files *protoregistry.Files) []string {
	values, err := frameMessageTypeValues(frameText)
	if err != nil {
		return []string{"frame.proto's MessageType cannot be read: " + err.Error()}
	}
	problems := []string{}
	for number := 1000; number <= 1003; number++ {
		specName := urmessageCodePointSpecNames[number]
		name, found := values[number]
		if !found {
			problems = append(problems, fmt.Sprintf("frame.proto's MessageType has no value %d (%s)", number, specName))
			continue
		}
		descriptor, err := files.FindDescriptorByName(protoreflect.FullName("bringyour." + specName))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%d: no message bringyour.%s is registered by message/protocol (%v); the collision that makes %s diverge is gone, so the divergence wants revisiting", number, specName, err, name))
		} else if _, isMessage := descriptor.(protoreflect.MessageDescriptor); !isMessage {
			problems = append(problems, fmt.Sprintf("%d: bringyour.%s is a %T, not a message", number, specName, descriptor))
		}
		if name == specName {
			problems = append(problems, fmt.Sprintf("%d: frame.proto names it %s, the spec's own name, which collides with message bringyour.%s in this package's schema", number, name, specName))
		}
		if !strings.HasSuffix(name, specName) {
			problems = append(problems, fmt.Sprintf("%d: frame.proto names it %s, which does not end in the spec's name %s; the divergence is a repeated domain prefix, not a free rename", number, name, specName))
		}
	}
	return problems
}

func TestUrmessageCodePointNamesStillDivergeFromConnectsFrame(t *testing.T) {
	// the package is linked, so its file is registered; read it through the registry
	_ = protocol.File_message_proto
	text, err := os.ReadFile(connectFrameProto)
	if err != nil {
		absolute, _ := filepath.Abs(connectFrameProto)
		if os.Getenv("URMESSAGE_REQUIRE_CONNECT_ROOT") != "" {
			t.Fatalf("URMESSAGE_REQUIRE_CONNECT_ROOT is set and %s cannot be read: %v", absolute, err)
		}
		t.Skipf("connect is not checked out beside this repository (%s): %v", absolute, err)
	}
	for _, problem := range codePointNameProblems(string(text), protoregistry.GlobalFiles) {
		t.Error(problem)
	}
}

// The control: a frame.proto that names a code point exactly like the message, one whose name
// does not end in the spec's, and one missing a value, each reported; the real names are not.
func TestTheCodePointNameCheckReportsANameEqualToAMessage(t *testing.T) {
	_ = protocol.File_message_proto
	fixture := strings.Join([]string{
		"syntax = \"proto3\";",
		"package bringyour;",
		"enum MessageType {",
		"    TransferPack = 0;",
		"    MessageServerRequest = 1000; // the spec's own name",
		"    MessageMessageServerResponse = 1001;",
		"    ServerPushFrame = 1002;",
		"}",
		"",
	}, "\n")
	problems := codePointNameProblems(fixture, protoregistry.GlobalFiles)
	wants := []string{
		"1000: frame.proto names it MessageServerRequest, the spec's own name",
		"1002: frame.proto names it ServerPushFrame, which does not end in the spec's name MessageServerPush",
		"frame.proto's MessageType has no value 1003 (MessageServerFragment)",
	}
	for _, want := range wants {
		reported := false
		for _, problem := range problems {
			if strings.HasPrefix(problem, want) {
				reported = true
			}
		}
		if !reported {
			t.Errorf("not reported: %q\ngot: %q", want, problems)
		}
	}
	if len(problems) != len(wants) {
		t.Errorf("%d problems planted, %d reported: %q", len(wants), len(problems), problems)
	}
}
