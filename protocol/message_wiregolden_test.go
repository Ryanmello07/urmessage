package protocol_test

// The wire corpus, held append-only.
//
// testdata/wire-golden.tsv is the encodings this schema's wire behaviour and authentication
// inputs rest on: every message at depths 0 and 2 and empty, every oneof arm of every message,
// the canonical_request_bytes and op of every request carrying req_auth (Spec B section 4.3.8),
// and the descriptor without go_package. testdata/wiregolden emits it from a binary that links
// exactly one copy of the schema.
//
// Its first wireGoldenBaseLines lines are the corpus connect's own copy emitted before the
// schema left connect, pinned here by digest. CI's wire-golden job re-emits them from that
// pinned connect checkout (-tags orig) and from this package (-tags new) and requires both to
// be those bytes, and cross-decodes each into the other's types. That is the proof the move
// left every authenticated inner byte where it was (MESSAGEREVIEW.md, "Completion checks").
//
// From here on the corpus only grows. This test re-emits it from this package, with no
// sibling checkout, and holds:
//
//	A. every base row of kind msg, arm or canonical is emitted again, byte for byte; the base
//	   descriptor is a structural subset of this package's (every message, field, oneof, enum
//	   and value of the base is here unchanged);
//	B. every row this package emits is in the file: a schema addition appends its rows;
//	C. every row after the base is one this package emits: an appended row is never orphaned;
//	D. the base lines are the pinned bytes;
//
// and the messages with rows are the descriptor's messages, both ways.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

const (
	wireGoldenPath = "testdata/wire-golden.tsv"
	// the corpus emitted by urnetwork/connect 92a657fa's protocol package (message.pb.go sha256
	// 2e0f2640..., the copy connect committed and this package was regenerated from): 197 items,
	// 57,264 bytes
	wireGoldenBaseLines  = 197
	wireGoldenBaseSha256 = "9b5772b7e5d57956ce54c491b311bf86b5b39565c2a87f6d9dc2ad09a8454edc"
	wireGoldenDescriptor = "descriptor-without-go_package"
)

var (
	reemitOnce  sync.Once
	reemitLines []string
	reemitErr   error
)

// The corpus as this package emits it today: testdata/wiregolden run with -tags new under a
// temporary module file that names only this module and protobuf, so no sibling is needed.
func reemitCorpus(t *testing.T) []string {
	t.Helper()
	reemitOnce.Do(func() {
		root, err := filepath.Abs("..")
		if err != nil {
			reemitErr = err
			return
		}
		goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
		if err != nil {
			reemitErr = err
			return
		}
		protobuf := ""
		for _, line := range strings.Split(string(goMod), "\n") {
			if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "google.golang.org/protobuf" {
				protobuf = fields[1]
			}
		}
		if protobuf == "" {
			reemitErr = fmt.Errorf("go.mod requires no google.golang.org/protobuf")
			return
		}
		goSum, err := os.ReadFile(filepath.Join(root, "go.sum"))
		if err != nil {
			reemitErr = err
			return
		}
		scratch, err := os.MkdirTemp("", "wiregolden")
		if err != nil {
			reemitErr = err
			return
		}
		defer os.RemoveAll(scratch)
		modFile := fmt.Sprintf("module github.com/urnetwork/message/protocol/testdata/wiregolden\n\ngo 1.26.3\n\n"+
			"require (\n\tgithub.com/urnetwork/message v0.0.0\n\tgoogle.golang.org/protobuf %s\n)\n\n"+
			"replace github.com/urnetwork/message => %s\n", protobuf, filepath.ToSlash(root))
		if err := os.WriteFile(filepath.Join(scratch, "emit.mod"), []byte(modFile), 0o600); err != nil {
			reemitErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(scratch, "emit.sum"), goSum, 0o600); err != nil {
			reemitErr = err
			return
		}
		command := exec.Command("go", "run", "-modfile="+filepath.Join(scratch, "emit.mod"), "-tags", "new", ".", "emit")
		command.Dir = filepath.Join("testdata", "wiregolden")
		command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
		out, err := command.Output()
		if err != nil {
			if exit, isExit := err.(*exec.ExitError); isExit {
				err = fmt.Errorf("%w: %s", err, exit.Stderr)
			}
			reemitErr = err
			return
		}
		reemitLines = strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	})
	if reemitErr != nil {
		t.Fatalf("re-emit the corpus from this package: %v", reemitErr)
	}
	return slices.Clone(reemitLines)
}

func readCorpus(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(wireGoldenPath)
	if err != nil {
		t.Fatalf("read %s: %v", wireGoldenPath, err)
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

func corpusKind(row string) string {
	kind, _, _ := strings.Cut(row, "\t")
	return kind
}

func corpusDescriptor(row string) (*descriptorpb.FileDescriptorProto, error) {
	parts := strings.Split(row, "\t")
	if len(parts) != 4 {
		return nil, fmt.Errorf("a descriptor row with %d fields", len(parts))
	}
	raw, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	descriptor := &descriptorpb.FileDescriptorProto{}
	return descriptor, proto.Unmarshal(raw, descriptor)
}

// What the current descriptor removed or changed of the base descriptor. Additions are free.
func descriptorRemovals(base *descriptorpb.FileDescriptorProto, current *descriptorpb.FileDescriptorProto) []string {
	problems := []string{}
	if base.GetPackage() != current.GetPackage() || base.GetSyntax() != current.GetSyntax() {
		problems = append(problems, fmt.Sprintf("the schema is package %q syntax %q, the base %q %q", current.GetPackage(), current.GetSyntax(), base.GetPackage(), base.GetSyntax()))
	}
	for _, dependency := range base.GetDependency() {
		if !slices.Contains(current.GetDependency(), dependency) {
			problems = append(problems, "the schema no longer imports "+dependency)
		}
	}
	var enums func(scope string, base, current []*descriptorpb.EnumDescriptorProto)
	enums = func(scope string, base, current []*descriptorpb.EnumDescriptorProto) {
		for _, baseEnum := range base {
			name := scope + baseEnum.GetName()
			index := slices.IndexFunc(current, func(e *descriptorpb.EnumDescriptorProto) bool { return e.GetName() == baseEnum.GetName() })
			if index < 0 {
				problems = append(problems, "enum "+name+" was removed")
				continue
			}
			currentEnum := current[index]
			for _, value := range baseEnum.GetValue() {
				at := slices.IndexFunc(currentEnum.GetValue(), func(v *descriptorpb.EnumValueDescriptorProto) bool { return v.GetName() == value.GetName() })
				switch {
				case at < 0:
					problems = append(problems, fmt.Sprintf("enum value %s.%s was removed", name, value.GetName()))
				case !proto.Equal(value, currentEnum.GetValue()[at]):
					problems = append(problems, fmt.Sprintf("enum value %s.%s changed", name, value.GetName()))
				}
			}
			if !proto.Equal(baseEnum.GetOptions(), currentEnum.GetOptions()) {
				problems = append(problems, "enum "+name+"'s options changed")
			}
		}
	}
	var messages func(scope string, base, current []*descriptorpb.DescriptorProto)
	messages = func(scope string, base, current []*descriptorpb.DescriptorProto) {
		for _, baseMessage := range base {
			name := scope + baseMessage.GetName()
			index := slices.IndexFunc(current, func(m *descriptorpb.DescriptorProto) bool { return m.GetName() == baseMessage.GetName() })
			if index < 0 {
				problems = append(problems, "message "+name+" was removed")
				continue
			}
			currentMessage := current[index]
			for _, field := range baseMessage.GetField() {
				at := slices.IndexFunc(currentMessage.GetField(), func(f *descriptorpb.FieldDescriptorProto) bool { return f.GetName() == field.GetName() })
				switch {
				case at < 0:
					problems = append(problems, fmt.Sprintf("field %s.%s was removed", name, field.GetName()))
				case !proto.Equal(field, currentMessage.GetField()[at]):
					problems = append(problems, fmt.Sprintf("field %s.%s changed", name, field.GetName()))
				}
			}
			for i, oneof := range baseMessage.GetOneofDecl() {
				if i >= len(currentMessage.GetOneofDecl()) || !proto.Equal(oneof, currentMessage.GetOneofDecl()[i]) {
					problems = append(problems, fmt.Sprintf("oneof %s.%s moved or changed", name, oneof.GetName()))
				}
			}
			for _, reserved := range baseMessage.GetReservedRange() {
				if !slices.ContainsFunc(currentMessage.GetReservedRange(), func(r *descriptorpb.DescriptorProto_ReservedRange) bool { return proto.Equal(r, reserved) }) {
					problems = append(problems, fmt.Sprintf("message %s no longer reserves %d-%d", name, reserved.GetStart(), reserved.GetEnd()))
				}
			}
			for _, reserved := range baseMessage.GetReservedName() {
				if !slices.Contains(currentMessage.GetReservedName(), reserved) {
					problems = append(problems, fmt.Sprintf("message %s no longer reserves the name %s", name, reserved))
				}
			}
			if !proto.Equal(baseMessage.GetOptions(), currentMessage.GetOptions()) {
				problems = append(problems, "message "+name+"'s options changed")
			}
			messages(name+".", baseMessage.GetNestedType(), currentMessage.GetNestedType())
			enums(name+".", baseMessage.GetEnumType(), currentMessage.GetEnumType())
		}
	}
	messages(base.GetPackage()+".", base.GetMessageType(), current.GetMessageType())
	enums(base.GetPackage()+".", base.GetEnumType(), current.GetEnumType())
	return problems
}

// What the file owes the append-only rule, given what this package emits today.
func appendOnlyProblems(file []string, current []string) []string {
	problems := []string{}
	if len(file) < wireGoldenBaseLines {
		return []string{fmt.Sprintf("the corpus has %d lines; its base alone is %d", len(file), wireGoldenBaseLines)}
	}
	base := file[:wireGoldenBaseLines]
	if sum := sha256.Sum256([]byte(strings.Join(base, "\n") + "\n")); hex.EncodeToString(sum[:]) != wireGoldenBaseSha256 {
		problems = append(problems, fmt.Sprintf("D: the base lines hash to %x, pinned %s: a base row was edited", sum, wireGoldenBaseSha256))
	}
	inFile := map[string]bool{}
	for _, row := range file {
		if inFile[row] {
			problems = append(problems, "the corpus holds a row twice: "+row[:min(len(row), 120)])
		}
		inFile[row] = true
	}
	emitted := map[string]bool{}
	currentDescriptor := ""
	for _, row := range current {
		emitted[row] = true
		if corpusKind(row) == wireGoldenDescriptor {
			currentDescriptor = row
		}
	}
	for _, row := range base {
		if corpusKind(row) != wireGoldenDescriptor {
			if !emitted[row] {
				parts := strings.SplitN(row, "\t", 4)
				problems = append(problems, fmt.Sprintf("A: base row %s %s %s is not emitted byte for byte any more", parts[0], parts[1], parts[2]))
			}
			continue
		}
		baseDescriptor, err := corpusDescriptor(row)
		if err != nil {
			problems = append(problems, "A: the base descriptor row does not decode: "+err.Error())
			continue
		}
		now, err := corpusDescriptor(currentDescriptor)
		if err != nil {
			problems = append(problems, "A: this package's descriptor row does not decode: "+err.Error())
			continue
		}
		for _, removal := range descriptorRemovals(baseDescriptor, now) {
			problems = append(problems, "A: "+removal)
		}
	}
	for _, row := range current {
		if !inFile[row] {
			parts := strings.SplitN(row, "\t", 4)
			problems = append(problems, fmt.Sprintf("B: %s %s %s is emitted and not in the corpus: append it", parts[0], parts[1], parts[2]))
		}
	}
	for _, row := range file[wireGoldenBaseLines:] {
		if !emitted[row] {
			parts := strings.SplitN(row, "\t", 4)
			problems = append(problems, fmt.Sprintf("C: appended row %s %s %s is not emitted any more", parts[0], parts[1], parts[2]))
		}
	}
	return problems
}

func TestTheWireCorpusIsAppendOnly(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	for _, problem := range appendOnlyProblems(file, current) {
		t.Error(problem)
	}
	// the type set, both ways: the messages with rows are the descriptor's messages
	descriptorRow := current[slices.IndexFunc(current, func(row string) bool { return corpusKind(row) == wireGoldenDescriptor })]
	descriptor, err := corpusDescriptor(descriptorRow)
	if err != nil {
		t.Fatal(err)
	}
	declared := []string{}
	for _, message := range descriptor.GetMessageType() {
		declared = append(declared, descriptor.GetPackage()+"."+message.GetName())
	}
	withRows := []string{}
	for _, row := range file {
		if corpusKind(row) == "msg" {
			_, rest, _ := strings.Cut(row, "\t")
			name, _, _ := strings.Cut(rest, "\t")
			withRows = append(withRows, name)
		}
	}
	slices.Sort(declared)
	slices.Sort(withRows)
	withRows = slices.Compact(withRows)
	if !slices.Equal(declared, withRows) {
		t.Errorf("the descriptor declares %d messages and the corpus has rows for %d; they must be the same set", len(declared), len(withRows))
	}
	t.Logf("%d corpus rows (%d base, %d appended); this package emits %d; %d messages, each with its rows",
		len(file), wireGoldenBaseLines, len(file)-wireGoldenBaseLines, len(current), len(declared))
}

// Every way a change could break the rule, applied to the real corpus and the real
// re-emission, must be reported for its own reason; an addition must not be.
func TestTheAppendOnlyRuleReportsEachWayACorpusCanBreak(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	if problems := appendOnlyProblems(file, current); len(problems) != 0 {
		t.Fatalf("the controls start from a corpus the rule already rejects: %v", problems)
	}
	descriptorAt := slices.IndexFunc(current, func(row string) bool { return corpusKind(row) == wireGoldenDescriptor })
	msgAt := slices.IndexFunc(current, func(row string) bool { return strings.HasPrefix(row, "msg\tbringyour.MessageServerRequest\tdepth=2\t") })
	if descriptorAt < 0 || msgAt < 0 {
		t.Fatal("the re-emission holds no descriptor row or no MessageServerRequest depth=2 row to mutate")
	}
	withDescriptor := func(mutate func(*descriptorpb.FileDescriptorProto)) []string {
		descriptor, err := corpusDescriptor(current[descriptorAt])
		if err != nil {
			t.Fatal(err)
		}
		mutate(descriptor)
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		mutated := slices.Clone(current)
		parts := strings.Split(mutated[descriptorAt], "\t")
		parts[3] = hex.EncodeToString(raw)
		mutated[descriptorAt] = strings.Join(parts, "\t")
		return mutated
	}
	message := func(d *descriptorpb.FileDescriptorProto, name string) *descriptorpb.DescriptorProto {
		for _, m := range d.GetMessageType() {
			if m.GetName() == name {
				return m
			}
		}
		t.Fatalf("no message %s", name)
		return nil
	}
	changedBytes := slices.Clone(current)
	changedBytes[msgAt] = changedBytes[msgAt] + "00"
	controls := []struct {
		name          string
		file, current []string
		want          string
	}{
		{"a base row's bytes changed", file, changedBytes, "A: base row msg bringyour.MessageServerRequest depth=2 is not emitted byte for byte"},
		{"a base row edited in the file", append([]string{file[0] + "00"}, file[1:]...), current, "D: the base lines hash to"},
		{"an emitted row not appended", file, append(slices.Clone(current), "msg\tbringyour.NewMessage\tempty\t"), "B: msg bringyour.NewMessage empty is emitted and not in the corpus"},
		{"an appended row orphaned", append(slices.Clone(file), "msg\tbringyour.GoneMessage\tempty\t"), current, "C: appended row msg bringyour.GoneMessage empty is not emitted"},
		{"a field removed", file, withDescriptor(func(d *descriptorpb.FileDescriptorProto) {
			m := message(d, "MessageServerRequest")
			m.Field = m.Field[1:]
		}), "A: field bringyour.MessageServerRequest."},
		{"a field renumbered", file, withDescriptor(func(d *descriptorpb.FileDescriptorProto) {
			m := message(d, "MessageServerRequest")
			m.Field[0].Number = proto.Int32(m.Field[0].GetNumber() + 1000)
		}), "changed"},
		{"an enum value removed", file, withDescriptor(func(d *descriptorpb.FileDescriptorProto) {
			e := d.GetEnumType()[0]
			e.Value = e.Value[:len(e.Value)-1]
		}), "A: enum value bringyour."},
		{"a message removed", file, withDescriptor(func(d *descriptorpb.FileDescriptorProto) {
			d.MessageType = d.MessageType[:len(d.MessageType)-1]
		}), "was removed"},
	}
	for _, control := range controls {
		problems := appendOnlyProblems(control.file, control.current)
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, control.want) }) {
			t.Errorf("control %q was not reported (want %q): %q", control.name, control.want, problems)
		}
	}
	// a field ADDED to the descriptor is an addition, and the DESCRIPTOR half of the rule accepts
	// it once the new descriptor row is appended. (A real addition to an existing message also
	// changes that message's fully populated rows, which rule A refuses: the base rows are the
	// encodings as they were, so adding to an existing message is a reviewed re-basing of the
	// corpus, never a silent append. A new message, or a new arm, only appends.)
	added := withDescriptor(func(d *descriptorpb.FileDescriptorProto) {
		m := message(d, "MessageServerRequest")
		m.Field = append(m.Field, &descriptorpb.FieldDescriptorProto{
			Name: proto.String("added_later"), Number: proto.Int32(9000), JsonName: proto.String("addedLater"),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BYTES.Enum(),
		})
	})
	problems := appendOnlyProblems(append(slices.Clone(file), added[descriptorAt]), added)
	if len(problems) != 0 {
		t.Errorf("a field added later, with its descriptor row appended, was refused: %q", problems)
	}
}
