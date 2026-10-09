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
// schema left connect, pinned here by digest. test.sh's wire-golden step re-emits them from that
// pinned connect checkout (-tags orig) and requires those exact bytes, then decodes connect's
// emission into this package's types and the base into connect's, each re-encoding identically.
// That is the proof the move left every authenticated inner byte where it was
// (MESSAGEREVIEW.md, "Completion checks").
//
// From here on the corpus only grows, and what it holds stays readable. The rule is the
// compatibility property itself, not a freeze: a schema change is accepted exactly when every
// encoding already recorded still means what it meant. This test re-emits the corpus from this
// package, with no sibling checkout, and holds:
//
//	A. every base row of kind msg, arm or canonical decodes into this package's type of that name
//	   with no unknown field at any depth, and re-marshals deterministically to exactly its bytes;
//	   the base descriptor is a structural subset of this package's (every message, field, oneof,
//	   enum and value of the base is here unchanged). The decode half sees a field removed,
//	   renumbered or retyped onto another wire type; the descriptor half sees what decodes the same
//	   and means something else (uint64 to int64, a name, a json_name);
//	B. every row this package emits is in the file: a new message or arm, and a field added to an
//	   existing message (which changes its fully populated rows), append their rows;
//	C. every row after the base is held as A holds the base: an appended row, and an appended
//	   descriptor, are never orphaned by a later change;
//	D. the base lines are the pinned bytes, forever. They are what connect's copy emitted, and
//	   test.sh compares them byte for byte with a pinned connect from before the removal, which
//	   stays true however the schema grows;
//
// and the messages with rows are the descriptor's messages, both ways.
//
// Decoding is in process. The real run reads rows with the generated types this package
// registers; the controls read them with dynamic types built from a changed descriptor, and emit
// that schema's corpus through testdata/wiregolden's -tags dyn, the same emitter code.

import (
	"bytes"
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
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/urnetwork/message/protocol"
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

// The message types a rule reads rows with, by full name: the generated ones this package
// registers, or dynamic ones built from a descriptor.
type wireTypes interface {
	FindMessageByName(protoreflect.FullName) (protoreflect.MessageType, error)
}

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
		reemitLines, reemitErr = emitCorpus("new", nil)
	})
	if reemitErr != nil {
		t.Fatalf("re-emit the corpus from this package: %v", reemitErr)
	}
	return slices.Clone(reemitLines)
}

// Runs testdata/wiregolden's emit with the build tag given. For -tags dyn, descriptor is the
// serialized FileDescriptorProto of the schema to emit, handed over in a file.
func emitCorpus(tag string, descriptor []byte) ([]string, error) {
	root, err := filepath.Abs("..")
	if err != nil {
		return nil, err
	}
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return nil, err
	}
	protobuf := ""
	for _, line := range strings.Split(string(goMod), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "google.golang.org/protobuf" {
			protobuf = fields[1]
		}
	}
	if protobuf == "" {
		return nil, fmt.Errorf("go.mod requires no google.golang.org/protobuf")
	}
	goSum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		return nil, err
	}
	scratch, err := os.MkdirTemp("", "wiregolden")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	modFile := fmt.Sprintf("module github.com/urnetwork/message/protocol/testdata/wiregolden\n\ngo 1.26.3\n\n"+
		"require (\n\tgithub.com/urnetwork/message v0.0.0\n\tgoogle.golang.org/protobuf %s\n)\n\n"+
		"replace github.com/urnetwork/message => %s\n", protobuf, filepath.ToSlash(root))
	if err := os.WriteFile(filepath.Join(scratch, "emit.mod"), []byte(modFile), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(scratch, "emit.sum"), goSum, 0o600); err != nil {
		return nil, err
	}
	command := exec.Command("go", "run", "-modfile="+filepath.Join(scratch, "emit.mod"), "-tags", tag, ".", "emit")
	command.Dir = filepath.Join("testdata", "wiregolden")
	command.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	if descriptor != nil {
		path := filepath.Join(scratch, "schema.descriptor")
		if err := os.WriteFile(path, descriptor, 0o600); err != nil {
			return nil, err
		}
		command.Env = append(command.Env, "WIREGOLDEN_DESCRIPTOR="+path)
	}
	out, err := command.Output()
	if err != nil {
		if exit, isExit := err.(*exec.ExitError); isExit {
			err = fmt.Errorf("%w: %s", err, exit.Stderr)
		}
		return nil, err
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"), nil
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

// The dynamic message types of a descriptor: what the controls read rows with, for a schema that
// exists only as a changed descriptor.
func dynamicWireTypes(descriptor *descriptorpb.FileDescriptorProto) (wireTypes, error) {
	file, err := protodesc.NewFile(descriptor, nil)
	if err != nil {
		return nil, err
	}
	types := &protoregistry.Types{}
	var register func(messages protoreflect.MessageDescriptors) error
	register = func(messages protoreflect.MessageDescriptors) error {
		for i := 0; i < messages.Len(); i++ {
			if err := types.RegisterMessage(dynamicpb.NewMessageType(messages.Get(i))); err != nil {
				return err
			}
			if err := register(messages.Get(i).Messages()); err != nil {
				return err
			}
		}
		return nil
	}
	return types, register(file.Messages())
}

// Where a decoded message holds fields its type does not declare, at any depth; "" if nowhere. A
// field the schema no longer declares, or declares under another number or wire type, arrives as
// an unknown field, and re-marshalling carries an unknown field along unseen when it was the last
// one, so byte equality alone would miss it.
func unknownFieldsIn(m protoreflect.Message, path string) string {
	if len(m.GetUnknown()) > 0 {
		return path
	}
	found := ""
	m.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList() && field.Message() != nil:
			list := value.List()
			for i := 0; i < list.Len() && found == ""; i++ {
				found = unknownFieldsIn(list.Get(i).Message(), fmt.Sprintf("%s.%s[%d]", path, field.Name(), i))
			}
		case field.IsMap() && field.MapValue().Message() != nil:
			value.Map().Range(func(key protoreflect.MapKey, entry protoreflect.Value) bool {
				found = unknownFieldsIn(entry.Message(), fmt.Sprintf("%s.%s[%v]", path, field.Name(), key.Interface()))
				return found == ""
			})
		case !field.IsList() && !field.IsMap() && field.Message() != nil:
			found = unknownFieldsIn(value.Message(), path+"."+string(field.Name()))
		}
		return found == ""
	})
	return found
}

// What a recorded msg, arm or canonical row owes the schema: it decodes into the schema's type of
// that name with no unknown field at any depth, and re-marshals deterministically to exactly its
// bytes. nil when it does.
func rowReadsTheSame(types wireTypes, row string) error {
	parts := strings.Split(row, "\t")
	if len(parts) != 4 {
		return fmt.Errorf("a row with %d fields", len(parts))
	}
	raw, err := hex.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("its hex does not decode: %v", err)
	}
	messageType, err := types.FindMessageByName(protoreflect.FullName(parts[1]))
	if err != nil {
		return fmt.Errorf("the schema has no message %s", parts[1])
	}
	message := messageType.New()
	if err := proto.Unmarshal(raw, message.Interface()); err != nil {
		return fmt.Errorf("does not decode: %v", err)
	}
	if where := unknownFieldsIn(message, parts[1]); where != "" {
		return fmt.Errorf("decodes with unknown fields at %s", where)
	}
	again, err := proto.MarshalOptions{Deterministic: true}.Marshal(message.Interface())
	if err != nil {
		return fmt.Errorf("does not re-marshal: %v", err)
	}
	if !bytes.Equal(raw, again) {
		return fmt.Errorf("re-marshals to different bytes")
	}
	return nil
}

// What the current descriptor removed or changed of a recorded descriptor. Additions are free.
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

// What the file owes the append-only rule, given what the schema emits today (current, which holds
// its descriptor row) and the types it reads rows with.
func appendOnlyProblems(file []string, current []string, types wireTypes) []string {
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
	currentDescriptor := ""
	for _, row := range current {
		if corpusKind(row) == wireGoldenDescriptor {
			currentDescriptor = row
		}
	}
	now, err := corpusDescriptor(currentDescriptor)
	if err != nil {
		return append(problems, "the schema's own descriptor row does not decode: "+err.Error())
	}
	for i, row := range file {
		rule := "A: base row"
		if i >= wireGoldenBaseLines {
			rule = "C: appended row"
		}
		parts := strings.SplitN(row, "\t", 4)
		if len(parts) != 4 {
			problems = append(problems, fmt.Sprintf("%s %d has %d fields", rule, i+1, len(parts)))
			continue
		}
		if parts[0] != wireGoldenDescriptor {
			if err := rowReadsTheSame(types, row); err != nil {
				problems = append(problems, fmt.Sprintf("%s %s %s %s %v", rule, parts[0], parts[1], parts[2], err))
			}
			continue
		}
		recorded, err := corpusDescriptor(row)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s %s does not decode: %v", rule, parts[0], err))
			continue
		}
		for _, removal := range descriptorRemovals(recorded, now) {
			problems = append(problems, fmt.Sprintf("%s %s: %s", rule, parts[0], removal))
		}
	}
	for _, row := range current {
		if !inFile[row] {
			parts := strings.SplitN(row, "\t", 4)
			problems = append(problems, fmt.Sprintf("B: %s %s %s is emitted and not in the corpus: append it", parts[0], parts[1], parts[2]))
		}
	}
	return problems
}

func TestTheWireCorpusIsAppendOnly(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	for _, problem := range appendOnlyProblems(file, current, protoregistry.GlobalTypes) {
		t.Error(problem)
	}
	// the types the rule read the rows with are this package's: every message with a row
	// resolves to message.proto as this package registers it
	for _, row := range file {
		if corpusKind(row) == wireGoldenDescriptor {
			continue
		}
		name := strings.SplitN(row, "\t", 3)[1]
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(name))
		if err != nil || messageType.Descriptor().ParentFile() != protocol.File_message_proto {
			t.Fatalf("%s does not resolve to this package's message.proto (%v)", name, err)
		}
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

// A changed schema, as the controls need it: the corpus it emits (testdata/wiregolden -tags dyn)
// and its dynamic types.
type wireSchemaChange struct {
	emitted []string
	types   wireTypes
}

func changeWireSchema(t *testing.T, current []string, mutate func(*descriptorpb.FileDescriptorProto)) wireSchemaChange {
	t.Helper()
	descriptor, err := corpusDescriptor(current[slices.IndexFunc(current, func(row string) bool { return corpusKind(row) == wireGoldenDescriptor })])
	if err != nil {
		t.Fatal(err)
	}
	mutate(descriptor)
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	emitted, err := emitCorpus("dyn", raw)
	if err != nil {
		t.Fatalf("emit the changed schema with -tags dyn: %v", err)
	}
	types, err := dynamicWireTypes(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return wireSchemaChange{emitted: emitted, types: types}
}

func wireMessage(t *testing.T, d *descriptorpb.FileDescriptorProto, name string) *descriptorpb.DescriptorProto {
	t.Helper()
	for _, m := range d.GetMessageType() {
		if m.GetName() == name {
			return m
		}
	}
	t.Fatalf("no message %s", name)
	return nil
}

func wireField(t *testing.T, m *descriptorpb.DescriptorProto, name string) *descriptorpb.FieldDescriptorProto {
	t.Helper()
	for _, f := range m.GetField() {
		if f.GetName() == name {
			return f
		}
	}
	t.Fatalf("no field %s.%s", m.GetName(), name)
	return nil
}

// One optional uint64 field appended to a message, under the next free number.
func wireFieldAppended(t *testing.T, message string) func(*descriptorpb.FileDescriptorProto) {
	return func(d *descriptorpb.FileDescriptorProto) {
		m := wireMessage(t, d, message)
		next := int32(0)
		for _, f := range m.GetField() {
			next = max(next, f.GetNumber())
		}
		m.Field = append(m.Field, &descriptorpb.FieldDescriptorProto{
			Name: proto.String("added_later"), Number: proto.Int32(next + 1), JsonName: proto.String("addedLater"),
			Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum(),
		})
	}
}

// The rows a changed schema emits that the file does not hold yet, in emission order: what B asks
// a developer to append.
func rowsToAppend(file []string, emitted []string) []string {
	have := map[string]bool{}
	for _, row := range file {
		have[row] = true
	}
	appended := []string{}
	for _, row := range emitted {
		if !have[row] {
			appended = append(appended, row)
		}
	}
	return appended
}

// The dynamic route the controls take is the generated route, byte for byte: the descriptor this
// package emits, read back with -tags dyn, emits this package's corpus exactly, and the corpus
// read with its dynamic types satisfies the rule. Without this, a control's verdict could be the
// dynamic route's and not the rule's.
func TestTheDynamicSchemaRouteIsTheGeneratedRoute(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	same := changeWireSchema(t, current, func(*descriptorpb.FileDescriptorProto) {})
	if !slices.Equal(same.emitted, current) {
		t.Fatalf("-tags dyn over this package's own descriptor emits %d rows, -tags new %d, and they differ", len(same.emitted), len(current))
	}
	if problems := appendOnlyProblems(file, same.emitted, same.types); len(problems) != 0 {
		t.Fatalf("the corpus read with the dynamic types of this package's own descriptor is refused: %q", problems)
	}
}

// The schema changes the rule must ACCEPT, each made to a real message and emitted through the
// emitter, with what B asks appended: one optional field appended to a small message, to the
// largest, and to a request carrying req_auth (whose canonical row changes too), and one value
// appended to an enum. Before the append, B and only B names the changed rows, so it is the append
// that makes each change acceptable; after it, A and C hold the old rows and the new alike.
func TestTheAppendOnlyRuleAcceptsAnAdditiveSchemaChange(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	if problems := appendOnlyProblems(file, current, protoregistry.GlobalTypes); len(problems) != 0 {
		t.Fatalf("the controls start from a corpus the rule already rejects: %v", problems)
	}
	for _, change := range []struct {
		name   string
		mutate func(*descriptorpb.FileDescriptorProto)
	}{
		{"a field appended to MessageServerFragment", wireFieldAppended(t, "MessageServerFragment")},
		{"a field appended to Record", wireFieldAppended(t, "Record")},
		{"a field appended to GroupStatusRequest", wireFieldAppended(t, "GroupStatusRequest")},
		{"a value appended to enum Direction", func(d *descriptorpb.FileDescriptorProto) {
			for _, e := range d.GetEnumType() {
				if e.GetName() == "Direction" {
					e.Value = append(e.Value, &descriptorpb.EnumValueDescriptorProto{Name: proto.String("DIRECTION_ADDED_LATER"), Number: proto.Int32(int32(len(e.Value)))})
					return
				}
			}
			t.Fatal("no enum Direction")
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := changeWireSchema(t, current, change.mutate)
			appended := rowsToAppend(file, changed.emitted)
			if len(appended) < 2 {
				t.Fatalf("the change re-emitted %d rows; a control that changes nothing proves nothing", len(appended))
			}
			before := appendOnlyProblems(file, changed.emitted, changed.types)
			for _, problem := range before {
				if !strings.HasPrefix(problem, "B: ") {
					t.Errorf("before the append, a problem other than B: %s", problem)
				}
			}
			if len(before) != len(appended) {
				t.Errorf("before the append, B named %d rows and the change emitted %d new ones", len(before), len(appended))
			}
			grown := append(slices.Clone(file), appended...)
			if problems := appendOnlyProblems(grown, changed.emitted, changed.types); len(problems) != 0 {
				t.Errorf("the change, with its %d rows appended, was refused: %q", len(appended), problems)
			}
			t.Logf("%s: %d rows appended, accepted", change.name, len(appended))
		})
	}
}

// Every way a change could break the rule, applied to the real corpus, must be reported for its
// own reason. The schema changes are emitted, appended and read exactly like the accepted ones
// above, so the only difference between a refusal here and an acceptance there is the change.
func TestTheAppendOnlyRuleReportsEachWayACorpusCanBreak(t *testing.T) {
	file := readCorpus(t)
	current := reemitCorpus(t)
	if problems := appendOnlyProblems(file, current, protoregistry.GlobalTypes); len(problems) != 0 {
		t.Fatalf("the controls start from a corpus the rule already rejects: %v", problems)
	}
	refused := func(t *testing.T, problems []string, wants ...string) {
		t.Helper()
		for _, want := range wants {
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, want) }) {
				t.Errorf("not reported: %q; reported %d: %q", want, len(problems), problems[:min(len(problems), 6)])
			}
		}
	}
	afterAppending := func(changed wireSchemaChange) []string {
		return appendOnlyProblems(append(slices.Clone(file), rowsToAppend(file, changed.emitted)...), changed.emitted, changed.types)
	}
	t.Run("a base row edited in the file", func(t *testing.T) {
		refused(t, appendOnlyProblems(append([]string{file[0] + "00"}, file[1:]...), current, protoregistry.GlobalTypes), "D: the base lines hash to")
	})
	t.Run("an emitted row not appended", func(t *testing.T) {
		refused(t, appendOnlyProblems(file, append(slices.Clone(current), "msg\tbringyour.NewMessage\tempty\t"), protoregistry.GlobalTypes),
			"B: msg bringyour.NewMessage empty is emitted and not in the corpus")
	})
	t.Run("an appended row whose message is gone", func(t *testing.T) {
		refused(t, appendOnlyProblems(append(slices.Clone(file), "msg\tbringyour.GoneMessage\tempty\t"), current, protoregistry.GlobalTypes),
			"C: appended row msg bringyour.GoneMessage empty the schema has no message bringyour.GoneMessage")
	})
	t.Run("an appended row that does not read the same", func(t *testing.T) {
		at := slices.IndexFunc(file, func(row string) bool {
			return strings.HasPrefix(row, "msg\tbringyour.MessageServerFragment\tdepth=0\t")
		})
		if at < 0 {
			t.Fatal("no MessageServerFragment depth=0 row")
		}
		// field 8191, varint 1, after the fields the schema declares
		refused(t, appendOnlyProblems(append(slices.Clone(file), file[at]+"f8ff0301"), current, protoregistry.GlobalTypes),
			"C: appended row msg bringyour.MessageServerFragment depth=0 decodes with unknown fields")
	})
	t.Run("a field renumbered", func(t *testing.T) {
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			f := wireField(t, wireMessage(t, d, "MessageServerFragment"), "index")
			f.Number = proto.Int32(f.GetNumber() + 1000)
		})
		refused(t, afterAppending(changed),
			"A: base row msg bringyour.MessageServerFragment depth=0 decodes with unknown fields",
			"A: base row descriptor-without-go_package: field bringyour.MessageServerFragment.index changed")
	})
	t.Run("a field retyped onto another wire type", func(t *testing.T) {
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			wireField(t, wireMessage(t, d, "MessageServerFragment"), "request_id").Type = descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
		})
		refused(t, afterAppending(changed),
			"A: base row msg bringyour.MessageServerFragment depth=0 decodes with unknown fields",
			"A: base row descriptor-without-go_package: field bringyour.MessageServerFragment.request_id changed")
	})
	t.Run("a field retyped onto the same wire type", func(t *testing.T) {
		// uint64 to int64 decodes the same varint and re-encodes it identically, so only the
		// descriptor half can see that the bytes now mean another number
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			wireField(t, wireMessage(t, d, "MessageServerFragment"), "request_id").Type = descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()
		})
		problems := afterAppending(changed)
		refused(t, problems, "A: base row descriptor-without-go_package: field bringyour.MessageServerFragment.request_id changed")
		if slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, "MessageServerFragment depth") }) {
			t.Errorf("the decode half reported a uint64 to int64 change it cannot see; the control is not what it says: %q", problems)
		}
	})
	t.Run("a field removed", func(t *testing.T) {
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			m := wireMessage(t, d, "MessageServerFragment")
			m.Field = slices.DeleteFunc(m.Field, func(f *descriptorpb.FieldDescriptorProto) bool { return f.GetName() == "part" })
		})
		refused(t, afterAppending(changed),
			"A: base row msg bringyour.MessageServerFragment depth=0 decodes with unknown fields",
			"A: base row descriptor-without-go_package: field bringyour.MessageServerFragment.part was removed")
	})
	t.Run("an enum value removed", func(t *testing.T) {
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			for _, e := range d.GetEnumType() {
				if e.GetName() == "Direction" {
					e.Value = e.Value[:len(e.Value)-1]
				}
			}
		})
		refused(t, afterAppending(changed),
			"A: base row descriptor-without-go_package: enum value bringyour.Direction.DIRECTION_DOWNLOAD was removed")
	})
	t.Run("a message removed", func(t *testing.T) {
		changed := changeWireSchema(t, current, func(d *descriptorpb.FileDescriptorProto) {
			d.MessageType = slices.DeleteFunc(d.MessageType, func(m *descriptorpb.DescriptorProto) bool { return m.GetName() == "MessageServerFragment" })
		})
		refused(t, afterAppending(changed),
			"A: base row msg bringyour.MessageServerFragment depth=0 the schema has no message bringyour.MessageServerFragment",
			"A: base row descriptor-without-go_package: message bringyour.MessageServerFragment was removed")
	})
	t.Run("an appended field removed again", func(t *testing.T) {
		// a field added and its rows appended, then the field removed: the rows the first change
		// appended are held as the base is, so the second change is refused for them
		added := changeWireSchema(t, current, wireFieldAppended(t, "MessageServerFragment"))
		grown := append(slices.Clone(file), rowsToAppend(file, added.emitted)...)
		if problems := appendOnlyProblems(grown, added.emitted, added.types); len(problems) != 0 {
			t.Fatalf("the addition itself was refused: %q", problems)
		}
		refused(t, appendOnlyProblems(grown, current, protoregistry.GlobalTypes),
			"C: appended row descriptor-without-go_package: field bringyour.MessageServerFragment.added_later was removed",
			"C: appended row msg bringyour.MessageServerFragment depth=0 decodes with unknown fields")
	})
}
