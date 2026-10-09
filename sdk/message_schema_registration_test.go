package sdk

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	connectprotocol "github.com/urnetwork/connect/protocol"
	messageprotocol "github.com/urnetwork/message/protocol"
)

// EVERY BINARY REGISTERS message.proto EXACTLY ONCE, AND THE COPY IT REGISTERS IS THIS REPOSITORY'S.
//
// The message-server schema (message.proto, package bringyour) moved from connect's protocol
// package to message/protocol, and the connect removal deletes connect's copy. A binary that linked
// a connect still carrying it would hold two files declaring the same names: protobuf refuses that
// at init, and with the conflict policy relaxed it would resolve a name to whichever copy
// registered first. Build and vet see neither, which is why every main package here has a test
// and why this one asks the registry itself, at run time:
//
//   - message.proto is registered, from github.com/urnetwork/message/protocol;
//   - every message it declares resolves, by full name, to a Go type of that package;
//   - exactly one registered file declares any of those names.
//
// The control: connect's Frame, in the same proto package, resolves to connect's protocol package,
// so the Go-package reading tells the two packages apart.
func TestOneCopyOfMessageProtoIsRegistered(t *testing.T) {
	const want = "github.com/urnetwork/message/protocol"
	file := (&messageprotocol.MessageServerRequest{}).ProtoReflect().Descriptor().ParentFile()
	registered, err := protoregistry.GlobalFiles.FindFileByPath(file.Path())
	if err != nil {
		t.Fatalf("%s is not registered: %v", file.Path(), err)
	}
	if registered != file {
		t.Fatalf("the registry's %s is not the descriptor message/protocol declares", file.Path())
	}
	options, _ := registered.Options().(*descriptorpb.FileOptions)
	if goPackage := options.GetGoPackage(); goPackage != want {
		t.Fatalf("the registered %s declares go_package %q, want %q", file.Path(), goPackage, want)
	}

	names := map[protoreflect.FullName]bool{}
	messages := file.Messages()
	for index := range messages.Len() {
		name := messages.Get(index).FullName()
		names[name] = true
		messageType, err := protoregistry.GlobalTypes.FindMessageByName(name)
		if err != nil {
			t.Errorf("%s does not resolve in the registry: %v", name, err)
			continue
		}
		if got := reflect.TypeOf(messageType.Zero().Interface()).Elem().PkgPath(); got != want {
			t.Errorf("%s resolves to a Go type of %s, want %s", name, got, want)
		}
	}
	if len(names) == 0 {
		t.Fatal("message.proto declares no message, so nothing above was asked")
	}

	declaring := []string{}
	protoregistry.GlobalFiles.RangeFiles(func(other protoreflect.FileDescriptor) bool {
		others := other.Messages()
		for index := range others.Len() {
			if names[others.Get(index).FullName()] {
				declaring = append(declaring, other.Path())
				break
			}
		}
		return true
	})
	if len(declaring) != 1 {
		t.Fatalf("%d registered files declare message.proto's names: %v; a binary must hold exactly one", len(declaring), declaring)
	}

	// THE CONTROL: the same reading, on a name of connect's in the same proto package
	frame, err := protoregistry.GlobalTypes.FindMessageByName((&connectprotocol.Frame{}).ProtoReflect().Descriptor().FullName())
	if err != nil {
		t.Fatalf("CONTROL FAILED: connect's Frame does not resolve: %v", err)
	}
	if got := reflect.TypeOf(frame.Zero().Interface()).Elem().PkgPath(); got != "github.com/urnetwork/connect/protocol" {
		t.Fatalf("CONTROL FAILED: connect's Frame resolves to %s, so the Go-package reading cannot tell the two packages apart", got)
	}
	t.Logf("%s is registered once, from %s: %d messages, each resolving to it; connect's Frame resolves to connect's protocol package",
		file.Path(), want, len(names))
}
