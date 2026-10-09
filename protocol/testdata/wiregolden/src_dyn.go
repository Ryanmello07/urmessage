//go:build dyn

package main

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// -tags dyn: the schema is a serialized FileDescriptorProto read from the file named by
// WIREGOLDEN_DESCRIPTOR, built with protodesc and registered as dynamic message types, so a schema
// that exists only as a descriptor -- a change being weighed, or one of the append-only rule's
// controls -- emits through exactly the code that emits the generated schemas. No generated copy of
// message.proto is linked, so nothing registers twice. The variable is required: a dyn build with no
// descriptor has no schema, and it says so rather than emitting nothing.
//
// protocol/message_wiregolden_test.go runs it, and checks first that the descriptor this package
// emits, read back this way, emits this package's corpus byte for byte.
var fileDesc = dynamicFile()

func dynamicFile() protoreflect.FileDescriptor {
	path := os.Getenv("WIREGOLDEN_DESCRIPTOR")
	if path == "" {
		panic("-tags dyn needs WIREGOLDEN_DESCRIPTOR: a file holding a serialized FileDescriptorProto")
	}
	raw, err := os.ReadFile(path)
	must(err)
	descriptor := &descriptorpb.FileDescriptorProto{}
	must(proto.Unmarshal(raw, descriptor))
	file, err := protodesc.NewFile(descriptor, protoregistry.GlobalFiles)
	must(err)
	must(protoregistry.GlobalFiles.RegisterFile(file))
	var register func(messages protoreflect.MessageDescriptors)
	register = func(messages protoreflect.MessageDescriptors) {
		for i := 0; i < messages.Len(); i++ {
			message := messages.Get(i)
			must(protoregistry.GlobalTypes.RegisterMessage(dynamicpb.NewMessageType(message)))
			register(message.Messages())
		}
	}
	register(file.Messages())
	if file.Messages().Len() == 0 {
		panic(fmt.Sprintf("the descriptor in %s declares no message", path))
	}
	return file
}
