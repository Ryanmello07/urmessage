// wiregolden emits the wire and authentication-input corpus of message.proto from a binary that
// links exactly ONE generated copy of the schema, chosen by build tag:
//
//	-tags orig: github.com/urnetwork/connect/protocol, from a connect checkout from BEFORE the
//	            schema left connect (the sibling ../../../../connect-golden, pinned in
//	            .github/siblings.txt), as connect committed it;
//	-tags new:  github.com/urnetwork/message/protocol, this repository's, regenerated once with
//	            go_package github.com/urnetwork/message/protocol.
//
//	wiregolden emit            one line per item: kind \t message full name \t label \t hex
//	wiregolden check <file>    decode every line of another build's corpus into THIS build's Go
//	                           types, re-marshal deterministically, and require identical bytes
//
// protocol/testdata/wire-golden.tsv is the committed corpus; its first lines are the corpus
// connect's copy emitted, and protocol/message_wiregolden_test.go holds the rule that keeps
// them: the corpus is append-only. This module lives under testdata so `go test ./...` and every
// scanner that skips testdata leave it alone; CI's wire-golden job runs it with both tags.
//
// The emitter was written for inventory D of the move (2026-10-04) and is unchanged in what it
// emits; only its output is routed through emit's writers so its own test can read it.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// sampleScalar is connect/protocol/message_test.go's, extended to every scalar kind so an
// unexpected kind fails loudly instead of being skipped.
func sampleScalar(fd protoreflect.FieldDescriptor, seed int) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(seed%2 == 0)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(1000 + seed))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(1_000_000 + seed))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(1000 + seed))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(1_000_000 + seed))
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(seed) + 0.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(float64(seed) + 0.25)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(fmt.Sprintf("sample-%s-%d", fd.Name(), seed))
	case protoreflect.BytesKind:
		b := make([]byte, 8)
		for i := range b {
			b[i] = byte(seed + i + 1)
		}
		return protoreflect.ValueOfBytes(b)
	case protoreflect.EnumKind:
		vals := fd.Enum().Values()
		idx := 0
		if vals.Len() > 1 {
			idx = 1 + (seed % (vals.Len() - 1))
		}
		return protoreflect.ValueOfEnum(vals.Get(idx).Number())
	}
	panic(fmt.Sprintf("unhandled kind %v on %s", fd.Kind(), fd.FullName()))
}

// populate is connect/protocol/message_test.go's: every non-oneof field, depth levels deep.
func populate(m protoreflect.Message, depth int) {
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.ContainingOneof() != nil {
			continue
		}
		switch {
		case fd.IsMap():
			mp := m.Mutable(fd).Map()
			want := 8
			if fd.MapKey().Kind() == protoreflect.BoolKind {
				want = 2
			}
			for k := 0; k < want; k++ {
				key := sampleScalar(fd.MapKey(), k).MapKey()
				val := fd.MapValue()
				if val.Kind() == protoreflect.MessageKind || val.Kind() == protoreflect.GroupKind {
					sub := mp.NewValue()
					if depth > 0 {
						populate(sub.Message(), depth-1)
					}
					mp.Set(key, sub)
				} else {
					mp.Set(key, sampleScalar(val, k))
				}
			}
		case fd.IsList():
			list := m.Mutable(fd).List()
			for k := 0; k < 3; k++ {
				if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
					sub := list.NewElement()
					if depth > 0 {
						populate(sub.Message(), depth-1)
					}
					list.Append(sub)
				} else {
					list.Append(sampleScalar(fd, k))
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			sub := m.NewField(fd)
			if depth > 0 {
				populate(sub.Message(), depth-1)
			}
			m.Set(fd, sub)
		default:
			m.Set(fd, sampleScalar(fd, i))
		}
	}
}

func newOf(name protoreflect.FullName) protoreflect.Message {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(name)
	must(err)
	return mt.New()
}

var det = proto.MarshalOptions{Deterministic: true}

// emit writes the corpus, one sorted line per item, to w, and a two-line summary to diag.
func emit(w io.Writer, diag io.Writer) {
	fd := fileDesc
	var lines []string
	add := func(kind string, name protoreflect.FullName, label string, b []byte) {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%x", kind, name, label, b))
	}

	// 1. every message, fully populated two levels deep; plus the empty message
	msgs := fd.Messages()
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		for _, depth := range []int{0, 2} {
			m := newOf(md.FullName())
			populate(m, depth)
			b, err := det.Marshal(m.Interface())
			must(err)
			add("msg", md.FullName(), fmt.Sprintf("depth=%d", depth), b)
		}
		b, err := det.Marshal(newOf(md.FullName()).Interface())
		must(err)
		add("msg", md.FullName(), "empty", b)
	}

	// 2. every oneof arm of every message (the three envelopes' `body` and any other oneof)
	arms := 0
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		for o := 0; o < md.Oneofs().Len(); o++ {
			od := md.Oneofs().Get(o)
			for j := 0; j < od.Fields().Len(); j++ {
				arm := od.Fields().Get(j)
				env := newOf(md.FullName())
				populate(env, 0)
				var v protoreflect.Value
				if arm.Kind() == protoreflect.MessageKind {
					v = env.NewField(arm)
					populate(v.Message(), 2)
				} else {
					v = sampleScalar(arm, j)
				}
				env.Set(arm, v)
				b, err := det.Marshal(env.Interface())
				must(err)
				target := ""
				if arm.Message() != nil {
					target = string(arm.Message().FullName())
				}
				add("arm", md.FullName(), fmt.Sprintf("%s.%s=%d(%s)", od.Name(), arm.Name(), arm.Number(), target), b)
				arms++
			}
		}
	}

	// 3. section 4.3.8 canonical_request_bytes and op for every request carrying req_auth
	reqBody := fd.Messages().ByName("MessageServerRequest").Oneofs().ByName("body")
	canon := 0
	for i := 0; i < msgs.Len(); i++ {
		md := msgs.Get(i)
		f := md.Fields().ByName("req_auth")
		if f == nil {
			continue
		}
		op := -1
		for j := 0; j < reqBody.Fields().Len(); j++ {
			if reqBody.Fields().Get(j).Message().FullName() == md.FullName() {
				op = int(reqBody.Fields().Get(j).Number())
			}
		}
		m := newOf(md.FullName())
		populate(m, 2)
		m.Set(f, protoreflect.ValueOfBytes(bytes.Repeat([]byte{0xab}, 32)))
		m.Clear(f)
		b, err := det.Marshal(m.Interface())
		must(err)
		add("canonical", md.FullName(), fmt.Sprintf("op=%d", op), b)
		canon++
	}

	// 4. the descriptor itself, with go_package removed
	fdp := protodesc.ToFileDescriptorProto(fd)
	gp := fdp.GetOptions().GetGoPackage()
	with, err := det.Marshal(fdp)
	must(err)
	fdp.Options.GoPackage = nil
	without, err := det.Marshal(fdp)
	must(err)
	add("descriptor-without-go_package", protoreflect.FullName(fd.Package()), string(fd.Path()), without)

	sort.Strings(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	gpp := "?"
	if g, ok := fd.(interface{ GoPackagePath() string }); ok {
		gpp = g.GoPackagePath()
	}
	sumWith := sha256.Sum256(with)
	fmt.Fprintf(diag, "file=%q package=%s go_package=%q runtime GoPackagePath=%q messages=%d enums=%d\n",
		fd.Path(), fd.Package(), gp, gpp, msgs.Len(), fd.Enums().Len())
	fmt.Fprintf(diag, "items=%d (oneof arms=%d, canonical requests=%d) descriptor-with-go_package sha256=%x len=%d; without len=%d\n",
		len(lines), arms, canon, sumWith, len(with), len(without))
}

// check decodes another build's corpus into this build's types and re-encodes it; it answers
// how many items were decoded and how many re-encoded byte-identical without unknown fields.
func check(r io.Reader, out io.Writer) (decoded int, identical int) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) != 4 || parts[0] == "descriptor-without-go_package" {
			continue
		}
		b, err := hex.DecodeString(parts[3])
		must(err)
		m := newOf(protoreflect.FullName(parts[1]))
		must(proto.UnmarshalOptions{DiscardUnknown: false}.Unmarshal(b, m.Interface()))
		again, err := det.Marshal(m.Interface())
		must(err)
		decoded++
		switch {
		case m.GetUnknown() != nil:
			fmt.Fprintf(out, "UNKNOWN FIELDS after decode: %s %s\n", parts[1], parts[2])
		case !bytes.Equal(b, again):
			fmt.Fprintf(out, "DIFFERENT: %s %s\n", parts[1], parts[2])
		default:
			identical++
		}
	}
	must(sc.Err())
	return decoded, identical
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "check" {
		f, err := os.Open(os.Args[2])
		must(err)
		defer f.Close()
		decoded, identical := check(f, os.Stdout)
		fmt.Printf("cross-decoded %d items from %s; %d re-encoded byte-identical\n", decoded, os.Args[2], identical)
		if decoded == 0 || decoded != identical {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] != "emit" {
		fmt.Fprintln(os.Stderr, "usage: wiregolden [emit] | wiregolden check <corpus>")
		os.Exit(2)
	}
	emit(os.Stdout, os.Stderr)
}
