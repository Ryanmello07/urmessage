package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// cgoDirectory is sdk/cgo, the directory gen writes for and reads from.
func cgoDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test path")
	}
	return filepath.Join(filepath.Dir(filename), "..")
}

// coreSdkRoot is the core SDK checkout the composition is built against: urnetwork/sdk at the
// pinned commit, beside this repository, where CI's siblings step puts it. The module's go.mod
// replaces github.com/urnetwork/sdk with the same directory, so nothing in this module builds
// without it either; its absence is a failure, not a skip.
func coreSdkRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(cgoDirectory(t), "..", "..", "..", "sdk")
	if _, err := os.Stat(filepath.Join(root, "cgo", "include", "urnetwork_sdk.def")); err != nil {
		t.Fatalf("the core SDK is not checked out beside this repository at %s (%v): the composition is the core's library with the messaging half laid in, and it has no core to compose", root, err)
	}
	return root
}

// EVERY HAND-WRITTEN EXPORT THAT SHIPS IS NAMED IN THE .def, AND THE .def IS EXACTLY THE COMPOSITION.
//
// Re-homed from the core SDK's cgo/gen/manual_exports_test.go, where the same name held the core's
// .def against every hand-written export in its directory, the messaging surface included. The
// messaging surface lives here now, and the core's case holds only the core's own; this one holds
// the library both halves ship in. It is BYTE FOR BYTE: the committed include/urnetwork_sdk.def
// must be what `go run ./gen` writes from the core SDK at the pinned commit and this directory's
// exports, so a core pin that moved, or an export added or removed here, is red until gen is rerun,
// in both directions -- a name the library would not export is as much a link error at an MSVC
// consumer as a name it lacks.
func TestTheDefNamesEveryHandWrittenExportThatShips(t *testing.T) {
	cgoDir := cgoDirectory(t)
	committed, err := os.ReadFile(filepath.Join(cgoDir, "include", "urnetwork_sdk.def"))
	if err != nil {
		t.Fatal(err)
	}
	want, counts, err := composedDef(coreSdkRoot(t), cgoDir)
	if err != nil {
		t.Fatal(err)
	}
	have := strings.ReplaceAll(string(committed), "\r\n", "\n")
	if have != string(want) {
		haveNames, _ := defEntries(have)
		wantNames, _ := defEntries(string(want))
		missing, extra := []string{}, []string{}
		for _, name := range wantNames {
			if !slices.Contains(haveNames, name) {
				missing = append(missing, name)
			}
		}
		for _, name := range haveNames {
			if !slices.Contains(wantNames, name) {
				extra = append(extra, name)
			}
		}
		t.Fatalf("include/urnetwork_sdk.def is not what `go run ./gen` writes from the core SDK and this directory's exports: it lacks %d name(s) %v and names %d the library does not export %v (and if both lists are empty, the bytes differ in order or header); rerun `go run ./gen` from sdk/cgo",
			len(missing), missing, len(extra), extra)
	}
	// THE CONTROL THAT STOPS AN EMPTY SCAN PASSING: the messaging file declares its exports, and the
	// scan must find every one of them, the most-used verb among them.
	source, err := os.ReadFile(filepath.Join(cgoDir, "exports_message.go"))
	if err != nil {
		t.Fatal(err)
	}
	declared := len(exportDirective.FindAllStringSubmatch(string(source), -1))
	if declared == 0 || counts.messaging != declared {
		t.Fatalf("exports_message.go declares %d //export and the scan found %d messaging exports", declared, counts.messaging)
	}
	messaging, err := messagingExports(cgoDir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(messaging, "urnet_message_group_send") {
		t.Fatalf("CONTROL FAILED: the scan did not find urnet_message_group_send among its %d names; on a CRLF checkout that is the `\\r` in its pattern having been lost", len(messaging))
	}
	t.Logf("include/urnetwork_sdk.def names %d exports: %d from the core SDK's .def, %d messaging", counts.total, counts.core, counts.messaging)
}

// The generator refuses what it should, on fixtures: a core .def that already names a messaging
// export (a core from before the removal), a .def that is not the generator's shape, and it reads
// neither a build-tag-gated file nor a file a compose laid here from the core.
func TestTheComposedDefRefusesACoreThatStillCarriesTheMessagingHalf(t *testing.T) {
	write := func(t *testing.T, path string, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fixture := func(t *testing.T, coreDef string) (string, string) {
		t.Helper()
		root := t.TempDir()
		core := filepath.Join(root, "core")
		dir := filepath.Join(root, "cgo")
		write(t, filepath.Join(core, "cgo", "include", "urnetwork_sdk.def"), coreDef)
		write(t, filepath.Join(dir, "exports_message.go"), "package main\n\n//export urnet_message_a\nfunc urnet_message_a() {}\n")
		write(t, filepath.Join(dir, "loopback.go"), "//go:build urnet_message_loopback\n\npackage main\n\n//export urnet_message_loopback_x\nfunc urnet_message_loopback_x() {}\n")
		write(t, filepath.Join(dir, "exports_manual.go"), "package main\n\n//export urnet_core_manual\nfunc urnet_core_manual() {}\n")
		write(t, filepath.Join(dir, ".composed"), "# composed by a fixture\nexports_manual.go\n")
		return core, dir
	}
	const header = "; a core def\nLIBRARY URnetworkSdk\nEXPORTS\n"

	core, dir := fixture(t, header+"\turnet_core_manual\n\turnet_version\n")
	def, counts, err := composedDef(core, dir)
	if err != nil {
		t.Fatalf("a well-formed composition was refused: %v", err)
	}
	if want := composedDefHeader + "\turnet_core_manual\n\turnet_message_a\n\turnet_version\n"; string(def) != want {
		t.Errorf("the fixture composed to\n%s\nwant\n%s", def, want)
	}
	if counts != (defCounts{core: 2, messaging: 1, total: 3}) {
		t.Errorf("counts %+v, want core 2, messaging 1, total 3: the composed file's exports reached the scan, or the tagged file did", counts)
	}

	core, dir = fixture(t, header+"\turnet_message_a\n\turnet_version\n")
	if _, _, err := composedDef(core, dir); err == nil || !strings.Contains(err.Error(), "urnet_message_a is exported here AND named by the core's .def") {
		t.Errorf("a core .def that still names a messaging export was accepted or refused for another reason: %v", err)
	}
	for name, bad := range map[string]string{
		"no header":                 "\turnet_version\n",
		"a line that is not a name": header + "\turnet_version\nurnet_flush_left\n",
		"another library":           "; c\nLIBRARY Other\nEXPORTS\n\turnet_version\n",
		"no exports":                header,
	} {
		core, dir = fixture(t, bad)
		if _, _, err := composedDef(core, dir); err == nil {
			t.Errorf("a core .def with %s was accepted", name)
		}
	}
}

// Ported from the core SDK's cgo/gen/manual_exports_test.go, for inAnyShippedBuild, which came
// with it: what a file's build constraint says about whether its exports may reach the .def.
func TestAFileNoShippedBuildCompilesContributesNoExportedSymbol(t *testing.T) {
	for _, c := range []struct {
		name   string
		source string
		want   bool
	}{
		{"no constraint at all", "package main\n\n//export urnet_x\nfunc urnet_x() {}\n", true},
		{"a tag nobody passes", "//go:build urnet_message_loopback\n\npackage main\n", false},
		{"a tag nobody passes, negated", "//go:build !urnet_message_loopback\n\npackage main\n", true},
		{"a goos that is not this one", "//go:build js\n\npackage main\n", true},
		{"not a goos", "//go:build !js\n\npackage main\n", true},
		{"unix", "//go:build unix\n\npackage main\n", true},
		{"an and of a real tag and a made up one", "//go:build unix && urnet_message_loopback\n\npackage main\n", false},
		{"an or of a real tag and a made up one", "//go:build unix || urnet_message_loopback\n\npackage main\n", true},
		{"crlf line endings", "//go:build urnet_message_loopback\r\n\r\npackage main\r\n", false},
		{"a comment that only looks like one", "// go:build urnet_message_loopback\n\npackage main\n", true},
		{
			"a constraint below the package clause is not a constraint",
			"package main\n\n//go:build urnet_message_loopback\n",
			true,
		},
		{"an unparseable constraint is not published", "//go:build && ||\n\npackage main\n", false},
	} {
		if got := inAnyShippedBuild(c.source); got != c.want {
			t.Errorf("%s: inAnyShippedBuild answered %v, want %v", c.name, got, c.want)
		}
	}
}

// Re-homed from the core SDK's cgo/gen/manual_exports_test.go (its loopback half): the loopback
// world is the only build-tag-gated file in this directory, it really does carry //export
// directives, and not one of them may reach the .def. The second half -- that the file HAS
// exports -- keeps the first from passing vacuously if the harness is deleted or renamed, and the
// last lines hold it through messagingExports itself, so deleting the build-constraint guard there
// is red here.
func TestTheLoopbackHarnessIsNotInTheShippingLibrarysDef(t *testing.T) {
	cgoDir := cgoDirectory(t)
	b, err := os.ReadFile(filepath.Join(cgoDir, "loopback_test_world.go"))
	if err != nil {
		t.Fatalf("the loopback harness is not where this test expects it: %v", err)
	}
	source := string(b)
	exports := exportDirective.FindAllStringSubmatch(source, -1)
	if len(exports) == 0 {
		t.Fatal("loopback_test_world.go declares no //export, so this case proves nothing")
	}
	for _, m := range exports {
		if !strings.HasPrefix(m[1], "urnet_message_loopback_") {
			t.Errorf("the harness exports %q, which is not under the urnet_message_loopback_ prefix "+
				"the shipping-library check in ctest/run.sh greps for", m[1])
		}
	}
	if inAnyShippedBuild(source) {
		t.Fatalf("the harness's %d exports would reach include/urnetwork_sdk.def, and they are in "+
			"no shipped library", len(exports))
	}
	defBytes, err := os.ReadFile(filepath.Join(cgoDir, "include", "urnetwork_sdk.def"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range exports {
		if strings.Contains(string(defBytes), m[1]) {
			t.Errorf("include/urnetwork_sdk.def names the harness symbol %q", m[1])
		}
	}
	messaging, err := messagingExports(cgoDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(messaging) == 0 {
		t.Fatal("messagingExports found nothing at all, so the two checks below prove nothing")
	}
	for _, m := range exports {
		if slices.Contains(messaging, m[1]) {
			t.Errorf("messagingExports published the harness symbol %q, which no shipped library exports", m[1])
		}
	}
	if !slices.Contains(messaging, "urnet_message_group_send") {
		t.Errorf("messagingExports did not find urnet_message_group_send among its %d names", len(messaging))
	}
}

// THE .def IS ONE PROMISE ABOUT THE SHIPPED LIBRARY AND THE HEADER IS THE OTHER. Re-homed from the
// core SDK's cgo/gen/manual_exports_test.go, with its history:
//
// WRITTEN BECAUSE THE SECOND ONE HAPPENED. urnet_message_group_add_member_and_publish was added
// to exports_message.go and to the .def, and the patch that was meant to declare it in
// urnetwork_message.h built the explanatory comment and never appended the declaration under it.
// Everything passed; the Windows client found it with C3861, identifier not found, the first time
// it called the verb -- which is a compile in another repository and is no kind of gate.
//
// THE MATCH IS ON THE DECLARATION AND NOT ON THE NAME ANYWHERE IN THE FILE: the name appeared SEVEN
// times in that header, all inside comments about it. What is required is the name followed by an
// open parenthesis, on a line that does not open a comment.
func TestTheMessagingHeaderDeclaresEveryMessagingExport(t *testing.T) {
	cgoDir := cgoDirectory(t)
	headerBytes, err := os.ReadFile(filepath.Join(cgoDir, "include", "urnetwork_message.h"))
	if err != nil {
		t.Fatal(err)
	}
	header := strings.ReplaceAll(string(headerBytes), "\r\n", "\n")
	declares := func(name string) bool {
		return regexp.MustCompile(`(?m)^[^/* ].*\b` + regexp.QuoteMeta(name) + `\(`).MatchString(header)
	}
	b, err := os.ReadFile(filepath.Join(cgoDir, "exports_message.go"))
	if err != nil {
		t.Fatal(err)
	}
	found := exportDirective.FindAllStringSubmatch(string(b), -1)
	if len(found) == 0 {
		t.Fatal("exports_message.go declares no //export at all, so this case would pass vacuously")
	}
	missing := []string{}
	for _, m := range found {
		if !declares(m[1]) {
			missing = append(missing, m[1])
		}
	}
	// TWO CONTROLS, AND THE SECOND IS THE ONE THAT MATTERS: the matcher finds a declaration that is
	// there, and does NOT find a name that appears only in prose.
	if !declares("urnet_message_group_add_member") {
		t.Fatal("CONTROL FAILED: the matcher cannot find a declaration that is in the header")
	}
	if declares("urnet_message_this_name_is_in_no_declaration") {
		t.Fatal("CONTROL FAILED: the matcher answers yes for a name the header does not declare")
	}
	const prose = "A JOIN CODE IS NOT A SECRET"
	if strings.Contains(header, prose) && declares(prose) {
		t.Fatal("CONTROL FAILED: the matcher treats comment prose as a declaration")
	}
	if len(missing) != 0 {
		t.Fatalf("include/urnetwork_message.h does not DECLARE %d of the %d messaging exports, so a C consumer calling them does not compile: %v",
			len(missing), len(found), missing)
	}
	t.Logf("include/urnetwork_message.h declares all %d messaging exports", len(found))
}
