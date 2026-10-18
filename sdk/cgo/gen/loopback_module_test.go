package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// THE LOOPBACK HARNESS HAS NO IDENTITY DOOR OF ITS OWN (LRI R76 item 8; identity phase 1's Task 14).
// Until the shipping library exported the identity, the harness carried
// urnet_message_loopback_device_identify, so that the C consumer's devices could have one. The
// identity exports ship now, and the C consumer makes its devices' identities through them, as a C
// caller does: the door is gone from the harness and from the C consumer, and the C consumer calls
// urnet_message_device_create_identity and urnet_message_device_confirm_words.
//
// THE CONTROL: the reader finds the name where it is, in this file.
func TestTheLoopbackHarnessHasNoIdentityDoorOfItsOwn(t *testing.T) {
	cgoDirectory := filepath.Dir(testingGenDir(t))
	const door = "urnet_message_loopback_" + "device_identify"
	self, err := os.ReadFile(filepath.Join(cgoDirectory, "gen", "loopback_module_test.go"))
	if err != nil || !strings.Contains(string(self), "urnet_message_loopback_device_identify") {
		t.Fatalf("CONTROL FAILED: the reader does not find the door's name in this file (%v)", err)
	}
	read := 0
	for _, pattern := range []string{"ctest/*.c", "ctest/*.sh", "ctest/*.json", "ctest/testdata/*.go", "*.go", "include/*.h", "include/*.def"} {
		matches, err := filepath.Glob(filepath.Join(cgoDirectory, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range matches {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			read += 1
			if strings.Contains(string(contents), door) {
				t.Errorf("%s names %s, the loopback harness's identity door, which the identity exports replace", path, door)
			}
		}
	}
	if read < 5 {
		t.Fatalf("the reader read %d files, so it read almost nothing", read)
	}
	consumer, err := os.ReadFile(filepath.Join(cgoDirectory, "ctest", "message_abi_test.c"))
	if err != nil {
		t.Fatal(err)
	}
	for _, export := range []string{"urnet_message_device_create_identity(", "urnet_message_device_confirm_words("} {
		if !strings.Contains(string(consumer), export) {
			t.Errorf("the C consumer does not call %s: its devices' identities are not made through the shipping exports", export)
		}
	}
}

// Release preparation runs tidy and get with the shipping module. Custom build
// tags are enabled by tidy, so the fixture's testdata boundary must exclude its
// server dependencies even on a host with no message-server checkout or network.
// Use the real fixture and overlay, with a dependency-free shipping package, to
// test Go's discovery without changing this checkout's module files.
func TestLoopbackModuleBoundaryAndOverlay(t *testing.T) {
	cgoDirectory := filepath.Dir(testingGenDir(t))
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "-tags=urnet_message_loopback", "./...")
	command.Dir = cgoDirectory
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("shipping package discovery with the loopback tag: %v\n%s", err, output)
	}
	if strings.Contains(string(output), "github.com/urnetwork/message-server") {
		t.Fatalf("shipping module includes the loopback server without the overlay:\n%s", output)
	}

	root := filepath.Join(t.TempDir(), "cgo with spaces")
	if err := os.MkdirAll(filepath.Join(root, "ctest", "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"go.mod":  []byte("module example.invalid/loopback-boundary\n\ngo 1.26.5\n"),
		"main.go": []byte("package main\n\nfunc main() {}\n"),
	}
	for _, name := range []string{
		"ctest/loopback-overlay.json",
		"ctest/testdata/loopback_test_world.go",
	} {
		contents, err := os.ReadFile(filepath.Join(cgoDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = contents
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(root, name), contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGo := func(t *testing.T, args ...string) []byte {
		t.Helper()
		command := exec.Command("go", args...)
		command.Dir = root
		command.Env = append(os.Environ(),
			"GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=1",
		)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, output)
		}
		return output
	}
	runGo(t, "mod", "tidy")
	runGo(t, "get", "-t", "./...")

	for _, tc := range []struct {
		name string
		args []string
		want bool
	}{
		{"tag alone", []string{"-tags=urnet_message_loopback"}, false},
		{"overlay alone", []string{"-overlay=ctest/loopback-overlay.json"}, false},
		{"test build", []string{"-overlay=ctest/loopback-overlay.json", "-tags=urnet_message_loopback"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// -e lets us inspect the test package without resolving its intentionally
			// unavailable dependencies. The real library build checks those separately.
			args := append([]string{"list", "-e", "-json"}, tc.args...)
			output := runGo(t, append(args, ".")...)
			var pkg struct {
				CgoFiles []string
				Imports  []string
			}
			if err := json.Unmarshal(output, &pkg); err != nil {
				t.Fatalf("decode package metadata: %v\n%s", err, output)
			}
			if got := slices.Contains(pkg.CgoFiles, "loopback_test_world.go"); got != tc.want {
				t.Fatalf("loopback fixture present = %v, want %v: %s", got, tc.want, output)
			}
			if got := slices.Contains(pkg.Imports, "github.com/urnetwork/message-server/api"); got != tc.want {
				t.Fatalf("message-server import present = %v, want %v: %s", got, tc.want, output)
			}
		})
	}
}
