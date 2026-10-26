package urmessage

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// holdRemoval holds one file's removal for real, as an antivirus or a deny does, and answers the
// release (LRI R89 item 4; review D2L-2, G-D2):
//   - on Windows, a handle opened without FILE_SHARE_DELETE, which os.Open is;
//   - elsewhere, for a process that is not root, its directory without write permission;
//   - for root, which permissions do not stop, the file made immutable (chattr +i), and the test is
//     skipped where the filesystem cannot make it so.
//
// The release is registered for cleanup too, so that a failing test leaves its folder removable.
func holdRemoval(t *testing.T, path string) func() {
	t.Helper()
	var once sync.Once
	var release func()
	switch {
	case runtime.GOOS == "windows":
		file, err := os.Open(path)
		if err != nil {
			t.Fatalf("holding %s: %v", filepath.Base(path), err)
		}
		release = func() { file.Close() }
	case os.Geteuid() != 0:
		dir := filepath.Dir(path)
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("holding %s: %v", filepath.Base(path), err)
		}
		release = func() { os.Chmod(dir, info.Mode().Perm()) }
	default:
		if out, err := exec.Command("chattr", "+i", path).CombinedOutput(); err != nil {
			t.Skipf("a root process can hold no file here: chattr +i answered %v (%s)", err, out)
		}
		release = func() { exec.Command("chattr", "-i", path).Run() }
	}
	answer := func() { once.Do(release) }
	t.Cleanup(answer)
	return answer
}
