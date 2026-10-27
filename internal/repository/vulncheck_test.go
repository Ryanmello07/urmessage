package repository

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// EVERY MODULE FILE HAS A ROW IN scripts/vulncheck.sh, IN EVERY RUN OF test.sh (LRI R72).
//
// The scan holds its rows both ways itself, but only when it runs, and test.sh runs it only when
// asked (MESSAGE_TEST_VULNCHECK=1), because its verdict moves with the vulnerability database. So
// a module added without its row passed test.sh: the NFKD table's generator did, at 325558659836,
// and the scan on alt-2 found it (a6ea6f3e). This is the scan's own row check, read out of the
// script and held here, where it needs no network and runs every time.

// The wirings the scan's case statement handles; anything else falls to its "no row" refusal.
var vulncheckWirings = []string{"plain", "tests", "composed", "not-scanned"}

// The rows of the scan's `declare -A how=(...)` table, module file to wiring. A script with no such
// table, or an empty one, is fatal: a table this reading cannot find is a check of nothing.
func vulncheckRows(t *testing.T, script string) map[string]string {
	t.Helper()
	rows := map[string]string{}
	inside := false
	found := false
	for _, line := range strings.Split(strings.ReplaceAll(script, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "declare -A how=(" {
			inside, found = true, true
			continue
		}
		if !inside {
			continue
		}
		if trimmed == ")" {
			inside = false
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		file, wiring, isRow := strings.Cut(trimmed, "]=")
		if !isRow || !strings.HasPrefix(file, "[") {
			t.Fatalf("the scan's table has a line this reading cannot read: %q", trimmed)
		}
		rows[strings.TrimPrefix(file, "[")] = strings.Trim(wiring, `"`)
	}
	if !found || inside {
		t.Fatal("scripts/vulncheck.sh has no closed `declare -A how=(` table, so this check would hold nothing")
	}
	if len(rows) == 0 {
		t.Fatal("the scan's table has no row, so this check would hold nothing")
	}
	return rows
}

// Every go.mod and every alternate modfile (*.go.mod) under the repository, repository-relative and
// slash separated: the files the scan's own `git ls-files -- 'go.mod' '*/go.mod' '*.go.mod'` walks.
// Directories whose names begin with a dot are skipped, as git's own and the tools' are.
func repositoryModuleFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{}
	err := filepath.WalkDir(root, func(at string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if at != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" && !strings.HasSuffix(entry.Name(), ".go.mod") {
			return nil
		}
		relative, err := filepath.Rel(root, at)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	slices.Sort(files)
	return files
}

// What the scan's rows owe the tree and the tree owes them: a module file with no row, a row that
// names no module file, and a row whose wiring the scan does not handle.
func vulncheckRowProblems(files []string, rows map[string]string) []string {
	problems := []string{}
	for _, file := range files {
		if _, hasRow := rows[file]; !hasRow {
			problems = append(problems, fmt.Sprintf("%s is a module file and scripts/vulncheck.sh has no row saying how it is loaded", file))
		}
	}
	for file, wiring := range rows {
		if !slices.Contains(files, file) {
			problems = append(problems, fmt.Sprintf("scripts/vulncheck.sh has a row for %s, which is no module file here", file))
		}
		if !slices.Contains(vulncheckWirings, wiring) && !strings.HasPrefix(wiring, "tags:") {
			problems = append(problems, fmt.Sprintf("scripts/vulncheck.sh loads %s as %q, which its case statement does not handle", file, wiring))
		}
	}
	slices.Sort(problems)
	return problems
}

func TestEveryModuleFileHasARowInTheVulnerabilityScan(t *testing.T) {
	root := repositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "scripts", "vulncheck.sh"))
	if err != nil {
		t.Fatalf("read scripts/vulncheck.sh: %v", err)
	}
	files := repositoryModuleFiles(t, root)
	if !slices.Contains(files, "go.mod") {
		t.Fatalf("the walk found %v and not the root's go.mod, so it is not walking this repository", files)
	}
	rows := vulncheckRows(t, string(script))
	t.Logf("%d module files: %v", len(files), files)
	t.Logf("%d rows in the scan: %v", len(rows), rows)
	for _, problem := range vulncheckRowProblems(files, rows) {
		t.Error(problem)
	}
}

// The control: the check reports a module file planted with no row, a row left after its file, and
// a wiring the scan does not handle -- and reads a table it is handed exactly, comments and blank
// lines skipped. It is the check above against the tree as it would be.
func TestTheVulnerabilityScanRowCheckReportsAMissingRowAnOrphanAndAWiring(t *testing.T) {
	read := vulncheckRows(t, "set -e\ndeclare -A how=(\n  [go.mod]=\"plain\"\n  # a note\n\n  [sdk/x/go.mod]=\"tags:new\"\n)\n")
	if want := map[string]string{"go.mod": "plain", "sdk/x/go.mod": "tags:new"}; !maps.Equal(read, want) {
		t.Errorf("the reading answers %v from a table of two rows, want %v", read, want)
	}
	root := repositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "scripts", "vulncheck.sh"))
	if err != nil {
		t.Fatalf("read scripts/vulncheck.sh: %v", err)
	}
	files := repositoryModuleFiles(t, root)
	rows := vulncheckRows(t, string(script))
	if problems := vulncheckRowProblems(files, rows); len(problems) != 0 {
		t.Fatalf("the tree has problems of its own, %v, so the planted ones below cannot be told apart", problems)
	}
	planted := append(slices.Clone(files), "messagegroup/testdata/planted/go.mod")
	orphaned := map[string]string{"sdk/gone/go.mod": "plain"}
	for file, wiring := range rows {
		orphaned[file] = wiring
	}
	unhandled := map[string]string{}
	for file, wiring := range rows {
		unhandled[file] = wiring
	}
	unhandled["go.mod"] = "plane"
	for _, one := range []struct {
		what  string
		files []string
		rows  map[string]string
		want  string
	}{
		{"a module file with no row", planted, rows, "messagegroup/testdata/planted/go.mod is a module file and scripts/vulncheck.sh has no row"},
		{"a row with no module file", files, orphaned, "scripts/vulncheck.sh has a row for sdk/gone/go.mod, which is no module file here"},
		{"a wiring the scan does not handle", files, unhandled, `scripts/vulncheck.sh loads go.mod as "plane"`},
	} {
		problems := vulncheckRowProblems(one.files, one.rows)
		if len(problems) != 1 || !strings.HasPrefix(problems[0], one.want) {
			t.Errorf("%s: the check answers %v, want one problem beginning %q", one.what, problems, one.want)
		}
	}
}
