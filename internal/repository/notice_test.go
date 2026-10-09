// Package repository holds checks on the repository as a whole that belong to no package. It
// has no source of its own and nothing imports it.
package repository

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The repository's own files under testdata/vectors/ directories: bookkeeping written here,
// not vendored, so NOTICE owes them no row. Asserted both ways like everything else in this
// file: each must exist, and each must match no third-party row.
var firstPartyVectorFiles = map[string]string{
	"mls/testdata/vectors/.gitattributes":              "the checkout rule (* -text) that keeps git's text conversion off the vendored bytes",
	"mls/testdata/vectors/VECTORS.sha256":              "this repository's digest list of the sixteen vendored files",
	"mls/testdata/vectors/rfc/.gitattributes":          "the same checkout rule for the RFC 9180 corpus",
	"messagegroup/testdata/vectors/rfc/.gitattributes": "the same checkout rule for the X-Wing corpus",
}

// The repository root, found from this package's directory and checked by its module line.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read the repository's go.mod: %v", err)
	}
	if !strings.Contains(string(goMod), "module github.com/urnetwork/message\n") && !strings.Contains(string(goMod), "module github.com/urnetwork/message\r\n") {
		t.Fatalf("%s/go.mod is not the message repository's root module", root)
	}
	return root
}

// The "Path:" rows of NOTICE's third-party section.
func noticePathRows(notice string) []string {
	rows := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(notice, "\r\n", "\n"), "\n") {
		if pattern, found := strings.CutPrefix(line, "Path: "); found {
			rows = append(rows, strings.TrimSpace(pattern))
		}
	}
	return rows
}

// Every file under a testdata/vectors/ directory, repository-relative and slash separated.
func vendoredVectorFiles(t *testing.T, root string) []string {
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
		relative, err := filepath.Rel(root, at)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasPrefix(relative, "testdata/vectors/") || strings.Contains(relative, "/testdata/vectors/") {
			files = append(files, relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	slices.Sort(files)
	return files
}

// What NOTICE owes the tree and the tree owes NOTICE: an uncovered vendored file, a row that
// covers nothing, a malformed row, a first-party file that is missing or that a third-party
// row claims.
func noticeProblems(files []string, rows []string, firstParty map[string]string) []string {
	problems := []string{}
	matched := map[string]bool{}
	for _, row := range rows {
		if _, err := path.Match(row, ""); err != nil {
			problems = append(problems, fmt.Sprintf("NOTICE row %q is not a valid pattern: %v", row, err))
		}
	}
	for _, file := range files {
		covered := false
		for _, row := range rows {
			if hit, _ := path.Match(row, file); hit {
				covered = true
				matched[row] = true
				if firstParty[file] != "" {
					problems = append(problems, fmt.Sprintf("%s is listed as the repository's own and NOTICE row %q claims it as third-party", file, row))
				}
			}
		}
		if !covered && firstParty[file] == "" {
			problems = append(problems, fmt.Sprintf("%s is vendored under testdata/vectors/ and no NOTICE row covers it", file))
		}
	}
	for _, row := range rows {
		if !matched[row] {
			problems = append(problems, fmt.Sprintf("NOTICE row %q matches no file: a notice for something this repository does not hold", row))
		}
	}
	for file := range firstParty {
		if !slices.Contains(files, file) {
			problems = append(problems, fmt.Sprintf("%s is listed as the repository's own vector bookkeeping and does not exist", file))
		}
	}
	slices.Sort(problems)
	return problems
}

// Every vendored corpus carries its notice. The third-party vector files are not this
// repository's to license, and the one set whose upstream publishes no license at all says
// so in NOTICE rather than by silence; a vector file added without a row, or a row left
// after its files are gone, fails here.
func TestEveryVendoredCorpusHasANoticeRow(t *testing.T) {
	root := repositoryRoot(t)
	notice, err := os.ReadFile(filepath.Join(root, "NOTICE"))
	if err != nil {
		t.Fatalf("read NOTICE: %v", err)
	}
	rows := noticePathRows(string(notice))
	files := vendoredVectorFiles(t, root)
	if len(rows) == 0 || len(files) == 0 {
		t.Fatalf("NOTICE has %d rows and the tree %d vendored vector files; a check over nothing proves nothing", len(rows), len(files))
	}
	covered := 0
	for _, file := range files {
		if firstPartyVectorFiles[file] == "" {
			covered++
		}
	}
	t.Logf("%d files under testdata/vectors/: %d third-party, held to %d NOTICE rows; %d the repository's own: %v",
		len(files), covered, len(rows), len(files)-covered, firstPartyVectorFiles)
	for _, problem := range noticeProblems(files, rows, firstPartyVectorFiles) {
		t.Error(problem)
	}
}

// The control: an uncovered file, an orphan row, a malformed row, a first-party file a row
// claims, and a first-party entry with no file, each reported; a covered file is not.
func TestTheNoticeGateReportsAnUncoveredFileAndAnOrphanRow(t *testing.T) {
	files := []string{
		"a/testdata/vectors/covered.json",
		"a/testdata/vectors/VECTORS.sha256",
		"b/testdata/vectors/uncovered.json",
	}
	rows := []string{"a/testdata/vectors/*", "c/testdata/vectors/*.json", "[bad"}
	firstParty := map[string]string{
		"a/testdata/vectors/VECTORS.sha256": "the digest list",
		"a/testdata/vectors/gone.txt":       "a file that is not there",
	}
	problems := noticeProblems(files, rows, firstParty)
	wants := []string{
		`b/testdata/vectors/uncovered.json is vendored under testdata/vectors/ and no NOTICE row covers it`,
		`NOTICE row "c/testdata/vectors/*.json" matches no file`,
		`NOTICE row "[bad" is not a valid pattern`,
		`NOTICE row "[bad" matches no file`,
		`a/testdata/vectors/VECTORS.sha256 is listed as the repository's own and NOTICE row "a/testdata/vectors/*" claims it as third-party`,
		`a/testdata/vectors/gone.txt is listed as the repository's own vector bookkeeping and does not exist`,
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
	for _, problem := range problems {
		if strings.HasPrefix(problem, "a/testdata/vectors/covered.json") {
			t.Errorf("a covered file was reported: %s", problem)
		}
	}
	if len(problems) != len(wants) {
		t.Errorf("%d problems planted, %d reported: %q", len(wants), len(problems), problems)
	}
}
