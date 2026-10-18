package cp3b

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// THE ADVERSARY SIMULATION'S REGISTRY: what each scenario is EXPECTED to observe, written down
// before the scenario runs.
//
// A scenario drives an adversary over the real server and the real client, collects what the
// adversary got (its OBSERVATION, a sorted set of short facts such as "epoch:1"), and hands it to
// [advJudge]. The registry entry for that scenario says what the observation must be:
//
//   - "open": a known gap. The entry's `expect` is the gap's exact shape today and `goal` is what
//     the observation must become. It PASSES, as a known gap, only while the observation equals
//     `expect` exactly. An observation equal to `goal` FAILS with the instruction to flip the
//     entry in the commit that closed the gap; any other observation FAILS as a gap that moved.
//     So a gap cannot close, widen or change shape without an edit to this file.
//   - "closed", "control" and "residual": the observation must equal `expect` exactly. The three
//     differ only in what they say: a closed gap, a control that proves the harness can see, and
//     a breach that is documented and deliberately not closed.
//
// ADVSIM_STRICT=1 fails every open entry. That run is the RED report: it lists each gap that is
// still open with what the adversary got.
const (
	advRegistryFormat = "advsim-known-gaps/1"
	advRegistryPath   = "testdata/advsim/known-gaps.json"
)

type advEntry struct {
	Id       string   `json:"id"`
	State    string   `json:"state"`
	Expect   []string `json:"expect"`
	Goal     []string `json:"goal"`
	ClosedBy string   `json:"closed_by"`
	Reads    string   `json:"reads"`
}

type advRegistryFile struct {
	Format  string     `json:"format"`
	Entries []advEntry `json:"entries"`
}

func advLoadRegistry(t *testing.T) map[string]advEntry {
	t.Helper()
	body, err := os.ReadFile(filepath.FromSlash(advRegistryPath))
	if err != nil {
		t.Fatalf("FAIL(HARNESS): the registry %s could not be read: %v", advRegistryPath, err)
	}
	file := advRegistryFile{}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		t.Fatalf("FAIL(HARNESS): the registry %s does not decode: %v", advRegistryPath, err)
	}
	if file.Format != advRegistryFormat {
		t.Fatalf("FAIL(HARNESS): the registry names format %q, want %q", file.Format, advRegistryFormat)
	}
	entries := map[string]advEntry{}
	for _, entry := range file.Entries {
		if _, twice := entries[entry.Id]; twice {
			t.Fatalf("FAIL(HARNESS): the registry names %q twice", entry.Id)
		}
		entries[entry.Id] = entry
	}
	if len(entries) == 0 {
		t.Fatalf("FAIL(HARNESS): the registry holds no entry, so every scenario would be judged against nothing")
	}
	return entries
}

// advSet is an observation in its one canonical form: sorted, without repeats, never nil.
func advSet(facts []string) []string {
	set := append([]string{}, facts...)
	slices.Sort(set)
	return slices.Compact(set)
}

// advVerdict is the whole of the rule, as a function of its three inputs and nothing else, so that
// [TestAdvSimVerdictRules] can drive every arm of it without a scenario.
func advVerdict(entry advEntry, observed []string, strict bool) (bool, string) {
	observed = advSet(observed)
	expect := advSet(entry.Expect)
	goal := advSet(entry.Goal)
	switch entry.State {
	case "closed", "control", "residual":
		if slices.Equal(observed, expect) {
			return true, strings.ToUpper(entry.State)
		}
		return false, fmt.Sprintf("FAIL (%s): observed %v, and this entry holds exactly %v", entry.State, observed, expect)
	case "open":
		switch {
		case slices.Equal(observed, expect) && strict:
			return false, fmt.Sprintf("RED: the gap is open, closed by %s: the adversary observed %v, and the goal is %v", entry.ClosedBy, observed, goal)
		case slices.Equal(observed, expect):
			return true, fmt.Sprintf("KNOWN GAP (closed by %s)", entry.ClosedBy)
		case slices.Equal(observed, goal):
			return false, fmt.Sprintf("FAIL: the gap has CLOSED: observed %v is the goal. Set this entry's state to \"closed\" and its expect to %v in the commit that closed it", observed, goal)
		default:
			return false, fmt.Sprintf("FAIL: the gap MOVED: observed %v, the registry models %v and the goal is %v. This is a regression, or a registry edit that needs a ledger entry", observed, expect, goal)
		}
	}
	return false, fmt.Sprintf("FAIL(HARNESS): state %q is not one of open, closed, control, residual", entry.State)
}

// advJudge holds one scenario's observation against its registry entry and prints the row.
func advJudge(t *testing.T, id string, observed []string) {
	t.Helper()
	entry, registered := advLoadRegistry(t)[id]
	if !registered {
		t.Fatalf("FAIL(HARNESS): scenario %q has no registry entry; every scenario's expected observation is written down first", id)
	}
	strict := os.Getenv("ADVSIM_STRICT") == "1"
	passed, verdict := advVerdict(entry, observed, strict)
	line := fmt.Sprintf("ADVSIM %-30s state=%-8s expect=%v observed=%v :: %s", id, entry.State, advSet(entry.Expect), advSet(observed), verdict)
	fmt.Println(line)
	if !passed {
		t.Fatalf("%s\n    the scenario: %s", line, entry.Reads)
	}
}

// advHarness fails a scenario whose own preconditions did not hold. It is a different verdict from
// a gap: a harness that could not set its scene up has measured nothing, in either direction.
func advHarness(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf("FAIL(HARNESS): "+format, args...)
}

func TestAdvSimVerdictRules(t *testing.T) {
	open := advEntry{Id: "x", State: "open", Expect: []string{"epoch:1"}, Goal: []string{}, ClosedBy: "T1"}
	closed := advEntry{Id: "y", State: "closed", Expect: []string{}}
	control := advEntry{Id: "z", State: "control", Expect: []string{"epoch:1"}}
	for _, one := range []struct {
		name     string
		entry    advEntry
		observed []string
		strict   bool
		pass     bool
		says     string
	}{
		{"an open gap observed exactly as modelled passes as a known gap", open, []string{"epoch:1"}, false, true, "KNOWN GAP"},
		{"the same gap is RED under ADVSIM_STRICT", open, []string{"epoch:1"}, true, false, "RED"},
		{"an open gap that reached its goal fails until the registry is flipped", open, nil, false, false, "CLOSED"},
		{"an open gap that reached its goal fails under strict too, and says the same", open, nil, true, false, "CLOSED"},
		{"an open gap wider than its model fails", open, []string{"epoch:1", "epoch:2"}, false, false, "MOVED"},
		{"an open gap of another shape fails", open, []string{"epoch:2"}, false, false, "MOVED"},
		{"a closed entry passes on its exact set", closed, nil, false, true, "CLOSED"},
		{"a closed entry fails on anything else", closed, []string{"epoch:1"}, false, false, "FAIL"},
		{"a control passes on its exact set", control, []string{"epoch:1"}, true, true, "CONTROL"},
		{"a control that saw nothing fails: the harness went blind", control, nil, false, false, "FAIL"},
		{"an unknown state fails", advEntry{State: "advisory"}, nil, false, false, "FAIL(HARNESS)"},
	} {
		passed, verdict := advVerdict(one.entry, one.observed, one.strict)
		if passed != one.pass || !strings.Contains(verdict, one.says) {
			t.Errorf("%s: passed=%v verdict=%q, want passed=%v and a verdict naming %q", one.name, passed, verdict, one.pass, one.says)
		}
	}
}

// Every entry is well formed, and every entry is named by exactly one scenario in this package.
//
// The second half is a census over the SOURCE of the advsim files: each registry id occurs exactly
// once as a quoted literal. An entry no scenario names is a property nothing measures, which reads
// as a closed gap; an id named twice is two scenarios whose verdicts one entry cannot both hold.
// The other direction, a scenario naming an id the registry lacks, is [advJudge]'s own refusal.
func TestAdvSimEveryRegistryEntryIsNamedByExactlyOneScenario(t *testing.T) {
	entries := advLoadRegistry(t)
	sources, err := filepath.Glob("advsim_*_test.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no advsim source file was found (%v), so the census below read nothing", err)
	}
	text := ""
	for _, source := range sources {
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		text += string(body)
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		entry := entries[id]
		switch entry.State {
		case "open":
			if entry.ClosedBy == "" || entry.ClosedBy == "none" {
				t.Errorf("%s is open and names no track that closes it", id)
			}
			if slices.Equal(advSet(entry.Expect), advSet(entry.Goal)) {
				t.Errorf("%s is open and its model equals its goal, so it could never be told from a closed gap", id)
			}
		case "closed", "control", "residual":
		default:
			t.Errorf("%s has state %q", id, entry.State)
		}
		if entry.Reads == "" {
			t.Errorf("%s does not say what its adversary does", id)
		}
		if named := strings.Count(text, `"`+id+`"`); named != 1 {
			t.Errorf("%s is named %d times as a literal in %v, want exactly once", id, named, sources)
		}
	}
	t.Logf("%d registry entries, each named by exactly one scenario in %v", len(ids), sources)
}

// EVERY ENTRY IS JUDGED BY A TestAdvSim FUNCTION, so the RED report judges every one (LRI R84 item 13;
// review G-7). The report is the strict run narrowed to `-run TestAdvSim`, so a scenario judged from
// any other test runs in the normal run and is skipped by the report, and a closed entry's regression
// is then invisible where Task 17 reads. Every [advJudge] call in the advsim sources sits in a
// top-level function whose name begins TestAdvSim, and names its entry by a literal; with the census
// above, each entry is judged by exactly one such function. What no call reaches is printed.
//
// THE CONTROL: a judging call in a helper, and one in a test of another name, are each refused.
func TestAdvSimEveryEntryIsJudgedByATestAdvSimFunction(t *testing.T) {
	sources, err := filepath.Glob("advsim_*_test.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no advsim source file was found (%v), so the census below read nothing", err)
	}
	judged := map[string]string{}
	for _, source := range sources {
		body, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		calls, problems := advJudgingCallsOf(t, source, body)
		for _, problem := range problems {
			t.Error(problem)
		}
		for id, function := range calls {
			judged[id] = function
		}
	}
	entries := advLoadRegistry(t)
	unjudged := []string{}
	for id := range entries {
		if _, found := judged[id]; !found {
			unjudged = append(unjudged, id)
		}
	}
	slices.Sort(unjudged)
	if len(unjudged) != 0 {
		t.Errorf("no TestAdvSim function judges %v, so the RED report has no row for them", unjudged)
	}
	t.Logf("%d judging call(s), each in a TestAdvSim function; %d registry entries; not judged: %v",
		len(judged), len(entries), unjudged)

	// THE CONTROL
	_, problems := advJudgingCallsOf(t, "advsim_control_test.go", []byte(`package cp3b

func advHelperThatJudges(t *testing.T) {
	advJudge(t, "control-in-a-helper", nil)
}

func TestSomethingElse(t *testing.T) {
	advJudge(t, "control-in-another-test", nil)
}
`))
	if len(problems) != 2 {
		t.Errorf("CONTROL FAILED: a judging call in a helper and one in another test answered %d problem(s), want 2: %v",
			len(problems), problems)
	}
}

// advJudgingCallsOf reads one advsim source and answers each judged entry with the function that
// judges it, and every call outside a TestAdvSim function, or without a literal id, as a problem.
func advJudgingCallsOf(t *testing.T, name string, body []byte) (map[string]string, []string) {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, name, body, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	calls := map[string]string{}
	problems := []string{}
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil || function.Name.Name == "advJudge" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok || callee.Name != "advJudge" {
				return true
			}
			at := fileSet.Position(call.Pos())
			if !strings.HasPrefix(function.Name.Name, "TestAdvSim") {
				problems = append(problems, fmt.Sprintf("%s: advJudge is called in %s, which the RED report's -run TestAdvSim never runs",
					at, function.Name.Name))
				return true
			}
			var literal *ast.BasicLit
			if 2 <= len(call.Args) {
				literal, _ = call.Args[1].(*ast.BasicLit)
			}
			if literal == nil || literal.Kind != token.STRING {
				problems = append(problems, fmt.Sprintf("%s: advJudge in %s names its entry by no literal", at, function.Name.Name))
				return true
			}
			id, err := strconv.Unquote(literal.Value)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", at, err))
				return true
			}
			calls[id] = function.Name.Name
			return true
		})
	}
	return calls, problems
}
