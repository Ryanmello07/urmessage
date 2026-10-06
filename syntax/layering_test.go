// The structural gates on this package. The first is the dependency gate: it must
// depend on nothing outside the standard library. Spec A section 2.3 makes
// connect/mls/syntax stdlib only so the codec can be audited and fuzzed with no
// transport, no crypto and no third party code in the graph, and so importing it
// from any wave creates no cycle.
//
// The second is the continuous integration gate, asserted from here for the same
// reason: slice A1 is done when family 16 passes and the fuzz properties are clean
// for 60 seconds on each target, and a done-when that only a reviewer checks is a
// note rather than a gate. These checks read the workflow through a small reader of
// the YAML subset workflow files are written in, standard library only like the
// package itself, so they judge its structure rather than its spelling: "- maintenance"
// is not the branch main, a step that is commented out is not a step, and a run step
// that a condition switches off runs nothing. The reader refuses what it does not
// understand (anchors, aliases, tags, flow mappings), so a file it cannot read fails
// rather than passing. Running the workflow's own commands is what establishes the rest.
package syntax

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const selfImportPath = "github.com/urnetwork/message/syntax"

// The per commit gate lives here, relative to the package directory the tests run in.
const workflowPath = "../.github/workflows/syntax.yml"

// Fails if go list -deps reports a dependency whose first path element is not stdlib.
func TestSyntaxImportsStdlibOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if dep == "" || dep == selfImportPath {
			continue
		}
		// every standard library import path has a dot free first element
		first, _, _ := strings.Cut(dep, "/")
		if strings.Contains(first, ".") {
			t.Errorf("non stdlib dependency %s; this package is stdlib only per spec A section 2.3", dep)
		}
	}
}

// Reads the workflow, failing the calling test rather than returning an error,
// because every check below is meaningless if the file is not there. A CRLF
// checkout (core.autocrlf=true on the Windows runner) is folded to LF first, so
// the controls below find their anchors on every checkout.
func readSyntaxWorkflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("reading the syntax workflow: %v", err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// Scans the package's own test sources for fuzz target declarations, so the list
// the workflow is checked against is derived rather than restated. A hand written
// list would still pass on the day a fourth target is added and never run in the
// gate, which is the failure this file exists to catch.
func declaredFuzzTargets(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}
	targets := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "func Fuzz") {
				continue
			}
			name, _, found := strings.Cut(strings.TrimPrefix(line, "func "), "(")
			if found {
				targets = append(targets, name)
			}
		}
	}
	// a scan that silently matched nothing would make the caller's loop vacuous
	if len(targets) == 0 {
		t.Fatal("found no fuzz targets in the package sources; the scan is broken, not the workflow")
	}
	return targets
}

// The 60 seconds on each of the three targets that slice A1's done-when asks for is
// only a gate if the workflow exists, pins the toolchain this plan is built against
// and runs every target the package actually declares, in a step that is live.
func TestSyntaxWorkflowRunsEveryFuzzTarget(t *testing.T) {
	workflow, err := parseSyntaxWorkflow(readSyntaxWorkflow(t))
	if err != nil {
		t.Fatalf("the syntax workflow does not parse as the YAML subset this check reads: %v", err)
	}
	for _, problem := range syntaxWorkflowRunProblems(workflow, declaredFuzzTargets(t)) {
		t.Error(problem)
	}
}

// A workflow can name every command and still gate nothing, in two ways this file
// can see. It can trigger on a branch the work is not on, so it never runs at all.
// Or a step can carry continue-on-error, which reports a failure and passes the job
// anyway — this repo's own history has that on the flaky extender step in
// connect's .github/workflows/test.yml, so it is a convention a later edit may well
// copy here, where the whole point is to block the commit. The spelling is refused
// anywhere in the file, comments included, as before; the triggers are read as
// structure.
func TestSyntaxWorkflowGatesRatherThanReports(t *testing.T) {
	text := readSyntaxWorkflow(t)
	workflow, err := parseSyntaxWorkflow(text)
	if err != nil {
		t.Fatalf("the syntax workflow does not parse as the YAML subset this check reads: %v", err)
	}
	for _, problem := range syntaxWorkflowTriggerProblems(workflow) {
		t.Error(problem)
	}
	if strings.Contains(text, "continue-on-error") {
		t.Error("the syntax workflow has a continue-on-error step; a step that cannot fail the job gates nothing")
	}
}

// Each control is one edit a later change could plausibly make, applied to the real
// workflow; each must be reported, and for its own reason. The first three are the
// edits the substring checks these replace could not see: "- maintenance" contains
// "- main", a commented-out step still spells its command, and branches-ignore spells
// the branch it excludes.
func TestSyntaxWorkflowCheckFiresOnEachControl(t *testing.T) {
	text := readSyntaxWorkflow(t)
	targets := declaredFuzzTargets(t)
	if problems := syntaxWorkflowProblems(text, targets); len(problems) != 0 {
		t.Fatalf("the controls start from a workflow the check already rejects: %v", problems)
	}
	controls := []struct {
		name, old, new, want string
	}{
		{"a branch whose name only starts with main",
			"  pull_request:\n    branches:\n      - main\n",
			"  pull_request:\n    branches:\n      - maintenance\n",
			"on.pull_request.branches does not list main"},
		{"branches-ignore in place of branches",
			"  push:\n    branches:\n      - main\n",
			"  push:\n    branches-ignore: [main]\n",
			"on.push has branches-ignore"},
		{"a fuzz step commented out",
			"      - name: Fuzz the varint\n        run: go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s\n",
			"      # - name: Fuzz the varint\n      #   run: go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s\n",
			"no live step runs go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s"},
		{"a fuzz step dropped",
			"      - name: Fuzz the length prefixed forms\n        run: go test ./syntax -run=NONE -fuzz=FuzzOpaque -fuzztime=60s\n\n",
			"",
			"no live step runs go test ./syntax -run=NONE -fuzz=FuzzOpaque -fuzztime=60s"},
		{"a fuzz step switched off by a condition",
			"      - name: Fuzz the nested structure\n        run: go test",
			"      - name: Fuzz the nested structure\n        if: false\n        run: go test",
			"no live step runs go test ./syntax -run=NONE -fuzz=FuzzSyntaxStruct -fuzztime=60s"},
		{"a fuzz command commented out inside its run block",
			"        run: go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s\n",
			"        run: |\n          # go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s\n          true\n",
			"no live step runs go test ./syntax -run=NONE -fuzz=FuzzVarint -fuzztime=60s"},
		{"the toolchain unpinned",
			"          go-version: '1.26.5'\n",
			"          go-version: stable\n",
			"go-version '1.26.5'"},
		{"the race leg dropped",
			"        run: go test ./syntax/... -count=1 -race -timeout 10m\n",
			"        run: go test ./syntax/... -count=1 -timeout 10m\n",
			"go test ./syntax/... -count=1 -race"},
		{"a path filter on pushes",
			"  push:\n    branches:\n      - main\n",
			"  push:\n    branches:\n      - main\n    paths:\n      - 'syntax/**'\n",
			"on.push filters by path"},
		{"continue-on-error on a step",
			"      - name: Vet\n",
			"      - name: Vet\n        continue-on-error: true\n",
			"continue-on-error"},
		{"an alias the reader does not understand",
			"permissions:\n  contents: read\n",
			"permissions:\n  contents: *read\n",
			"does not parse"},
		{"an anchor the reader does not understand",
			"permissions:\n  contents: read\n",
			"permissions:\n  contents: &read read\n",
			"does not parse"},
	}
	for _, control := range controls {
		if n := strings.Count(text, control.old); n != 1 {
			t.Fatalf("control %q: its anchor occurs %d times in the workflow, want exactly once", control.name, n)
		}
		mutated := strings.Replace(text, control.old, control.new, 1)
		problems := syntaxWorkflowProblems(mutated, targets)
		reported := false
		for _, problem := range problems {
			if strings.Contains(problem, control.want) {
				reported = true
			}
		}
		if !reported {
			t.Errorf("control %q was not reported for its own reason (want %q), got %v", control.name, control.want, problems)
		}
	}
}

// Every problem the three gates above report, for one workflow text.
func syntaxWorkflowProblems(text string, targets []string) []string {
	workflow, err := parseSyntaxWorkflow(text)
	if err != nil {
		return []string{"the syntax workflow does not parse as the YAML subset this check reads: " + err.Error()}
	}
	problems := syntaxWorkflowTriggerProblems(workflow)
	problems = append(problems, syntaxWorkflowRunProblems(workflow, targets)...)
	if strings.Contains(text, "continue-on-error") {
		problems = append(problems, "the syntax workflow has a continue-on-error step; a step that cannot fail the job gates nothing")
	}
	return problems
}

// The workflow runs on every push to main and every pull request into main, with no
// branch or path exclusion that lets a change merge without it.
func syntaxWorkflowTriggerProblems(workflow *workflowNode) []string {
	problems := []string{}
	on := workflow.get("on")
	for _, event := range []string{"push", "pull_request"} {
		trigger := on.get(event)
		if trigger == nil || trigger.mapping == nil {
			problems = append(problems, fmt.Sprintf("on.%s is not a mapping with a branch list, so the workflow does not run on that event for main", event))
			continue
		}
		if trigger.get("branches-ignore") != nil {
			problems = append(problems, fmt.Sprintf("on.%s has branches-ignore, which this gate refuses: the branches it gates are the ones it names", event))
		}
		if trigger.get("paths") != nil || trigger.get("paths-ignore") != nil {
			problems = append(problems, fmt.Sprintf("on.%s filters by path, so a change outside the filter merges without this gate", event))
		}
		if !trigger.get("branches").listsScalar("main") {
			problems = append(problems, fmt.Sprintf("on.%s.branches does not list main, so the workflow does not run on the branch this work merges into", event))
		}
	}
	return problems
}

// The toolchain is pinned, and the vet, the race suite and one fuzz leg per declared
// target each run in a live step: a run step of some job that no condition switches
// off, on a line that is not a shell comment.
func syntaxWorkflowRunProblems(workflow *workflowNode, targets []string) []string {
	problems := []string{}
	steps := []*workflowNode{}
	jobs := workflow.get("jobs")
	if jobs == nil || jobs.mapping == nil {
		return []string{"the workflow has no jobs mapping"}
	}
	for _, name := range jobs.keys {
		steps = append(steps, jobs.get(name).get("steps").items()...)
	}
	pinned := false
	for _, step := range steps {
		if uses := step.get("uses").text(); strings.HasPrefix(uses, "actions/setup-go@") && step.get("with").get("go-version").text() == "1.26.5" {
			pinned = true
		}
	}
	if !pinned {
		problems = append(problems, "no actions/setup-go step pins go-version '1.26.5'; this package asserts canonical encodings byte for byte under that toolchain")
	}
	live := func(command string) bool {
		for _, step := range steps {
			if step.get("if") != nil || step.get("run") == nil {
				continue
			}
			for _, line := range strings.Split(step.get("run").text(), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "#") && strings.Contains(line, command) {
					return true
				}
			}
		}
		return false
	}
	commands := []string{"go vet ./syntax", "go test ./syntax/... -count=1 -race"}
	for _, target := range targets {
		commands = append(commands, "go test ./syntax -run=NONE -fuzz="+target+" -fuzztime=60s")
	}
	for _, command := range commands {
		if !live(command) {
			problems = append(problems, fmt.Sprintf("no live step runs %s", command))
		}
	}
	return problems
}

// workflowNode is one node of the YAML subset workflow files are written in: a block
// mapping (keys in order), a block or flow sequence, or a scalar.
type workflowNode struct {
	scalar   *string
	keys     []string
	mapping  map[string]*workflowNode
	sequence []*workflowNode
}

func (n *workflowNode) get(key string) *workflowNode {
	if n == nil || n.mapping == nil {
		return nil
	}
	return n.mapping[key]
}

func (n *workflowNode) items() []*workflowNode {
	if n == nil {
		return nil
	}
	return n.sequence
}

func (n *workflowNode) text() string {
	if n == nil || n.scalar == nil {
		return ""
	}
	return *n.scalar
}

func (n *workflowNode) listsScalar(value string) bool {
	for _, item := range n.items() {
		if item.scalar != nil && *item.scalar == value {
			return true
		}
	}
	return false
}

type workflowParser struct {
	lines []string
	at    int
}

func parseSyntaxWorkflow(text string) (*workflowNode, error) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "\t") {
			return nil, fmt.Errorf("line %d indents with a tab", i+1)
		}
		if strings.TrimSpace(line) == "---" || strings.TrimSpace(line) == "..." {
			return nil, fmt.Errorf("line %d: a document marker; one document only", i+1)
		}
	}
	p := &workflowParser{lines: lines}
	p.skip()
	if p.at >= len(p.lines) {
		return nil, fmt.Errorf("the workflow is empty")
	}
	root, err := p.mapping(workflowIndent(p.lines[p.at]))
	if err != nil {
		return nil, err
	}
	if p.skip(); p.at < len(p.lines) {
		return nil, fmt.Errorf("line %d is outside the document's top-level mapping", p.at+1)
	}
	return root, nil
}

func workflowIndent(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// the content of a line after its indentation, with a trailing comment removed: a #
// at the start or after a blank, outside quotes
func workflowContent(line string) string {
	content := line[workflowIndent(line):]
	quote := byte(0)
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#' && (i == 0 || content[i-1] == ' ' || content[i-1] == '\t'):
			return strings.TrimRight(content[:i], " \t")
		}
	}
	return strings.TrimRight(content, " \t")
}

// skips blank lines and lines holding only a comment; never called inside a block scalar
func (p *workflowParser) skip() {
	for p.at < len(p.lines) && workflowContent(p.lines[p.at]) == "" {
		p.at++
	}
}

func workflowIsItem(content string) bool {
	return content == "-" || strings.HasPrefix(content, "- ")
}

// key and value of a mapping entry, split at the first ": " (or a final ":") outside
// quotes and brackets
func workflowEntry(content string) (string, string, bool) {
	quote, depth := byte(0), 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			depth--
		case c == ':' && depth == 0 && (i+1 == len(content) || content[i+1] == ' '):
			key := strings.TrimSpace(content[:i])
			if key == "" {
				return "", "", false
			}
			return workflowUnquote(key), strings.TrimSpace(content[i+1:]), true
		}
	}
	return "", "", false
}

func workflowUnquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func (p *workflowParser) node(indent int) (*workflowNode, error) {
	p.skip()
	if p.at >= len(p.lines) {
		return nil, fmt.Errorf("the workflow ends where a value was expected")
	}
	if workflowIsItem(workflowContent(p.lines[p.at])) {
		return p.sequence(indent)
	}
	return p.mapping(indent)
}

func (p *workflowParser) mapping(indent int) (*workflowNode, error) {
	node := &workflowNode{mapping: map[string]*workflowNode{}}
	for {
		p.skip()
		if p.at >= len(p.lines) {
			return node, nil
		}
		line := p.lines[p.at]
		at := workflowIndent(line)
		if at < indent {
			return node, nil
		}
		if at > indent {
			return nil, fmt.Errorf("line %d is indented %d where its mapping is at %d", p.at+1, at, indent)
		}
		content := workflowContent(line)
		if workflowIsItem(content) {
			return node, nil
		}
		key, value, ok := workflowEntry(content)
		if !ok {
			return nil, fmt.Errorf("line %d is not a mapping entry: %q", p.at+1, content)
		}
		if _, seen := node.mapping[key]; seen {
			return nil, fmt.Errorf("line %d repeats the key %q", p.at+1, key)
		}
		node.keys = append(node.keys, key)
		p.at++
		switch {
		case value == "":
			p.skip()
			if p.at < len(p.lines) {
				next := p.lines[p.at]
				nextAt := workflowIndent(next)
				if nextAt > indent || (nextAt == indent && workflowIsItem(workflowContent(next))) {
					child, err := p.node(nextAt)
					if err != nil {
						return nil, err
					}
					node.mapping[key] = child
					continue
				}
			}
			empty := ""
			node.mapping[key] = &workflowNode{scalar: &empty}
		case strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">"):
			child, err := p.blockScalar(indent, value)
			if err != nil {
				return nil, err
			}
			node.mapping[key] = child
		default:
			child, err := workflowFlow(value, p.at)
			if err != nil {
				return nil, err
			}
			node.mapping[key] = child
		}
	}
}

func (p *workflowParser) sequence(indent int) (*workflowNode, error) {
	node := &workflowNode{sequence: []*workflowNode{}}
	for {
		p.skip()
		if p.at >= len(p.lines) {
			return node, nil
		}
		line := p.lines[p.at]
		at := workflowIndent(line)
		content := workflowContent(line)
		if at < indent || (at == indent && !workflowIsItem(content)) {
			return node, nil
		}
		if at > indent {
			return nil, fmt.Errorf("line %d is indented %d where its sequence is at %d", p.at+1, at, indent)
		}
		rest := strings.TrimLeft(strings.TrimPrefix(content, "-"), " ")
		column := at + (len(content) - len(rest))
		if rest == "" {
			p.at++
			child, err := p.node(indent + 1)
			if err != nil {
				return nil, err
			}
			node.sequence = append(node.sequence, child)
			continue
		}
		if _, _, entry := workflowEntry(rest); entry && !strings.HasPrefix(rest, "[") && !strings.HasPrefix(rest, "'") && !strings.HasPrefix(rest, "\"") {
			// "- key: value": a mapping whose first key sits where the dash's content starts
			p.lines[p.at] = strings.Repeat(" ", column) + line[column:]
			child, err := p.mapping(column)
			if err != nil {
				return nil, err
			}
			node.sequence = append(node.sequence, child)
			continue
		}
		child, err := workflowFlow(rest, p.at)
		if err != nil {
			return nil, err
		}
		node.sequence = append(node.sequence, child)
		p.at++
	}
}

// a block scalar: every following line indented past the key, or blank
func (p *workflowParser) blockScalar(indent int, header string) (*workflowNode, error) {
	if header != "|" && header != "|-" && header != ">" && header != ">-" {
		return nil, fmt.Errorf("line %d: block scalar header %q is outside the subset this check reads", p.at, header)
	}
	body := []string{}
	content := -1
	for p.at < len(p.lines) {
		line := p.lines[p.at]
		if strings.TrimSpace(line) == "" {
			body = append(body, "")
			p.at++
			continue
		}
		at := workflowIndent(line)
		if at <= indent {
			break
		}
		if content < 0 {
			content = at
		}
		if at < content {
			return nil, fmt.Errorf("line %d is less indented than its block scalar", p.at+1)
		}
		body = append(body, line[content:])
		p.at++
	}
	for len(body) > 0 && body[len(body)-1] == "" {
		body = body[:len(body)-1]
	}
	separator := "\n"
	if strings.HasPrefix(header, ">") {
		separator = " "
	}
	text := strings.Join(body, separator)
	return &workflowNode{scalar: &text}, nil
}

// a plain or quoted scalar, or a flow sequence of them
func workflowFlow(value string, line int) (*workflowNode, error) {
	switch value[0] {
	case '&', '*', '!', '{', '%', '@', '`':
		return nil, fmt.Errorf("line %d: %q is outside the subset this check reads (anchors, aliases, tags and flow mappings are refused)", line, value)
	case '[':
		if !strings.HasSuffix(value, "]") || strings.ContainsAny(value[1:len(value)-1], "[]{}") {
			return nil, fmt.Errorf("line %d: %q is not a flat flow sequence", line, value)
		}
		node := &workflowNode{sequence: []*workflowNode{}}
		for _, item := range strings.Split(value[1:len(value)-1], ",") {
			item = workflowUnquote(strings.TrimSpace(item))
			if item == "" {
				continue
			}
			node.sequence = append(node.sequence, &workflowNode{scalar: &item})
		}
		return node, nil
	}
	scalar := workflowUnquote(value)
	return &workflowNode{scalar: &scalar}, nil
}
