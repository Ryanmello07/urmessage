package repository

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The root module's go.mod, held to MESSAGEREVIEW.md's "Final dependency boundary" (BOUNDARY.md B2):
// the root module is github.com/urnetwork/message, the five foundational packages, and it requires
// and replaces neither connect nor the core SDK. internal/layering holds the same boundary over
// every import declaration; this holds it over the module graph, where a requirement can arrive
// without any import (a tool dependency, a stray `go get`) and drag the core into every consumer's
// build list.

// The module paths go.mod's directives name: the module line, and every require, replace (both
// sides of the arrow that are module paths) and exclude, single-line and in blocks. Comments are
// not directives: a comment naming connect is prose.
func goModDirectivePaths(goMod string) map[string][]string {
	paths := map[string][]string{}
	block := ""
	for _, raw := range strings.Split(strings.ReplaceAll(goMod, "\r\n", "\n"), "\n") {
		line := raw
		if at := strings.Index(line, "//"); at >= 0 {
			line = line[:at]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if block != "" {
			if fields[0] == ")" {
				block = ""
				continue
			}
			paths[block] = append(paths[block], directiveModules(block, fields)...)
			continue
		}
		switch fields[0] {
		case "require", "replace", "exclude":
			if len(fields) >= 2 && fields[1] == "(" {
				block = fields[0]
				continue
			}
			paths[fields[0]] = append(paths[fields[0]], directiveModules(fields[0], fields[1:])...)
		case "module":
			if len(fields) >= 2 {
				paths["module"] = append(paths["module"], strings.Trim(fields[1], `"`))
			}
		}
	}
	return paths
}

// The module paths in one directive's arguments: the first field, and for a replace the
// replacement too when it is a module path rather than a directory.
func directiveModules(directive string, fields []string) []string {
	if len(fields) == 0 {
		return nil
	}
	modules := []string{strings.Trim(fields[0], `"`)}
	if directive == "replace" {
		if arrow := slices.Index(fields, "=>"); arrow >= 0 && arrow+1 < len(fields) {
			target := strings.Trim(fields[arrow+1], `"`)
			if !strings.HasPrefix(target, ".") && !strings.HasPrefix(target, "/") && !filepath.IsAbs(target) {
				modules = append(modules, target)
			}
		}
	}
	return modules
}

// What go.mod owes the boundary: its module line, and no directive naming connect or the core SDK
// (the path itself or a package beneath it; github.com/urnetwork/connectx is another module).
func rootGoModProblems(goMod string) []string {
	problems := []string{}
	paths := goModDirectivePaths(goMod)
	if !slices.Equal(paths["module"], []string{"github.com/urnetwork/message"}) {
		problems = append(problems, "the module line declares "+strings.Join(paths["module"], ", ")+", want github.com/urnetwork/message")
	}
	for _, directive := range []string{"require", "replace", "exclude"} {
		for _, module := range paths[directive] {
			for _, core := range []string{"github.com/urnetwork/connect", "github.com/urnetwork/sdk"} {
				if module == core || strings.HasPrefix(module, core+"/") {
					problems = append(problems, directive+" names "+module+": the root module depends on neither connect nor the core SDK")
				}
			}
		}
	}
	return problems
}

func TestTheRootModuleRequiresNeitherConnectNorTheCoreSdk(t *testing.T) {
	root := repositoryRoot(t)
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	paths := goModDirectivePaths(string(goMod))
	if len(paths["require"]) == 0 {
		t.Fatalf("go.mod has no require directive this reader found, so the check below was asked of nothing: %q", paths)
	}
	t.Logf("go.mod: module %v; require %v; replace %v; exclude %v", paths["module"], paths["require"], paths["replace"], paths["exclude"])
	for _, problem := range rootGoModProblems(string(goMod)) {
		t.Error(problem)
	}
}

// Each way a go.mod can name the core, refused for its own reason; what only looks like it, and a
// comment, passed.
func TestTheRootGoModCheckRefusesEveryWayToNameTheCore(t *testing.T) {
	const clean = "module github.com/urnetwork/message\n\ngo 1.26.3\n\nrequire (\n\tgolang.org/x/crypto v0.54.0\n)\n"
	if problems := rootGoModProblems(clean); len(problems) != 0 {
		t.Fatalf("a clean go.mod was refused: %q", problems)
	}
	for _, control := range []struct {
		name, goMod, want string
	}{
		{"required in a block", clean + "require (\n\tgithub.com/urnetwork/connect v0.0.0\n)\n", "require names github.com/urnetwork/connect"},
		{"required on one line", clean + "require github.com/urnetwork/sdk v0.0.0 // indirect\n", "require names github.com/urnetwork/sdk"},
		{"a package beneath it", clean + "require github.com/urnetwork/connect/protocol v0.0.0\n", "require names github.com/urnetwork/connect/protocol"},
		{"replaced", clean + "replace github.com/urnetwork/connect => ../connect\n", "replace names github.com/urnetwork/connect"},
		{"the replacement of another module", clean + "replace example.com/x => github.com/urnetwork/sdk v0.0.0\n", "replace names github.com/urnetwork/sdk"},
		{"excluded in a block", clean + "exclude (\n\tgithub.com/urnetwork/sdk v0.0.1\n)\n", "exclude names github.com/urnetwork/sdk"},
		{"another module line", strings.Replace(clean, "module github.com/urnetwork/message", "module github.com/urnetwork/messageclone", 1), "the module line declares github.com/urnetwork/messageclone"},
	} {
		problems := rootGoModProblems(control.goMod)
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, control.want) }) {
			t.Errorf("%s: not refused for %q; reported %q", control.name, control.want, problems)
		}
	}
	for _, lookalike := range []string{
		clean + "require github.com/urnetwork/connectx v0.0.0\n",
		clean + "require github.com/urnetwork/sdkfoo v0.0.0\n",
		clean + "// connect was github.com/urnetwork/connect before the split\n",
		clean + "replace golang.org/x/crypto => ../crypto // not github.com/urnetwork/connect\n",
	} {
		if problems := rootGoModProblems(lookalike); len(problems) != 0 {
			t.Errorf("a go.mod that only looks like it names the core was refused: %q\n%s", problems, lookalike)
		}
	}
}
