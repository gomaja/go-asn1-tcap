package gsmmap_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gomaja/go-asn1-tcap"
	"github.com/gomaja/go-asn1-tcap/gsmmap"
	"github.com/gomaja/go-asn1/telecom/ss7/gsm_map"
)

var dottedOID = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))+$`)

// dotted formats an object identifier as dotted decimal.
func dotted(o interface{ String() string }) string {
	return o.String()
}

// checkCanonical reports whether s is a canonical OID: dotted decimal without
// leading zeros, first arc 0 to 2, second arc at most 39 below arcs 0 and 1.
func checkCanonical(t *testing.T, name string, s string) {
	t.Helper()
	if !dottedOID.MatchString(s) {
		t.Errorf("%s = %q: not dotted decimal without leading zeros", name, s)
		return
	}
	arcs := strings.Split(s, ".")
	first, err := strconv.ParseUint(arcs[0], 10, 64)
	if err != nil || first > 2 {
		t.Errorf("%s = %q: first arc must be 0, 1 or 2", name, s)
		return
	}
	second, err := strconv.ParseUint(arcs[1], 10, 64)
	if err != nil {
		t.Errorf("%s = %q: second arc: %v", name, s, err)
		return
	}
	if first < 2 && second > 39 {
		t.Errorf("%s = %q: second arc exceeds 39 below first arc %d", name, s, first)
	}
}

func TestCurrentContextsMatchGoASN1(t *testing.T) {
	if len(currentContexts) != 44 {
		t.Fatalf("table has %d current contexts, want 44", len(currentContexts))
	}
	for _, c := range currentContexts {
		if got, want := string(c.value), c.oracle; got != want {
			t.Errorf("%s = %q, go-asn1 returns %q", c.name, got, want)
		}
	}
}

func TestDialogueAS(t *testing.T) {
	if got, want := string(gsmmap.DialogueAS), dotted(gsm_map.MapDialogueAS()); got != want {
		t.Errorf("DialogueAS = %q, go-asn1 MapDialogueAS returns %q", got, want)
	}
}

func TestOperationCodesMatchGoASN1(t *testing.T) {
	if len(operationCodes) != 81 {
		t.Fatalf("table has %d operation codes, want 81", len(operationCodes))
	}
	for _, c := range operationCodes {
		if int64(c.value) != c.oracle {
			t.Errorf("%s = %d, go-asn1 has %d", c.name, c.value, c.oracle)
		}
	}
}

func TestErrorCodesMatchGoASN1(t *testing.T) {
	if len(errorCodes) != 59 {
		t.Fatalf("table has %d error codes, want 59", len(errorCodes))
	}
	for _, c := range errorCodes {
		if int64(c.value) != c.oracle {
			t.Errorf("%s = %d, go-asn1 has %d", c.name, c.value, c.oracle)
		}
	}
}

func TestOIDsCanonicalAndUnique(t *testing.T) {
	seen := map[tcap.OID]string{}
	add := func(name string, v tcap.OID) {
		checkCanonical(t, name, string(v))
		if prev, dup := seen[v]; dup {
			t.Errorf("%s and %s share the value %q", prev, name, v)
		}
		seen[v] = name
	}
	for _, c := range currentContexts {
		add(c.name, c.value)
	}
	for _, c := range reservedContexts {
		add(c.name, c.value)
	}
	for _, c := range equivalentContexts {
		add(c.name, c.value)
	}
	add("DialogueAS", gsmmap.DialogueAS)
	if want := 44 + 33 + 1 + 1; len(seen) != want {
		t.Errorf("%d distinct OIDs, want %d", len(seen), want)
	}
}

func TestCodesUnique(t *testing.T) {
	for kind, cases := range map[string][]codeCase{"operation": operationCodes, "error": errorCodes} {
		seen := map[tcap.LocalCode]string{}
		for _, c := range cases {
			if prev, dup := seen[c.value]; dup {
				t.Errorf("%s codes %s and %s share the value %d", kind, prev, c.name, c.value)
			}
			seen[c.value] = c.name
		}
	}
}

// TestTablesCoverPackage checks that the tables above list every constant
// the package declares, so that a new constant cannot escape the checks.
func TestTablesCoverPackage(t *testing.T) {
	fset := token.NewFileSet()
	files := []string{"acn.go", "dialogue.go", "opcode.go", "errcode.go"}
	declared := map[string]bool{}
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				t.Errorf("%s: package must hold constants only", f)
				continue
			}
			if gd.Tok == token.IMPORT {
				continue
			}
			if gd.Tok != token.CONST {
				t.Errorf("%s: package must hold constants only, found %s", f, gd.Tok)
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					declared[n.Name] = true
				}
			}
		}
	}
	listed := map[string]bool{"DialogueAS": true}
	for _, c := range currentContexts {
		listed[c.name] = true
	}
	for _, c := range reservedContexts {
		listed[c.name] = true
	}
	for _, c := range equivalentContexts {
		listed[c.name] = true
	}
	for _, c := range operationCodes {
		listed[c.name] = true
	}
	for _, c := range errorCodes {
		listed[c.name] = true
	}
	for n := range declared {
		if !listed[n] {
			t.Errorf("constant %s is not covered by the tables", n)
		}
	}
	for n := range listed {
		if !declared[n] {
			t.Errorf("table entry %s is not declared in the package", n)
		}
	}
}

// TestContextsMatchSpecification compares the contexts that go-asn1 does not
// generate with the values read from 3GPP TS 29.002 V19.1.0 clauses 17.3.2 and
// 17.3.3.
func TestContextsMatchSpecification(t *testing.T) {
	for _, c := range reservedContexts {
		if c.value != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.value, c.want)
		}
	}
	for _, c := range equivalentContexts {
		if c.value != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.value, c.want)
		}
	}
}
