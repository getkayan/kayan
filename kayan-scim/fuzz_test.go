package scim

import (
	"strings"
	"testing"
)

// FuzzParseFilter drives the filter grammar with arbitrary input.
//
// The filter arrives as a query parameter, so it is attacker-controlled. It
// must never panic, and anything it accepts must render back to something it
// accepts again — a parser whose output it cannot re-read is one whose tree
// does not mean what the text said.
func FuzzParseFilter(f *testing.F) {
	seeds := []string{
		`userName eq "bjensen"`,
		`title pr and userType eq "Employee"`,
		`not (userType eq "Employee")`,
		`(a eq "1" or b eq "2") and c eq "3"`,
		`emails[type eq "work"]`,
		`userName eq "unterminated`,
		`((((((((((a eq "1"))))))))))`,
		``,
		`"`,
		`\`,
		`userName eq "\q"`,
		strings.Repeat("not (", 50) + `a eq "1"` + strings.Repeat(")", 50),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		expr, err := ParseFilter(input)
		if err != nil {
			return
		}
		if expr == nil {
			t.Fatal("ParseFilter returned no error and no expression")
		}

		// The rendered form must parse back. If it does not, the tree and the
		// text disagree, and a backend compiling the tree would query for
		// something other than what was asked.
		rendered := expr.String()
		if _, err := ParseFilter(rendered); err != nil {
			t.Fatalf("filter %q rendered to %q, which does not parse: %v", input, rendered, err)
		}
	})
}

// FuzzParsePath drives the attribute path parser.
func FuzzParsePath(f *testing.F) {
	seeds := []string{
		"active",
		"name.givenName",
		`emails[type eq "work"].value`,
		"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
		"",
		"[",
		"]",
		"a.b.c",
		"emails[",
		`emails[]`,
		strings.Repeat("a.", 100) + "b",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		path, err := ParsePath(input)
		if err != nil {
			return
		}

		// An accepted path must name an attribute; without one there is
		// nothing for a patch to target.
		if path.Attribute == "" {
			t.Fatalf("ParsePath accepted %q with no attribute", input)
		}
		// It must also round-trip, for the same reason as the filter.
		if _, err := ParsePath(path.String()); err != nil {
			t.Fatalf("path %q rendered to %q, which does not parse: %v", input, path.String(), err)
		}
	})
}

// FuzzParsePatchOp drives the PATCH body parser.
//
// The body is JSON from a provisioning client. It must never panic, and
// anything it accepts must be safe to hand to ApplyPatch.
func FuzzParsePatchOp(f *testing.F) {
	seeds := []string{
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[type eq \"work\"]"}]}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","value":{"active":true}}]}`,
		`{}`,
		``,
		`null`,
		`{"schemas":[],"Operations":null}`,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"id","value":"x"}]}`,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, body []byte) {
		patch, err := ParsePatchOp(body)
		if err != nil {
			return
		}

		if len(patch.Operations) == 0 {
			t.Fatal("ParsePatchOp accepted a request with no operations")
		}
		if len(patch.Operations) > MaxPatchOperations {
			t.Fatalf("ParsePatchOp accepted %d operations, over the limit", len(patch.Operations))
		}

		// Applying a parsed patch must not panic, whatever the operations say.
		user := &User{
			UserName: "user@example.test",
			Active:   true,
			Emails:   []MultiValued{{Value: "user@example.test", Type: "work"}},
		}
		updated, err := ApplyPatch(user, patch)
		if err != nil {
			return
		}

		// Read-only attributes must survive any patch that was accepted.
		if updated.ID != user.ID {
			t.Fatalf("PATCH changed the read-only ID from %q to %q", user.ID, updated.ID)
		}
	})
}
