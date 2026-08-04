package scim

import (
	"testing"
)

// TestParseFilter covers the examples in RFC 7644 section 3.4.2.2 plus the
// forms identity providers actually send.
func TestParseFilter(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`userName eq "bjensen"`, `userName eq "bjensen"`},
		{`name.familyName co "O'Malley"`, `name.familyName co "O'Malley"`},
		{`userName sw "J"`, `userName sw "J"`},
		{`title pr`, `title pr`},
		{`meta.lastModified gt "2011-05-13T04:42:34Z"`, `meta.lastModified gt "2011-05-13T04:42:34Z"`},
		{`title pr and userType eq "Employee"`, `(title pr and userType eq "Employee")`},
		{`title pr or userType eq "Intern"`, `(title pr or userType eq "Intern")`},
		{`not (userType eq "Employee")`, `not (userType eq "Employee")`},
		{`active eq true`, `active eq true`},
		{`age gt 21`, `age gt 21`},

		// Precedence: and binds tighter than or.
		{
			input: `a eq "1" or b eq "2" and c eq "3"`,
			want:  `(a eq "1" or (b eq "2" and c eq "3"))`,
		},
		// Parentheses override it.
		{
			input: `(a eq "1" or b eq "2") and c eq "3"`,
			want:  `((a eq "1" or b eq "2") and c eq "3")`,
		},
		// Operators are case-insensitive.
		{`userName EQ "bjensen"`, `userName eq "bjensen"`},
		{`title PR AND active EQ true`, `(title pr and active eq true)`},
		// Escapes inside a quoted value.
		{`displayName eq "say \"hi\""`, `displayName eq "say \"hi\""`},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			expr, err := ParseFilter(tc.input)
			if err != nil {
				t.Fatalf("ParseFilter: %v", err)
			}
			if got := expr.String(); got != tc.want {
				t.Errorf("parsed to %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseFilterRejects(t *testing.T) {
	for _, input := range []string{
		``,
		`   `,
		`userName`,                    // no operator
		`userName eq`,                 // no value
		`eq "bjensen"`,                // no attribute
		`userName xx "bjensen"`,       // unknown operator
		`userName eq "unterminated`,   // unterminated string
		`(userName eq "a"`,            // missing closing parenthesis
		`userName eq "a")`,            // stray closing parenthesis
		`userName eq "a" and`,         // dangling conjunction
		`not`,                         // dangling negation
		`userName eq "bad \q escape"`, // invalid escape
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseFilter(input); err == nil {
				t.Fatalf("ParseFilter accepted %q", input)
			}
		})
	}
}

// TestFilterDepthIsBounded proves a deeply nested filter cannot exhaust the
// stack. The filter arrives as a query parameter, so the input is untrusted.
func TestFilterDepthIsBounded(t *testing.T) {
	deep := "userName eq \"a\""
	for range MaxFilterDepth + 10 {
		deep = "not (" + deep + ")"
	}

	if _, err := ParseFilter(deep); err == nil {
		t.Fatal("a filter nested past the limit was accepted")
	}
}

// TestFilterASTShape checks the tree, not just the round-tripped text, so a
// backend compiling it sees what the test asserts.
func TestFilterASTShape(t *testing.T) {
	expr, err := ParseFilter(`userType eq "Employee" and emails co "example.com"`)
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}

	and, ok := expr.(And)
	if !ok {
		t.Fatalf("root is %T, want And", expr)
	}

	left, ok := and.Left.(Comparison)
	if !ok {
		t.Fatalf("left is %T, want Comparison", and.Left)
	}
	if left.Path.Attribute != "userType" || left.Operator != OpEqual || left.Value != "Employee" {
		t.Errorf("left = %+v", left)
	}

	right, ok := and.Right.(Comparison)
	if !ok {
		t.Fatalf("right is %T, want Comparison", and.Right)
	}
	if right.Operator != OpContains {
		t.Errorf("right operator = %q, want co", right.Operator)
	}
}

// TestFilterValueTypes proves literals keep their JSON type, so a backend can
// bind them as parameters rather than as strings.
func TestFilterValueTypes(t *testing.T) {
	tests := []struct {
		input string
		want  any
	}{
		{`active eq true`, true},
		{`active eq false`, false},
		{`count eq 42`, int64(42)},
		{`userName eq "42"`, "42"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			expr, err := ParseFilter(tc.input)
			if err != nil {
				t.Fatalf("ParseFilter: %v", err)
			}
			comparison, ok := expr.(Comparison)
			if !ok {
				t.Fatalf("expression is %T, want Comparison", expr)
			}
			if comparison.Value != tc.want {
				t.Errorf("value = %#v, want %#v", comparison.Value, tc.want)
			}
		})
	}
}
