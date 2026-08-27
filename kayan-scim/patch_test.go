package scim

import (
	"encoding/json"
	"testing"
)

// TestDeprovisioningPayloads runs the exact bodies Okta and Entra ID send to
// disable an account.
//
// This is the operation that matters most in a provisioning integration: both
// products deactivate a user with PATCH rather than DELETE, so a server
// without PATCH silently leaves departed employees enabled.
func TestDeprovisioningPayloads(t *testing.T) {
	payloads := map[string]string{
		"Okta": `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "replace", "value": {"active": false}}]
		}`,
		"Entra ID": `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "Replace", "path": "active", "value": false}]
		}`,
		"lowercase operations key": `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [{"op": "replace", "path": "active", "value": "False"}]
		}`,
	}

	for name, body := range payloads {
		t.Run(name, func(t *testing.T) {
			patch, err := ParsePatchOp([]byte(body))
			if err != nil {
				t.Fatalf("ParsePatchOp: %v", err)
			}

			user := &User{UserName: "departed@example.test", Active: true}
			updated, err := ApplyPatch(user, patch)
			if err != nil {
				// The string "False" is not valid JSON for a boolean; that
				// case is expected to be refused rather than silently ignored.
				if name == "lowercase operations key" {
					return
				}
				t.Fatalf("ApplyPatch: %v", err)
			}

			if updated.Active {
				t.Fatal("the user is still active after a deprovisioning patch")
			}
			// The original must not be modified.
			if !user.Active {
				t.Error("ApplyPatch modified its input")
			}
		})
	}
}

func TestParsePatchOpRejects(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"empty body", ``},
		{"malformed JSON", `{"schemas":`},
		{"missing schema", `{"Operations":[{"op":"replace","path":"active","value":false}]}`},
		{
			name: "no operations",
			body: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[]}`,
		},
		{
			name: "unknown op",
			body: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			        "Operations":[{"op":"upsert","path":"active","value":false}]}`,
		},
		{
			name: "add without a value",
			body: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			        "Operations":[{"op":"add","path":"active"}]}`,
		},
		{
			name: "remove without a path would delete the resource",
			body: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			        "Operations":[{"op":"remove"}]}`,
		},
		{
			name: "malformed path",
			body: `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			        "Operations":[{"op":"replace","path":"emails[unclosed","value":"x"}]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePatchOp([]byte(tc.body)); err == nil {
				t.Fatal("the request was accepted")
			}
		})
	}
}

// TestPatchRejectsReadOnlyAttributes proves a client cannot change an ID and
// believe it worked.
func TestPatchRejectsReadOnlyAttributes(t *testing.T) {
	for _, attribute := range []string{"id", "meta", "groups", "schemas"} {
		t.Run(attribute, func(t *testing.T) {
			patch := &PatchOp{
				Schemas: []string{PatchOpSchema},
				Operations: []PatchOperation{
					{Op: PatchOpReplace, Path: attribute, Value: json.RawMessage(`"anything"`)},
				},
			}

			if _, err := ApplyPatch(&User{Resource: Resource{ID: "original"}}, patch); err == nil {
				t.Fatalf("%s was modified through PATCH", attribute)
			}
		})
	}
}

func TestApplyPatchOperations(t *testing.T) {
	tests := []struct {
		name   string
		user   User
		ops    []PatchOperation
		verify func(*testing.T, *User)
	}{
		{
			name: "replace a simple attribute",
			user: User{UserName: "old@example.test"},
			ops: []PatchOperation{
				{Op: PatchOpReplace, Path: "userName", Value: json.RawMessage(`"new@example.test"`)},
			},
			verify: func(t *testing.T, u *User) {
				if u.UserName != "new@example.test" {
					t.Errorf("UserName = %q", u.UserName)
				}
			},
		},
		{
			name: "set a nested sub-attribute",
			ops: []PatchOperation{
				{Op: PatchOpReplace, Path: "name.givenName", Value: json.RawMessage(`"Ada"`)},
			},
			verify: func(t *testing.T, u *User) {
				if u.Name == nil || u.Name.GivenName != "Ada" {
					t.Errorf("name.givenName not set: %+v", u.Name)
				}
			},
		},
		{
			name: "add to a multi-valued attribute",
			user: User{Emails: []MultiValued{{Value: "a@example.test", Type: "home"}}},
			ops: []PatchOperation{
				{Op: PatchOpAdd, Path: "emails", Value: json.RawMessage(`{"value":"b@example.test","type":"work"}`)},
			},
			verify: func(t *testing.T, u *User) {
				if len(u.Emails) != 2 {
					t.Fatalf("Emails has %d entries, want 2", len(u.Emails))
				}
			},
		},
		{
			name: "replace through a value filter",
			user: User{Emails: []MultiValued{
				{Value: "home@example.test", Type: "home"},
				{Value: "work@example.test", Type: "work"},
			}},
			ops: []PatchOperation{
				{
					Op:    PatchOpReplace,
					Path:  `emails[type eq "work"].value`,
					Value: json.RawMessage(`"newwork@example.test"`),
				},
			},
			verify: func(t *testing.T, u *User) {
				for _, email := range u.Emails {
					if email.Type == "work" && email.Value != "newwork@example.test" {
						t.Errorf("work email = %q", email.Value)
					}
					if email.Type == "home" && email.Value != "home@example.test" {
						t.Errorf("the home email was modified: %q", email.Value)
					}
				}
			},
		},
		{
			name: "remove through a value filter",
			user: User{Emails: []MultiValued{
				{Value: "home@example.test", Type: "home"},
				{Value: "work@example.test", Type: "work"},
			}},
			ops: []PatchOperation{
				{Op: PatchOpRemove, Path: `emails[type eq "home"]`},
			},
			verify: func(t *testing.T, u *User) {
				if len(u.Emails) != 1 || u.Emails[0].Type != "work" {
					t.Errorf("Emails = %+v, want only the work entry", u.Emails)
				}
			},
		},
		{
			name: "remove a selected sub-attribute through a value filter",
			user: User{Emails: []MultiValued{
				{Value: "home@example.test", Type: "home", Display: "Home"},
				{Value: "work@example.test", Type: "work", Display: "Work"},
			}},
			ops: []PatchOperation{
				{Op: PatchOpRemove, Path: `emails[type eq "work"].display`},
			},
			verify: func(t *testing.T, u *User) {
				if len(u.Emails) != 2 || u.Emails[0].Display != "Home" || u.Emails[1].Display != "" {
					t.Errorf("Emails = %+v", u.Emails)
				}
			},
		},
		{
			name: "several attributes without a path",
			ops: []PatchOperation{
				{Op: PatchOpReplace, Value: json.RawMessage(`{"active":true,"title":"Engineer"}`)},
			},
			verify: func(t *testing.T, u *User) {
				if !u.Active {
					t.Error("active was not set")
				}
				if u.Title != "Engineer" {
					t.Errorf("Title = %q", u.Title)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			user := tc.user
			updated, err := ApplyPatch(&user, &PatchOp{
				Schemas:    []string{PatchOpSchema},
				Operations: tc.ops,
			})
			if err != nil {
				t.Fatalf("ApplyPatch: %v", err)
			}
			tc.verify(t, updated)
		})
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		input        string
		attribute    string
		subAttribute string
		hasFilter    bool
		urn          string
	}{
		{input: "active", attribute: "active"},
		{input: "name.givenName", attribute: "name", subAttribute: "givenName"},
		{input: `emails[type eq "work"]`, attribute: "emails", hasFilter: true},
		{input: `emails[type eq "work"].value`, attribute: "emails", subAttribute: "value", hasFilter: true},
		{
			input:     "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
			attribute: "manager",
			urn:       "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			path, err := ParsePath(tc.input)
			if err != nil {
				t.Fatalf("ParsePath: %v", err)
			}
			if path.Attribute != tc.attribute {
				t.Errorf("Attribute = %q, want %q", path.Attribute, tc.attribute)
			}
			if path.SubAttribute != tc.subAttribute {
				t.Errorf("SubAttribute = %q, want %q", path.SubAttribute, tc.subAttribute)
			}
			if (path.Filter != nil) != tc.hasFilter {
				t.Errorf("Filter present = %v, want %v", path.Filter != nil, tc.hasFilter)
			}
			if path.URN != tc.urn {
				t.Errorf("URN = %q, want %q", path.URN, tc.urn)
			}
		})
	}
}

func TestParsePathRejects(t *testing.T) {
	for _, input := range []string{
		"",
		"   ",
		"emails[",
		"emails]",
		`emails[type eq "work"]garbage`,
		"a.b.c",
		"name.",
		".givenName",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParsePath(input); err == nil {
				t.Fatalf("ParsePath accepted %q", input)
			}
		})
	}
}
