package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PATCH operation names (RFC 7644 section 3.5.2).
const (
	PatchOpAdd     = "add"
	PatchOpRemove  = "remove"
	PatchOpReplace = "replace"
)

// PatchOpSchema is the schema URN a PATCH request must declare.
const PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

// PatchOp is a SCIM PATCH request (RFC 7644 section 3.5.2).
//
// PATCH is how identity providers deprovision: Okta and Entra ID both
// deactivate a user by sending replace on the "active" attribute rather than
// deleting the resource. A provisioning integration without PATCH silently
// fails to disable anyone.
type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one modification within a [PatchOp].
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// MaxPatchOperations bounds how many operations one request may carry.
//
// The endpoint is authenticated but the body is still attacker-supplied, and
// each operation costs a reflective walk of the resource.
const MaxPatchOperations = 100

// ParsePatchOp decodes and validates a SCIM PATCH request body.
func ParsePatchOp(data []byte) (*PatchOp, error) {
	if len(data) == 0 {
		return nil, NewError("400", "invalidSyntax", "empty request body")
	}

	var op PatchOp
	if err := json.Unmarshal(data, &op); err != nil {
		return nil, NewError("400", "invalidSyntax", "malformed JSON")
	}

	if !hasSchema(op.Schemas, PatchOpSchema) {
		return nil, NewError("400", "invalidSyntax",
			fmt.Sprintf("schemas must contain %s", PatchOpSchema))
	}
	if len(op.Operations) == 0 {
		return nil, NewError("400", "invalidValue", "Operations must not be empty")
	}
	if len(op.Operations) > MaxPatchOperations {
		return nil, NewError("400", "tooMany",
			fmt.Sprintf("at most %d operations are accepted", MaxPatchOperations))
	}

	for i := range op.Operations {
		// SCIM operation names are case-insensitive.
		op.Operations[i].Op = strings.ToLower(strings.TrimSpace(op.Operations[i].Op))

		switch op.Operations[i].Op {
		case PatchOpAdd, PatchOpReplace:
			if len(op.Operations[i].Value) == 0 {
				return nil, NewError("400", "invalidValue",
					fmt.Sprintf("operation %d: %s requires a value", i, op.Operations[i].Op))
			}
		case PatchOpRemove:
			// remove without a path would delete the entire resource.
			if op.Operations[i].Path == "" {
				return nil, NewError("400", "noTarget", fmt.Sprintf("operation %d: remove requires a path", i))
			}
		default:
			return nil, NewError("400", "invalidValue",
				fmt.Sprintf("operation %d: unknown op %q", i, op.Operations[i].Op))
		}

		if op.Operations[i].Path != "" {
			if _, err := ParsePath(op.Operations[i].Path); err != nil {
				return nil, err
			}
		}
	}

	return &op, nil
}

// Path is a parsed SCIM attribute path.
//
// SCIM paths address more than a field name: emails[type eq "work"].value
// selects the value sub-attribute of whichever email has type "work".
type Path struct {
	// Attribute is the top-level attribute, such as "emails" or "active".
	Attribute string

	// Filter selects among a multi-valued attribute's entries. Nil when the
	// path carries no filter.
	Filter FilterExpr

	// SubAttribute addresses a member of the selected value, such as the
	// "value" in emails[...].value.
	SubAttribute string

	// URN is the schema extension the attribute belongs to, if the path was
	// fully qualified.
	URN string
}

// String renders the path in SCIM syntax.
func (p Path) String() string {
	var b strings.Builder
	if p.URN != "" {
		b.WriteString(p.URN)
		b.WriteByte(':')
	}
	b.WriteString(p.Attribute)
	if p.Filter != nil {
		b.WriteByte('[')
		b.WriteString(p.Filter.String())
		b.WriteByte(']')
	}
	if p.SubAttribute != "" {
		b.WriteByte('.')
		b.WriteString(p.SubAttribute)
	}
	return b.String()
}

// ParsePath parses a SCIM attribute path (RFC 7644 section 3.5.2).
//
// Accepted forms:
//
//	active
//	name.givenName
//	emails[type eq "work"].value
//	urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager
func ParsePath(path string) (Path, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Path{}, NewError("400", "noTarget", "empty path")
	}

	var parsed Path

	// A fully qualified path prefixes the attribute with its schema URN. The
	// URN itself contains colons, so split at the last one that precedes the
	// attribute rather than the first.
	if strings.HasPrefix(strings.ToLower(trimmed), "urn:") {
		idx := strings.LastIndex(trimmed, ":")
		if idx < 0 || idx == len(trimmed)-1 {
			return Path{}, NewError("400", "invalidPath", "malformed schema URN in path")
		}
		parsed.URN = trimmed[:idx]
		trimmed = trimmed[idx+1:]
	}

	// A value filter, if present, sits between brackets.
	if open := strings.IndexByte(trimmed, '['); open >= 0 {
		close := strings.LastIndexByte(trimmed, ']')
		if close < open {
			return Path{}, NewError("400", "invalidPath", "unbalanced brackets in path")
		}

		parsed.Attribute = strings.TrimSpace(trimmed[:open])
		if parsed.Attribute == "" {
			return Path{}, NewError("400", "invalidPath", "path has no attribute before its filter")
		}

		filter, err := ParseFilter(trimmed[open+1 : close])
		if err != nil {
			return Path{}, err
		}
		parsed.Filter = filter

		rest := strings.TrimSpace(trimmed[close+1:])
		if rest != "" {
			if !strings.HasPrefix(rest, ".") {
				return Path{}, NewError("400", "invalidPath", "expected a sub-attribute after the filter")
			}
			parsed.SubAttribute = strings.TrimSpace(rest[1:])
			if parsed.SubAttribute == "" {
				return Path{}, NewError("400", "invalidPath", "empty sub-attribute")
			}
		}
		return parsed, nil
	}

	// A closing bracket with no opening one is malformed, not an attribute
	// name containing a bracket.
	if strings.ContainsAny(trimmed, "]") {
		return Path{}, NewError("400", "invalidPath", "unbalanced brackets in path")
	}

	// No filter: at most one dot separates attribute from sub-attribute.
	attribute, sub, found := strings.Cut(trimmed, ".")
	parsed.Attribute = strings.TrimSpace(attribute)
	if parsed.Attribute == "" {
		return Path{}, NewError("400", "invalidPath", "empty attribute")
	}
	if found {
		parsed.SubAttribute = strings.TrimSpace(sub)
		if parsed.SubAttribute == "" {
			return Path{}, NewError("400", "invalidPath", "empty sub-attribute")
		}
		if strings.Contains(parsed.SubAttribute, ".") {
			return Path{}, NewError("400", "invalidPath", "paths are at most two levels deep")
		}
	}

	return parsed, nil
}

func hasSchema(schemas []string, want string) bool {
	for _, s := range schemas {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
