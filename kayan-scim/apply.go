package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ApplyPatch applies a PATCH request to a user and returns the result.
//
// The input is not modified. Deprovisioning arrives here as a replace on
// "active", which is how Okta and Entra ID disable an account:
//
//	{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
//	 "Operations":[{"op":"replace","path":"active","value":false}]}
//
// Read-only attributes are refused rather than silently ignored, so a caller
// cannot believe it changed an ID that in fact stayed put.
func ApplyPatch(user *User, patch *PatchOp) (*User, error) {
	if user == nil {
		return nil, NewError("400", "invalidValue", "no resource to patch")
	}
	if patch == nil {
		return nil, NewError("400", "invalidSyntax", "no patch operations")
	}

	updated := *user

	for i, op := range patch.Operations {
		if err := applyOperation(&updated, op); err != nil {
			var scimErr *ErrorResponse
			if ok := asScimError(err, &scimErr); ok {
				scimErr.Detail = fmt.Sprintf("operation %d: %s", i, scimErr.Detail)
				return nil, scimErr
			}
			return nil, err
		}
	}

	return &updated, nil
}

// readOnlyAttributes may not be modified through PATCH (RFC 7643 section 3.1).
var readOnlyAttributes = map[string]struct{}{
	"id":      {},
	"meta":    {},
	"groups":  {},
	"schemas": {},
}

func applyOperation(user *User, op PatchOperation) error {
	// An operation with no path replaces whole attributes from an object
	// value, which is how some clients set several fields at once.
	if op.Path == "" {
		if op.Op == PatchOpRemove {
			return NewError("400", "noTarget", "remove requires a path")
		}
		return applyPathlessOperation(user, op)
	}

	path, err := ParsePath(op.Path)
	if err != nil {
		return err
	}

	attribute := strings.ToLower(path.Attribute)
	if _, readOnly := readOnlyAttributes[attribute]; readOnly {
		return NewError("400", "mutability",
			fmt.Sprintf("%s is read-only", path.Attribute))
	}

	switch attribute {
	case "active":
		if op.Op == PatchOpRemove {
			user.Active = false
			return nil
		}
		var active bool
		if err := json.Unmarshal(op.Value, &active); err != nil {
			return NewError("400", "invalidValue", "active must be a boolean")
		}
		user.Active = active
		return nil

	case "username":
		return applyStringAttribute(&user.UserName, op, "userName")

	case "displayname":
		return applyStringAttribute(&user.DisplayName, op, "displayName")

	case "externalid":
		return applyStringAttribute(&user.ExternalID, op, "externalId")

	case "nickname":
		return applyStringAttribute(&user.NickName, op, "nickName")

	case "title":
		return applyStringAttribute(&user.Title, op, "title")

	case "usertype":
		return applyStringAttribute(&user.UserType, op, "userType")

	case "preferredlanguage":
		return applyStringAttribute(&user.PreferredLanguage, op, "preferredLanguage")

	case "locale":
		return applyStringAttribute(&user.Locale, op, "locale")

	case "timezone":
		return applyStringAttribute(&user.Timezone, op, "timezone")

	case "password":
		if op.Op == PatchOpRemove {
			return NewError("400", "invalidValue", "password cannot be removed")
		}
		return applyStringAttribute(&user.Password, op, "password")

	case "name":
		return applyNameAttribute(user, path, op)

	case "emails":
		return applyMultiValued(&user.Emails, path, op, "emails")

	case "phonenumbers":
		return applyMultiValued(&user.PhoneNumbers, path, op, "phoneNumbers")

	default:
		return NewError("400", "invalidPath",
			fmt.Sprintf("unsupported attribute %q", path.Attribute))
	}
}

// applyPathlessOperation applies an object value across several attributes.
func applyPathlessOperation(user *User, op PatchOperation) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(op.Value, &fields); err != nil {
		return NewError("400", "invalidValue", "a patch without a path requires an object value")
	}

	for name, raw := range fields {
		if err := applyOperation(user, PatchOperation{Op: op.Op, Path: name, Value: raw}); err != nil {
			return err
		}
	}
	return nil
}

func applyStringAttribute(target *string, op PatchOperation, name string) error {
	if op.Op == PatchOpRemove {
		*target = ""
		return nil
	}

	var value string
	if err := json.Unmarshal(op.Value, &value); err != nil {
		return NewError("400", "invalidValue", fmt.Sprintf("%s must be a string", name))
	}
	*target = value
	return nil
}

func applyNameAttribute(user *User, path Path, op PatchOperation) error {
	if path.SubAttribute == "" {
		if op.Op == PatchOpRemove {
			user.Name = nil
			return nil
		}
		var name Name
		if err := json.Unmarshal(op.Value, &name); err != nil {
			return NewError("400", "invalidValue", "name must be an object")
		}
		user.Name = &name
		return nil
	}

	// A sub-attribute assignment on an absent name creates it.
	if user.Name == nil {
		user.Name = &Name{}
	}

	var target *string
	switch strings.ToLower(path.SubAttribute) {
	case "formatted":
		target = &user.Name.Formatted
	case "familyname":
		target = &user.Name.FamilyName
	case "givenname":
		target = &user.Name.GivenName
	case "middlename":
		target = &user.Name.MiddleName
	case "honorificprefix":
		target = &user.Name.HonorificPrefix
	case "honorificsuffix":
		target = &user.Name.HonorificSuffix
	default:
		return NewError("400", "invalidPath",
			fmt.Sprintf("unsupported sub-attribute name.%s", path.SubAttribute))
	}

	return applyStringAttribute(target, op, "name."+path.SubAttribute)
}

// applyMultiValued applies an operation to a multi-valued attribute, honoring
// a value filter when the path carries one.
func applyMultiValued(target *[]MultiValued, path Path, op PatchOperation, name string) error {
	switch op.Op {
	case PatchOpRemove:
		if path.Filter == nil {
			*target = nil
			return nil
		}
		kept := (*target)[:0]
		for _, entry := range *target {
			if !matchesMultiValued(entry, path.Filter) {
				kept = append(kept, entry)
			}
		}
		*target = kept
		return nil

	case PatchOpAdd:
		values, err := decodeMultiValued(op.Value, name)
		if err != nil {
			return err
		}
		*target = append(*target, values...)
		return nil

	case PatchOpReplace:
		if path.Filter == nil {
			values, err := decodeMultiValued(op.Value, name)
			if err != nil {
				return err
			}
			*target = values
			return nil
		}

		// A filtered replace updates the matching entries in place. With a
		// sub-attribute it sets just that member; without one it replaces the
		// whole entry.
		var replacement string
		if path.SubAttribute != "" {
			if err := json.Unmarshal(op.Value, &replacement); err != nil {
				return NewError("400", "invalidValue",
					fmt.Sprintf("%s.%s must be a string", name, path.SubAttribute))
			}
		}

		matched := false
		for i := range *target {
			if !matchesMultiValued((*target)[i], path.Filter) {
				continue
			}
			matched = true

			if path.SubAttribute == "" {
				var entry MultiValued
				if err := json.Unmarshal(op.Value, &entry); err != nil {
					return NewError("400", "invalidValue", fmt.Sprintf("%s entry must be an object", name))
				}
				(*target)[i] = entry
				continue
			}

			switch strings.ToLower(path.SubAttribute) {
			case "value":
				(*target)[i].Value = replacement
			case "type":
				(*target)[i].Type = replacement
			case "display":
				(*target)[i].Display = replacement
			case "primary":
				var primary bool
				if err := json.Unmarshal(op.Value, &primary); err != nil {
					return NewError("400", "invalidValue", "primary must be a boolean")
				}
				(*target)[i].Primary = primary
			default:
				return NewError("400", "invalidPath",
					fmt.Sprintf("unsupported sub-attribute %s.%s", name, path.SubAttribute))
			}
		}

		if !matched {
			return NewError("400", "noTarget", fmt.Sprintf("no %s entry matches the filter", name))
		}
		return nil

	default:
		return NewError("400", "invalidValue", fmt.Sprintf("unknown op %q", op.Op))
	}
}

func decodeMultiValued(raw json.RawMessage, name string) ([]MultiValued, error) {
	// The value may be a single entry or an array of them.
	var many []MultiValued
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}

	var one MultiValued
	if err := json.Unmarshal(raw, &one); err != nil {
		return nil, NewError("400", "invalidValue",
			fmt.Sprintf("%s must be an object or an array of objects", name))
	}
	return []MultiValued{one}, nil
}

// matchesMultiValued evaluates a value filter against one entry.
func matchesMultiValued(entry MultiValued, filter FilterExpr) bool {
	switch f := filter.(type) {
	case Comparison:
		var field string
		switch strings.ToLower(f.Path.Attribute) {
		case "value":
			field = entry.Value
		case "type":
			field = entry.Type
		case "display":
			field = entry.Display
		case "primary":
			want, ok := f.Value.(bool)
			return ok && entry.Primary == want
		default:
			return false
		}

		want, _ := f.Value.(string)
		switch f.Operator {
		case OpEqual:
			return strings.EqualFold(field, want)
		case OpNotEqual:
			return !strings.EqualFold(field, want)
		case OpContains:
			return strings.Contains(strings.ToLower(field), strings.ToLower(want))
		case OpStartsWith:
			return strings.HasPrefix(strings.ToLower(field), strings.ToLower(want))
		case OpEndsWith:
			return strings.HasSuffix(strings.ToLower(field), strings.ToLower(want))
		case OpPresent:
			return field != ""
		default:
			return false
		}

	case And:
		return matchesMultiValued(entry, f.Left) && matchesMultiValued(entry, f.Right)
	case Or:
		return matchesMultiValued(entry, f.Left) || matchesMultiValued(entry, f.Right)
	case Not:
		return !matchesMultiValued(entry, f.Expr)
	default:
		return false
	}
}

// asScimError reports whether err is an *ErrorResponse.
func asScimError(err error, target **ErrorResponse) bool {
	if e, ok := err.(*ErrorResponse); ok {
		copy := *e
		*target = &copy
		return true
	}
	return false
}
