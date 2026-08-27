package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ApplyGroupPatch applies a PATCH request to a group and returns the result.
//
// The input is not modified.
//
// Group membership is the operation identity providers perform most: every
// time somebody joins or leaves a team, Okta and Entra send
// PATCH /Groups/{id} with an add or remove on "members". [ApplyPatch] handles
// users only, so this is the group half of the same contract.
//
// Providers do not agree on the shape. Okta names the member to remove with a
// filter in the path:
//
//	{"op":"remove","path":"members[value eq \"user-2\"]"}
//
// Entra sends the members as the operation's value, and sometimes omits the
// path entirely, naming the attribute inside the value object:
//
//	{"op":"add","value":{"members":[{"value":"user-2"}]}}
//
// All three forms are accepted, because refusing one means that provider
// cannot provision groups at all.
func ApplyGroupPatch(group *Group, patch *PatchOp) (*Group, error) {
	if group == nil {
		return nil, NewError("400", "invalidValue", "no resource to patch")
	}
	if patch == nil {
		return nil, NewError("400", "invalidSyntax", "no patch operations")
	}

	updated := *group
	// Copy the members rather than sharing the caller's backing array.
	//
	// The filters below already build into a zero-capacity reslice, which
	// forces an allocation and so cannot write through to the input on its
	// own. This copy is the belt to that braces: it keeps the guarantee a
	// property of this function rather than of one expression inside a helper,
	// where changing [:0:0] to [:0] during some later edit would silently
	// start rewriting the caller's slice.
	updated.Members = append([]MemberRef(nil), group.Members...)

	for i, op := range patch.Operations {
		if err := applyGroupOperation(&updated, op); err != nil {
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

func applyGroupOperation(group *Group, op PatchOperation) error {
	if op.Path == "" {
		if op.Op == PatchOpRemove {
			return NewError("400", "noTarget", "remove requires a path")
		}
		return applyPathlessGroupOperation(group, op)
	}

	path, err := ParsePath(op.Path)
	if err != nil {
		return err
	}

	name := strings.ToLower(path.Attribute)
	if _, readOnly := readOnlyAttributes[name]; readOnly {
		return NewError("400", "mutability",
			fmt.Sprintf("%s is read-only and cannot be modified through PATCH", path.Attribute))
	}

	switch name {
	case "displayname":
		if path.Filter != nil || path.SubAttribute != "" {
			return NewError("400", "invalidPath", "displayName is not multi-valued")
		}
		return applyStringAttribute(&group.DisplayName, op, "displayName")
	case "externalid":
		if path.Filter != nil || path.SubAttribute != "" {
			return NewError("400", "invalidPath", "externalId is not multi-valued")
		}
		return applyStringAttribute(&group.ExternalID, op, "externalId")
	case "members":
		return applyMembers(group, op, path)
	default:
		// An unknown attribute is refused rather than ignored. Accepting it
		// silently would report success for a change that never happened, and
		// the provider would believe the group was in sync.
		return NewError("400", "invalidPath", fmt.Sprintf("unknown attribute %q", path.Attribute))
	}
}

func applyPathlessGroupOperation(group *Group, op PatchOperation) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(op.Value, &fields); err != nil {
		return NewError("400", "invalidValue", "a patch without a path requires an object value")
	}

	for name, raw := range fields {
		if err := applyGroupOperation(group, PatchOperation{Op: op.Op, Path: name, Value: raw}); err != nil {
			return err
		}
	}
	return nil
}

func applyMembers(group *Group, op PatchOperation, path Path) error {
	if path.SubAttribute != "" {
		return NewError("400", "invalidPath",
			fmt.Sprintf("members.%s cannot be patched directly", path.SubAttribute))
	}

	switch op.Op {
	case PatchOpRemove:
		return removeMembers(group, op, path)
	case PatchOpAdd, PatchOpReplace:
		members, err := parseMemberValue(op.Value)
		if err != nil {
			return err
		}
		if op.Op == PatchOpReplace && path.Filter == nil {
			group.Members = members
			return nil
		}
		return addMembers(group, members)
	default:
		return NewError("400", "invalidSyntax", fmt.Sprintf("unknown operation %q", op.Op))
	}
}

// addMembers appends members that are not already present.
//
// Identity providers retry, so the same add arrives more than once. A group
// that lists a member twice breaks anything counting membership, and removing
// them once would then leave a stale entry behind.
func addMembers(group *Group, members []MemberRef) error {
	for _, candidate := range members {
		if candidate.Value == "" {
			return NewError("400", "invalidValue", "a member requires a value")
		}
		var present bool
		for _, existing := range group.Members {
			if strings.EqualFold(existing.Value, candidate.Value) {
				present = true
				break
			}
		}
		if !present {
			group.Members = append(group.Members, candidate)
		}
	}
	return nil
}

// removeMembers handles the three shapes a removal arrives in: a filter in the
// path, an explicit list of members as the value, or neither -- which clears
// the attribute.
func removeMembers(group *Group, op PatchOperation, path Path) error {
	if path.Filter != nil {
		kept := group.Members[:0:0]
		for _, member := range group.Members {
			if !matchesMultiValued(memberAsMultiValued(member), path.Filter) {
				kept = append(kept, member)
			}
		}
		group.Members = kept
		return nil
	}

	if len(op.Value) > 0 {
		targets, err := parseMemberValue(op.Value)
		if err != nil {
			return err
		}
		kept := group.Members[:0:0]
		for _, member := range group.Members {
			var drop bool
			for _, target := range targets {
				if strings.EqualFold(member.Value, target.Value) {
					drop = true
					break
				}
			}
			if !drop {
				kept = append(kept, member)
			}
		}
		group.Members = kept
		return nil
	}

	group.Members = nil
	return nil
}

// parseMemberValue accepts either an array of members or a single member
// object, since providers send both.
func parseMemberValue(raw json.RawMessage) ([]MemberRef, error) {
	if len(raw) == 0 {
		return nil, NewError("400", "invalidValue", "members requires a value")
	}

	var members []MemberRef
	if err := json.Unmarshal(raw, &members); err == nil {
		return members, nil
	}

	var single MemberRef
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, NewError("400", "invalidValue", "members must be an object or an array of objects")
	}
	return []MemberRef{single}, nil
}

// memberAsMultiValued lets a member reuse the value-filter matching the rest
// of the package already implements, rather than growing a second copy of it
// that could disagree.
func memberAsMultiValued(m MemberRef) MultiValued {
	return MultiValued{
		Value:   m.Value,
		Display: m.Display,
		Type:    m.Type,
		Ref:     m.Ref,
	}
}
