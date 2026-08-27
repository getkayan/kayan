package scim

import (
	"encoding/json"
	"testing"
)

// Group membership is pushed by identity providers as PATCH /Groups/{id} with
// add or remove operations on "members". It is the most common provisioning
// operation in production -- every time somebody joins or leaves a team, this
// is the request -- and ApplyPatch accepted only *User, so it could not be
// served at all.
//
// The payloads below are the shapes Okta and Microsoft Entra actually send,
// rather than what the RFC's examples suggest, because the two differ in ways
// that matter: Entra omits "path" and puts the attribute in the value object,
// and Okta sends a remove with the filter in the path.

func groupWith(members ...string) *Group {
	g := &Group{DisplayName: "Engineering"}
	g.ID = "group-1"
	for _, m := range members {
		g.Members = append(g.Members, MemberRef{Value: m, Type: "User"})
	}
	return g
}

func memberValues(g *Group) []string {
	out := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, m.Value)
	}
	return out
}

func equalValues(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestApplyGroupPatchAddsMembers covers the Okta add: a path of "members" and
// an array value.
func TestApplyGroupPatchAddsMembers(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpAdd,
		Path:  "members",
		Value: json.RawMessage(`[{"value":"user-2","display":"Bob"}]`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-1", "user-2"}) {
		t.Errorf("members = %v, want [user-1 user-2]", memberValues(got))
	}
}

// TestApplyGroupPatchAddIsIdempotent keeps a replayed provisioning request
// from duplicating a membership. Identity providers retry, and a group that
// lists the same user twice breaks any consumer counting members.
func TestApplyGroupPatchAddIsIdempotent(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpAdd,
		Path:  "members",
		Value: json.RawMessage(`[{"value":"user-1"}]`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-1"}) {
		t.Errorf("members = %v, want [user-1]: a repeated add duplicated the membership",
			memberValues(got))
	}
}

// TestApplyGroupPatchRemovesByFilter covers the Okta remove, where the member
// to drop is named by a value filter in the path.
func TestApplyGroupPatchRemovesByFilter(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:   PatchOpRemove,
		Path: `members[value eq "user-2"]`,
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1", "user-2", "user-3"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-1", "user-3"}) {
		t.Errorf("members = %v, want [user-1 user-3]", memberValues(got))
	}
}

// TestApplyGroupPatchRemoveWithNoPathValue covers Entra's remove, which sends
// the members to drop as the operation's value rather than as a path filter.
func TestApplyGroupPatchRemoveWithValue(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpRemove,
		Path:  "members",
		Value: json.RawMessage(`[{"value":"user-2"}]`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1", "user-2"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-1"}) {
		t.Errorf("members = %v, want [user-1]", memberValues(got))
	}
}

// TestApplyGroupPatchRemoveAllMembers covers a remove with no value and no
// filter, which clears the attribute.
func TestApplyGroupPatchRemoveAllMembers(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{Op: PatchOpRemove, Path: "members"}}}

	got, err := ApplyGroupPatch(groupWith("user-1", "user-2"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if len(got.Members) != 0 {
		t.Errorf("members = %v, want empty", memberValues(got))
	}
}

// TestApplyGroupPatchReplaceMembers covers a full membership replacement,
// which is how some providers reconcile rather than sending deltas.
func TestApplyGroupPatchReplaceMembers(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpReplace,
		Path:  "members",
		Value: json.RawMessage(`[{"value":"user-9"}]`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1", "user-2"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-9"}) {
		t.Errorf("members = %v, want [user-9]", memberValues(got))
	}
}

// TestApplyGroupPatchRenamesTheGroup covers the other attribute a provider
// actually patches.
func TestApplyGroupPatchRenamesTheGroup(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpReplace,
		Path:  "displayName",
		Value: json.RawMessage(`"Platform"`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if got.DisplayName != "Platform" {
		t.Errorf("DisplayName = %q, want Platform", got.DisplayName)
	}
	if !equalValues(memberValues(got), []string{"user-1"}) {
		t.Error("renaming the group changed its membership")
	}
}

// TestApplyGroupPatchEntraPathlessOperation covers Microsoft Entra's shape:
// no path, with the attribute named inside the value object.
func TestApplyGroupPatchEntraPathlessOperation(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpAdd,
		Value: json.RawMessage(`{"members":[{"value":"user-2"}]}`),
	}}}

	got, err := ApplyGroupPatch(groupWith("user-1"), patch)
	if err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(got), []string{"user-1", "user-2"}) {
		t.Errorf("members = %v, want [user-1 user-2]", memberValues(got))
	}
}

// TestApplyGroupPatchRefusesReadOnlyAttributes keeps PATCH from rewriting
// server-controlled fields. Silently dropping them would be worse: the client
// would believe the change applied.
func TestApplyGroupPatchRefusesReadOnlyAttributes(t *testing.T) {
	for _, attr := range []string{"id", "meta", "schemas"} {
		t.Run(attr, func(t *testing.T) {
			patch := &PatchOp{Operations: []PatchOperation{{
				Op: PatchOpReplace, Path: attr, Value: json.RawMessage(`"anything"`),
			}}}
			if _, err := ApplyGroupPatch(groupWith("user-1"), patch); err == nil {
				t.Errorf("PATCH modified the read-only attribute %q", attr)
			}
		})
	}
}

// TestApplyGroupPatchDoesNotMutateTheInput matches ApplyPatch's contract. A
// handler that returns an error after mutating in place leaves the caller
// holding a half-applied group.
func TestApplyGroupPatchDoesNotMutateTheInput(t *testing.T) {
	// A removal is the case that exposes a shared backing array: it filters
	// in place, so without a copy the caller's slice is rewritten under them.
	// An add would not catch this -- append reallocates and the original
	// survives by luck, which is exactly the kind of test that passes whether
	// or not the code is correct.
	original := groupWith("user-1", "user-2", "user-3")
	patch := &PatchOp{Operations: []PatchOperation{{
		Op:   PatchOpRemove,
		Path: `members[value eq "user-2"]`,
	}}}

	if _, err := ApplyGroupPatch(original, patch); err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(original), []string{"user-1", "user-2", "user-3"}) {
		t.Errorf("the input group was mutated: %v", memberValues(original))
	}

	// The add path must leave the input alone too.
	added := groupWith("user-1")
	addPatch := &PatchOp{Operations: []PatchOperation{{
		Op:    PatchOpAdd,
		Path:  "members",
		Value: json.RawMessage(`[{"value":"user-2"}]`),
	}}}
	if _, err := ApplyGroupPatch(added, addPatch); err != nil {
		t.Fatalf("ApplyGroupPatch: %v", err)
	}
	if !equalValues(memberValues(added), []string{"user-1"}) {
		t.Errorf("the input group was mutated by an add: %v", memberValues(added))
	}
}

// TestApplyGroupPatchRejectsUnknownAttributes keeps a typo from being accepted
// as a successful no-op, which would leave a provider believing it had synced.
func TestApplyGroupPatchRejectsUnknownAttributes(t *testing.T) {
	patch := &PatchOp{Operations: []PatchOperation{{
		Op: PatchOpReplace, Path: "memburs", Value: json.RawMessage(`[]`),
	}}}
	if _, err := ApplyGroupPatch(groupWith("user-1"), patch); err == nil {
		t.Error("an unknown attribute was accepted")
	}
}

// TestApplyGroupPatchValidatesArguments covers the degenerate inputs a handler
// can produce from a malformed request body.
func TestApplyGroupPatchValidatesArguments(t *testing.T) {
	if _, err := ApplyGroupPatch(nil, &PatchOp{}); err == nil {
		t.Error("a nil group was accepted")
	}
	if _, err := ApplyGroupPatch(groupWith(), nil); err == nil {
		t.Error("a nil patch was accepted")
	}
}
