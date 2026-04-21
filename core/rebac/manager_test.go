package rebac

import (
	"context"
	"testing"
)

func TestManager_Grant(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	if err := mgr.Grant(ctx, "user", "alice", "viewer", "document", "1"); err != nil {
		t.Fatalf("Grant failed: %v", err)
	}

	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !ok {
		t.Error("expected Check to return true after Grant")
	}
}

func TestManager_Revoke(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.Grant(ctx, "user", "alice", "viewer", "document", "1")
	mgr.Revoke(ctx, "user", "alice", "viewer", "document", "1")

	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected Check to return false after Revoke")
	}
}

func TestManager_Check_NoRelation(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected Check to return false for nonexistent relation")
	}
}

func TestManager_ListObjects(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.Grant(ctx, "user", "alice", "viewer", "document", "1")
	mgr.Grant(ctx, "user", "alice", "viewer", "document", "2")
	mgr.Grant(ctx, "user", "alice", "editor", "document", "3")

	objects, err := mgr.ListObjects(ctx, "user", "alice", "viewer", "document")
	if err != nil {
		t.Fatalf("ListObjects failed: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %d", len(objects))
	}

	ids := map[string]bool{}
	for _, o := range objects {
		ids[o.ID] = true
	}
	if !ids["1"] || !ids["2"] {
		t.Errorf("expected objects 1 and 2, got %v", objects)
	}
}

func TestManager_ListSubjects(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.Grant(ctx, "user", "alice", "viewer", "document", "1")
	mgr.Grant(ctx, "user", "bob", "viewer", "document", "1")

	subjects, err := mgr.ListSubjects(ctx, "viewer", "document", "1")
	if err != nil {
		t.Fatalf("ListSubjects failed: %v", err)
	}
	if len(subjects) != 2 {
		t.Fatalf("expected 2 subjects, got %d", len(subjects))
	}
}

func TestManager_AddToGroup_RemoveFromGroup(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	if err := mgr.AddToGroup(ctx, "alice", "engineering"); err != nil {
		t.Fatalf("AddToGroup failed: %v", err)
	}

	ok, err := mgr.Check(ctx, "user", "alice", "member", "group", "engineering")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !ok {
		t.Error("expected alice to be member of engineering")
	}

	if err := mgr.RemoveFromGroup(ctx, "alice", "engineering"); err != nil {
		t.Fatalf("RemoveFromGroup failed: %v", err)
	}

	ok, err = mgr.Check(ctx, "user", "alice", "member", "group", "engineering")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected alice to no longer be member after RemoveFromGroup")
	}
}

func TestManager_SetParent_GetParent(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	if err := mgr.SetParent(ctx, "folder", "home", "document", "1"); err != nil {
		t.Fatalf("SetParent failed: %v", err)
	}

	parent, err := mgr.GetParent(ctx, "document", "1")
	if err != nil {
		t.Fatalf("GetParent failed: %v", err)
	}
	if parent == nil {
		t.Fatal("expected parent, got nil")
	}
	if parent.Type != "folder" || parent.ID != "home" {
		t.Errorf("expected folder:home, got %s:%s", parent.Type, parent.ID)
	}

	// No parent case
	parent2, err := mgr.GetParent(ctx, "document", "999")
	if err != nil {
		t.Fatalf("GetParent failed: %v", err)
	}
	if parent2 != nil {
		t.Errorf("expected nil parent for unknown document, got %v", parent2)
	}
}

func TestManager_GrantUserset(t *testing.T) {
	store := NewMemoryStore()
	// Schema: document viewer can be computed from group membership
	mgr := NewManager(store, WithSchema(Schema{
		Type: "document",
		Relations: map[string]RelationConfig{
			"viewer": {DirectAllowed: true},
		},
	}))
	ctx := context.Background()

	// Grant: all members of group:engineering are viewers of document:1
	if err := mgr.GrantUserset(ctx, "group", "engineering", "member", "viewer", "document", "1"); err != nil {
		t.Fatalf("GrantUserset failed: %v", err)
	}

	// Make alice a member of engineering
	if err := mgr.AddToGroup(ctx, "alice", "engineering"); err != nil {
		t.Fatalf("AddToGroup failed: %v", err)
	}

	// alice should now be a viewer of document:1 via group membership
	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !ok {
		t.Error("expected alice to be viewer of document:1 via group membership")
	}

	// bob is NOT a member, should not have access
	ok, err = mgr.Check(ctx, "user", "bob", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected bob to NOT be viewer of document:1")
	}
}

func TestManager_RequirePermission(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.Grant(ctx, "user", "alice", "viewer", "document", "1")

	// Allowed
	err := mgr.RequirePermission(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Errorf("expected nil error for allowed permission, got %v", err)
	}

	// Denied
	err = mgr.RequirePermission(ctx, "user", "bob", "viewer", "document", "1")
	if err == nil {
		t.Error("expected error for denied permission")
	}
}

func TestManager_ComputedRelation(t *testing.T) {
	store := NewMemoryStore()
	// Schema: document editors automatically become viewers
	mgr := NewManager(store, WithSchema(Schema{
		Type: "document",
		Relations: map[string]RelationConfig{
			"editor": {DirectAllowed: true},
			"viewer": {
				DirectAllowed: true,
				ComputedFrom: []ComputedRule{
					{Relation: "editor"},
				},
			},
		},
	}))
	ctx := context.Background()

	// Grant alice editor on document:1
	mgr.Grant(ctx, "user", "alice", "editor", "document", "1")

	// alice should also be a viewer (computed from editor)
	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !ok {
		t.Error("expected editor to imply viewer via computed relation")
	}
}

func TestManager_TupleToUserset(t *testing.T) {
	store := NewMemoryStore()
	// Schema: document viewer inherits from parent folder's viewer
	mgr := NewManager(store, WithSchema(Schema{
		Type: "document",
		Relations: map[string]RelationConfig{
			"parent": {DirectAllowed: true},
			"viewer": {
				DirectAllowed: true,
				ComputedFrom: []ComputedRule{
					{TupleToUserset: &TupleToUserset{
						TuplesetRelation: "parent",
						ComputedRelation: "viewer",
					}},
				},
			},
		},
	}))
	ctx := context.Background()

	// folder:home has alice as viewer
	mgr.Grant(ctx, "user", "alice", "viewer", "folder", "home")

	// document:1's parent is folder:home
	mgr.SetParent(ctx, "folder", "home", "document", "1")

	// alice should be viewer of document:1 via parent folder
	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !ok {
		t.Error("expected viewer to be inherited from parent folder via tuple-to-userset")
	}

	// bob should not
	ok, err = mgr.Check(ctx, "user", "bob", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected bob to NOT be viewer of document:1")
	}
}

func TestManager_RevokeUserset(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store)
	ctx := context.Background()

	mgr.GrantUserset(ctx, "group", "eng", "member", "viewer", "document", "1")
	mgr.RevokeUserset(ctx, "group", "eng", "member", "viewer", "document", "1")

	// Even if alice is a member of eng, no userset tuple should exist
	mgr.AddToGroup(ctx, "alice", "eng")
	ok, err := mgr.Check(ctx, "user", "alice", "viewer", "document", "1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if ok {
		t.Error("expected Check to return false after RevokeUserset")
	}
}
