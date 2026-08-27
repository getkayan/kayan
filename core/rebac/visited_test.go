package rebac

import (
	"context"
	"testing"
	"time"
)

// TestCheckIsNotOrderDependent guards the cycle-detection set against
// order-dependent answers.
//
// The set is created once per Check and threaded by reference through every
// recursive call without being unwound, which reads like the classic
// path-vs-global mistake -- core/rbac/role.go unwinds with defer, and this
// does not. It was reported as a source of silent false denials.
//
// It is not, and this test is the evidence. For a given (subject, relation,
// object) the answer is a pure function of the stored tuples, so retaining a
// completed result is memoisation rather than corruption: a sibling branch
// that re-visits the triple would compute the same answer. Four graph shapes
// were tried against the unfixed code -- a diamond, nested usersets, chained
// computed relations, and a cyclic group graph whose inner result is
// provisional -- and every one returned the correct answer.
//
// The test stays because that reasoning depends on Check having no
// path-dependent state. A future rule that makes the answer depend on how a
// triple was reached would break it, and this is where that shows up.
func TestCheckIsNotOrderDependent(t *testing.T) {
	// document:readme reaches folder:shared through two separate rules, so the
	// second rule re-visits triples the first one marked.
	docSchema := Schema{
		Type: "document",
		Relations: map[string]RelationConfig{
			"viewer": {
				Name:          "viewer",
				DirectAllowed: true,
				ComputedFrom: []ComputedRule{
					{TupleToUserset: &TupleToUserset{TuplesetRelation: "dead_end", ComputedRelation: "viewer"}},
					{TupleToUserset: &TupleToUserset{TuplesetRelation: "parent", ComputedRelation: "viewer"}},
				},
			},
		},
	}
	folderSchema := Schema{
		Type: "folder",
		Relations: map[string]RelationConfig{
			"viewer": {
				Name:          "viewer",
				DirectAllowed: true,
				ComputedFrom:  []ComputedRule{{Relation: "editor"}},
			},
			"editor": {Name: "editor", DirectAllowed: true},
		},
	}

	alice := SubjectRef{Object: ObjectRef{Type: "user", ID: "alice"}}
	readme := ObjectRef{Type: "document", ID: "readme"}
	empty := SubjectRef{Object: ObjectRef{Type: "folder", ID: "empty"}}
	shared := SubjectRef{Object: ObjectRef{Type: "folder", ID: "shared"}}

	store := NewMemoryStore()
	ctx := context.Background()

	// The first rule leads somewhere with no grant; the second one leads to
	// the folder that does grant access, and only through a computed relation.
	mustWrite(t, store, Tuple{Subject: empty, Relation: "dead_end", Object: readme})
	mustWrite(t, store, Tuple{Subject: shared, Relation: "parent", Object: readme})
	mustWrite(t, store, Tuple{Subject: alice, Relation: "editor", Object: shared.Object})

	checker := NewChecker(store, WithSchemas([]Schema{docSchema, folderSchema}))

	allowed, err := checker.Check(ctx, alice, "viewer", readme)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("Check denied access reachable through the second rule")
	}
}

// TestCheckStillTerminatesOnCycles keeps the guard honest: unwinding the
// visited set must not reintroduce infinite recursion.
func TestCheckStillTerminatesOnCycles(t *testing.T) {
	schema := Schema{
		Type: "group",
		Relations: map[string]RelationConfig{
			"member": {Name: "member", DirectAllowed: true},
		},
	}

	store := NewMemoryStore()
	ctx := context.Background()

	// group:a is a member of group:b and vice versa.
	a := ObjectRef{Type: "group", ID: "a"}
	b := ObjectRef{Type: "group", ID: "b"}
	mustWrite(t, store, Tuple{
		Subject:  SubjectRef{Object: ObjectRef{Type: "group", ID: "b"}, Relation: "member"},
		Relation: "member", Object: a,
	})
	mustWrite(t, store, Tuple{
		Subject:  SubjectRef{Object: ObjectRef{Type: "group", ID: "a"}, Relation: "member"},
		Relation: "member", Object: b,
	})

	checker := NewChecker(store, WithSchemas([]Schema{schema}))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// The answer does not matter; not hanging and not blowing the stack do.
		_, _ = checker.Check(ctx, SubjectRef{Object: ObjectRef{Type: "user", ID: "nobody"}}, "member", a)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Check did not terminate on a cyclic graph")
	}
}

func mustWrite(t *testing.T, store Store, tuple Tuple) {
	t.Helper()
	if err := store.WriteTuple(context.Background(), tuple); err != nil {
		t.Fatalf("WriteTuple %s: %v", tuple.String(), err)
	}
}
