// Package rebac implements Relationship-Based Access Control (ReBAC).
//
// ReBAC is an authorization model where permissions are derived from
// relationships between entities. This package provides:
//   - Core types for representing relationship tuples
//   - Storage interface for persisting relations
//   - Permission checker with graph traversal
//   - High-level manager for application use
//
// The design is inspired by Google Zanzibar and similar systems.
package rebac

// ObjectRef represents a typed reference to an object.
// Examples: "document:123", "folder:home", "user:alice"
type ObjectRef struct {
	Type string // The object type (e.g., "document", "folder", "user")
	ID   string // The object identifier
}

// String returns the canonical string representation: "type:id"
func (o ObjectRef) String() string {
	return o.Type + ":" + o.ID
}

// SubjectRef represents a subject in a relationship tuple.
// A subject can be:
//   - A direct object reference: user:alice
//   - A userset reference: group:engineering#member (all members of a group)
type SubjectRef struct {
	Object   ObjectRef
	Relation string // Optional: for usersets like "group:eng#member"
}

// String returns the canonical string representation.
// Direct: "user:alice", Userset: "group:engineering#member"
func (s SubjectRef) String() string {
	if s.Relation == "" {
		return s.Object.String()
	}
	return s.Object.String() + "#" + s.Relation
}

// IsUserset returns true if this subject reference is a userset.
func (s SubjectRef) IsUserset() bool {
	return s.Relation != ""
}

// Tuple represents a relationship tuple: (subject, relation, object).
// This is the fundamental unit of authorization data in ReBAC.
//
// Examples:
//   - user:alice#viewer@document:123 (Alice is a viewer of document 123)
//   - group:eng#member@user:bob (Bob is a member of the engineering group)
//   - document:123#parent@folder:home (Document 123's parent is folder home)
type Tuple struct {
	Subject  SubjectRef
	Relation string
	Object   ObjectRef
}

// String returns the canonical tuple representation: "subject#relation@object"
func (t Tuple) String() string {
	return t.Subject.String() + "#" + t.Relation + "@" + t.Object.String()
}

// RelationConfig defines how a relation can be computed for a schema.
// Relations can be:
//   - Direct: Users can be directly assigned the relation
//   - Computed: Derived from other relations (union)
type RelationConfig struct {
	Name          string         // Relation name (e.g., "viewer", "editor", "owner")
	DirectAllowed bool           // Can subjects be directly assigned this relation?
	ComputedFrom  []ComputedRule // Optional: union of computed relations
}

// ComputedRule defines a way to compute a relation from existing data.
// It can be:
//   - A direct relation inheritance: owners automatically become editors
//   - A tuple-to-userset: inherit from parent's viewers
type ComputedRule struct {
	// Relation specifies direct inheritance.
	// Example: "owner" means anyone with "owner" relation also has this relation.
	Relation string

	// TupleToUserset specifies indirect inheritance through another relation.
	// Example: Follow document's "parent" relation, then check folder's "viewer".
	TupleToUserset *TupleToUserset
}

// TupleToUserset enables "follow the pointer" inheritance.
// For example, a document's viewers can inherit from its parent folder's viewers:
//
//	TupleToUserset{
//	    TuplesetRelation: "parent",   // Follow the "parent" relation
//	    ComputedRelation: "viewer",   // Then check for "viewer" on that object
//	}
type TupleToUserset struct {
	TuplesetRelation string // The relation to follow (e.g., "parent")
	ComputedRelation string // The relation to check on the target (e.g., "viewer")
}

// Schema defines the authorization model for an object type.
// It specifies what relations are valid and how they can be computed.
type Schema struct {
	Type      string                    // Object type this schema applies to
	Relations map[string]RelationConfig // Relation name -> config
}

// TupleFilter specifies criteria for querying tuples.
// All non-empty fields are ANDed together.
type TupleFilter struct {
	SubjectType     string // Filter by subject type
	SubjectID       string // Filter by subject ID
	SubjectRelation string // Filter by subject relation (for usersets)
	Relation        string // Filter by tuple relation
	ObjectType      string // Filter by object type
	ObjectID        string // Filter by object ID
}

// Matches returns true if the tuple matches the filter.
func (f TupleFilter) Matches(t Tuple) bool {
	if f.SubjectType != "" && t.Subject.Object.Type != f.SubjectType {
		return false
	}
	if f.SubjectID != "" && t.Subject.Object.ID != f.SubjectID {
		return false
	}
	if f.SubjectRelation != "" && t.Subject.Relation != f.SubjectRelation {
		return false
	}
	if f.Relation != "" && t.Relation != f.Relation {
		return false
	}
	if f.ObjectType != "" && t.Object.Type != f.ObjectType {
		return false
	}
	if f.ObjectID != "" && t.Object.ID != f.ObjectID {
		return false
	}
	return true
}

// Helper constructors for common patterns

// NewObjectRef creates a new ObjectRef.
func NewObjectRef(objectType, id string) ObjectRef {
	return ObjectRef{Type: objectType, ID: id}
}

// NewSubjectRef creates a direct subject reference (not a userset).
func NewSubjectRef(subjectType, id string) SubjectRef {
	return SubjectRef{
		Object: ObjectRef{Type: subjectType, ID: id},
	}
}

// NewUsersetRef creates a userset subject reference.
func NewUsersetRef(objectType, id, relation string) SubjectRef {
	return SubjectRef{
		Object:   ObjectRef{Type: objectType, ID: id},
		Relation: relation,
	}
}

// NewTuple creates a new relationship tuple.
func NewTuple(subjectType, subjectID, relation, objectType, objectID string) Tuple {
	return Tuple{
		Subject:  NewSubjectRef(subjectType, subjectID),
		Relation: relation,
		Object:   NewObjectRef(objectType, objectID),
	}
}

// NewUsersetTuple creates a tuple with a userset subject.
func NewUsersetTuple(subjectType, subjectID, subjectRelation, relation, objectType, objectID string) Tuple {
	return Tuple{
		Subject:  NewUsersetRef(subjectType, subjectID, subjectRelation),
		Relation: relation,
		Object:   NewObjectRef(objectType, objectID),
	}
}
