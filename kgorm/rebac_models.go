package kgorm

import (
	"time"

	"github.com/getkayan/kayan/core/rebac"
)

// gormRelationTuple stores relationship tuples in the database.
// The table is optimized for ReBAC query patterns with composite indexes.
type gormRelationTuple struct {
	ID              string    `gorm:"primaryKey"`
	SubjectType     string    `gorm:"size:64;index:idx_subject,priority:1;index:idx_full,priority:1"`
	SubjectID       string    `gorm:"size:255;index:idx_subject,priority:2;index:idx_full,priority:2"`
	SubjectRelation string    `gorm:"size:64;index:idx_full,priority:3"`
	Relation        string    `gorm:"size:64;index:idx_relation,priority:1;index:idx_full,priority:4"`
	ObjectType      string    `gorm:"size:64;index:idx_object,priority:1;index:idx_full,priority:5"`
	ObjectID        string    `gorm:"size:255;index:idx_object,priority:2;index:idx_full,priority:6"`
	CreatedAt       time.Time `gorm:"autoCreateTime"`
}

// TableName returns the table name for GORM.
func (gormRelationTuple) TableName() string {
	return "rebac_relation_tuples"
}

// toCoreRelationTuple converts a GORM model to the core domain type.
func toCoreRelationTuple(gt *gormRelationTuple) rebac.Tuple {
	return rebac.Tuple{
		Subject: rebac.SubjectRef{
			Object: rebac.ObjectRef{
				Type: gt.SubjectType,
				ID:   gt.SubjectID,
			},
			Relation: gt.SubjectRelation,
		},
		Relation: gt.Relation,
		Object: rebac.ObjectRef{
			Type: gt.ObjectType,
			ID:   gt.ObjectID,
		},
	}
}

// fromCoreRelationTuple converts a core domain type to a GORM model.
func fromCoreRelationTuple(t rebac.Tuple, id string) *gormRelationTuple {
	return &gormRelationTuple{
		ID:              id,
		SubjectType:     t.Subject.Object.Type,
		SubjectID:       t.Subject.Object.ID,
		SubjectRelation: t.Subject.Relation,
		Relation:        t.Relation,
		ObjectType:      t.Object.Type,
		ObjectID:        t.Object.ID,
	}
}

// generateTupleID creates a unique identifier for a tuple based on its content.
// This ensures the same tuple can't be inserted twice.
func generateTupleID(t rebac.Tuple) string {
	return t.String()
}
