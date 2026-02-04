package kgorm

import (
	"context"

	"github.com/getkayan/kayan/core/rebac"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ReBACRepository implements rebac.Store using GORM.
// It provides persistent storage for relationship tuples.
type ReBACRepository struct {
	db *gorm.DB
}

// NewReBACRepository creates a new ReBAC repository.
func NewReBACRepository(db *gorm.DB) *ReBACRepository {
	return &ReBACRepository{db: db}
}

// AutoMigrate creates the necessary tables for ReBAC.
func (r *ReBACRepository) AutoMigrate() error {
	return r.db.AutoMigrate(&gormRelationTuple{})
}

// WriteTuple creates or updates a relationship tuple.
func (r *ReBACRepository) WriteTuple(ctx context.Context, tuple rebac.Tuple) error {
	id := generateTupleID(tuple)
	gt := fromCoreRelationTuple(tuple, id)

	// Use upsert to handle duplicates gracefully
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).Create(gt).Error
}

// WriteTuples creates multiple tuples atomically.
func (r *ReBACRepository) WriteTuples(ctx context.Context, tuples []rebac.Tuple) error {
	if len(tuples) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, tuple := range tuples {
			id := generateTupleID(tuple)
			gt := fromCoreRelationTuple(tuple, id)

			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "id"}},
				DoNothing: true,
			}).Create(gt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteTuple removes a specific relationship tuple.
func (r *ReBACRepository) DeleteTuple(ctx context.Context, tuple rebac.Tuple) error {
	id := generateTupleID(tuple)
	return r.db.WithContext(ctx).Delete(&gormRelationTuple{}, "id = ?", id).Error
}

// DeleteTuples removes all tuples matching the filter.
func (r *ReBACRepository) DeleteTuples(ctx context.Context, filter rebac.TupleFilter) error {
	query := r.db.WithContext(ctx)
	query = r.applyFilter(query, filter)
	return query.Delete(&gormRelationTuple{}).Error
}

// ReadTuples returns all tuples matching the filter.
func (r *ReBACRepository) ReadTuples(ctx context.Context, filter rebac.TupleFilter) ([]rebac.Tuple, error) {
	query := r.db.WithContext(ctx)
	query = r.applyFilter(query, filter)

	var tuples []gormRelationTuple
	if err := query.Find(&tuples).Error; err != nil {
		return nil, err
	}

	result := make([]rebac.Tuple, len(tuples))
	for i, gt := range tuples {
		result[i] = toCoreRelationTuple(&gt)
	}

	return result, nil
}

// TupleExists checks if a specific tuple exists.
func (r *ReBACRepository) TupleExists(ctx context.Context, tuple rebac.Tuple) (bool, error) {
	id := generateTupleID(tuple)

	var count int64
	if err := r.db.WithContext(ctx).Model(&gormRelationTuple{}).Where("id = ?", id).Count(&count).Error; err != nil {
		return false, err
	}

	return count > 0, nil
}

// applyFilter adds WHERE clauses based on the filter.
func (r *ReBACRepository) applyFilter(query *gorm.DB, filter rebac.TupleFilter) *gorm.DB {
	if filter.SubjectType != "" {
		query = query.Where("subject_type = ?", filter.SubjectType)
	}
	if filter.SubjectID != "" {
		query = query.Where("subject_id = ?", filter.SubjectID)
	}
	if filter.SubjectRelation != "" {
		query = query.Where("subject_relation = ?", filter.SubjectRelation)
	}
	if filter.Relation != "" {
		query = query.Where("relation = ?", filter.Relation)
	}
	if filter.ObjectType != "" {
		query = query.Where("object_type = ?", filter.ObjectType)
	}
	if filter.ObjectID != "" {
		query = query.Where("object_id = ?", filter.ObjectID)
	}
	return query
}

// Compile-time interface check
var _ rebac.Store = (*ReBACRepository)(nil)
