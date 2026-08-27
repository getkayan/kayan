package gormstore

import (
	"testing"

	"github.com/getkayan/kayan/core/domain"
	kayantesting "github.com/getkayan/kayan/kayan-testing"
)

func TestStorageContract(t *testing.T) {
	kayantesting.StorageSuiteWithModel(t, func() domain.Storage {
		repo := NewRepository(setupSQLiteDB(t))
		if err := repo.AutoMigrateDev(&kayantesting.SuiteIdentity{}); err != nil {
			t.Fatalf("migrate storage contract schema: %v", err)
		}
		return repo
	}, func() any { return &kayantesting.SuiteIdentity{} })
}
