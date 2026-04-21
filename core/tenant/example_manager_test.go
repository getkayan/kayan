package tenant

import (
	"context"
	"fmt"
)

func ExampleManager_Resolve() {
	store := newMockStore()
	store.tenants["acme"] = &Tenant{ID: "acme", Name: "Acme Corp", Active: true}

	manager := NewManager(store, NewHeaderResolver("X-Tenant-ID"))
	info := ResolveInfo{
		Headers: map[string][]string{
			"X-Tenant-ID": {"acme"},
		},
	}

	tenant, ctx, err := manager.Resolve(context.Background(), info)
	if err != nil {
		fmt.Println("resolve error:", err)
		return
	}

	fmt.Println(tenant.ID)
	fmt.Println(IDFromContext(ctx))
	// Output:
	// acme
	// acme
}
