package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/tenant"
)

func TestTenantGovernorHooksSupportEnabledAndDisabledProviders(t *testing.T) {
	providers := []*Provider{nil, {config: Config{Enabled: false}}}
	for _, provider := range providers {
		hooks := provider.TenantGovernorHooks()
		if hooks.OnDecision != nil || hooks.OnRelease != nil {
			t.Fatal("nil or disabled provider returned active hooks")
		}
	}

	provider, err := NewProvider(Config{ServiceName: "governance-test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	hooks := provider.TenantGovernorHooks()
	if hooks.OnDecision == nil || hooks.OnRelease == nil {
		t.Fatal("enabled provider returned incomplete hooks")
	}
	hooks.OnDecision(context.Background(), tenant.GovernanceDecision{
		TenantID: "tenant-a", Operation: "reports.export", Scope: tenant.GovernanceScopeTenant,
		Kind: tenant.GovernanceKindConcurrency, Allowed: true,
	})
	hooks.OnRelease(context.Background(), tenant.GovernanceUsage{
		TenantID: "tenant-a", Operation: "reports.export", Duration: time.Second,
	})
}
