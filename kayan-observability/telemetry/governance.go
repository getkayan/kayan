package telemetry

import (
	"context"
	"errors"

	"github.com/getkayan/kayan/core/tenant"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// TenantGovernorHooks connects a tenant.Governor to OpenTelemetry metrics.
// Tenant and operation labels are intentionally included for usage and
// noisy-neighbor diagnosis. Deployments with an unbounded tenant population
// should aggregate or drop the tenant attribute in their collector.
func (p *Provider) TenantGovernorHooks() tenant.GovernorHooks {
	if p == nil || !p.config.Enabled {
		return tenant.GovernorHooks{}
	}
	return tenant.GovernorHooks{
		OnDecision: p.recordGovernanceDecision,
		OnRelease:  p.recordGovernanceRelease,
	}
}

func (p *Provider) recordGovernanceDecision(ctx context.Context, decision tenant.GovernanceDecision) {
	if p.governanceDecisions == nil {
		return
	}
	outcome := "allowed"
	if !decision.Allowed {
		outcome = "error"
		if errors.Is(decision.Err, tenant.ErrRateLimitExceeded) ||
			errors.Is(decision.Err, tenant.ErrConcurrencyExceeded) {
			outcome = "limited"
		}
	}
	attributes := governanceAttributes(decision.TenantID, decision.Operation)
	attributes = append(attributes,
		attribute.String("scope", string(decision.Scope)),
		attribute.String("kind", string(decision.Kind)),
		attribute.String("outcome", outcome),
	)
	p.governanceDecisions.Add(ctx, 1, metric.WithAttributes(attributes...))
	if decision.Allowed && p.governanceInFlight != nil {
		p.governanceInFlight.Add(ctx, 1, metric.WithAttributes(governanceAttributes(decision.TenantID, decision.Operation)...))
	}
}

func (p *Provider) recordGovernanceRelease(ctx context.Context, usage tenant.GovernanceUsage) {
	attributes := governanceAttributes(usage.TenantID, usage.Operation)
	if p.governanceInFlight != nil {
		p.governanceInFlight.Add(ctx, -1, metric.WithAttributes(attributes...))
	}
	if p.governanceDuration != nil {
		p.governanceDuration.Record(ctx, usage.Duration.Seconds(), metric.WithAttributes(attributes...))
	}
}

func governanceAttributes(tenantID, operation string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("tenant", tenantID),
		attribute.String("operation", operation),
	}
}
