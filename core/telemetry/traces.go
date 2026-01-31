package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Common span attribute keys
const (
	AttrIdentityID = "kayan.identity.id"
	AttrTenantID   = "kayan.tenant.id"
	AttrStrategy   = "kayan.auth.strategy"
	AttrSessionID  = "kayan.session.id"
	AttrIPAddress  = "kayan.client.ip"
	AttrUserAgent  = "kayan.client.user_agent"
)

// SpanOptions provides configuration for span creation.
type SpanOptions struct {
	TenantID   string
	IdentityID string
	Strategy   string
	SessionID  string
	IPAddress  string
	UserAgent  string
}

// StartSpan starts a new span with common Kayan attributes.
func (p *Provider) StartSpan(ctx context.Context, name string, opts SpanOptions) (context.Context, trace.Span) {
	tracer := p.Tracer()
	if tracer == nil {
		return ctx, nil
	}

	attrs := []attribute.KeyValue{}

	if opts.TenantID != "" {
		attrs = append(attrs, attribute.String(AttrTenantID, opts.TenantID))
	}
	if opts.IdentityID != "" {
		attrs = append(attrs, attribute.String(AttrIdentityID, opts.IdentityID))
	}
	if opts.Strategy != "" {
		attrs = append(attrs, attribute.String(AttrStrategy, opts.Strategy))
	}
	if opts.SessionID != "" {
		attrs = append(attrs, attribute.String(AttrSessionID, opts.SessionID))
	}
	if opts.IPAddress != "" {
		attrs = append(attrs, attribute.String(AttrIPAddress, opts.IPAddress))
	}
	if opts.UserAgent != "" {
		attrs = append(attrs, attribute.String(AttrUserAgent, opts.UserAgent))
	}

	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// ---- Authentication Flow Spans ----

// SpanLogin starts a span for login operations.
func (p *Provider) SpanLogin(ctx context.Context, identifier, strategy string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.login", SpanOptions{
		IdentityID: identifier,
		Strategy:   strategy,
	})
}

// SpanRegistration starts a span for registration operations.
func (p *Provider) SpanRegistration(ctx context.Context, strategy string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.registration", SpanOptions{
		Strategy: strategy,
	})
}

// SpanMFA starts a span for MFA operations.
func (p *Provider) SpanMFA(ctx context.Context, mfaType, identityID string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.mfa."+mfaType, SpanOptions{
		IdentityID: identityID,
		Strategy:   mfaType,
	})
}

// SpanOIDC starts a span for OIDC operations.
func (p *Provider) SpanOIDC(ctx context.Context, provider string) (context.Context, trace.Span) {
	ctx, span := p.StartSpan(ctx, "kayan.oidc", SpanOptions{
		Strategy: "oidc",
	})
	if span != nil {
		span.SetAttributes(attribute.String("kayan.oidc.provider", provider))
	}
	return ctx, span
}

// SpanSAML starts a span for SAML operations.
func (p *Provider) SpanSAML(ctx context.Context, idpID string) (context.Context, trace.Span) {
	ctx, span := p.StartSpan(ctx, "kayan.saml", SpanOptions{
		Strategy: "saml",
	})
	if span != nil {
		span.SetAttributes(attribute.String("kayan.saml.idp", idpID))
	}
	return ctx, span
}

// SpanWebAuthn starts a span for WebAuthn operations.
func (p *Provider) SpanWebAuthn(ctx context.Context, operation string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.webauthn."+operation, SpanOptions{
		Strategy: "webauthn",
	})
}

// ---- Session Spans ----

// SpanSessionCreate starts a span for session creation.
func (p *Provider) SpanSessionCreate(ctx context.Context, identityID string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.session.create", SpanOptions{
		IdentityID: identityID,
	})
}

// SpanSessionValidate starts a span for session validation.
func (p *Provider) SpanSessionValidate(ctx context.Context, sessionID string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.session.validate", SpanOptions{
		SessionID: sessionID,
	})
}

// SpanSessionRefresh starts a span for session refresh.
func (p *Provider) SpanSessionRefresh(ctx context.Context, sessionID string) (context.Context, trace.Span) {
	return p.StartSpan(ctx, "kayan.session.refresh", SpanOptions{
		SessionID: sessionID,
	})
}

// ---- Policy Spans ----

// SpanPolicyCheck starts a span for policy evaluation.
func (p *Provider) SpanPolicyCheck(ctx context.Context, action, resource string) (context.Context, trace.Span) {
	ctx, span := p.StartSpan(ctx, "kayan.policy.check", SpanOptions{})
	if span != nil {
		span.SetAttributes(
			attribute.String("kayan.policy.action", action),
			attribute.String("kayan.policy.resource", resource),
		)
	}
	return ctx, span
}

// ---- Rate Limit Spans ----

// SpanRateLimit starts a span for rate limit checking.
func (p *Provider) SpanRateLimit(ctx context.Context, key string) (context.Context, trace.Span) {
	ctx, span := p.StartSpan(ctx, "kayan.ratelimit.check", SpanOptions{})
	if span != nil {
		span.SetAttributes(attribute.String("kayan.ratelimit.key", key))
	}
	return ctx, span
}

// ---- Utility Functions ----

// SetSpanError marks a span as having an error.
func SetSpanError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetSpanSuccess marks a span as successful.
func SetSpanSuccess(span trace.Span) {
	if span == nil {
		return
	}
	span.SetStatus(codes.Ok, "")
}

// AddSpanEvent adds an event to the span.
func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	if span == nil {
		return
	}
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// EndSpan ends a span with optional error handling.
func EndSpan(span trace.Span, err error) {
	if span == nil {
		return
	}
	if err != nil {
		SetSpanError(span, err)
	} else {
		SetSpanSuccess(span)
	}
	span.End()
}
