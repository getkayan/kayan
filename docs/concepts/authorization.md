# Authorization

Kayan ships three complementary authorization models. They are not mutually exclusive.

- `core/rbac` for direct role and permission checks
- `core/policy` for ABAC and hybrid policy evaluation
- `core/rebac` for graph-based relationship authorization

Choose based on the shape of your permissions, not on library preference.

## RBAC

RBAC is the simplest option.

Use `core/rbac` when:

- identities already contain role or permission lists
- you need straightforward role gates such as `admin`, `editor`, `support`
- you want transport-agnostic checks inside service methods

The built-in strategy reads roles and permissions from optional identity interfaces. That makes it a good fit for BYOS models with role arrays, JSON traits, or adapter-managed lookups.

Typical checks:

- `HasRole`
- `HasPermission`
- `Authorize`
- `AuthorizePermission`

## ABAC

Use `core/policy` when authorization depends on attributes rather than just named roles.

Common examples:

- a user can read an invoice only if they belong to the same tenant
- a support agent can access a ticket only during business hours
- a login may be blocked when geo risk is high and the device is unknown

Rules are ordinary Go functions. That keeps policy logic close to your domain model and avoids forcing a DSL into the core library.

## Hybrid Policies

Use hybrid policy when neither pure role checks nor pure attribute checks are enough.

Typical pattern:

- RBAC decides broad capability, for example `billing_admin`
- ABAC decides scope, for example same tenant and owned account

`core/policy` includes a hybrid strategy for composing both decisions.

## ReBAC

Use `core/rebac` when access depends on graph relationships:

- users belong to groups
- groups grant access to projects
- documents inherit access from folders
- organizations, workspaces, teams, and resources form a hierarchy

ReBAC supports:

- direct tuples
- computed relations
- tuple-to-userset expansion
- cycle protection and bounded traversal depth

This is the right model when permissions cannot be expressed cleanly as a flat role list.

## Combining Models

A common production architecture is:

- RBAC for coarse-grained internal roles
- ReBAC for customer-facing resource graphs
- ABAC for request-time conditions such as tenant, time, device, or risk score

Keep those layers explicit. Avoid hiding graph checks inside flat permission strings where the real access model becomes hard to reason about.

## Enforcement Guidance

- Resolve tenant context before authorization in multi-tenant systems.
- Use typed resource references in ReBAC rather than ad hoc string concatenation.
- Keep policy engines in the service layer, not in handlers only.
- Treat authorization denial reasons as internal diagnostics. Surface minimal user-facing error messages.