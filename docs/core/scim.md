# SCIM 2.0 Provisioning

`core/scim` provides the provisioning layer for user and group lifecycle synchronization.

## Package Scope

The package includes:

- SCIM resource types
- validation and error model
- manager APIs for user and group operations
- mapper utilities between SCIM payloads and internal identities
- storage interfaces for persistence

It is intentionally not a full HTTP server. Your application exposes SCIM endpoints and delegates the business logic to the manager.

## Manager Responsibilities

`scim.NewManager(storage, mapper)` handles:

- creating and updating SCIM users
- listing users and groups with pagination
- group membership operations
- input validation and SCIM-style errors
- mapping between protocol data and your internal model

## Mapper Strategy

The mapper is the critical BYOS bridge in SCIM integrations. It should define how fields such as:

- `userName`
- emails
- display name
- active state
- external ID

map into your identity schema.

If your identity model is tenant-scoped, make tenant rules explicit in the mapper or in the HTTP layer before calling the manager.

## Storage Expectations

SCIM storage should support:

- identity lookup by SCIM identifier or mapped fields
- create and update semantics
- filtering and pagination
- group lifecycle and membership persistence

Use relational storage when provisioning must be strongly consistent with the rest of your IAM data.

## Deployment Guidance

- make SCIM idempotency rules explicit
- audit provisioning events, especially deactivation and group membership changes
- document which attributes your tenant-specific integrations support
- test pagination and filtering against real IdP clients such as Okta or Azure AD