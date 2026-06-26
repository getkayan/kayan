# Deprecation Policy

Kayan prefers additive, backward-compatible change during a major version. When a public API needs to be replaced, it should be deprecated before it is removed.

## Standard Lifecycle

1. Introduce the replacement API.
2. Mark the old API as deprecated in documentation, comments, or release notes.
3. Record the change in [CHANGELOG.md](./CHANGELOG.md).
4. Remove the deprecated API no earlier than the next major release.

## What Deprecation Should Include

Each deprecation should include:

- what is deprecated
- why it is being replaced
- what to use instead
- the earliest release where removal may happen

## Where Deprecations Are Announced

Deprecations should appear in the relevant places for the affected surface:

- `CHANGELOG.md`
- package comments or godoc for exported APIs
- migration or usage documentation in `docs/`

## Exceptions

Security issues may require faster removal or behavior changes than the standard lifecycle allows. When that happens, Kayan will document the reason and the safest migration path available.

## Contributor Checklist

Before merging a deprecation:

1. Add or confirm a replacement path.
2. Update [CHANGELOG.md](./CHANGELOG.md).
3. Update user-facing docs.
4. Ensure the change remains backward-compatible for the current major version unless a security exception applies.