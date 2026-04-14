# Kayan Documentation

Welcome to the official technical documentation for **Kayan**, a headless, non-generic, extensible Identity & Access Management (IAM) library for Go.

Kayan is designed for developers who need enterprise-grade authentication and authorization without the overhead of forced schemas or UI opinions.

## 📚 Documentation Map

### [Overview](overview/)
- **[Philosophy](overview/philosophy.md)**: Headless, BYOS (Bring Your Own Schema), Non-generic design, and the Strategy Pattern.
- **[Architecture](overview/architecture.md)**: Exhaustive map of all 22 core packages, layering, and dependency rules.

### [Core API & Usage Reference](core/)
Each guide includes **Standard Usage**, **Custom Implementation**, and **Common Mistakes**.

- **[Identity](core/identity.md)**: Multi-identifier identities, Traits (JSON), and the BYOS Reflection Mapper.
- **[Flow](core/flow.md)**: Registration and Login flows, and how to build custom authentication strategies.
- **[Session](core/session.md)**: Stateless (JWT) and Stateful (DB/Redis) session lifecycle management.
- **[MFA](core/mfa.md)**: TOTP, Recovery codes, and custom Multi-Factor methods (Push, etc.).
- **[RBAC](core/rbac.md)**: Role-Based Access Control via Bitmasks or traditional JSON roles.
- **[ReBAC](core/rebac.md)**: Relationship-Based Access Control (Zanzibar style) for complex hierarchies.
- **[Policy & ABAC](core/policy.md)**: Dynamic Attribute-Based checks and Hybrid authorization engines.
- **[Multi-Tenancy](core/tenant.md)**: Native isolation, resolution strategies, and scoped storage.
- **[Audit](core/audit.md)**: SOC 2 compliant structured security logging and change tracking.
- **[Infrastructure](core/infrastructure.md)**: Compliance, Telemetry, Health checks, and Dynamic config.

### [Protocols](core/)
Extensive guides on enterprise protocol integration.
- **[OIDC](core/oidc.md)**: Implementing an OpenID Connect Provider or Relying Party.
- **[SAML 2.0](core/saml.md)**: Enterprise SSO with Service Provider (SP) and IdP support.
- **[SCIM 2.0](core/scim.md)**: Automated user provisioning and advanced filtering.

### [Adapters & Extensions](adapters/)
- **[Storage Adapters](adapters/storage.md)**: Using `kgorm` or implementing a custom DB adapter from scratch.

---

## 🚀 Getting Started

1. Understand the **[Philosophy](overview/philosophy.md)**.
2. Define your **[Identity](core/identity.md)** model.
3. Configure your **[Auth Flows](core/flow.md)**.
4. Integrate **[RBAC](core/rbac.md)** or **[Fine-grained ReBAC](core/rebac.md)** for access control.
