# Kayan Documentation

Welcome to the Kayan documentation! Kayan is a headless, extensible Identity & Access Management library for Go.

## 📚 Documentation Structure

### Getting Started
- [Getting Started Guide](./getting-started.md) - Quick start with Kayan

### Core Concepts
- [BYOS (Bring Your Own Schema)](./concepts/byos.md) - Use your own data models
- [Authentication Strategies](./concepts/strategies.md) - Password, OIDC, WebAuthn, SAML, Magic Link
- [Session Management](./concepts/sessions.md) - JWT and database sessions
- [Authorization](./concepts/authorization.md) - RBAC, ABAC, and hybrid policies
- [Multi-Tenancy](./concepts/multi-tenancy.md) - Tenant isolation and configuration

### Reference
- [Configuration](./reference/configuration.md) - Environment and code configuration
- [API Reference](./reference/api.md) - REST API endpoints

### SDKs
- [JavaScript/TypeScript SDK](./sdk/javascript.md) - kayan.js usage guide

### Architecture
- [Overview](./architecture/README.md) - System architecture
- [Security Model](./architecture/security-model.md) - Threat model and security controls
- [Strategy Internals](./architecture/strategy-internals.md) - How strategies work
- [Storage Layer](./architecture/storage-layer.md) - Repository pattern
- [Extending Kayan](./architecture/extending-kayan.md) - Custom strategies guide
- [Authentication Flows](./architecture/authentication-flows.md) - Flow diagrams
- [Authorization Models](./architecture/authorization-models.md) - RBAC/ABAC deep dive

### Deployment
- [Docker](./deployment/docker/) - Docker deployment
- [Kubernetes](./deployment/kubernetes/) - K8s manifests
- [Helm](./deployment/helm/) - Helm charts

---

## 🔗 Quick Links

- [Examples](../../kayan-examples/) - 20+ runnable examples
- [OpenAPI Spec](./openapi/openapi.yaml) - Full API specification
- [GitHub](https://github.com/getkayan/kayan) - Source code
