# Infrastructure & Utilities

Kayan provides several built-in packages to handle the cross-cutting concerns of production-grade IAM systems, such as monitoring, compliance, and dynamic configuration.

## 1. Compliance (Data Retention & Encryption)
- **`compliance/`**: Implements data retention policies (e.g., automatic deletion of inactive identities after 7 years) and field-level encryption for sensitive PII.

## 2. Telemetry & Health
- **`telemetry/`**: Deep integration with OpenTelemetry and Prometheus. 
  - **Metrics**: Track login success/failure rates, session duration, and API latency.
  - **Tracing**: Follow a request from the SAML ACS callback through to identity reconciliation.
- **`health/`**: Standardized health probes for Kubernetes/Docker. Checks database connectivity and certificate validity.

```go
// Register a health check
checker.AddCheck("database", db.LivenessProbe())
```

## 3. Dynamic Configuration
- **`config/`**: A tenant-aware configuration system. 
  - Allows you to change system behavior (like password strength requirements) at runtime for a specific tenant without restarting the server.
  - Supports loading from Environment Variables, JSON files, or Etcd.

```go
// Get tenant-specific password complexity
complexity := config.Get(ctx, "password.min_length")
```

## 4. Device Management
- **`device/`**: Track "Trusted Devices" for users. 
  - Supports device fingerprinting. 
  - Allows for "Remember this device" logic to skip MFA on recognized browsers.

## 5. Consent Management
- **`consent/`**: Manage GDPR and CCPA consent records. 
  - Tracks which versions of the Terms of Service a user has agreed to. 
  - Generates audit events for consent revocation.

## 6. Administration API
- **`admin/`**: Provides the internal logic for the Kayan Management Console. 
  - Use this package to build your own internal dashboard for managing tenants, viewing audit logs, or manual account recovery.
