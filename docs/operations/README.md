# Kayan Operations Guide

This guide covers day-to-day operations for running Kayan in production.

## Table of Contents

- [Configuration Reference](#configuration-reference)
- [Database Operations](#database-operations)
- [Monitoring & Alerting](#monitoring--alerting)
- [Backup & Recovery](#backup--recovery)
- [Troubleshooting](#troubleshooting)
- [Security Operations](#security-operations)

---

## Configuration Reference

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_ENV` | Environment (development, production) | development | No |
| `KAYAN_PORT` | HTTP port | 8080 | No |
| `KAYAN_LOG_LEVEL` | Log level (debug, info, warn, error) | info | No |
| `KAYAN_LOG_FORMAT` | Log format (text, json) | text | No |

#### Database

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_DB_TYPE` | Database type (postgres, mysql, sqlite) | sqlite | Yes (prod) |
| `KAYAN_DB_DSN` | Database connection string | - | Yes (prod) |
| `KAYAN_DB_MAX_OPEN_CONNS` | Maximum open connections | 25 | No |
| `KAYAN_DB_MAX_IDLE_CONNS` | Maximum idle connections | 5 | No |
| `KAYAN_DB_CONN_MAX_LIFETIME` | Connection max lifetime | 5m | No |

#### Redis

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_REDIS_URL` | Redis connection URL | - | Yes (for rate limiting) |
| `KAYAN_REDIS_POOL_SIZE` | Connection pool size | 10 | No |

#### Security

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_SESSION_SECRET` | Session encryption key (32 bytes) | - | Yes |
| `KAYAN_JWT_SECRET` | JWT signing key | - | Yes (for JWT sessions) |
| `KAYAN_BCRYPT_COST` | Bcrypt cost factor | 10 | No |

#### Rate Limiting

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_RATE_LIMIT_ENABLED` | Enable rate limiting | false | No |
| `KAYAN_RATE_LIMIT_REQUESTS` | Requests per window | 100 | No |
| `KAYAN_RATE_LIMIT_WINDOW` | Time window | 60s | No |

#### Account Lockout

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KAYAN_LOCKOUT_ENABLED` | Enable account lockout | false | No |
| `KAYAN_LOCKOUT_MAX_FAILURES` | Max failed attempts | 5 | No |
| `KAYAN_LOCKOUT_DURATION` | Lockout duration | 15m | No |

---

## Database Operations

### Migrations

```bash
# Run pending migrations
kayan migrate up

# Rollback last migration
kayan migrate down

# Check migration status
kayan migrate status

# Create new migration
kayan migrate create add_new_table
```

### Connection String Examples

**PostgreSQL:**
```
postgres://user:password@localhost:5432/kayan?sslmode=require
```

**MySQL:**
```
user:password@tcp(localhost:3306)/kayan?parseTime=true
```

**SQLite (development only):**
```
file:kayan.db?cache=shared&mode=rwc
```

### Database Maintenance

```sql
-- PostgreSQL: Vacuum and analyze
VACUUM ANALYZE identities;
VACUUM ANALYZE sessions;
VACUUM ANALYZE audit_events;

-- PostgreSQL: Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

---

## Monitoring & Alerting

### Health Endpoints

| Endpoint | Purpose | Use Case |
|----------|---------|----------|
| `/health/live` | Liveness check | Kubernetes liveness probe |
| `/health/ready` | Readiness check | Kubernetes readiness probe |
| `/health` | Full health report | Monitoring dashboards |

### Key Metrics

```prometheus
# Authentication metrics
kayan_login_total{status="success|failure", strategy="password|oidc|webauthn"}
kayan_registration_total{status="success|failure"}
kayan_mfa_total{status="success|failure", type="totp|webauthn"}

# Security metrics
kayan_rate_limit_hits_total{key}
kayan_lockout_events_total{action="locked|unlocked"}

# Performance metrics
kayan_auth_duration_seconds{strategy, quantile="0.5|0.9|0.99"}
kayan_db_query_duration_seconds{operation}

# Session metrics
kayan_active_sessions{tenant}
kayan_session_refreshes_total
```

### Recommended Alerts

```yaml
# High failure rate
- alert: KayanHighAuthFailureRate
  expr: rate(kayan_login_total{status="failure"}[5m]) / rate(kayan_login_total[5m]) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: High authentication failure rate

# Service unhealthy
- alert: KayanUnhealthy
  expr: kayan_health_status != 1
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: Kayan health check failing

# High latency
- alert: KayanHighLatency
  expr: histogram_quantile(0.99, kayan_auth_duration_seconds) > 1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: Authentication latency above 1s
```

---

## Backup & Recovery

### Database Backup

**PostgreSQL:**
```bash
# Full backup
pg_dump -h localhost -U kayan -Fc kayan > kayan_$(date +%Y%m%d).dump

# Restore
pg_restore -h localhost -U kayan -d kayan kayan_20240118.dump
```

### Critical Tables

Priority order for recovery:
1. `identities` - User accounts
2. `credentials` - Authentication credentials
3. `sessions` - Active sessions (can regenerate)
4. `audit_events` - Audit logs (compliance)

### Point-in-Time Recovery

```bash
# PostgreSQL WAL archiving
archive_mode = on
archive_command = 'cp %p /backup/wal/%f'

# Restore to specific time
recovery_target_time = '2024-01-18 10:00:00'
```

---

## Troubleshooting

### Common Issues

#### 1. Connection Refused

```bash
# Check if service is running
curl -v http://localhost:8080/health/live

# Check port binding
netstat -tlnp | grep 8080

# Check logs
docker logs kayan 2>&1 | tail -100
```

#### 2. Database Connection Errors

```bash
# Test connectivity
psql $KAYAN_DB_DSN -c "SELECT 1"

# Check connection pool
curl http://localhost:8080/health | jq '.checks[] | select(.name=="database")'
```

#### 3. Redis Connection Errors

```bash
# Test connectivity
redis-cli -u $KAYAN_REDIS_URL PING

# Check rate limiter
curl http://localhost:8080/health | jq '.checks[] | select(.name=="redis")'
```

#### 4. High Memory Usage

```bash
# Check Go runtime metrics
curl http://localhost:8080/debug/pprof/heap > heap.prof
go tool pprof heap.prof

# Force GC (if needed)
curl -X POST http://localhost:8080/debug/gc
```

### Log Analysis

```bash
# Find failed logins
jq 'select(.type=="auth.login.failure")' /var/log/kayan/audit.log

# Find locked accounts
jq 'select(.type=="auth.login.blocked")' /var/log/kayan/audit.log

# Find rate limited requests
jq 'select(.type=="security.rate_limited")' /var/log/kayan/audit.log
```

---

## Security Operations

### Rotate Secrets

```bash
# 1. Generate new secrets
NEW_SESSION_SECRET=$(openssl rand -base64 32)
NEW_JWT_SECRET=$(openssl rand -base64 64)

# 2. Update Kubernetes secret
kubectl create secret generic kayan-secrets \
  --from-literal=KAYAN_SESSION_SECRET=$NEW_SESSION_SECRET \
  --from-literal=KAYAN_JWT_SECRET=$NEW_JWT_SECRET \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Rolling restart
kubectl rollout restart deployment/kayan

# 4. Monitor for errors
kubectl logs -f deployment/kayan
```

### Force Logout All Users

```bash
# Clear all sessions
kayan admin sessions revoke-all

# Or via SQL (emergency)
UPDATE sessions SET active = false WHERE active = true;
```

### Lock Specific User

```bash
# Via CLI
kayan admin user lock --id <user-id> --reason "Security incident"

# Via API
curl -X POST http://localhost:8080/admin/users/<id>/lock \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Audit Log Export

```bash
# Export for compliance audit
kayan audit export \
  --start "2024-01-01" \
  --end "2024-01-31" \
  --format json \
  --output audit-2024-01.json

# Export specific event types
kayan audit export \
  --types "auth.login.failure,auth.login.blocked" \
  --format csv
```

---

## Scaling Guidelines

### Horizontal Scaling

| Load (req/s) | Replicas | CPU (per pod) | Memory (per pod) |
|--------------|----------|---------------|------------------|
| < 100 | 2 | 250m | 256Mi |
| 100-500 | 3-5 | 500m | 512Mi |
| 500-1000 | 5-10 | 1000m | 1Gi |
| > 1000 | 10+ | 2000m | 2Gi |

### Database Scaling

1. **Read replicas** - Route read queries to replicas
2. **Connection pooling** - Use PgBouncer or similar
3. **Partitioning** - Partition audit_events by date

### Redis Scaling

1. **Cluster mode** - For high availability
2. **Sentinel** - For automatic failover
3. **Separate instances** - Rate limiting vs sessions
