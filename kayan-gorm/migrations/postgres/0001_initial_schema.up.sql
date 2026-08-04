-- Initial Kayan schema.
--
-- Every table carrying identity data has a tenant_id column. It is indexed
-- alongside the columns each query filters on, because the tenant predicate is
-- added to every statement by the isolation callback — an index that omits it
-- is an index the planner will not use.

CREATE TABLE identities (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    traits      JSONB,
    roles       JSONB,
    permissions JSONB,
    state       TEXT NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret  TEXT,
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

CREATE INDEX idx_identities_tenant ON identities (tenant_id);
CREATE INDEX idx_identities_deleted_at ON identities (deleted_at);

CREATE TABLE credentials (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    type        TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    secret      TEXT,
    config      JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- An identifier is unique within a tenant and method, not globally: two
-- tenants may each have a user with the same email address.
CREATE UNIQUE INDEX idx_credentials_lookup
    ON credentials (tenant_id, type, identifier);
CREATE INDEX idx_credentials_identity ON credentials (tenant_id, identity_id);

CREATE TABLE sessions (
    id                 TEXT PRIMARY KEY,
    tenant_id          TEXT NOT NULL DEFAULT '',
    identity_id        TEXT NOT NULL,
    refresh_token      TEXT,
    expires_at         TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    issued_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active             BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_sessions_identity ON sessions (tenant_id, identity_id);
CREATE UNIQUE INDEX idx_sessions_refresh_token
    ON sessions (refresh_token) WHERE refresh_token IS NOT NULL;
-- Supports sweeping expired sessions.
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE auth_tokens (
    token       TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    type        TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_tokens_identity ON auth_tokens (tenant_id, identity_id);
CREATE INDEX idx_auth_tokens_expires_at ON auth_tokens (expires_at);

CREATE TABLE audit_events (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL DEFAULT '',
    type          TEXT NOT NULL,
    actor_id      TEXT,
    subject_id    TEXT,
    status        TEXT,
    message       TEXT,
    metadata      JSONB,
    ip_address    TEXT,
    user_agent    TEXT,
    device_id     TEXT,
    session_id    TEXT,
    resource_type TEXT,
    resource_id   TEXT,
    old_value     JSONB,
    new_value     JSONB,
    risk          TEXT,
    request_id    TEXT,
    geo_country   TEXT,
    geo_region    TEXT,
    geo_city      TEXT,
    geo_lat       DOUBLE PRECISION,
    geo_long      DOUBLE PRECISION,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit queries are almost always "this tenant, this actor, recent first".
CREATE INDEX idx_audit_events_tenant_created ON audit_events (tenant_id, created_at DESC);
CREATE INDEX idx_audit_events_actor ON audit_events (tenant_id, actor_id);
CREATE INDEX idx_audit_events_subject ON audit_events (tenant_id, subject_id);
CREATE INDEX idx_audit_events_type ON audit_events (tenant_id, type);

CREATE TABLE relation_tuples (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL DEFAULT '',
    object_type      TEXT NOT NULL,
    object_id        TEXT NOT NULL,
    relation         TEXT NOT NULL,
    subject_type     TEXT NOT NULL,
    subject_id       TEXT NOT NULL,
    subject_relation TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A tuple is the unit of authorization, so the same tuple must not exist
-- twice: a duplicate would survive a revocation of the first.
CREATE UNIQUE INDEX idx_relation_tuples_unique ON relation_tuples (
    tenant_id, object_type, object_id, relation,
    subject_type, subject_id, subject_relation
);
-- Forward check: "may this subject act on this object?"
CREATE INDEX idx_relation_tuples_object
    ON relation_tuples (tenant_id, object_type, object_id, relation);
-- Reverse lookup: "what may this subject reach?"
CREATE INDEX idx_relation_tuples_subject
    ON relation_tuples (tenant_id, subject_type, subject_id, relation);

CREATE TABLE mfa_enrollments (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    method_id   TEXT NOT NULL,
    status      TEXT NOT NULL,
    config      BYTEA,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_enrollments_identity ON mfa_enrollments (tenant_id, identity_id);

CREATE TABLE mfa_challenges (
    id            TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL DEFAULT '',
    enrollment_id TEXT NOT NULL,
    method_id     TEXT NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    metadata      BYTEA
);

CREATE INDEX idx_mfa_challenges_enrollment ON mfa_challenges (tenant_id, enrollment_id);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

CREATE TABLE mfa_recovery_codes (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    -- A bcrypt hash. A recovery code bypasses the second factor entirely, so
    -- the plaintext must never be stored.
    code_hash   TEXT NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Redemption reads the unconsumed codes for one identity.
CREATE INDEX idx_mfa_recovery_codes_lookup
    ON mfa_recovery_codes (tenant_id, identity_id, consumed_at);

CREATE TABLE devices (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL DEFAULT '',
    identity_id  TEXT NOT NULL,
    name         TEXT,
    -- Supplied by the client and therefore spoofable: it identifies a
    -- device rather than authenticating one.
    fingerprint  TEXT NOT NULL,
    user_agent   TEXT,
    ip_address   TEXT,
    trust_level  TEXT NOT NULL DEFAULT 'low',
    last_seen_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX idx_devices_fingerprint
    ON devices (tenant_id, identity_id, fingerprint);

CREATE TABLE role_assignments (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    role        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_role_assignments_unique
    ON role_assignments (tenant_id, identity_id, role);
CREATE INDEX idx_role_assignments_identity
    ON role_assignments (tenant_id, identity_id);
