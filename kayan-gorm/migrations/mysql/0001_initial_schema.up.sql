-- Initial Kayan schema (MySQL).
--
-- Identifier columns are VARCHAR(191) rather than TEXT: MySQL cannot index a
-- TEXT column without a prefix length, and 191 keeps a composite unique key
-- inside the InnoDB limit under utf8mb4.
--
-- Every table carrying identity data has a tenant_id column. It is indexed
-- alongside the columns each query filters on, because the tenant predicate is
-- added to every statement by the isolation callback — an index that omits it
-- is an index the planner will not use.

CREATE TABLE identities (
    id          VARCHAR(191) PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    traits      JSON,
    roles       JSON,
    permissions JSON,
    state       TEXT NOT NULL DEFAULT 'active',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret  TEXT,
    verified    BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMP NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMP NULL
);

CREATE INDEX idx_identities_tenant ON identities (tenant_id);
CREATE INDEX idx_identities_deleted_at ON identities (deleted_at);

CREATE TABLE credentials (
    id          VARCHAR(191) PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    identity_id VARCHAR(191) NOT NULL,
    type        VARCHAR(191) NOT NULL,
    identifier  VARCHAR(191) NOT NULL,
    secret      TEXT,
    config      JSON,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- An identifier is unique within a tenant and method, not globally: two
-- tenants may each have a user with the same email address.
CREATE UNIQUE INDEX idx_credentials_lookup
    ON credentials (tenant_id, type, identifier);
CREATE INDEX idx_credentials_identity ON credentials (tenant_id, identity_id);

CREATE TABLE sessions (
    id                 VARCHAR(191) PRIMARY KEY,
    tenant_id          VARCHAR(191) NOT NULL DEFAULT '',
    identity_id        VARCHAR(191) NOT NULL,
    refresh_token      VARCHAR(191),
    expires_at         TIMESTAMP NULL NOT NULL,
    refresh_expires_at TIMESTAMP NULL,
    issued_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active             BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_sessions_identity ON sessions (tenant_id, identity_id);
CREATE UNIQUE INDEX idx_sessions_refresh_token ON sessions (refresh_token);
-- Supports sweeping expired sessions.
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE TABLE auth_tokens (
    token       VARCHAR(191) PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    identity_id VARCHAR(191) NOT NULL,
    type        VARCHAR(191) NOT NULL,
    expires_at  TIMESTAMP NULL NOT NULL
);

CREATE INDEX idx_auth_tokens_identity ON auth_tokens (tenant_id, identity_id);
CREATE INDEX idx_auth_tokens_expires_at ON auth_tokens (expires_at);

CREATE TABLE audit_events (
    id            VARCHAR(191) PRIMARY KEY,
    tenant_id     VARCHAR(191) NOT NULL DEFAULT '',
    type          VARCHAR(191) NOT NULL,
    actor_id      VARCHAR(191),
    subject_id    VARCHAR(191),
    status        VARCHAR(191),
    message       TEXT,
    metadata      JSON,
    ip_address    TEXT,
    user_agent    TEXT,
    device_id     VARCHAR(191),
    session_id    VARCHAR(191),
    resource_type VARCHAR(191),
    resource_id   VARCHAR(191),
    old_value     JSON,
    new_value     JSON,
    risk          TEXT,
    request_id    VARCHAR(191),
    geo_country   TEXT,
    geo_region    TEXT,
    geo_city      TEXT,
    geo_lat       DOUBLE,
    geo_long      DOUBLE,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Audit queries are almost always "this tenant, this actor, recent first".
CREATE INDEX idx_audit_events_tenant_created ON audit_events (tenant_id, created_at);
CREATE INDEX idx_audit_events_actor ON audit_events (tenant_id, actor_id);
CREATE INDEX idx_audit_events_subject ON audit_events (tenant_id, subject_id);
CREATE INDEX idx_audit_events_type ON audit_events (tenant_id, type);

CREATE TABLE relation_tuples (
    id               VARCHAR(191) PRIMARY KEY,
    tenant_id        VARCHAR(191) NOT NULL DEFAULT '',
    object_type      VARCHAR(191) NOT NULL,
    object_id        VARCHAR(191) NOT NULL,
    relation         VARCHAR(191) NOT NULL,
    subject_type     VARCHAR(191) NOT NULL,
    subject_id       VARCHAR(191) NOT NULL,
    subject_relation VARCHAR(191) NOT NULL DEFAULT '',
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    id          VARCHAR(191) PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    identity_id VARCHAR(191) NOT NULL,
    method_id   VARCHAR(191) NOT NULL,
    status      VARCHAR(191) NOT NULL,
    config      BLOB,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_mfa_enrollments_identity ON mfa_enrollments (tenant_id, identity_id);

CREATE TABLE mfa_challenges (
    id            VARCHAR(191) PRIMARY KEY,
    tenant_id     VARCHAR(191) NOT NULL DEFAULT '',
    enrollment_id VARCHAR(191) NOT NULL,
    method_id     VARCHAR(191) NOT NULL,
    expires_at    TIMESTAMP NULL NOT NULL,
    metadata      BLOB
);

CREATE INDEX idx_mfa_challenges_enrollment ON mfa_challenges (tenant_id, enrollment_id);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

CREATE TABLE mfa_recovery_codes (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    identity_id VARCHAR(191) NOT NULL,
    -- A bcrypt hash. A recovery code bypasses the second factor entirely, so
    -- the plaintext must never be stored.
    code_hash   VARCHAR(191) NOT NULL,
    consumed_at TIMESTAMP NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Redemption reads the unconsumed codes for one identity.
CREATE INDEX idx_mfa_recovery_codes_lookup
    ON mfa_recovery_codes (tenant_id, identity_id, consumed_at);

CREATE TABLE devices (
    id           VARCHAR(191) PRIMARY KEY,
    tenant_id    VARCHAR(191) NOT NULL DEFAULT '',
    identity_id  VARCHAR(191) NOT NULL,
    name         TEXT,
    -- Supplied by the client and therefore spoofable: it identifies a
    -- device rather than authenticating one.
    fingerprint  VARCHAR(191) NOT NULL,
    user_agent   TEXT,
    ip_address   TEXT,
    trust_level  VARCHAR(191) NOT NULL DEFAULT 'low',
    last_seen_at TIMESTAMP NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE UNIQUE INDEX idx_devices_fingerprint
    ON devices (tenant_id, identity_id, fingerprint);

CREATE TABLE role_assignments (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id   VARCHAR(191) NOT NULL DEFAULT '',
    identity_id VARCHAR(191) NOT NULL,
    role        VARCHAR(191) NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_role_assignments_unique
    ON role_assignments (tenant_id, identity_id, role);
CREATE INDEX idx_role_assignments_identity
    ON role_assignments (tenant_id, identity_id);
