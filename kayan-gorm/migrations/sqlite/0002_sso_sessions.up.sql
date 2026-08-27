CREATE TABLE sso_sessions (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    identity_id TEXT NOT NULL,
    created_at  DATETIME NOT NULL,
    expires_at  DATETIME NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, identity_id)
);

CREATE INDEX idx_sso_sessions_expiry ON sso_sessions (tenant_id, expires_at);

CREATE TABLE sso_app_sessions (
    session_id TEXT PRIMARY KEY,
    sso_id     TEXT NOT NULL REFERENCES sso_sessions(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    UNIQUE (sso_id, app_id)
);
