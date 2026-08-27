CREATE TABLE sso_sessions (
    id          VARCHAR(255) PRIMARY KEY,
    tenant_id   VARCHAR(255) NOT NULL DEFAULT '',
    identity_id VARCHAR(255) NOT NULL,
    created_at  DATETIME(6) NOT NULL,
    expires_at  DATETIME(6) NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE KEY idx_sso_identity (tenant_id, identity_id),
    KEY idx_sso_expiry (tenant_id, expires_at)
);

CREATE TABLE sso_app_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    sso_id     VARCHAR(255) NOT NULL,
    app_id     VARCHAR(255) NOT NULL,
    created_at DATETIME(6) NOT NULL,
    UNIQUE KEY idx_sso_app (sso_id, app_id),
    CONSTRAINT fk_sso_app_session FOREIGN KEY (sso_id) REFERENCES sso_sessions(id) ON DELETE CASCADE
);
