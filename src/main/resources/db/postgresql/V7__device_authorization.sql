CREATE TABLE idp_device_grant (
    id varchar(100) NOT NULL PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    event_id varchar(64) NOT NULL,
    edge_device_id varchar(64) NOT NULL,
    approver_sub varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    approved_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz DEFAULT NULL,
    revoked_reason varchar(100) DEFAULT NULL,
    created_at timestamptz NOT NULL
);

CREATE INDEX ix_idp_device_grant_event_edge
    ON idp_device_grant (event_id, edge_device_id);
CREATE INDEX ix_idp_device_grant_edge_device
    ON idp_device_grant (edge_device_id);

CREATE TABLE idp_device_grant_refresh_token (
    token_hash varchar(64) NOT NULL PRIMARY KEY,
    grant_id varchar(100) NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    superseded_at timestamptz DEFAULT NULL
);

CREATE INDEX ix_idp_device_grant_refresh_token_grant
    ON idp_device_grant_refresh_token (grant_id);

CREATE TABLE idp_revoked_edge_device (
    event_id varchar(64) NOT NULL,
    edge_device_id varchar(64) NOT NULL,
    revoked_at timestamptz NOT NULL,
    PRIMARY KEY (event_id, edge_device_id)
);

CREATE TABLE idp_device_grant_lock (
    edge_device_id varchar(64) NOT NULL PRIMARY KEY
);

ALTER TABLE idp_audit_log ADD COLUMN edge_device_id varchar(64);
