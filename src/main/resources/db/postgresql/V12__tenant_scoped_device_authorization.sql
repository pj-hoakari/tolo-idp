-- Refuse migration when an old marker cannot be assigned to any known tenant.
-- Resolve these rows explicitly before retrying; never silently discard revocations.
CREATE TABLE idp_device_revocation_migration_guard (unmapped_count integer CHECK (unmapped_count = 0));
INSERT INTO idp_device_revocation_migration_guard
SELECT COUNT(*) FROM idp_revoked_edge_device r
WHERE NOT EXISTS (
    SELECT 1 FROM idp_device_grant g
    WHERE g.event_id = r.event_id AND g.edge_device_id = r.edge_device_id
);
DROP TABLE idp_device_revocation_migration_guard;

ALTER TABLE idp_revoked_edge_device RENAME TO idp_revoked_edge_device_legacy;
CREATE TABLE idp_revoked_edge_device (
    tenant_id varchar(64) NOT NULL,
    event_id varchar(64) NOT NULL,
    edge_device_id varchar(64) NOT NULL,
    revoked_at timestamp NOT NULL,
    permanent boolean NOT NULL DEFAULT TRUE,
    PRIMARY KEY (tenant_id, event_id, edge_device_id)
);
INSERT INTO idp_revoked_edge_device (tenant_id, event_id, edge_device_id, revoked_at, permanent)
SELECT DISTINCT g.tenant_id, r.event_id, r.edge_device_id, r.revoked_at, r.permanent
FROM idp_revoked_edge_device_legacy r
JOIN idp_device_grant g ON g.event_id = r.event_id AND g.edge_device_id = r.edge_device_id;
DROP TABLE idp_revoked_edge_device_legacy;

DROP TABLE idp_device_grant_lock;
CREATE TABLE idp_device_grant_lock (
    tenant_id varchar(64) NOT NULL,
    event_id varchar(64) NOT NULL,
    edge_device_id varchar(64) NOT NULL,
    PRIMARY KEY (tenant_id, event_id, edge_device_id)
);
DROP INDEX ix_idp_device_grant_event_edge;
DROP INDEX ix_idp_device_grant_edge_device;
CREATE INDEX ix_idp_device_grant_tenant_event_edge
    ON idp_device_grant (tenant_id, event_id, edge_device_id);
