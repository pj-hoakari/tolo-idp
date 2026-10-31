CREATE TABLE idp_login_challenge (
    challenge_hash varchar(64) NOT NULL PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    authorization_request text NOT NULL,
    login_id varchar(36),
    expires_at timestamp NOT NULL
);

CREATE INDEX ix_login_challenge_expires_at ON idp_login_challenge (expires_at);
