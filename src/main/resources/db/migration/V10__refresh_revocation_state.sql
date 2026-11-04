CREATE TABLE idp_authorization_refresh_state (
    authorization_id varchar(100) NOT NULL PRIMARY KEY,
    refresh_revoked boolean NOT NULL DEFAULT false
);
