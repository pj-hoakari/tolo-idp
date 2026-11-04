CREATE TABLE idp_authorization_code_claim (
    code_hash varchar(64) NOT NULL PRIMARY KEY,
    expires_at timestamptz NOT NULL
);
