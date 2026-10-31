-- Legacy users have no tenant identity. The development schema is recreated without guessing a tenant.
DELETE FROM oauth2_authorization WHERE principal_name IN (SELECT username FROM users);
DELETE FROM oauth2_authorization_consent WHERE principal_name IN (SELECT username FROM users);
DELETE FROM idp_relation_membership_cache;
DROP TABLE authorities;
DROP TABLE users;

CREATE TABLE idp_users (
    id varchar(36) NOT NULL PRIMARY KEY,
    tenant_id varchar(64) NOT NULL,
    username varchar(50) NOT NULL,
    password varchar(500) NOT NULL,
    enabled boolean NOT NULL,
    UNIQUE (tenant_id, username)
);

CREATE TABLE idp_user_authorities (
    user_id varchar(36) NOT NULL REFERENCES idp_users(id),
    authority varchar(50) NOT NULL,
    PRIMARY KEY (user_id, authority)
);
