CREATE TABLE idp_users (
    id varchar(36) NOT NULL PRIMARY KEY,
    username varchar(50) NOT NULL UNIQUE,
    password varchar(500) NOT NULL,
    enabled boolean NOT NULL
);

INSERT INTO idp_users (id, username, password, enabled)
SELECT CAST(RANDOM_UUID() AS varchar(36)), username, password, enabled FROM users;

CREATE TABLE idp_user_authorities (
    user_id varchar(36) NOT NULL REFERENCES idp_users(id),
    authority varchar(50) NOT NULL,
    PRIMARY KEY (user_id, authority)
);

INSERT INTO idp_user_authorities (user_id, authority)
SELECT u.id, a.authority FROM authorities a JOIN idp_users u ON u.username = a.username;

-- Old authorizations embed username principals. Require a fresh login instead of reinterpreting them.
DELETE FROM oauth2_authorization WHERE principal_name IN (SELECT username FROM users);
DELETE FROM oauth2_authorization_consent WHERE principal_name IN (SELECT username FROM users);
DELETE FROM idp_relation_membership_cache;
DROP TABLE authorities;
DROP TABLE users;
