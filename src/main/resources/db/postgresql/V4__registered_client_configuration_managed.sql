ALTER TABLE oauth2_registered_client
    ADD COLUMN configuration_managed boolean NOT NULL DEFAULT false;
