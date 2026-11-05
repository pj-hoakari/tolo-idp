ALTER TABLE idp_login_challenge ADD COLUMN client_id varchar(100);
ALTER TABLE idp_login_challenge ADD COLUMN registration boolean NOT NULL DEFAULT false;
