CREATE TABLE idp_relation_cache_generation (
    id integer PRIMARY KEY,
    cache_generation bigint NOT NULL
);

INSERT INTO idp_relation_cache_generation (id, cache_generation) VALUES (1, 0);
