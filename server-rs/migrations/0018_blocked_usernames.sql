-- 18: usernames nobody can take (admin API, docs/ADMIN-API.md): names that would pass for the
-- service itself (support, admin, ...).
-- pattern: a name, which also covers the same name with a numeric suffix (support.01), or a
-- name with * at the start and/or the end (support*, *admin, *support*).
CREATE TABLE IF NOT EXISTS blocked_usernames (
    pattern     VARCHAR(34) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (pattern)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
