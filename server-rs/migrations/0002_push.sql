-- Mobile push notifications (API section 14).
-- push_provider: '' (disabled) or 'fcm'. push_token: the provider registration token.
-- push_token_hash: SHA-256 of the token; unique so that one app install (token) is attached
-- to at most one device, and a token registered again by another device can be found and
-- moved. NULL when push is disabled.
-- A single ALTER keeps the migration atomic (MySQL DDL is not transactional).
ALTER TABLE devices
    ADD COLUMN push_provider   VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '',
    ADD COLUMN push_token      VARCHAR(4096) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN push_token_hash BINARY(32) NULL,
    ADD UNIQUE KEY uq_devices_push_token (push_token_hash);
