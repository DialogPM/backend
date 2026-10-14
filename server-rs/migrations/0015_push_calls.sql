-- 15: push for calls and several accounts per phone (docs/PUSH-SETUP.md, API section 14).
-- push_tag: opaque random value chosen by the client for this account on that phone; pushes
-- carry it so the app can tell which of its local accounts a wake-up is for (it says nothing
-- about the sender or the conversation). voip_token: APNs PushKit (VoIP) token of an iOS
-- device, used only for incoming call offers. Several accounts on one phone share its FCM
-- token, so push_token_hash is no longer unique (the API keeps it unique per account).
-- A single ALTER keeps the migration atomic (MySQL DDL is not transactional).
ALTER TABLE devices
    DROP INDEX uq_devices_push_token,
    ADD KEY idx_devices_push_token (push_token_hash),
    ADD COLUMN push_tag        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN voip_token      VARCHAR(512) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN voip_token_hash BINARY(32) NULL,
    ADD KEY idx_devices_voip_token (voip_token_hash);
