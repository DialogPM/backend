-- 17: remote wipe of removed devices (docs/API.md, "Device revocation check").
--
-- Every device registers the SHA-256 of a random secret it keeps outside its encrypted data.
-- When the device is removed (unlinked by the account, old devices replaced by an account
-- recovery, account deleted), the hash is kept here: the removed device, even while its local
-- data is locked with the password, can then ask whether it was removed and wipe itself. Only
-- these explicit records say "removed", so a device missing for any other reason (a restored
-- backup, a bug) is never told to wipe.
ALTER TABLE devices ADD COLUMN revocation_hash BINARY(32) NULL;

CREATE TABLE IF NOT EXISTS device_revocations (
    account_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id    TINYINT UNSIGNED NOT NULL,
    secret_hash  BINARY(32) NOT NULL,
    revoked_at   BIGINT NOT NULL,
    PRIMARY KEY (secret_hash),
    KEY ix_device_revocations_revoked (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
