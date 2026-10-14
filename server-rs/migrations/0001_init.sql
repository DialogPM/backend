-- Initial schema. All timestamps are milliseconds since the Unix epoch (BIGINT).
-- Identifiers (UUIDs, numbers, hex ids) use the ascii charset with binary collation.

-- Every account number ever issued. Rows are never deleted, so a number is never reused
-- (this is the tombstone table for deleted accounts).
CREATE TABLE account_numbers (
    number      CHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at  BIGINT NOT NULL,
    deleted_at  BIGINT NULL,
    PRIMARY KEY (number),
    UNIQUE KEY uq_account_numbers_account (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE accounts (
    id                    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    number                CHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    auth_key_hash         BINARY(32) NOT NULL,
    kdf                   VARCHAR(1024) NOT NULL,
    wrapped_account_key   VARBINARY(1024) NOT NULL,
    identity_key          VARBINARY(64) NOT NULL,
    recovery_public_key   BINARY(32) NOT NULL,
    created_at            BIGINT NOT NULL,
    phone                 VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    phone_hash            BINARY(32) NULL,
    discoverable_by_phone TINYINT(1) NOT NULL DEFAULT 0,
    privacy_last_seen     VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'everyone',
    last_seen_at          BIGINT NULL,
    vault_bytes           BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY uq_accounts_number (number),
    UNIQUE KEY uq_accounts_phone_hash (phone_hash),
    CONSTRAINT fk_accounts_number FOREIGN KEY (number) REFERENCES account_numbers (number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE devices (
    account_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id       TINYINT UNSIGNED NOT NULL,
    name            VARCHAR(128) NOT NULL,
    platform        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    registration_id INT UNSIGNED NOT NULL,
    token_hash      BINARY(32) NOT NULL,
    created_at      BIGINT NOT NULL,
    last_seen_at    BIGINT NOT NULL,
    PRIMARY KEY (account_id, device_id),
    UNIQUE KEY uq_devices_token (token_hash),
    CONSTRAINT fk_devices_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Replaceable per-device keys. kind: 0 = signed EC pre-key, 1 = last-resort Kyber pre-key.
CREATE TABLE device_signed_keys (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id   TINYINT UNSIGNED NOT NULL,
    kind        TINYINT UNSIGNED NOT NULL,
    key_id      INT UNSIGNED NOT NULL,
    public_key  VARBINARY(4096) NOT NULL,
    signature   VARBINARY(256) NOT NULL,
    PRIMARY KEY (account_id, device_id, kind),
    CONSTRAINT fk_signed_keys_device FOREIGN KEY (account_id, device_id)
        REFERENCES devices (account_id, device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- One-time pre-keys. kind: 0 = EC pre-key, 1 = Kyber pre-key. signature is NULL for EC keys.
CREATE TABLE device_one_time_keys (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id   TINYINT UNSIGNED NOT NULL,
    kind        TINYINT UNSIGNED NOT NULL,
    key_id      INT UNSIGNED NOT NULL,
    public_key  VARBINARY(4096) NOT NULL,
    signature   VARBINARY(256) NULL,
    PRIMARY KEY (account_id, device_id, kind, key_id),
    CONSTRAINT fk_one_time_keys_device FOREIGN KEY (account_id, device_id)
        REFERENCES devices (account_id, device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Queued envelopes per destination device. seq gives the delivery order.
CREATE TABLE envelopes (
    seq                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    id                 CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    device_id          TINYINT UNSIGNED NOT NULL,
    type               TINYINT UNSIGNED NOT NULL,
    source_account     CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_device      TINYINT UNSIGNED NOT NULL,
    group_id           CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    client_timestamp   BIGINT NOT NULL,
    server_timestamp   BIGINT NOT NULL,
    content            MEDIUMBLOB NOT NULL,
    PRIMARY KEY (seq),
    UNIQUE KEY uq_envelopes_id (id),
    KEY idx_envelopes_dest (account_id, device_id, seq),
    KEY idx_envelopes_server_ts (server_timestamp),
    CONSTRAINT fk_envelopes_device FOREIGN KEY (account_id, device_id)
        REFERENCES devices (account_id, device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE profiles (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    data        BLOB NOT NULL,
    avatar_id   CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (account_id),
    CONSTRAINT fk_profiles_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- "groups" is a reserved word in MySQL 8, hence chat_groups.
CREATE TABLE chat_groups (
    id                CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    revision          BIGINT NOT NULL,
    metadata          BLOB NOT NULL,
    avatar_id         CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    created_by        CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at        BIGINT NOT NULL,
    only_admins_send  TINYINT(1) NOT NULL DEFAULT 0,
    only_admins_edit  TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- member_seq orders members by seniority (used for last-admin promotion).
CREATE TABLE group_members (
    member_seq  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    group_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    role        VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    joined_at   BIGINT NOT NULL,
    added_by    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    PRIMARY KEY (group_id, account_id),
    UNIQUE KEY uq_group_members_seq (member_seq),
    KEY idx_group_members_account (account_id),
    CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES chat_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_group_members_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- state: 0 = created (awaiting upload), 1 = upload in progress, 2 = uploaded.
CREATE TABLE attachments (
    id          CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    owner_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    kind        VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size        BIGINT NOT NULL,
    state       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_at  BIGINT NOT NULL,
    uploaded_at BIGINT NULL,
    PRIMARY KEY (id),
    KEY idx_attachments_owner (owner_id),
    KEY idx_attachments_kind_created (kind, created_at),
    KEY idx_attachments_state_created (state, created_at),
    CONSTRAINT fk_attachments_owner FOREIGN KEY (owner_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_records (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record_id   VARCHAR(128) NOT NULL,
    data        MEDIUMBLOB NULL,
    size        INT UNSIGNED NOT NULL,
    seq         BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (account_id, record_id),
    UNIQUE KEY uq_vault_records_seq (seq),
    KEY idx_vault_records_account_seq (account_id, seq),
    CONSTRAINT fk_vault_records_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Single-row global counter for vault sequence numbers.
CREATE TABLE vault_counter (
    id    TINYINT UNSIGNED NOT NULL,
    value BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

INSERT INTO vault_counter (id, value) VALUES (1, 0);

CREATE TABLE phone_codes (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    phone       VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    code_hash   BINARY(32) NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (account_id),
    KEY idx_phone_codes_expires (expires_at),
    CONSTRAINT fk_phone_codes_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE recovery_challenges (
    challenge   BINARY(32) NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (challenge),
    KEY idx_recovery_challenges_account (account_id),
    KEY idx_recovery_challenges_expires (expires_at),
    CONSTRAINT fk_recovery_challenges_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
