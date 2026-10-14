-- 13: private groups (zkgroup, docs/ZKGROUP-DESIGN.md stage 2).
--
-- Nothing here names an account: members are UuidCiphertexts (account ids encrypted
-- deterministically with the group's secret parameters, which only members hold), titles and
-- rules are blobs encrypted by the clients. Requests are authorized by zkgroup auth credential
-- presentations, which tell the server the caller's ciphertext and nothing else.

-- id = GroupIdentifier (32 bytes, derived from the group's public parameters).
-- edit_access / members_access: who may change the attributes / add members (1 member, 2 admin).
CREATE TABLE groups_v2 (
    id              BINARY(32) NOT NULL,
    public_params   VARBINARY(128) NOT NULL,
    revision        BIGINT NOT NULL,
    attributes      MEDIUMBLOB NOT NULL,
    settings        BLOB NOT NULL,
    edit_access     TINYINT UNSIGNED NOT NULL,
    members_access  TINYINT UNSIGNED NOT NULL,
    created_at      BIGINT NOT NULL,
    updated_at      BIGINT NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- role: 1 member, 2 admin.
CREATE TABLE group_members_v2 (
    group_id        BINARY(32) NOT NULL,
    uid_ciphertext  VARBINARY(65) NOT NULL,
    role            TINYINT UNSIGNED NOT NULL,
    joined_revision BIGINT NOT NULL,
    PRIMARY KEY (group_id, uid_ciphertext),
    CONSTRAINT fk_group_members_v2_group FOREIGN KEY (group_id) REFERENCES groups_v2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Members invited by a member (they accept or decline with their own presentation).
CREATE TABLE group_pending_v2 (
    group_id        BINARY(32) NOT NULL,
    uid_ciphertext  VARBINARY(65) NOT NULL,
    role            TINYINT UNSIGNED NOT NULL,
    added_by        VARBINARY(65) NOT NULL,
    added_revision  BIGINT NOT NULL,
    PRIMARY KEY (group_id, uid_ciphertext),
    CONSTRAINT fk_group_pending_v2_group FOREIGN KEY (group_id) REFERENCES groups_v2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Change log: one row per revision. "change" is the JSON of the actions (ciphertexts and
-- encrypted blobs only), "signature" the server's zkgroup notary signature over it.
CREATE TABLE group_changes_v2 (
    group_id        BINARY(32) NOT NULL,
    revision        BIGINT NOT NULL,
    `change`        MEDIUMBLOB NOT NULL,
    signature       BINARY(64) NOT NULL,
    created_at      BIGINT NOT NULL,
    PRIMARY KEY (group_id, revision),
    CONSTRAINT fk_group_changes_v2_group FOREIGN KEY (group_id) REFERENCES groups_v2 (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
