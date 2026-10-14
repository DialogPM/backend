-- Group invite links. The link carries a secret that never reaches the server: the server
-- stores a hash of the token derived from it, whether admins approve new members, and an
-- opaque blob (encrypted with another key derived from the secret) that previews the group.
CREATE TABLE group_invites (
    group_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token_hash  BINARY(32) NOT NULL,
    approval    BOOLEAN NOT NULL DEFAULT FALSE,
    preview     MEDIUMBLOB NOT NULL,
    created_by  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (group_id),
    UNIQUE KEY uq_group_invites_token (token_hash),
    CONSTRAINT fk_group_invites_group FOREIGN KEY (group_id) REFERENCES chat_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Requests to join a group whose link requires admin approval. "intro" is opaque to the
-- server (the requester's name and profile key, encrypted with the link's blob key).
CREATE TABLE group_join_requests (
    group_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    intro         BLOB NULL,
    requested_at  BIGINT NOT NULL,
    PRIMARY KEY (group_id, account_id),
    KEY idx_group_join_requests_account (account_id),
    CONSTRAINT fk_group_join_requests_group FOREIGN KEY (group_id) REFERENCES chat_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_group_join_requests_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
