-- 14: key transparency (docs/KEY-TRANSPARENCY.md): an append-only Merkle log of every
-- account's identity key. Clients verify inclusion proofs for the keys they are served,
-- consistency proofs between the signed tree heads they see, and monitor their own entry.

-- Log entries, in log order. `idx` is contiguous from 0 (assigned under the kt_state row
-- lock by the sequencer, never by AUTO_INCREMENT, which can leave gaps). Rows are never
-- updated or deleted, also not when the account is deleted. The leaf hash is recomputed
-- from the row, never stored.
CREATE TABLE kt_leaves (
    idx           BIGINT NOT NULL,
    account_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    identity_key  VARBINARY(64) NOT NULL,
    created_at    BIGINT NOT NULL,
    PRIMARY KEY (idx),
    KEY idx_kt_leaves_account (account_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Single row: the log size (serializes the sequencer).
CREATE TABLE kt_state (
    id    TINYINT NOT NULL,
    size  BIGINT NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO kt_state (id, size) VALUES (1, 0);
