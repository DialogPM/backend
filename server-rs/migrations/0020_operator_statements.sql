-- 20: statements signed by the operator (docs/API.md "Operator statements"): the badge of an
-- official account and notices shown in the apps. Each row keeps the signature made by an
-- admin key in the admin app; the apps verify it against the operator keys they pinned, so
-- the server stores and delivers these but cannot make them up.

-- label: what the badge says ("Dialog Support"). The signature also covers the account's
-- identity key at the time, so the badge does not survive a changed key.
CREATE TABLE IF NOT EXISTS operator_badges (
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    label       VARCHAR(80) NOT NULL,
    issued_at   BIGINT NOT NULL,
    signer      BINARY(32) NOT NULL,
    signature   BINARY(64) NOT NULL,
    PRIMARY KEY (account_id),
    CONSTRAINT fk_operator_badges_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- account_id NULL: for everyone.
CREATE TABLE IF NOT EXISTS operator_notices (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    title       VARCHAR(200) NOT NULL,
    body        TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    signer      BINARY(32) NOT NULL,
    signature   BINARY(64) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_operator_notices_account (account_id, id),
    CONSTRAINT fk_operator_notices_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
