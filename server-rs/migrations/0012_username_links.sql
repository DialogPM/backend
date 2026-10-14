-- 12: username links (QR / shareable link that carries no account number).
-- The client encrypts its username with a random key that lives only in the link
-- fragment; the server stores the ciphertext under a random handle and never sees the key.
-- Resetting the link replaces the handle, so old links stop resolving.
CREATE TABLE username_links (
    handle             CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id         CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    encrypted_username VARBINARY(128) NOT NULL,
    created_at         BIGINT NOT NULL,
    PRIMARY KEY (handle),
    UNIQUE KEY uq_username_links_account (account_id),
    CONSTRAINT fk_username_links_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
