-- 22: automatic deletion of inactive accounts (docs/API.md, "Inactive account deletion").
--
-- inactive_delete_days: the account is deleted once none of its devices connected for this
-- many days (the user's choice: 30, 60, 90, 365, 730, 1095 or 1825); 0 = never.
-- last_active_at: the last time a device of the account authenticated (kept on the account,
-- so it survives the removal of the account's last device).
ALTER TABLE accounts
    ADD COLUMN inactive_delete_days INT NOT NULL DEFAULT 365,
    ADD COLUMN last_active_at BIGINT NOT NULL DEFAULT 0,
    ADD KEY idx_accounts_last_active (last_active_at);

-- Existing accounts: their real last activity (the newest of their devices' last connection,
-- their own last seen and their creation). An account that would be due at once, or within
-- 30 days of this migration, gets those 30 days first: nothing is deleted the moment the
-- server is upgraded.
UPDATE accounts a SET a.last_active_at = GREATEST(
    a.created_at,
    COALESCE(a.last_seen_at, 0),
    COALESCE((SELECT MAX(d.last_seen_at) FROM devices d WHERE d.account_id = a.id), 0),
    (UNIX_TIMESTAMP() - 335 * 86400) * 1000
);

-- Restoring an account deleted for inactivity (POST /v1/auth/recover with its number and
-- recovery phrase gives back the same number, account id and identity). Its row here, which
-- already keeps the number and the account id for good, then also keeps the two public keys
-- the restore is checked against; they are cleared when the account is restored. Accounts
-- deleted by their user (DELETE /v1/account) keep NULL here and cannot be restored.
ALTER TABLE account_numbers
    ADD COLUMN recovery_public_key BINARY(32) NULL,
    ADD COLUMN identity_key VARBINARY(64) NULL;

-- Recovery challenges of deleted accounts (recovery_challenges needs a live account).
CREATE TABLE IF NOT EXISTS account_restore_challenges (
    challenge   BINARY(32) NOT NULL,
    number      CHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (challenge),
    KEY idx_account_restore_challenges_number (number),
    KEY idx_account_restore_challenges_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
