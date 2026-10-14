-- 10: account security: encrypted device names, approval of new logins, spam reports,
-- registration proof-of-work, username reservations and group bans.

-- Device name encrypted by the client with a key derived from the account key (only the
-- account's own devices can read it). When set, "name" holds only a generic placeholder.
ALTER TABLE devices ADD COLUMN name_enc VARBINARY(512) NULL;

-- "Require approval for new logins": a password login must be approved by an existing device.
ALTER TABLE accounts ADD COLUMN login_approval TINYINT(1) NOT NULL DEFAULT 0;

-- Password logins waiting for approval. The requester polls with the secret (stored hashed);
-- the device is created only once an existing device approved. status: 0 pending,
-- 1 approved, 2 denied. "name" is what the approving device is shown (it may be the real
-- device name; the row lives at most 10 minutes), "device_name" what the device row gets.
CREATE TABLE login_requests (
    id              CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    secret_hash     BINARY(32) NOT NULL,
    name            VARCHAR(128) NOT NULL,
    device_name     VARCHAR(128) NOT NULL,
    platform        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    registration_id INT UNSIGNED NOT NULL,
    status          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_at      BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    PRIMARY KEY (id),
    KEY idx_login_requests_account (account_id),
    KEY idx_login_requests_expires (expires_at),
    CONSTRAINT fk_login_requests_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Spam reports for admin review (one row per reporter and reported account; repeated reports
-- update it). envelope_ids: JSON array of server envelope ids the reporter chose to include.
CREATE TABLE spam_reports (
    reporter_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    reported_id   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    envelope_ids  TEXT CHARACTER SET ascii COLLATE ascii_bin NULL,
    report_count  INT UNSIGNED NOT NULL DEFAULT 1,
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    PRIMARY KEY (reporter_id, reported_id),
    KEY idx_spam_reports_reported (reported_id, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Single-use proof-of-work challenges for registration.
CREATE TABLE registration_challenges (
    challenge   BINARY(32) NOT NULL,
    difficulty  TINYINT UNSIGNED NOT NULL,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (challenge),
    KEY idx_registration_challenges_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- A released (changed, removed or deleted-account) username stays reserved for its previous
-- owner until expires_at, so nobody else can take it over right away.
CREATE TABLE username_reservations (
    username    VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at  BIGINT NOT NULL,
    PRIMARY KEY (username),
    KEY idx_username_reservations_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Accounts an admin removed from a group (or whose join request was rejected): they cannot
-- join again by invite link or send new join requests. Re-adding the member clears the ban.
CREATE TABLE group_bans (
    group_id    CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    banned_by   CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    banned_at   BIGINT NOT NULL,
    PRIMARY KEY (group_id, account_id),
    KEY idx_group_bans_account (account_id),
    CONSTRAINT fk_group_bans_group FOREIGN KEY (group_id) REFERENCES chat_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
