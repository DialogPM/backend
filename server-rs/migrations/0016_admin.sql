-- 16: admin API (docs/ADMIN-API.md): runtime settings, daily counters and moderation details.

-- Settings changed through PUT /v1/admin/settings; they override the environment at startup.
-- value: JSON (true, 20, ...).
CREATE TABLE IF NOT EXISTS admin_settings (
    name        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    value       VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Daily counters (GET /v1/admin/stats), so statistics never scan the large tables.
-- day: days since 1970-01-01 (UTC); metric: registrations, new_devices, envelopes_sent,
-- attachments_uploaded. Only aggregate numbers, nothing about who did what.
CREATE TABLE IF NOT EXISTS daily_stats (
    day     INT NOT NULL,
    metric  VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    value   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (day, metric)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- History before this migration, from what the tables still hold (account_numbers keeps
-- every number ever issued; devices and attachments only the current ones).
INSERT IGNORE INTO daily_stats (day, metric, value)
    SELECT created_at DIV 86400000, 'registrations', COUNT(*) FROM account_numbers GROUP BY created_at DIV 86400000;
INSERT IGNORE INTO daily_stats (day, metric, value)
    SELECT created_at DIV 86400000, 'new_devices', COUNT(*) FROM devices GROUP BY created_at DIV 86400000;
INSERT IGNORE INTO daily_stats (day, metric, value)
    SELECT uploaded_at DIV 86400000, 'attachments_uploaded', COUNT(*) FROM attachments
    WHERE state = 2 AND uploaded_at IS NOT NULL GROUP BY uploaded_at DIV 86400000;

-- Why an account was banned (admin API); the index serves the overview counts of new
-- accounts. One ALTER per table keeps each change atomic.
ALTER TABLE accounts
    ADD COLUMN ban_reason VARCHAR(500) NULL,
    ADD KEY idx_accounts_created (created_at);

-- The optional reason a reporter gave, and how an admin resolved the report.
ALTER TABLE spam_reports
    ADD COLUMN reason VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN resolution VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    ADD COLUMN resolution_note VARCHAR(500) NULL,
    ADD KEY idx_spam_reports_resolved (resolved_at, updated_at);

-- Overview counts of devices active in the last 24 h / 7 days.
ALTER TABLE devices ADD KEY idx_devices_last_seen (last_seen_at);
