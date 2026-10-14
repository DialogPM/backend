-- 11: moderation by the operator (admin CLI: `chatserver reports ...`).

-- Short numeric id for spam reports (the admin CLI refers to reports by it), and when an
-- admin resolved the report (NULL = open; a new report from the same reporter reopens it).
ALTER TABLE spam_reports
    ADD COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ADD UNIQUE KEY uq_spam_reports_id (id),
    ADD COLUMN resolved_at BIGINT NULL;

-- Banned accounts: the server rejects their tokens and refuses to create new devices for them;
-- the maintenance job closes their open WebSockets.
ALTER TABLE accounts
    ADD COLUMN banned_at BIGINT NULL,
    ADD KEY idx_accounts_banned (banned_at);
