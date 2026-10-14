-- Two-step verification (TOTP). Secrets are encrypted at rest (AES-GCM, key derived from the
-- server secret); totp_last_step prevents replaying a code.
ALTER TABLE accounts
  ADD COLUMN totp_secret VARBINARY(128) NULL,
  ADD COLUMN totp_pending VARBINARY(128) NULL,
  ADD COLUMN totp_last_step BIGINT NOT NULL DEFAULT 0;
