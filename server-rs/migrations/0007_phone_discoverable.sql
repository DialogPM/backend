-- Verified phone numbers are findable through phone contacts by default (they were opt-in).
UPDATE accounts SET discoverable_by_phone = 1 WHERE phone IS NOT NULL;
