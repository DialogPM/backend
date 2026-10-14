-- Sealed sender: 16-byte key derived from the account's profile key. Whoever knows it (the
-- account's contacts) may deliver messages without identifying themselves.
ALTER TABLE accounts ADD COLUMN unidentified_access_key VARBINARY(16) NULL;
