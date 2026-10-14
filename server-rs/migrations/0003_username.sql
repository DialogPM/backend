-- Optional public username (lowercase), searchable in the directory.
ALTER TABLE accounts ADD COLUMN username VARCHAR(32) NULL, ADD UNIQUE KEY uq_accounts_username (username);
