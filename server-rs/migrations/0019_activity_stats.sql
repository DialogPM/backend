-- 19: daily activity statistics for the admin API (docs/ADMIN-API.md): accounts active per
-- day, in total and per country. Only totals are kept (table daily_stats); nothing about
-- where an account connects from is stored on the account.
-- stats_day: the day (days since 1970-01-01, UTC) this account was last counted as active,
-- so that it is counted once a day however often it reconnects.
ALTER TABLE accounts ADD COLUMN stats_day INT NULL;
