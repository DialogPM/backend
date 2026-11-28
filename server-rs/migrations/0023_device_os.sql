-- 23: the operating system of a desktop device, for the admin statistics per platform
-- (docs/ADMIN-API.md, GET /v1/admin/platforms). `platform` already tells Android and iOS
-- apart; a desktop app says at connection which of windows, macos, linux it runs on. Only
-- that word is kept: no version, no model. NULL: not said yet (an app older than this).
ALTER TABLE devices ADD COLUMN os VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NULL;
