-- 21: bots (docs/API.md section 22). A bot belongs to the account that created it and is
-- driven from outside with its token (the Bot API). Its messages are not end-to-end
-- encrypted: the server receives them as text from the bot's script.
CREATE TABLE IF NOT EXISTS bots (
    id                CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    owner_account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    username          VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    name              VARCHAR(64) NOT NULL,
    about             VARCHAR(512) NOT NULL DEFAULT '',
    commands          TEXT NOT NULL,
    token_hash        BINARY(32) NOT NULL,
    disabled_at       BIGINT NULL,
    created_at        BIGINT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_bots_username (username),
    UNIQUE KEY uq_bots_token (token_hash),
    KEY idx_bots_owner (owner_account_id),
    CONSTRAINT fk_bots_owner FOREIGN KEY (owner_account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- One row per (bot, account that ever started it). chat_id is what the bot sees instead of
-- the account id: random and different for every bot, so two bots cannot tell they talk to
-- the same person. A bot can send only while active = 1.
CREATE TABLE IF NOT EXISTS bot_chats (
    bot_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    account_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    chat_id     CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    active      TINYINT NOT NULL,
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (bot_id, account_id),
    UNIQUE KEY uq_bot_chats_chat (chat_id),
    KEY idx_bot_chats_account (account_id),
    CONSTRAINT fk_bot_chats_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE,
    CONSTRAINT fk_bot_chats_account FOREIGN KEY (account_id) REFERENCES accounts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- What the bot's script has not collected yet (getUpdates): messages people sent it, and
-- chats that were stopped.
CREATE TABLE IF NOT EXISTS bot_updates (
    update_id   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    bot_id      CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    chat_id     CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    kind        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    message_id  CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NULL,
    body        TEXT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (update_id),
    KEY idx_bot_updates_bot (bot_id, update_id),
    KEY idx_bot_updates_created (created_at),
    CONSTRAINT fk_bot_updates_bot FOREIGN KEY (bot_id) REFERENCES bots (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
