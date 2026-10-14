-- Group-wide rules set by the admins: the disappearing-messages timer, whether members see
-- the member list (or only how many there are), and how members are named ("number" shows
-- account numbers, "first_name" requires a profile name and shows only its first word).
ALTER TABLE chat_groups
  ADD COLUMN disappearing_seconds INT NOT NULL DEFAULT 0,
  ADD COLUMN hide_members BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN member_names VARCHAR(16) NOT NULL DEFAULT 'number';
