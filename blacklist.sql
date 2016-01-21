PRAGMA user_version = 30; /* Tizen 3.0 */
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE blacklist_index (
  pkgid TEXT UNIQUE,
  idx   INTEGER PRIMARY KEY,
  ref   INTEGER NOT NULL
);

CREATE TABLE blacklist (
  uid INTEGER NOT NULL,
  idx INTEGER NOT NULL,
  UNIQUE (uid, idx)
);

CREATE TRIGGER delete_blacklist AFTER DELETE ON blacklist
BEGIN
  UPDATE blacklist_index SET ref = ref - 1 WHERE idx = OLD.idx;
END;

CREATE TRIGGER update_blacklist_index AFTER UPDATE ON blacklist_index
WHEN ((SELECT ref FROM blacklist_index WHERE idx = OLD.idx) = 0)
BEGIN
  DELETE FROM blacklist_index WHERE idx = OLD.idx;
END;
