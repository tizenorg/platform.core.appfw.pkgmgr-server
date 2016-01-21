PRAGMA user_version = 30; /* Tizen 3.0 */
PRAGMA journal_mode = WAL;

CREATE TABLE blacklist (
  uid   INTEGER NOT NULL,
  pkgid TEXT NOT NULL,
  UNIQUE (uid, pkgid)
);
