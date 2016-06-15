PRAGMA journal_mode = WAL;

CREATE TABLE restriction (
  uid   INTEGER NOT NULL,
  pkgid TEXT NOT NULL,
  mode  INTEGER NOT NULL,
  UNIQUE (uid, pkgid)
);
