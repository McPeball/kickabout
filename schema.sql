
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  pw_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  current_cookie TEXT NOT NULL,
  email_verification BOOLEAN NOT NULL DEFAULT 0
);

DROP TABLE IF EXISTS matches;

CREATE TABLE matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  competition TEXT,
  season INTEGER,
  matchday INTEGER,
  status TEXT,
  team_name TEXT,
  team_id INTEGER,
  result INTEGER,
  gd INTEGER,
  gf INTEGER,
  ga INTEGER,
  home_away TEXT
);
