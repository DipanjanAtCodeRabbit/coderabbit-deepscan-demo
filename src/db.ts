import sqlite3 from "sqlite3";

export const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, is_admin INTEGER)"
  );
  db.run(
    "INSERT INTO users (username, password, email, is_admin) VALUES ('alice', 'password123', 'alice@example.com', 0)"
  );
  db.run(
    "INSERT INTO users (username, password, email, is_admin) VALUES ('admin', 'admin123', 'admin@example.com', 1)"
  );
});
