import { Router, Request, Response } from "express";
import { db } from "../db";
import * as fs from "fs";
import * as path from "path";

export const usersRouter = Router();

// VULNERABLE: SQL Injection (CWE-89)
// User-controlled `username` is concatenated directly into the SQL string
// instead of using a parameterized query / prepared statement.
usersRouter.get("/search", (req: Request, res: Response) => {
  const username = req.query.username as string;
  const query = "SELECT id, username, email FROM users WHERE username = '" + username + "'";

  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// VULNERABLE: Reflected XSS (CWE-79)
// Untrusted query parameter is written straight into the HTML response
// without encoding, so a script tag in `name` executes in the victim's browser.
usersRouter.get("/greet", (req: Request, res: Response) => {
  const name = req.query.name as string;
  res.send("<h1>Welcome, " + name + "!</h1>");
});

// VULNERABLE: Broken Access Control / Insecure Direct Object Reference (CWE-639)
// Any authenticated-looking request can fetch or promote any user id with no
// ownership or role check on the caller.
usersRouter.post("/:id/promote", (req: Request, res: Response) => {
  const id = req.params.id;
  db.run("UPDATE users SET is_admin = 1 WHERE id = " + id, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ ok: true });
  });
});

// VULNERABLE: Path Traversal (CWE-22)
// `format` is trusted to be a safe file extension and joined into a path
// under the exports directory with no containment check, so a value like
// "../../../../etc/passwd%00" (or just "../secrets/config") can read files
// outside the intended export directory.
//
// VULNERABLE: Broken Access Control (CWE-639)
// Any caller can export any user id's profile with no session/ownership
// check tying the request to the `id` being exported.
usersRouter.get("/:id/export", (req: Request, res: Response) => {
  const id = req.params.id;
  const format = req.query.format as string;
  const exportDir = path.join(__dirname, "..", "..", "exports");
  const exportPath = path.join(exportDir, `${id}.${format}`);

  fs.readFile(exportPath, (err, data) => {
    if (err) {
      return res.status(404).json({ error: "export not found" });
    }
    res.send(data);
  });
});
