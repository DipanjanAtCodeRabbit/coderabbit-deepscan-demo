import { Router, Request, Response } from "express";
import { exec } from "child_process";
import * as fs from "fs";
import * as path from "path";

export const filesRouter = Router();

const UPLOAD_DIR = path.join(__dirname, "..", "..", "uploads");

// VULNERABLE: Path Traversal (CWE-22)
// `filename` is joined into a filesystem path without validating that the
// resolved path stays inside UPLOAD_DIR, so "../../etc/passwd" escapes it.
filesRouter.get("/download", (req: Request, res: Response) => {
  const filename = req.query.filename as string;
  const filePath = path.join(UPLOAD_DIR, filename);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).json({ error: "not found" });
    }
    res.send(data);
  });
});

// VULNERABLE: OS Command Injection (CWE-78)
// User input is interpolated into a shell command executed via `exec`,
// allowing shell metacharacters (e.g. "; rm -rf /") to run arbitrary commands.
filesRouter.get("/convert", (req: Request, res: Response) => {
  const filename = req.query.filename as string;
  exec("convert /tmp/uploads/" + filename + " /tmp/uploads/out.png", (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: stderr });
    }
    res.json({ ok: true, stdout });
  });
});
