import { Router, Request, Response } from "express";
import jwt from "jsonwebtoken";

export const adminRouter = Router();

// VULNERABLE: Hardcoded Secret (CWE-798)
// A real signing secret should come from a secret manager / typed env module,
// never be committed to source control.
const JWT_SECRET = "super-secret-signing-key-2024";

// VULNERABLE: Server-Side Request Forgery (CWE-918)
// The caller fully controls the outbound URL, including scheme and host, with
// no allowlist, so this endpoint can be used to probe internal/cloud metadata
// services (e.g. http://169.254.169.254/...).
adminRouter.get("/fetch-webhook", async (req: Request, res: Response) => {
  const target = req.query.url as string;
  const response = await fetch(target);
  const body = await response.text();
  res.send(body);
});

// VULNERABLE: Insecure Deserialization / Code Injection via eval (CWE-95)
// Running `eval` on client-supplied input allows arbitrary JS execution on
// the server.
adminRouter.post("/run-rule", (req: Request, res: Response) => {
  const { expression } = req.body as { expression: string };
  // eslint-disable-next-line no-eval
  const result = eval(expression);
  res.json({ result });
});

adminRouter.post("/login", (req: Request, res: Response) => {
  const { username, password } = req.body as { username: string; password: string };

  // VULNERABLE: Hardcoded credential check (CWE-798) alongside a weak,
  // algorithm-confusable JWT usage (no expiry, symmetric secret above).
  if (username === "admin" && password === "admin123") {
    const token = jwt.sign({ username, role: "admin" }, JWT_SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: "invalid credentials" });
});
