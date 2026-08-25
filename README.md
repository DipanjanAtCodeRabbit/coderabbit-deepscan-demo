# CodeRabbit DeepScan Demo

This repository is a **deliberately vulnerable** Node.js/TypeScript sample application. Its
only purpose is to demonstrate what [CodeRabbit's DeepScan](https://docs.coderabbit.ai/)
security feature flags when it reviews a pull request. **Do not deploy this code or reuse
any snippet from it in a real project.**

## How to use this demo

1. Fork or clone this repo and connect it to CodeRabbit (install the CodeRabbit GitHub App
   on the repo, or add the repo to your CodeRabbit org).
2. Open a pull request that touches any file under `src/` (e.g. branch from `main`, make a
   trivial change, and open a PR back to `main`).
3. Let CodeRabbit review the PR. DeepScan should surface findings for each vulnerability
   class listed below, with the relevant CWE identifier and a suggested fix.

## Vulnerability classes included

| File | Vulnerability | CWE |
| --- | --- | --- |
| `src/routes/users.ts` (`/users/search`) | SQL Injection via string-concatenated query | CWE-89 |
| `src/routes/users.ts` (`/users/greet`) | Reflected XSS via unescaped HTML output | CWE-79 |
| `src/routes/users.ts` (`/users/:id/promote`) | Broken access control / IDOR (no auth/role check) | CWE-639 |
| `src/routes/files.ts` (`/files/download`) | Path traversal via unsanitized filename | CWE-22 |
| `src/routes/files.ts` (`/files/convert`) | OS command injection via `exec` | CWE-78 |
| `src/routes/admin.ts` (`/admin/fetch-webhook`) | Server-side request forgery (unbounded outbound URL) | CWE-918 |
| `src/routes/admin.ts` (`/admin/run-rule`) | Arbitrary code execution via `eval` | CWE-95 |
| `src/routes/admin.ts` (top-level constant + `/admin/login`) | Hardcoded secret / hardcoded credentials | CWE-798 |

Each vulnerable line is annotated in-code with a `// VULNERABLE:` comment explaining the
flaw and its CWE, so the demo is easy to narrate even without CodeRabbit's output open
side-by-side.

## Project layout

```
src/
  server.ts          # Express app entrypoint, mounts the three routers below
  db.ts              # In-memory SQLite seed data (fake users, one marked admin)
  routes/
    users.ts          # SQL injection, XSS, broken access control
    files.ts           # Path traversal, command injection
    admin.ts           # SSRF, eval/code injection, hardcoded secrets
```

## Running locally (not required for the demo)

```bash
npm install
npm start
```

The app listens on port 3000. Since every route above is intentionally exploitable, only
run it in an isolated sandbox, never on a machine or network you care about.

## What to expect from DeepScan

DeepScan performs deep, cross-file security analysis (as opposed to purely syntactic
lint rules), so on the PR it should:

- Flag each vulnerable sink above with a severity and CWE mapping.
- Trace tainted input from the HTTP request (`req.query`, `req.params`, `req.body`) to the
  vulnerable sink (SQL query, `exec`, `fetch`, `eval`, filesystem path).
- Suggest a concrete remediation, e.g. parameterized queries for `users/search`, an
  allowlist/`path.resolve` containment check for `files/download`, avoiding `eval` in
  `admin/run-rule`, and moving the JWT secret to the environment/secret manager.

## License

This code exists solely for security-tooling demonstrations. Provided as-is, with no
warranty, under the MIT License.
