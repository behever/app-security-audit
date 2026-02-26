# 🔒 App Security Audit — AI Agent Skill

Comprehensive security audit skill for AI coding agents. Point it at your project and get actionable findings across your entire stack.

## What It Covers

| Area | Checks |
|------|--------|
| **Supabase** | RLS policies, storage buckets, edge function JWT verification, service key exposure, realtime security |
| **Web Apps** | XSS, CORS, CSP headers, secret exposure in bundles, auth token storage, dependency vulnerabilities |
| **Mobile Apps** | Hardcoded secrets, secure storage (Keychain/Keystore), cert pinning, deep link validation, Expo/RN specifics |
| **Databases** | Connection security, least privilege, SQL injection vectors, backup encryption, parameterized queries |
| **APIs** | Auth on all endpoints, rate limiting, input validation, error leakage, OWASP Top 10 |

## Quick Start

### Automated Scanner (zero dependencies)

```bash
bash scripts/scan_project.sh /path/to/your/project
```

Outputs a categorized report: **CRITICAL** / **WARNING** / **INFO**

### As an AI Agent Skill

Install into your AI agent's skills directory:

```
skills/
└── app-security-audit/
    ├── SKILL.md
    ├── references/
    │   ├── supabase-security.md
    │   ├── web-app-security.md
    │   ├── mobile-app-security.md
    │   ├── database-security.md
    │   └── api-security.md
    └── scripts/
        └── scan_project.sh
```

Compatible with:
- [OpenClaw](https://github.com/nicobailey/openclaw)
- Claude Code / Codex CLI
- Any agent that reads SKILL.md files

## How It Works

1. **Automated scan** — `scan_project.sh` greps for common issues (exposed secrets, missing RLS, XSS patterns, weak CORS)
2. **Decision tree** — SKILL.md guides the agent to the right reference files based on your stack
3. **Deep dive** — Reference files contain specific grep patterns, SQL queries, and remediation steps
4. **Report** — Structured output with severity levels and fix recommendations

## Example Findings

```
🔴 CRITICAL: Service role key found in client code
   src/lib/api.js:12 — SUPABASE_SERVICE_ROLE_KEY exposed to browser

🟡 WARNING: Wildcard CORS in edge function
   supabase/functions/send-email/index.ts:3 — Access-Control-Allow-Origin: *

🔵 INFO: No rate limiting library detected
   Consider express-rate-limit, @upstash/ratelimit, or similar
```

## File Structure

| File | Lines | Purpose |
|------|-------|---------|
| `SKILL.md` | 242 | Core workflow, decision tree, report template |
| `references/supabase-security.md` | 400+ | RLS, storage, edge functions, realtime |
| `references/web-app-security.md` | 350+ | XSS, CORS, CSP, auth, deps |
| `references/mobile-app-security.md` | 300+ | Secure storage, cert pinning, deep links |
| `references/database-security.md` | 250+ | Access control, injection, encryption |
| `references/api-security.md` | 300+ | Auth, rate limiting, OWASP |
| `scripts/scan_project.sh` | 435 | Automated scanner, bash only |

## License

MIT — use it, fork it, improve it.
