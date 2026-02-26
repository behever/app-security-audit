# 🔒 App Security Audit

A security scanner and AI agent skill that audits your web app, Supabase project, database, mobile app, or API for common vulnerabilities.

**Two ways to use it:**
1. **Standalone scanner** — Run the bash script directly on any project (zero dependencies)
2. **AI agent skill** — Drop it into Claude Code, OpenClaw, Codex CLI, or any AI agent that reads SKILL.md files for a guided, thorough audit

---

## Option 1: Just Run the Scanner (No AI Required)

The scanner is a standalone bash script. No installs, no dependencies — just bash and grep.

```bash
# Clone it
git clone https://github.com/behever/app-security-audit.git

# Run it on your project
bash app-security-audit/scripts/scan_project.sh /path/to/your/project
```

That's it. You'll get a report like this:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔒 App Security Audit Scanner
  Project: my-app
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

── 1. HARDCODED SECRETS ──

── 2. ENVIRONMENT VARIABLE EXPOSURE ──

── 3. XSS VULNERABILITIES ──
🔴 CRITICAL: dangerouslySetInnerHTML found
   src/components/Comment.tsx:42

── 5. CORS CONFIGURATION ──
🟡 WARNING: Wildcard CORS origin (*) found
   api/middleware.ts:8

── 7. API SECURITY ──
🟡 WARNING: No rate limiting library detected

  📊 SCAN SUMMARY
  CRITICAL: 1
  WARNING:  2
  INFO:     4
```

### What the Scanner Checks

| Check | What It Looks For |
|-------|-------------------|
| **Hardcoded secrets** | API keys, passwords, tokens committed to source |
| **Env exposure** | `.env` files in public/dist directories |
| **XSS** | `dangerouslySetInnerHTML`, unsanitized inputs |
| **Auth tokens** | Secrets stored in `localStorage` instead of secure cookies |
| **CORS** | Wildcard `Access-Control-Allow-Origin: *` |
| **Supabase RLS** | Tables without Row Level Security enabled |
| **Bare auth.uid()** | Unoptimized RLS policies (should use `(select auth.uid())`) |
| **Validation** | Missing input validation libraries (zod, yup, joi) |
| **Rate limiting** | Missing rate limiting on API endpoints |
| **Dependencies** | Runs `npm audit` for known vulnerabilities |
| **Mobile** | Hardcoded secrets, insecure storage in React Native/Expo |

---

## Option 2: Use as an AI Agent Skill

If you use an AI coding agent (Claude Code, OpenClaw, Codex CLI, etc.), you can install this as a **skill** — a knowledge package that teaches the AI how to do thorough security audits on your behalf.

### What's a Skill?

A skill is a folder with a `SKILL.md` file that AI agents read to learn specialized workflows. Instead of just running a grep scanner, the AI will:

- Read the detailed reference guides for your specific stack
- Inspect your actual code, RLS policies, and auth implementation
- Run the automated scanner AND do manual deep-dive analysis
- Generate a prioritized report with specific fix recommendations
- Optionally fix the issues for you

### Installation

**For Claude Code / Codex CLI:**
```bash
# Clone into your project's skills directory
git clone https://github.com/behever/app-security-audit.git .claude/skills/app-security-audit

# Or wherever your agent reads skills from
git clone https://github.com/behever/app-security-audit.git skills/app-security-audit
```

**For OpenClaw:**
```bash
# Clone into your OpenClaw skills directory
git clone https://github.com/behever/app-security-audit.git ~/clawd/skills/app-security-audit
```

Then just ask your AI agent: **"Run a security audit on this project"** — it will find the skill and follow the workflow.

### What the AI Gets (That the Scanner Doesn't)

The skill includes 5 detailed reference guides the AI reads based on your stack:

| Reference File | When It's Used | What It Covers |
|---|---|---|
| `references/supabase-security.md` | Supabase projects | RLS policies, storage buckets, edge function JWT verification, service key exposure, realtime channels |
| `references/web-app-security.md` | Web apps | XSS patterns, CORS config, CSP headers, auth token storage, dependency auditing |
| `references/mobile-app-security.md` | React Native / Expo | Secure storage (Keychain/Keystore), cert pinning, deep link validation, OTA update security |
| `references/database-security.md` | Any database | Connection security, least privilege, SQL injection, backup encryption |
| `references/api-security.md` | APIs / backends | Auth on endpoints, rate limiting, input validation, error leakage, OWASP Top 10 |

The AI reads only the guides relevant to your stack, so it doesn't waste context on things you don't use.

---

## File Structure

```
app-security-audit/
├── SKILL.md                              # AI agent instructions (workflow + decision tree)
├── scripts/
│   └── scan_project.sh                   # Standalone scanner (run directly, no deps)
└── references/
    ├── supabase-security.md              # Supabase-specific checks
    ├── web-app-security.md               # Web app security checks
    ├── mobile-app-security.md            # Mobile app security checks
    ├── database-security.md              # Database security checks
    └── api-security.md                   # API security checks
```

## Examples

### Audit a Next.js + Supabase project
```bash
bash scripts/scan_project.sh ~/my-saas-app
```

### Audit just your Supabase edge functions
```bash
bash scripts/scan_project.sh ~/my-app/supabase
```

### Ask your AI agent for a full audit
> "Run the security audit skill on this project. Focus on Supabase RLS and the API endpoints."

### Ask your AI agent to fix what it finds
> "Audit this project for security issues and fix anything critical."

---

## Contributing

Found a check that's missing? PRs welcome. The scanner is intentionally simple (bash + grep) so it runs anywhere without setup.

## License

MIT — use it, fork it, improve it.
