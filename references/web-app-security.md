# Web App Security Reference

## Table of Contents
- [Auth Token Storage](#auth-token-storage)
- [XSS Vulnerabilities](#xss-vulnerabilities)
- [CORS Misconfiguration](#cors-misconfiguration)
- [Content Security Policy](#content-security-policy)
- [API Key Exposure](#api-key-exposure)
- [HTTPS Enforcement](#https-enforcement)
- [Sensitive Data in URLs](#sensitive-data-in-urls)
- [Dependency Vulnerabilities](#dependency-vulnerabilities)
- [Environment Variable Exposure](#environment-variable-exposure)
- [CSRF Protection](#csrf-protection)
- [Clickjacking Protection](#clickjacking-protection)

---

## Auth Token Storage

### Scan for Insecure Token Storage

```bash
# localStorage storing auth tokens
grep -rn 'localStorage\.setItem.*token\|localStorage\.setItem.*auth\|localStorage\.setItem.*jwt\|localStorage\.setItem.*session' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# sessionStorage (slightly better but still XSS-vulnerable)
grep -rn 'sessionStorage\.setItem.*token\|sessionStorage\.setItem.*auth' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# Storing tokens in cookies without httpOnly flag
grep -rn 'document\.cookie.*token\|document\.cookie.*auth\|document\.cookie.*jwt' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/
```

**Severity:** WARNING  
**Recommendation:** Use httpOnly, Secure, SameSite cookies for auth tokens. If using Supabase Auth, the default `@supabase/ssr` package handles this correctly with cookie storage.

**Note:** Supabase JS client stores the session in localStorage by default. For web apps, switch to cookie-based storage with `@supabase/ssr`:
```typescript
import { createBrowserClient } from '@supabase/ssr'
// This stores tokens in cookies instead of localStorage
```

---

## XSS Vulnerabilities

### Scan for Dangerous Patterns

```bash
# dangerouslySetInnerHTML (React)
grep -rn 'dangerouslySetInnerHTML' --include='*.ts' --include='*.tsx' --include='*.jsx' src/

# v-html (Vue)
grep -rn 'v-html' --include='*.vue' src/

# innerHTML assignment
grep -rn '\.innerHTML\s*=' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# document.write
grep -rn 'document\.write' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# eval usage
grep -rn '\beval\s*(' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# Unescaped template literals in DOM
grep -rn '\$\{.*\}.*innerHTML\|innerHTML.*\$\{' --include='*.ts' --include='*.js' src/
```

**Severity:** CRITICAL (if user input flows into any of these)  

**Remediation:**
- Use framework-provided text rendering (React auto-escapes JSX)
- If HTML rendering is required, sanitize with DOMPurify:
  ```typescript
  import DOMPurify from 'dompurify';
  const clean = DOMPurify.sanitize(dirtyHtml);
  ```
- Never pass user input to `eval()`, `Function()`, or `innerHTML`

---

## CORS Misconfiguration

### Scan for CORS Issues

```bash
# Wildcard CORS in server code
grep -rn "Access-Control-Allow-Origin.*\*" --include='*.ts' --include='*.js' --include='*.json' src/ server/ api/

# CORS configuration files
grep -rn 'cors\|CORS' --include='*.ts' --include='*.js' --include='*.json' src/ server/ api/ | head -20

# Next.js API routes
grep -rn 'Access-Control' --include='*.ts' --include='*.js' pages/api/ app/api/ 2>/dev/null

# Express CORS middleware
grep -rn "cors({" --include='*.ts' --include='*.js' src/ server/

# Vercel/Next.js headers config
grep -A5 'headers' next.config.* vercel.json 2>/dev/null
```

**Severity:** WARNING (CRITICAL if credentials: true + wildcard origin)

**Dangerous combination:**
```javascript
// NEVER: credentials + wildcard = browsers block this, but misconfig invites attacks
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Credentials', 'true');
```

**Correct pattern:**
```javascript
const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
const origin = req.headers.origin;
if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}
```

---

## Content Security Policy

### Check for CSP Headers

```bash
# Check next.config for CSP
grep -rn 'Content-Security-Policy\|contentSecurityPolicy\|CSP' next.config.* vercel.json 2>/dev/null

# Meta tag CSP
grep -rn 'Content-Security-Policy' --include='*.html' --include='*.tsx' --include='*.jsx' src/ public/

# Middleware setting CSP
grep -rn 'Content-Security-Policy' --include='*.ts' --include='*.js' middleware.* src/middleware.*
```

**Severity:** WARNING if missing entirely

**Minimum recommended CSP:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none';
```

**Key directives:**
| Directive | Purpose | Recommendation |
|-----------|---------|----------------|
| `default-src` | Fallback for all | `'self'` |
| `script-src` | JavaScript sources | `'self'` (avoid `'unsafe-inline'`, `'unsafe-eval'`) |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` (many frameworks need inline) |
| `connect-src` | XHR/fetch/WebSocket | `'self'` + API domains |
| `frame-ancestors` | Embedding protection | `'none'` (prevents clickjacking) |
| `img-src` | Image sources | `'self' data: https:` |

---

## API Key Exposure

### Scan for Exposed Keys

```bash
# Generic API key patterns in source
grep -rn 'api[_-]key\|apiKey\|API_KEY' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/ | grep -v 'process\.env\|import\.meta\.env\|NEXT_PUBLIC\|VITE_'

# Hardcoded keys (common patterns)
grep -rn "sk_live_\|sk_test_\|pk_live_\|pk_test_" --include='*.ts' --include='*.tsx' --include='*.js' src/
grep -rn "AKIA[0-9A-Z]{16}" --include='*.ts' --include='*.tsx' --include='*.js' src/  # AWS
grep -rn "AIza[0-9A-Za-z_-]{35}" --include='*.ts' --include='*.tsx' --include='*.js' src/  # Google

# Check build output for leaked env vars
grep -rn 'SUPABASE_SERVICE_ROLE\|DATABASE_URL\|PRIVATE_KEY\|SECRET_KEY' dist/ build/ .next/ out/ 2>/dev/null

# Check for keys in NEXT_PUBLIC_ that shouldn't be public
grep -rn 'NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*PRIVATE\|NEXT_PUBLIC_.*SERVICE_ROLE' --include='*.ts' --include='*.env*' .
```

**Severity:** CRITICAL  

**Rules:**
- Only `NEXT_PUBLIC_*` / `VITE_*` env vars are client-safe (they get bundled)
- Supabase anon key = OK to be public (it's designed for it)
- Supabase service role key = NEVER public
- Stripe `pk_*` = OK public, `sk_*` = NEVER public
- Any `SECRET`, `PRIVATE`, or `PASSWORD` in client code = CRITICAL

---

## HTTPS Enforcement

### Check Configuration

```bash
# Check for HTTP URLs in source (should be HTTPS)
grep -rn "http://" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.env*' src/ | grep -v 'localhost\|127\.0\.0\.1\|http://\*'

# Check for HSTS header
grep -rn 'Strict-Transport-Security' next.config.* vercel.json middleware.* 2>/dev/null

# Check for secure cookie flags
grep -rn 'secure.*true\|Secure' --include='*.ts' --include='*.js' src/ server/
```

**Severity:** WARNING  

**Recommended HSTS header:**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## Sensitive Data in URLs

### Scan for Leaked Data

```bash
# Tokens/keys in URL params
grep -rn 'token=\|key=\|secret=\|password=\|api_key=' --include='*.ts' --include='*.tsx' --include='*.js' src/ | grep -v 'test\|mock\|example'

# URL construction with sensitive data
grep -rn '`.*\?.*token\|`.*\?.*key\|`.*\&.*secret' --include='*.ts' --include='*.tsx' src/

# Query params in navigation
grep -rn 'router\.push.*token\|navigate.*token\|href.*token=' --include='*.ts' --include='*.tsx' src/
```

**Severity:** WARNING  

**Why it matters:** URLs end up in browser history, server logs, referrer headers, and analytics. Never put auth tokens, API keys, or PII in URLs.

---

## Dependency Vulnerabilities

### Automated Scanning

```bash
# npm audit
cd /path/to/project && npm audit 2>/dev/null

# Check for outdated packages with known vulns
npm audit --json 2>/dev/null | jq '.vulnerabilities | to_entries[] | select(.value.severity == "critical" or .value.severity == "high") | {name: .key, severity: .value.severity, via: .value.via[0]}' 2>/dev/null

# Yarn
cd /path/to/project && yarn audit 2>/dev/null

# pnpm
cd /path/to/project && pnpm audit 2>/dev/null
```

**Severity:** Varies (CRITICAL for known exploits, INFO for low-severity)

### Manual Checks

```bash
# Check for known vulnerable packages
grep -E '"node-fetch"|"minimist"|"qs"|"lodash"' package.json
# These have had critical CVEs — ensure they're on patched versions

# Check for deprecated auth packages
grep -E '"passport-local"|"express-session"' package.json
```

---

## Environment Variable Exposure

### Scan for Leaked .env Files

```bash
# .env files in public directories
find . -path '*/public/.env*' -o -path '*/dist/.env*' -o -path '*/build/.env*' -o -path '*/out/.env*' 2>/dev/null

# .env files not in .gitignore
git ls-files --cached '*.env' '*.env.*' 2>/dev/null | grep -v '.env.example\|.env.local.example'

# Check .gitignore includes .env patterns
grep '\.env' .gitignore 2>/dev/null || echo "WARNING: No .env pattern in .gitignore"

# Environment variables hardcoded in source
grep -rn "DATABASE_URL\|POSTGRES_PASSWORD\|JWT_SECRET\|ENCRYPTION_KEY" --include='*.ts' --include='*.tsx' --include='*.js' src/ | grep -v 'process\.env\|import\.meta\.env'
```

**Severity:** CRITICAL (if secrets found in tracked/public files)

---

## CSRF Protection

### Scan for CSRF Vulnerabilities

```bash
# Check for CSRF token usage
grep -rn 'csrf\|CSRF\|xsrf\|XSRF' --include='*.ts' --include='*.tsx' --include='*.js' src/ server/

# Forms without CSRF tokens
grep -rn '<form' --include='*.tsx' --include='*.jsx' --include='*.html' src/ | head -10

# Check SameSite cookie attribute
grep -rn 'SameSite\|sameSite' --include='*.ts' --include='*.js' src/ server/
```

**Severity:** WARNING  

**Mitigations:**
- SameSite=Lax cookies (default in modern browsers)
- CSRF tokens for state-changing forms
- Verify Origin/Referer headers on server

---

## Clickjacking Protection

### Check Headers

```bash
# X-Frame-Options header
grep -rn 'X-Frame-Options\|frame-options' next.config.* vercel.json middleware.* 2>/dev/null

# CSP frame-ancestors directive (modern replacement)
grep -rn 'frame-ancestors' next.config.* vercel.json middleware.* 2>/dev/null
```

**Severity:** WARNING if missing  

**Recommended:**
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none';
```
