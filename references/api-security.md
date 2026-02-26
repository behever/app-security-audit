# API Security Reference

## Table of Contents
- [Authentication on Endpoints](#authentication-on-endpoints)
- [Rate Limiting](#rate-limiting)
- [Input Validation](#input-validation)
- [Error Message Leakage](#error-message-leakage)
- [OWASP Top 10 Quick Checks](#owasp-top-10-quick-checks)
- [API Versioning & Deprecation](#api-versioning--deprecation)
- [Request Size & Timeout Limits](#request-size--timeout-limits)
- [Logging & Audit Trails](#logging--audit-trails)

---

## Authentication on Endpoints

### Scan for Unprotected Endpoints

```bash
# Next.js API routes — check for auth middleware
find pages/api app/api -name '*.ts' -o -name '*.js' 2>/dev/null | while read f; do
  if ! grep -q 'auth\|session\|token\|getServerSession\|getUser\|requireAuth\|withAuth\|middleware' "$f"; then
    echo "POTENTIALLY UNPROTECTED: $f"
  fi
done

# Express routes without auth middleware
grep -rn 'app\.get\|app\.post\|app\.put\|app\.patch\|app\.delete\|router\.get\|router\.post' \
  --include='*.ts' --include='*.js' src/ server/ routes/ | grep -v 'auth\|middleware\|protect'

# Supabase Edge Functions without JWT check
find supabase/functions -name '*.ts' 2>/dev/null | while read f; do
  if ! grep -q 'Authorization\|auth\|jwt\|getUser\|verify' "$f"; then
    echo "NO AUTH CHECK: $f"
  fi
done

# Check for --no-verify-jwt deployments
grep -rn 'no-verify-jwt' supabase/ .github/ 2>/dev/null
```

**Severity:** CRITICAL for state-changing endpoints without auth  

**Patterns to verify:**
- Every POST/PUT/PATCH/DELETE endpoint checks authentication
- GET endpoints returning private data check authentication
- Public endpoints are intentionally public and documented
- Auth middleware runs before request handlers (not after)

### Common Auth Middleware Patterns

```typescript
// Next.js App Router — server-side auth check
import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

async function getUser() {
  const supabase = createServerClient(/* ... */)
  const { data: { user }, error } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  return user
}

// Express middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split('Bearer ')[1]
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  try {
    req.user = verifyJWT(token)
    next()
  } catch {
    res.status(401).json({ error: 'Invalid token' })
  }
}
```

---

## Rate Limiting

### Check for Rate Limiting Implementation

```bash
# Express rate limiting
grep -rn 'rate-limit\|rateLimit\|express-rate-limit\|throttle' \
  --include='*.ts' --include='*.js' --include='*.json' . | grep -v 'node_modules'

# Next.js rate limiting
grep -rn 'rate.*limit\|rateLimiter\|upstash.*ratelimit' \
  --include='*.ts' --include='*.js' . | grep -v 'node_modules'

# Redis-based rate limiting
grep -rn 'ioredis\|redis.*rate\|limiter' package.json

# Check Vercel/infrastructure-level rate limiting
grep -rn 'rateLimit\|rateLimiting' vercel.json wrangler.toml 2>/dev/null

# Supabase — check if rate limiting is configured
grep -rn 'rate_limit\|RATE_LIMIT' supabase/ 2>/dev/null
```

**Severity:** WARNING  

**Endpoints that MUST have rate limiting:**
| Endpoint Type | Max Rate | Reasoning |
|--------------|----------|-----------|
| Login/Auth | 5-10/min | Prevent brute force |
| Password Reset | 3-5/hour | Prevent email spam |
| Signup | 10/hour per IP | Prevent mass account creation |
| File Upload | 10-20/min | Prevent storage abuse |
| API endpoints | 100-1000/min | Prevent abuse/DDoS |
| Webhooks | Based on provider | Prevent replay attacks |

**Implementation options:**
```typescript
// Using upstash/ratelimit (serverless-friendly)
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'),
})

// In API route
const { success } = await ratelimit.limit(ip)
if (!success) return new Response('Too Many Requests', { status: 429 })
```

---

## Input Validation

### Scan for Missing Validation

```bash
# Direct use of req.body without validation
grep -rn 'req\.body\.\|request\.body\.\|body\.' --include='*.ts' --include='*.js' \
  src/ server/ pages/api/ app/api/ | grep -v 'node_modules\|\.test\.' | head -20

# Check for validation libraries
grep -rn 'zod\|yup\|joi\|class-validator\|superstruct\|valibot' package.json

# Zod usage (GOOD)
grep -rn '\.parse\|\.safeParse\|z\.object\|z\.string' --include='*.ts' --include='*.js' \
  src/ server/ pages/api/ app/api/ | grep -v 'node_modules' | head -10

# tRPC (includes built-in validation)
grep -rn 'trpc\|createTRPCRouter\|publicProcedure\|protectedProcedure' \
  --include='*.ts' src/ server/ | head -10
```

**Severity:** WARNING (CRITICAL if user input directly used in queries/commands)  

**What to validate:**
| Input | Validate |
|-------|----------|
| Email | Format, length, normalize |
| URLs | Format, protocol (https only), no SSRF |
| IDs | UUID format or integer range |
| Strings | Length limits, no null bytes |
| Numbers | Range, type (int vs float) |
| Files | Size, MIME type, extension |
| Arrays | Length limits, item validation |

**Correct pattern (Zod):**
```typescript
import { z } from 'zod'

const CreateUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100),
  role: z.enum(['user', 'admin']),
})

// In handler
const body = CreateUserSchema.parse(req.body) // Throws on invalid
// or
const result = CreateUserSchema.safeParse(req.body) // Returns success/error
```

---

## Error Message Leakage

### Scan for Information Disclosure

```bash
# Stack traces in error responses
grep -rn 'stack\|stackTrace\|err\.message\|error\.message' \
  --include='*.ts' --include='*.js' src/ server/ pages/api/ app/api/ | \
  grep -i 'res\.\|response\.\|json(' | grep -v 'node_modules'

# Verbose error handling
grep -rn 'console\.error\|console\.log.*error\|console\.log.*err' \
  --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules' | head -15

# Database errors passed to client
grep -rn 'catch.*res.*json.*err\|catch.*response.*err' \
  --include='*.ts' --include='*.js' src/ server/ pages/api/ | grep -v 'node_modules'

# Check for generic error handler
grep -rn 'errorHandler\|error.*middleware\|onError' --include='*.ts' --include='*.js' src/ server/
```

**Severity:** WARNING  

**What leaks information:**
- Database error messages (reveal schema, table names, column names)
- Stack traces (reveal file paths, framework versions)
- Validation errors with internal field names
- "User not found" vs "Invalid password" (user enumeration)
- Detailed 500 errors in production

**Correct pattern:**
```typescript
// Global error handler
function errorHandler(err, req, res, next) {
  // Log full error server-side
  console.error(err)
  
  // Send generic message to client
  if (err.status === 401) {
    res.status(401).json({ error: 'Unauthorized' })
  } else if (err.status === 403) {
    res.status(403).json({ error: 'Forbidden' })
  } else if (err.status === 404) {
    res.status(404).json({ error: 'Not found' })
  } else {
    // NEVER send err.message or err.stack to client
    res.status(500).json({ error: 'Internal server error' })
  }
}

// Login — same message for wrong user or wrong password
res.status(401).json({ error: 'Invalid credentials' })  // NOT "User not found"
```

---

## OWASP Top 10 Quick Checks

### A01: Broken Access Control

```bash
# Check for authorization on resource access
grep -rn 'params\.id\|params\.userId\|req\.params' --include='*.ts' --include='*.js' \
  src/ server/ pages/api/ | grep -v 'node_modules' | head -10
```
- Can user A access user B's resources by changing IDs?
- Are admin endpoints protected by role checks, not just auth?
- Do file download endpoints verify ownership?

### A02: Cryptographic Failures

```bash
# Weak hashing
grep -rn 'md5\|sha1\|SHA1\|MD5' --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules'

# Check for proper bcrypt/scrypt usage (if handling passwords)
grep -rn 'bcrypt\|scrypt\|argon2\|pbkdf2' --include='*.ts' --include='*.js' . | grep -v 'node_modules'

# Hardcoded encryption keys
grep -rn 'encrypt.*=.*["\x27]\|cipher.*key.*=.*["\x27]' --include='*.ts' --include='*.js' src/
```

### A03: Injection

See [SQL Injection Vectors](database-security.md#sql-injection-vectors) and [XSS Vulnerabilities](web-app-security.md#xss-vulnerabilities).

### A04: Insecure Design

- Does the app enforce business logic limits server-side (not just client)?
- Are there transaction limits, rate limits, usage caps?
- Can users escalate privileges through normal workflows?

### A05: Security Misconfiguration

```bash
# Debug mode enabled
grep -rn 'DEBUG.*true\|debug.*=.*true\|NODE_ENV.*development' \
  --include='*.ts' --include='*.js' --include='*.env' . | grep -v 'node_modules\|\.env\.development'

# Default credentials
grep -rn 'admin.*admin\|password.*password\|default.*password' \
  --include='*.ts' --include='*.js' --include='*.yaml' . | grep -v 'node_modules\|test\|mock'

# Unnecessary features enabled
grep -rn 'GraphQL\|graphiql\|playground.*true\|introspection.*true' \
  --include='*.ts' --include='*.js' . | grep -v 'node_modules'
```

### A06: Vulnerable Components

See [Dependency Vulnerabilities](web-app-security.md#dependency-vulnerabilities).

### A07: Authentication Failures

```bash
# Password requirements
grep -rn 'password.*length\|minLength.*password\|password.*regex\|password.*pattern' \
  --include='*.ts' --include='*.js' src/ | grep -v 'node_modules'

# Session configuration
grep -rn 'maxAge\|expiresIn\|session.*expire\|token.*expire' \
  --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules'

# MFA / 2FA implementation
grep -rn 'mfa\|2fa\|totp\|two.factor\|authenticator' \
  --include='*.ts' --include='*.js' src/ | grep -v 'node_modules'
```

### A08: Software and Data Integrity

- Are CI/CD pipelines locked down?
- Are dependencies pinned (lockfile committed)?
- Are OTA updates signed? (see [mobile-app-security.md](mobile-app-security.md#ota-update-security))

```bash
# Check for lockfile
ls package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null
```

### A09: Logging & Monitoring Failures

```bash
# Check for audit logging
grep -rn 'audit\|log.*action\|log.*event\|activity.*log' \
  --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules'

# Check for error monitoring (Sentry, etc.)
grep -rn 'sentry\|Sentry\|bugsnag\|datadog\|newrelic' package.json
```

### A10: Server-Side Request Forgery (SSRF)

```bash
# User-controlled URLs being fetched server-side
grep -rn 'fetch.*req\.\|axios.*req\.\|got.*req\.\|request.*req\.' \
  --include='*.ts' --include='*.js' src/ server/ pages/api/ | grep -v 'node_modules'

# URL from user input
grep -rn 'req\.body\.url\|req\.query\.url\|body\.url\|params\.url' \
  --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules'
```

---

## Request Size & Timeout Limits

### Check Configuration

```bash
# Express body parser limits
grep -rn 'bodyParser\|body-parser\|express\.json\|express\.urlencoded' \
  --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules'

# Next.js API config
grep -rn 'bodyParser\|sizeLimit' --include='*.ts' --include='*.js' pages/api/ app/api/ 2>/dev/null

# File upload limits
grep -rn 'multer\|formidable\|busboy\|maxFileSize\|fileSizeLimit' \
  --include='*.ts' --include='*.js' . | grep -v 'node_modules'

# Timeout configuration
grep -rn 'timeout\|maxDuration' --include='*.ts' --include='*.js' --include='*.json' \
  src/ server/ vercel.json 2>/dev/null | grep -v 'node_modules'
```

**Recommended limits:**
| Setting | Value | Purpose |
|---------|-------|---------|
| JSON body | 1MB | Prevent memory exhaustion |
| File upload | 10-50MB | Based on use case |
| Request timeout | 30s | Prevent hanging connections |
| Query timeout | 30s | Prevent DB lock-up |

---

## Logging & Audit Trails

### What to Log for Security

**Must log:**
- Authentication events (login, logout, failed attempts)
- Authorization failures (403s)
- Input validation failures (potential attack probing)
- Admin actions (user management, config changes)
- Data exports or bulk operations

**Never log:**
- Passwords (even hashed)
- Full credit card numbers
- Auth tokens / session IDs
- PII beyond what's needed for the audit trail

```bash
# Check what's being logged
grep -rn 'console\.log\|logger\.\|log\.' --include='*.ts' --include='*.js' \
  src/ server/ | grep -i 'password\|token\|secret\|credit' | grep -v 'node_modules'
```
