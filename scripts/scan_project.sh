#!/usr/bin/env bash
# scan_project.sh — Quick security scanner for web/mobile/Supabase projects
# Usage: ./scan_project.sh /path/to/project
# Dependencies: bash, grep, find (no external deps)

set -uo pipefail
# Note: -e intentionally omitted — grep returns 1 on no match, which is expected

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

# Counters
CRITICAL_COUNT=0
WARNING_COUNT=0
INFO_COUNT=0

PROJECT_DIR="${1:-.}"

if [ ! -d "$PROJECT_DIR" ]; then
  echo "Error: Directory '$PROJECT_DIR' not found"
  echo "Usage: $0 /path/to/project"
  exit 1
fi

cd "$PROJECT_DIR"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BOLD}  🔒 App Security Audit Scanner${NC}"
echo -e "  Project: ${BOLD}$(basename "$(pwd)")${NC}"
echo -e "  Path:    $(pwd)"
echo -e "  Date:    $(date '+%Y-%m-%d %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Helpers
critical() {
  echo -e "${RED}[CRITICAL]${NC} $1"
  if [ -n "${2:-}" ]; then echo -e "  ${2}"; fi
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
}

warning() {
  echo -e "${YELLOW}[WARNING]${NC}  $1"
  if [ -n "${2:-}" ]; then echo -e "  ${2}"; fi
  WARNING_COUNT=$((WARNING_COUNT + 1))
}

info() {
  echo -e "${BLUE}[INFO]${NC}     $1"
  if [ -n "${2:-}" ]; then echo -e "  ${2}"; fi
  INFO_COUNT=$((INFO_COUNT + 1))
}

section() {
  echo ""
  echo -e "${BOLD}── $1 ──${NC}"
}

# Determine source directories
SRC_DIRS=""
for d in src app lib pages components server routes api supabase/functions; do
  if [ -d "$d" ]; then
    SRC_DIRS="$SRC_DIRS $d"
  fi
done

if [ -z "$SRC_DIRS" ]; then
  SRC_DIRS="."
fi

# ──────────────────────────────────────────────
section "1. HARDCODED SECRETS"
# ──────────────────────────────────────────────

# AWS keys
if grep -rn 'AKIA[0-9A-Z]\{16\}' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.py' --include='*.env' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|\.env\.example' | head -5; then
  critical "AWS access key found in source code"
fi

# Private keys
if grep -rn 'BEGIN.*PRIVATE KEY\|BEGIN RSA' --include='*.ts' --include='*.js' --include='*.tsx' --include='*.pem' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5; then
  critical "Private key found in source code"
fi

# Stripe secret keys
if grep -rn 'sk_live_[0-9a-zA-Z]\{20,\}' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5; then
  critical "Stripe live secret key found in source code"
fi

# Generic hardcoded secrets (strings assigned to secret-like variables)
if grep -rn "['\"]sk_\|['\"]pk_live\|['\"]ghp_\|['\"]glpat-\|['\"]xox[bsp]-" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|\.env' | head -5; then
  critical "Potential API key/token hardcoded in source"
fi

# Supabase service role key in client code
HAS_SVC_ROLE=0
for d in src app lib pages components; do
  if [ -d "$d" ] && grep -rn 'service_role\|SERVICE_ROLE' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' "$d" 2>/dev/null | grep -v 'node_modules\|\.env\|// \|/\*\|#' | head -3; then
    HAS_SVC_ROLE=1
  fi
done
if [ "$HAS_SVC_ROLE" -eq 1 ]; then
  critical "Supabase service_role key reference found in client code" \
    "Service role key bypasses RLS — must only be in server-side code"
fi

# Password/secret in source (not env vars)
PASS_HITS=$(grep -rn "password\s*[:=]\s*['\"][^'\"]\{8,\}['\"]" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|\.test\.\|\.spec\.\|mock\|placeholder\|example\|schema\|type\|interface\|zod\|yup\|joi\|validation\|__tests__' | head -5)
if [ -n "$PASS_HITS" ]; then
  echo "$PASS_HITS"
  critical "Possible hardcoded password in source"
fi

# ──────────────────────────────────────────────
section "2. ENVIRONMENT VARIABLE EXPOSURE"
# ──────────────────────────────────────────────

# .env files in public/dist/build directories
ENV_IN_PUBLIC=$(find . -path '*/public/.env*' -o -path '*/dist/.env*' -o -path '*/build/.env*' -o -path '*/.next/.env*' -o -path '*/out/.env*' 2>/dev/null | grep -v 'node_modules')
if [ -n "$ENV_IN_PUBLIC" ]; then
  echo "$ENV_IN_PUBLIC"
  critical ".env file found in public/build directory"
fi

# .env files tracked by git
if command -v git &>/dev/null && git rev-parse --git-dir &>/dev/null 2>&1; then
  ENV_TRACKED=$(git ls-files --cached '.env' '.env.*' 2>/dev/null | grep -v '.env.example\|.env.local.example\|.env.sample' || true)
  if [ -n "$ENV_TRACKED" ]; then
    echo "$ENV_TRACKED"
    critical ".env file is tracked by git"
  fi
fi

# Check .gitignore for .env
if [ -f ".gitignore" ]; then
  if ! grep -q '\.env' .gitignore 2>/dev/null; then
    warning "No .env pattern found in .gitignore"
  fi
else
  warning "No .gitignore file found"
fi

# NEXT_PUBLIC_ vars with sensitive names
if grep -rn 'NEXT_PUBLIC_.*SECRET\|NEXT_PUBLIC_.*PRIVATE\|NEXT_PUBLIC_.*SERVICE_ROLE\|NEXT_PUBLIC_.*PASSWORD' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.env*' . 2>/dev/null | grep -v 'node_modules' | head -5; then
  critical "NEXT_PUBLIC_ environment variable contains a secret name" \
    "NEXT_PUBLIC_ vars are exposed in the client bundle"
fi

# VITE_ vars with sensitive names
if grep -rn 'VITE_.*SECRET\|VITE_.*PRIVATE\|VITE_.*SERVICE_ROLE\|VITE_.*PASSWORD' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.env*' . 2>/dev/null | grep -v 'node_modules' | head -5; then
  critical "VITE_ environment variable contains a secret name" \
    "VITE_ vars are exposed in the client bundle"
fi

# ──────────────────────────────────────────────
section "3. XSS VULNERABILITIES"
# ──────────────────────────────────────────────

# dangerouslySetInnerHTML
DHTML=$(grep -rn 'dangerouslySetInnerHTML' --include='*.ts' --include='*.tsx' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5)
if [ -n "$DHTML" ]; then
  echo "$DHTML"
  warning "dangerouslySetInnerHTML usage found — verify input is sanitized"
fi

# innerHTML assignment
IHTML=$(grep -rn '\.innerHTML\s*=' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5)
if [ -n "$IHTML" ]; then
  echo "$IHTML"
  warning "innerHTML assignment found — verify input is sanitized"
fi

# eval usage
EVAL_HITS=$(grep -rn '\beval\s*(' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|webpack\|eslint\|\.config' | head -5)
if [ -n "$EVAL_HITS" ]; then
  echo "$EVAL_HITS"
  critical "eval() usage found — high XSS/injection risk"
fi

# document.write
DOCWRITE=$(grep -rn 'document\.write' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5)
if [ -n "$DOCWRITE" ]; then
  echo "$DOCWRITE"
  warning "document.write usage found"
fi

# ──────────────────────────────────────────────
section "4. AUTH TOKEN STORAGE"
# ──────────────────────────────────────────────

# localStorage with tokens
LS_TOKENS=$(grep -rn 'localStorage\.\(setItem\|getItem\).*\(token\|auth\|jwt\|session\|credential\)' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -vi 'node_modules' | head -5)
if [ -n "$LS_TOKENS" ]; then
  echo "$LS_TOKENS"
  warning "Auth tokens stored in localStorage — vulnerable to XSS" \
    "Consider httpOnly cookies via @supabase/ssr or similar"
fi

# ──────────────────────────────────────────────
section "5. CORS CONFIGURATION"
# ──────────────────────────────────────────────

# Wildcard CORS
CORS_WILD=$(grep -rn "Access-Control-Allow-Origin.*\*" --include='*.ts' --include='*.js' --include='*.json' --include='*.mjs' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5)
if [ -n "$CORS_WILD" ]; then
  echo "$CORS_WILD"
  warning "Wildcard CORS origin (*) found — verify this is intentional"
fi

# ──────────────────────────────────────────────
section "6. SUPABASE / DATABASE SECURITY"
# ──────────────────────────────────────────────

# Check migrations for missing RLS
if [ -d "supabase/migrations" ]; then
  info "Supabase migrations directory found — scanning..."
  
  for migration in supabase/migrations/*.sql; do
    [ -f "$migration" ] || continue
    TABLES_CREATED=$(grep -oiP 'CREATE TABLE\s+(IF NOT EXISTS\s+)?\K[^\s(]+' "$migration" 2>/dev/null || true)
    for table in $TABLES_CREATED; do
      # Normalize table name for checking
      clean_table=$(echo "$table" | sed 's/public\.//;s/"//g')
      if ! grep -qi "ENABLE ROW LEVEL SECURITY.*${clean_table}\|${clean_table}.*ENABLE ROW LEVEL SECURITY\|ALTER TABLE.*${clean_table}.*ENABLE ROW LEVEL SECURITY" "$migration" 2>/dev/null; then
        # Check all migrations for this table's RLS enablement
        if ! grep -rqi "ALTER TABLE.*${clean_table}.*ENABLE ROW LEVEL SECURITY" supabase/migrations/ 2>/dev/null; then
          warning "Table ${clean_table} may not have RLS enabled" \
            "Created in: $(basename "$migration")"
        fi
      fi
    done
  done
  
  # Bare auth.uid() without subselect
  BARE_AUTH=$(grep -rn 'auth\.uid()' --include='*.sql' supabase/migrations/ 2>/dev/null | grep -v '(select auth\.uid()\|(SELECT auth\.uid()' | head -10)
  if [ -n "$BARE_AUTH" ]; then
    echo "$BARE_AUTH"
    warning "Bare auth.uid() found in SQL — use (select auth.uid()) for performance" \
      "Bare calls evaluate per-row; subselect caches per-query (100x+ faster)"
  fi
  
  # Permissive grants to public/anon
  PERM_GRANTS=$(grep -rn 'GRANT.*TO.*public\b\|GRANT.*ALL.*anon' --include='*.sql' supabase/migrations/ 2>/dev/null | head -5)
  if [ -n "$PERM_GRANTS" ]; then
    echo "$PERM_GRANTS"
    warning "Permissive grants to public/anon roles found in migrations"
  fi
else
  info "No supabase/migrations directory found — skipping migration scan"
fi

# Connection strings in source
CONN_STRINGS=$(grep -rn 'postgres://\|postgresql://\|mysql://\|mongodb://' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|\.env\.example\|// \|/\*\|\.d\.ts\|type\|interface' | head -5)
if [ -n "$CONN_STRINGS" ]; then
  echo "$CONN_STRINGS"
  critical "Database connection string found in source code"
fi

# ──────────────────────────────────────────────
section "7. API SECURITY"
# ──────────────────────────────────────────────

# Check for validation library
HAS_VALIDATION=0
if [ -f "package.json" ]; then
  if grep -q '"zod"\|"yup"\|"joi"\|"class-validator"\|"superstruct"\|"valibot"' package.json 2>/dev/null; then
    HAS_VALIDATION=1
    info "Input validation library found in dependencies"
  else
    warning "No input validation library detected (zod, yup, joi, etc.)" \
      "Validate all user input at API boundaries"
  fi
fi

# Check for rate limiting
if [ -f "package.json" ]; then
  if grep -q '"rate-limit\|"rateLimit\|"express-rate-limit\|"@upstash/ratelimit\|"limiter"' package.json 2>/dev/null; then
    info "Rate limiting library found in dependencies"
  else
    warning "No rate limiting library detected" \
      "Add rate limiting to auth endpoints and API routes"
  fi
fi

# Check for error monitoring
if [ -f "package.json" ]; then
  if grep -q '"@sentry\|"sentry\|"bugsnag\|"datadog\|"newrelic"' package.json 2>/dev/null; then
    info "Error monitoring service found in dependencies"
  else
    info "No error monitoring service detected (Sentry, etc.)"
  fi
fi

# ──────────────────────────────────────────────
section "8. DEPENDENCY VULNERABILITIES"
# ──────────────────────────────────────────────

if [ -f "package.json" ]; then
  if command -v npm &>/dev/null; then
    echo "Running npm audit..."
    # Run with background timeout (macOS compatible)
    AUDIT_FILE=$(mktemp)
    npm audit --json > "$AUDIT_FILE" 2>/dev/null &
    NPM_PID=$!
    WAIT_COUNT=0
    while kill -0 "$NPM_PID" 2>/dev/null && [ "$WAIT_COUNT" -lt 30 ]; do
      sleep 1
      WAIT_COUNT=$((WAIT_COUNT + 1))
    done
    if kill -0 "$NPM_PID" 2>/dev/null; then
      kill "$NPM_PID" 2>/dev/null || true
      info "npm audit timed out after 30s — run manually"
    fi
    AUDIT_OUTPUT=$(cat "$AUDIT_FILE" 2>/dev/null || true)
    rm -f "$AUDIT_FILE"
    
    if [ -n "$AUDIT_OUTPUT" ]; then
      AUDIT_CRITICAL=$(echo "$AUDIT_OUTPUT" | grep -o '"critical":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
      AUDIT_HIGH=$(echo "$AUDIT_OUTPUT" | grep -o '"high":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
      AUDIT_MODERATE=$(echo "$AUDIT_OUTPUT" | grep -o '"moderate":[0-9]*' | head -1 | cut -d: -f2 || echo "0")
      
      if [ "${AUDIT_CRITICAL:-0}" -gt 0 ] 2>/dev/null; then
        critical "npm audit: ${AUDIT_CRITICAL} critical vulnerabilities"
      fi
      if [ "${AUDIT_HIGH:-0}" -gt 0 ] 2>/dev/null; then
        warning "npm audit: ${AUDIT_HIGH} high vulnerabilities"
      fi
      if [ "${AUDIT_MODERATE:-0}" -gt 0 ] 2>/dev/null; then
        info "npm audit: ${AUDIT_MODERATE} moderate vulnerabilities"
      fi
      if [ "${AUDIT_CRITICAL:-0}" -eq 0 ] 2>/dev/null && [ "${AUDIT_HIGH:-0}" -eq 0 ] 2>/dev/null; then
        info "npm audit: No critical or high vulnerabilities"
      fi
    fi
  else
    info "npm not available — skipping dependency audit"
  fi
  
  # Check lockfile exists
  if [ -f "package-lock.json" ] || [ -f "yarn.lock" ] || [ -f "pnpm-lock.yaml" ]; then
    info "Lockfile found (pinned dependencies)"
  else
    warning "No lockfile found — dependencies not pinned"
  fi
else
  info "No package.json found — skipping dependency checks"
fi

# ──────────────────────────────────────────────
section "9. MOBILE APP CHECKS"
# ──────────────────────────────────────────────

# Only run if it looks like a React Native / Expo project
if [ -f "app.json" ] || [ -f "app.config.js" ] || [ -f "app.config.ts" ] || [ -d "ios" ] || [ -d "android" ]; then
  info "Mobile app detected"
  
  # AsyncStorage with sensitive data
  ASYNC_TOKENS=$(grep -rn 'AsyncStorage.*token\|AsyncStorage.*secret\|AsyncStorage.*password\|AsyncStorage.*key' --include='*.ts' --include='*.tsx' --include='*.js' $SRC_DIRS 2>/dev/null | grep -v 'node_modules' | head -5)
  if [ -n "$ASYNC_TOKENS" ]; then
    echo "$ASYNC_TOKENS"
    critical "Sensitive data in AsyncStorage — use expo-secure-store or react-native-keychain"
  fi
  
  # Check for secure storage
  if grep -rq 'expo-secure-store\|react-native-keychain' package.json 2>/dev/null; then
    info "Secure storage library found (good)"
  else
    warning "No secure storage library found (expo-secure-store, react-native-keychain)"
  fi
  
  # iOS ATS
  if find ios/ -name 'Info.plist' -exec grep -l 'NSAllowsArbitraryLoads' {} \; 2>/dev/null | head -1 | grep -q .; then
    warning "iOS App Transport Security exceptions found — review Info.plist"
  fi
  
  # Android cleartext
  if grep -rq 'cleartextTrafficPermitted.*true\|usesCleartextTraffic.*true' android/ 2>/dev/null; then
    warning "Android cleartext traffic permitted — should be false in production"
  fi
else
  info "Not a mobile project — skipping mobile checks"
fi

# ──────────────────────────────────────────────
section "10. MISC SECURITY CHECKS"
# ──────────────────────────────────────────────

# HTTP URLs (should be HTTPS)
HTTP_URLS=$(grep -rn 'http://' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|localhost\|127\.0\.0\.1\|0\.0\.0\.0\|http://\*\|schema\|http://www\.w3\|http://xmlns\|\.test\.\|\.spec\.' | head -5)
if [ -n "$HTTP_URLS" ]; then
  echo "$HTTP_URLS"
  warning "Non-HTTPS URLs found in source — verify these aren't production URLs"
fi

# Sensitive data in URL construction
URL_SECRETS=$(grep -rn '`.*\?.*token=\|`.*\?.*key=\|`.*\?.*secret=\|`.*\&.*password=' --include='*.ts' --include='*.tsx' --include='*.js' $SRC_DIRS 2>/dev/null | grep -v 'node_modules\|\.test\.\|\.spec\.' | head -5)
if [ -n "$URL_SECRETS" ]; then
  echo "$URL_SECRETS"
  warning "Sensitive data in URL query parameters" \
    "Tokens/keys in URLs leak via logs, referrer headers, and browser history"
fi

# console.log with sensitive data
CONSOLE_SECRETS=$(grep -rn 'console\.log.*password\|console\.log.*token\|console\.log.*secret\|console\.log.*key' --include='*.ts' --include='*.tsx' --include='*.js' $SRC_DIRS 2>/dev/null | grep -vi 'node_modules\|\.test\.\|\.spec\.' | head -5)
if [ -n "$CONSOLE_SECRETS" ]; then
  echo "$CONSOLE_SECRETS"
  warning "Potentially sensitive data in console.log statements"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BOLD}  📊 SCAN SUMMARY${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${RED}CRITICAL:${NC} ${CRITICAL_COUNT}"
echo -e "  ${YELLOW}WARNING:${NC}  ${WARNING_COUNT}"
echo -e "  ${BLUE}INFO:${NC}     ${INFO_COUNT}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo -e "\n${RED}⚠️  ${CRITICAL_COUNT} critical issue(s) found — address immediately${NC}"
  exit 2
elif [ "$WARNING_COUNT" -gt 0 ]; then
  echo -e "\n${YELLOW}⚡ ${WARNING_COUNT} warning(s) found — review and address${NC}"
  exit 1
else
  echo -e "\n${GREEN}✅ No critical or warning issues found${NC}"
  exit 0
fi
