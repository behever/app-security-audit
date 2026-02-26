# Database Security Reference

## Table of Contents
- [Connection String Exposure](#connection-string-exposure)
- [SSL/TLS for Connections](#ssltls-for-connections)
- [Principle of Least Privilege](#principle-of-least-privilege)
- [SQL Injection Vectors](#sql-injection-vectors)
- [Query Parameterization](#query-parameterization)
- [Backup Security](#backup-security)
- [Database Configuration Hardening](#database-configuration-hardening)
- [Monitoring & Logging](#monitoring--logging)

---

## Connection String Exposure

### Scan for Leaked Connection Strings

```bash
# PostgreSQL connection strings
grep -rn 'postgres://\|postgresql://\|DATABASE_URL' \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' \
  --include='*.py' --include='*.yaml' --include='*.yml' --include='*.json' \
  . | grep -v 'node_modules\|\.env\.example\|dist/'

# MySQL connection strings
grep -rn 'mysql://\|MYSQL_' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.yaml' \
  . | grep -v 'node_modules'

# MongoDB connection strings
grep -rn 'mongodb://\|mongodb\+srv://\|MONGO_' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.yaml' \
  . | grep -v 'node_modules'

# Redis connection strings
grep -rn 'redis://\|REDIS_URL\|REDIS_PASSWORD' \
  --include='*.ts' --include='*.js' --include='*.py' --include='*.yaml' \
  . | grep -v 'node_modules'

# Connection strings in tracked files
git ls-files | xargs grep -l 'postgres://\|mysql://\|mongodb' 2>/dev/null | grep -v 'node_modules\|\.example'
```

**Severity:** CRITICAL  

**Checklist:**
- [ ] Connection strings only in environment variables, never hardcoded
- [ ] `.env` files in `.gitignore`
- [ ] No connection strings in Docker Compose files checked into git (use `.env` references)
- [ ] CI/CD secrets use encrypted environment variables
- [ ] Connection pooler URLs used instead of direct DB access where possible

---

## SSL/TLS for Connections

### Check SSL Configuration

```bash
# Check for sslmode in connection strings
grep -rn 'sslmode\|ssl=true\|ssl_require' --include='*.ts' --include='*.js' --include='*.py' --include='*.yaml' .

# Check for SSL cert files
find . -name '*.pem' -o -name '*.crt' -o -name '*.key' 2>/dev/null | grep -v 'node_modules'

# Supabase — check if SSL is enforced
# (Supabase enforces SSL by default, but check custom DB connections)
grep -rn 'rejectUnauthorized.*false\|ssl.*false\|sslmode.*disable' \
  --include='*.ts' --include='*.js' . | grep -v 'node_modules'
```

**Severity:** CRITICAL if SSL disabled in production  

**Red flags:**
- `sslmode=disable` or `ssl=false` in production
- `rejectUnauthorized: false` (disables certificate validation)
- No SSL configuration at all (many clients default to unencrypted)

**Correct patterns:**
```typescript
// Node.js with pg
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true }  // Verify server cert
});

// Prisma
// In DATABASE_URL: ?sslmode=require&sslcert=./ca-cert.pem
```

---

## Principle of Least Privilege

### Audit Database User Permissions

```sql
-- PostgreSQL: List all roles and their attributes
SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication
FROM pg_roles
WHERE rolname NOT LIKE 'pg_%'
ORDER BY rolname;

-- List grants per role
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.table_privileges
WHERE grantee NOT IN ('postgres', 'supabase_admin')
  AND table_schema = 'public'
ORDER BY grantee, table_name, privilege_type;

-- Find roles with superuser access
SELECT rolname FROM pg_roles WHERE rolsuper = true;

-- Find roles that can create databases
SELECT rolname FROM pg_roles WHERE rolcreatedb = true;

-- Check function ownership (functions run as owner by default)
SELECT n.nspname, p.proname, r.rolname as owner
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles r ON r.oid = p.proowner
WHERE n.nspname = 'public';
```

**Severity:** WARNING  

**Recommended role structure:**
| Role | Permissions | Use Case |
|------|-------------|----------|
| `app_readonly` | SELECT on needed tables | Reporting, analytics |
| `app_readwrite` | SELECT, INSERT, UPDATE on needed tables | Application backend |
| `app_admin` | Full schema control | Migrations only |
| `anon` | SELECT via RLS | Unauthenticated API |
| `authenticated` | SELECT, INSERT, UPDATE, DELETE via RLS | Authenticated API |

**Never:**
- Give the application user `superuser` privileges
- Use the `postgres` role in application code
- Grant `ALL PRIVILEGES` on all tables

---

## SQL Injection Vectors

### Scan for Injection Vulnerabilities

```bash
# String concatenation in SQL queries (HIGH RISK)
grep -rn "query.*\+.*\|\`.*\$\{.*\}.*SELECT\|.*\$\{.*\}.*INSERT\|.*\$\{.*\}.*UPDATE\|.*\$\{.*\}.*DELETE\|.*\$\{.*\}.*WHERE" \
  --include='*.ts' --include='*.js' . | grep -v 'node_modules\|\.test\.'

# Raw SQL without parameterization
grep -rn '\.raw\|\.rawQuery\|\.execute.*\+\|db\.query.*\+' \
  --include='*.ts' --include='*.js' --include='*.py' . | grep -v 'node_modules'

# Sequelize raw queries
grep -rn 'sequelize\.query' --include='*.ts' --include='*.js' . | grep -v 'node_modules'

# Prisma raw queries
grep -rn '\$queryRaw\|\$executeRaw' --include='*.ts' --include='*.js' . | grep -v 'node_modules'

# Knex raw queries
grep -rn 'knex\.raw\|\.whereRaw\|\.havingRaw' --include='*.ts' --include='*.js' . | grep -v 'node_modules'
```

**Severity:** CRITICAL  

**Vulnerable patterns:**
```typescript
// BAD: String interpolation
const result = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);

// BAD: String concatenation
const result = await db.query("SELECT * FROM users WHERE name = '" + name + "'");
```

**Safe patterns:**
```typescript
// GOOD: Parameterized query
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

// GOOD: Prisma typed queries
const user = await prisma.user.findUnique({ where: { id: userId } });

// GOOD: Prisma safe raw (tagged template)
const result = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;

// GOOD: Knex parameterized
const result = await knex('users').where('id', userId);
```

---

## Query Parameterization

### Verify Parameterized Queries

```bash
# Find all database query calls
grep -rn '\.query\|\.execute\|\.prepare' --include='*.ts' --include='*.js' src/ server/ | grep -v 'node_modules' | head -30

# Check for template literals in queries (potential injection)
grep -rn 'query\s*(`\|execute\s*(`' --include='*.ts' --include='*.js' src/ server/ | grep '\${'

# Check Supabase client calls with user input
grep -rn '\.rpc\|\.from.*\.select\|\.from.*\.insert\|\.from.*\.update' --include='*.ts' --include='*.tsx' src/ | head -20
```

**Supabase-specific:** The Supabase JS client uses PostgREST which parameterizes automatically. However, `.rpc()` calls to custom functions may be vulnerable if the function uses dynamic SQL.

**Check RPC functions for dynamic SQL:**
```sql
-- Find functions using EXECUTE (dynamic SQL)
SELECT p.proname, pg_get_functiondef(p.oid)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND pg_get_functiondef(p.oid) LIKE '%EXECUTE%';
```

---

## Backup Security

### Audit Backup Configuration

**Questions to answer:**
1. Are backups encrypted at rest?
2. Are backups stored in a different region/account?
3. Who has access to backup files?
4. Are backups tested regularly (can you restore them)?
5. What's the retention policy?

**Supabase-specific:**
- Supabase Pro plan includes daily backups with 7-day retention
- Point-in-time recovery (PITR) available on Pro+
- Check: `supabase inspect db db-stats --linked`

```bash
# Check for backup scripts that might leak credentials
grep -rn 'pg_dump\|mysqldump\|mongodump' --include='*.sh' --include='*.yaml' --include='*.yml' .
grep -rn 'PGPASSWORD\|MYSQL_PWD' --include='*.sh' --include='*.yaml' .
```

**Severity:** WARNING  

**Best practices:**
- Encrypt backups with AES-256 or use provider-managed encryption
- Store backup encryption keys separately from backups
- Don't embed credentials in backup scripts — use `.pgpass` or environment variables
- Test restore procedures monthly

---

## Database Configuration Hardening

### PostgreSQL Hardening Checks

```sql
-- Check if password authentication is enforced
SHOW password_encryption;  -- Should be 'scram-sha-256'

-- Check connection limits
SELECT rolname, rolconnlimit FROM pg_roles WHERE rolconnlimit != -1;

-- Check for idle connections
SELECT count(*), state FROM pg_stat_activity GROUP BY state;

-- Check statement timeout (prevents runaway queries)
SHOW statement_timeout;

-- Check if logging is enabled
SHOW log_statement;  -- 'all', 'ddl', 'mod', or 'none'
SHOW log_min_duration_statement;  -- Log slow queries
```

**Recommended settings:**
| Setting | Value | Why |
|---------|-------|-----|
| `password_encryption` | `scram-sha-256` | Strongest password hash |
| `statement_timeout` | `30s` (app), `5min` (admin) | Prevent runaway queries |
| `idle_in_transaction_session_timeout` | `60s` | Release locks |
| `log_min_duration_statement` | `1000` (ms) | Log slow queries |
| `ssl` | `on` | Encrypt connections |

---

## Monitoring & Logging

### What to Monitor

```sql
-- Failed authentication attempts
SELECT count(*) as failed_auths
FROM pg_stat_activity
WHERE state = 'idle'
  AND backend_type = 'client backend';

-- Unusual query patterns (check pg_stat_statements)
SELECT query, calls, mean_exec_time, rows
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 20;

-- Table access patterns
SELECT schemaname, relname, seq_scan, idx_scan, n_tup_ins, n_tup_upd, n_tup_del
FROM pg_stat_user_tables
ORDER BY seq_scan DESC;
```

**Log these events:**
- All DDL statements (CREATE, ALTER, DROP)
- Failed login attempts
- Permission denied errors
- Queries exceeding timeout
- Connection count spikes

**Supabase monitoring:**
```bash
# Using Supabase CLI
supabase inspect db outliers --linked       # Slowest queries
supabase inspect db bloat --linked          # Table/index bloat
supabase inspect db index-stats --linked    # Unused indexes
supabase inspect db table-stats --linked    # Seq scans (missing indexes)
```
