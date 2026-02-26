# Supabase Security Reference

## Table of Contents
- [RLS Policy Checks](#rls-policy-checks)
- [Service Role Key Exposure](#service-role-key-exposure)
- [Anon Key Scope](#anon-key-scope)
- [Storage Bucket Policies](#storage-bucket-policies)
- [Edge Function Security](#edge-function-security)
- [Database Role Permissions](#database-role-permissions)
- [Realtime Channel Security](#realtime-channel-security)
- [Migration Security Review](#migration-security-review)
- [Missing FK Indexes](#missing-fk-indexes)
- [RLS Performance Patterns](#rls-performance-patterns)

---

## RLS Policy Checks

### Find Tables Without RLS Enabled

```sql
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public'
  AND tablename NOT IN (
    SELECT tablename FROM pg_tables t
    JOIN pg_class c ON c.relname = t.tablename
    WHERE c.relrowsecurity = true
  );
```

### Alternative — Check RLS Status for All Public Tables

```sql
SELECT c.relname AS table_name,
       c.relrowsecurity AS rls_enabled,
       c.relforcerowsecurity AS rls_forced
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
ORDER BY c.relname;
```

### List All RLS Policies

```sql
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
WHERE schemaname = 'public'
ORDER BY tablename, policyname;
```

### Find Weak Policies — Bare `auth.uid()` (No Subselect)

Bare `auth.uid()` evaluates per-row instead of once per query. At scale, this causes 100x+ slowdowns.

**Grep in migration files:**
```bash
grep -rn 'auth\.uid()' --include='*.sql' | grep -v '(select auth.uid())'
```

**Correct pattern:**
```sql
-- BAD: evaluates per row
CREATE POLICY "users_own_data" ON public.items
  USING (user_id = auth.uid());

-- GOOD: subselect caches per query
CREATE POLICY "users_own_data" ON public.items
  USING (user_id = (select auth.uid()));
```

### Find Overly Permissive Policies

```sql
-- Policies that grant access to ALL roles (including anon)
SELECT tablename, policyname, roles, cmd, qual
FROM pg_policies
WHERE schemaname = 'public'
  AND roles = '{public}'
ORDER BY tablename;
```

### Find Tables With SELECT but No INSERT/UPDATE/DELETE Policies

```sql
SELECT DISTINCT tablename
FROM pg_policies
WHERE schemaname = 'public' AND cmd = 'SELECT'
  AND tablename NOT IN (
    SELECT tablename FROM pg_policies
    WHERE schemaname = 'public' AND cmd IN ('INSERT', 'UPDATE', 'DELETE')
  );
```

---

## Service Role Key Exposure

The service role key bypasses RLS entirely. It must NEVER appear in client code.

**Grep patterns:**
```bash
# Check for service_role in client code
grep -rn 'service_role' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/
grep -rn 'SUPABASE_SERVICE_ROLE' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/

# Check for service role key value (eyJhb... pattern with service_role)
grep -rn 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' src/
```

**What to verify:**
- Service role key is ONLY in server-side code (API routes, edge functions, server components)
- Environment variable is named clearly (e.g., `SUPABASE_SERVICE_ROLE_KEY`)
- `.env` files containing it are in `.gitignore`
- No hardcoded JWT strings in source

---

## Anon Key Scope

The anon key is public-facing but should only allow access through RLS policies.

**Audit checklist:**
1. Decode the anon JWT at jwt.io — verify `role: anon`
2. Check what anon can do without RLS:
   ```sql
   -- Tables accessible to anon without RLS
   SELECT c.relname
   FROM pg_class c
   JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public'
     AND c.relkind = 'r'
     AND c.relrowsecurity = false
     AND has_table_privilege('anon', c.oid, 'SELECT');
   ```
3. Check RPC functions callable by anon:
   ```sql
   SELECT p.proname, p.prosecdef
   FROM pg_proc p
   JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE n.nspname = 'public'
     AND has_function_privilege('anon', p.oid, 'EXECUTE');
   ```

---

## Storage Bucket Policies

### List All Buckets and Their Public Status

```sql
SELECT id, name, public, file_size_limit, allowed_mime_types
FROM storage.buckets;
```

### List Storage Policies

```sql
SELECT * FROM pg_policies WHERE schemaname = 'storage';
```

**Common issues:**
- Public buckets allowing unauthenticated uploads
- No file size limits on upload policies
- No MIME type restrictions (allows executable uploads)
- Missing DELETE policies (users can't remove their own files)

**Recommended policy pattern:**
```sql
-- Users can only upload to their own folder
CREATE POLICY "user_uploads" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (
    bucket_id = 'avatars'
    AND (storage.foldername(name))[1] = (select auth.uid())::text
  );
```

---

## Edge Function Security

### JWT Verification

```bash
# Find edge functions deployed without JWT verification
grep -rn 'no-verify-jwt' supabase/

# Check for Authorization header validation in function code
grep -rn 'Authorization' --include='*.ts' supabase/functions/
```

**Every edge function should:**
1. Verify the JWT from the Authorization header (unless intentionally public)
2. Validate the user has permission for the requested action
3. Set proper CORS headers

### CORS Configuration

```typescript
// Correct CORS pattern for edge functions
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://yourdomain.com', // NOT '*'
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
```

**Red flags:**
- `Access-Control-Allow-Origin: '*'` in production
- Missing OPTIONS handler
- Functions deployed with `--no-verify-jwt` that handle sensitive data

---

## Database Role Permissions

### Check Grants on Public Schema

```sql
SELECT grantee, table_name, privilege_type
FROM information_schema.table_privileges
WHERE table_schema = 'public'
ORDER BY grantee, table_name;
```

### Check Function Security

```sql
-- Find SECURITY DEFINER functions (run as function owner, not caller)
SELECT n.nspname, p.proname, p.prosecdef,
       pg_get_functiondef(p.oid) as definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.prosecdef = true;
```

**SECURITY DEFINER functions MUST:**
- Set `search_path = public` to prevent search_path hijacking
- Validate all inputs
- Not expose data the caller shouldn't see

```sql
-- Correct pattern
CREATE OR REPLACE FUNCTION public.get_user_data(target_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  -- Validate caller has permission
  IF (select auth.uid()) != target_user_id THEN
    RAISE EXCEPTION 'unauthorized';
  END IF;
  -- ...
END;
$$;
```

---

## Realtime Channel Security

### Check Realtime Policies

Supabase Realtime uses RLS policies. If a table has RLS enabled, Realtime respects those policies.

**Audit:**
1. Tables broadcast via Realtime must have RLS enabled
2. Check client code for Realtime subscriptions:
   ```bash
   grep -rn '\.channel\|\.on.*postgres_changes\|supabase.*subscribe' --include='*.ts' --include='*.tsx' src/
   ```
3. Verify no sensitive tables are subscribed to without filtering
4. Check for `broadcast` channels that might leak data between users

---

## Migration Security Review

### Scan Migrations for Common Issues

```bash
# Tables created without RLS
grep -l 'CREATE TABLE' supabase/migrations/*.sql | while read f; do
  table=$(grep -oP 'CREATE TABLE (?:IF NOT EXISTS )?\K\S+' "$f" | head -1)
  if ! grep -q 'ENABLE ROW LEVEL SECURITY' "$f"; then
    echo "WARNING: $f creates table but may not enable RLS"
  fi
done

# Check for permissive grants
grep -n 'GRANT.*TO.*public\|GRANT.*TO.*anon' supabase/migrations/*.sql

# Check for dangerous operations
grep -n 'DROP POLICY\|ALTER TABLE.*DISABLE.*ROW' supabase/migrations/*.sql
```

---

## Missing FK Indexes

Foreign keys without indexes cause slow JOIN operations and slow cascading deletes. They also impact RLS performance when policies reference related tables.

### Find Missing FK Indexes

```sql
SELECT
  c.conrelid::regclass AS table_name,
  a.attname AS fk_column,
  c.confrelid::regclass AS referenced_table
FROM pg_constraint c
JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
WHERE c.contype = 'f'
  AND NOT EXISTS (
    SELECT 1 FROM pg_index i
    WHERE i.indrelid = c.conrelid
      AND a.attnum = ANY(i.indkey)
  )
ORDER BY table_name, fk_column;
```

**Fix:** Create an index for each missing FK column:
```sql
CREATE INDEX idx_items_user_id ON public.items (user_id);
```

---

## RLS Performance Patterns

### Index Columns Used in RLS Policies

```sql
-- Find columns referenced in RLS quals
SELECT tablename, policyname, qual
FROM pg_policies
WHERE schemaname = 'public' AND qual IS NOT NULL;
```

Every column in a `USING` or `WITH CHECK` clause should have an index.

### Use Subselects for Auth Functions

```sql
-- BAD: Called per-row
USING (user_id = auth.uid())

-- GOOD: Cached per-query via subselect
USING (user_id = (select auth.uid()))

-- BAD: Helper function per-row
USING (is_admin())

-- GOOD: Helper function cached
USING ((select is_admin()))
```

### Avoid JOINs in RLS Policies

```sql
-- BAD: JOIN in policy (evaluated per-row)
USING (EXISTS (
  SELECT 1 FROM memberships m
  WHERE m.org_id = items.org_id AND m.user_id = auth.uid()
))

-- BETTER: Subselect with IN
USING (org_id IN (
  SELECT org_id FROM memberships WHERE user_id = (select auth.uid())
))
```
