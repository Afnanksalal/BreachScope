# Supabase Integration

BreachScope probes your live Supabase project for common misconfigurations that lead to data breaches.

## Setup

Add to `breachscope.yaml`:

```yaml
toolchain:
  supabase:
    url: ""      # or set SUPABASE_URL env var
    anonKey: ""  # or set SUPABASE_ANON_KEY env var
```

Or set environment variables:

```bash
export SUPABASE_URL=https://xxxx.supabase.co
export SUPABASE_ANON_KEY=eyJ...
```

> **Security note:** Always use the **anon key**, not the service role key, in your config. BreachScope will detect and flag it if you accidentally supply the service role key.

## What gets checked

### RLS on auth.users

Checks if the `users` table is readable by unauthenticated requests via the anon key. If RLS is disabled or there's no restrictive policy, this is a critical finding.

**Fix:** Enable Row Level Security on the users table and add a restrictive policy that denies anonymous access.

### Public storage buckets

Lists all storage buckets and flags any marked as public. Public buckets allow unauthenticated read access to every file.

**Fix:** Set buckets to private. Use signed URLs for user-specific file access.

### Service role key detection

Decodes the JWT to check if it has `service_role` privileges. Service role keys bypass all RLS policies and must never be used client-side or exposed.

**Fix:** Rotate the key immediately. Use only the `anon` key for client-side access.

## Severity mapping

| Finding | Severity |
|---------|----------|
| auth.users accessible via anon | CRITICAL |
| Service role key used as anon key | CRITICAL |
| Public storage bucket | MEDIUM |
