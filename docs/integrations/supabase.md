# Supabase Integration

BreachScope checks Supabase projects for data-exposure patterns that commonly lead to incidents.

## Configuration

Prefer environment variables or encrypted dashboard settings.

```bash
export SUPABASE_URL=https://example.supabase.co
export SUPABASE_ANON_KEY=eyJ...
```

Or in `breachscope.yaml`:

```yaml
toolchain:
  supabase:
    url: ""
    anonKey: ""
```

Use the anon key, not the service-role key. If a service-role key is supplied, BreachScope flags it as critical because it bypasses Row Level Security.

## Checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| Service-role key supplied | Critical | A leaked service-role key can bypass all RLS policies |
| `auth.users` readable via anon access | Critical | User records may be exposed without authentication |
| Public storage buckets | Medium | Bucket contents may be readable by anyone |
| Broad auth settings | Medium/Low | Signup and domain policy may be too permissive |

## Recommended Fixes

- Rotate any exposed service-role key immediately.
- Keep service-role keys server-side only.
- Enable Row Level Security on tables with user or tenant data.
- Use signed URLs instead of public buckets for private objects.
- Restrict signup to intended domains for internal products.

## Dashboard Use

Supabase findings uploaded to the dashboard can be triaged like any other finding. Use project policies to fail CI on service-role exposure or public user-data access.
