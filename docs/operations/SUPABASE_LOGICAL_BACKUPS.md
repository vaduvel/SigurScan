# Supabase Logical Backups

This is SigurScan's no-PITR backup posture for the current freeze phase.

It is deliberately simple:

- A daily GitHub Actions workflow runs `pg_dump`.
- The dump is verified with `pg_restore --list`.
- The result is uploaded as a private GitHub Actions artifact with 30-day retention.
- The same script can be run locally for an emergency manual backup.

This is not point-in-time recovery. It is a daily logical backup safety net.

## Why This Exists

Supabase PITR is not enabled for the project during the current freeze. The live
database is small, and the immediate risk we need to cover is accidental data
loss or a bad migration, not second-by-second recovery.

Current project:

- Supabase ref: `hslqboubacrdhatmqcky`
- Last checked DB size: about `26 MB`

## Required GitHub Secret

Add this repository secret:

```text
SUPABASE_DB_URL
```

Use a Supabase direct Postgres connection string or session-pooler connection
string. Avoid the transaction pooler for `pg_dump`.

Do not commit the connection string. Do not paste it into logs or issue text.

## Workflow

File:

```text
.github/workflows/supabase-logical-backup.yml
```

Triggers:

- Manual: GitHub Actions -> Supabase logical backup -> Run workflow
- Scheduled: daily at `02:23 UTC`

Artifact retention:

- `30` days

What is included:

- Custom-format Postgres dump: `*.dump`
- Schema-only SQL dump: `*_schema.sql.gz`
- Restore list: `*_restore.list`
- Manifest with checksums: `*_manifest.json`

What is not included:

- Supabase Storage bucket objects
- Provider-side logs
- Point-in-time recovery

## Local Manual Backup

Install a PostgreSQL client first.

macOS:

```bash
brew install libpq
brew link --force libpq
```

Ubuntu/Debian:

```bash
sudo apt-get update
sudo apt-get install -y postgresql-client
```

Run:

```bash
export SUPABASE_DB_URL="postgresql://..."
tools/supabase_logical_backup.sh
```

Default output:

```text
build/backups/supabase/
```

The script prints only whether `SUPABASE_DB_URL` is set and its length. It must
not print the secret value.

## Restore Drill

To inspect a dump:

```bash
pg_restore --list path/to/hslqboubacrdhatmqcky_YYYYMMDDTHHMMSSZ.dump
```

To restore into a throwaway database:

```bash
createdb sigurscan_restore_test
pg_restore \
  --clean \
  --if-exists \
  --no-owner \
  --dbname sigurscan_restore_test \
  path/to/hslqboubacrdhatmqcky_YYYYMMDDTHHMMSSZ.dump
```

Never restore directly over production during a drill.

## Freeze Acceptance

Accepted for the current no-PITR freeze posture on 2026-06-13:

- `SUPABASE_DB_URL` is configured as a GitHub Actions secret.
- Manual workflow run `27462542127` succeeded on `main` commit `cdad5f97cb258ab4c242776ad48e4b24edda6d92`.
- Artifact `supabase-logical-backup-27462542127` contains dump, schema, restore list, and manifest.
- The workflow installed `pg_dump (PostgreSQL) 17.10`, matching the Supabase Postgres 17 major version.
- `pg_restore --list` was executed by the workflow and passed.
- Local checksum verification against the downloaded artifact returned `sha256_ok=True` for dump, schema, and restore list.

This posture is accepted as automated daily logical backup while still noting that PITR remains disabled.
