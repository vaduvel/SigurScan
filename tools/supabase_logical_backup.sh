#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage:
  SUPABASE_DB_URL="postgresql://..." tools/supabase_logical_backup.sh

Creates a custom-format pg_dump, a schema-only dump, a restore list, checksums,
and a JSON manifest under BACKUP_DIR (default: build/backups/supabase).

Required environment:
  SUPABASE_DB_URL        Direct or session-pooler Postgres connection string.

Optional environment:
  SUPABASE_PROJECT_REF   Defaults to hslqboubacrdhatmqcky.
  BACKUP_DIR             Defaults to build/backups/supabase.
  BACKUP_TIMESTAMP       Defaults to current UTC timestamp.
  PGCONNECT_TIMEOUT      Defaults to 10 seconds.
EOF
  exit 0
fi

if [[ -z "${SUPABASE_DB_URL:-}" ]]; then
  echo "::error::SUPABASE_DB_URL is not configured. Use a direct or session-pooler Postgres connection string." >&2
  exit 2
fi

for required_bin in pg_dump pg_restore python3; do
  if ! command -v "$required_bin" >/dev/null 2>&1; then
    echo "::error::Missing required binary: $required_bin" >&2
    exit 2
  fi
done

PROJECT_REF="${SUPABASE_PROJECT_REF:-hslqboubacrdhatmqcky}"
BACKUP_DIR="${BACKUP_DIR:-build/backups/supabase}"
BACKUP_TIMESTAMP="${BACKUP_TIMESTAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
PGCONNECT_TIMEOUT="${PGCONNECT_TIMEOUT:-10}"

mkdir -p "$BACKUP_DIR"

DUMP_FILE="$BACKUP_DIR/${PROJECT_REF}_${BACKUP_TIMESTAMP}.dump"
SCHEMA_FILE="$BACKUP_DIR/${PROJECT_REF}_${BACKUP_TIMESTAMP}_schema.sql"
SCHEMA_GZ_FILE="${SCHEMA_FILE}.gz"
RESTORE_LIST_FILE="$BACKUP_DIR/${PROJECT_REF}_${BACKUP_TIMESTAMP}_restore.list"
MANIFEST_FILE="$BACKUP_DIR/${PROJECT_REF}_${BACKUP_TIMESTAMP}_manifest.json"

checksum_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

file_size_bytes() {
  wc -c < "$1" | tr -d ' '
}

echo "[backup] Starting Supabase logical backup for project ${PROJECT_REF}"
echo "[backup] SUPABASE_DB_URL: SET length=${#SUPABASE_DB_URL}"
echo "[backup] Output directory: ${BACKUP_DIR}"

PGCONNECT_TIMEOUT="$PGCONNECT_TIMEOUT" pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file "$DUMP_FILE" \
  --dbname "$SUPABASE_DB_URL"

if [[ ! -s "$DUMP_FILE" ]]; then
  echo "::error::pg_dump produced an empty dump file: $DUMP_FILE" >&2
  exit 1
fi

pg_restore --list "$DUMP_FILE" > "$RESTORE_LIST_FILE"

if [[ ! -s "$RESTORE_LIST_FILE" ]]; then
  echo "::error::pg_restore --list produced an empty restore list for: $DUMP_FILE" >&2
  exit 1
fi

PGCONNECT_TIMEOUT="$PGCONNECT_TIMEOUT" pg_dump \
  --schema-only \
  --no-owner \
  --no-privileges \
  --file "$SCHEMA_FILE" \
  --dbname "$SUPABASE_DB_URL"

gzip -f "$SCHEMA_FILE"

DUMP_SHA="$(checksum_sha256 "$DUMP_FILE")"
SCHEMA_SHA="$(checksum_sha256 "$SCHEMA_GZ_FILE")"
RESTORE_LIST_SHA="$(checksum_sha256 "$RESTORE_LIST_FILE")"
DUMP_BYTES="$(file_size_bytes "$DUMP_FILE")"
SCHEMA_BYTES="$(file_size_bytes "$SCHEMA_GZ_FILE")"
RESTORE_LIST_BYTES="$(file_size_bytes "$RESTORE_LIST_FILE")"

python3 - "$MANIFEST_FILE" <<PY
import json
import os
import sys
from datetime import datetime, timezone

manifest_path = sys.argv[1]
manifest = {
    "project_ref": os.environ.get("PROJECT_REF", "${PROJECT_REF}"),
    "created_at": datetime.now(timezone.utc).isoformat(),
    "backup_timestamp": "${BACKUP_TIMESTAMP}",
    "format": "pg_dump_custom",
    "dump": {
        "path": "${DUMP_FILE}",
        "bytes": int("${DUMP_BYTES}"),
        "sha256": "${DUMP_SHA}",
    },
    "schema": {
        "path": "${SCHEMA_GZ_FILE}",
        "bytes": int("${SCHEMA_BYTES}"),
        "sha256": "${SCHEMA_SHA}",
    },
    "restore_list": {
        "path": "${RESTORE_LIST_FILE}",
        "bytes": int("${RESTORE_LIST_BYTES}"),
        "sha256": "${RESTORE_LIST_SHA}",
    },
    "verification": {
        "pg_restore_list": "passed",
        "empty_file_guard": "passed",
    },
    "limitations": [
        "Logical daily backup, not PITR.",
        "Does not back up Supabase Storage objects.",
    ],
}
with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY

echo "[backup] Created dump: ${DUMP_FILE} (${DUMP_BYTES} bytes, sha256=${DUMP_SHA})"
echo "[backup] Created schema: ${SCHEMA_GZ_FILE} (${SCHEMA_BYTES} bytes, sha256=${SCHEMA_SHA})"
echo "[backup] Created restore list: ${RESTORE_LIST_FILE} (${RESTORE_LIST_BYTES} bytes, sha256=${RESTORE_LIST_SHA})"
echo "[backup] Created manifest: ${MANIFEST_FILE}"
echo "[backup] Backup verification: pg_restore --list passed"
