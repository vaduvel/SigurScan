create table if not exists public.fast_preview_capture_runs (
  run_id text primary key,
  worker_version text not null,
  trigger_source text not null,
  dry_run boolean not null default false,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  duration_ms bigint,
  total_inputs integer not null default 0,
  total_raw_urls integer not null default 0,
  unique_urls integer not null default 0,
  captured_new integer not null default 0,
  skipped_fresh integer not null default 0,
  skipped_reserved integer not null default 0,
  expired_rows_deleted integer not null default 0,
  expired_screenshots_deleted integer not null default 0,
  failed integer not null default 0,
  cleanup_error_count integer not null default 0,
  final_report jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint fast_preview_capture_runs_report_object
    check (jsonb_typeof(final_report) = 'object')
);

create index if not exists fast_preview_capture_runs_started_at_idx
  on public.fast_preview_capture_runs (started_at desc);

create index if not exists fast_preview_capture_runs_trigger_source_idx
  on public.fast_preview_capture_runs (trigger_source);

alter table public.fast_preview_capture_runs enable row level security;

revoke all on table public.fast_preview_capture_runs from anon;
revoke all on table public.fast_preview_capture_runs from authenticated;
