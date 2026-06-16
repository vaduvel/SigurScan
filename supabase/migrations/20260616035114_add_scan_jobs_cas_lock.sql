-- Distributed orchestration guard for Cloud Run multi-instance polling.
--
-- The Android client can poll the same scan from retries/background resumes,
-- and Cloud Run may route those polls to different instances. These columns let
-- the backend claim one refresh step atomically through PostgREST PATCH filters,
-- without exposing scan_jobs to anon/authenticated clients.

alter table public.scan_jobs
  add column if not exists revision integer not null default 0,
  add column if not exists locked_until timestamptz,
  add column if not exists active_step text,
  add column if not exists lock_owner text,
  add column if not exists lock_acquired_at timestamptz;

create index if not exists scan_jobs_locked_until_idx
  on public.scan_jobs (locked_until)
  where locked_until is not null;

create index if not exists scan_jobs_active_step_idx
  on public.scan_jobs (active_step)
  where active_step is not null;

alter table public.scan_jobs enable row level security;

revoke all on table public.scan_jobs from anon;
revoke all on table public.scan_jobs from authenticated;
