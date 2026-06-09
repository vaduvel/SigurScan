alter table public.fast_preview_capture_runs
add column if not exists skipped_sensitive integer not null default 0;

alter table public.fast_preview_capture_runs
drop constraint if exists fast_preview_capture_runs_skipped_sensitive_nonnegative_chk;

alter table public.fast_preview_capture_runs
add constraint fast_preview_capture_runs_skipped_sensitive_nonnegative_chk
check (skipped_sensitive >= 0);
