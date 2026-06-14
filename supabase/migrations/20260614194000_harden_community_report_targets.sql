-- Community reports can describe different target kinds, but only phone
-- reports are eligible for Radar CallScreening reputation.
alter table public.community_reports
  add column if not exists target_type text not null default 'unknown';

delete from public.community_reports
where hash !~ '^[0-9a-fA-F]{64}$';

update public.community_reports
set hash = lower(hash),
    target_type = lower(target_type);

alter table public.community_reports
  drop constraint if exists community_reports_hash_sha256_chk;
alter table public.community_reports
  add constraint community_reports_hash_sha256_chk
  check (hash ~ '^[0-9a-f]{64}$');

alter table public.community_reports
  drop constraint if exists community_reports_target_type_chk;
alter table public.community_reports
  add constraint community_reports_target_type_chk
  check (target_type in ('phone', 'url', 'text', 'email', 'iban', 'unknown'));

create index if not exists community_reports_phone_hash_idx
  on public.community_reports (hash)
  where target_type = 'phone';
