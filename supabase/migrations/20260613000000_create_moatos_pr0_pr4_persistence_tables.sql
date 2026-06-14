-- MoatOS PR0-PR4 persistence tables.
-- These tables are service-role only by default; RLS is enabled and no anon/auth
-- policies are granted here. Runtime can keep using JSON seeds when Supabase is
-- not configured, but Cloud Run can persist OSINT/campaign state durably.

create table if not exists public.brand_truth_manifest (
  manifest_id text primary key,
  type text not null check (type in ('brand', 'person')),
  display_name text not null,
  category text,
  country text not null default 'RO',
  data jsonb not null default '{}'::jsonb,
  confidence text not null default 'needs_confirmation'
    check (confidence in ('high', 'medium', 'needs_confirmation')),
  review_status text not null default 'active'
    check (review_status in ('active', 'retired', 'stale')),
  source_kind text,
  version text not null default 'btr-ro-2026.06.13',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.campaign_intel (
  intel_id text primary key,
  family text not null,
  skeleton jsonb not null default '{}'::jsonb,
  iocs jsonb not null default '{}'::jsonb,
  source jsonb not null default '{}'::jsonb,
  evidence_quality text not null default 'medium',
  status text not null default 'active'
    check (status in ('active', 'draft', 'rejected', 'stale')),
  regions_hint text[] not null default '{national}',
  moderation jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.campaign_fingerprint (
  fingerprint_id text primary key,
  locale text not null default 'ro-RO',
  channel_class text not null default 'sms',
  arc_family text not null default '',
  ask_sequence_sig text not null default '',
  cta_pattern_sig text not null default '',
  identity_claim_sig text not null default '',
  payment_rail_sig text not null default '',
  sensitive_request_sig text[] not null default '{}',
  text_skeleton_hash text not null default '',
  url_shape_sig text not null default 'no-url',
  no_raw_iocs boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.circle_link (
  id uuid primary key default gen_random_uuid(),
  source_intel_id text not null,
  target_intel_id text not null,
  link_type text not null default 'related'
    check (link_type in ('related', 'same_family', 'contradicts', 'supersedes')),
  reason_codes text[] not null default '{}',
  weight numeric(5,2) not null default 1.0 check (weight >= 0 and weight <= 1),
  created_at timestamptz not null default now()
);

create table if not exists public.guardian_audit_log (
  id uuid primary key default gen_random_uuid(),
  actor_id text,
  action text not null,
  target_type text not null,
  target_id text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.guardian_dangerous_approval (
  id uuid primary key default gen_random_uuid(),
  intel_id text not null unique,
  approved_by text not null,
  approved_at timestamptz not null default now(),
  notes text,
  expires_at timestamptz
);

create table if not exists public.call_radar_hot_cache (
  id uuid primary key default gen_random_uuid(),
  target_hash text not null,
  target_type text not null check (target_type in ('phone','domain','url','iban','email')),
  risk_level text not null default 'unknown'
    check (risk_level in ('low','info','medium','high','unknown')),
  report_count integer not null default 0 check (report_count >= 0),
  family text,
  last_reported_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists brand_truth_manifest_confidence_idx
  on public.brand_truth_manifest (confidence);
create index if not exists brand_truth_manifest_review_status_idx
  on public.brand_truth_manifest (review_status);
create index if not exists campaign_intel_family_idx
  on public.campaign_intel (family);
create index if not exists campaign_intel_status_idx
  on public.campaign_intel (status);
create index if not exists campaign_intel_last_seen_idx
  on public.campaign_intel (last_seen_at desc);
create index if not exists campaign_fingerprint_arc_family_idx
  on public.campaign_fingerprint (arc_family);
create index if not exists campaign_fingerprint_locale_idx
  on public.campaign_fingerprint (locale);
create index if not exists circle_link_source_idx
  on public.circle_link (source_intel_id);
create index if not exists circle_link_target_idx
  on public.circle_link (target_intel_id);
create index if not exists circle_link_type_idx
  on public.circle_link (link_type);
create index if not exists guardian_audit_log_created_at_idx
  on public.guardian_audit_log (created_at desc);
create index if not exists guardian_audit_log_target_idx
  on public.guardian_audit_log (target_type, target_id);
create index if not exists guardian_dangerous_approval_intel_id_idx
  on public.guardian_dangerous_approval (intel_id);
create index if not exists call_radar_hot_cache_target_hash_idx
  on public.call_radar_hot_cache (target_hash);
create index if not exists call_radar_hot_cache_expires_at_idx
  on public.call_radar_hot_cache (expires_at);
create index if not exists call_radar_hot_cache_risk_level_idx
  on public.call_radar_hot_cache (risk_level);

alter table public.brand_truth_manifest enable row level security;
alter table public.campaign_intel enable row level security;
alter table public.campaign_fingerprint enable row level security;
alter table public.circle_link enable row level security;
alter table public.guardian_audit_log enable row level security;
alter table public.guardian_dangerous_approval enable row level security;
alter table public.call_radar_hot_cache enable row level security;

drop trigger if exists set_brand_truth_manifest_updated_at on public.brand_truth_manifest;
create trigger set_brand_truth_manifest_updated_at
  before update on public.brand_truth_manifest
  for each row execute function public.set_updated_at();

drop trigger if exists set_campaign_intel_updated_at on public.campaign_intel;
create trigger set_campaign_intel_updated_at
  before update on public.campaign_intel
  for each row execute function public.set_updated_at();

drop trigger if exists set_call_radar_hot_cache_updated_at on public.call_radar_hot_cache;
create trigger set_call_radar_hot_cache_updated_at
  before update on public.call_radar_hot_cache
  for each row execute function public.set_updated_at();
