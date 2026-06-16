-- Reputation Graph v1 — privacy-first cross-surface intel.
-- Stores only hashed/canonical identifiers. No raw phone numbers, IBANs, emails or URLs.

create table if not exists public.reputation_observations (
  id uuid primary key default gen_random_uuid(),
  target_type text not null
    check (target_type in ('phone','domain','url','iban','email','wallet','text','unknown')),
  target_hash text not null check (target_hash ~ '^[0-9a-f]{64}$'),
  source text not null default 'unknown',
  risk_level text not null default 'medium',
  family text,
  report_count integer not null default 1 check (report_count > 0),
  evidence_quality text not null default 'medium'
    check (evidence_quality in ('low','medium','high','authoritative')),
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.reputation_edges (
  id uuid primary key default gen_random_uuid(),
  source_type text not null
    check (source_type in ('phone','domain','url','iban','email','wallet','text','unknown')),
  source_hash text not null check (source_hash ~ '^[0-9a-f]{64}$'),
  target_type text not null
    check (target_type in ('phone','domain','url','iban','email','wallet','text','unknown')),
  target_hash text not null check (target_hash ~ '^[0-9a-f]{64}$'),
  relation text not null
    check (relation in ('pays_to','co_occurred_in_case','same_campaign','claimed_by','redirects_to')),
  source text not null default 'case_correlation',
  family text,
  evidence_quality text not null default 'medium'
    check (evidence_quality in ('low','medium','high','authoritative')),
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create table if not exists public.reputation_allowlist (
  target_type text not null
    check (target_type in ('phone','domain','url','iban','email','wallet','text','unknown')),
  target_hash text not null check (target_hash ~ '^[0-9a-f]{64}$'),
  source text not null,
  reason text not null default 'official',
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  primary key (target_type, target_hash, source)
);

create index if not exists reputation_observations_target_idx
  on public.reputation_observations (target_type, target_hash);
create index if not exists reputation_observations_observed_idx
  on public.reputation_observations (observed_at desc);
create index if not exists reputation_observations_risk_idx
  on public.reputation_observations (target_type, risk_level);
create index if not exists reputation_edges_source_idx
  on public.reputation_edges (source_type, source_hash);
create index if not exists reputation_edges_target_idx
  on public.reputation_edges (target_type, target_hash);
create index if not exists reputation_edges_relation_idx
  on public.reputation_edges (relation);

alter table public.reputation_observations enable row level security;
alter table public.reputation_edges enable row level security;
alter table public.reputation_allowlist enable row level security;

revoke all on table public.reputation_observations from anon;
revoke all on table public.reputation_observations from authenticated;
revoke all on table public.reputation_edges from anon;
revoke all on table public.reputation_edges from authenticated;
revoke all on table public.reputation_allowlist from anon;
revoke all on table public.reputation_allowlist from authenticated;

grant select, insert, update, delete on table public.reputation_observations to service_role;
grant select, insert, update, delete on table public.reputation_edges to service_role;
grant select, insert, update, delete on table public.reputation_allowlist to service_role;
