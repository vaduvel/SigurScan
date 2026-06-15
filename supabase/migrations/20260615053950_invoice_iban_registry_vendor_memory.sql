-- InvoiceTruth: registru negativ IBAN + istoric IBAN per vendor.
-- Accesul este backend service-role only. RLS ramane activ si nu cream politici
-- publice pentru anon/authenticated.

create table if not exists public.negative_iban_registry (
  iban text primary key,
  source text not null default 'manual'
    check (source in ('dnsc_alert', 'community_report', 'press', 'official_ip_office', 'court', 'manual')),
  family text,
  report_count integer not null default 1 check (report_count >= 1),
  created_at timestamptz not null default now(),
  last_reported_at timestamptz not null default now()
);

create index if not exists negative_iban_registry_source_idx
  on public.negative_iban_registry (source);

alter table public.negative_iban_registry enable row level security;

create table if not exists public.vendor_iban_memory (
  cui text not null,
  iban text not null,
  seen_count integer not null default 1 check (seen_count >= 1),
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  primary key (cui, iban)
);

create index if not exists vendor_iban_memory_cui_idx
  on public.vendor_iban_memory (cui);

alter table public.vendor_iban_memory enable row level security;
