-- PR-6 §6/§9 — Cercul (out-of-band verification) + Guardian second opinion.
-- NB: distinct de `circle_link` (graful de corelare intel din migrarea anterioară).
-- Aici: relația umană protejat↔verificator, ping-urile de verificare și a doua opinie.

-- Pairing semnat protejat↔verificator (consimțământ explicit, revocabil).
-- NB: id-urile sunt `text` (prefixate „cl_/vp_/go_" de backend), nu uuid — backend-ul
-- furnizează mereu id-ul (services/circle_verification.py), nu DB-ul.
create table if not exists public.circle_links (
  link_id           text primary key,
  protected_user_id text not null,
  verifier_user_id  text not null,
  consent           text not null default 'explicit' check (consent in ('explicit')),
  revocable         boolean not null default true,
  active            boolean not null default true,
  created_at        timestamptz not null default now(),
  revoked_at        timestamptz,
  check (protected_user_id <> verifier_user_id)
);

-- Ping de verificare out-of-band. Payload metadata-only; default_on_timeout = PRECAUTIE.
create table if not exists public.verification_pings (
  ping_id            text primary key,
  link_id            text not null references public.circle_links(link_id) on delete cascade,
  claim              text not null default 'caller_claims_to_be_verifier',
  payload_class      text not null default 'metadata_only' check (payload_class in ('metadata_only')),
  default_on_timeout text not null default 'PRECAUTIE',
  latency_target_s   integer not null default 10 check (latency_target_s > 0),
  status             text not null default 'pending' check (status in ('pending','resolved')),
  verifier_response  text check (verifier_response in ('its_me','not_me','timeout')),
  created_at         timestamptz not null default now(),
  resolved_at        timestamptz
);

-- A doua opinie pentru protejat. share_level implicit metadata_only; full doar cu consimțământ.
-- Linia roșie: doar redacted_summary structurat, ZERO conținut brut.
create table if not exists public.guardian_second_opinion (
  request_id        text primary key,
  case_id           text not null,
  protected_user_id text not null,
  guardian_user_id  text not null,
  share_level       text not null default 'metadata_only'
                    check (share_level in ('metadata_only','redacted_excerpt','full_with_consent')),
  share_downgraded  boolean not null default false,
  redacted_summary  jsonb not null default '{}'::jsonb,
  status            text not null default 'pending' check (status in ('pending','answered','expired')),
  created_at        timestamptz not null default now(),
  resolved_at       timestamptz
);

create index if not exists circle_links_protected_idx on public.circle_links (protected_user_id);
create index if not exists circle_links_verifier_idx on public.circle_links (verifier_user_id);
create index if not exists circle_links_active_idx on public.circle_links (active);
create index if not exists verification_pings_link_idx on public.verification_pings (link_id);
create index if not exists verification_pings_status_idx on public.verification_pings (status);
create index if not exists guardian_second_opinion_case_idx on public.guardian_second_opinion (case_id);
create index if not exists guardian_second_opinion_protected_idx on public.guardian_second_opinion (protected_user_id);
create index if not exists guardian_second_opinion_status_idx on public.guardian_second_opinion (status);

alter table public.circle_links enable row level security;
alter table public.verification_pings enable row level security;
alter table public.guardian_second_opinion enable row level security;
