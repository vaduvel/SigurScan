-- Vendor memory: istoric IBAN per CUI (pentru detecția „cont schimbat" / BEC).
-- Backend-ul scrie write-through best-effort (services/vendor_memory.py).
-- Se memorează DOAR din scanări fără semnale de fraudă (anti-poisoning).
create table if not exists public.vendor_iban_memory (
  cui          text not null,
  iban         text not null,
  seen_count   integer not null default 1 check (seen_count >= 1),
  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  primary key (cui, iban)
);

create index if not exists vendor_iban_memory_cui_idx on public.vendor_iban_memory (cui);

alter table public.vendor_iban_memory enable row level security;
