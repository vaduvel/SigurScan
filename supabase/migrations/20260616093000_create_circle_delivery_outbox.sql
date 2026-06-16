-- Cercul delivery outbox — metadata-only push/deeplink queue.
-- No raw content. A separate worker/FCM sender can consume pending rows.

create table if not exists public.circle_delivery_outbox (
  id uuid primary key default gen_random_uuid(),
  event_type text not null default 'push_deeplink'
    check (event_type in ('push_deeplink')),
  target_user_id text not null,
  deeplink text not null check (deeplink like 'sigurscan://%'),
  payload_class text not null default 'metadata_only'
    check (payload_class = 'metadata_only'),
  raw_content_shared boolean not null default false
    check (raw_content_shared is false),
  status text not null default 'pending'
    check (status in ('pending','sent','failed','expired')),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  sent_at timestamptz
);

create index if not exists circle_delivery_outbox_target_idx
  on public.circle_delivery_outbox (target_user_id, status);
create index if not exists circle_delivery_outbox_created_idx
  on public.circle_delivery_outbox (created_at desc);

alter table public.circle_delivery_outbox enable row level security;

revoke all on table public.circle_delivery_outbox from anon;
revoke all on table public.circle_delivery_outbox from authenticated;

grant select, insert, update, delete on table public.circle_delivery_outbox to service_role;
