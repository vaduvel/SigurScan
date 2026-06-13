-- Freeze hardening: MoatOS PR0-PR4 persistence tables are backend/service-role
-- only. RLS is enabled in the create migration, but Supabase grants default
-- table privileges to anon/authenticated unless they are explicitly revoked.

revoke all on table public.brand_truth_manifest from anon;
revoke all on table public.brand_truth_manifest from authenticated;

revoke all on table public.campaign_intel from anon;
revoke all on table public.campaign_intel from authenticated;

revoke all on table public.campaign_fingerprint from anon;
revoke all on table public.campaign_fingerprint from authenticated;

revoke all on table public.circle_link from anon;
revoke all on table public.circle_link from authenticated;

revoke all on table public.guardian_audit_log from anon;
revoke all on table public.guardian_audit_log from authenticated;

revoke all on table public.guardian_dangerous_approval from anon;
revoke all on table public.guardian_dangerous_approval from authenticated;

revoke all on table public.call_radar_hot_cache from anon;
revoke all on table public.call_radar_hot_cache from authenticated;
