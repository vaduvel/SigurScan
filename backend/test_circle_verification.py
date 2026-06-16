"""PR-6 — Cercul (out-of-band verification) + Guardian second opinion.

Reguli pinuite (MoatOS §6 + §9):
- Cercul NU trece prin verdict_gate — e un protocol semnat, separat de lamă.
- Pairing: protejat + verificator, consimțământ EXPLICIT, revocabil.
- Ping: payload metadata-only (zero conținut), default_on_timeout = PRECAUTIE,
  latency target 10s. Timeout → PRECAUTIE + acțiune out-of-band (tel: nr. real salvat).
- Verificatorul NU poate activa supraveghere; doar protejatul revocă.
- Second opinion: share_level implicit metadata_only; full doar cu consimțământ.
- Zero conținut brut server-side: doar redacted_summary.
"""
import json

import pytest

from services.circle_verification import (
    CircleStore,
    ping_outcome,
    normalize_share_level,
    PING_LATENCY_TARGET_S,
)


# ─── Pure helpers ──────────────────────────────────────────────────────────
class TestPingOutcome:
    def test_its_me_confirms(self):
        assert ping_outcome("its_me")["status"] == "CONFIRMED"

    def test_not_me_rejects_with_out_of_band(self):
        out = ping_outcome("not_me")
        assert out["status"] == "REJECTED"
        assert out["recommended_action"]["channel"] == "out_of_band"

    def test_timeout_is_precautie_not_safe(self):
        out = ping_outcome("timeout")
        assert out["status"] == "PRECAUTIE"
        # NEVERIFICAT, nu coboară riscul: niciodată CONFIRMED/SAFE pe timeout
        assert out["status"] != "CONFIRMED"
        assert out["recommended_action"]["type"] == "call_known_number"
        assert out["recommended_action"]["channel"] == "out_of_band"

    def test_none_defaults_to_precautie(self):
        assert ping_outcome(None)["status"] == "PRECAUTIE"

    def test_unknown_response_defaults_to_precautie(self):
        assert ping_outcome("garbled")["status"] == "PRECAUTIE"


class TestShareLevelNormalization:
    def test_default_is_metadata_only(self):
        assert normalize_share_level(None, consent=False)[0] == "metadata_only"

    def test_full_requires_consent(self):
        level, downgraded = normalize_share_level("full_with_consent", consent=False)
        assert level == "metadata_only"
        assert downgraded is True

    def test_full_with_consent_allowed(self):
        level, downgraded = normalize_share_level("full_with_consent", consent=True)
        assert level == "full_with_consent"
        assert downgraded is False

    def test_redacted_excerpt_allowed_without_consent(self):
        level, downgraded = normalize_share_level("redacted_excerpt", consent=False)
        assert level == "redacted_excerpt"
        assert downgraded is False


# ─── Pairing ───────────────────────────────────────────────────────────────
class TestPairing:
    def test_pair_creates_active_revocable_link(self):
        store = CircleStore()
        link = store.pair(protected_id="u_gran", verifier_id="u_son", consent="explicit")
        assert link.active is True
        assert link.revocable is True
        assert link.consent == "explicit"
        assert link.protected_user_id == "u_gran"
        assert link.verifier_user_id == "u_son"

    def test_pair_requires_explicit_consent(self):
        store = CircleStore()
        with pytest.raises(ValueError):
            store.pair(protected_id="u_gran", verifier_id="u_son", consent="none")

    def test_verifier_cannot_surveil(self):
        # Invariant §6: link-ul NU dă verificatorului nicio capabilitate de supraveghere.
        store = CircleStore()
        link = store.pair(protected_id="u_gran", verifier_id="u_son", consent="explicit")
        d = link.to_dict()
        assert d.get("verifier_can_read_content", False) is False
        assert d.get("verifier_can_surveil", False) is False


class TestRevocation:
    def test_protected_revokes_anytime(self):
        store = CircleStore()
        link = store.pair(protected_id="u_gran", verifier_id="u_son", consent="explicit")
        assert store.revoke(link.link_id, by_user="u_gran") is True
        assert store.get_link(link.link_id).active is False

    def test_verifier_cannot_revoke(self):
        store = CircleStore()
        link = store.pair(protected_id="u_gran", verifier_id="u_son", consent="explicit")
        with pytest.raises(PermissionError):
            store.revoke(link.link_id, by_user="u_son")
        assert store.get_link(link.link_id).active is True


# ─── Ping / respond ────────────────────────────────────────────────────────
class TestPing:
    def _link(self):
        store = CircleStore()
        link = store.pair(protected_id="u_gran", verifier_id="u_son", consent="explicit")
        return store, link

    def test_ping_is_metadata_only_with_precautie_default(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        assert ping.payload_class == "metadata_only"
        assert ping.default_on_timeout == "PRECAUTIE"
        assert ping.latency_target_s == PING_LATENCY_TARGET_S == 10
        assert ping.status == "pending"

    def test_ping_payload_carries_no_raw_content(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        blob = json.dumps(ping.to_dict())
        # metadata-only: nimic care să semene cu transcript/conținut brut
        assert "transcript" not in blob
        assert "raw" not in blob or '"raw_stored":false' in blob.replace(" ", "")

    def test_ping_carries_metadata_only_delivery_intent(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        delivery = ping.to_dict()["delivery"]
        blob = json.dumps(delivery)

        assert delivery["type"] == "push_deeplink"
        assert delivery["target_user_id"] == "u_son"
        assert delivery["deeplink"].startswith("sigurscan://radar?")
        assert f"ping_id={ping.ping_id}" in delivery["deeplink"]
        assert delivery["payload_class"] == "metadata_only"
        assert delivery["raw_content_shared"] is False
        assert "transcript" not in blob and "raw_text" not in blob

    def test_ping_on_missing_link_fails(self):
        store = CircleStore()
        with pytest.raises(KeyError):
            store.create_ping("nope", claim="caller_claims_to_be_verifier")

    def test_ping_on_revoked_link_fails(self):
        store, link = self._link()
        store.revoke(link.link_id, by_user="u_gran")
        with pytest.raises(ValueError):
            store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")

    def test_respond_its_me_confirms_and_resolves(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        res = store.respond(ping.ping_id, "its_me")
        assert res["status"] == "CONFIRMED"
        assert store.get_ping(ping.ping_id).status == "resolved"

    def test_respond_not_me_rejects(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        res = store.respond(ping.ping_id, "not_me")
        assert res["status"] == "REJECTED"
        assert res["recommended_action"]["channel"] == "out_of_band"

    def test_timeout_resolves_to_precautie_with_tel_action(self):
        store, link = self._link()
        ping = store.create_ping(link.link_id, claim="caller_claims_to_be_verifier")
        res = store.resolve_timeout(ping.ping_id)
        assert res["status"] == "PRECAUTIE"
        assert res["recommended_action"]["type"] == "call_known_number"
        assert store.get_ping(ping.ping_id).verifier_response == "timeout"


# ─── Guardian second opinion ───────────────────────────────────────────────
class TestSecondOpinion:
    def test_default_share_is_metadata_only(self):
        store = CircleStore()
        so = store.second_opinion(
            case_id="sc_1", protected_id="u_gran", guardian_id="u_son",
            redacted_summary={"family": "IMP-02"},
        )
        assert so.share_level == "metadata_only"
        assert so.status == "pending"

    def test_full_without_consent_downgrades(self):
        store = CircleStore()
        so = store.second_opinion(
            case_id="sc_1", protected_id="u_gran", guardian_id="u_son",
            redacted_summary={"family": "IMP-02"},
            share_level="full_with_consent", consent=False,
        )
        assert so.share_level == "metadata_only"

    def test_only_redacted_summary_is_stored(self):
        store = CircleStore()
        so = store.second_opinion(
            case_id="sc_1", protected_id="u_gran", guardian_id="u_son",
            redacted_summary={"family": "IMP-02", "verdict": "SUSPECT"},
        )
        blob = json.dumps(so.to_dict())
        # zero conținut brut: doar redacted_summary structurat
        assert "redacted_summary" in blob
        assert so.to_dict()["redacted_summary"] == {"family": "IMP-02", "verdict": "SUSPECT"}


# ─── Endpoints ─────────────────────────────────────────────────────────────
class TestEndpoints:
    def _client(self):
        from fastapi.testclient import TestClient
        import main as app_main
        return TestClient(app_main.app)

    def test_pair_ping_respond_flow(self):
        client = self._client()
        r = client.post("/v1/circle/pair", json={
            "protected_id": "u_gran", "verifier_id": "u_son", "consent": "explicit"})
        assert r.status_code == 200
        link_id = r.json()["link_id"]

        r = client.post("/v1/circle/ping", json={
            "link_id": link_id, "claim": "caller_claims_to_be_verifier"})
        assert r.status_code == 200
        ping = r.json()
        assert ping["default_on_timeout"] == "PRECAUTIE"
        assert ping["delivery"]["payload_class"] == "metadata_only"
        assert ping["delivery"]["raw_content_shared"] is False
        ping_id = ping["ping_id"]

        r = client.post("/v1/circle/respond", json={"ping_id": ping_id, "response": "its_me"})
        assert r.status_code == 200
        assert r.json()["status"] == "CONFIRMED"

    def test_pair_without_consent_rejected(self):
        client = self._client()
        r = client.post("/v1/circle/pair", json={
            "protected_id": "u_gran", "verifier_id": "u_son", "consent": "none"})
        assert r.status_code == 400

    def test_revoke_endpoint(self):
        client = self._client()
        link_id = client.post("/v1/circle/pair", json={
            "protected_id": "u_g", "verifier_id": "u_s", "consent": "explicit"}).json()["link_id"]
        r = client.post("/v1/circle/revoke", json={"link_id": link_id, "by_user": "u_g"})
        assert r.status_code == 200
        assert r.json()["active"] is False

    def test_second_opinion_endpoint_defaults_metadata_only(self):
        client = self._client()
        r = client.post("/v1/guardian/second-opinion", json={
            "case_id": "sc_1", "protected_id": "u_g", "guardian_id": "u_s",
            "redacted_summary": {"family": "IMP-02"}})
        assert r.status_code == 200
        assert r.json()["share_level"] == "metadata_only"


class TestSupabasePersistenceWiring:
    """Write-through best-effort: endpoint-urile cheamă supabase_store (no-op fără
    chei). Verificăm că wiring-ul există — Codex doar aplică migrarea + pune cheile."""

    def _client(self):
        from fastapi.testclient import TestClient
        import main as app_main
        return TestClient(app_main.app)

    def test_pair_persists_link(self, monkeypatch):
        import main as app_main
        calls = {}
        monkeypatch.setattr(app_main.supabase_store, "save_circle_link",
                            lambda link: calls.setdefault("link", link))
        client = self._client()
        client.post("/v1/circle/pair", json={
            "protected_id": "u_g", "verifier_id": "u_s", "consent": "explicit"})
        assert calls.get("link", {}).get("protected_user_id") == "u_g"

    def test_revoke_persists_revocation(self, monkeypatch):
        import main as app_main
        seen = {}
        monkeypatch.setattr(app_main.supabase_store, "mark_circle_link_revoked",
                            lambda link_id: seen.setdefault("id", link_id))
        client = self._client()
        link_id = client.post("/v1/circle/pair", json={
            "protected_id": "u_g", "verifier_id": "u_s", "consent": "explicit"}).json()["link_id"]
        client.post("/v1/circle/revoke", json={"link_id": link_id, "by_user": "u_g"})
        assert seen.get("id") == link_id

    def test_second_opinion_persists(self, monkeypatch):
        import main as app_main
        seen = {}
        monkeypatch.setattr(app_main.supabase_store, "save_guardian_second_opinion",
                            lambda op: seen.setdefault("op", op))
        client = self._client()
        client.post("/v1/guardian/second-opinion", json={
            "case_id": "sc_9", "protected_id": "u_g", "guardian_id": "u_s",
            "redacted_summary": {"family": "IMP-02"}})
        assert seen.get("op", {}).get("case_id") == "sc_9"

    def test_ping_rehydrates_circle_link_from_supabase(self, monkeypatch):
        import main as app_main
        monkeypatch.setattr(app_main, "_circle_store", CircleStore())
        monkeypatch.setattr(app_main.supabase_store, "load_circle_link", lambda link_id: {
            "link_id": link_id,
            "protected_user_id": "u_g",
            "verifier_user_id": "u_s",
            "consent": "explicit",
            "revocable": True,
            "active": True,
            "created_at": 1,
            "revoked_at": None,
        })
        saved = {}
        monkeypatch.setattr(app_main.supabase_store, "save_verification_ping",
                            lambda ping: saved.setdefault("ping", ping))

        r = self._client().post("/v1/circle/ping", json={
            "link_id": "cl_persisted", "claim": "caller_claims_to_be_verifier"})

        assert r.status_code == 200
        assert r.json()["link_id"] == "cl_persisted"
        assert saved.get("ping", {}).get("link_id") == "cl_persisted"

    def test_ping_persists_delivery_outbox_event(self, monkeypatch):
        import main as app_main
        delivered = {}
        monkeypatch.setattr(app_main.supabase_store, "save_circle_delivery_event",
                            lambda event: delivered.setdefault("event", event))

        client = self._client()
        link_id = client.post("/v1/circle/pair", json={
            "protected_id": "u_g", "verifier_id": "u_s", "consent": "explicit"}).json()["link_id"]
        r = client.post("/v1/circle/ping", json={
            "link_id": link_id, "claim": "caller_claims_to_be_verifier"})

        assert r.status_code == 200
        event = delivered.get("event", {})
        assert event["type"] == "push_deeplink"
        assert event["target_user_id"] == "u_s"
        assert event["payload_class"] == "metadata_only"
        assert event["raw_content_shared"] is False

    def test_respond_rehydrates_ping_from_supabase(self, monkeypatch):
        import main as app_main
        monkeypatch.setattr(app_main, "_circle_store", CircleStore())
        monkeypatch.setattr(app_main.supabase_store, "load_verification_ping", lambda ping_id: {
            "ping_id": ping_id,
            "link_id": "cl_persisted",
            "claim": "caller_claims_to_be_verifier",
            "payload_class": "metadata_only",
            "default_on_timeout": "PRECAUTIE",
            "latency_target_s": 10,
            "status": "pending",
            "verifier_response": None,
            "created_at": 1,
            "resolved_at": None,
        })
        updated = {}
        monkeypatch.setattr(app_main.supabase_store, "update_verification_ping",
                            lambda ping_id, response, status: updated.setdefault(
                                "row", {"ping_id": ping_id, "response": response, "status": status}))

        r = self._client().post("/v1/circle/respond", json={
            "ping_id": "vp_persisted", "response": "its_me"})

        assert r.status_code == 200
        assert r.json()["status"] == "CONFIRMED"
        assert updated.get("row") == {
            "ping_id": "vp_persisted", "response": "its_me", "status": "resolved"}

    def test_revoke_rehydrates_circle_link_from_supabase(self, monkeypatch):
        import main as app_main
        monkeypatch.setattr(app_main, "_circle_store", CircleStore())
        monkeypatch.setattr(app_main.supabase_store, "load_circle_link", lambda link_id: {
            "link_id": link_id,
            "protected_user_id": "u_g",
            "verifier_user_id": "u_s",
            "consent": "explicit",
            "revocable": True,
            "active": True,
            "created_at": 1,
            "revoked_at": None,
        })
        revoked = {}
        monkeypatch.setattr(app_main.supabase_store, "mark_circle_link_revoked",
                            lambda link_id: revoked.setdefault("id", link_id))

        r = self._client().post("/v1/circle/revoke", json={
            "link_id": "cl_persisted", "by_user": "u_g"})

        assert r.status_code == 200
        assert r.json()["active"] is False
        assert revoked.get("id") == "cl_persisted"
