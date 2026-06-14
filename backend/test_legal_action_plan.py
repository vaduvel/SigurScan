"""PR-8 — Jurist Dinamic Lvl 2 (M6): plan de acțiune personalizat post-incident.

Reguli pinuite:
- NU schimbă verdictul (rulează post-gate, ca legal_layer).
- Pașii sunt OPERAȚIONALI (sună banca, schimbă parola); articolele de lege rămân
  verbatim din legal_kb.json (reuse legal_cards_for) — zero invenție juridică.
- Personalizare după ce a făcut userul (impacts) + familie + verdict.
- Pași ordonați după urgență (now < today < soon), dedup.
- Bundle: report_package (reuse PR-5) + carduri legale (reuse L1).
- Label UI „Plan de acțiune", niciodată „Jurist"/„Avocat".
"""
from services.legal_action_plan import build_action_plan, URGENCY_ORDER


def _urgencies(plan):
    return [s["urgency"] for s in plan["steps"]]


class TestShape:
    def test_label_is_not_jurist(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["none"])
        assert plan["label"] == "Plan de acțiune"
        assert "jurist" not in plan["label"].lower() and "avocat" not in plan["label"].lower()

    def test_verdict_passthrough_unchanged(self):
        plan = build_action_plan(verdict="SUSPECT", impacts=["clicked_link"])
        assert plan["verdict"] == "SUSPECT"

    def test_disclaimer_present(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["none"])
        assert plan["disclaimer"]

    def test_steps_have_required_fields(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["shared_card"])
        for s in plan["steps"]:
            assert {"order", "urgency", "title", "detail"} <= set(s)
            assert s["urgency"] in URGENCY_ORDER


class TestImpactMapping:
    def test_shared_card_first_step_is_now_and_bank(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["shared_card"],
                                 target={"type": "url", "value_redacted": "x[.]test"})
        assert plan["steps"][0]["urgency"] == "now"
        joined = " ".join(s["title"] + s["detail"] for s in plan["steps"]).lower()
        assert "banc" in joined  # sună banca / blochează cardul
        # cardul legal pe instrumente de plată (art. 311) e atașat
        ids = {c["id"] for c in plan["legal"]["cards"]}
        assert "law-instrumente-plata-311" in ids

    def test_installed_remote_access_has_now_disconnect_step(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["installed_remote_access"])
        now_steps = " ".join(s["detail"].lower() for s in plan["steps"] if s["urgency"] == "now")
        assert "deconect" in now_steps or "dezinstal" in now_steps

    def test_shared_id_document_references_birou_credit_and_identity_card(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["shared_id_document"])
        joined = " ".join(s["title"] + s["detail"] for s in plan["steps"]).lower()
        assert "birou" in joined or "credit" in joined
        ids = {c["id"] for c in plan["legal"]["cards"]}
        assert "law-furt-identitate-327" in ids

    def test_paid_transfer_has_recall_and_inselaciune_card(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["paid_transfer"])
        joined = " ".join(s["title"] + s["detail"] for s in plan["steps"]).lower()
        assert "recall" in joined or "rechem" in joined
        ids = {c["id"] for c in plan["legal"]["cards"]}
        assert "law-inselaciune-244" in ids

    def test_none_impact_is_preventive_with_cercul(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["none"])
        joined = " ".join(s["title"] + s["detail"] for s in plan["steps"]).lower()
        assert "nu plăti" in joined or "nu plati" in joined or "verific" in joined
        assert "cerc" in joined  # a doua opinie out-of-band

    def test_unknown_impact_does_not_crash(self):
        plan = build_action_plan(verdict="SUSPECT", impacts=["totally_unknown_xyz"])
        assert isinstance(plan["steps"], list)


class TestOrderingAndDedup:
    def test_steps_sorted_by_urgency(self):
        plan = build_action_plan(
            verdict="DANGEROUS",
            impacts=["shared_id_document", "shared_card", "clicked_link"],
        )
        ranks = [URGENCY_ORDER.index(u) for u in _urgencies(plan)]
        assert ranks == sorted(ranks)
        # order field e secvențial 1..n
        assert [s["order"] for s in plan["steps"]] == list(range(1, len(plan["steps"]) + 1))

    def test_steps_deduplicated_across_impacts(self):
        # două impacturi care produc același pas (card+otp → ambele „sună banca")
        plan = build_action_plan(verdict="DANGEROUS", impacts=["shared_card", "shared_otp"])
        titles = [s["title"] for s in plan["steps"]]
        assert len(titles) == len(set(titles))


class TestBundles:
    def test_report_package_bundled_with_dnsc(self):
        plan = build_action_plan(verdict="DANGEROUS", family="CONV_BANK_SAFE_ACCOUNT",
                                 impacts=["paid_transfer"],
                                 target={"type": "iban", "value_redacted": "RO** 3456"})
        names = {c["name"] for c in plan["report_package"]["channels"]}
        assert "DNSC" in names

    def test_legal_block_has_label_and_disclaimer(self):
        plan = build_action_plan(verdict="DANGEROUS", impacts=["shared_card"])
        assert plan["legal"]["label"]
        assert plan["legal"]["disclaimer"]

    def test_determinism(self):
        kwargs = dict(verdict="DANGEROUS", family="DOC_BEC_IBAN_CHANGE",
                      impacts=["shared_card", "paid_transfer"],
                      target={"type": "iban", "value_redacted": "RO** 3456"})
        assert build_action_plan(**kwargs) == build_action_plan(**kwargs)


class TestEndpoint:
    def _client(self):
        from fastapi.testclient import TestClient
        import main as app_main
        return TestClient(app_main.app)

    def test_action_plan_endpoint(self):
        client = self._client()
        r = client.post("/v1/legal/action-plan", json={
            "verdict": "DANGEROUS", "family": "CONV_BANK_SAFE_ACCOUNT",
            "impacts": ["shared_card", "paid_transfer"],
            "target_type": "iban", "target_redacted": "RO** 3456"})
        assert r.status_code == 200
        body = r.json()
        assert body["label"] == "Plan de acțiune"
        assert body["steps"] and body["steps"][0]["urgency"] == "now"
        assert "DNSC" in {c["name"] for c in body["report_package"]["channels"]}
