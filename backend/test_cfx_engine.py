"""PR-4: CFX determinist v1 — fingerprint extraction + campaign matching."""

import pytest
from services.cfx_engine import (
    CfxStore, extract_fingerprint, compute_similarity, _simhash, _clean_skeleton_text,
    CampaignFingerprint, FingerprintMatch,
)


class TestTextCleaning:
    def test_removes_pii_phone(self):
        result = _clean_skeleton_text("Sună la 0712345678 pentru detalii")
        assert "0712345678" not in result

    def test_removes_iban(self):
        result = _clean_skeleton_text("Plata în RO49AAAA1B31007593840000")
        assert "ro49" not in result

    def test_removes_email(self):
        result = _clean_skeleton_text("Contactează suport@banca.ro")
        assert "suport@banca.ro" not in result

    def test_removes_url(self):
        result = _clean_skeleton_text("Intră pe https://phishing.xyz/pay")
        assert "https" not in result
        assert "phishing" not in result

    def test_normalizes_diacritics(self):
        result = _clean_skeleton_text("Înștiințare privind o fraudă")
        assert "in" in result
        assert "științare" not in result

    def test_strips_short_tokens(self):
        result = _clean_skeleton_text("a a a ab abc")
        tokens = [t for t in result.split() if len(t) > 2]
        assert "abc" in tokens
        assert len(tokens) == 1


class TestSimHash:
    def test_simhash_64_bits(self):
        h = _simhash(["test", "text", "fraud"])
        assert h.bit_length() <= 64
        assert h > 0

    def test_similar_texts_similar_hash(self):
        t1 = _simhash(["transfer", "cont", "sigur", "banca"])
        t2 = _simhash(["transfera", "contul", "sigur", "banca"])
        diff = bin(t1 ^ t2).count("1")
        assert diff < 22

    def test_different_texts_different_hash(self):
        t1 = _simhash(["oferta", "cadou", "castig"])
        t2 = _simhash(["politia", "arest", "proces"])
        diff = bin(t1 ^ t2).count("1")
        assert diff > 20


class TestExtractFingerprint:
    def test_bank_safe_account(self):
        fp = extract_fingerprint(
            "Transferă fondurile în contul nostru sigur. Sună la banca urgent!",
            channel="sms",
            claimed_identity="Banca Transilvania",
        )
        assert fp.identity_claim_sig == "bank"
        assert "move_money" in fp.ask_sequence_sig
        assert "urgency" in fp.ask_sequence_sig
        assert fp.channel_class == "sms"
        assert fp.text_skeleton_hash != ""

    def test_fan_courier_tax(self):
        fp = extract_fingerprint(
            "Ai o taxă vamală de plată pentru coletul FAN Courier. Plateste cardul aici.",
            channel="sms",
            claimed_identity="FAN Courier",
        )
        assert fp.identity_claim_sig == "courier"
        assert fp.url_shape_sig == "no-url"
        assert fp.text_skeleton_hash != ""

    def test_isarescu_deepfake(self):
        fp = extract_fingerprint(
            "Mugur Isărescu: oportunitate unică de investiții. Profit garantat 15%!",
            channel="social_dm",
        )
        assert fp.channel_class == "sms"
        assert fp.text_skeleton_hash != ""

    def test_police_threat(self):
        fp = extract_fingerprint(
            "Aici ofițer de la Poliția Română. Ai un dosar penal. Transferă 5000 RON în contul sigur.",
            channel="phone_call",
            claimed_identity="Poliția Română",
        )
        assert fp.identity_claim_sig == "police"
        assert "authority_claim" in fp.ask_sequence_sig
        assert "threat" in fp.ask_sequence_sig
        assert "move_money" in fp.ask_sequence_sig
        assert fp.channel_class == "phone_transcript"

    def test_olx_card_receive_money(self):
        fp = extract_fingerprint(
            "Salut, sunt interesat de produs. Dă-mi numărul de card să îți trimit banii.",
            channel="im",
            claimed_identity="OLX",
        )
        assert fp.cta_pattern_sig == "card_details"
        assert "card" in fp.sensitive_request_sig


class TestUrlShape:
    def test_no_url(self):
        from services.cfx_engine import _url_shape
        assert _url_shape([]) == "no-url"

    def test_lookalike_domain(self):
        from services.cfx_engine import _url_shape
        assert _url_shape(["https://fan-livrare.xyz/pay"]) == "brand-lookalike-domain"

    def test_shortener(self):
        from services.cfx_engine import _url_shape
        assert _url_shape(["https://bit.ly/3xYZ"]) == "shortener"


class TestCfxStore:
    def test_empty_store_no_match(self):
        store = CfxStore()
        fp = extract_fingerprint("test text", channel="sms")
        matches = store.match(fp)
        assert len(matches) == 0

    def test_store_and_match(self):
        store = CfxStore()
        fp1 = extract_fingerprint(
            "Transferă fondurile în contul sigur. Sună la banca.",
            channel="sms",
        )
        fp1.fingerprint_id = "cf_test_001"
        store.put(fp1)
        fp2 = extract_fingerprint(
            "Transfera banii in contul nostru sigur. Suna la banca urgent!",
            channel="sms",
        )
        matches = store.match(fp2)
        assert len(matches) == 1
        assert matches[0].fingerprint_id == "cf_test_001"
        assert matches[0].similarity >= 0.5

    def test_different_text_low_similarity(self):
        store = CfxStore()
        fp1 = extract_fingerprint("Transferă fondurile în cont sigur", channel="sms")
        fp1.fingerprint_id = "cf_test_002"
        store.put(fp1)
        fp2 = extract_fingerprint("Ofertă cadou de ziua ta! Câștigă un iPhone", channel="sms")
        matches = store.match(fp2)
        if matches:
            assert matches[0].similarity < 0.6

    def test_match_above_threshold(self):
        store = CfxStore()
        fp1 = extract_fingerprint(
            "Suna la banca, transfera in contul sigur, urgent!",
            channel="phone_call",
        )
        fp1.fingerprint_id = "cf_test_003"
        store.put(fp1)
        fp2 = extract_fingerprint(
            "Sună la bancă, transferă în contul sigur, urgent!",
            channel="phone_call",
        )
        matches = store.match(fp2)
        if matches:
            assert any(m.matched for m in matches)

    def test_zero_raw_iocs(self):
        fp = extract_fingerprint("test text", channel="sms")
        assert fp.no_raw_iocs is True
        d = fp.to_dict()
        assert d["text_skeleton_hash"] != ""

    def test_similarity_identical_fingerprints(self):
        fp = extract_fingerprint("transferă fondurile în cont sigur", channel="sms")
        sim = compute_similarity(fp, fp)
        assert sim >= 0.99
