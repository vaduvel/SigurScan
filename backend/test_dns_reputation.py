"""Pilon nou — DNS reputation (gratis, fără cheie, Play-safe).

Semnale:
- blocked: domeniul rezolvă pe DNS normal DAR e blocat de DNS-ul de securitate
  (Cloudflare 1.1.1.2 / Quad9) → bloc autoritar de malware/phishing → terminal.
- suspended: nameservere de suspendare (ex. Tucows trs-dns.com) → semnal de abuz,
  ponderat (medium), niciodată terminal solo.
- nxdomain: nu rezolvă nicăieri → posibil luat jos; ponderat medium.
- resolves: rezolvă normal, nu e blocat → fără semnal de risc.

Clasificatorul e PUR (fără rețea); wrapper-ul de rețea primește un doh_get injectabil.
"""
from services.dns_reputation import (
    classify_dns,
    check_dns_reputation,
    dns_summary_entry,
    dns_infra_entry,
)


class TestClassifier:
    def test_single_security_resolver_block_without_consensus_is_weighted(self):
        rep = classify_dns(
            normal_status=0,
            normal_ips=["1.2.3.4"],
            security_status=3,
            security_ips=[],
            ns_hosts=["ns1.example.com"],
            security_results=[
                ("cloudflare_security", 3, []),
                ("quad9", 0, ["1.2.3.4"]),
            ],
        )

        assert rep.status == "security_disagreement"
        assert rep.severity == "medium"
        assert dns_summary_entry(rep) is None
        assert dns_infra_entry(rep)["verdict"] == "security_dns_disagreement"

    def test_multiple_security_resolvers_block_is_hard(self):
        rep = classify_dns(
            normal_status=0,
            normal_ips=["1.2.3.4"],
            security_status=3,
            security_ips=[],
            ns_hosts=["ns1.example.com"],
            security_results=[
                ("cloudflare_security", 3, []),
                ("quad9", 3, []),
            ],
        )

        assert rep.status == "blocked"
        assert dns_summary_entry(rep)["status"] == "malicious"

    def test_blocked_when_security_refuses_but_normal_resolves(self):
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=3, security_ips=[], ns_hosts=["ns1.example.com"])
        assert rep.status == "blocked"
        assert rep.severity == "high"

    def test_blocked_when_security_returns_sentinel_ip(self):
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=0, security_ips=["0.0.0.0"], ns_hosts=[])
        assert rep.status == "blocked"

    def test_suspended_on_registrar_hold_ns(self):
        rep = classify_dns(normal_status=3, normal_ips=[], security_status=3,
                           security_ips=[], ns_hosts=["ns.trs-dns.com", "trs-ops.tucows.com"])
        assert rep.status == "suspended"
        assert rep.severity == "medium"

    def test_nxdomain_when_nothing_resolves(self):
        rep = classify_dns(normal_status=3, normal_ips=[], security_status=3,
                           security_ips=[], ns_hosts=["ns1.legit.com"])
        assert rep.status == "nxdomain"
        assert rep.severity == "medium"

    def test_resolves_clean(self):
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=0, security_ips=["1.2.3.4"], ns_hosts=["ns1.legit.com"])
        assert rep.status == "resolves"
        assert rep.severity == "low"

    def test_blocked_takes_priority_over_suspended(self):
        # rezolvă normal + blocat la security = blocked (mai informativ decât NS hold)
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=3, security_ips=[], ns_hosts=["ns.trs-dns.com"])
        assert rep.status == "blocked"


class TestMappers:
    def test_blocked_maps_to_hard_malicious_provider(self):
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=3, security_ips=[], ns_hosts=[])
        entry = dns_summary_entry(rep)
        assert entry["status"] == "malicious"      # hard → terminal prin mecanismul existent
        assert entry["severity"] == "high"
        assert entry["consulted"] is True

    def test_resolves_has_clean_infra_entry(self):
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=0, security_ips=["1.2.3.4"], ns_hosts=[])
        assert dns_summary_entry(rep) is None
        infra = dns_infra_entry(rep)
        assert infra["status"] == "clean"
        assert infra["verdict"] == "resolves"
        assert infra["consulted"] is True

    def test_suspended_is_weighted_medium_not_terminal(self):
        rep = classify_dns(normal_status=3, normal_ips=[], security_status=3,
                           security_ips=[], ns_hosts=["ns.trs-dns.com"])
        assert dns_summary_entry(rep) is None          # NU intră ca provider hard
        infra = dns_infra_entry(rep)
        assert infra["status"] == "suspicious"
        assert infra["severity"] == "medium"           # ponderat, nu terminal


class TestNetworkWrapperInjectable:
    def test_uses_injected_doh_and_classifies_consensus_block(self):
        calls = []

        def fake_doh(resolver, name, qtype, timeout):
            calls.append((resolver, qtype))
            if ("security" in resolver or "quad9" in resolver) and qtype == "A":
                return 3, []                 # security blochează
            if qtype == "A":
                return 0, ["1.2.3.4"]         # normal rezolvă
            if qtype == "NS":
                return 0, ["ns1.example.com"]
            return 0, []

        rep = check_dns_reputation("flixsou.site", doh_get=fake_doh)
        assert rep.status == "blocked"
        assert calls  # a fost folosit doh-ul injectat, fără rețea reală

    def test_network_wrapper_uses_multiple_resolvers_for_consensus(self):
        calls = []

        def fake_doh(resolver, name, qtype, timeout):
            calls.append((resolver, qtype))
            if "security" in resolver and qtype == "A":
                return 3, []
            if "quad9" in resolver and qtype == "A":
                return 0, ["1.2.3.4"]
            if qtype == "A":
                return 0, ["1.2.3.4"]
            if qtype == "NS":
                return 0, ["ns1.example.com"]
            return 0, []

        rep = check_dns_reputation("flixsou.site", doh_get=fake_doh)
        resolvers = {resolver for resolver, _ in calls}
        assert any("dns.google" in resolver for resolver in resolvers)
        assert any("quad9" in resolver for resolver in resolvers)
        assert rep.status == "security_disagreement"

    def test_network_wrapper_treats_resolver_timeout_as_unknown_not_exception(self):
        def fake_doh(resolver, name, qtype, timeout):
            if "quad9" in resolver and qtype == "A":
                raise TimeoutError("quad9 timeout")
            if "security" in resolver and qtype == "A":
                return 3, []
            if qtype == "A":
                return 0, ["1.2.3.4"]
            if qtype == "NS":
                return 0, ["ns1.example.com"]
            return 2, []

        rep = check_dns_reputation("flixsou.site", doh_get=fake_doh)

        assert rep.status == "security_disagreement"
        assert rep.severity == "medium"

    def test_empty_domain_is_unknown(self):
        rep = check_dns_reputation("", doh_get=lambda *a, **k: (0, []))
        assert rep.status == "unknown"


class TestPipelineRecognition:
    """blocked → summary['dns_security'] cu status malicious → recunoscut de
    _has_bad_provider_verdict (mecanism existent, fără rescriere de gate)."""

    def test_dns_security_recognized_as_bad_provider(self):
        import main as app_main
        rep = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                           security_status=3, security_ips=[], ns_hosts=[])
        summary = {"dns_security": dns_summary_entry(rep)}
        assert app_main._has_bad_provider_verdict(summary) is True

    def test_default_flag_is_off(self):
        # Free-first opt-in: implicit OFF, nu schimbă comportamentul/latency by default.
        import main as app_main
        assert app_main.ENABLE_DNS_REPUTATION is False

    def test_maybe_add_populates_summary_when_enabled(self, monkeypatch):
        import main as app_main
        from services import dns_reputation

        blocked = classify_dns(normal_status=0, normal_ips=["1.2.3.4"],
                               security_status=3, security_ips=[], ns_hosts=[])
        monkeypatch.setattr(app_main, "ENABLE_DNS_REPUTATION", True)
        monkeypatch.setattr(dns_reputation, "check_dns_reputation", lambda domain: blocked)

        summary = {}
        app_main._maybe_add_dns_reputation(summary, [{"final_url": "https://flixsou.site/x"}])
        assert summary.get("dns_security", {}).get("status") == "malicious"
        assert app_main._has_bad_provider_verdict(summary) is True
