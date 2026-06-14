import asyncio

from services import whois_ssl_signals


def test_check_rdap_follows_rdap_bootstrap_redirect(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "events": [
                    {
                        "eventAction": "registration",
                        "eventDate": "1997-09-15T04:00:00Z",
                    }
                ]
            }

    class FakeAsyncClient:
        def __init__(self, *, timeout, follow_redirects=False):
            self.follow_redirects = follow_redirects

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def get(self, url, headers):
            if self.follow_redirects:
                return FakeResponse()
            response = FakeResponse()
            response.status_code = 302
            return response

    monkeypatch.setattr(whois_ssl_signals.httpx, "AsyncClient", FakeAsyncClient)

    result = asyncio.run(whois_ssl_signals.check_rdap("google.com", timeout=2.0))

    assert result["registered"] is True
    assert result["age_days"] is not None
    assert result["registration_date"].startswith("1997-09-15")
