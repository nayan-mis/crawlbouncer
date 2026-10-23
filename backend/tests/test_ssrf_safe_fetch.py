"""
Tests for ssrf_safe_fetch.resolve_and_pin — the shared helper that
replaced three independent, driftable copies of "validate a hostname,
then let the HTTP client resolve it again independently" across
origin_proxy.py and agent_mirror.py.
"""
import pytest
from app.services.ssrf_safe_fetch import resolve_and_pin, UnsafeURLError


class TestResolveAndPin:

    def test_localhost_is_rejected(self):
        """localhost resolves to 127.0.0.1 — a real DNS resolution,
        not a mocked one, confirming the loopback check works against
        an actual resolver call, not just a table of literals."""
        with pytest.raises(UnsafeURLError, match="non-public"):
            resolve_and_pin("http://localhost:8000/path")

    def test_literal_private_ip_is_rejected(self):
        with pytest.raises(UnsafeURLError, match="non-public"):
            resolve_and_pin("http://10.0.0.5/path")

    def test_literal_link_local_metadata_ip_is_rejected(self):
        """169.254.169.254 is the AWS/GCP/Azure cloud metadata
        endpoint — the single highest-value SSRF target in any
        cloud deployment (instance credentials, etc). Must be
        rejected regardless of framing."""
        with pytest.raises(UnsafeURLError, match="non-public"):
            resolve_and_pin("http://169.254.169.254/latest/meta-data/")

    def test_loopback_literal_is_rejected(self):
        with pytest.raises(UnsafeURLError, match="non-public"):
            resolve_and_pin("http://127.0.0.1:9000/")

    def test_public_ip_is_accepted_and_pinned(self):
        """1.1.1.1 (Cloudflare DNS) is a stable, known-public literal
        — using it directly (rather than a real hostname) keeps this
        test independent of external DNS while still exercising the
        real ipaddress.is_global check."""
        pinned_url, extensions = resolve_and_pin("http://1.1.1.1:443/foo?q=1")
        assert "1.1.1.1" in pinned_url
        assert pinned_url.endswith("/foo?q=1")
        # http, not https — no SNI extension needed
        assert extensions == {}

    def test_https_sets_sni_hostname_extension_to_the_real_hostname(self):
        """The whole point of the extensions dict: TLS SNI/cert
        validation must still check the real hostname even though
        the socket connects to the pinned IP literal — otherwise
        every HTTPS origin would fail certificate validation."""
        pinned_url, extensions = resolve_and_pin("https://1.1.1.1/")
        assert extensions == {"sni_hostname": "1.1.1.1"}

    def test_credentials_in_url_rejected(self):
        with pytest.raises(UnsafeURLError, match="credentials"):
            resolve_and_pin("http://user:pass@1.1.1.1/")

    def test_non_http_scheme_rejected(self):
        with pytest.raises(UnsafeURLError):
            resolve_and_pin("ftp://1.1.1.1/")

    def test_unresolvable_hostname_rejected(self):
        with pytest.raises(UnsafeURLError, match="could not be resolved"):
            resolve_and_pin("http://this-domain-should-never-resolve-anywhere-xyz123.invalid/")

    def test_pinned_url_preserves_path_and_port(self):
        pinned_url, _ = resolve_and_pin("http://1.1.1.1:8080/a/b/c")
        assert pinned_url == "http://1.1.1.1:8080/a/b/c"
