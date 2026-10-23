"""
Tests for Config.validate_production_config() and the startup check in
main.py's lifespan() that uses it — this is the fix for the critical
audit finding: a working, non-empty JWT_SECRET default that nothing
previously stopped from reaching production.
"""
import pytest
from app.config import Config


class TestValidateProductionConfig:

    def test_noop_outside_production(self):
        cfg = Config(ENV="development", JWT_SECRET="CHANGE_THIS_IN_PRODUCTION_USE_64_RANDOM_CHARS")
        assert cfg.validate_production_config() == []

    def test_noop_in_test_env_even_with_default_secret(self):
        cfg = Config(ENV="test", JWT_SECRET="CHANGE_THIS_IN_PRODUCTION_USE_64_RANDOM_CHARS")
        assert cfg.validate_production_config() == []

    def test_default_secret_blocked_in_production(self):
        cfg = Config(ENV="production", JWT_SECRET="CHANGE_THIS_IN_PRODUCTION_USE_64_RANDOM_CHARS")
        problems = cfg.validate_production_config()
        assert len(problems) == 1
        assert "default placeholder" in problems[0]

    def test_short_secret_blocked_in_production(self):
        cfg = Config(ENV="production", JWT_SECRET="tooshort")
        problems = cfg.validate_production_config()
        assert len(problems) == 1
        assert "too short" in problems[0]

    def test_strong_secret_passes_in_production(self):
        cfg = Config(ENV="production", JWT_SECRET="a" * 64)
        assert cfg.validate_production_config() == []

    def test_exactly_32_chars_passes(self):
        cfg = Config(ENV="production", JWT_SECRET="a" * 32)
        assert cfg.validate_production_config() == []

    def test_31_chars_fails(self):
        cfg = Config(ENV="production", JWT_SECRET="a" * 31)
        assert len(cfg.validate_production_config()) == 1


class TestStartupRefusesInsecureProductionConfig:
    """End-to-end: the actual app startup, not just the validation
    function in isolation — confirms lifespan() really does raise and
    refuse to boot, not just that the check function returns a value
    nobody acts on."""

    def test_lifespan_raises_with_default_secret_in_production(self, monkeypatch):
        import app.main as main_module
        monkeypatch.setattr(main_module.cfg, "ENV", "production")
        monkeypatch.setattr(main_module.cfg, "JWT_SECRET", "CHANGE_THIS_IN_PRODUCTION_USE_64_RANDOM_CHARS")

        import asyncio
        async def _try_start():
            async with main_module.lifespan(main_module.app):
                pass

        with pytest.raises(RuntimeError, match="Insecure production configuration"):
            asyncio.run(_try_start())

    def test_lifespan_succeeds_with_strong_secret_in_production(self, monkeypatch):
        """Confirms the config check passes and doesn't raise — without
        actually starting the real background schedulers as a side
        effect of this test (they're mocked out; testing that they get
        called is a separate concern from testing the config gate)."""
        import app.main as main_module
        monkeypatch.setattr(main_module.cfg, "ENV", "production")
        monkeypatch.setattr(main_module.cfg, "JWT_SECRET", "a" * 64)
        monkeypatch.setattr(main_module, "init_db", lambda: None)

        import app.workers.scheduler as scheduler_module
        import app.workers.tor_updater as tor_updater_module
        import app.workers.anomaly_detector as anomaly_module
        monkeypatch.setattr(scheduler_module, "start_scheduler", lambda: None)
        monkeypatch.setattr(tor_updater_module, "start_tor_updater", lambda s: None)
        monkeypatch.setattr(anomaly_module, "start_periodic_check", lambda s: None)

        import asyncio
        async def _try_start():
            async with main_module.lifespan(main_module.app):
                return True

        try:
            result = asyncio.run(_try_start())
            assert result is True
        except RuntimeError as e:
            pytest.fail(f"Should not have raised with a strong secret: {e}")
