"""
test_crtsh_utils.py

Unit tests for crtsh_utils module-level constants: USER_AGENT and
CRTSH_RATE_LIMIT_DELAY_SEC (including env-var override behavior).
"""

import importlib
import check_tls.utils.crtsh_utils as crtsh_utils


class TestUserAgent:
    """Tests for the USER_AGENT constant."""

    def test_user_agent_is_non_empty(self):
        """USER_AGENT must be a non-empty string."""
        assert isinstance(crtsh_utils.USER_AGENT, str)
        assert len(crtsh_utils.USER_AGENT) > 0

    def test_user_agent_starts_with_package_prefix(self):
        """USER_AGENT must start with 'check-tls/' to identify the package."""
        assert crtsh_utils.USER_AGENT.startswith("check-tls/")

    def test_user_agent_contains_version(self):
        """USER_AGENT must include a version component after the slash."""
        prefix = "check-tls/"
        assert crtsh_utils.USER_AGENT.startswith(prefix)
        version_part = crtsh_utils.USER_AGENT[len(prefix):]
        assert len(version_part) > 0


class TestRateLimitDelay:
    """Tests for the CRTSH_RATE_LIMIT_DELAY_SEC constant and env-var override."""

    def test_default_delay(self):
        """Default rate-limit delay is 0.5 seconds when env var is not set."""
        # This assumes CHECK_TLS_CRTSH_DELAY is not set in the test environment.
        # The module was loaded without the env var, so it should be 0.5.
        assert crtsh_utils.CRTSH_RATE_LIMIT_DELAY_SEC == 0.5

    def test_env_var_override(self, monkeypatch):
        """CHECK_TLS_CRTSH_DELAY env var sets the rate-limit delay on module reload."""
        monkeypatch.setenv("CHECK_TLS_CRTSH_DELAY", "1.5")
        importlib.reload(crtsh_utils)
        try:
            assert crtsh_utils.CRTSH_RATE_LIMIT_DELAY_SEC == 1.5
        finally:
            monkeypatch.delenv("CHECK_TLS_CRTSH_DELAY", raising=False)
            importlib.reload(crtsh_utils)

    def test_invalid_env_var_falls_back_to_default(self, monkeypatch):
        """An invalid CHECK_TLS_CRTSH_DELAY value falls back to 0.5 seconds."""
        monkeypatch.setenv("CHECK_TLS_CRTSH_DELAY", "not-a-float")
        importlib.reload(crtsh_utils)
        try:
            assert crtsh_utils.CRTSH_RATE_LIMIT_DELAY_SEC == 0.5
        finally:
            monkeypatch.delenv("CHECK_TLS_CRTSH_DELAY", raising=False)
            importlib.reload(crtsh_utils)

    def test_negative_env_var_clamped_to_zero(self, monkeypatch):
        """A negative CHECK_TLS_CRTSH_DELAY value is clamped to 0.0."""
        monkeypatch.setenv("CHECK_TLS_CRTSH_DELAY", "-1.0")
        importlib.reload(crtsh_utils)
        try:
            assert crtsh_utils.CRTSH_RATE_LIMIT_DELAY_SEC == 0.0
        finally:
            monkeypatch.delenv("CHECK_TLS_CRTSH_DELAY", raising=False)
            importlib.reload(crtsh_utils)
