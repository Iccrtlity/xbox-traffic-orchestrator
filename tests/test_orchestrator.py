"""Tests for AdGuardOrchestrator – state caching, block/unblock, query log."""

import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import main as orchestrator_module
from main import AdGuardOrchestrator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DOMAINS = ["auth.xboxlive.com", "family.microsoft.com", "presence.xboxlive.com"]


@pytest.fixture
def orch():
    """Create an orchestrator with a mocked HTTP session."""
    o = AdGuardOrchestrator(
        base_url="http://adguard:80",
        username="admin",
        password="pass",
        xbox_domains=list(DOMAINS),
        bypass_duration=60,
    )
    o._session = MagicMock()
    return o


def _mock_response(json_data=None, status_code=200):
    """Build a mock requests.Response."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        http_err = requests.exceptions.HTTPError(response=resp)
        resp.raise_for_status.side_effect = http_err
    return resp


# ---------------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------------


class TestCheckStatus:
    def test_returns_true_on_success(self, orch):
        orch._session.get.return_value = _mock_response(
            {"version": "0.107", "running": True}
        )
        assert orch.check_status() is True

    def test_returns_false_on_connection_error(self, orch):
        orch._session.get.side_effect = requests.exceptions.ConnectionError
        assert orch.check_status() is False

    def test_returns_false_on_http_error(self, orch):
        orch._session.get.return_value = _mock_response(status_code=500)
        assert orch.check_status() is False


# ---------------------------------------------------------------------------
# State sync (rewrites)
# ---------------------------------------------------------------------------


class TestSyncRewrites:
    def test_reads_current_rewrites(self, orch):
        orch._session.get.return_value = _mock_response(
            [
                {"domain": "auth.xboxlive.com", "ip": "0.0.0.0"},
                {"domain": "unrelated.com", "ip": "0.0.0.0"},
            ]
        )
        assert orch.sync_state() is True
        assert orch._blocked_domains == {"auth.xboxlive.com"}
        assert orch._initialized is True

    def test_empty_rewrite_list(self, orch):
        orch._session.get.return_value = _mock_response([])
        assert orch.sync_state() is True
        assert orch._blocked_domains == set()

    def test_api_failure_returns_false(self, orch):
        orch._session.get.side_effect = Exception("timeout")
        assert orch.sync_state() is False
        assert orch._initialized is False


# ---------------------------------------------------------------------------
# block_xbox_domains – state caching
# ---------------------------------------------------------------------------


class TestBlockXboxDomains:
    def test_blocks_all_when_none_blocked(self, orch):
        orch._session.post.return_value = _mock_response()
        result = orch.block_xbox_domains()

        assert result is True
        # Should have called POST for each domain
        assert orch._session.post.call_count == len(DOMAINS)
        assert orch._blocked_domains == set(DOMAINS)

    def test_skips_already_blocked_domains(self, orch):
        orch._blocked_domains = {"auth.xboxlive.com"}
        orch._session.post.return_value = _mock_response()

        orch.block_xbox_domains()

        # Only 2 new domains need API calls
        assert orch._session.post.call_count == 2
        posted_domains = {
            call.kwargs["json"]["domain"]
            for call in orch._session.post.call_args_list
        }
        assert "auth.xboxlive.com" not in posted_domains
        assert "family.microsoft.com" in posted_domains
        assert "presence.xboxlive.com" in posted_domains

    def test_no_api_calls_when_all_blocked(self, orch):
        orch._blocked_domains = set(DOMAINS)
        result = orch.block_xbox_domains()

        assert result is True
        orch._session.post.assert_not_called()

    def test_returns_false_on_api_failure(self, orch):
        orch._session.post.side_effect = Exception("connection refused")
        result = orch.block_xbox_domains()
        assert result is False


# ---------------------------------------------------------------------------
# unblock_xbox_domains – state caching
# ---------------------------------------------------------------------------


class TestUnblockXboxDomains:
    def test_unblocks_all_when_all_blocked(self, orch):
        orch._blocked_domains = set(DOMAINS)
        orch._session.post.return_value = _mock_response()

        result = orch.unblock_xbox_domains()

        assert result is True
        assert orch._session.post.call_count == len(DOMAINS)
        assert orch._blocked_domains == set()

    def test_skips_already_unblocked_domains(self, orch):
        orch._blocked_domains = {"auth.xboxlive.com"}
        orch._session.post.return_value = _mock_response()

        orch.unblock_xbox_domains()

        assert orch._session.post.call_count == 1
        posted_domains = {
            call.kwargs["json"]["domain"]
            for call in orch._session.post.call_args_list
        }
        assert posted_domains == {"auth.xboxlive.com"}

    def test_no_api_calls_when_none_blocked(self, orch):
        orch._blocked_domains = set()
        result = orch.unblock_xbox_domains()

        assert result is True
        orch._session.post.assert_not_called()

    def test_returns_false_on_api_failure(self, orch):
        orch._blocked_domains = set(DOMAINS)
        orch._session.post.side_effect = Exception("timeout")
        result = orch.unblock_xbox_domains()
        assert result is False


# ---------------------------------------------------------------------------
# _add_rewrite / _delete_rewrite edge cases
# ---------------------------------------------------------------------------


class TestRewriteEdgeCases:
    def test_add_rewrite_400_treated_as_success(self, orch):
        resp = _mock_response(status_code=400)
        orch._session.post.return_value = resp
        result = orch._add_rewrite("auth.xboxlive.com")
        assert result is True
        assert "auth.xboxlive.com" in orch._blocked_domains

    def test_delete_rewrite_400_treated_as_success(self, orch):
        orch._blocked_domains = {"auth.xboxlive.com"}
        resp = _mock_response(status_code=400)
        orch._session.post.return_value = resp
        result = orch._delete_rewrite("auth.xboxlive.com")
        assert result is True
        assert "auth.xboxlive.com" not in orch._blocked_domains

    def test_add_rewrite_server_error_returns_false(self, orch):
        resp = _mock_response(status_code=500)
        orch._session.post.return_value = resp
        result = orch._add_rewrite("auth.xboxlive.com")
        assert result is False
        assert "auth.xboxlive.com" not in orch._blocked_domains


# ---------------------------------------------------------------------------
# start_block / is_block_active
# ---------------------------------------------------------------------------


class TestBypassTiming:
    def test_bypass_active_immediately_after_start(self, orch):
        orch.start_bypass()
        assert orch.is_bypass_active() is True

    def test_custom_duration(self, orch):
        orch.start_bypass(duration=0)
        # Duration=0 means bypass expires immediately
        assert orch.is_bypass_active() is False

    def test_bypass_expires(self, orch):
        orch.start_bypass(duration=1)
        assert orch.is_bypass_active() is True
        # Force expiry by backdating the timestamp
        orch._bypass_until = time.monotonic() - 1
        assert orch.is_bypass_active() is False

    def test_bypass_extends_on_new_activity(self, orch):
        orch.start_bypass(duration=60)
        first_expiry = orch._bypass_until
        time.sleep(0.01)
        orch.start_bypass(duration=120)
        assert orch._bypass_until > first_expiry


# ---------------------------------------------------------------------------
# check_xbox_activity – query log filtering
# ---------------------------------------------------------------------------


class TestCheckXboxActivity:
    def _querylog_response(self, entries):
        return _mock_response({"data": entries})

    def test_detects_xbox_domains(self, orch):
        orch._session.get.return_value = self._querylog_response(
            [
                {"question": {"name": "auth.xboxlive.com."}, "client": "10.0.0.1"},
                {"question": {"name": "google.com"}, "client": "10.0.0.1"},
                {"question": {"name": "family.microsoft.com."}, "client": "10.0.0.1"},
            ]
        )
        result = orch.check_xbox_activity()
        assert result == ["auth.xboxlive.com", "family.microsoft.com"]

    def test_filters_by_client_ip(self, orch):
        orch._session.get.return_value = self._querylog_response(
            [
                {"question": {"name": "auth.xboxlive.com."}, "client": "10.0.0.1"},
                {"question": {"name": "family.microsoft.com."}, "client": "10.0.0.2"},
            ]
        )
        result = orch.check_xbox_activity(client_ip="10.0.0.1")
        assert result == ["auth.xboxlive.com"]

    def test_empty_log_returns_empty(self, orch):
        orch._session.get.return_value = self._querylog_response([])
        result = orch.check_xbox_activity()
        assert result == []

    def test_api_failure_returns_empty(self, orch):
        orch._session.get.side_effect = Exception("timeout")
        result = orch.check_xbox_activity()
        assert result == []

    def test_deduplicates_domains(self, orch):
        orch._session.get.return_value = self._querylog_response(
            [
                {"question": {"name": "auth.xboxlive.com."}, "client": "10.0.0.1"},
                {"question": {"name": "auth.xboxlive.com"}, "client": "10.0.0.1"},
                {"question": {"name": "sub.auth.xboxlive.com."}, "client": "10.0.0.1"},
            ]
        )
        result = orch.check_xbox_activity()
        # auth.xboxlive.com appears twice (with/without dot) + subdomain
        assert result.count("auth.xboxlive.com") == 1

    def test_strips_trailing_dot(self, orch):
        orch._session.get.return_value = self._querylog_response(
            [
                {"question": {"name": "auth.xboxlive.com."}, "client": "10.0.0.1"},
            ]
        )
        result = orch.check_xbox_activity()
        assert result == ["auth.xboxlive.com"]
        assert not any(d.endswith(".") for d in result)


# ---------------------------------------------------------------------------
# sync_desired_state – integration of all pieces
# ---------------------------------------------------------------------------


class TestSyncDesiredState:
    def test_unblocks_when_bypass_active(self, orch):
        # Initialise state
        orch._session.get.return_value = _mock_response([])
        orch.sync_state()

        orch.start_bypass()
        orch._session.post.return_value = _mock_response()
        result = orch.sync_desired_state()

        assert result is True
        assert orch._blocked_domains == set()

    def test_blocks_when_no_bypass(self, orch):
        # Initialise with all blocked
        orch._session.get.return_value = _mock_response(
            [{"domain": d, "ip": "0.0.0.0"} for d in DOMAINS]
        )
        orch.sync_state()

        # Bypass already expired (start with 0 duration)
        orch.start_bypass(duration=0)
        orch._session.post.return_value = _mock_response()
        result = orch.sync_desired_state()

        assert result is True
        assert orch._blocked_domains == set(DOMAINS)

    def test_skips_api_when_already_in_desired_state(self, orch):
        # All blocked, bypass expired
        orch._blocked_domains = set(DOMAINS)
        orch._initialized = True
        orch.start_bypass(duration=0)

        # block_xbox_domains should skip API calls
        orch.sync_desired_state()
        orch._session.post.assert_not_called()
