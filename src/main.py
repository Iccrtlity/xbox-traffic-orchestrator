import logging
import os
import time
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("orchestrator")

# ---------------------------------------------------------------------------
# Configuration (via environment variables)
# ---------------------------------------------------------------------------
ADGUARD_URL = os.getenv("ADGUARD_URL", "http://adguardhome:80")
ADGUARD_USER = os.getenv("ADGUARD_USER", "admin")
ADGUARD_PASS = os.getenv("ADGUARD_PASS", "")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))
STARTUP_TIMEOUT = int(os.getenv("STARTUP_TIMEOUT", "120"))   # seconds to wait for AdGuard at boot
BACKOFF_MAX = int(os.getenv("BACKOFF_MAX", "300"))            # cap for exponential backoff (seconds)
XBOX_CLIENT_IP = os.getenv("XBOX_CLIENT_IP", "")             # optional: LAN IP of the Xbox console

# ---------------------------------------------------------------------------
# Xbox screen-time domain lists
# ---------------------------------------------------------------------------

# Domains blocked during a screentime pause.
# Blocking Xbox Live auth services prevents games that require online auth
# from launching; blocking Family Safety domains stops sync reporting.
_XBOX_BLOCK_DOMAINS: list[str] = [
    # Xbox Live authentication (blocking these prevents online game launches)
    "device.auth.xboxlive.com",
    "title.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "def.auth.xboxlive.com",
    "title.mgt.xboxlive.com",
    # Microsoft Family Safety / Screen Time reporting
    "family.microsoft.com",
    "familysafety.microsoft.com",
    # Activity & presence reporting
    "presence.xboxlive.com",
    "userpresence.xboxlive.com",
    "activity.windows.com",
    "edge.activity.windows.com",
    # Telemetry carrying screen-time events
    "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
]

# Broader set used for *detecting* Xbox activity in the query log.
_XBOX_ACTIVITY_DOMAINS: list[str] = list({
    *_XBOX_BLOCK_DOMAINS,
    "xboxlive.com",
    "xbox.com",
    "xboxservices.com",
    "assets1.xboxlive.com",
    "assets2.xboxlive.com",
    "catalog.gamepass.com",
    "time.windows.com",
})


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
class AdGuardOrchestrator:
    """Controls AdGuard Home via its REST API."""

    def __init__(self, base_url: str, username: str, password: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._auth = HTTPBasicAuth(username, password)
        self._session = self._build_session()
        # None = unknown (will be read from AdGuard on first toggle call)
        self._screentime_blocked: Optional[bool] = None

    def _build_session(self) -> requests.Session:
        """Create a Session with transport-level retry logic."""
        session = requests.Session()
        session.auth = self._auth

        # Retry on connection errors and 502/503/504 (AdGuard not yet ready).
        # Note: POST is not in allowed_methods by default to avoid double-mutations;
        # we keep it that way – retries apply only to GET.
        retry = Retry(
            total=3,
            backoff_factor=1.0,          # 1s, 2s, 4s between attempts
            status_forcelist={502, 503, 504},
            allowed_methods={"GET", "HEAD"},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.timeout = 10
        return session

    def _reset_session(self) -> None:
        """Recreate the session after persistent failures."""
        log.info("Resetting HTTP session")
        try:
            self._session.close()
        except Exception:
            pass
        self._session = self._build_session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> requests.Response:
        url = f"{self.base_url}{path}"
        response = self._session.get(url)
        response.raise_for_status()
        return response

    def _post(self, path: str, payload: dict) -> requests.Response:
        url = f"{self.base_url}{path}"
        response = self._session.post(url, json=payload)
        response.raise_for_status()
        return response

    # ------------------------------------------------------------------
    # Public API methods
    # ------------------------------------------------------------------

    def check_status(self) -> bool:
        """Return True if AdGuard Home is reachable and responds correctly."""
        try:
            resp = self._get("/control/status")
            data = resp.json()
            version = data.get("version", "unknown")
            running = data.get("running", False)
            log.info("AdGuard Home reachable – version=%s running=%s", version, running)
            return True
        except requests.exceptions.ConnectionError:
            log.warning("Cannot reach AdGuard Home at %s", self.base_url)
        except requests.exceptions.HTTPError as exc:
            log.warning("HTTP error during status check: %s", exc)
        except Exception as exc:
            log.error("Unexpected error during status check: %s", exc)
        return False

    def add_allowed_client(self, ip: str) -> bool:
        """Add *ip* to the AdGuard Home allowed-clients list.

        AdGuard Home stores clients via /control/clients/add.
        The entry is named after the IP for easy identification.
        Returns True on success.
        """
        payload = {
            "name": f"allowed-{ip}",
            "ids": [ip],
            "use_global_settings": True,
            "filtering_enabled": False,
            "parental_enabled": False,
            "safebrowsing_enabled": False,
            "safesearch_enabled": False,
        }
        try:
            self._post("/control/clients/add", payload)
            log.info("Client added: %s", ip)
            return True
        except requests.exceptions.HTTPError as exc:
            # 400 is returned when the client already exists
            if exc.response is not None and exc.response.status_code == 400:
                log.info("Client %s already exists – skipping", ip)
                return True
            log.error("Failed to add client %s: %s", ip, exc)
        except Exception as exc:
            log.error("Unexpected error adding client %s: %s", ip, exc)
        return False

    def remove_allowed_client(self, ip: str) -> bool:
        """Remove the client entry for *ip* from AdGuard Home.

        Returns True on success or if the client did not exist.
        """
        payload = {"name": f"allowed-{ip}"}
        try:
            self._post("/control/clients/delete", payload)
            log.info("Client removed: %s", ip)
            return True
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                log.info("Client %s not found – nothing to remove", ip)
                return True
            log.error("Failed to remove client %s: %s", ip, exc)
        except Exception as exc:
            log.error("Unexpected error removing client %s: %s", ip, exc)
        return False

    # ------------------------------------------------------------------
    # Xbox screen-time control  (via user filtering rules)
    # ------------------------------------------------------------------
    # Rule format used for blocking:  ||domain.com^
    #   → matches domain.com and all its subdomains
    #   → AdGuard returns NXDOMAIN; Xbox auth services become unreachable
    # Removing the rule restores normal resolution.
    # ------------------------------------------------------------------

    def _get_user_rules(self) -> list[str]:
        """Return the current user-defined filtering rules from AdGuard."""
        resp = self._get("/control/filtering/status")
        return resp.json().get("user_rules", [])

    def _set_user_rules(self, rules: list[str]) -> bool:
        """Replace AdGuard's user filtering rules with *rules* (full overwrite)."""
        try:
            self._post("/control/filtering/set_rules", {"rules": rules})
            return True
        except requests.exceptions.HTTPError as exc:
            log.error("set_rules HTTP error: %s", exc)
        except Exception as exc:
            log.error("set_rules unexpected error: %s", exc)
        return False

    @staticmethod
    def _block_rules() -> list[str]:
        """Return the canonical set of block-rule strings for Xbox domains."""
        return [f"||{d}^" for d in _XBOX_BLOCK_DOMAINS]

    def _sync_state_from_adguard(self) -> bool:
        """Read current rule set and update the internal cache. Returns False on error."""
        try:
            existing = set(self._get_user_rules())
            rules = self._block_rules()
            # Treat as blocked if at least the first rule is present
            self._screentime_blocked = rules[0] in existing
            log.info(
                "Screen-time state read from AdGuard: %s",
                "PAUSED" if self._screentime_blocked else "ACTIVE",
            )
            return True
        except Exception as exc:
            log.error("Could not read user rules for state sync: %s", exc)
            return False

    def toggle_xbox_screentime(self, enabled: bool) -> bool:
        """Block or unblock Xbox screen-time domains via AdGuard filtering rules.

        enabled=True  → normal operation  (block rules removed from user rules)
        enabled=False → screentime pause  (block rules added to user rules)

        Uses Read → Modify → Write on /control/filtering/set_rules.
        Skips the write when the cached state already matches the target.
        """
        desired_blocked = not enabled

        if self._screentime_blocked is None:
            if not self._sync_state_from_adguard():
                return False

        if self._screentime_blocked == desired_blocked:
            log.debug(
                "Xbox screen-time already %s – no API call needed",
                "PAUSED" if desired_blocked else "ACTIVE",
            )
            return True

        # Read current rules, modify, write back
        try:
            current = self._get_user_rules()
        except Exception as exc:
            log.error("Cannot read current user rules: %s", exc)
            return False

        block_set = set(self._block_rules())
        current_set = set(current)

        if desired_blocked:
            log.info("Pausing Xbox screen-time – adding %d block rule(s)", len(block_set))
            updated = sorted(current_set | block_set)
        else:
            log.info("Resuming Xbox screen-time – removing block rules")
            updated = [r for r in current if r not in block_set]

        if not self._set_user_rules(updated):
            return False

        self._screentime_blocked = desired_blocked
        log.info(
            "Xbox screen-time %s",
            "PAUSED (blocked)" if desired_blocked else "RESUMED (unblocked)",
        )
        return True

    def toggle_screentime_pause(self) -> bool:
        """Flip the current screen-time state without knowing it in advance.

        Reads current state from AdGuard if not cached, then inverts it.
        Returns True on success.
        """
        if self._screentime_blocked is None:
            if not self._sync_state_from_adguard():
                return False

        return self.toggle_xbox_screentime(enabled=self._screentime_blocked)

    # ------------------------------------------------------------------
    # Xbox activity detection via query log
    # ------------------------------------------------------------------

    def check_xbox_activity(self, client_ip: str = "") -> list[str]:
        """Query the AdGuard DNS log and return Xbox-related domains seen.

        If *client_ip* is provided, only queries from that IP are considered.
        Returns a deduplicated list of matched domain names.
        """
        params = "limit=200"
        if client_ip:
            params += f"&search={client_ip}"

        try:
            resp = self._get(f"/control/querylog?{params}")
            entries = resp.json().get("data", [])
        except Exception as exc:
            log.error("Failed to fetch query log: %s", exc)
            return []

        seen: set[str] = set()
        for entry in entries:
            name = entry.get("question", {}).get("name", "").rstrip(".")
            if client_ip and entry.get("client", "") != client_ip:
                continue
            if name and self._is_xbox_domain(name):
                seen.add(name)

        return sorted(seen)

    def _is_xbox_domain(self, domain: str) -> bool:
        """Return True if *domain* matches any known Xbox/Microsoft service."""
        domain = domain.lower()
        for known in _XBOX_ACTIVITY_DOMAINS:
            if domain == known or domain.endswith("." + known):
                return True
        return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _wait_for_adguard(orchestrator: AdGuardOrchestrator, timeout: int) -> bool:
    """Block until AdGuard Home is reachable or *timeout* seconds have passed."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if orchestrator.check_status():
            return True
        remaining = int(deadline - time.monotonic())
        log.info("Waiting for AdGuard Home (attempt %d, %ds remaining)…", attempt, remaining)
        time.sleep(5)
    return False


def main() -> None:
    log.info("AdGuard Orchestrator starting up")
    log.info(
        "Config – url=%s user=%s poll_interval=%ss startup_timeout=%ss",
        ADGUARD_URL,
        ADGUARD_USER,
        POLL_INTERVAL,
        STARTUP_TIMEOUT,
    )

    orchestrator = AdGuardOrchestrator(ADGUARD_URL, ADGUARD_USER, ADGUARD_PASS)

    # ---- Startup: wait until AdGuard Home is ready ----------------------
    if not _wait_for_adguard(orchestrator, STARTUP_TIMEOUT):
        log.error(
            "AdGuard Home did not become reachable within %ds – exiting",
            STARTUP_TIMEOUT,
        )
        raise SystemExit(1)

    log.info("AdGuard Home is ready – entering main loop")

    consecutive_failures = 0

    while True:
        try:
            if orchestrator.check_status():
                consecutive_failures = 0

                # ── Xbox activity detection ──────────────────────────────────
                active_domains = orchestrator.check_xbox_activity(
                    client_ip=XBOX_CLIENT_IP
                )
                if active_domains:
                    log.info(
                        "Xbox activity detected (%d domain(s)): %s",
                        len(active_domains),
                        ", ".join(active_domains),
                    )
                else:
                    log.debug("No Xbox activity in recent query log")

                # ── Custom orchestration logic ───────────────────────────────
                # Example: read a control file to pause/resume screen time.
                #
                #   echo pause > /app/pause   →  blocks Xbox domains
                #   rm /app/pause             →  unblocks them
                #
                pause_file = "/app/pause"
                if os.path.exists(pause_file):
                    orchestrator.toggle_xbox_screentime(enabled=False)
                else:
                    orchestrator.toggle_xbox_screentime(enabled=True)
                # ─────────────────────────────────────────────────────────────

                log.debug("Cycle complete – sleeping %ds", POLL_INTERVAL)
                time.sleep(POLL_INTERVAL)
            else:
                consecutive_failures += 1
                # Reset session every 5 consecutive failures (stale connections)
                if consecutive_failures % 5 == 0:
                    orchestrator._reset_session()
                    orchestrator._screentime_blocked = None  # re-sync state after reset
                # Exponential backoff capped at BACKOFF_MAX
                wait = min(POLL_INTERVAL * (2 ** (consecutive_failures - 1)), BACKOFF_MAX)
                log.warning(
                    "AdGuard Home unreachable (failure #%d) – retrying in %ds",
                    consecutive_failures,
                    wait,
                )
                time.sleep(wait)
        except Exception as exc:
            consecutive_failures += 1
            wait = min(POLL_INTERVAL * (2 ** (consecutive_failures - 1)), BACKOFF_MAX)
            log.error(
                "Unhandled exception in main loop (failure #%d): %s – retrying in %ds",
                consecutive_failures,
                exc,
                wait,
            )
            time.sleep(wait)


if __name__ == "__main__":
    main()
