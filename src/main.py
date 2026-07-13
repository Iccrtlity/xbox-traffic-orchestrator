"""Xbox Screen-Time Orchestrator

Monitors AdGuard Home DNS query logs for Xbox-related domain activity
and controls domain blocking via DNS rewrite rules (/control/rewrite/add
and /control/rewrite/delete) for fast, atomic switching with state caching.
"""

import logging
import os
import time
from pathlib import Path
from typing import Optional

import requests
import yaml
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
# Configuration
# ---------------------------------------------------------------------------
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", "/app/config.yaml"))

DEFAULT_CONFIG: dict = {
    "adguard_url": "http://dns-server:80",
    "adguard_user": "admin",
    "adguard_pass": "",
    "xbox_domain": [
        "device.auth.xboxlive.com",
        "title.auth.xboxlive.com",
        "xsts.auth.xboxlive.com",
        "def.auth.xboxlive.com",
        "title.mgt.xboxlive.com",
        "family.microsoft.com",
        "familysafety.microsoft.com",
        "presence.xboxlive.com",
        "userpresence.xboxlive.com",
        "activity.windows.com",
        "edge.activity.windows.com",
        "settings-win.data.microsoft.com",
        "v10.events.data.microsoft.com",
        "v20.events.data.microsoft.com",
    ],
    "bypass_duration": 3600,
    "poll_interval": 30,
    "xbox_client_ip": "",
    "startup_timeout": 120,
}


def _write_default_config(path: Path) -> None:
    """Write the default config.yaml template and exit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as fh:
        yaml.dump(DEFAULT_CONFIG, fh, default_flow_style=False, sort_keys=False)
    log.info("Default config written to %s", path)


def load_config() -> dict:
    """Load config from YAML with environment variable overrides.

    1. Start from DEFAULT_CONFIG
    2. Merge values from config.yaml (if it exists)
    3. Override sensitive / numeric fields from environment variables

    If config.yaml does not exist a default template is written and
    the process exits, prompting the user to edit it.
    """
    config: dict = dict(DEFAULT_CONFIG)

    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as fh:
            file_config = yaml.safe_load(fh) or {}
        for key, value in file_config.items():
            if key in config:
                config[key] = value
        log.info("Config loaded from %s", CONFIG_PATH)
    else:
        log.warning(
            "Config file not found at %s – creating default template", CONFIG_PATH
        )
        _write_default_config(CONFIG_PATH)
        raise SystemExit(
            f"Default config written to {CONFIG_PATH}. "
            "Edit it with your settings, then restart."
        )

    # Environment variables override sensitive fields (from .env via Docker)
    env_sensitive: dict[str, str] = {
        "ADGUARD_URL": "adguard_url",
        "ADGUARD_USER": "adguard_user",
        "ADGUARD_PASS": "adguard_pass",
    }
    for env_key, cfg_key in env_sensitive.items():
        env_val = os.getenv(env_key)
        if env_val:
            config[cfg_key] = env_val

    # Numeric env overrides
    env_numeric: list[tuple[str, str, type]] = [
        ("POLL_INTERVAL", "poll_interval", int),
        ("STARTUP_TIMEOUT", "startup_timeout", int),
    ]
    for env_key, cfg_key, cast in env_numeric:
        env_val = os.getenv(env_key)
        if env_val:
            config[cfg_key] = cast(env_val)

    return config


# ---------------------------------------------------------------------------
# Orchestrator – DNS rewrite based blocking
# ---------------------------------------------------------------------------
class AdGuardOrchestrator:
    """Controls AdGuard Home via its REST API.

    Uses ``/control/rewrite/add`` and ``/control/rewrite/delete`` for
    fast, atomic domain blocking instead of the slower read-modify-write
    cycle on user filtering rules.

    State caching ensures the API is only called when the desired state
    actually differs from the current state.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        xbox_domains: list[str],
        bypass_duration: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._auth = HTTPBasicAuth(username, password)
        self._session = self._build_session()
        self._xbox_domains: list[str] = list(xbox_domains)
        self._bypass_duration: int = bypass_duration

        # ── State caching ──────────────────────────────────────────────
        self._blocked_domains: set[str] = set()  # domains currently rewritten
        self._bypass_until: float = 0.0  # monotonic timestamp when bypass expires
        self._initialized: bool = False

    # ------------------------------------------------------------------
    # HTTP session
    # ------------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        """Create a Session with transport-level retry logic."""
        session = requests.Session()
        session.auth = self._auth

        retry = Retry(
            total=3,
            backoff_factor=1.0,
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
    # Low-level HTTP helpers
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
    # Status check
    # ------------------------------------------------------------------

    def check_status(self) -> bool:
        """Return True if AdGuard Home is reachable."""
        try:
            resp = self._get("/control/status")
            data = resp.json()
            version = data.get("version", "unknown")
            running = data.get("running", False)
            log.info(
                "AdGuard Home reachable – version=%s running=%s", version, running
            )
            return True
        except requests.exceptions.ConnectionError:
            log.warning("Cannot reach AdGuard Home at %s", self.base_url)
        except requests.exceptions.HTTPError as exc:
            log.warning("HTTP error during status check: %s", exc)
        except Exception as exc:
            log.error("Unexpected error during status check: %s", exc)
        return False

    # ------------------------------------------------------------------
    # Rewrite-based domain blocking  (fast atomic switching)
    # ------------------------------------------------------------------

    def _sync_rewrites_from_adguard(self) -> bool:
        """Read current rewrite rules and populate the blocked-domains cache."""
        try:
            resp = self._get("/control/rewrite/list")
            rewrites = resp.json()
            xbox_set = set(self._xbox_domains)
            self._blocked_domains = {
                r["domain"]
                for r in rewrites
                if r.get("domain") in xbox_set
            }
            log.info(
                "Rewrite state synced: %d/%d Xbox domain(s) currently blocked",
                len(self._blocked_domains),
                len(self._xbox_domains),
            )
            return True
        except Exception as exc:
            log.warning(
                "Could not read current rewrites for state sync: %s", exc
            )
            return False

    def _add_rewrite(self, domain: str) -> bool:
        """Add a DNS rewrite to block *domain* (resolve to 0.0.0.0)."""
        try:
            self._post(
                "/control/rewrite/add", {"domain": domain, "ip": "0.0.0.0"}
            )
            self._blocked_domains.add(domain)
            log.debug("Rewrite added: %s -> 0.0.0.0", domain)
            return True
        except requests.exceptions.HTTPError as exc:
            # 400 = domain already has a rewrite entry – treat as success
            if exc.response is not None and exc.response.status_code == 400:
                self._blocked_domains.add(domain)
                return True
            log.error("Failed to add rewrite for %s: %s", domain, exc)
        except Exception as exc:
            log.error("Unexpected error adding rewrite for %s: %s", domain, exc)
        return False

    def _delete_rewrite(self, domain: str) -> bool:
        """Delete the DNS rewrite for *domain*."""
        try:
            self._post(
                "/control/rewrite/delete",
                {"domain": domain, "ip": "0.0.0.0"},
            )
            self._blocked_domains.discard(domain)
            log.debug("Rewrite deleted: %s", domain)
            return True
        except requests.exceptions.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 400:
                self._blocked_domains.discard(domain)
                return True
            log.error("Failed to delete rewrite for %s: %s", domain, exc)
        except Exception as exc:
            log.error(
                "Unexpected error deleting rewrite for %s: %s", domain, exc
            )
        return False

    def block_xbox_domains(self) -> bool:
        """Block all Xbox domains that are not yet blocked.

        State-caching: only calls the API for domains not already in the
        blocked set.  Returns True if all domains are (now) blocked.
        """
        to_block = set(self._xbox_domains) - self._blocked_domains
        if not to_block:
            log.debug("All Xbox domains already blocked – no API calls needed")
            return True

        log.info(
            "Blocking %d Xbox domain(s) via rewrite rules…", len(to_block)
        )
        success = True
        for domain in sorted(to_block):
            if not self._add_rewrite(domain):
                success = False
        return success

    def unblock_xbox_domains(self) -> bool:
        """Unblock all currently blocked Xbox domains.

        State-caching: only calls the API for domains in the blocked set.
        """
        if not self._blocked_domains:
            log.debug(
                "No Xbox domains to unblock – no API calls needed"
            )
            return True

        log.info(
            "Unblocking %d Xbox domain(s)…", len(self._blocked_domains)
        )
        success = True
        for domain in sorted(self._blocked_domains):
            if not self._delete_rewrite(domain):
                success = False
        return success

    # ------------------------------------------------------------------
    # Bypass management (unblock Xbox domains temporarily)
    # ------------------------------------------------------------------

    def start_bypass(self, duration: Optional[int] = None) -> None:
        """Activate bypass for *duration* seconds (default: bypass_duration).

        Xbox domains are unblocked for this period, allowing screen-time
        to be bypassed.  After expiry the orchestrator re-blocks them.
        """
        dur = duration if duration is not None else self._bypass_duration
        self._bypass_until = time.monotonic() + dur
        log.info("Bypass started – expires in %ds", dur)

    def is_bypass_active(self) -> bool:
        """Return True if the bypass period has not yet expired."""
        return time.monotonic() < self._bypass_until

    # ------------------------------------------------------------------
    # Query log monitoring
    # ------------------------------------------------------------------

    def check_xbox_activity(self, client_ip: str = "") -> list[str]:
        """Query the AdGuard DNS log and return Xbox-related domains seen.

        If *client_ip* is provided, only queries from that IP are considered.
        Returns a deduplicated, sorted list of matched domain names.
        """
        try:
            params = "?limit=200"
            if client_ip:
                params += f"&search={client_ip}"
            resp = self._get(f"/control/querylog{params}")
            entries = resp.json().get("data", [])
        except Exception as exc:
            log.error("Failed to fetch query log: %s", exc)
            return []

        xbox_set = set(self._xbox_domains)
        seen: set[str] = set()
        for entry in entries:
            name = entry.get("question", {}).get("name", "").rstrip(".")
            if client_ip and entry.get("client", "") != client_ip:
                continue
            if name and (
                name in xbox_set
                or any(name.endswith("." + d) for d in xbox_set)
            ):
                seen.add(name)
        return sorted(seen)

    # ------------------------------------------------------------------
    # State synchronisation
    # ------------------------------------------------------------------

    def sync_state(self) -> bool:
        """Synchronise internal state with AdGuard on first run."""
        if not self._sync_rewrites_from_adguard():
            return False
        self._initialized = True
        return True

    def sync_desired_state(self) -> bool:
        """Ensure AdGuard rewrite rules match the desired state.

        Bypass active → domains should be UNBLOCKED (Xbox can connect).
        Bypass expired → domains should be BLOCKED (screen-time on).
        """
        if not self._initialized:
            if not self.sync_state():
                return False

        if self.is_bypass_active():
            return self.unblock_xbox_domains()
        else:
            return self.block_xbox_domains()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

_BACKOFF_MAX = 300  # cap for exponential backoff (seconds)


def _wait_for_adguard(
    orchestrator: AdGuardOrchestrator, timeout: int
) -> bool:
    """Block until AdGuard Home is reachable or *timeout* seconds have passed."""
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if orchestrator.check_status():
            return True
        remaining = int(deadline - time.monotonic())
        log.info(
            "Waiting for AdGuard Home (attempt %d, %ds remaining)…",
            attempt,
            remaining,
        )
        time.sleep(5)
    return False


def main() -> None:
    config = load_config()

    adguard_url: str = config["adguard_url"]
    adguard_user: str = config["adguard_user"]
    adguard_pass: str = config["adguard_pass"]
    xbox_domains: list[str] = config["xbox_domain"]
    bypass_duration: int = config["bypass_duration"]
    poll_interval: int = config["poll_interval"]
    xbox_client_ip: str = config["xbox_client_ip"]
    startup_timeout: int = config["startup_timeout"]

    log.info("Xbox Screen-Time Orchestrator starting up")
    log.info(
        "Config – url=%s user=%s poll_interval=%ss bypass_duration=%ss",
        adguard_url,
        adguard_user,
        poll_interval,
        bypass_duration,
    )
    log.info("Monitoring %d Xbox domain(s)", len(xbox_domains))

    orchestrator = AdGuardOrchestrator(
        base_url=adguard_url,
        username=adguard_user,
        password=adguard_pass,
        xbox_domains=xbox_domains,
        bypass_duration=bypass_duration,
    )

    # ── Startup: wait until AdGuard Home is ready ──────────────────────
    if not _wait_for_adguard(orchestrator, startup_timeout):
        log.error(
            "AdGuard Home did not become reachable within %ds – exiting",
            startup_timeout,
        )
        raise SystemExit(1)

    log.info("AdGuard Home is ready – entering main loop")

    # Sync initial state from AdGuard rewrite list
    if not orchestrator.sync_state():
        log.warning("Initial state sync failed – will retry on first cycle")

    consecutive_failures = 0

    while True:
        try:
            if orchestrator.check_status():
                consecutive_failures = 0

                # ── Query-log monitoring ───────────────────────────────
                active_domains = orchestrator.check_xbox_activity(
                    client_ip=xbox_client_ip
                )
                if active_domains:
                    log.info(
                        "Xbox activity detected (%d domain(s)): %s",
                        len(active_domains),
                        ", ".join(active_domains),
                    )
                    # Start / extend bypass – unblock Xbox domains
                    orchestrator.start_bypass()
                else:
                    log.debug("No Xbox activity in recent query log")

                # ── Sync rewrite rules to desired state ────────────────
                orchestrator.sync_desired_state()

                log.debug("Cycle complete – sleeping %ds", poll_interval)
                time.sleep(poll_interval)
            else:
                consecutive_failures += 1
                if consecutive_failures % 5 == 0:
                    orchestrator._reset_session()
                    orchestrator._initialized = False
                wait = min(
                    poll_interval * (2 ** (consecutive_failures - 1)),
                    _BACKOFF_MAX,
                )
                log.warning(
                    "AdGuard Home unreachable (failure #%d) – retrying in %ds",
                    consecutive_failures,
                    wait,
                )
                time.sleep(wait)
        except Exception as exc:
            consecutive_failures += 1
            wait = min(
                poll_interval * (2 ** (consecutive_failures - 1)),
                _BACKOFF_MAX,
            )
            log.error(
                "Unhandled exception (failure #%d): %s – retrying in %ds",
                consecutive_failures,
                exc,
                wait,
            )
            time.sleep(wait)


if __name__ == "__main__":
    main()
