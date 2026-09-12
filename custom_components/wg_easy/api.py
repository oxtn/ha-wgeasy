from __future__ import annotations

import logging
from typing import Any

import aiohttp
from aiohttp import ClientError, ClientSession

_LOGGER = logging.getLogger(__name__)


class WGEasyApiError(Exception):
    """Raised when the WG Easy API cannot be reached or returns an error."""


class WGEasyAuthError(WGEasyApiError):
    """Raised when authentication with the WG Easy API fails."""


class WGEasyNotDetectedError(WGEasyApiError):
    """Raised when a server responds, but doesn't look like wg-easy at all.

    Distinct from a plain WGEasyApiError (network/connectivity failure) so
    the config flow can show a more specific, human message: the address
    was reachable, it just isn't a wg-easy install.
    """


def _strip_known_endpoint_suffix(url: str) -> str:
    """Return the server's base address, stripping a known endpoint path if
    the user pasted a full endpoint URL instead of just the base (e.g.
    "https://host/metrics/json" or "https://host/api/release"). Shared by
    the version probe and the v15 client's own URL building, so entering
    either the base address or a full endpoint URL works consistently
    everywhere instead of only in one place.
    """
    base = (url or "").rstrip("/")
    for suffix in ("/metrics/json", "/api/release", "/api"):
        if base.endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


class WGEasyV15Client:
    """Talks to wg-easy v15's Bearer-token-secured metrics endpoint.

    v15 has no general Bearer-token JSON API - the only endpoint secured by
    a Bearer token is the metrics feature (Admin Panel -> General ->
    Metrics), and its JSON variant at "{base_url}/metrics/json" returns
    exactly the {clients: [...], wireguard_configured_peers, ...} shape
    this integration expects (confirmed against wg-easy's own
    src/server/routes/metrics/json.get.ts). The general "/api/..." REST
    API is Basic Auth only and unrelated to this token.

    The configured URL is treated as the server's base address (optionally
    including a reverse-proxy subpath, e.g. "https://host/wireguard") and
    "/metrics/json" is appended automatically unless it's already there,
    so entering just the base address is enough.
    """

    def __init__(
        self,
        session: ClientSession,
        url: str,
        token: str | None,
        verify_ssl: bool = True,
        username: str | None = None,
        admin_password: str | None = None,
    ) -> None:
        self._session = session
        self._base_url = _strip_known_endpoint_suffix(url)
        self._token = token
        self._verify_ssl = verify_ssl
        self._admin_username = username
        self._admin_password = admin_password
        self._admin_cookie: str | None = None
        # Cache: publicKey -> numeric id from GET /api/client (admin API).
        # Cleared whenever the session cookie is dropped so stale IDs can't
        # persist across re-logins.
        self._client_id_cache: dict[str, str] = {}

    async def async_fetch_raw(self) -> bytes:
        if not self._token:
            raise WGEasyApiError("No API token configured for the v15 API")

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }
        try:
            async with self._session.get(
                f"{self._base_url}/metrics/json", headers=headers, ssl=self._verify_ssl
            ) as response:
                if response.status == 401:
                    raise WGEasyAuthError("Unauthorized - check API token")
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(f"HTTP {response.status}: {body[:200]}")
                return await response.read()
        except ClientError as err:
            raise WGEasyApiError(f"Request failed: {err}") from err

    async def _async_admin_login(self) -> None:
        """Login to the wg-easy v15 admin REST API and store the session cookie.

        Uses POST /api/auth/password with {username, password, remember: false}.
        """
        if not self._admin_username or not self._admin_password:
            raise WGEasyApiError(
                "No admin credentials configured; cannot authenticate to the write API"
            )

        login_url = f"{self._base_url}/api/auth/password"
        try:
            async with self._session.post(
                login_url,
                json={
                    "username": self._admin_username,
                    "password": self._admin_password,
                    "remember": False,
                },
                ssl=self._verify_ssl,
            ) as response:
                if response.status == 401:
                    raise WGEasyAuthError(
                        "Admin credentials rejected by wg-easy v15"
                    )
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(
                        f"Admin login HTTP {response.status}: {body[:200]}"
                    )
                # h3/nitro uses a signed cookie named 'wg-easy'
                cookie = response.cookies.get("wg-easy")
                if not cookie:
                    raise WGEasyApiError(
                        "Admin login succeeded but no session cookie was returned"
                    )
                self._admin_cookie = cookie.value
        except ClientError as err:
            raise WGEasyApiError(f"Admin login request failed: {err}") from err

    async def _async_admin_post(self, path: str) -> None:
        """Issue an authenticated admin POST, re-logging in once on 401."""
        if not self._admin_cookie:
            await self._async_admin_login()

        url = f"{self._base_url}{path}"
        cookies = {"wg-easy": self._admin_cookie} if self._admin_cookie else {}
        try:
            async with self._session.post(
                url,
                cookies=cookies,
                ssl=self._verify_ssl,
            ) as response:
                if response.status == 401:
                    self._admin_cookie = None
                    self._client_id_cache.clear()
                    raise WGEasyAuthError(
                        "Admin session expired - will re-authenticate next attempt"
                    )
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(
                        f"Admin POST {path} HTTP {response.status}: {body[:200]}"
                    )
        except ClientError as err:
            raise WGEasyApiError(f"Admin POST request failed: {err}") from err

    async def _async_resolve_client_id(self, public_key: str) -> str:
        """Resolve a WireGuard peer's numeric database ID from its public key.

        The metrics endpoint used for polling only surfaces ``publicKey``, but
        the enable/disable REST endpoints require the numeric ``id`` assigned
        by wg-easy's database. This method calls ``GET /api/client`` (which
        requires admin session auth) and caches the result so subsequent
        toggles for the same peer don't need another round-trip.
        """
        if public_key in self._client_id_cache:
            return self._client_id_cache[public_key]

        if not self._admin_cookie:
            await self._async_admin_login()

        url = f"{self._base_url}/api/client"
        cookies = {"wg-easy": self._admin_cookie} if self._admin_cookie else {}
        try:
            async with self._session.get(
                url,
                cookies=cookies,
                headers={"Accept": "application/json"},
                ssl=self._verify_ssl,
            ) as response:
                if response.status == 401:
                    self._admin_cookie = None
                    self._client_id_cache.clear()
                    raise WGEasyAuthError(
                        "Admin session expired while fetching client list"
                    )
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(
                        f"GET /api/client HTTP {response.status}: {body[:200]}"
                    )
                clients = await response.json()
        except ClientError as err:
            raise WGEasyApiError(f"Failed to fetch client list: {err}") from err

        client_list = clients if isinstance(clients, list) else clients.get("clients", [])
        for client in client_list:
            pk = client.get("publicKey")
            numeric_id = client.get("id")
            if pk and numeric_id is not None:
                self._client_id_cache[pk] = str(numeric_id)

        if public_key not in self._client_id_cache:
            raise WGEasyApiError(
                f"Client with publicKey {public_key[:8]}... not found in admin API"
            )
        return self._client_id_cache[public_key]

    async def async_enable_client(self, public_key: str) -> None:
        """Enable a WireGuard peer via the v15 admin API."""
        client_id = await self._async_resolve_client_id(public_key)
        await self._async_admin_post(f"/api/client/{client_id}/enable")

    async def async_disable_client(self, public_key: str) -> None:
        """Disable a WireGuard peer via the v15 admin API."""
        client_id = await self._async_resolve_client_id(public_key)
        await self._async_admin_post(f"/api/client/{client_id}/disable")


class WGEasyV14Client:
    """Talks to a wg-easy v14 style API: password login -> session cookie -> REST endpoint."""

    def __init__(
        self,
        session: ClientSession,
        url: str,
        password: str | None,
        verify_ssl: bool = True,
    ) -> None:
        self._session = session
        self._base_url = _strip_known_endpoint_suffix(url)
        self._password = password
        self._verify_ssl = verify_ssl
        self._session_cookie: str | None = None

    async def _async_login(self) -> None:
        if not self._password:
            raise WGEasyApiError("No password configured for the v14 API")

        session_url = f"{self._base_url}/api/session"
        try:
            async with self._session.post(
                session_url, json={"password": self._password}, ssl=self._verify_ssl
            ) as response:
                if response.status == 401:
                    raise WGEasyAuthError("Unauthorized - check password")
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(f"Login HTTP {response.status}: {body[:200]}")

                try:
                    login_data = await response.json()
                except ValueError as err:
                    raise WGEasyApiError(f"Invalid login response: {err}") from err

                if isinstance(login_data, dict) and login_data.get("success") is False:
                    raise WGEasyAuthError("wg-easy rejected the configured password")

                cookie = response.cookies.get("connect.sid")
                if not cookie:
                    raise WGEasyApiError("Login succeeded but no session cookie was returned")
                self._session_cookie = cookie.value
        except ClientError as err:
            raise WGEasyApiError(f"Login request failed: {err}") from err

    async def async_fetch_raw(self) -> bytes:
        if not self._session_cookie:
            await self._async_login()

        data_url = f"{self._base_url}/api/wireguard/client"
        cookies = {"connect.sid": self._session_cookie} if self._session_cookie else {}

        try:
            async with self._session.get(
                data_url,
                headers={"Accept": "application/json"},
                cookies=cookies,
                ssl=self._verify_ssl,
            ) as response:
                if response.status == 401:
                    # Session likely expired; drop it so the next poll logs in again.
                    self._session_cookie = None
                    raise WGEasyAuthError("Session expired - will re-authenticate next poll")
                if response.status >= 400:
                    body = await response.text()
                    raise WGEasyApiError(f"HTTP {response.status}: {body[:200]}")
                return await response.read()
        except ClientError as err:
            raise WGEasyApiError(f"Request failed: {err}") from err


async def _looks_like_json(response) -> bool:
    """True if a response is actually JSON, by header or by successfully parsing it.

    Used to avoid being fooled by servers that return HTTP 200/401/etc. for
    every path (e.g. an unrelated single-page app with catch-all client-side
    routing serving its index.html for any URL) instead of a real API
    response.
    """
    content_type = response.headers.get("Content-Type", "")
    if "json" in content_type.lower():
        return True
    try:
        await response.json(content_type=None)
    except ValueError:
        return False
    return True


async def async_probe_wg_easy_version(
    session: ClientSession, url: str, verify_ssl: bool = True
) -> str:
    """Unauthenticated probe to tell wg-easy v14 apart from v15, before any credentials.

    Looks for a version-specific *positive* signature for each, rather than
    assuming "not v14 => v15" - pointing this at an unrelated web service
    that happens to respond to every path (a common pattern for single-page
    apps) would otherwise be misclassified as v15 instead of failing.

    - v14 signature: unauthenticated ``GET {base_url}/api/release`` returns
      the running release as a bare JSON string (confirmed against v14's
      src/lib/Server.js - registered before the password-check middleware).
    - v15 signature: ``GET {base_url}/metrics/json`` is a real route that
      exists only on v15 (its metrics feature). Even without a token it
      should answer with 200 (no metrics password configured) or
      401/403 (password required) and an actual JSON body - never a plain
      404, and never an HTML page.

    If neither signature matches, a WGEasyNotDetectedError is raised so the
    caller can tell the user this doesn't look like a wg-easy server,
    instead of silently guessing. A genuine connection failure (bad URL,
    DNS, refused, timeout, TLS error) raises the plain WGEasyApiError
    instead, so the two cases can get distinct, more useful error messages.

    Deliberately does NOT use Home Assistant's shared client session
    (``session`` is accepted for API-compatibility with callers but
    unused). wg-easy's web UI sets cookies (theme, i18n_redirected, ...)
    on every response, and HA's shared session is process-wide - if
    another wg_easy config entry is already polling this same host with a
    valid Bearer token, its cookies end up in that shared jar too. Using
    a throwaway session with an empty cookie jar makes this probe behave
    like a fresh client every time, regardless of what else is talking to
    the same host.

    The ``/metrics/json`` request also sends a deliberately-bogus
    ``Authorization: Bearer`` header (plus ``Accept: application/json``).
    Even with a clean cookie jar, a request with *no* Authorization header
    at all can still get routed through wg-easy's browser/session-login
    logic on some deployments (reverse proxies and the app's own auth
    middleware may treat "no credentials presented" as "anonymous browser
    visit -> redirect to /login" rather than "API client -> 401 JSON").
    Presenting *a* Bearer token - even an invalid one - unambiguously
    signals "this is an API-style request" to the same auth middleware
    real token-authenticated requests go through (see
    ``WGEasyV15Client.async_fetch_raw``, which reliably gets a clean JSON
    response this way), so the server evaluates and rejects it as bad
    credentials (401/403 JSON) instead of redirecting.
    """
    # Imported locally to avoid a circular import with const.py's importers.
    from .const import API_VERSION_V14, API_VERSION_V15

    base_url = _strip_known_endpoint_suffix(url)
    _LOGGER.debug("wg-easy probe: input url=%r -> base_url=%r", url, base_url)

    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as probe_session:
        try:
            async with probe_session.get(
                f"{base_url}/api/release", ssl=verify_ssl
            ) as response:
                _LOGGER.debug(
                    "wg-easy probe: GET %s -> final_url=%s status=%s content-type=%r",
                    f"{base_url}/api/release",
                    response.url,
                    response.status,
                    response.headers.get("Content-Type"),
                )
                if response.status == 200:
                    try:
                        body = await response.json(content_type=None)
                    except ValueError:
                        body = None
                    if isinstance(body, str) and body.strip():
                        return API_VERSION_V14

            async with probe_session.get(
                f"{base_url}/metrics/json",
                headers={
                    "Authorization": "Bearer wg-easy-ha-integration-version-probe",
                    "Accept": "application/json",
                },
                ssl=verify_ssl,
            ) as response:
                looks_json = await _looks_like_json(response)
                _LOGGER.debug(
                    "wg-easy probe: GET %s -> final_url=%s status=%s "
                    "content-type=%r looks_like_json=%s",
                    f"{base_url}/metrics/json",
                    response.url,
                    response.status,
                    response.headers.get("Content-Type"),
                    looks_json,
                )
                if response.status in (200, 401, 403) and looks_json:
                    return API_VERSION_V15
        except ClientError as err:
            raise WGEasyApiError(f"Could not reach {base_url}: {err}") from err

    raise WGEasyNotDetectedError(
        f"{base_url} does not look like a wg-easy server (neither the v14 "
        "nor the v15 signature endpoint responded as expected). Check the "
        "address, or pick the API version manually if you're sure it's "
        "correct."
    )


async def async_check_v15_admin_credentials(
    session: ClientSession,
    url: str,
    username: str,
    password: str,
    verify_ssl: bool = True,
) -> None:
    """Attempt a v15 admin login to validate credentials.

    Raises WGEasyAuthError on bad credentials, WGEasyApiError on
    connectivity/unexpected errors. Used by the config flow to verify the
    optional admin username+password before saving them.
    """
    client = WGEasyV15Client(
        session, url, token=None, verify_ssl=verify_ssl,
        username=username, admin_password=password,
    )
    await client._async_admin_login()
