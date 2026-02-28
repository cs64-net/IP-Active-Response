"""UniFi controller client for managing IP blocks via REST API.

Uses the ``requests`` library to interact with the UniFi controller's
REST API.  Manages a named Network List (firewall group of type
``address-group``) containing blocked IP addresses.  SSL verification
is disabled by default because self-signed certificates are common on
UniFi controllers.
"""

import ipaddress
import logging
from typing import Optional

import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

BATCH_SIZE = 200


class UniFiError(Exception):
    """Custom exception for UniFi client operations."""
    pass


class UniFiClient:
    """Client for managing IP blocks on UniFi controllers via REST API.

    Operates in alias-only mode: creates and maintains a Network List
    on the UniFi controller.  The administrator must manually reference
    the Network List in their firewall rules or ZBFW zone policies.
    """

    def __init__(self, host: str, api_port: int, username: str,
                 password: str,
                 network_list_name: str = "SOC_BLOCKLIST"):
        """Initialize REST API connection parameters for UniFi controller.

        Args:
            host: Hostname or IP of the UniFi controller.
            api_port: API port number (typically 443).
            username: API username.
            password: API password.
            network_list_name: Name of the Network List to manage
                (default: SOC_BLOCKLIST).
        """
        self.host = host
        self.api_port = api_port
        self.username = username
        self.password = password
        self.network_list_name = network_list_name
        self.base_url = f"https://{self.host}:{self.api_port}"
        self.session: Optional[requests.Session] = None
        self._csrf_token: Optional[str] = None

    # -----------------------------------------------------------------
    # IP normalisation helper
    # -----------------------------------------------------------------

    @staticmethod
    def _normalise_ip(ip_str: str) -> str:
        """Normalise an IP/CIDR for the UniFi firewall group API.

        The UniFi API rejects ``/32`` suffixes on IPv4 host addresses
        and ``/128`` suffixes on IPv6 host addresses, but accepts bare
        IPs and proper subnet CIDR (e.g. ``/24``, ``/64``).

        Examples:
            '10.0.0.1'       -> '10.0.0.1'
            '10.0.0.1/32'    -> '10.0.0.1'
            '10.0.3.0/24'    -> '10.0.3.0/24'
            '2003::1/128'    -> '2003::1'
            '2003::/64'      -> '2003::/64'
        """
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
            if isinstance(network, ipaddress.IPv4Network):
                if network.prefixlen == 32:
                    return str(network.network_address)
            elif isinstance(network, ipaddress.IPv6Network):
                if network.prefixlen == 128:
                    return str(network.network_address)
            return str(network)
        except ValueError:
            return ip_str.split("/")[0]

    @staticmethod
    def _is_ipv6(ip_str: str) -> bool:
        """Return True if *ip_str* is an IPv6 address or network."""
        try:
            return isinstance(
                ipaddress.ip_network(ip_str, strict=False),
                ipaddress.IPv6Network,
            )
        except ValueError:
            return ":" in ip_str

    # -----------------------------------------------------------------
    # Session / authentication helpers
    # -----------------------------------------------------------------

    def _login(self) -> requests.Session:
        """Authenticate to the UniFi controller API.

        POSTs credentials to ``/api/auth/login``, stores the session
        cookies, and fetches the CSRF token required for write operations.

        Returns:
            The authenticated :class:`requests.Session`.

        Raises:
            UniFiError: If login fails.
        """
        try:
            self.session = requests.Session()
            self.session.verify = False  # self-signed certs

            login_url = f"{self.base_url}/api/auth/login"
            resp = self.session.post(
                login_url,
                json={"username": self.username, "password": self.password},
                timeout=30,
            )
            if resp.status_code == 401:
                raise UniFiError(
                    f"Login failed for {self.host}: invalid credentials"
                )
            resp.raise_for_status()

            # Fetch CSRF token from a GET request
            csrf_resp = self.session.get(
                self._firewallgroup_url(), timeout=30,
            )
            self._csrf_token = csrf_resp.headers.get("X-Csrf-Token")

            logger.info(
                "Successfully logged in to UniFi controller at %s",
                self.host,
            )
            return self.session

        except requests.RequestException as e:
            raise UniFiError(
                f"Failed to connect to UniFi controller at {self.host}: {e}"
            ) from e

    def _ensure_session(self) -> None:
        """Ensure we have an active authenticated session."""
        if self.session is None:
            self._login()

    def _write_headers(self) -> dict:
        """Return headers required for write operations (POST/PUT/DELETE)."""
        headers = {}
        if self._csrf_token:
            headers["X-Csrf-Token"] = self._csrf_token
        return headers

    # -----------------------------------------------------------------
    # Network List (firewall group) helpers
    # -----------------------------------------------------------------

    def _firewallgroup_url(self, group_id: Optional[str] = None) -> str:
        """Build the REST URL for firewall group operations.

        Args:
            group_id: Optional group ``_id`` for PUT/DELETE operations.

        Returns:
            Full URL string.
        """
        base = (
            f"{self.base_url}"
            "/proxy/network/api/s/default/rest/firewallgroup"
        )
        if group_id:
            return f"{base}/{group_id}"
        return base

    def _get_network_list(self, name: Optional[str] = None) -> Optional[dict]:
        """Fetch a managed Network List from the controller by name.

        Args:
            name: Group name to look up.  Defaults to
                ``self.network_list_name``.

        Returns:
            The firewall group dict if found, or ``None``.

        Raises:
            UniFiError: On API errors.
        """
        self._ensure_session()
        target = name or self.network_list_name
        try:
            resp = self.session.get(
                self._firewallgroup_url(), timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            groups = data.get("data", [])
            for group in groups:
                if group.get("name") == target:
                    return group
            return None
        except requests.RequestException as e:
            raise UniFiError(
                f"Failed to fetch firewall groups from {self.host}: {e}"
            ) from e

    def _create_network_list(self, ip_addresses: list,
                             name: Optional[str] = None,
                             group_type: str = "address-group") -> dict:
        """Create a new Network List on the controller.

        Args:
            ip_addresses: Initial list of (already normalised) IPs.
            name: Group name.  Defaults to ``self.network_list_name``.
            group_type: ``address-group`` for IPv4 or
                ``ipv6-address-group`` for IPv6.

        Returns:
            The created firewall group dict.

        Raises:
            UniFiError: On API errors.
        """
        self._ensure_session()
        target = name or self.network_list_name
        payload = {
            "name": target,
            "group_type": group_type,
            "group_members": ip_addresses,
        }
        try:
            resp = self.session.post(
                self._firewallgroup_url(),
                json=payload,
                headers=self._write_headers(),
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            created = data.get("data", [{}])[0]
            logger.info(
                "Created Network List '%s' (%s) on %s with %d IPs",
                target, group_type, self.host, len(ip_addresses),
            )
            return created
        except requests.RequestException as e:
            raise UniFiError(
                f"Failed to create Network List on {self.host}: {e}"
            ) from e

    def _update_network_list(self, group_id: str,
                             ip_addresses: list,
                             name: Optional[str] = None,
                             group_type: str = "address-group") -> dict:
        """Update the Network List members on the controller.

        Args:
            group_id: The ``_id`` of the existing firewall group.
            ip_addresses: Complete list of (already normalised) IPs.
            name: Group name.  Defaults to ``self.network_list_name``.
            group_type: ``address-group`` or ``ipv6-address-group``.

        Returns:
            The updated firewall group dict.

        Raises:
            UniFiError: On API errors.
        """
        self._ensure_session()
        target = name or self.network_list_name
        payload = {
            "name": target,
            "group_type": group_type,
            "group_members": ip_addresses,
        }
        try:
            resp = self.session.put(
                self._firewallgroup_url(group_id),
                json=payload,
                headers=self._write_headers(),
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            updated = data.get("data", [{}])[0]
            return updated
        except requests.RequestException as e:
            raise UniFiError(
                f"Failed to update Network List on {self.host}: {e}"
            ) from e

    def _delete_network_list(self, group_id: str) -> bool:
        """Delete the Network List from the controller.

        Args:
            group_id: The ``_id`` of the firewall group to delete.

        Returns:
            True if deletion succeeded.

        Raises:
            UniFiError: On API errors.
        """
        self._ensure_session()
        try:
            resp = self.session.delete(
                self._firewallgroup_url(group_id),
                headers=self._write_headers(),
                timeout=30,
            )
            resp.raise_for_status()
            logger.info(
                "Deleted Network List '%s' from %s",
                self.network_list_name, self.host,
            )
            return True
        except requests.RequestException as e:
            raise UniFiError(
                f"Failed to delete Network List on {self.host}: {e}"
            ) from e

    # -----------------------------------------------------------------
    # Public interface (matches other device clients)
    # -----------------------------------------------------------------

    def _upsert_group(self, ips: list, name: str,
                      group_type: str) -> None:
        """Create-or-merge IPs into a firewall group.

        Args:
            ips: Already-normalised IP strings.
            name: Firewall group name.
            group_type: ``address-group`` or ``ipv6-address-group``.
        """
        group = self._get_network_list(name)
        if group is None:
            self._create_network_list(ips, name=name,
                                      group_type=group_type)
        else:
            existing = set(group.get("group_members", []))
            new_ips = [ip for ip in ips if ip not in existing]
            if new_ips:
                merged = list(existing | set(new_ips))
                self._update_network_list(group["_id"], merged,
                                          name=name,
                                          group_type=group_type)

    def _shrink_group(self, ips: set, name: str,
                      group_type: str) -> None:
        """Remove IPs from a firewall group.

        Args:
            ips: Already-normalised IP strings to remove.
            name: Firewall group name.
            group_type: ``address-group`` or ``ipv6-address-group``.
        """
        group = self._get_network_list(name)
        if group is None:
            return
        existing = set(group.get("group_members", []))
        remaining = list(existing - ips)
        self._update_network_list(group["_id"], remaining,
                                  name=name, group_type=group_type)

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Add IPs to the named Network List(s) via the Networks API.

        IPv4 addresses go into an ``address-group`` named
        ``{network_list_name}``.  IPv6 addresses go into an
        ``ipv6-address-group`` named ``{network_list_name}_V6``.

        Args:
            ip_addresses: List of IP addresses to add.

        Returns:
            Dict with ``success`` and ``failed`` lists.
        """
        results: dict = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            self._ensure_session()

            v4 = [self._normalise_ip(ip) for ip in ip_addresses
                  if not self._is_ipv6(ip)]
            v6 = [self._normalise_ip(ip) for ip in ip_addresses
                  if self._is_ipv6(ip)]

            if v4:
                self._upsert_group(
                    v4, self.network_list_name, "address-group")
            if v6:
                self._upsert_group(
                    v6, f"{self.network_list_name}_V6",
                    "ipv6-address-group")

            results["success"] = list(ip_addresses)

        except Exception as e:
            processed = set(results["success"])
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        added = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk Network List add on %s: %d added, %d failed",
            self.host, added, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove IPs from the named Network List(s) via the Networks API.

        Args:
            ip_addresses: List of IP addresses to remove.

        Returns:
            Dict with ``success`` and ``failed`` lists.
        """
        results: dict = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            self._ensure_session()

            v4 = {self._normalise_ip(ip) for ip in ip_addresses
                  if not self._is_ipv6(ip)}
            v6 = {self._normalise_ip(ip) for ip in ip_addresses
                  if self._is_ipv6(ip)}

            if v4:
                self._shrink_group(
                    v4, self.network_list_name, "address-group")
            if v6:
                self._shrink_group(
                    v6, f"{self.network_list_name}_V6",
                    "ipv6-address-group")

            results["success"] = list(ip_addresses)

        except Exception as e:
            processed = set(results["success"])
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        removed = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk Network List remove on %s: %d removed, %d failed",
            self.host, removed, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify API connectivity to the UniFi controller.

        Attempts to log in and fetch the firewall groups endpoint.

        Returns:
            True if the API is reachable and authentication succeeds,
            False otherwise.
        """
        try:
            # Force a fresh login to verify credentials
            self.session = None
            self._login()
            resp = self.session.get(
                self._firewallgroup_url(), timeout=30,
            )
            resp.raise_for_status()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove the SOC-managed Network Lists from the controller.

        Finds both the IPv4 and IPv6 managed groups by name and deletes
        them.

        Returns:
            True if cleanup succeeded or the lists didn't exist,
            False otherwise.
        """
        try:
            self._ensure_session()
            for name in (self.network_list_name,
                         f"{self.network_list_name}_V6"):
                group = self._get_network_list(name)
                if group is None:
                    logger.info(
                        "Network List '%s' not found on %s — nothing to "
                        "clean up", name, self.host,
                    )
                else:
                    self._delete_network_list(group["_id"])
            return True
        except Exception as e:
            logger.error(
                "Failed to cleanup Network Lists on %s: %s",
                self.host, e,
            )
            return False
