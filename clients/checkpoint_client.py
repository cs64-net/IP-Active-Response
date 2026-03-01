"""Check Point firewall client for managing IP blocks via Management API.

Uses the Check Point Management API (HTTPS REST) with session-based
authentication.  Host objects are created with a ``SOC_`` prefix and
added to a network group.  All changes must be followed by a
``publish`` call to commit the session.

On publish failure, ``discard`` is called to roll back uncommitted
changes.
"""

import logging
from typing import Optional

import requests
import urllib3

from clients.base_client import BaseDeviceClient

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
MAX_GROUP_OBJECTS = 10000


class CheckPointError(Exception):
    """Custom exception for Check Point client operations."""
    pass


class CheckPointClient(BaseDeviceClient):
    """Client for managing IP blocks on Check Point firewalls via HTTPS.

    Uses the Check Point Management API with session-based auth.  Each
    session begins with a ``/web_api/login`` call that returns a session
    ID (``sid``).  The ``sid`` is included in the ``X-chkp-sid`` header
    for all subsequent API calls.

    Host objects are named with a ``SOC_`` prefix where dots are
    replaced by underscores (e.g. ``SOC_192_168_1_1`` for IP
    ``192.168.1.1``) so they can be identified and cleaned up.

    When the number of objects in a single network group exceeds
    ``MAX_GROUP_OBJECTS`` (10,000), entries are split across multiple
    groups with numeric suffixes.
    """

    def __init__(self, host: str, api_port: int, username: str,
                 password: str,
                 object_group_name: str = "SOC_BLOCKLIST",
                 domain: str = ""):
        """Initialize HTTPS connection parameters for Check Point.

        Args:
            host: Hostname or IP of the Check Point management server.
            api_port: Management API port (typically 443).
            username: API username.
            password: API password.
            object_group_name: Name of the network group to manage
                (default: SOC_BLOCKLIST).
            domain: Optional domain name for multi-domain server (MDS)
                environments.
        """
        self.host = host
        self.api_port = api_port
        self.username = username
        self.password = password
        self.object_group_name = object_group_name
        self.domain = domain
        self.base_url = f"https://{self.host}:{self.api_port}/web_api"
        self.sid: Optional[str] = None

    # ------------------------------------------------------------------
    # Naming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _host_object_name(ip: str) -> str:
        """Return the Check Point host object name for an IP.

        Dots and colons are replaced with underscores.  CIDR /32
        suffixes are stripped.

        Examples:
            '192.168.1.1'     -> 'SOC_192_168_1_1'
            '10.0.0.1/32'     -> 'SOC_10_0_0_1'

        Args:
            ip: IP address, optionally with CIDR notation.

        Returns:
            Name string like ``SOC_192_168_1_1``.
        """
        addr = ip
        if "/" in addr:
            parts = addr.split("/")
            if parts[1] == "32":
                addr = parts[0]
            else:
                addr = addr.replace("/", "_")
        return "SOC_" + addr.replace(".", "_").replace(":", "_")

    @staticmethod
    def _bare_ip(ip_str: str) -> str:
        """Strip CIDR /32 suffix from an IP address.

        Args:
            ip_str: IP address, optionally with CIDR notation.

        Returns:
            Bare IP address string.
        """
        if ip_str.endswith("/32"):
            return ip_str[:-3]
        return ip_str

    # ------------------------------------------------------------------
    # Group splitting helpers
    # ------------------------------------------------------------------

    def _group_name(self, index: int) -> str:
        """Return the network group name for a given split index.

        Index 0 uses the base name; subsequent indices get a numeric
        suffix starting at 2.

        Args:
            index: Zero-based split index.

        Returns:
            Group name, e.g. ``SOC_BLOCKLIST`` or ``SOC_BLOCKLIST_2``.
        """
        if index == 0:
            return self.object_group_name
        return f"{self.object_group_name}_{index + 1}"

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _api_call(self, endpoint: str, payload: dict) -> dict:
        """Make an authenticated API call to the Check Point Management API.

        Args:
            endpoint: API endpoint path (e.g. ``add-host``).
            payload: JSON request body.

        Returns:
            Parsed JSON response dict.

        Raises:
            CheckPointError: If the API call fails.
        """
        url = f"{self.base_url}/{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid

        try:
            resp = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=30,
            )
            data = resp.json()
            return data
        except requests.RequestException as e:
            raise CheckPointError(
                f"API call to {endpoint} failed: {e}"
            ) from e

    def _login(self) -> str:
        """Authenticate and obtain a session ID.

        Returns:
            Session ID string.

        Raises:
            CheckPointError: If login fails.
        """
        payload: dict = {
            "user": self.username,
            "password": self.password,
        }
        if self.domain:
            payload["domain"] = self.domain

        data = self._api_call("login", payload)
        sid = data.get("sid")
        if not sid:
            msg = data.get("message", "Unknown login error")
            raise CheckPointError(f"Login failed: {msg}")
        self.sid = sid
        return sid

    def _publish(self) -> dict:
        """Publish (commit) the current session.

        Returns:
            API response dict.

        Raises:
            CheckPointError: If publish fails.
        """
        data = self._api_call("publish", {})
        if "task-id" not in data and "message" in data:
            raise CheckPointError(
                f"Publish failed: {data.get('message', 'Unknown error')}"
            )
        return data

    def _discard(self) -> dict:
        """Discard (roll back) uncommitted changes in the current session.

        Returns:
            API response dict.
        """
        try:
            return self._api_call("discard", {})
        except CheckPointError:
            logger.warning("Discard call failed on %s", self.host)
            return {}

    def _logout(self) -> None:
        """Log out and invalidate the session."""
        try:
            self._api_call("logout", {})
        except CheckPointError:
            logger.warning("Logout call failed on %s", self.host)
        finally:
            self.sid = None

    # ------------------------------------------------------------------
    # add_rules_bulk
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Create host objects and add them to the network group.

        Creates host objects via ``add-host`` with ``SOC_`` prefix
        naming, then adds them to the configured network group via
        ``set-group``.  When objects exceed ``MAX_GROUP_OBJECTS``,
        splits across multiple groups with numeric suffixes.

        Calls ``publish`` after each batch.  On publish failure, calls
        ``discard`` to roll back and returns failed IPs with error.

        Args:
            ip_addresses: List of IP addresses to block.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            self._login()
            try:
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    batch_success: list = []
                    batch_names: list = []

                    for ip in batch:
                        try:
                            obj_name = self._host_object_name(ip)
                            bare = self._bare_ip(ip)

                            # Create host object
                            data = self._api_call("add-host", {
                                "name": obj_name,
                                "ip-address": bare,
                            })

                            if "uid" in data:
                                batch_success.append(ip)
                                batch_names.append(obj_name)
                            elif "already exists" in data.get("message", "").lower():
                                results["skipped"].append(ip)
                            else:
                                msg = data.get("message", "Unknown error")
                                results["failed"].append(
                                    {"ip": ip, "error": msg}
                                )
                        except CheckPointError as e:
                            results["failed"].append(
                                {"ip": ip, "error": str(e)}
                            )

                    # Add created hosts to group(s)
                    if batch_names:
                        current_total = len(results["success"]) + len(batch_success)
                        self._add_to_groups(batch_names, current_total)

                    # Publish after each batch
                    if batch_success:
                        try:
                            self._publish()
                            results["success"].extend(batch_success)
                        except CheckPointError as pe:
                            self._discard()
                            for ip in batch_success:
                                results["failed"].append(
                                    {"ip": ip, "error": str(pe)}
                                )
            finally:
                self._logout()
        except CheckPointError as e:
            processed = (
                set(results["success"])
                | {f["ip"] for f in results["failed"]}
                | set(results["skipped"])
            )
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        added = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk add on %s: %d added, %d failed",
            self.host, added, failed,
        )
        return results

    def _add_to_groups(self, obj_names: list, current_total: int) -> None:
        """Add host object names to the appropriate network group(s).

        Distributes objects across groups based on the current total
        count and ``MAX_GROUP_OBJECTS`` limit.

        Args:
            obj_names: List of host object names to add.
            current_total: Current total number of objects across all
                groups (used for split index calculation).
        """
        # Group the names by which split group they belong to
        groups: dict = {}
        base_count = current_total - len(obj_names)
        for idx, name in enumerate(obj_names):
            group_index = (base_count + idx) // MAX_GROUP_OBJECTS
            group_name = self._group_name(group_index)
            groups.setdefault(group_name, []).append(name)

        for group_name, members in groups.items():
            self._api_call("set-group", {
                "name": group_name,
                "members": {"add": members},
            })

    # ------------------------------------------------------------------
    # remove_rules_bulk
    # ------------------------------------------------------------------

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove host objects from the network group and delete them.

        Removes host objects from the group via ``set-group``, then
        deletes them via ``delete-host``.  Calls ``publish`` after each
        batch.  On publish failure, calls ``discard``.

        Missing objects are skipped gracefully.

        Args:
            ip_addresses: List of IP addresses to unblock.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            self._login()
            try:
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    batch_success: list = []
                    batch_names: list = []

                    for ip in batch:
                        obj_name = self._host_object_name(ip)
                        batch_names.append((ip, obj_name))

                    # Remove from all possible groups
                    all_names = [n for _, n in batch_names]
                    self._remove_from_groups(all_names)

                    # Delete host objects
                    for ip, obj_name in batch_names:
                        try:
                            data = self._api_call("delete-host", {
                                "name": obj_name,
                            })
                            msg = data.get("message", "")
                            if ("not found" in msg.lower()
                                    or "do not exist" in msg.lower()):
                                results["skipped"].append(ip)
                            elif "code" in data and data.get("code") == "generic_err_object_not_found":
                                results["skipped"].append(ip)
                            else:
                                batch_success.append(ip)
                        except CheckPointError as e:
                            if "not found" in str(e).lower():
                                results["skipped"].append(ip)
                            else:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                    # Publish after each batch
                    if batch_success:
                        try:
                            self._publish()
                            results["success"].extend(batch_success)
                        except CheckPointError as pe:
                            self._discard()
                            for ip in batch_success:
                                results["failed"].append(
                                    {"ip": ip, "error": str(pe)}
                                )
            finally:
                self._logout()
        except CheckPointError as e:
            processed = (
                set(results["success"])
                | {f["ip"] for f in results["failed"]}
                | set(results["skipped"])
            )
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        removed = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk remove on %s: %d removed, %d failed",
            self.host, removed, failed,
        )
        return results

    def _remove_from_groups(self, obj_names: list) -> None:
        """Remove host object names from all managed network groups.

        Tries the base group and numbered suffixes.  Errors are
        silently ignored since the object may not be in every group.

        Args:
            obj_names: List of host object names to remove.
        """
        for idx in range(10):
            group_name = self._group_name(idx)
            try:
                self._api_call("set-group", {
                    "name": group_name,
                    "members": {"remove": obj_names},
                })
            except CheckPointError:
                # Group may not exist — that's fine
                break

    # ------------------------------------------------------------------
    # check_health
    # ------------------------------------------------------------------

    def check_health(self) -> bool:
        """Verify connectivity to the Check Point Management API.

        Attempts to log in and immediately logs out.

        Returns:
            True if login succeeds, False otherwise.
        """
        try:
            self._login()
            self._logout()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> bool:
        """Remove all SOC-managed host objects and network groups.

        Deletes all ``SOC_`` prefixed host objects and the managed
        network group(s), then publishes.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            self._login()
            try:
                # Delete managed network groups (base + numbered)
                for idx in range(10):
                    group_name = self._group_name(idx)
                    try:
                        data = self._api_call("delete-group", {
                            "name": group_name,
                        })
                    except CheckPointError:
                        if idx > 0:
                            break  # No more numbered groups

                # Find and delete all SOC_ host objects
                self._delete_soc_hosts()

                # Publish cleanup
                self._publish()

                logger.info("Cleaned up SOC entries on %s", self.host)
                return True
            finally:
                self._logout()
        except Exception as e:
            logger.error("Failed to cleanup on %s: %s", self.host, e)
            return False

    def _delete_soc_hosts(self) -> None:
        """Delete all host objects with the SOC_ prefix.

        Uses ``show-hosts`` to list objects and deletes those matching
        the ``SOC_`` naming convention.
        """
        offset = 0
        limit = 500
        while True:
            try:
                data = self._api_call("show-hosts", {
                    "limit": limit,
                    "offset": offset,
                    "details-level": "standard",
                })
                objects = data.get("objects", [])
                if not objects:
                    break

                for obj in objects:
                    name = obj.get("name", "")
                    if name.startswith("SOC_"):
                        try:
                            self._api_call("delete-host", {
                                "name": name,
                            })
                        except CheckPointError:
                            logger.warning(
                                "Failed to delete host %s on %s",
                                name, self.host,
                            )

                if len(objects) < limit:
                    break
                offset += limit
            except CheckPointError:
                break
