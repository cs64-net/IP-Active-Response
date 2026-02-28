"""pfSense client for managing firewall rules via the web interface.

Interacts with pfSense by submitting forms and parsing HTML responses,
since the REST API package may not be installed.
"""

import ipaddress
import logging
import re
from html.parser import HTMLParser
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


class PfSenseError(Exception):
    """Custom exception for pfSense client operations."""
    pass


class PfSenseClient:
    """Client for interacting with pfSense web interface via HTTP."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False, block_method: str = "null_route"):
        """Initialize with pfSense web interface credentials.

        Args:
            host: Hostname or IP of the pfSense device (e.g. '192.168.1.1').
            username: Web interface username.
            password: Web interface password.
            verify_ssl: Whether to verify SSL certificates.
            block_method: 'null_route' or 'floating_rule' — determines which
                          methods add_rules_bulk/remove_rules_bulk delegate to.
        """
        self.host = host.rstrip("/")
        if not self.host.startswith(("http://", "https://")):
            self.host = f"https://{self.host}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.block_method = block_method
        self.session: Optional[requests.Session] = None
        self.csrf_token: Optional[str] = None

    def _get_url(self, path: str) -> str:
        """Build full URL from a path."""
        return f"{self.host}/{path.lstrip('/')}"

    def _parse_csrf_token(self, html: str) -> str:
        """Extract __csrf_magic token from HTML response.

        Args:
            html: HTML content from a pfSense page.

        Returns:
            The CSRF token value.

        Raises:
            PfSenseError: If CSRF token cannot be found.
        """
        match = re.search(
            r'name=["\']__csrf_magic["\']\s+value=["\']([^"\']+)["\']',
            html,
        )
        if not match:
            match = re.search(
                r'value=["\']([^"\']+)["\']\s+name=["\']__csrf_magic["\']',
                html,
            )
        if not match:
            raise PfSenseError("Failed to parse CSRF token from pfSense response")
        return match.group(1)

    def login(self, timeout: int = 30) -> requests.Session:
        """Authenticate to pfSense web interface.

        POSTs credentials to the login page, extracts the CSRF token,
        and maintains the authenticated session.

        Args:
            timeout: Timeout in seconds for each HTTP request (default 30).

        Returns:
            The authenticated requests.Session.

        Raises:
            PfSenseError: If login fails.
        """
        try:
            self.session = requests.Session()
            self.session.verify = self.verify_ssl

            # GET login page to obtain initial CSRF token
            login_url = self._get_url("/index.php")
            resp = self.session.get(login_url, timeout=timeout)
            resp.raise_for_status()

            csrf_token = self._parse_csrf_token(resp.text)

            # POST login credentials
            login_data = {
                "__csrf_magic": csrf_token,
                "usernamefld": self.username,
                "passwordfld": self.password,
                "login": "Sign In",
            }
            resp = self.session.post(login_url, data=login_data, timeout=timeout)
            resp.raise_for_status()

            # Detect failed login: pfSense re-renders the login form on failure.
            # Check for the actual login form fields, not generic words.
            if 'usernamefld' in resp.text and 'passwordfld' in resp.text:
                raise PfSenseError(f"Login failed for {self.host}: invalid credentials")

            # Update CSRF token from the post-login page
            self.csrf_token = self._parse_csrf_token(resp.text)

            logger.info("Successfully logged in to pfSense at %s", self.host)
            return self.session

        except requests.RequestException as e:
            raise PfSenseError(f"Failed to connect to pfSense at {self.host}: {e}") from e

    def _ensure_session(self) -> None:
        """Ensure we have an active authenticated session."""
        if self.session is None:
            self.login()

    def _refresh_csrf(self, html: str) -> None:
        """Update the CSRF token from a page response."""
        try:
            self.csrf_token = self._parse_csrf_token(html)
        except PfSenseError:
            pass  # Keep existing token if parsing fails

    @staticmethod
    def _get_gateway(ip_or_cidr: str) -> str:
        """Return the correct null-route gateway for the given IP address.

        Args:
            ip_or_cidr: IP address or CIDR notation.

        Returns:
            ``"Null6"`` for IPv6 addresses, ``"Null4"`` for IPv4.
        """
        addr = ip_or_cidr.split("/")[0]
        return "Null6" if isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address) else "Null4"

    @staticmethod
    def _split_ip_mask(ip_or_cidr: str) -> tuple:
        """Split an IP or CIDR into (address, subnet_mask) for pfSense forms.

        Args:
            ip_or_cidr: IP address or CIDR notation (e.g. '10.0.0.1' or '10.0.0.0/24').

        Returns:
            Tuple of (address_str, mask_str). Single IPv4 IPs get mask '32',
            single IPv6 IPs get mask '128'.
        """
        if "/" in ip_or_cidr:
            parts = ip_or_cidr.split("/", 1)
            return (parts[0], parts[1])
        addr = ip_or_cidr.split("/")[0]
        if isinstance(ipaddress.ip_address(addr), ipaddress.IPv6Address):
            return (ip_or_cidr, "128")
        return (ip_or_cidr, "32")

    def _parse_alias_entries(self, html: str) -> tuple:
        """Parse alias address entries and subnet masks from pfSense edit page HTML.

        Uses Python's stdlib HTMLParser for reliable parsing instead of regex,
        since pfSense's HTML attribute ordering varies across versions.

        Args:
            html: HTML content from the alias edit page.

        Returns:
            Tuple of (existing_ips, existing_addrs) where:
                existing_ips: list of full CIDR strings (e.g. ['10.0.0.0/24', '1.2.3.4/32'])
                existing_addrs: list of just the address parts (e.g. ['10.0.0.0', '1.2.3.4'])
        """
        addr_map = {}    # index -> address value
        subnet_map = {}  # index -> subnet mask value

        class _AliasHTMLParser(HTMLParser):
            """Stateful parser that extracts address inputs and subnet selects."""

            def __init__(self):
                super().__init__()
                # Track which <select name="address_subnetN"> we're inside
                self._in_select = None  # None or index string

            def handle_starttag(self, tag, attrs):
                attr_dict = dict(attrs)

                if tag == "input":
                    name = attr_dict.get("name", "")
                    value = attr_dict.get("value", "")
                    # Match address0, address1, ... but NOT address_subnet0
                    if name.startswith("address") and "_" not in name:
                        idx = name[len("address"):]
                        if idx.isdigit():
                            addr_map[idx] = value

                elif tag == "select":
                    name = attr_dict.get("name", "")
                    if name.startswith("address_subnet"):
                        idx = name[len("address_subnet"):]
                        if idx.isdigit():
                            self._in_select = idx

                elif tag == "option":
                    if self._in_select is not None:
                        # Check if this option is selected
                        is_selected = ("selected" in attr_dict or
                                       attr_dict.get("selected") == "selected")
                        if is_selected:
                            value = attr_dict.get("value", "")
                            if value.isdigit():
                                subnet_map[self._in_select] = value

            def handle_endtag(self, tag):
                if tag == "select":
                    self._in_select = None

        parser = _AliasHTMLParser()
        try:
            parser.feed(html)
        except Exception:
            logger.warning("HTML parser encountered an error, falling back to partial results")

        # Build full CIDR strings
        existing_ips = []
        existing_addrs = []
        for idx in sorted(addr_map.keys(), key=int):
            raw_addr = addr_map[idx]

            # If the address field already contains CIDR (e.g. "10.0.0.0/24"),
            # extract the mask from it — this is the most reliable source.
            if "/" in raw_addr:
                parts = raw_addr.split("/", 1)
                addr = parts[0]
                mask = parts[1]
            else:
                addr = raw_addr
                # Use the subnet select value, default to 32
                mask = subnet_map.get(idx, "32")

            existing_ips.append(f"{addr}/{mask}")
            existing_addrs.append(addr)

        logger.debug("Parsed %d alias entries (addrs=%s, subnets=%s): %s",
                      len(existing_ips), list(addr_map.keys()),
                      list(subnet_map.keys()), existing_ips)
        return existing_ips, existing_addrs

    def _build_alias_form_data(self, alias_name: str, ips: list, alias_id: str = None) -> dict:
        """Build POST form data for saving a pfSense alias.

        Sends address and subnet mask as separate form fields, matching
        how pfSense's own JavaScript submits the alias edit form.

        Args:
            alias_name: Name of the alias.
            ips: List of IP/CIDR strings (e.g. ['10.0.0.0/24', '1.2.3.4/32']).
            alias_id: Existing alias ID for updates, or None for new aliases.

        Returns:
            Dict of form data ready to POST.
        """
        data = {
            "__csrf_magic": self.csrf_token,
            "name": alias_name,
            "origname": alias_name,
            "descr": "SOC IP Blocker managed alias",
            "type": "network",
            "tab": "network",
            "save": "Save",
        }
        if alias_id is not None:
            data["id"] = alias_id

        for i, ip in enumerate(ips):
            if "/" not in ip:
                ip = f"{ip}/32"
            addr, mask = self._split_ip_mask(ip)
            # Send address and subnet as separate fields — this is how
            # pfSense's own form JavaScript submits alias entries.
            data[f"address{i}"] = addr
            data[f"address_subnet{i}"] = mask
            data[f"detail{i}"] = "SOC blocked entry"

        return data

    def add_null_route(self, ip_address: str) -> bool:
        """Add a static route to null for the given IP via the web interface.

        Creates a static route on pfSense that routes the blocked IP
        to a null/reject gateway, effectively dropping all traffic.

        Args:
            ip_address: IPv4 or IPv6 address to null-route.

        Returns:
            True if the route was added successfully.

        Raises:
            PfSenseError: If the operation fails.
        """
        try:
            self._ensure_session()

            # Check if route already exists (dedup)
            routes_list_url = self._get_url("/system_routes.php")
            resp = self.session.get(routes_list_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Check for existing route — handle both plain IPs and CIDR
            addr, mask = self._split_ip_mask(ip_address)
            route_check = f"{addr}/{mask}"
            if route_check in resp.text:
                logger.debug("Null route for %s already exists on %s, skipping", ip_address, self.host)
                return True

            # GET the static route edit page to get a fresh CSRF token
            route_url = self._get_url("/system_routes_edit.php")
            resp = self.session.get(route_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Submit the static route form
            gateway = self._get_gateway(ip_address)
            route_data = {
                "__csrf_magic": self.csrf_token,
                "network": addr,
                "network_subnet": mask,
                "gateway": gateway,
                "descr": f"SOC IP Blocker - blocked {ip_address}",
                "disabled": "",
                "save": "Save",
                "apply": "Apply Changes",
            }
            resp = self.session.post(route_url, data=route_data, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Apply changes
            routes_url = self._get_url("/system_routes.php")
            resp = self.session.get(routes_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(routes_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info("Added null route for %s on %s", ip_address, self.host)
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to add null route for {ip_address} on {self.host}: {e}"
            ) from e

    def remove_null_route(self, ip_address: str) -> bool:
        """Remove a static null route for the given IP via the web interface.

        Finds the route matching the IP on the static routes page and deletes it.

        Args:
            ip_address: IPv4 or IPv6 address whose null route to remove.

        Returns:
            True if the route was removed successfully.

        Raises:
            PfSenseError: If the operation fails or route is not found.
        """
        try:
            self._ensure_session()

            # GET the static routes list page
            routes_url = self._get_url("/system_routes.php")
            resp = self.session.get(routes_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Find the route ID for this IP by parsing rows
            route_id = None
            rows = re.split(r'<tr[^>]*>', resp.text)
            # Handle both plain IPs and CIDR — use _split_ip_mask for correct default
            addr, mask = self._split_ip_mask(ip_address)
            route_search = f"{addr}/{mask}"
            # Escape dots and slashes for regex word-boundary matching
            route_pattern = re.compile(re.escape(route_search))
            for row in rows:
                if route_pattern.search(row):
                    # Try multiple patterns pfSense uses for delete links
                    id_match = re.search(r'act=del&amp;id=(\d+)', row)
                    if not id_match:
                        id_match = re.search(r'act=del&id=(\d+)', row)
                    if not id_match:
                        # Some pfSense versions use data attributes or JS
                        id_match = re.search(r'data-id=["\'](\d+)["\']', row)
                    if not id_match:
                        # Try finding the row index from a checkbox or hidden input
                        id_match = re.search(r'name=["\']route(\d+)["\']', row)
                    if id_match:
                        route_id = id_match.group(1)
                        break

            if route_id is None:
                raise PfSenseError(
                    f"Null route for {ip_address} not found on {self.host}"
                )

            # Delete the route - try POST first (newer pfSense), fall back to GET
            try:
                delete_data = {
                    "__csrf_magic": self.csrf_token,
                    "act": "del",
                    "id": route_id,
                }
                resp = self.session.post(routes_url, data=delete_data, timeout=30)
                resp.raise_for_status()
                self._refresh_csrf(resp.text)
            except Exception:
                # Fall back to GET-based delete
                delete_url = self._get_url(
                    f"/system_routes.php?act=del&id={route_id}"
                )
                resp = self.session.get(delete_url, timeout=30)
                resp.raise_for_status()
                self._refresh_csrf(resp.text)

            # Apply changes
            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(routes_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info("Removed null route for %s on %s", ip_address, self.host)
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to remove null route for {ip_address} on {self.host}: {e}"
            ) from e

    def add_null_routes_bulk(self, ip_addresses: list) -> dict:
        """Add multiple null routes in a single session to minimize transactions.

        Reuses the same authenticated session for all route additions and
        applies changes only once at the end.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDRs to null-route.

        Returns:
            Dict with 'success' (list of IPs added), 'failed' (list of
            {'ip': str, 'error': str} dicts), and 'skipped' (already existed).
        """
        results = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            self._ensure_session()

            # Fetch routes page once to check existing routes
            routes_list_url = self._get_url("/system_routes.php")
            resp = self.session.get(routes_list_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)
            existing_text = resp.text

            added_any = False
            for ip_address in ip_addresses:
                try:
                    # Check if route already exists
                    check_addr, check_mask = self._split_ip_mask(ip_address)
                    route_check = f"{check_addr}/{check_mask}"
                    if route_check in existing_text:
                        logger.debug(
                            "Null route for %s already exists on %s, skipping",
                            ip_address, self.host,
                        )
                        results["skipped"].append(ip_address)
                        continue

                    # GET the edit page for a fresh CSRF token
                    route_url = self._get_url("/system_routes_edit.php")
                    resp = self.session.get(route_url, timeout=30)
                    resp.raise_for_status()
                    self._refresh_csrf(resp.text)

                    addr, mask = self._split_ip_mask(ip_address)
                    gateway = self._get_gateway(ip_address)

                    route_data = {
                        "__csrf_magic": self.csrf_token,
                        "network": addr,
                        "network_subnet": mask,
                        "gateway": gateway,
                        "descr": f"SOC IP Blocker - blocked {ip_address}",
                        "disabled": "",
                        "save": "Save",
                        "apply": "Apply Changes",
                    }
                    resp = self.session.post(route_url, data=route_data, timeout=30)
                    resp.raise_for_status()
                    self._refresh_csrf(resp.text)

                    results["success"].append(ip_address)
                    added_any = True
                    logger.debug("Added null route for %s on %s", ip_address, self.host)

                except (requests.RequestException, PfSenseError) as e:
                    results["failed"].append({"ip": ip_address, "error": str(e)})
                    logger.warning(
                        "Failed to add null route for %s on %s: %s",
                        ip_address, self.host, e,
                    )

            # Apply changes once at the end if any routes were added
            if added_any:
                try:
                    routes_url = self._get_url("/system_routes.php")
                    resp = self.session.get(routes_url, timeout=30)
                    resp.raise_for_status()
                    self._refresh_csrf(resp.text)

                    apply_data = {
                        "__csrf_magic": self.csrf_token,
                        "apply": "Apply Changes",
                    }
                    resp = self.session.post(routes_url, data=apply_data, timeout=30)
                    resp.raise_for_status()
                except requests.RequestException as e:
                    logger.error("Failed to apply route changes on %s: %s", self.host, e)

            logger.info(
                "Bulk add null routes on %s: %d added, %d skipped, %d failed",
                self.host, len(results["success"]),
                len(results["skipped"]), len(results["failed"]),
            )
            return results

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to bulk add null routes on {self.host}: {e}"
            ) from e

    def remove_null_routes_bulk(self, ip_addresses: list) -> dict:
        """Remove multiple null routes in a single session to minimize transactions.

        Reuses the same authenticated session. For each IP, re-fetches the routes
        page to get current route IDs (since pfSense re-indexes after each deletion),
        then deletes and applies changes once at the end.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses or CIDRs to remove.

        Returns:
            Dict with 'success' (list of IPs removed), 'failed' (list of
            {'ip': str, 'error': str} dicts), and 'skipped' (not found).
        """
        results = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            self._ensure_session()
            routes_url = self._get_url("/system_routes.php")

            removed_any = False
            for ip_address in ip_addresses:
                try:
                    # Use _split_ip_mask for correct default mask
                    search_addr, search_mask = self._split_ip_mask(ip_address)
                    route_search = f"{search_addr}/{search_mask}"

                    # Re-fetch routes page each time to get current IDs
                    resp = self.session.get(routes_url, timeout=30)
                    resp.raise_for_status()
                    self._refresh_csrf(resp.text)
                    rows = re.split(r'<tr[^>]*>', resp.text)

                    route_pattern = re.compile(re.escape(route_search))
                    route_id = None
                    for row in rows:
                        if route_pattern.search(row):
                            id_match = re.search(r'act=del&amp;id=(\d+)', row)
                            if not id_match:
                                id_match = re.search(r'act=del&id=(\d+)', row)
                            if not id_match:
                                id_match = re.search(r'data-id=["\'](\d+)["\']', row)
                            if not id_match:
                                id_match = re.search(r'name=["\']route(\d+)["\']', row)
                            if id_match:
                                route_id = id_match.group(1)
                                break

                    if route_id is None:
                        logger.debug(
                            "Null route for %s not found on %s, skipping",
                            ip_address, self.host,
                        )
                        results["skipped"].append(ip_address)
                        continue

                    # Delete the route
                    try:
                        delete_data = {
                            "__csrf_magic": self.csrf_token,
                            "act": "del",
                            "id": route_id,
                        }
                        resp = self.session.post(routes_url, data=delete_data, timeout=30)
                        resp.raise_for_status()
                        self._refresh_csrf(resp.text)
                    except Exception:
                        delete_url = self._get_url(
                            f"/system_routes.php?act=del&id={route_id}"
                        )
                        resp = self.session.get(delete_url, timeout=30)
                        resp.raise_for_status()
                        self._refresh_csrf(resp.text)

                    results["success"].append(ip_address)
                    removed_any = True
                    logger.debug("Removed null route for %s on %s", ip_address, self.host)

                except (requests.RequestException, PfSenseError) as e:
                    results["failed"].append({"ip": ip_address, "error": str(e)})
                    logger.warning(
                        "Failed to remove null route for %s on %s: %s",
                        ip_address, self.host, e,
                    )

            # Apply changes once at the end if any routes were removed
            if removed_any:
                try:
                    resp = self.session.get(routes_url, timeout=30)
                    resp.raise_for_status()
                    self._refresh_csrf(resp.text)

                    apply_data = {
                        "__csrf_magic": self.csrf_token,
                        "apply": "Apply Changes",
                    }
                    resp = self.session.post(routes_url, data=apply_data, timeout=30)
                    resp.raise_for_status()
                except requests.RequestException as e:
                    logger.error("Failed to apply route changes on %s: %s", self.host, e)

            logger.info(
                "Bulk remove null routes on %s: %d removed, %d skipped, %d failed",
                self.host, len(results["success"]),
                len(results["skipped"]), len(results["failed"]),
            )
            return results

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to bulk remove null routes on {self.host}: {e}"
            ) from e


    def ensure_alias_exists(self, alias_name: str, ips: List[str]) -> bool:
        """Create or update a pfSense alias with the given IP list.

        If the alias already exists, it is updated with the new IP list.
        If it doesn't exist, a new alias is created.

        Args:
            alias_name: Name of the alias (e.g. 'soc_blocklist').
            ips: List of IP addresses to include in the alias.

        Returns:
            True if the alias was created/updated successfully.

        Raises:
            PfSenseError: If the operation fails.
        """
        try:
            self._ensure_session()

            # Check if alias already exists by loading the alias list page
            aliases_url = self._get_url("/firewall_aliases.php")
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Look for existing alias edit link
            alias_id = None
            pattern = re.compile(
                rf'firewall_aliases_edit\.php\?id=(\d+).*?{re.escape(alias_name)}|'
                rf'{re.escape(alias_name)}.*?firewall_aliases_edit\.php\?id=(\d+)',
                re.DOTALL,
            )
            match = pattern.search(resp.text)
            if match:
                alias_id = match.group(1) or match.group(2)

            # Build the alias edit URL
            if alias_id is not None:
                edit_url = self._get_url(f"/firewall_aliases_edit.php?id={alias_id}")
            else:
                edit_url = self._get_url("/firewall_aliases_edit.php")

            # GET the edit page for a fresh CSRF token
            resp = self.session.get(edit_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Build form data — CIDR embedded in address fields
            alias_data = self._build_alias_form_data(alias_name, ips, alias_id)

            resp = self.session.post(edit_url, data=alias_data, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Apply changes
            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(aliases_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info(
                "Alias '%s' ensured with %d IPs on %s",
                alias_name, len(ips), self.host,
            )
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to ensure alias '{alias_name}' on {self.host}: {e}"
            ) from e

    def add_ip_to_alias(self, alias_name: str, ip_address: str) -> bool:
        """Add a single IP to an existing pfSense alias.

        Loads the current alias, appends the new IP, and saves.

        Args:
            alias_name: Name of the alias.
            ip_address: IP address to add.

        Returns:
            True if the IP was added successfully.

        Raises:
            PfSenseError: If the operation fails or alias not found.
        """
        try:
            self._ensure_session()

            # Find the alias ID
            aliases_url = self._get_url("/firewall_aliases.php")
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            pattern = re.compile(
                rf'firewall_aliases_edit\.php\?id=(\d+).*?{re.escape(alias_name)}|'
                rf'{re.escape(alias_name)}.*?firewall_aliases_edit\.php\?id=(\d+)',
                re.DOTALL,
            )
            match = pattern.search(resp.text)
            if not match:
                raise PfSenseError(
                    f"Alias '{alias_name}' not found on {self.host}"
                )

            alias_id = match.group(1) or match.group(2)

            # Load the alias edit page to get current IPs
            edit_url = self._get_url(f"/firewall_aliases_edit.php?id={alias_id}")
            resp = self.session.get(edit_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Parse existing alias entries (handles any HTML attribute order)
            existing_ips, existing_addrs = self._parse_alias_entries(resp.text)

            search_addr, _ = self._split_ip_mask(ip_address)

            # Skip if IP already exists in the alias
            if search_addr in existing_addrs:
                logger.debug(
                    "IP %s already in alias '%s' on %s, skipping",
                    ip_address, alias_name, self.host,
                )
                return True

            # Add the new IP — existing_ips already has full CIDR
            all_ips = existing_ips + [ip_address]

            # Rebuild and submit the form — CIDR embedded in address fields
            alias_data = self._build_alias_form_data(alias_name, all_ips, alias_id)

            resp = self.session.post(edit_url, data=alias_data, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Apply changes
            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(aliases_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info(
                "Added %s to alias '%s' on %s",
                ip_address, alias_name, self.host,
            )
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to add {ip_address} to alias '{alias_name}' on {self.host}: {e}"
            ) from e

    def remove_ip_from_alias(self, alias_name: str, ip_address: str) -> bool:
        """Remove a single IP from a pfSense alias.

        Loads the current alias, removes the IP, and saves.

        Args:
            alias_name: Name of the alias.
            ip_address: IP address to remove.

        Returns:
            True if the IP was removed successfully.

        Raises:
            PfSenseError: If the operation fails or alias/IP not found.
        """
        try:
            self._ensure_session()

            # Find the alias ID
            aliases_url = self._get_url("/firewall_aliases.php")
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            pattern = re.compile(
                rf'firewall_aliases_edit\.php\?id=(\d+).*?{re.escape(alias_name)}|'
                rf'{re.escape(alias_name)}.*?firewall_aliases_edit\.php\?id=(\d+)',
                re.DOTALL,
            )
            match = pattern.search(resp.text)
            if not match:
                raise PfSenseError(
                    f"Alias '{alias_name}' not found on {self.host}"
                )

            alias_id = match.group(1) or match.group(2)

            # Load the alias edit page to get current IPs
            edit_url = self._get_url(f"/firewall_aliases_edit.php?id={alias_id}")
            resp = self.session.get(edit_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Parse existing alias entries (handles any HTML attribute order)
            existing_ips, existing_addrs = self._parse_alias_entries(resp.text)

            search_addr, _ = self._split_ip_mask(ip_address)

            if search_addr not in existing_addrs:
                raise PfSenseError(
                    f"IP {ip_address} not found in alias '{alias_name}' on {self.host}"
                )

            # Remove the IP (compare by address part, keep full CIDR for remaining)
            updated_ips = [ip for ip, addr in zip(existing_ips, existing_addrs) if addr != search_addr]

            # Rebuild and submit the form — CIDR embedded in address fields
            alias_data = self._build_alias_form_data(alias_name, updated_ips, alias_id)

            resp = self.session.post(edit_url, data=alias_data, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Apply changes
            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(aliases_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info(
                "Removed %s from alias '%s' on %s",
                ip_address, alias_name, self.host,
            )
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to remove {ip_address} from alias '{alias_name}' on {self.host}: {e}"
            ) from e

    def _create_single_floating_rule(self, rule_data: dict) -> None:
        """Submit a single floating rule form to pfSense.

        Args:
            rule_data: Form data dict for the rule (without CSRF token).

        Raises:
            PfSenseError: If the form submission fails or pfSense returns errors.
        """
        # GET the rule edit page for a fresh CSRF token
        rule_url = self._get_url("/firewall_rules_edit.php")
        resp = self.session.get(rule_url, timeout=30)
        resp.raise_for_status()
        self._refresh_csrf(resp.text)

        # Merge CSRF token into the form data
        form_data = {"__csrf_magic": self.csrf_token}
        form_data.update(rule_data)

        resp = self.session.post(rule_url, data=form_data, timeout=30, allow_redirects=True)
        if resp.status_code >= 400:
            logger.error("pfSense returned %d for rule creation on %s. Body (first 500 chars): %s",
                         resp.status_code, self.host, resp.text[:500])
            resp.raise_for_status()

        # Check for pfSense input validation errors in the response.
        # On success, pfSense redirects to the rules list (302) or shows
        # the rules page without error divs. On failure, it re-renders
        # the edit form with class="input-errors" or "alert-danger".
        body_lower = resp.text.lower()
        if "input-errors" in body_lower or "alert-danger" in body_lower:
            # Try to extract the error message
            import re as _re
            err_match = _re.search(
                r'class="[^"]*(?:input-errors|alert-danger)[^"]*"[^>]*>(.*?)</div>',
                resp.text,
                _re.DOTALL | _re.IGNORECASE,
            )
            err_detail = err_match.group(1).strip() if err_match else "unknown validation error"
            # Strip HTML tags for a cleaner message
            err_detail = _re.sub(r'<[^>]+>', ' ', err_detail).strip()
            logger.error("pfSense rejected the rule: %s", err_detail)
            raise PfSenseError(f"pfSense rejected the rule: {err_detail}")

        self._refresh_csrf(resp.text)
        logger.debug("Floating rule submitted successfully on %s", self.host)

    def create_floating_rule(self, alias_name: str) -> bool:
        """Create floating block rules referencing the given alias.

        Creates TWO floating firewall rules on pfSense:
          1. Inbound  — block traffic FROM the alias (source) TO any destination
          2. Outbound — block traffic FROM any source TO the alias (destination)

        This ensures blocked IPs cannot send or receive traffic through
        the firewall.

        Args:
            alias_name: Name of the pfSense alias to reference.

        Returns:
            True if both rules were created and applied successfully.

        Raises:
            PfSenseError: If the operation fails.
        """
        try:
            self._ensure_session()

            # Check if floating rules already exist
            floating_url = self._get_url("/firewall_rules.php?if=FloatingRules")
            resp = self.session.get(floating_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            has_inbound = "SOC IP Blocker" in resp.text and "Inbound block" in resp.text
            has_outbound = "SOC IP Blocker" in resp.text and "Outbound block" in resp.text

            if has_inbound and has_outbound:
                logger.info("Floating rules already exist for alias '%s' on %s, skipping", alias_name, self.host)
                return True

            # --- Rule 1: Inbound — source = alias, destination = any ---
            if not has_inbound:
                inbound_data = {
                    "type": "block",
                    "interface[]": ["any"],
                    "ipprotocol": "inet",
                    "proto": "any",
                    "srctype": "single",
                    "src": alias_name,
                    "dsttype": "any",
                    "descr": f"SOC IP Blocker — Inbound block ({alias_name})",
                    "floating": "yes",
                    "quick": "yes",
                    "direction": "any",
                    "save": "Save",
                }
                logger.info("Creating inbound floating rule for alias '%s' on %s", alias_name, self.host)
                self._create_single_floating_rule(inbound_data)

            # --- Rule 2: Outbound — source = any, destination = alias ---
            if not has_outbound:
                outbound_data = {
                    "type": "block",
                    "interface[]": ["any"],
                    "ipprotocol": "inet",
                    "proto": "any",
                    "srctype": "any",
                    "dsttype": "single",
                    "dst": alias_name,
                    "descr": f"SOC IP Blocker — Outbound block ({alias_name})",
                    "floating": "yes",
                    "quick": "yes",
                    "direction": "any",
                    "save": "Save",
                }
                logger.info("Creating outbound floating rule for alias '%s' on %s", alias_name, self.host)
                self._create_single_floating_rule(outbound_data)

            # --- Apply changes on the floating rules page ---
            floating_url = self._get_url("/firewall_rules.php?if=FloatingRules")
            resp = self.session.get(floating_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(floating_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            logger.info(
                "Created inbound + outbound floating block rules for alias '%s' on %s",
                alias_name, self.host,
            )
            return True

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to create floating rule for alias '{alias_name}' on {self.host}: {e}"
            ) from e

    def remove_floating_rules(self, alias_name: str) -> bool:
        """Remove SOC IP Blocker floating rules from pfSense.

        Finds and deletes all floating rules whose description contains
        'SOC IP Blocker'.

        Args:
            alias_name: Name of the alias referenced by the rules.

        Returns:
            True if rules were removed successfully.

        Raises:
            PfSenseError: If the operation fails.
        """
        try:
            self._ensure_session()

            floating_url = self._get_url("/firewall_rules.php?if=FloatingRules")
            resp = self.session.get(floating_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Find rule IDs that match SOC IP Blocker
            rows = re.split(r'<tr[^>]*>', resp.text)
            rule_ids = []
            for row in rows:
                if "SOC IP Blocker" in row:
                    id_match = re.search(r'act=del[^"\']*id=(\d+)', row)
                    if id_match:
                        rule_ids.append(id_match.group(1))

            if not rule_ids:
                logger.info("No SOC IP Blocker floating rules found on %s", self.host)
                return True

            logger.info("Found %d SOC IP Blocker floating rule(s) to remove on %s: %s",
                        len(rule_ids), self.host, rule_ids)

            # Delete rules in reverse order (highest ID first) to avoid index shifting
            for rule_id in sorted(rule_ids, key=int, reverse=True):
                # pfSense 16.0+ requires POST for deletions (usepost attribute)
                delete_data = {
                    "__csrf_magic": self.csrf_token,
                    "act": "del",
                    "if": "FloatingRules",
                    "id": rule_id,
                }
                resp = self.session.post(
                    self._get_url("/firewall_rules.php"),
                    data=delete_data, timeout=30
                )
                resp.raise_for_status()
                self._refresh_csrf(resp.text)
                logger.debug("Deleted floating rule ID %s on %s", rule_id, self.host)

            # Apply changes
            resp = self.session.get(floating_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(floating_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            # Verify rules were actually removed
            resp = self.session.get(floating_url, timeout=30)
            resp.raise_for_status()
            if "SOC IP Blocker" in resp.text:
                logger.warning("SOC IP Blocker rules still present after deletion attempt on %s", self.host)
                raise PfSenseError(
                    f"Failed to remove floating rules on {self.host}: rules still present after deletion"
                )

            logger.info("Removed %d SOC IP Blocker floating rule(s) on %s", len(rule_ids), self.host)
            return True

        except PfSenseError:
            raise
        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to remove floating rules on {self.host}: {e}"
            ) from e

    def remove_alias(self, alias_name: str) -> bool:
        """Remove a pfSense alias by name.

        Args:
            alias_name: Name of the alias to remove.

        Returns:
            True if the alias was removed successfully.

        Raises:
            PfSenseError: If the operation fails or alias not found.
        """
        try:
            self._ensure_session()

            aliases_url = self._get_url("/firewall_aliases.php")
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Find alias ID
            pattern = re.compile(
                rf'firewall_aliases_edit\.php\?id=(\d+).*?{re.escape(alias_name)}|'
                rf'{re.escape(alias_name)}.*?firewall_aliases_edit\.php\?id=(\d+)',
                re.DOTALL,
            )
            match = pattern.search(resp.text)
            if not match:
                logger.info("Alias '%s' not found on %s, nothing to remove", alias_name, self.host)
                return True

            alias_id = match.group(1) or match.group(2)
            logger.info("Found alias '%s' with ID %s on %s, removing", alias_name, alias_id, self.host)

            # pfSense 16.0+ requires POST for deletions (usepost attribute)
            delete_data = {
                "__csrf_magic": self.csrf_token,
                "act": "del",
                "tab": "ip",
                "id": alias_id,
            }
            logger.debug("Deleting alias '%s' (ID %s) via POST on %s", alias_name, alias_id, self.host)
            resp = self.session.post(aliases_url, data=delete_data, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Apply changes
            apply_data = {
                "__csrf_magic": self.csrf_token,
                "apply": "Apply Changes",
            }
            resp = self.session.post(aliases_url, data=apply_data, timeout=30)
            resp.raise_for_status()

            # Verify alias was removed
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            if alias_name in resp.text:
                logger.warning("Alias '%s' still present after deletion attempt on %s", alias_name, self.host)
                raise PfSenseError(
                    f"Failed to remove alias '{alias_name}' on {self.host}: alias still present after deletion"
                )

            logger.info("Removed alias '%s' on %s", alias_name, self.host)
            return True

        except PfSenseError:
            raise
        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to remove alias '{alias_name}' on {self.host}: {e}"
            ) from e

    def check_health(self) -> bool:
        """Check if pfSense web interface is reachable.

        Performs a simple GET to the login page and returns True if HTTP 200.

        Returns:
            True if the pfSense web interface is reachable, False otherwise.
        """
        try:
            session = requests.Session()
            session.verify = self.verify_ssl
            resp = session.get(self._get_url("/index.php"), timeout=30)
            return resp.status_code == 200
        except requests.RequestException:
            return False
    def get_alias_entries(self, alias_name: str) -> set:
        """Retrieve current entries from a pfSense alias for reconciliation.

        Navigates to the alias edit page and parses the current IP entries.

        Args:
            alias_name: Name of the alias to query.

        Returns:
            Set of IP/CIDR strings currently in the alias.

        Raises:
            PfSenseError: If the alias is not found or the operation fails.
        """
        try:
            self._ensure_session()

            # Find the alias ID from the aliases list page
            aliases_url = self._get_url("/firewall_aliases.php")
            resp = self.session.get(aliases_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            pattern = re.compile(
                rf'firewall_aliases_edit\.php\?id=(\d+).*?{re.escape(alias_name)}|'
                rf'{re.escape(alias_name)}.*?firewall_aliases_edit\.php\?id=(\d+)',
                re.DOTALL,
            )
            match = pattern.search(resp.text)
            if not match:
                raise PfSenseError(
                    f"Alias '{alias_name}' not found on {self.host}"
                )

            alias_id = match.group(1) or match.group(2)

            # Load the alias edit page and parse entries
            edit_url = self._get_url(f"/firewall_aliases_edit.php?id={alias_id}")
            resp = self.session.get(edit_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            existing_ips, _ = self._parse_alias_entries(resp.text)

            logger.debug(
                "Retrieved %d entries from alias '%s' on %s",
                len(existing_ips), alias_name, self.host,
            )
            return set(existing_ips)

        except PfSenseError:
            raise
        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to get alias entries for '{alias_name}' on {self.host}: {e}"
            ) from e

    def get_static_routes(self) -> set:
        """Retrieve current null/blackhole static routes for reconciliation.

        Navigates to the static routes page and parses routes that use
        Null4/Null6 gateways (blackhole routes managed by SOC IP Blocker).

        Returns:
            Set of IP/CIDR strings that have null routes.

        Raises:
            PfSenseError: If the operation fails.
        """
        try:
            self._ensure_session()

            routes_url = self._get_url("/system_routes.php")
            resp = self.session.get(routes_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            routes = set()
            rows = re.split(r'<tr[^>]*>', resp.text)
            for row in rows:
                # Only match rows with null gateway (blackhole routes)
                if not re.search(r'Null[46]', row, re.IGNORECASE):
                    continue
                # Extract the network/CIDR from the row
                # pfSense displays routes as "x.x.x.x/mask" in table cells
                ip_match = re.search(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})',
                    row,
                )
                if ip_match:
                    routes.add(ip_match.group(1))

            logger.debug(
                "Retrieved %d null routes from %s", len(routes), self.host,
            )
            return routes

        except requests.RequestException as e:
            raise PfSenseError(
                f"Failed to get static routes from {self.host}: {e}"
            ) from e

    # --- BaseDeviceClient adapter methods ---

    ALIAS_NAME = "soc_blocklist"

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Adapter for BaseDeviceClient interface.

        Routes to alias-based or null-route methods based on self.block_method.
        """
        if self.block_method == "floating_rule":
            return self._add_via_alias(ip_addresses)
        return self.add_null_routes_bulk(ip_addresses)

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Adapter for BaseDeviceClient interface.

        Routes to alias-based or null-route methods based on self.block_method.
        """
        if self.block_method == "floating_rule":
            return self._remove_via_alias(ip_addresses)
        return self.remove_null_routes_bulk(ip_addresses)

    def _add_via_alias(self, ip_addresses: list) -> dict:
        """Add IPs using the read-merge-write alias approach."""
        failed = []
        try:
            try:
                current_entries = self.get_alias_entries(self.ALIAS_NAME)
            except Exception:
                current_entries = set()

            merged = set(current_entries)
            current_addrs = {e.split("/")[0] for e in current_entries}

            for ip in ip_addresses:
                addr = ip.split("/")[0] if "/" in ip else ip
                if addr not in current_addrs:
                    merged.add(ip if "/" in ip else f"{ip}/32")
                    current_addrs.add(addr)

            self.ensure_alias_exists(self.ALIAS_NAME, list(merged))
            try:
                self.create_floating_rule(self.ALIAS_NAME)
            except Exception as exc:
                logger.warning("Failed to ensure floating rule: %s", exc)

        except Exception:
            failed = list(ip_addresses)

        return {"success": [ip for ip in ip_addresses if ip not in failed],
                "failed": failed, "skipped": []}

    def _remove_via_alias(self, ip_addresses: list) -> dict:
        """Remove IPs using the read-merge-write alias approach."""
        failed = []
        try:
            try:
                current_entries = self.get_alias_entries(self.ALIAS_NAME)
            except Exception:
                current_entries = set()

            remove_addrs = {(ip.split("/")[0] if "/" in ip else ip) for ip in ip_addresses}
            remaining = [e for e in current_entries
                         if (e.split("/")[0] if "/" in e else e) not in remove_addrs]

            self.ensure_alias_exists(self.ALIAS_NAME, remaining)

        except Exception:
            failed = list(ip_addresses)

        return {"success": [ip for ip in ip_addresses if ip not in failed],
                "failed": failed, "skipped": []}



