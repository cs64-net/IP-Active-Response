"""pfSense client for managing firewall rules via the web interface.

Interacts with pfSense by submitting forms and parsing HTML responses,
since the REST API package may not be installed.
"""

import logging
import re
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)


class PfSenseError(Exception):
    """Custom exception for pfSense client operations."""
    pass


class PfSenseClient:
    """Client for interacting with pfSense web interface via HTTP."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        """Initialize with pfSense web interface credentials.

        Args:
            host: Hostname or IP of the pfSense device (e.g. '192.168.1.1').
            username: Web interface username.
            password: Web interface password.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.host = host.rstrip("/")
        if not self.host.startswith(("http://", "https://")):
            self.host = f"https://{self.host}"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
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
    def _split_ip_mask(ip_or_cidr: str) -> tuple:
        """Split an IP or CIDR into (address, subnet_mask) for pfSense forms.

        Args:
            ip_or_cidr: IP address or CIDR notation (e.g. '10.0.0.1' or '10.0.0.0/24').

        Returns:
            Tuple of (address_str, mask_str). Single IPs get mask '32'.
        """
        if "/" in ip_or_cidr:
            parts = ip_or_cidr.split("/", 1)
            return (parts[0], parts[1])
        return (ip_or_cidr, "32")

    def _parse_alias_entries(self, html: str) -> tuple:
        """Parse alias address entries and subnet masks from pfSense edit page HTML.

        Handles both attribute orderings (name before value and value before name)
        and both input and select elements.

        Args:
            html: HTML content from the alias edit page.

        Returns:
            Tuple of (existing_ips, existing_addrs) where:
                existing_ips: list of full CIDR strings (e.g. ['10.0.0.0/24', '1.2.3.4/32'])
                existing_addrs: list of just the address parts (e.g. ['10.0.0.0', '1.2.3.4'])
        """
        # Find all tags (input/select) and extract name + value from each
        # This handles any attribute order
        addr_map = {}  # index -> address value
        subnet_map = {}  # index -> subnet mask value

        # Match each HTML tag that contains 'address' in a name attribute
        for tag_match in re.finditer(r'<(?:input|select)[^>]*>', html, re.IGNORECASE):
            tag = tag_match.group(0)

            # Extract name attribute
            name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
            if not name_match:
                continue
            name_val = name_match.group(1)

            # Extract value attribute (for input elements)
            value_match = re.search(r'value=["\']([^"\']*)["\']', tag)

            # Check if this is an address field
            addr_field = re.match(r'^address(\d+)$', name_val)
            if addr_field and value_match and value_match.group(1):
                addr_map[addr_field.group(1)] = value_match.group(1)
                continue

            # Check if this is a subnet field
            subnet_field = re.match(r'^address_subnet(\d+)$', name_val)
            if subnet_field:
                # For select elements, look for the selected option value
                if '<select' in tag.lower() or not value_match:
                    # Find the selected option after this select tag
                    tag_end = tag_match.end()
                    # Look for selected option within the next chunk of HTML
                    select_chunk = html[tag_end:tag_end + 2000]
                    selected_match = re.search(
                        r'<option[^>]*value=["\']([^"\']*)["\'][^>]*selected',
                        select_chunk,
                        re.IGNORECASE,
                    )
                    if not selected_match:
                        selected_match = re.search(
                            r'<option[^>]*selected[^>]*value=["\']([^"\']*)["\']',
                            select_chunk,
                            re.IGNORECASE,
                        )
                    if selected_match:
                        subnet_map[subnet_field.group(1)] = selected_match.group(1)
                elif value_match:
                    subnet_map[subnet_field.group(1)] = value_match.group(1)

        # Build full CIDR strings
        existing_ips = []
        existing_addrs = []
        for idx in sorted(addr_map.keys(), key=int):
            addr = addr_map[idx]
            mask = subnet_map.get(idx, "32")
            existing_ips.append(f"{addr}/{mask}")
            existing_addrs.append(addr)

        logger.debug("Parsed %d alias entries: %s", len(existing_ips), existing_ips)
        return existing_ips, existing_addrs
    def _build_alias_form_data(self, alias_name: str, ips: list, alias_id: str = None) -> dict:
        """Build POST form data for saving a pfSense alias.

        Embeds CIDR notation directly in the address field so pfSense's
        saveAlias() parses the subnet from the address string itself,
        avoiding issues where address_subnet POST values are ignored.

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
            # Ensure every entry has CIDR notation so pfSense parses
            # the subnet from the address field directly.
            if "/" not in ip:
                ip = f"{ip}/32"
            addr, mask = self._split_ip_mask(ip)
            # Put full CIDR in address field — pfSense splits on "/"
            data[f"address{i}"] = f"{addr}/{mask}"
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
            if "/" in ip_address:
                route_check = ip_address
            else:
                route_check = f"{ip_address}/32"
            if route_check in resp.text:
                logger.debug("Null route for %s already exists on %s, skipping", ip_address, self.host)
                return True

            # GET the static route edit page to get a fresh CSRF token
            route_url = self._get_url("/system_routes_edit.php")
            resp = self.session.get(route_url, timeout=30)
            resp.raise_for_status()
            self._refresh_csrf(resp.text)

            # Split IP and subnet for the form
            addr, mask = self._split_ip_mask(ip_address)

            # Submit the static route form
            route_data = {
                "__csrf_magic": self.csrf_token,
                "network": addr,
                "network_subnet": mask,
                "gateway": "Null4",
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
            # Handle both plain IPs and CIDR
            if "/" in ip_address:
                route_search = ip_address
            else:
                route_search = f"{ip_address}/32"
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
