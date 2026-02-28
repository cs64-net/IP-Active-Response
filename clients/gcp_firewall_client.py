"""GCP VPC Firewall device client for managing IP blocking via firewall deny rules.

Uses google-cloud-compute SDK to create/remove ingress deny rules on a GCP
VPC network. SOC-managed rules use the naming convention ``soc-block-<ip-hash>``.

Adding this client requires:
1. google-cloud-compute installed
2. Register the factory in CLIENT_REGISTRY in services/push_orchestrator.py
"""

import hashlib
import ipaddress
import json
import logging
import time
from typing import Dict, List, Optional

from google.cloud import compute_v1
from google.api_core import exceptions as gcp_exceptions
from google.oauth2 import service_account

from clients.base_client import BaseDeviceClient

logger = logging.getLogger(__name__)

# GCP VPC firewall default rule limit (quota-based, configurable)
DEFAULT_RULE_LIMIT = 500

# Rule name prefix for SOC-managed rules
SOC_RULE_PREFIX = "soc-block-"

# Retry configuration for API throttling
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds


class GcpFirewallError(Exception):
    """Raised on GCP Firewall API errors."""


class GcpFirewallClient(BaseDeviceClient):
    """Manage IP blocking via GCP VPC firewall deny rules.

    Creates ingress deny-all rules for each blocked IP address. Rules are
    named ``soc-block-<ip-hash>`` where the hash is a deterministic SHA-256
    truncation of the IP address. Supports both IPv4 and IPv6 addresses.
    """

    def __init__(self, service_account_json: str,
                 project_id: str, network_name: str,
                 capacity_limit: int = DEFAULT_RULE_LIMIT):
        """Initialise the GCP Firewall client.

        Args:
            service_account_json: GCP service account key as a JSON string.
            project_id: GCP project ID.
            network_name: VPC network name to manage firewall rules on.
            capacity_limit: Maximum number of firewall rules (default 500).
        """
        self.project_id = project_id
        self.network_name = network_name
        self.capacity_limit = capacity_limit

        sa_info = json.loads(service_account_json)
        credentials = service_account.Credentials.from_service_account_info(
            sa_info,
        )
        self.firewalls_client = compute_v1.FirewallsClient(
            credentials=credentials,
        )
        logger.info(
            "GcpFirewallClient initialised for project '%s', network '%s'",
            project_id, network_name,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_ipv6(ip_str: str) -> bool:
        """Return True if *ip_str* is an IPv6 address."""
        try:
            return isinstance(
                ipaddress.ip_address(ip_str.split("/")[0]),
                ipaddress.IPv6Address,
            )
        except ValueError:
            return ":" in ip_str

    @staticmethod
    def _to_cidr(ip_str: str) -> str:
        """Normalise an IP to a host CIDR (``/32`` or ``/128``)."""
        if "/" in ip_str:
            return ip_str
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv6Address):
                return f"{ip_str}/128"
            return f"{ip_str}/32"
        except ValueError:
            return f"{ip_str}/32"

    @staticmethod
    def rule_name_for_ip(ip_str: str) -> str:
        """Generate a deterministic rule name for an IP address.

        Uses ``soc-block-<first-8-chars-of-sha256>`` to produce a
        consistent, collision-resistant name.

        Args:
            ip_str: The IP address (without CIDR suffix).

        Returns:
            Rule name like ``soc-block-a1b2c3d4``.
        """
        bare_ip = ip_str.split("/")[0].strip().lower()
        ip_hash = hashlib.sha256(bare_ip.encode()).hexdigest()[:8]
        return f"{SOC_RULE_PREFIX}{ip_hash}"

    def _network_url(self) -> str:
        """Return the full network URL for the VPC."""
        return (
            f"projects/{self.project_id}/global/networks/{self.network_name}"
        )

    def _api_call_with_retry(self, func, *args, **kwargs):
        """Execute a GCP API call with exponential backoff on throttling.

        Args:
            func: The GCP SDK method to call.
            *args: Positional arguments forwarded to *func*.
            **kwargs: Keyword arguments forwarded to *func*.

        Returns:
            The API response.

        Raises:
            google.api_core.exceptions.GoogleAPIError: If all retries exhausted.
        """
        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except gcp_exceptions.TooManyRequests as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    logger.warning(
                        "GCP API throttled (attempt %d/%d), "
                        "retrying in %ds …",
                        attempt + 1, MAX_RETRIES, delay,
                    )
                    time.sleep(delay)
                    continue
                raise
            except gcp_exceptions.ResourceExhausted as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    delay = RETRY_DELAYS[attempt]
                    logger.warning(
                        "GCP API resource exhausted (attempt %d/%d), "
                        "retrying in %ds …",
                        attempt + 1, MAX_RETRIES, delay,
                    )
                    time.sleep(delay)
                    continue
                raise
        raise last_exc  # pragma: no cover

    def _list_firewall_rules(self) -> List:
        """Fetch all firewall rules for the project.

        Returns:
            List of firewall rule objects.
        """
        request = compute_v1.ListFirewallsRequest(project=self.project_id)
        rules = []
        for rule in self._api_call_with_retry(
            self.firewalls_client.list, request=request,
        ):
            rules.append(rule)
        return rules

    def _soc_managed_rules(self, rules: List) -> List:
        """Filter rules to only SOC-managed rules (by name prefix)."""
        return [
            r for r in rules
            if r.name and r.name.startswith(SOC_RULE_PREFIX)
        ]

    def _find_rule_for_ip(self, rules: List, ip_str: str) -> Optional[object]:
        """Find an existing SOC-managed rule matching *ip_str*."""
        rule_name = self.rule_name_for_ip(ip_str)
        for rule in rules:
            if rule.name == rule_name:
                return rule
        return None

    def _count_soc_rules(self, rules: List) -> int:
        """Count SOC-managed firewall rules."""
        return len(self._soc_managed_rules(rules))

    def _wait_for_operation(self, operation):
        """Wait for a GCP global operation to complete."""
        if operation is None:
            return
        # The compute_v1 insert/delete methods return an ExtendedOperation
        # that supports .result() to block until completion.
        try:
            operation.result()
        except Exception as exc:
            logger.warning("Operation wait error: %s", exc)
            raise

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Create VPC firewall ingress deny rules for each IP address.

        Each rule is named ``soc-block-<ip-hash>`` and denies all ingress
        traffic from the source IP. Skips IPs that already have a deny
        rule. Respects the configurable capacity limit.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses to block.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: Dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            rules = self._list_firewall_rules()
        except Exception as exc:
            logger.error("Failed to list firewall rules for project '%s': %s",
                         self.project_id, exc)
            for ip in ip_addresses:
                results["failed"].append({"ip": ip, "error": str(exc)})
            return results

        soc_count = self._count_soc_rules(rules)

        for ip in ip_addresses:
            cidr = self._to_cidr(ip)
            rule_name = self.rule_name_for_ip(ip)

            # Skip already-blocked
            existing = self._find_rule_for_ip(rules, ip)
            if existing is not None:
                results["skipped"].append(ip)
                continue

            # Capacity check
            if soc_count >= self.capacity_limit:
                logger.warning(
                    "GCP firewall capacity limit reached for project '%s': "
                    "%d/%d rules",
                    self.project_id, soc_count, self.capacity_limit,
                )
                results["failed"].append({
                    "ip": ip,
                    "error": f"Capacity limit reached: "
                             f"{soc_count}/{self.capacity_limit} rules",
                })
                continue

            try:
                firewall_rule = compute_v1.Firewall(
                    name=rule_name,
                    network=self._network_url(),
                    direction="INGRESS",
                    priority=1000,
                    source_ranges=[cidr],
                    denied=[compute_v1.Denied(
                        I_p_protocol="all",
                    )],
                    description=f"SOC IP Blocker - block {ip}",
                )

                operation = self._api_call_with_retry(
                    self.firewalls_client.insert,
                    project=self.project_id,
                    firewall_resource=firewall_rule,
                )
                self._wait_for_operation(operation)

                results["success"].append(ip)
                soc_count += 1
                # Add synthetic rule so subsequent IPs see updated state
                synthetic = type("Rule", (), {"name": rule_name})()
                rules.append(synthetic)

            except Exception as exc:
                logger.error(
                    "Failed to add GCP firewall deny rule for %s: %s",
                    ip, exc,
                )
                results["failed"].append({"ip": ip, "error": str(exc)})

        added = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk GCP firewall add on project '%s': "
            "%d added, %d skipped, %d failed",
            self.project_id, added, skipped, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Remove VPC firewall deny rules for each IP address.

        Skips IPs that do not have a matching deny rule.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses to unblock.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: Dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            rules = self._list_firewall_rules()
        except Exception as exc:
            logger.error("Failed to list firewall rules for project '%s': %s",
                         self.project_id, exc)
            for ip in ip_addresses:
                results["failed"].append({"ip": ip, "error": str(exc)})
            return results

        for ip in ip_addresses:
            rule_name = self.rule_name_for_ip(ip)

            existing = self._find_rule_for_ip(rules, ip)
            if existing is None:
                results["skipped"].append(ip)
                continue

            try:
                operation = self._api_call_with_retry(
                    self.firewalls_client.delete,
                    project=self.project_id,
                    firewall=rule_name,
                )
                self._wait_for_operation(operation)

                results["success"].append(ip)
                rules.remove(existing)

            except Exception as exc:
                logger.error(
                    "Failed to remove GCP firewall deny rule for %s: %s",
                    ip, exc,
                )
                results["failed"].append({"ip": ip, "error": str(exc)})

        removed = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk GCP firewall remove on project '%s': "
            "%d removed, %d skipped, %d failed",
            self.project_id, removed, skipped, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify GCP Compute API connectivity and project access.

        Returns:
            True if the project's firewall rules can be listed, False otherwise.
        """
        try:
            self._list_firewall_rules()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed VPC firewall deny rules.

        Deletes every rule whose name starts with ``soc-block-``.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            rules = self._list_firewall_rules()
            soc_rules = self._soc_managed_rules(rules)

            for rule in soc_rules:
                try:
                    operation = self._api_call_with_retry(
                        self.firewalls_client.delete,
                        project=self.project_id,
                        firewall=rule.name,
                    )
                    self._wait_for_operation(operation)
                except Exception as exc:
                    logger.error(
                        "Failed to delete GCP firewall rule '%s': %s",
                        rule.name, exc,
                    )
                    return False

            logger.info(
                "Cleaned up %d SOC-managed rules from project '%s'",
                len(soc_rules), self.project_id,
            )
            return True

        except Exception as exc:
            logger.error(
                "Failed to cleanup GCP firewall rules for project '%s': %s",
                self.project_id, exc,
            )
            return False
