"""Azure NSG device client for managing IP blocking via Network Security Group deny rules.

Uses azure-mgmt-network SDK to create/remove inbound deny rules on an Azure
NSG. SOC-managed rules use the naming convention ``soc-block-<ip-hash>`` and
priorities in the range 100–4096.

Adding this client requires:
1. azure-identity and azure-mgmt-network installed
2. Register the factory in CLIENT_REGISTRY in services/push_orchestrator.py
"""

import hashlib
import ipaddress
import logging
import time
from typing import Dict, List, Optional

from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import SecurityRule
from azure.core.exceptions import HttpResponseError, ClientAuthenticationError

from clients.base_client import BaseDeviceClient

logger = logging.getLogger(__name__)

# Azure NSG default rule limit
DEFAULT_RULE_LIMIT = 1000

# SOC-managed rule priority range (inclusive)
SOC_PRIORITY_MIN = 100
SOC_PRIORITY_MAX = 4096

# Rule name prefix for SOC-managed rules
SOC_RULE_PREFIX = "soc-block-"

# Retry configuration for API throttling
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds


class AzureNsgError(Exception):
    """Raised on Azure NSG API errors."""


class AzureNsgClient(BaseDeviceClient):
    """Manage IP blocking via Azure Network Security Group deny rules.

    Creates inbound deny-all rules for each blocked IP address. Rules are
    named ``soc-block-<ip-hash>`` where the hash is a deterministic SHA-256
    truncation of the IP address. Supports both IPv4 and IPv6 addresses.
    """

    def __init__(self, tenant_id: str, client_id: str,
                 client_secret: str, subscription_id: str,
                 resource_group: str, nsg_name: str):
        """Initialise the Azure NSG client.

        Args:
            tenant_id: Azure AD tenant ID.
            client_id: Azure AD application (client) ID.
            client_secret: Azure AD client secret.
            subscription_id: Azure subscription ID.
            resource_group: Resource group containing the NSG.
            nsg_name: Name of the Network Security Group to manage.
        """
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.nsg_name = nsg_name

        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self.network_client = NetworkManagementClient(
            credential, subscription_id,
        )
        logger.info(
            "AzureNsgClient initialised for NSG '%s' in resource group '%s'",
            nsg_name, resource_group,
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
        # Normalise: strip CIDR, lowercase
        bare_ip = ip_str.split("/")[0].strip().lower()
        ip_hash = hashlib.sha256(bare_ip.encode()).hexdigest()[:8]
        return f"{SOC_RULE_PREFIX}{ip_hash}"

    def _api_call_with_retry(self, func, *args, **kwargs):
        """Execute an Azure API call with exponential backoff on throttling.

        Args:
            func: The Azure SDK method to call.
            *args: Positional arguments forwarded to *func*.
            **kwargs: Keyword arguments forwarded to *func*.

        Returns:
            The API response.

        Raises:
            HttpResponseError: If all retries are exhausted.
        """
        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except HttpResponseError as exc:
                if exc.status_code == 429 or "throttl" in str(exc).lower():
                    last_exc = exc
                    if attempt < MAX_RETRIES:
                        delay = RETRY_DELAYS[attempt]
                        logger.warning(
                            "Azure API throttled (attempt %d/%d), "
                            "retrying in %ds …",
                            attempt + 1, MAX_RETRIES, delay,
                        )
                        time.sleep(delay)
                        continue
                raise
        raise last_exc  # pragma: no cover

    def _get_nsg(self):
        """Fetch the NSG from Azure.

        Returns:
            The NSG object.

        Raises:
            AzureNsgError: If the NSG is not found.
        """
        try:
            return self._api_call_with_retry(
                self.network_client.network_security_groups.get,
                self.resource_group,
                self.nsg_name,
            )
        except HttpResponseError as exc:
            raise AzureNsgError(
                f"NSG '{self.nsg_name}' not found in resource group "
                f"'{self.resource_group}': {exc}"
            ) from exc

    def _get_existing_rules(self) -> List:
        """Return the current security rules on the NSG."""
        nsg = self._get_nsg()
        return list(nsg.security_rules or [])

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

    def _next_priority(self, rules: List) -> Optional[int]:
        """Find the next available priority in the SOC-managed range.

        Returns:
            An available priority number, or ``None`` if the range is full.
        """
        used = {
            r.priority for r in rules
            if r.priority is not None
            and SOC_PRIORITY_MIN <= r.priority <= SOC_PRIORITY_MAX
        }
        for priority in range(SOC_PRIORITY_MIN, SOC_PRIORITY_MAX + 1):
            if priority not in used:
                return priority
        return None

    def _count_rules(self, rules: List) -> int:
        """Count total security rules on the NSG."""
        return len(rules)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Create NSG inbound deny rules for each IP address.

        Each rule is named ``soc-block-<ip-hash>`` and denies all inbound
        traffic from the source IP. Skips IPs that already have a deny
        rule. Respects the Azure NSG rule limit (1,000 rules by default).

        Args:
            ip_addresses: List of IPv4/IPv6 addresses to block.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: Dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            rules = self._get_existing_rules()
        except Exception as exc:
            logger.error("Failed to get NSG rules for '%s': %s",
                         self.nsg_name, exc)
            for ip in ip_addresses:
                results["failed"].append({"ip": ip, "error": str(exc)})
            return results

        for ip in ip_addresses:
            cidr = self._to_cidr(ip)
            rule_name = self.rule_name_for_ip(ip)

            # Skip already-blocked
            existing = self._find_rule_for_ip(rules, ip)
            if existing is not None:
                results["skipped"].append(ip)
                continue

            # Capacity check
            rule_count = self._count_rules(rules)
            if rule_count >= DEFAULT_RULE_LIMIT:
                logger.warning(
                    "NSG '%s' capacity limit reached: %d/%d rules",
                    self.nsg_name, rule_count, DEFAULT_RULE_LIMIT,
                )
                results["failed"].append({
                    "ip": ip,
                    "error": f"Capacity limit reached: "
                             f"{rule_count}/{DEFAULT_RULE_LIMIT} rules",
                })
                continue

            priority = self._next_priority(rules)
            if priority is None:
                results["failed"].append({
                    "ip": ip,
                    "error": "No available SOC priority numbers",
                })
                continue

            try:
                rule_params = SecurityRule(
                    protocol="*",
                    source_address_prefix=cidr,
                    destination_address_prefix="*",
                    access="Deny",
                    direction="Inbound",
                    priority=priority,
                    source_port_range="*",
                    destination_port_range="*",
                    description=f"SOC IP Blocker - block {ip}",
                )

                poller = self._api_call_with_retry(
                    self.network_client.security_rules.begin_create_or_update,
                    self.resource_group,
                    self.nsg_name,
                    rule_name,
                    rule_params,
                )
                poller.result()  # Wait for completion

                results["success"].append(ip)
                # Add a synthetic rule so subsequent IPs see updated state
                synthetic = type("Rule", (), {
                    "name": rule_name,
                    "priority": priority,
                })()
                rules.append(synthetic)

            except Exception as exc:
                logger.error(
                    "Failed to add NSG deny rule for %s: %s", ip, exc,
                )
                results["failed"].append({"ip": ip, "error": str(exc)})

        added = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk NSG add on '%s': %d added, %d skipped, %d failed",
            self.nsg_name, added, skipped, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Remove NSG inbound deny rules for each IP address.

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
            rules = self._get_existing_rules()
        except Exception as exc:
            logger.error("Failed to get NSG rules for '%s': %s",
                         self.nsg_name, exc)
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
                poller = self._api_call_with_retry(
                    self.network_client.security_rules.begin_delete,
                    self.resource_group,
                    self.nsg_name,
                    rule_name,
                )
                poller.result()  # Wait for completion

                results["success"].append(ip)
                rules.remove(existing)

            except Exception as exc:
                logger.error(
                    "Failed to remove NSG deny rule for %s: %s", ip, exc,
                )
                results["failed"].append({"ip": ip, "error": str(exc)})

        removed = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk NSG remove on '%s': %d removed, %d skipped, %d failed",
            self.nsg_name, removed, skipped, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify Azure API connectivity and NSG existence.

        Returns:
            True if the NSG can be retrieved, False otherwise.
        """
        try:
            self._get_nsg()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed NSG deny rules.

        Deletes every rule whose name starts with ``soc-block-``.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            rules = self._get_existing_rules()
            soc_rules = self._soc_managed_rules(rules)

            for rule in soc_rules:
                try:
                    poller = self._api_call_with_retry(
                        self.network_client.security_rules.begin_delete,
                        self.resource_group,
                        self.nsg_name,
                        rule.name,
                    )
                    poller.result()
                except Exception as exc:
                    logger.error(
                        "Failed to delete NSG rule '%s': %s",
                        rule.name, exc,
                    )
                    return False

            logger.info(
                "Cleaned up %d SOC-managed rules from NSG '%s'",
                len(soc_rules), self.nsg_name,
            )
            return True

        except Exception as exc:
            logger.error(
                "Failed to cleanup NSG '%s': %s", self.nsg_name, exc,
            )
            return False
