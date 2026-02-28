"""OCI NSG device client for managing IP blocking via Network Security Group rules.

Uses the OCI Python SDK ``VirtualNetworkClient`` to create/remove inbound deny
rules on an OCI NSG. SOC-managed rules are identified by the description tag
``SOC IP Blocker``.

Adding this client requires:
1. oci SDK installed (``pip install oci``)
2. Register the factory in CLIENT_REGISTRY in services/push_orchestrator.py
"""

import ipaddress
import logging
import time
from typing import Dict, List, Optional

import oci
from oci.exceptions import ServiceError, ConnectTimeout

from clients.base_client import BaseDeviceClient

logger = logging.getLogger(__name__)

# OCI NSG default security rule limit
DEFAULT_RULE_LIMIT = 200

# Description tag used to identify SOC-managed rules
SOC_DESCRIPTION = "SOC IP Blocker"

# Retry configuration for API throttling
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds


class OciNsgError(Exception):
    """Raised on OCI NSG API errors."""


class OciNsgClient(BaseDeviceClient):
    """Manage IP blocking via OCI Network Security Group security rules.

    Creates inbound deny-all rules for each blocked IP address. Rules are
    tagged with the description ``SOC IP Blocker`` for identification and
    cleanup. Supports both IPv4 and IPv6 addresses.
    """

    def __init__(self, tenancy_ocid: str, user_ocid: str,
                 api_key_pem: str, fingerprint: str,
                 region: str, nsg_ocid: str):
        """Initialise the OCI NSG client.

        Args:
            tenancy_ocid: OCI tenancy OCID.
            user_ocid: OCI user OCID.
            api_key_pem: PEM-encoded API signing key.
            fingerprint: Key fingerprint.
            region: OCI region (e.g. ``us-ashburn-1``).
            nsg_ocid: The Network Security Group OCID to manage.
        """
        self.nsg_ocid = nsg_ocid
        self.region = region

        config = {
            "tenancy": tenancy_ocid,
            "user": user_ocid,
            "key_content": api_key_pem,
            "fingerprint": fingerprint,
            "region": region,
        }
        self.vn_client = oci.core.VirtualNetworkClient(config)
        logger.info("OciNsgClient initialised for NSG %s in %s",
                     nsg_ocid, region)

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

    def _api_call_with_retry(self, func, *args, **kwargs):
        """Execute an OCI API call with exponential backoff on throttling.

        Args:
            func: The OCI SDK method to call.
            *args: Positional arguments forwarded to *func*.
            **kwargs: Keyword arguments forwarded to *func*.

        Returns:
            The API response.

        Raises:
            ServiceError: If all retries are exhausted.
        """
        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return func(*args, **kwargs)
            except ServiceError as exc:
                if exc.status == 429:
                    last_exc = exc
                    if attempt < MAX_RETRIES:
                        delay = RETRY_DELAYS[attempt]
                        logger.warning(
                            "OCI API throttled (attempt %d/%d), "
                            "retrying in %ds …",
                            attempt + 1, MAX_RETRIES, delay,
                        )
                        time.sleep(delay)
                        continue
                raise
        raise last_exc  # pragma: no cover

    def _get_nsg(self):
        """Fetch the NSG from OCI.

        Returns:
            The NSG response object.

        Raises:
            OciNsgError: If the NSG is not found.
        """
        try:
            response = self._api_call_with_retry(
                self.vn_client.get_network_security_group,
                self.nsg_ocid,
            )
            return response.data
        except ServiceError as exc:
            raise OciNsgError(
                f"NSG {self.nsg_ocid} not found: {exc}"
            ) from exc

    def _get_existing_rules(self) -> list:
        """Return the current security rules on the NSG."""
        response = self._api_call_with_retry(
            self.vn_client.list_network_security_group_security_rules,
            self.nsg_ocid,
        )
        return list(response.data or [])

    def _soc_managed_rules(self, rules: list) -> list:
        """Filter rules to only SOC-managed rules (by description tag)."""
        return [
            r for r in rules
            if getattr(r, "description", None)
            and SOC_DESCRIPTION in r.description
        ]

    def _find_rule_for_ip(self, rules: list, cidr: str, is_v6: bool) -> Optional[object]:
        """Find an existing SOC-managed inbound deny rule matching *cidr*."""
        for rule in rules:
            desc = getattr(rule, "description", None)
            if not desc or SOC_DESCRIPTION not in desc:
                continue
            direction = getattr(rule, "direction", None)
            if direction != "INGRESS":
                continue
            if is_v6:
                source = getattr(rule, "source", None)
                source_type = getattr(rule, "source_type", None)
                if source == cidr and source_type == "CIDR_BLOCK":
                    return rule
            else:
                source = getattr(rule, "source", None)
                source_type = getattr(rule, "source_type", None)
                if source == cidr and source_type == "CIDR_BLOCK":
                    return rule
        return None

    def _count_rules(self, rules: list) -> int:
        """Count total security rules on the NSG."""
        return len(rules)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Create NSG inbound deny rules for each IP address.

        Each rule is tagged with the description ``SOC IP Blocker`` for
        identification. Skips IPs that already have a deny rule. Respects
        the OCI NSG rule limit (200 rules by default).

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
            logger.error("Failed to list NSG rules for %s: %s",
                         self.nsg_ocid, exc)
            for ip in ip_addresses:
                results["failed"].append({"ip": ip, "error": str(exc)})
            return results

        for ip in ip_addresses:
            cidr = self._to_cidr(ip)
            is_v6 = self._is_ipv6(ip)

            # Skip already-blocked
            existing = self._find_rule_for_ip(rules, cidr, is_v6)
            if existing is not None:
                results["skipped"].append(ip)
                continue

            # Capacity check
            rule_count = self._count_rules(rules)
            if rule_count >= DEFAULT_RULE_LIMIT:
                logger.warning(
                    "NSG %s capacity limit reached: %d/%d rules",
                    self.nsg_ocid, rule_count, DEFAULT_RULE_LIMIT,
                )
                results["failed"].append({
                    "ip": ip,
                    "error": f"Capacity limit reached: "
                             f"{rule_count}/{DEFAULT_RULE_LIMIT} rules",
                })
                continue

            try:
                rule_details = oci.core.models.AddSecurityRuleDetails(
                    direction="INGRESS",
                    protocol="all",
                    source=cidr,
                    source_type="CIDR_BLOCK",
                    is_stateless=True,
                    description=f"{SOC_DESCRIPTION} - block {ip}",
                )

                add_details = oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                    security_rules=[rule_details],
                )

                self._api_call_with_retry(
                    self.vn_client.add_network_security_group_security_rules,
                    self.nsg_ocid,
                    add_details,
                )
                results["success"].append(ip)
                # Add a synthetic rule so subsequent IPs see updated state
                synthetic = type("Rule", (), {
                    "description": f"{SOC_DESCRIPTION} - block {ip}",
                    "direction": "INGRESS",
                    "source": cidr,
                    "source_type": "CIDR_BLOCK",
                    "id": f"synthetic-{ip}",
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
            "Bulk NSG add on %s: %d added, %d skipped, %d failed",
            self.nsg_ocid, added, skipped, failed,
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
            logger.error("Failed to list NSG rules for %s: %s",
                         self.nsg_ocid, exc)
            for ip in ip_addresses:
                results["failed"].append({"ip": ip, "error": str(exc)})
            return results

        for ip in ip_addresses:
            cidr = self._to_cidr(ip)
            is_v6 = self._is_ipv6(ip)

            existing = self._find_rule_for_ip(rules, cidr, is_v6)
            if existing is None:
                results["skipped"].append(ip)
                continue

            try:
                rule_id = getattr(existing, "id", None)
                if rule_id is None:
                    results["failed"].append({
                        "ip": ip,
                        "error": "Rule has no ID for removal",
                    })
                    continue

                remove_details = oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
                    security_rule_ids=[rule_id],
                )

                self._api_call_with_retry(
                    self.vn_client.remove_network_security_group_security_rules,
                    self.nsg_ocid,
                    remove_details,
                )
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
            "Bulk NSG remove on %s: %d removed, %d skipped, %d failed",
            self.nsg_ocid, removed, skipped, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify OCI API connectivity and NSG existence.

        Returns:
            True if the NSG can be retrieved, False otherwise.
        """
        try:
            self._get_nsg()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed deny rules from the NSG.

        Deletes every rule whose description contains ``SOC IP Blocker``.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            rules = self._get_existing_rules()
            soc_rules = self._soc_managed_rules(rules)

            if not soc_rules:
                logger.info("No SOC-managed rules to clean up on NSG %s",
                            self.nsg_ocid)
                return True

            rule_ids = [
                getattr(r, "id", None) for r in soc_rules
                if getattr(r, "id", None) is not None
            ]

            if not rule_ids:
                logger.warning(
                    "Found %d SOC-managed rules but none have IDs on NSG %s",
                    len(soc_rules), self.nsg_ocid,
                )
                return False

            # OCI supports batch removal by rule IDs
            remove_details = oci.core.models.RemoveNetworkSecurityGroupSecurityRulesDetails(
                security_rule_ids=rule_ids,
            )

            self._api_call_with_retry(
                self.vn_client.remove_network_security_group_security_rules,
                self.nsg_ocid,
                remove_details,
            )

            logger.info(
                "Cleaned up %d SOC-managed rules from NSG %s",
                len(rule_ids), self.nsg_ocid,
            )
            return True

        except Exception as exc:
            logger.error(
                "Failed to cleanup NSG %s: %s", self.nsg_ocid, exc,
            )
            return False
