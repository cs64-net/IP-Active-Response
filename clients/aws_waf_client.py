"""AWS WAF device client for managing IP blocking via WAFv2 IP sets.

Uses boto3 WAFv2 client to add/remove IPs from WAF IP sets. Manages
separate IPv4 and IPv6 IP sets named ``{name}-ipv4`` and ``{name}-ipv6``.

Adding this client requires:
1. boto3 installed (``pip install boto3``)
2. Register the factory in CLIENT_REGISTRY in services/push_orchestrator.py
"""

import ipaddress
import logging
import time
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from clients.base_client import BaseDeviceClient

logger = logging.getLogger(__name__)

# AWS WAF IP set capacity limit (addresses per set)
IP_SET_CAPACITY = 10_000

# Retry configuration for API throttling
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2, 4]  # seconds


class AwsWafError(Exception):
    """Raised on AWS WAF API errors."""


class AwsWafClient(BaseDeviceClient):
    """Manage IP blocking via AWS WAFv2 IP sets.

    Maintains separate IPv4 (``IPAddressVersion='IPV4'``) and IPv6
    (``IPAddressVersion='IPV6'``) IP sets. IPs are stored as CIDR
    notation (``/32`` for IPv4, ``/128`` for IPv6).
    """

    def __init__(self, access_key: str, secret_key: str,
                 region: str, ip_set_name: str,
                 ip_set_scope: str = "REGIONAL",
                 ipv4_ip_set_name: str = "",
                 ipv6_ip_set_name: str = ""):
        """Initialise the AWS WAF client.

        Args:
            access_key: AWS Access Key ID.
            secret_key: AWS Secret Access Key.
            region: AWS region (e.g. ``us-east-1``).
            ip_set_name: Base name for the IP sets.
            ip_set_scope: ``REGIONAL`` or ``CLOUDFRONT``.
            ipv4_ip_set_name: Explicit IPv4 IP set name. When provided,
                overrides the auto-generated ``<ip_set_name>-ipv4`` name.
            ipv6_ip_set_name: Explicit IPv6 IP set name. When provided,
                overrides the auto-generated ``<ip_set_name>-ipv6`` name.
        """
        self.ip_set_name = ip_set_name
        self.ip_set_scope = ip_set_scope
        self.region = region
        self._ipv4_ip_set_name = ipv4_ip_set_name.strip() if ipv4_ip_set_name else ""
        self._ipv6_ip_set_name = ipv6_ip_set_name.strip() if ipv6_ip_set_name else ""
        self.wafv2 = boto3.client(
            "wafv2",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        # Cached IP set metadata: {version: {"id": ..., "lock_token": ...}}
        self._ip_set_cache: Dict[str, Dict] = {}
        logger.info(
            "AwsWafClient initialised for IP set '%s' (%s) in %s",
            ip_set_name, ip_set_scope, region,
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

    def _api_call_with_retry(self, func, **kwargs):
        """Execute an AWS API call with exponential backoff on throttling.

        Args:
            func: The boto3 method to call.
            **kwargs: Arguments forwarded to *func*.

        Returns:
            The API response.

        Raises:
            ClientError: If all retries are exhausted.
        """
        last_exc = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                return func(**kwargs)
            except ClientError as exc:
                error_code = exc.response["Error"]["Code"]
                if error_code in (
                    "WAFLimitsExceededException",
                    "WAFOptimisticLockException",
                    "Throttling",
                ):
                    last_exc = exc
                    if attempt < MAX_RETRIES:
                        delay = RETRY_DELAYS[attempt]
                        logger.warning(
                            "AWS WAF API throttled/conflict (attempt %d/%d), "
                            "retrying in %ds …",
                            attempt + 1, MAX_RETRIES, delay,
                        )
                        time.sleep(delay)
                        # Refresh lock token on optimistic lock conflict
                        if error_code == "WAFOptimisticLockException":
                            self._ip_set_cache.clear()
                        continue
                raise
        raise last_exc  # pragma: no cover

    def _ip_set_versioned_name(self, version: str) -> str:
        """Return the IP set name for a given address version.

        Uses the explicit IPv4/IPv6 name when provided, otherwise
        falls back to auto-generating from the base ``ip_set_name``.

        Args:
            version: ``IPV4`` or ``IPV6``.
        """
        if version == "IPV4" and self._ipv4_ip_set_name:
            return self._ipv4_ip_set_name
        if version == "IPV6" and self._ipv6_ip_set_name:
            return self._ipv6_ip_set_name
        suffix = "ipv4" if version == "IPV4" else "ipv6"
        return f"{self.ip_set_name}-{suffix}"

    def _find_ip_set(self, version: str) -> Optional[Dict]:
        """Find an existing IP set by name and version.

        Args:
            version: ``IPV4`` or ``IPV6``.

        Returns:
            Dict with ``Id`` and ``LockToken``, or None.
        """
        name = self._ip_set_versioned_name(version)
        try:
            resp = self._api_call_with_retry(
                self.wafv2.list_ip_sets,
                Scope=self.ip_set_scope,
            )
            for ip_set in resp.get("IPSets", []):
                if ip_set["Name"] == name:
                    return {"Id": ip_set["Id"], "LockToken": ip_set["LockToken"]}
        except Exception as exc:
            logger.error("Failed to list IP sets: %s", exc)
        return None

    def _get_or_create_ip_set(self, version: str) -> Dict:
        """Get or create the IP set for a given address version.

        Returns:
            Dict with ``Id``, ``LockToken``, and ``Addresses``.

        Raises:
            AwsWafError: If the IP set cannot be found or created.
        """
        if version in self._ip_set_cache:
            cached = self._ip_set_cache[version]
            try:
                resp = self._api_call_with_retry(
                    self.wafv2.get_ip_set,
                    Name=self._ip_set_versioned_name(version),
                    Scope=self.ip_set_scope,
                    Id=cached["id"],
                )
                ip_set = resp["IPSet"]
                lock_token = resp["LockToken"]
                self._ip_set_cache[version] = {
                    "id": ip_set["Id"],
                    "lock_token": lock_token,
                }
                return {
                    "Id": ip_set["Id"],
                    "LockToken": lock_token,
                    "Addresses": ip_set.get("Addresses", []),
                }
            except Exception:
                self._ip_set_cache.pop(version, None)

        # Try to find existing
        found = self._find_ip_set(version)
        if found:
            try:
                resp = self._api_call_with_retry(
                    self.wafv2.get_ip_set,
                    Name=self._ip_set_versioned_name(version),
                    Scope=self.ip_set_scope,
                    Id=found["Id"],
                )
                ip_set = resp["IPSet"]
                lock_token = resp["LockToken"]
                self._ip_set_cache[version] = {
                    "id": ip_set["Id"],
                    "lock_token": lock_token,
                }
                return {
                    "Id": ip_set["Id"],
                    "LockToken": lock_token,
                    "Addresses": ip_set.get("Addresses", []),
                }
            except Exception as exc:
                raise AwsWafError(
                    f"Failed to get IP set {self._ip_set_versioned_name(version)}: {exc}"
                ) from exc

        # Create new IP set
        name = self._ip_set_versioned_name(version)
        try:
            resp = self._api_call_with_retry(
                self.wafv2.create_ip_set,
                Name=name,
                Scope=self.ip_set_scope,
                IPAddressVersion=version,
                Addresses=[],
                Description=f"SOC IP Blocker managed {version} IP set",
            )
            summary = resp["Summary"]
            self._ip_set_cache[version] = {
                "id": summary["Id"],
                "lock_token": summary["LockToken"],
            }
            logger.info("Created WAF IP set '%s' (%s)", name, version)
            return {
                "Id": summary["Id"],
                "LockToken": summary["LockToken"],
                "Addresses": [],
            }
        except Exception as exc:
            raise AwsWafError(
                f"Failed to create IP set {name}: {exc}"
            ) from exc

    def _update_ip_set(self, version: str, ip_set_id: str,
                       lock_token: str, addresses: List[str]) -> str:
        """Update the IP set with a new address list.

        Returns:
            The new lock token.
        """
        resp = self._api_call_with_retry(
            self.wafv2.update_ip_set,
            Name=self._ip_set_versioned_name(version),
            Scope=self.ip_set_scope,
            Id=ip_set_id,
            Addresses=addresses,
            LockToken=lock_token,
            Description=f"SOC IP Blocker managed {version} IP set",
        )
        new_token = resp["NextLockToken"]
        self._ip_set_cache[version] = {
            "id": ip_set_id,
            "lock_token": new_token,
        }
        return new_token

    def _partition_ips(self, ip_addresses: List[str]) -> Tuple[List[str], List[str]]:
        """Split IPs into IPv4 and IPv6 lists (as CIDRs)."""
        ipv4, ipv6 = [], []
        for ip in ip_addresses:
            cidr = self._to_cidr(ip)
            if self._is_ipv6(ip):
                ipv6.append((ip, cidr))
            else:
                ipv4.append((ip, cidr))
        return ipv4, ipv6

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Add IPs to the WAF IP sets (separate IPv4/IPv6 sets).

        Skips IPs already present in the set. Respects the AWS WAF IP
        set capacity limit (10,000 addresses per set).

        Args:
            ip_addresses: List of IPv4/IPv6 addresses to block.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: Dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        ipv4_ips, ipv6_ips = self._partition_ips(ip_addresses)

        for version, ip_list in [("IPV4", ipv4_ips), ("IPV6", ipv6_ips)]:
            if not ip_list:
                continue

            try:
                ip_set_data = self._get_or_create_ip_set(version)
            except Exception as exc:
                logger.error("Failed to get/create %s IP set: %s", version, exc)
                for ip, _cidr in ip_list:
                    results["failed"].append({"ip": ip, "error": str(exc)})
                continue

            current_addresses = set(ip_set_data["Addresses"])
            new_addresses = list(ip_set_data["Addresses"])
            to_add = []

            for ip, cidr in ip_list:
                if cidr in current_addresses:
                    results["skipped"].append(ip)
                    continue

                current_count = len(new_addresses)
                if current_count >= IP_SET_CAPACITY:
                    logger.warning(
                        "WAF IP set '%s' capacity limit reached: %d/%d IPs",
                        self._ip_set_versioned_name(version),
                        current_count, IP_SET_CAPACITY,
                    )
                    results["failed"].append({
                        "ip": ip,
                        "error": f"Capacity limit reached: "
                                 f"{current_count}/{IP_SET_CAPACITY} IPs",
                    })
                    continue

                new_addresses.append(cidr)
                current_addresses.add(cidr)
                to_add.append(ip)

            if to_add:
                try:
                    self._update_ip_set(
                        version,
                        ip_set_data["Id"],
                        ip_set_data["LockToken"],
                        new_addresses,
                    )
                    results["success"].extend(to_add)
                except Exception as exc:
                    logger.error(
                        "Failed to update %s IP set: %s", version, exc,
                    )
                    for ip in to_add:
                        results["failed"].append({"ip": ip, "error": str(exc)})

        added = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk WAF add on '%s': %d added, %d skipped, %d failed",
            self.ip_set_name, added, skipped, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Remove IPs from the WAF IP sets.

        Skips IPs that are not present in the set.

        Args:
            ip_addresses: List of IPv4/IPv6 addresses to unblock.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: Dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        ipv4_ips, ipv6_ips = self._partition_ips(ip_addresses)

        for version, ip_list in [("IPV4", ipv4_ips), ("IPV6", ipv6_ips)]:
            if not ip_list:
                continue

            try:
                ip_set_data = self._get_or_create_ip_set(version)
            except Exception as exc:
                logger.error("Failed to get %s IP set: %s", version, exc)
                for ip, _cidr in ip_list:
                    results["failed"].append({"ip": ip, "error": str(exc)})
                continue

            current_addresses = set(ip_set_data["Addresses"])
            new_addresses = list(ip_set_data["Addresses"])
            to_remove = []

            for ip, cidr in ip_list:
                if cidr not in current_addresses:
                    results["skipped"].append(ip)
                    continue

                new_addresses.remove(cidr)
                current_addresses.discard(cidr)
                to_remove.append(ip)

            if to_remove:
                try:
                    self._update_ip_set(
                        version,
                        ip_set_data["Id"],
                        ip_set_data["LockToken"],
                        new_addresses,
                    )
                    results["success"].extend(to_remove)
                except Exception as exc:
                    logger.error(
                        "Failed to update %s IP set: %s", version, exc,
                    )
                    for ip in to_remove:
                        results["failed"].append({"ip": ip, "error": str(exc)})

        removed = len(results["success"])
        skipped = len(results["skipped"])
        failed = len(results["failed"])
        logger.info(
            "Bulk WAF remove on '%s': %d removed, %d skipped, %d failed",
            self.ip_set_name, removed, skipped, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify WAFv2 API connectivity and IP set accessibility.

        Attempts to list IP sets and, if existing sets are found,
        verifies they can be retrieved.

        Returns:
            True if the API is reachable and IP sets are accessible,
            False otherwise.
        """
        try:
            # Verify API connectivity by listing IP sets
            self._api_call_with_retry(
                self.wafv2.list_ip_sets,
                Scope=self.ip_set_scope,
            )
            # If we have cached sets, verify they're still accessible
            for version in ("IPV4", "IPV6"):
                found = self._find_ip_set(version)
                if found:
                    self._api_call_with_retry(
                        self.wafv2.get_ip_set,
                        Name=self._ip_set_versioned_name(version),
                        Scope=self.ip_set_scope,
                        Id=found["Id"],
                    )
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed IPs from the WAF IP sets.

        Empties both the IPv4 and IPv6 IP sets (does not delete the
        sets themselves).

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            for version in ("IPV4", "IPV6"):
                found = self._find_ip_set(version)
                if not found:
                    continue

                try:
                    resp = self._api_call_with_retry(
                        self.wafv2.get_ip_set,
                        Name=self._ip_set_versioned_name(version),
                        Scope=self.ip_set_scope,
                        Id=found["Id"],
                    )
                    ip_set = resp["IPSet"]
                    lock_token = resp["LockToken"]

                    if ip_set.get("Addresses"):
                        self._update_ip_set(
                            version, ip_set["Id"], lock_token, [],
                        )
                        logger.info(
                            "Cleaned up %d IPs from WAF IP set '%s'",
                            len(ip_set["Addresses"]),
                            self._ip_set_versioned_name(version),
                        )
                except Exception as exc:
                    logger.error(
                        "Failed to cleanup WAF IP set '%s': %s",
                        self._ip_set_versioned_name(version), exc,
                    )
                    return False

            return True

        except Exception as exc:
            logger.error(
                "Failed to cleanup WAF IP sets for '%s': %s",
                self.ip_set_name, exc,
            )
            return False
