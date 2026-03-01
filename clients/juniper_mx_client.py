"""Juniper MX router client for managing IP blocks via SSH.

Uses Paramiko to connect via SSH and manages prefix-list entries under
``policy-options`` (address_group mode) or static routes to ``discard``
(null_route mode) via the Junos CLI.

Junos requires entering ``cli`` from the shell, then ``configure`` to
enter configuration mode. All changes must be followed by a ``commit``.
"""

import logging
import time

import paramiko

from clients.base_client import BaseDeviceClient

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
MAX_PREFIX_LIST_ENTRIES = 200000
COMMAND_DELAY = 0.5
READ_TIMEOUT = 10
COMMIT_TIMEOUT = 60


class JuniperMxError(Exception):
    """Custom exception for Juniper MX client operations."""
    pass


class JuniperMxClient(BaseDeviceClient):
    """Client for managing IP blocks on Juniper MX routers via SSH.

    Supports two block methods:

    - ``address_group``: Creates prefix-list entries under
      ``policy-options`` with the configured group name. The
      administrator must reference the prefix-list in a Junos
      firewall filter.
    - ``null_route``: Creates static routes pointing blocked IPs to
      the ``discard`` next-hop.

    Unlike the SRX client, the MX prefix-list mode is simpler — IPs
    are added directly to the prefix-list without creating separate
    address objects.

    When the number of entries in a single prefix-list exceeds
    ``MAX_PREFIX_LIST_ENTRIES`` (200,000), entries are split across
    multiple prefix-lists with numeric suffixes.
    """

    def __init__(self, host: str, port: int, username: str,
                 password: str,
                 address_group_name: str = "SOC_BLOCKLIST",
                 block_method: str = "address_group"):
        """Initialize SSH connection parameters for Juniper MX.

        Args:
            host: Hostname or IP of the MX router.
            port: SSH port number.
            username: SSH username.
            password: SSH password.
            address_group_name: Name of the prefix-list or route tag
                (default: SOC_BLOCKLIST).
            block_method: ``'address_group'`` to manage prefix-list
                entries, or ``'null_route'`` to create discard routes.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.address_group_name = address_group_name
        self.block_method = block_method

    # ------------------------------------------------------------------
    # Naming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ip_to_cidr(ip_str: str) -> str:
        """Ensure an IP string has CIDR notation.

        Examples:
            '192.168.1.1'    -> '192.168.1.1/32'
            '10.0.3.0/24'    -> '10.0.3.0/24'

        Args:
            ip_str: IP address, optionally with CIDR prefix length.

        Returns:
            CIDR notation string.
        """
        if "/" in ip_str:
            return ip_str
        return f"{ip_str}/32"

    # ------------------------------------------------------------------
    # SSH / shell helpers
    # ------------------------------------------------------------------

    def _get_ssh_shell(self) -> tuple:
        """Create an SSH client, invoke an interactive shell, and enter
        Junos configuration mode (``cli`` then ``configure``).

        Returns:
            Tuple of (paramiko.SSHClient, paramiko.Channel).

        Raises:
            JuniperMxError: If the SSH connection fails.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception as e:
            raise JuniperMxError(
                f"SSH connection to {self.host}:{self.port} failed: {e}"
            ) from e

        shell = client.invoke_shell()
        shell.settimeout(READ_TIMEOUT)
        # Wait for initial prompt
        self._read_until_prompt(shell)
        # Enter CLI mode (in case we land in a shell)
        self._send_command(shell, "cli")
        # Enter configuration mode
        self._send_command(shell, "configure")
        return client, shell

    def _read_until_prompt(self, shell, timeout: float = READ_TIMEOUT) -> str:
        """Read from shell until a Junos CLI prompt is detected.

        Junos prompts typically end with ``>``, ``#``, or ``%``.

        Args:
            shell: Paramiko channel.
            timeout: Maximum seconds to wait.

        Returns:
            All output read from the shell.
        """
        output = ""
        end_time = time.time() + timeout
        while time.time() < end_time:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8", errors="replace")
                output += chunk
                stripped = output.rstrip()
                if (stripped.endswith(">") or stripped.endswith("#")
                        or stripped.endswith("%")):
                    break
            else:
                time.sleep(0.1)
        return output

    def _send_command(self, shell, command: str,
                      timeout: float = READ_TIMEOUT) -> str:
        """Send a command and read the output until the next prompt.

        Args:
            shell: Paramiko channel.
            command: CLI command to send.
            timeout: Maximum seconds to wait for prompt.

        Returns:
            Command output.
        """
        shell.send(command + "\n")
        time.sleep(COMMAND_DELAY)
        output = self._read_until_prompt(shell, timeout=timeout)
        return output

    def _commit(self, shell) -> str:
        """Issue a ``commit`` command on the Juniper MX.

        Uses a longer timeout since commits can take time.

        Args:
            shell: Paramiko channel in configuration mode.

        Returns:
            Commit command output.

        Raises:
            JuniperMxError: If the commit fails.
        """
        output = self._send_command(shell, "commit", timeout=COMMIT_TIMEOUT)
        lower = output.lower()
        if "error" in lower or "failed" in lower:
            raise JuniperMxError(
                f"Commit failed on {self.host}: {output.strip()}"
            )
        logger.info("Commit successful on %s", self.host)
        return output

    # ------------------------------------------------------------------
    # Group splitting helpers
    # ------------------------------------------------------------------

    def _prefix_list_name(self, index: int) -> str:
        """Return the prefix-list name for a given split index.

        Index 0 uses the base name; subsequent indices get a numeric
        suffix starting at 2.

        Args:
            index: Zero-based split index.

        Returns:
            Prefix-list name, e.g. ``SOC_BLOCKLIST`` or
            ``SOC_BLOCKLIST_2``.
        """
        if index == 0:
            return self.address_group_name
        return f"{self.address_group_name}_{index + 1}"

    # ------------------------------------------------------------------
    # add_rules_bulk
    # ------------------------------------------------------------------

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Create prefix-list entries / static routes and commit.

        In ``address_group`` mode, creates prefix-list entries under
        ``policy-options`` with the configured group name. When entries
        exceed ``MAX_PREFIX_LIST_ENTRIES``, splits across multiple
        prefix-lists with numeric suffixes.

        In ``null_route`` mode, creates static routes to ``discard``.

        Processes IPs in batches of ``BATCH_SIZE`` and issues a
        ``commit`` after each batch.

        Args:
            ip_addresses: List of IP addresses to block.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            client, shell = self._get_ssh_shell()
            try:
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    batch_success: list = []
                    try:
                        if self.block_method == "address_group":
                            self._add_batch_address_group(
                                shell, batch, batch_success, results,
                            )
                        else:
                            self._add_batch_null_route(
                                shell, batch, batch_success, results,
                            )

                        # Commit after each batch
                        if batch_success:
                            try:
                                self._commit(shell)
                                results["success"].extend(batch_success)
                            except JuniperMxError as ce:
                                for ip in batch_success:
                                    results["failed"].append(
                                        {"ip": ip, "error": str(ce)}
                                    )
                    except Exception as e:
                        for ip in batch:
                            if (ip not in results["success"]
                                    and ip not in [f["ip"] for f in results["failed"]]
                                    and ip not in results["skipped"]):
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
            finally:
                client.close()
        except Exception as e:
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

    def _add_batch_address_group(self, shell, batch: list,
                                  batch_success: list,
                                  results: dict) -> None:
        """Process a batch of IPs in address_group mode.

        Creates prefix-list entries directly — no separate address
        objects needed (unlike SRX address-set mode).  Splits across
        multiple prefix-lists when the limit is exceeded.
        """
        current_total = len(results["success"]) + len(batch_success)

        for ip in batch:
            try:
                cidr = self._ip_to_cidr(ip)

                # Determine which prefix-list to use (group splitting)
                list_index = current_total // MAX_PREFIX_LIST_ENTRIES
                list_name = self._prefix_list_name(list_index)

                # Add entry to prefix-list
                cmd = (
                    f"set policy-options prefix-list {list_name} {cidr}"
                )
                output = self._send_command(shell, cmd)
                if "error" in output.lower() or "invalid" in output.lower():
                    results["failed"].append(
                        {"ip": ip, "error": output.strip()}
                    )
                else:
                    batch_success.append(ip)
                    current_total += 1
            except Exception as e:
                results["failed"].append({"ip": ip, "error": str(e)})

    def _add_batch_null_route(self, shell, batch: list,
                               batch_success: list,
                               results: dict) -> None:
        """Process a batch of IPs in null_route mode.

        Creates static routes to ``discard`` for each IP.
        """
        for ip in batch:
            try:
                cidr = self._ip_to_cidr(ip)
                cmd = (
                    f"set routing-options static route {cidr} discard"
                )
                output = self._send_command(shell, cmd)
                if "error" in output.lower() or "invalid" in output.lower():
                    results["failed"].append(
                        {"ip": ip, "error": output.strip()}
                    )
                else:
                    batch_success.append(ip)
            except Exception as e:
                results["failed"].append({"ip": ip, "error": str(e)})

    # ------------------------------------------------------------------
    # remove_rules_bulk
    # ------------------------------------------------------------------

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove prefix-list entries / static routes and commit.

        In ``address_group`` mode, removes prefix-list entries.

        In ``null_route`` mode, deletes the static routes.

        Missing entries are skipped gracefully.

        Args:
            ip_addresses: List of IP addresses to unblock.

        Returns:
            Dict with ``success``, ``failed``, and ``skipped`` lists.
        """
        results: dict = {"success": [], "failed": [], "skipped": []}
        if not ip_addresses:
            return results

        try:
            client, shell = self._get_ssh_shell()
            try:
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    batch_success: list = []
                    try:
                        if self.block_method == "address_group":
                            self._remove_batch_address_group(
                                shell, batch, batch_success, results,
                            )
                        else:
                            self._remove_batch_null_route(
                                shell, batch, batch_success, results,
                            )

                        # Commit after each batch
                        if batch_success:
                            try:
                                self._commit(shell)
                                results["success"].extend(batch_success)
                            except JuniperMxError as ce:
                                for ip in batch_success:
                                    results["failed"].append(
                                        {"ip": ip, "error": str(ce)}
                                    )
                    except Exception as e:
                        for ip in batch:
                            if (ip not in results["success"]
                                    and ip not in [f["ip"] for f in results["failed"]]
                                    and ip not in results["skipped"]):
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
            finally:
                client.close()
        except Exception as e:
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

    def _remove_batch_address_group(self, shell, batch: list,
                                     batch_success: list,
                                     results: dict) -> None:
        """Process a batch of IP removals in address_group mode.

        Removes each IP from all possible prefix-lists (base name and
        numbered suffixes).  Missing entries are treated as skipped.
        """
        for ip in batch:
            try:
                cidr = self._ip_to_cidr(ip)
                found = False

                # Try to remove from the base prefix-list and numbered
                # variants.  Junos silently accepts deletes of
                # non-existent members, so we attempt the base name and
                # a few numbered suffixes.
                for idx in range(10):
                    list_name = self._prefix_list_name(idx)
                    cmd = (
                        f"delete policy-options prefix-list"
                        f" {list_name} {cidr}"
                    )
                    output = self._send_command(shell, cmd)
                    lower = output.lower()
                    if "error" in lower and "not found" not in lower:
                        results["failed"].append(
                            {"ip": ip, "error": output.strip()}
                        )
                        found = True
                        break
                    elif "not found" not in lower and "warning" not in lower:
                        found = True

                if not found:
                    results["skipped"].append(ip)
                elif ip not in [f["ip"] for f in results["failed"]]:
                    batch_success.append(ip)
            except Exception as e:
                results["failed"].append({"ip": ip, "error": str(e)})

    def _remove_batch_null_route(self, shell, batch: list,
                                  batch_success: list,
                                  results: dict) -> None:
        """Process a batch of IP removals in null_route mode.

        Deletes static routes.  Missing routes are treated as skipped.
        """
        for ip in batch:
            try:
                cidr = self._ip_to_cidr(ip)
                cmd = (
                    f"delete routing-options static route {cidr}"
                )
                output = self._send_command(shell, cmd)
                lower = output.lower()
                if "error" in lower and "not found" not in lower:
                    results["failed"].append(
                        {"ip": ip, "error": output.strip()}
                    )
                elif "not found" in lower or "warning" in lower:
                    results["skipped"].append(ip)
                else:
                    batch_success.append(ip)
            except Exception as e:
                results["failed"].append({"ip": ip, "error": str(e)})

    # ------------------------------------------------------------------
    # check_health
    # ------------------------------------------------------------------

    def check_health(self) -> bool:
        """Verify SSH connectivity to the Juniper MX.

        Connects via SSH, enters CLI mode, and runs ``show version``
        to confirm the device is responsive.

        Returns:
            True if the device responds, False otherwise.
        """
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            shell = ssh_client.invoke_shell()
            shell.settimeout(READ_TIMEOUT)
            self._read_until_prompt(shell)
            self._send_command(shell, "cli")
            output = self._send_command(shell, "show version")
            ssh_client.close()
            # If we got any output back, the device is healthy
            return len(output.strip()) > 0
        except Exception:
            return False

    # ------------------------------------------------------------------
    # cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> bool:
        """Remove all SOC-managed entries and commit.

        In ``address_group`` mode, deletes all managed prefix-lists.

        In ``null_route`` mode, deletes all managed static routes.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            try:
                if self.block_method == "address_group":
                    self._cleanup_address_group(shell)
                else:
                    self._cleanup_null_route(shell)

                # Commit after cleanup
                self._commit(shell)

                logger.info(
                    "Cleaned up SOC entries (%s mode) on %s",
                    self.block_method, self.host,
                )
                return True
            finally:
                client.close()
        except Exception as e:
            logger.error(
                "Failed to cleanup on %s: %s", self.host, e,
            )
            return False

    def _cleanup_address_group(self, shell) -> None:
        """Delete all managed prefix-lists.

        Lists prefix-lists under policy-options and deletes any that
        match the configured address_group_name (base and numbered
        suffixes).
        """
        output = self._send_command(
            shell,
            "show policy-options prefix-list",
        )
        for line in output.splitlines():
            stripped = line.strip()
            # Look for prefix-list names that match our pattern
            if self.address_group_name in stripped:
                tokens = stripped.split()
                for token in tokens:
                    if token.startswith(self.address_group_name):
                        list_name = token.rstrip("{;}")
                        self._send_command(
                            shell,
                            f"delete policy-options prefix-list"
                            f" {list_name}",
                        )
                        break

    def _cleanup_null_route(self, shell) -> None:
        """Delete all SOC-managed static routes.

        Identifies managed routes by listing static routes and looking
        for entries that correspond to IPs we would have created
        (routes to ``discard``).
        """
        output = self._send_command(
            shell, "show routing-options static",
        )
        for line in output.splitlines():
            stripped = line.strip()
            # Look for route lines containing 'discard'
            if "discard" in stripped.lower():
                tokens = stripped.split()
                for j, token in enumerate(tokens):
                    if token == "route" and j + 1 < len(tokens):
                        route = tokens[j + 1].rstrip(";")
                        self._send_command(
                            shell,
                            f"delete routing-options static route {route}",
                        )
                        break
