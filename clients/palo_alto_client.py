"""Palo Alto Networks firewall client for managing IP blocks via SSH.

Uses Paramiko to connect via SSH and manages address objects and an
address group containing blocked IPs. Palo Alto requires an explicit
``commit`` command after configuration changes to apply them.
No enable mode is needed — the CLI is available after SSH authentication.
"""

import logging
import time

import paramiko

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
COMMAND_DELAY = 0.5
READ_TIMEOUT = 10
COMMIT_TIMEOUT = 60


class PaloAltoError(Exception):
    """Custom exception for Palo Alto client operations."""
    pass


class PaloAltoClient:
    """Client for managing IP blocks on Palo Alto firewalls via SSH.

    Operates in alias-only mode: creates and maintains address objects
    and an address group. The administrator must manually reference
    the address group in security policies.

    Address objects are named with a ``SOC_`` prefix (e.g. ``SOC_10.0.0.1``)
    so they can be identified and cleaned up by the SOC IP Blocker.

    All configuration changes are followed by an explicit ``commit``
    command as required by Palo Alto (Requirement 4.11).
    """

    def __init__(self, host: str, port: int, username: str,
                 password: str,
                 address_group_name: str = "SOC_BLOCKLIST"):
        """Initialize SSH connection parameters for Palo Alto.

        Args:
            host: Hostname or IP of the Palo Alto firewall.
            port: SSH port number.
            username: SSH username.
            password: SSH password.
            address_group_name: Name of the address group to manage
                (default: SOC_BLOCKLIST).
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.address_group_name = address_group_name

    @staticmethod
    def _address_object_name(ip: str) -> str:
        """Return the Palo Alto address object name for an IP.

        Strips CIDR suffix and replaces slashes for safe naming.

        Args:
            ip: The IP address, optionally with CIDR notation.

        Returns:
            Name string like ``SOC_10.0.0.1`` or ``SOC_10.0.3.0_24``.
        """
        if "/" in ip:
            parts = ip.split("/")
            if parts[1] == "32":
                return f"SOC_{parts[0]}"
            return f"SOC_{parts[0]}_{parts[1]}"
        return f"SOC_{ip}"

    @staticmethod
    def _ip_to_netmask(ip_str: str) -> str:
        """Convert an IP or CIDR string to Palo Alto ip-netmask notation.

        Examples:
            '10.0.0.1'      -> '10.0.0.1/32'
            '10.0.0.1/32'   -> '10.0.0.1/32'
            '10.0.3.0/24'   -> '10.0.3.0/24'

        Args:
            ip_str: IP address, optionally with CIDR prefix length.

        Returns:
            CIDR notation string suitable for Palo Alto ``ip-netmask``.
        """
        if "/" in ip_str:
            return ip_str
        return f"{ip_str}/32"

    def _get_ssh_shell(self) -> tuple:
        """Create an SSH client and invoke an interactive shell.

        Palo Alto does not require an enable step — the CLI is available
        immediately after SSH authentication. Prompts end with ``>`` or
        ``#``.

        Returns:
            Tuple of (paramiko.SSHClient, paramiko.Channel).

        Raises:
            PaloAltoError: If the SSH connection fails.
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
            raise PaloAltoError(
                f"SSH connection to {self.host}:{self.port} failed: {e}"
            ) from e

        shell = client.invoke_shell()
        shell.settimeout(READ_TIMEOUT)
        # Wait for initial prompt
        self._read_until_prompt(shell)
        return client, shell

    def _read_available(self, shell) -> str:
        """Read all currently available data from the shell channel.

        Args:
            shell: Paramiko channel.

        Returns:
            Decoded string of available output.
        """
        output = ""
        while shell.recv_ready():
            output += shell.recv(65535).decode("utf-8", errors="replace")
        return output

    def _read_until_prompt(self, shell, timeout: float = READ_TIMEOUT) -> str:
        """Read from shell until a Palo Alto CLI prompt is detected.

        Palo Alto prompts end with ``>`` (operational mode) or ``#``
        (configuration mode).

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
                if stripped.endswith(">") or stripped.endswith("#"):
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
        """Issue a commit command on the Palo Alto firewall.

        Commits use a longer timeout since they can take time to apply.

        Args:
            shell: Paramiko channel in configuration mode.

        Returns:
            Commit command output.

        Raises:
            PaloAltoError: If the commit fails.
        """
        output = self._send_command(shell, "commit", timeout=COMMIT_TIMEOUT)
        if "failed" in output.lower() or "error" in output.lower():
            raise PaloAltoError(
                f"Commit failed on {self.host}: {output.strip()}"
            )
        logger.info("Commit successful on %s", self.host)
        return output

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Create address objects, add to group, and commit.

        For each IP, creates an address object named ``SOC_<ip>`` with
        ip-netmask ``<ip>/32``, then adds it to the address group.
        Issues a ``commit`` after all changes are made.

        Args:
            ip_addresses: List of IP addresses to block.

        Returns:
            Dict with 'success' and 'failed' lists.
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            client, shell = self._get_ssh_shell()
            try:
                has_changes = False
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    try:
                        for ip in batch:
                            try:
                                obj_name = self._address_object_name(ip)
                                # Create address object
                                output = self._send_command(
                                    shell,
                                    f"set address {obj_name} ip-netmask {self._ip_to_netmask(ip)}"
                                )
                                if "error" in output.lower() or "invalid" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                    continue

                                # Add to address group
                                output = self._send_command(
                                    shell,
                                    f"set address-group {self.address_group_name} static {obj_name}"
                                )
                                if "error" in output.lower() or "invalid" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    results["success"].append(ip)
                                    has_changes = True
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
                    except Exception as e:
                        for ip in batch:
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                # Commit after all changes (Requirement 4.11)
                if has_changes:
                    self._commit(shell)
            finally:
                client.close()
        except Exception as e:
            processed = (
                set(results["success"])
                | {f["ip"] for f in results["failed"]}
            )
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        added = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk address group add on %s: %d added, %d failed",
            self.host, added, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove address objects from group, delete them, and commit.

        For each IP, removes the address object from the address group,
        then deletes the address object. Issues a ``commit`` after all
        changes are made.

        Args:
            ip_addresses: List of IP addresses to unblock.

        Returns:
            Dict with 'success' and 'failed' lists.
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            client, shell = self._get_ssh_shell()
            try:
                has_changes = False
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    try:
                        for ip in batch:
                            try:
                                obj_name = self._address_object_name(ip)
                                # Remove from address group
                                output = self._send_command(
                                    shell,
                                    f"delete address-group {self.address_group_name} static {obj_name}"
                                )
                                if "error" in output.lower() or "invalid" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                    continue

                                # Delete address object
                                output = self._send_command(
                                    shell,
                                    f"delete address {obj_name}"
                                )
                                if "error" in output.lower() or "invalid" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    results["success"].append(ip)
                                    has_changes = True
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
                    except Exception as e:
                        for ip in batch:
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                # Commit after all changes (Requirement 4.11)
                if has_changes:
                    self._commit(shell)
            finally:
                client.close()
        except Exception as e:
            processed = (
                set(results["success"])
                | {f["ip"] for f in results["failed"]}
            )
            for ip in ip_addresses:
                if ip not in processed:
                    results["failed"].append({"ip": ip, "error": str(e)})

        removed = len(results["success"])
        failed = len(results["failed"])
        logger.info(
            "Bulk address group remove on %s: %d removed, %d failed",
            self.host, removed, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify SSH connectivity to the Palo Alto firewall.

        Connects via SSH and verifies the CLI prompt is available.
        Palo Alto does not require enable mode.

        Returns:
            True if SSH connection succeeds, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            client.close()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed address objects, the group, and commit.

        Deletes the address group first, then removes all address objects
        with the ``SOC_`` prefix. Issues a ``commit`` after cleanup.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            try:
                # Delete the address group
                self._send_command(
                    shell,
                    f"delete address-group {self.address_group_name}"
                )

                # Delete all SOC_ address objects
                # Use 'show address' to list objects and delete SOC_ prefixed ones
                output = self._send_command(shell, "show address")
                for line in output.splitlines():
                    line = line.strip()
                    if "SOC_" in line:
                        # Extract the object name (first token containing SOC_)
                        for token in line.split():
                            if token.startswith("SOC_"):
                                obj_name = token.rstrip(";")
                                self._send_command(
                                    shell, f"delete address {obj_name}"
                                )
                                break

                # Commit after cleanup (Requirement 4.11)
                self._commit(shell)

                logger.info(
                    "Cleaned up address group '%s' and SOC_ objects on %s",
                    self.address_group_name, self.host,
                )
                return True
            finally:
                client.close()
        except Exception as e:
            logger.error(
                "Failed to cleanup address group '%s' on %s: %s",
                self.address_group_name, self.host, e,
            )
            return False
