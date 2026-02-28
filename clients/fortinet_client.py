"""Fortinet FortiGate firewall client for managing IP blocks via SSH.

Uses Paramiko to connect via SSH and manages firewall address objects
and an address group containing blocked IPs. No enable mode is needed
on FortiGate — the CLI is available immediately after SSH authentication.
"""

import logging
import time

import paramiko

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
COMMAND_DELAY = 0.5
READ_TIMEOUT = 10


class FortinetError(Exception):
    """Custom exception for Fortinet client operations."""
    pass


class FortinetClient:
    """Client for managing IP blocks on Fortinet FortiGate firewalls via SSH.

    Operates in alias-only mode: creates and maintains firewall address
    objects and an address group. The administrator must manually reference
    the address group in firewall policies.

    Address objects are named with a ``SOC_`` prefix (e.g. ``SOC_10.0.0.1``)
    so they can be identified and cleaned up by the SOC IP Blocker.
    """

    def __init__(self, host: str, port: int, username: str,
                 password: str,
                 address_group_name: str = "SOC_BLOCKLIST"):
        """Initialize SSH connection parameters for FortiGate.

        Args:
            host: Hostname or IP of the FortiGate firewall.
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
        """Return the FortiGate address object name for an IP.

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
    def _ip_to_subnet(ip_str: str) -> str:
        """Convert an IP or CIDR string to FortiGate subnet notation.

        Examples:
            '10.0.0.1'      -> '10.0.0.1/32'
            '10.0.0.1/32'   -> '10.0.0.1/32'
            '10.0.3.0/24'   -> '10.0.3.0/24'

        Args:
            ip_str: IP address, optionally with CIDR prefix length.

        Returns:
            CIDR notation string suitable for FortiGate ``set subnet``.
        """
        if "/" in ip_str:
            return ip_str
        return f"{ip_str}/32"

    def _get_ssh_shell(self) -> tuple:
        """Create an SSH client and invoke an interactive shell.

        FortiGate does not require an enable step — the CLI is available
        immediately after SSH authentication.

        Returns:
            Tuple of (paramiko.SSHClient, paramiko.Channel).

        Raises:
            FortinetError: If the SSH connection fails.
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
            raise FortinetError(
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
        """Read from shell until a FortiGate CLI prompt is detected.

        FortiGate prompts typically end with ``$`` or ``#``.

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
                if stripped.endswith("$") or stripped.endswith("#") or stripped.endswith(")"):
                    break
            else:
                time.sleep(0.1)
        return output

    def _send_command(self, shell, command: str) -> str:
        """Send a command and read the output until the next prompt.

        Args:
            shell: Paramiko channel.
            command: CLI command to send.

        Returns:
            Command output.
        """
        shell.send(command + "\n")
        time.sleep(COMMAND_DELAY)
        output = self._read_until_prompt(shell)
        return output

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Create address objects and add them to the address group.

        For each IP, creates a firewall address object named ``SOC_<ip>``
        with subnet ``<ip>/32``, then appends it to the address group.
        Processes in batches.

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
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    try:
                        # Step 1: Create address objects for the batch
                        self._send_command(shell, "config firewall address")
                        created_ips = []
                        for ip in batch:
                            try:
                                obj_name = self._address_object_name(ip)
                                self._send_command(
                                    shell, f'edit "{obj_name}"'
                                )
                                output = self._send_command(
                                    shell, f"set subnet {self._ip_to_subnet(ip)}"
                                )
                                if "error" in output.lower() or "fail" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    created_ips.append(ip)
                                self._send_command(shell, "next")
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
                        self._send_command(shell, "end")

                        # Step 2: Add created objects to the address group
                        if created_ips:
                            self._send_command(
                                shell, "config firewall addrgrp"
                            )
                            self._send_command(
                                shell,
                                f'edit "{self.address_group_name}"'
                            )
                            for ip in created_ips:
                                try:
                                    obj_name = self._address_object_name(ip)
                                    output = self._send_command(
                                        shell,
                                        f'append member "{obj_name}"'
                                    )
                                    if "error" in output.lower() or "fail" in output.lower():
                                        results["failed"].append(
                                            {"ip": ip, "error": output.strip()}
                                        )
                                    else:
                                        results["success"].append(ip)
                                except Exception as e:
                                    results["failed"].append(
                                        {"ip": ip, "error": str(e)}
                                    )
                            self._send_command(shell, "end")
                    except Exception as e:
                        for ip in batch:
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
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
        """Remove address objects from the group and delete them.

        For each IP, removes the address object from the address group
        using ``unselect member``, then deletes the address object.
        Processes in batches.

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
                for i in range(0, len(ip_addresses), BATCH_SIZE):
                    batch = ip_addresses[i:i + BATCH_SIZE]
                    try:
                        # Step 1: Remove objects from the address group
                        self._send_command(
                            shell, "config firewall addrgrp"
                        )
                        self._send_command(
                            shell,
                            f'edit "{self.address_group_name}"'
                        )
                        removed_from_group = []
                        for ip in batch:
                            try:
                                obj_name = self._address_object_name(ip)
                                output = self._send_command(
                                    shell,
                                    f'unselect member "{obj_name}"'
                                )
                                if "error" in output.lower() or "fail" in output.lower():
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    removed_from_group.append(ip)
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
                        self._send_command(shell, "end")

                        # Step 2: Delete the address objects
                        if removed_from_group:
                            self._send_command(
                                shell, "config firewall address"
                            )
                            for ip in removed_from_group:
                                try:
                                    obj_name = self._address_object_name(ip)
                                    output = self._send_command(
                                        shell, f'delete "{obj_name}"'
                                    )
                                    if "error" in output.lower() or "fail" in output.lower():
                                        results["failed"].append(
                                            {"ip": ip, "error": output.strip()}
                                        )
                                    else:
                                        results["success"].append(ip)
                                except Exception as e:
                                    results["failed"].append(
                                        {"ip": ip, "error": str(e)}
                                    )
                            self._send_command(shell, "end")
                    except Exception as e:
                        for ip in batch:
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )
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
        """Verify SSH connectivity to the FortiGate.

        Connects via SSH and verifies the CLI prompt is available.
        FortiGate does not require enable mode.

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
        """Remove all SOC-managed address objects and the address group.

        Deletes the address group first, then removes all address objects
        with the ``SOC_`` prefix.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            try:
                # Delete the address group
                self._send_command(shell, "config firewall addrgrp")
                self._send_command(
                    shell, f'delete "{self.address_group_name}"'
                )
                self._send_command(shell, "end")

                # Delete all SOC_ address objects
                # List address objects and delete those with SOC_ prefix
                self._send_command(shell, "config firewall address")
                output = self._send_command(shell, "show")
                # Parse object names from show output
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("edit") and '"SOC_' in line:
                        # Extract the object name between quotes
                        parts = line.split('"')
                        if len(parts) >= 2:
                            obj_name = parts[1]
                            self._send_command(
                                shell, f'delete "{obj_name}"'
                            )
                self._send_command(shell, "end")

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
