"""Cisco ASA firewall client for managing IP blocks via SSH.

Uses Paramiko to connect via SSH, enters privileged EXEC mode using the
enable password, and manages a named network object group with host entries
for blocked IPs.
"""

import ipaddress
import logging
import time

import paramiko

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
COMMAND_DELAY = 0.5
READ_TIMEOUT = 10


class CiscoASAError(Exception):
    """Custom exception for Cisco ASA client operations."""
    pass


class CiscoASAClient:
    """Client for managing IP blocks on Cisco ASA firewalls via SSH.

    Operates in alias-only mode: creates and maintains a named network
    object group with host entries for blocked IPs. The administrator
    must manually reference the object group in access rules.
    """

    def __init__(self, host: str, port: int, username: str,
                 password: str, enable_password: str,
                 object_group_name: str = "SOC_BLOCKLIST"):
        """Initialize SSH connection parameters for Cisco ASA.

        Args:
            host: Hostname or IP of the Cisco ASA firewall.
            port: SSH port number.
            username: SSH username.
            password: SSH password.
            enable_password: Password for privileged EXEC mode.
            object_group_name: Name of the object group to manage
                (default: SOC_BLOCKLIST).
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.object_group_name = object_group_name

    @staticmethod
    def _ip_to_network_object(ip_str: str) -> str:
        """Convert an IP or CIDR string to ASA network-object syntax.

        Examples:
            '10.0.0.1'      -> 'network-object host 10.0.0.1'
            '10.0.0.1/32'   -> 'network-object host 10.0.0.1'
            '10.0.3.0/24'   -> 'network-object 10.0.3.0 255.255.255.0'

        Args:
            ip_str: IP address, optionally with CIDR prefix length.

        Returns:
            Full ASA network-object command string.
        """
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            bare_ip = ip_str.split("/")[0]
            return f"network-object host {bare_ip}"

        if network.prefixlen == 32:
            return f"network-object host {network.network_address}"

        return f"network-object {network.network_address} {network.netmask}"

    def _get_ssh_shell(self) -> tuple:
        """Create an SSH client and invoke an interactive shell.

        Returns:
            Tuple of (paramiko.SSHClient, paramiko.Channel) in privileged
            EXEC mode.

        Raises:
            CiscoASAError: If connection or enable mode fails.
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
            raise CiscoASAError(
                f"SSH connection to {self.host}:{self.port} failed: {e}"
            ) from e

        shell = client.invoke_shell()
        shell.settimeout(READ_TIMEOUT)
        # Wait for initial prompt
        self._read_until_prompt(shell)

        # Enter privileged EXEC mode
        shell.send("enable\n")
        time.sleep(COMMAND_DELAY)
        output = self._read_available(shell)
        if "assword" in output:
            shell.send(self.enable_password + "\n")
            time.sleep(COMMAND_DELAY)
            output = self._read_available(shell)

        if "#" not in output:
            client.close()
            raise CiscoASAError(
                f"Failed to enter privileged EXEC mode on {self.host} "
                "— check enable password"
            )

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
        """Read from shell until a CLI prompt (> or #) is detected.

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
                if output.rstrip().endswith(">") or output.rstrip().endswith("#"):
                    break
            else:
                time.sleep(0.1)
        return output

    def _send_command(self, shell, command: str) -> str:
        """Send a command and read the output until the next prompt.

        Args:
            shell: Paramiko channel in privileged EXEC mode.
            command: CLI command to send.

        Returns:
            Command output (excluding the prompt line).
        """
        shell.send(command + "\n")
        time.sleep(COMMAND_DELAY)
        output = self._read_until_prompt(shell)
        return output

    def add_rules_bulk(self, ip_addresses: list) -> dict:
        """Add network object entries to the named object group.

        Enters config mode, then object group config mode, and adds a
        network-object host entry for each IP address. Processes in batches.

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
                        # Enter config mode and object group config
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"object-group network {self.object_group_name}"
                        )

                        for ip in batch:
                            try:
                                net_obj_cmd = self._ip_to_network_object(ip)
                                output = self._send_command(
                                    shell, net_obj_cmd
                                )
                                if "%" in output and "Invalid" in output:
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    results["success"].append(ip)
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                        # Exit object group config and config mode
                        self._send_command(shell, "exit")
                        self._send_command(shell, "exit")
                    except Exception as e:
                        for ip in batch:
                            if ip not in [r for r in results["success"]] and \
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
            "Bulk object group add on %s: %d added, %d failed",
            self.host, added, failed,
        )
        return results

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove network object entries from the named object group.

        Enters config mode, then object group config mode, and removes the
        network-object host entry for each IP address.

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
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"object-group network {self.object_group_name}"
                        )

                        for ip in batch:
                            try:
                                net_obj_cmd = self._ip_to_network_object(ip)
                                output = self._send_command(
                                    shell, f"no {net_obj_cmd}"
                                )
                                if "%" in output and "Invalid" in output:
                                    results["failed"].append(
                                        {"ip": ip, "error": output.strip()}
                                    )
                                else:
                                    results["success"].append(ip)
                            except Exception as e:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                        self._send_command(shell, "exit")
                        self._send_command(shell, "exit")
                    except Exception as e:
                        for ip in batch:
                            if ip not in [r for r in results["success"]] and \
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
            "Bulk object group remove on %s: %d removed, %d failed",
            self.host, removed, failed,
        )
        return results

    def check_health(self) -> bool:
        """Verify SSH connectivity and privileged EXEC access.

        Connects via SSH, enters enable mode, and verifies the prompt
        shows privileged EXEC (#).

        Returns:
            True if connection and enable mode succeed, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            client.close()
            return True
        except Exception:
            return False

    def cleanup(self) -> bool:
        """Remove all SOC-managed entries from the object group.

        Deletes the entire named network object group from the ASA
        configuration.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            try:
                self._send_command(shell, "configure terminal")
                self._send_command(
                    shell,
                    f"no object-group network {self.object_group_name}"
                )
                self._send_command(shell, "exit")
                logger.info(
                    "Cleaned up object group '%s' on %s",
                    self.object_group_name, self.host,
                )
                return True
            finally:
                client.close()
        except Exception as e:
            logger.error(
                "Failed to cleanup object group '%s' on %s: %s",
                self.object_group_name, self.host, e,
            )
            return False
