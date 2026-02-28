"""Cisco IOS router client for managing IP blocks via SSH.

Uses Paramiko to connect via SSH, enters privileged EXEC mode using the
enable password, and manages a named ACL with deny entries for blocked IPs.
"""

import ipaddress
import logging
import time

import paramiko

logger = logging.getLogger(__name__)

BATCH_SIZE = 200
COMMAND_DELAY = 0.5
READ_TIMEOUT = 10


class CiscoIOSError(Exception):
    """Custom exception for Cisco IOS client operations."""
    pass


class CiscoIOSClient:
    """Client for managing IP blocks on Cisco IOS routers via SSH.

    Operates in alias-only mode: creates and maintains a named ACL with
    deny entries for blocked IPs. The administrator must manually apply
    the ACL to an interface or policy.
    """

    def __init__(self, host: str, port: int, username: str,
                 password: str, enable_password: str,
                 acl_name: str = "SOC_BLOCKLIST"):
        """Initialize SSH connection parameters for Cisco IOS.

        Args:
            host: Hostname or IP of the Cisco IOS router.
            port: SSH port number.
            username: SSH username.
            password: SSH password.
            enable_password: Password for privileged EXEC mode.
            acl_name: Name of the ACL to manage (default: SOC_BLOCKLIST).
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.acl_name = acl_name

    @staticmethod
    def _is_ipv6(ip_str: str) -> bool:
        """Return True if *ip_str* is an IPv6 address or network."""
        try:
            return isinstance(
                ipaddress.ip_network(ip_str, strict=False),
                ipaddress.IPv6Network,
            )
        except ValueError:
            return ":" in ip_str

    @staticmethod
    def _ip_to_acl_entry(ip_str: str) -> str:
        """Convert an IP or CIDR string to IOS extended ACL deny syntax.

        IPv4 examples:
            '10.0.0.1'      -> 'deny ip host 10.0.0.1 any'
            '10.0.0.1/32'   -> 'deny ip host 10.0.0.1 any'
            '10.0.3.0/24'   -> 'deny ip 10.0.3.0 0.0.0.255 any'

        Args:
            ip_str: IPv4 address, optionally with CIDR prefix length.

        Returns:
            Full IOS ACL deny command string.
        """
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            bare_ip = ip_str.split("/")[0]
            return f"deny ip host {bare_ip} any"

        if network.prefixlen == 32:
            return f"deny ip host {network.network_address} any"

        wildcard = ipaddress.IPv4Address(int(network.hostmask))
        return f"deny ip {network.network_address} {wildcard} any"

    @staticmethod
    def _ipv6_to_acl_entry(ip_str: str) -> str:
        """Convert an IPv6 address/CIDR to IOS IPv6 ACL deny syntax.

        Examples:
            '2003::/64'         -> 'deny ipv6 2003::/64 any'
            '2001:db8::1'       -> 'deny ipv6 host 2001:db8::1 any'
            '2001:db8::1/128'   -> 'deny ipv6 host 2001:db8::1 any'

        Args:
            ip_str: IPv6 address, optionally with CIDR prefix length.

        Returns:
            Full IOS IPv6 ACL deny command string.
        """
        try:
            network = ipaddress.ip_network(ip_str, strict=False)
        except ValueError:
            bare_ip = ip_str.split("/")[0]
            return f"deny ipv6 host {bare_ip} any"

        if network.prefixlen == 128:
            return f"deny ipv6 host {network.network_address} any"

        return f"deny ipv6 {network} any"

    def _get_ssh_shell(self) -> tuple:
        """Create an SSH client and invoke an interactive shell.

        Returns:
            Tuple of (paramiko.SSHClient, paramiko.Channel) in privileged
            EXEC mode.

        Raises:
            CiscoIOSError: If connection or enable mode fails.
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
            raise CiscoIOSError(
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
            raise CiscoIOSError(
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
        """Add deny entries to the named ACL(s) for each IP.

        IPv4 addresses go into ``ip access-list extended {acl_name}``.
        IPv6 addresses go into ``ipv6 access-list {acl_name}_V6``.
        Processes in batches.

        Args:
            ip_addresses: List of IP addresses to block.

        Returns:
            Dict with 'success' and 'failed' lists.
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        ipv4_ips = [ip for ip in ip_addresses if not self._is_ipv6(ip)]
        ipv6_ips = [ip for ip in ip_addresses if self._is_ipv6(ip)]

        try:
            client, shell = self._get_ssh_shell()
            try:
                # --- IPv4 batches ---
                for i in range(0, len(ipv4_ips), BATCH_SIZE):
                    batch = ipv4_ips[i:i + BATCH_SIZE]
                    try:
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"ip access-list extended {self.acl_name}"
                        )
                        for ip in batch:
                            try:
                                acl_cmd = self._ip_to_acl_entry(ip)
                                output = self._send_command(shell, acl_cmd)
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
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                # --- IPv6 batches ---
                for i in range(0, len(ipv6_ips), BATCH_SIZE):
                    batch = ipv6_ips[i:i + BATCH_SIZE]
                    try:
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"ipv6 access-list {self.acl_name}_V6"
                        )
                        for ip in batch:
                            try:
                                acl_cmd = self._ipv6_to_acl_entry(ip)
                                output = self._send_command(shell, acl_cmd)
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
            "Bulk ACL add on %s: %d added, %d failed", self.host, added, failed
        )
        return results

    def remove_rules_bulk(self, ip_addresses: list) -> dict:
        """Remove deny entries from the named ACL(s) for each IP.

        IPv4 entries are removed from ``ip access-list extended {acl_name}``.
        IPv6 entries are removed from ``ipv6 access-list {acl_name}_V6``.

        Args:
            ip_addresses: List of IP addresses to unblock.

        Returns:
            Dict with 'success' and 'failed' lists.
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        ipv4_ips = [ip for ip in ip_addresses if not self._is_ipv6(ip)]
        ipv6_ips = [ip for ip in ip_addresses if self._is_ipv6(ip)]

        try:
            client, shell = self._get_ssh_shell()
            try:
                # --- IPv4 batches ---
                for i in range(0, len(ipv4_ips), BATCH_SIZE):
                    batch = ipv4_ips[i:i + BATCH_SIZE]
                    try:
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"ip access-list extended {self.acl_name}"
                        )
                        for ip in batch:
                            try:
                                acl_cmd = self._ip_to_acl_entry(ip)
                                output = self._send_command(
                                    shell, f"no {acl_cmd}"
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
                            if ip not in results["success"] and \
                               ip not in [f["ip"] for f in results["failed"]]:
                                results["failed"].append(
                                    {"ip": ip, "error": str(e)}
                                )

                # --- IPv6 batches ---
                for i in range(0, len(ipv6_ips), BATCH_SIZE):
                    batch = ipv6_ips[i:i + BATCH_SIZE]
                    try:
                        self._send_command(shell, "configure terminal")
                        self._send_command(
                            shell,
                            f"ipv6 access-list {self.acl_name}_V6"
                        )
                        for ip in batch:
                            try:
                                acl_cmd = self._ipv6_to_acl_entry(ip)
                                output = self._send_command(
                                    shell, f"no {acl_cmd}"
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
            "Bulk ACL remove on %s: %d removed, %d failed",
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
        """Remove all SOC-managed entries from the ACL(s).

        Deletes both the IPv4 extended ACL and the IPv6 ACL from the
        router configuration.

        Returns:
            True if cleanup succeeded, False otherwise.
        """
        try:
            client, shell = self._get_ssh_shell()
            try:
                self._send_command(shell, "configure terminal")
                self._send_command(
                    shell, f"no ip access-list extended {self.acl_name}"
                )
                self._send_command(
                    shell, f"no ipv6 access-list {self.acl_name}_V6"
                )
                self._send_command(shell, "exit")
                logger.info(
                    "Cleaned up ACL '%s' (v4+v6) on %s",
                    self.acl_name, self.host,
                )
                return True
            finally:
                client.close()
        except Exception as e:
            logger.error(
                "Failed to cleanup ACL '%s' on %s: %s",
                self.acl_name, self.host, e,
            )
            return False
