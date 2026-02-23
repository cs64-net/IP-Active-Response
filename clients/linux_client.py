"""Linux device client for managing IP blocks via SSH.

Uses paramiko to execute null route commands on remote Linux hosts.
"""

import io
import logging
import paramiko

logger = logging.getLogger(__name__)


class LinuxClientError(Exception):
    """Custom exception for Linux client operations."""
    pass


class LinuxClient:
    """Client for managing IP blocks on Linux devices via SSH."""

    def __init__(self, host: str, port: int, username: str,
                 password: str = None, key_path: str = None,
                 key_content: str = None, sudo_password: str = None):
        """Initialize SSH connection parameters.

        Args:
            host: Hostname or IP of the Linux device.
            port: SSH port number.
            username: SSH username.
            password: SSH password (optional if key_path/key_content provided).
            key_path: Path to SSH private key file (optional).
            key_content: SSH private key content as string (optional).
            sudo_password: Password for sudo commands (optional, defaults to ssh password).
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.key_content = key_content
        self.sudo_password = sudo_password or password

    def _get_ssh_client(self) -> paramiko.SSHClient:
        """Create and connect an SSH client.

        Returns:
            Connected paramiko.SSHClient instance.

        Raises:
            LinuxClientError: If connection fails.
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 10,
        }
        if self.key_content:
            # Try RSA, then Ed25519, then ECDSA
            pkey = None
            key_file = io.StringIO(self.key_content)
            for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                try:
                    key_file.seek(0)
                    pkey = key_class.from_private_key(key_file)
                    break
                except Exception:
                    continue
            if pkey is None:
                raise LinuxClientError("Unable to parse SSH key content as RSA, Ed25519, or ECDSA.")
            connect_kwargs["pkey"] = pkey
        elif self.key_path:
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password
        client.connect(**connect_kwargs)
        return client

    def _run_cmd(self, client: paramiko.SSHClient, cmd: str) -> tuple:
        """Run a command via SSH, using sudo if available.

        Tries the command with sudo first (piping the sudo password via stdin).
        If sudo_password is not set, runs without sudo.

        Args:
            client: Connected SSHClient.
            cmd: The command to execute.

        Returns:
            Tuple of (exit_status, stdout_text, stderr_text).
        """
        if self.sudo_password:
            full_cmd = f"sudo -S {cmd}"
            stdin, stdout, stderr = client.exec_command(full_cmd)
            stdin.write(self.sudo_password + "\n")
            stdin.flush()
        else:
            stdin, stdout, stderr = client.exec_command(cmd)

        exit_status = stdout.channel.recv_exit_status()
        out_text = stdout.read().decode().strip()
        err_text = stderr.read().decode().strip()
        # Filter out the sudo password prompt from stderr
        if err_text:
            lines = [l for l in err_text.splitlines() if not l.startswith("[sudo]") and "password for" not in l.lower()]
            err_text = "\n".join(lines).strip()
        return exit_status, out_text, err_text

    def _route_exists(self, client: paramiko.SSHClient, ip_address: str) -> bool:
        """Check if a blackhole route already exists for the given IP.

        Args:
            client: Connected SSHClient.
            ip_address: IP address to check.

        Returns:
            True if the blackhole route exists.
        """
        exit_status, out_text, _ = self._run_cmd(client, f"ip route show {ip_address}")
        return "blackhole" in out_text

    def add_null_route(self, ip_address: str) -> bool:
        """Add a blackhole route for the given IP via SSH.

        Checks if the route already exists first (idempotent).
        Uses sudo if a sudo password is configured.

        Args:
            ip_address: The IP address to block.

        Returns:
            True if the command succeeded or route already exists.

        Raises:
            LinuxClientError: If the SSH command fails.
        """
        try:
            client = self._get_ssh_client()
            try:
                # Check if route already exists
                if self._route_exists(client, ip_address):
                    logger.debug("Blackhole route for %s already exists on %s, skipping", ip_address, self.host)
                    return True

                exit_status, _, err_output = self._run_cmd(client, f"ip route add blackhole {ip_address}")
                if exit_status != 0 and err_output:
                    # "RTNETLINK answers: File exists" means route already there
                    if "File exists" in err_output:
                        logger.debug("Blackhole route for %s already exists on %s", ip_address, self.host)
                        return True
                    raise LinuxClientError(
                        f"Failed to add null route for {ip_address} on {self.host}: {err_output}"
                    )
                logger.info("Added null route for %s on %s", ip_address, self.host)
                return True
            finally:
                client.close()
        except LinuxClientError:
            raise
        except Exception as e:
            raise LinuxClientError(
                f"SSH error adding null route for {ip_address} on {self.host}: {e}"
            ) from e

    def remove_null_route(self, ip_address: str) -> bool:
        """Remove a blackhole route for the given IP via SSH.

        Checks if the route exists first. If not, returns True (idempotent).
        Uses sudo if a sudo password is configured.

        Args:
            ip_address: The IP address to unblock.

        Returns:
            True if the command succeeded or route didn't exist.

        Raises:
            LinuxClientError: If the SSH command fails.
        """
        try:
            client = self._get_ssh_client()
            try:
                # Check if route exists before trying to remove
                if not self._route_exists(client, ip_address):
                    logger.debug("No blackhole route for %s on %s, nothing to remove", ip_address, self.host)
                    return True

                exit_status, _, err_output = self._run_cmd(client, f"ip route del blackhole {ip_address}")
                if exit_status != 0 and err_output:
                    # "No such process" means route already gone
                    if "No such process" in err_output:
                        logger.debug("Blackhole route for %s already removed on %s", ip_address, self.host)
                        return True
                    raise LinuxClientError(
                        f"Failed to remove null route for {ip_address} on {self.host}: {err_output}"
                    )
                logger.info("Removed null route for %s on %s", ip_address, self.host)
                return True
            finally:
                client.close()
        except LinuxClientError:
            raise
        except Exception as e:
            raise LinuxClientError(
                f"SSH error removing null route for {ip_address} on {self.host}: {e}"
            ) from e

    def add_null_routes_bulk(self, ip_addresses: list) -> dict:
        """Add blackhole routes for multiple IPs in a single SSH session.

        Args:
            ip_addresses: List of IP addresses to block.

        Returns:
            Dict with 'success' (list of IPs added) and 'failed' (list of {ip, error} dicts).
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            client = self._get_ssh_client()
            try:
                for ip in ip_addresses:
                    try:
                        if self._route_exists(client, ip):
                            results["success"].append(ip)
                            continue
                        exit_status, _, err_output = self._run_cmd(client, f"ip route add blackhole {ip}")
                        if exit_status != 0 and err_output and "File exists" not in err_output:
                            results["failed"].append({"ip": ip, "error": err_output})
                        else:
                            results["success"].append(ip)
                    except Exception as e:
                        results["failed"].append({"ip": ip, "error": str(e)})
            finally:
                client.close()
        except Exception as e:
            # Connection failed — all IPs fail
            for ip in ip_addresses:
                if ip not in [r for r in results["success"]]:
                    results["failed"].append({"ip": ip, "error": str(e)})

        added = len(results["success"])
        failed = len(results["failed"])
        logger.info("Bulk add on %s: %d added, %d failed", self.host, added, failed)
        return results

    def remove_null_routes_bulk(self, ip_addresses: list) -> dict:
        """Remove blackhole routes for multiple IPs in a single SSH session.

        Args:
            ip_addresses: List of IP addresses to unblock.

        Returns:
            Dict with 'success' (list of IPs removed) and 'failed' (list of {ip, error} dicts).
        """
        results = {"success": [], "failed": []}
        if not ip_addresses:
            return results

        try:
            client = self._get_ssh_client()
            try:
                for ip in ip_addresses:
                    try:
                        if not self._route_exists(client, ip):
                            results["success"].append(ip)
                            continue
                        exit_status, _, err_output = self._run_cmd(client, f"ip route del blackhole {ip}")
                        if exit_status != 0 and err_output and "No such process" not in err_output:
                            results["failed"].append({"ip": ip, "error": err_output})
                        else:
                            results["success"].append(ip)
                    except Exception as e:
                        results["failed"].append({"ip": ip, "error": str(e)})
            finally:
                client.close()
        except Exception as e:
            for ip in ip_addresses:
                if ip not in [r for r in results["success"]]:
                    results["failed"].append({"ip": ip, "error": str(e)})

        removed = len(results["success"])
        failed = len(results["failed"])
        logger.info("Bulk remove on %s: %d removed, %d failed", self.host, removed, failed)
        return results

    def check_health(self) -> bool:
        """Check if SSH connection can be established.

        Returns:
            True if connection succeeds, False otherwise.
        """
        try:
            client = self._get_ssh_client()
            client.close()
            return True
        except Exception:
            return False
