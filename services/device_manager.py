"""Device manager service for CRUD operations on managed devices."""

import json
import logging
import sqlite3
from typing import Dict, List, Optional

from database import get_db

logger = logging.getLogger(__name__)

CLOUD_DEVICE_TYPES = {"aws_waf", "azure_nsg", "gcp_firewall", "oci_nsg"}


class DeviceManager:
    """CRUD operations for managed pfSense and Linux devices."""

    def __init__(self, db_path=None):
        self.db_path = db_path

    def add_pfsense(self, hostname: str, username: str, password: str,
                    block_method: str, friendly_name: str = "") -> Dict:
        """Register a new pfSense firewall.

        Args:
            hostname: IP or hostname of the pfSense device.
            username: Web interface username.
            password: Web interface password.
            block_method: "null_route" or "floating_rule".
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If block_method is invalid.
        """
        if block_method not in ("null_route", "floating_rule"):
            raise ValueError(f"Invalid block_method: {block_method}. Must be 'null_route' or 'floating_rule'.")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'pfsense'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A pfSense device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, web_username, web_password, block_method, friendly_name)
                   VALUES (?, 'pfsense', ?, ?, ?, ?)""",
                (hostname, username, password, block_method, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_linux(self, hostname: str, port: int, username: str,
                  password: Optional[str] = None,
                  key_path: Optional[str] = None,
                  friendly_name: str = "",
                  ssh_key: str = "",
                  sudo_password: str = "") -> Dict:
        """Register a new Linux device. Block method is always null_route.

        Args:
            hostname: IP or hostname of the Linux device.
            port: SSH port.
            username: SSH username.
            password: SSH password (optional).
            key_path: Path to SSH private key (optional).
            friendly_name: User-friendly display name.
            ssh_key: SSH private key content (optional).
            sudo_password: Password for sudo commands (optional, defaults to ssh password).

        Returns:
            Dict with the new device data.
        """
        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'linux'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A Linux device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password, ssh_key_path, friendly_name, ssh_key, sudo_password)
                   VALUES (?, 'linux', 'null_route', ?, ?, ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, key_path, friendly_name, ssh_key, sudo_password),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_cisco_ios(self, hostname: str, port: int, username: str,
                      password: str, enable_password: str,
                      acl_name: str = "SOC_BLOCKLIST",
                      friendly_name: str = "") -> Dict:
        """Register a new Cisco IOS router device.

        Args:
            hostname: IP or hostname of the Cisco IOS device.
            port: SSH port.
            username: SSH username.
            password: SSH password.
            enable_password: Privileged EXEC mode password.
            acl_name: Name of the ACL to manage, defaults to SOC_BLOCKLIST.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        missing = []
        if not hostname or not str(hostname).strip():
            missing.append("hostname")
        if not username or not str(username).strip():
            missing.append("username")
        if not password or not str(password).strip():
            missing.append("password")
        if not enable_password or not str(enable_password).strip():
            missing.append("enable_password")
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'cisco_ios'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A cisco_ios device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password,
                    enable_password, group_name, friendly_name)
                   VALUES (?, 'cisco_ios', 'alias_only', ?, ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, enable_password, acl_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_cisco_asa(self, hostname: str, port: int, username: str,
                      password: str, enable_password: str,
                      object_group_name: str = "SOC_BLOCKLIST",
                      friendly_name: str = "") -> Dict:
        """Register a new Cisco ASA firewall device.

        Args:
            hostname: IP or hostname of the Cisco ASA device.
            port: SSH port.
            username: SSH username.
            password: SSH password.
            enable_password: Privileged EXEC mode password.
            object_group_name: Name of the object group to manage, defaults to SOC_BLOCKLIST.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        missing = []
        if not hostname or not str(hostname).strip():
            missing.append("hostname")
        if not username or not str(username).strip():
            missing.append("username")
        if not password or not str(password).strip():
            missing.append("password")
        if not enable_password or not str(enable_password).strip():
            missing.append("enable_password")
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'cisco_asa'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A cisco_asa device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password,
                    enable_password, group_name, friendly_name)
                   VALUES (?, 'cisco_asa', 'alias_only', ?, ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, enable_password, object_group_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_fortinet(self, hostname: str, port: int, username: str,
                     password: str,
                     address_group_name: str = "SOC_BLOCKLIST",
                     friendly_name: str = "") -> Dict:
        """Register a new Fortinet FortiGate firewall device.

        Args:
            hostname: IP or hostname of the Fortinet device.
            port: SSH port.
            username: SSH username.
            password: SSH password.
            address_group_name: Name of the address group to manage, defaults to SOC_BLOCKLIST.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        missing = []
        if not hostname or not str(hostname).strip():
            missing.append("hostname")
        if not username or not str(username).strip():
            missing.append("username")
        if not password or not str(password).strip():
            missing.append("password")
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'fortinet'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A fortinet device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password,
                    group_name, friendly_name)
                   VALUES (?, 'fortinet', 'alias_only', ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, address_group_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_palo_alto(self, hostname: str, port: int, username: str,
                      password: str,
                      address_group_name: str = "SOC_BLOCKLIST",
                      friendly_name: str = "") -> Dict:
        """Register a new Palo Alto Networks firewall device.

        Args:
            hostname: IP or hostname of the Palo Alto device.
            port: SSH port.
            username: SSH username.
            password: SSH password.
            address_group_name: Name of the address group to manage, defaults to SOC_BLOCKLIST.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        missing = []
        if not hostname or not str(hostname).strip():
            missing.append("hostname")
        if not username or not str(username).strip():
            missing.append("username")
        if not password or not str(password).strip():
            missing.append("password")
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'palo_alto'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A palo_alto device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_port, ssh_username, ssh_password,
                    group_name, friendly_name)
                   VALUES (?, 'palo_alto', 'alias_only', ?, ?, ?, ?, ?)""",
                (hostname, port, username, password, address_group_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)

    def add_unifi(self, hostname: str, api_port: int, username: str,
                  password: str,
                  network_list_name: str = "SOC_BLOCKLIST",
                  friendly_name: str = "") -> Dict:
        """Register a new UniFi firewall device.

        Args:
            hostname: IP or hostname of the UniFi controller.
            api_port: API port for the UniFi controller.
            username: API username (stored in ssh_username column).
            password: API password (stored in ssh_password column).
            network_list_name: Name of the Network List to manage, defaults to SOC_BLOCKLIST.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        missing = []
        if not hostname or not str(hostname).strip():
            missing.append("hostname")
        if not username or not str(username).strip():
            missing.append("username")
        if not password or not str(password).strip():
            missing.append("password")
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'unifi'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A unifi device with hostname '{hostname}' already exists.")

            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, ssh_username, ssh_password,
                    api_port, group_name, friendly_name)
                   VALUES (?, 'unifi', 'alias_only', ?, ?, ?, ?, ?)""",
                (hostname, username, password, api_port, network_list_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            return dict(row)



    def add_aws_waf(self, hostname: str, access_key: str, secret_key: str,
                    region: str, ip_set_name: str,
                    ip_set_scope: str = "REGIONAL",
                    friendly_name: str = "") -> Dict:
        """Register an AWS WAF IP-set cloud device (Alpha).

        Args:
            hostname: Friendly hostname / identifier.
            access_key: AWS access key.
            secret_key: AWS secret access key.
            region: AWS region.
            ip_set_name: Name of the WAF IP set.
            ip_set_scope: REGIONAL or CLOUDFRONT.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        required = {"hostname": hostname, "access_key": access_key,
                     "secret_key": secret_key, "region": region,
                     "ip_set_name": ip_set_name}
        missing = [k for k, v in required.items() if not v or not str(v).strip()]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'aws_waf'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"An aws_waf device with hostname '{hostname}' already exists.")

            creds = json.dumps({"access_key": access_key, "secret_key": secret_key,
                                "ip_set_scope": ip_set_scope})
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, cloud_credentials,
                    cloud_region, cloud_resource_id, friendly_name)
                   VALUES (?, 'aws_waf', 'cloud_api', ?, ?, ?, ?)""",
                (hostname, creds, region, ip_set_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            logger.info("Added aws_waf device '%s' — this device type is in Alpha status.", hostname)
            return dict(row)

    def add_azure_nsg(self, hostname: str, tenant_id: str, client_id: str,
                      client_secret: str, subscription_id: str,
                      resource_group: str, nsg_name: str,
                      friendly_name: str = "") -> Dict:
        """Register an Azure NSG cloud device (Alpha).

        Args:
            hostname: Friendly hostname / identifier.
            tenant_id: Azure AD tenant ID.
            client_id: Azure AD application (client) ID.
            client_secret: Azure AD client secret.
            subscription_id: Azure subscription ID.
            resource_group: Azure resource group name.
            nsg_name: Network Security Group name.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        required = {"hostname": hostname, "tenant_id": tenant_id,
                     "client_id": client_id, "client_secret": client_secret,
                     "subscription_id": subscription_id,
                     "resource_group": resource_group, "nsg_name": nsg_name}
        missing = [k for k, v in required.items() if not v or not str(v).strip()]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'azure_nsg'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"An azure_nsg device with hostname '{hostname}' already exists.")

            creds = json.dumps({"tenant_id": tenant_id, "client_id": client_id,
                                "client_secret": client_secret,
                                "subscription_id": subscription_id,
                                "resource_group": resource_group})
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, cloud_credentials,
                    cloud_region, cloud_resource_id, friendly_name)
                   VALUES (?, 'azure_nsg', 'cloud_api', ?, '', ?, ?)""",
                (hostname, creds, nsg_name, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            logger.info("Added azure_nsg device '%s' — this device type is in Alpha status.", hostname)
            return dict(row)

    def add_gcp_firewall(self, hostname: str, service_account_json: str,
                         project_id: str, network_name: str,
                         friendly_name: str = "") -> Dict:
        """Register a GCP Firewall cloud device (Alpha).

        Args:
            hostname: Friendly hostname / identifier.
            service_account_json: GCP service account JSON key string.
            project_id: GCP project ID.
            network_name: VPC network name.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        required = {"hostname": hostname,
                     "service_account_json": service_account_json,
                     "project_id": project_id, "network_name": network_name}
        missing = [k for k, v in required.items() if not v or not str(v).strip()]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'gcp_firewall'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"A gcp_firewall device with hostname '{hostname}' already exists.")

            creds = json.dumps({"service_account_json": service_account_json,
                                "network_name": network_name})
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, cloud_credentials,
                    cloud_region, cloud_resource_id, friendly_name)
                   VALUES (?, 'gcp_firewall', 'cloud_api', ?, '', ?, ?)""",
                (hostname, creds, project_id, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            logger.info("Added gcp_firewall device '%s' — this device type is in Alpha status.", hostname)
            return dict(row)

    def add_oci_nsg(self, hostname: str, tenancy_ocid: str, user_ocid: str,
                    api_key_pem: str, fingerprint: str, region: str,
                    nsg_ocid: str, friendly_name: str = "") -> Dict:
        """Register an OCI NSG cloud device (Alpha).

        Args:
            hostname: Friendly hostname / identifier.
            tenancy_ocid: OCI tenancy OCID.
            user_ocid: OCI user OCID.
            api_key_pem: PEM-encoded API signing key.
            fingerprint: Key fingerprint.
            region: OCI region.
            nsg_ocid: Network Security Group OCID.
            friendly_name: User-friendly display name.

        Returns:
            Dict with the new device data.

        Raises:
            ValueError: If required fields are missing or device already exists.
        """
        required = {"hostname": hostname, "tenancy_ocid": tenancy_ocid,
                     "user_ocid": user_ocid, "api_key_pem": api_key_pem,
                     "fingerprint": fingerprint, "region": region,
                     "nsg_ocid": nsg_ocid}
        missing = [k for k, v in required.items() if not v or not str(v).strip()]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

        with get_db(self.db_path) as conn:
            existing = conn.execute(
                "SELECT id FROM managed_devices WHERE hostname = ? AND device_type = 'oci_nsg'",
                (hostname,),
            ).fetchone()
            if existing:
                raise ValueError(f"An oci_nsg device with hostname '{hostname}' already exists.")

            creds = json.dumps({"tenancy_ocid": tenancy_ocid, "user_ocid": user_ocid,
                                "api_key_pem": api_key_pem, "fingerprint": fingerprint})
            conn.execute(
                """INSERT INTO managed_devices
                   (hostname, device_type, block_method, cloud_credentials,
                    cloud_region, cloud_resource_id, friendly_name)
                   VALUES (?, 'oci_nsg', 'cloud_api', ?, ?, ?, ?)""",
                (hostname, creds, region, nsg_ocid, friendly_name),
            )
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = last_insert_rowid()"
            ).fetchone()
            logger.info("Added oci_nsg device '%s' — this device type is in Alpha status.", hostname)
            return dict(row)

    def update_device(self, device_id: int, **kwargs) -> Dict:
        """Update device configuration fields.

        Args:
            device_id: ID of the device to update.
            **kwargs: Fields to update (e.g., hostname, block_method).

        Returns:
            Dict with the updated device data.

        Raises:
            ValueError: If device not found or no fields provided.
        """
        if not kwargs:
            raise ValueError("No fields provided to update.")

        allowed = {
            "hostname", "web_username", "web_password", "block_method",
            "ssh_port", "ssh_username", "ssh_password", "ssh_key_path",
            "friendly_name", "ssh_key", "sudo_password",
            "enable_password", "group_name", "api_port",
            "cloud_credentials", "cloud_region", "cloud_resource_id",
        }
        invalid = set(kwargs.keys()) - allowed
        if invalid:
            raise ValueError(f"Invalid fields: {invalid}")

        # Skip blank password fields on edit to preserve existing passwords
        password_fields = {"ssh_password", "web_password", "enable_password"}
        kwargs = {
            k: v for k, v in kwargs.items()
            if k not in password_fields or v != ""
        }

        if not kwargs:
            raise ValueError("No fields provided to update.")

        set_clause = ", ".join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [device_id]

        with get_db(self.db_path) as conn:
            cursor = conn.execute(
                f"UPDATE managed_devices SET {set_clause} WHERE id = ?",
                values,
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Device with id {device_id} not found.")

            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = ?", (device_id,)
            ).fetchone()
            return dict(row)

    def remove_device(self, device_id: int, cleanup: bool = True) -> Optional[Dict]:
        """Remove a device from the registry.

        Args:
            device_id: ID of the device to remove.
            cleanup: If True, return the device info without deleting so the
                caller (RulesEngine) can orchestrate rule cleanup first.
                For cloud devices with cleanup=True, the client's cleanup()
                method is invoked before returning.
                If False, delete the device record and all associated
                push_status records immediately.

        Returns:
            Device dict when cleanup=True (caller handles cleanup).
            None when cleanup=False (immediate deletion).

        Raises:
            ValueError: If device not found.
        """
        with get_db(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM managed_devices WHERE id = ?", (device_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Device with id {device_id} not found.")

            device = dict(row)

            if cleanup and device.get("device_type") in CLOUD_DEVICE_TYPES:
                try:
                    self._run_cloud_cleanup(device)
                except Exception:
                    logger.exception(
                        "Cloud cleanup failed for device %s (id=%s); proceeding with removal.",
                        device.get("hostname"), device_id,
                    )

            if cleanup:
                # Return device info; caller (RulesEngine) will handle
                # rule removal and delete the device after cleanup completes.
                return device

            # Immediate deletion — remove related rows then device record.
            conn.execute(
                "DELETE FROM operation_queue WHERE device_id = ?", (device_id,)
            )
            conn.execute(
                "DELETE FROM push_statuses WHERE device_id = ?", (device_id,)
            )
            conn.execute(
                "DELETE FROM managed_devices WHERE id = ?", (device_id,)
            )
            return None

    def _run_cloud_cleanup(self, device: dict) -> None:
        """Instantiate the appropriate cloud client and call cleanup().

        Errors are propagated to the caller for logging.
        """
        device_type = device.get("device_type", "")
        creds = json.loads(device.get("cloud_credentials", "{}"))

        if device_type == "aws_waf":
            from clients.aws_waf_client import AwsWafClient
            client = AwsWafClient(
                access_key=creds["access_key"],
                secret_key=creds["secret_key"],
                region=device["cloud_region"],
                ip_set_name=device["cloud_resource_id"],
                ip_set_scope=creds.get("ip_set_scope", "REGIONAL"),
            )
        elif device_type == "azure_nsg":
            from clients.azure_nsg_client import AzureNsgClient
            client = AzureNsgClient(
                tenant_id=creds["tenant_id"],
                client_id=creds["client_id"],
                client_secret=creds["client_secret"],
                subscription_id=creds["subscription_id"],
                resource_group=creds["resource_group"],
                nsg_name=device["cloud_resource_id"],
            )
        elif device_type == "gcp_firewall":
            from clients.gcp_firewall_client import GcpFirewallClient
            client = GcpFirewallClient(
                service_account_json=creds["service_account_json"],
                project_id=device["cloud_resource_id"],
                network_name=creds.get("network_name", "default"),
            )
        elif device_type == "oci_nsg":
            from clients.oci_nsg_client import OciNsgClient
            client = OciNsgClient(
                tenancy_ocid=creds["tenancy_ocid"],
                user_ocid=creds["user_ocid"],
                api_key_pem=creds["api_key_pem"],
                fingerprint=creds["fingerprint"],
                region=device["cloud_region"],
                nsg_ocid=device["cloud_resource_id"],
            )
        else:
            return

        client.cleanup()

    def get_all_devices(self) -> List[Dict]:
        """Return all registered devices.

        Returns:
            List of dicts with device data.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]

    def get_devices_by_type(self, device_type: str) -> List[Dict]:
        """Return devices filtered by type.

        Args:
            device_type: "pfsense" or "linux".

        Returns:
            List of dicts with device data.
        """
        with get_db(self.db_path) as conn:
            rows = conn.execute(
                "SELECT * FROM managed_devices WHERE device_type = ? ORDER BY id",
                (device_type,),
            ).fetchall()
            return [dict(r) for r in rows]
