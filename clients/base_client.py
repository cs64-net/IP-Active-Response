"""Base device client interface for vendor-extensible architecture.

Adding a new vendor (e.g., Cisco, Fortinet, Palo Alto) requires:
1. Create clients/<vendor>_client.py with a class inheriting BaseDeviceClient
2. Implement add_rules_bulk(), remove_rules_bulk(), and check_health()
3. Register the factory in CLIENT_REGISTRY in services/push_orchestrator.py
"""

from abc import ABC, abstractmethod
from typing import Dict, List


class BaseDeviceClient(ABC):
    """Abstract base class that all vendor device clients must implement.

    Return structures:
        add_rules_bulk / remove_rules_bulk -> Dict with keys:
            - "success": list of IPs that succeeded
            - "failed": list of IPs that failed
            - "skipped": list of IPs that were skipped (already present / absent)

        check_health -> bool: True if the device is reachable and responsive.
    """

    @abstractmethod
    def add_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Apply block rules for the given IPs."""
        ...

    @abstractmethod
    def remove_rules_bulk(self, ip_addresses: List[str]) -> Dict:
        """Remove block rules for the given IPs."""
        ...

    @abstractmethod
    def check_health(self) -> bool:
        """Return True if the device is reachable."""
        ...
