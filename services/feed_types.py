"""Data types for external blocklist feed operations."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FeedParseResult:
    """Result of fetching and parsing a blocklist feed."""
    ip_set: set[str]
    raw_line_count: int
    valid_count: int
    invalid_count: int = 0
    error: str | None = None


@dataclass
class DiffResult:
    """Result of computing the differential between previous and new IP sets."""
    ips_to_add: set[str]
    ips_to_remove: set[str]


@dataclass
class SyncResult:
    """Result of applying a differential sync to devices."""
    ips_added: int
    ips_removed: int
    duration_seconds: float
    operation_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class FeedFetchError(Exception):
    """Raised when an HTTP fetch of a blocklist feed fails."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code
