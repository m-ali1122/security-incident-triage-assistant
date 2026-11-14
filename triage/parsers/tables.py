"""P2: typed loaders for the Markdown tables (02, 03, 04, 05, 06-10, 17, 18)."""
from __future__ import annotations

from typing import Any


def load_inventory() -> Any:
    """Asset inventory (file 02)."""
    raise NotImplementedError("P2")


def load_matrix() -> Any:
    """Severity matrix (file 03): lookup by incident type and asset criticality."""
    raise NotImplementedError("P2")


def load_escalation() -> Any:
    """Escalation sheet (file 04)."""
    raise NotImplementedError("P2")


def load_changes() -> Any:
    """Change calendar (file 05) with windows converted from PKT to UTC."""
    raise NotImplementedError("P2")


def load_runbooks() -> Any:
    """Runbooks (files 06 to 10) with numbered steps."""
    raise NotImplementedError("P2")


def load_alerts() -> Any:
    """IDS alerts (file 17)."""
    raise NotImplementedError("P2")


def load_users() -> Any:
    """User directory (file 18)."""
    raise NotImplementedError("P2")
