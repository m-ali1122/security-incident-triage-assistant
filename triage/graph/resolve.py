"""P6: identity resolution chains and entity activity lookup."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Union

from triage.models import Event

Chain = Any  # resolution chain with Cite evidence per hop, defined by P6


def resolve(identifier: str, at_utc: Optional[Union[str, datetime]] = None) -> Chain:
    """Resolve an IP, hostname, FQDN, tag or username to its entity, as a chain of evidence."""
    raise NotImplementedError("P6")


def touched(entity: str, from_utc: Union[str, datetime], to_utc: Union[str, datetime]) -> list[Event]:
    """Events involving `entity` between from_utc and to_utc."""
    raise NotImplementedError("P6")
