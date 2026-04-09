"""
BaseExecutor — abstract contract voor alle response action executors.

Contract
--------
- `execute()` is de enige vereiste methode.
- Het mag NOOIT raisen. Catch alle exceptions intern en return
  een ActionResult met status="failed".
- Alle I/O moet async zijn.
- Elke executor is stateless en kan hergebruikt worden.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from ..schemas import ActionResult, ResponseEvent

logger = logging.getLogger(__name__)


class BaseExecutor(ABC):
    """Abstract base class voor alle response action executors."""

    @property
    @abstractmethod
    def action_type(self) -> str:
        """Machine-readable actie type slug, bijv. 'ip_block'."""
        ...

    @abstractmethod
    async def execute(self, event: ResponseEvent) -> ActionResult:
        """
        Voer de actie uit voor het gegeven event.

        Returns altijd een ActionResult — raised nooit.
        Bij fouten: status="failed" met error message.
        """
        ...

    async def is_available(self) -> bool:
        """Check of deze executor geconfigureerd en bereikbaar is."""
        return True
