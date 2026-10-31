"""Scanner interface.

Every scanner takes some input (a list of domains, an AWS session, etc.)
and yields Asset objects. Keeping this interface tiny means adding a new
resource type (e.g. RDS snapshots, ECR repos) later is a single new file,
not a refactor.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from decay_tracker.models import Asset


class Scanner(ABC):
    name: str

    @abstractmethod
    def scan(self) -> Iterable[Asset]:
        """Yield Asset objects discovered by this scanner."""
        raise NotImplementedError
