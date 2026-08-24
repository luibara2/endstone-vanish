"""Framework-independent vanish state and authorization rules."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class PlayerIdentity:
    """The protocol identifiers needed to remove one player from a client."""

    uuid: UUID
    name: str
    actor_id: int
    runtime_id: int


class VanishRegistry:
    """Session-scoped vanished-player identities."""

    def __init__(self, admin_tag: str = "admin") -> None:
        self.admin_tag = admin_tag
        self._vanished: dict[UUID, PlayerIdentity] = {}

    def vanish(self, identity: PlayerIdentity) -> bool:
        if identity.uuid in self._vanished:
            return False
        self._vanished[identity.uuid] = identity
        return True

    def unvanish(self, player_uuid: UUID) -> PlayerIdentity | None:
        return self._vanished.pop(player_uuid, None)

    def remove_session(self, player_uuid: UUID) -> PlayerIdentity | None:
        return self.unvanish(player_uuid)

    def is_vanished(self, player_uuid: UUID) -> bool:
        return player_uuid in self._vanished

    def can_see_vanished(self, player_uuid: UUID, scoreboard_tags: object) -> bool:
        if self.is_vanished(player_uuid):
            return True
        try:
            return self.admin_tag in scoreboard_tags  # type: ignore[operator]
        except TypeError:
            return False

    def identities(self) -> tuple[PlayerIdentity, ...]:
        return tuple(self._vanished.values())

    def uuids(self) -> frozenset[UUID]:
        return frozenset(self._vanished)

    def clear(self) -> tuple[PlayerIdentity, ...]:
        previous = self.identities()
        self._vanished.clear()
        return previous
