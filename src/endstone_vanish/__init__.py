"""Endstone Vanish plugin."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .plugin import VanishPlugin

__all__ = ["VanishPlugin"]


def __getattr__(name: str) -> Any:
    if name != "VanishPlugin":
        raise AttributeError(name)
    from .plugin import VanishPlugin

    return VanishPlugin
