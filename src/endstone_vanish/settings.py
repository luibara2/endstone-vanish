"""Configuration validation independent of Endstone."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class VanishSettings:
    admin_tag: str = "admin"
    sync_period_ticks: int = 20


def load_settings(config: object) -> tuple[VanishSettings, tuple[str, ...]]:
    """Validate a partial/malformed mapping and return defaults plus warnings."""

    warnings: list[str] = []
    if not isinstance(config, Mapping):
        return VanishSettings(), ("configuration root is not a table; using defaults",)

    admin_tag = config.get("admin_tag", "admin")
    if not isinstance(admin_tag, str) or not admin_tag.strip():
        warnings.append("admin_tag must be a non-empty string; using 'admin'")
        admin_tag = "admin"
    else:
        admin_tag = admin_tag.strip()

    period = config.get("sync_period_ticks", 20)
    if isinstance(period, bool) or not isinstance(period, int) or not 1 <= period <= 1200:
        warnings.append("sync_period_ticks must be an integer from 1 to 1200; using 20")
        period = 20

    return VanishSettings(admin_tag=admin_tag, sync_period_ticks=period), tuple(warnings)
