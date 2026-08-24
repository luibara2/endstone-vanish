from __future__ import annotations

import unittest
import sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from endstone_vanish.settings import VanishSettings, load_settings
from endstone_vanish.state import PlayerIdentity, VanishRegistry


class SettingsTests(unittest.TestCase):
    def test_defaults_and_partial_configuration(self) -> None:
        settings, warnings = load_settings({})
        self.assertEqual(settings, VanishSettings())
        self.assertEqual(warnings, ())

        settings, warnings = load_settings({"admin_tag": " staff "})
        self.assertEqual(settings.admin_tag, "staff")
        self.assertEqual(settings.sync_period_ticks, 20)
        self.assertEqual(warnings, ())

    def test_malformed_configuration_uses_safe_defaults(self) -> None:
        settings, warnings = load_settings(
            {"admin_tag": [], "sync_period_ticks": True}
        )
        self.assertEqual(settings, VanishSettings())
        self.assertEqual(len(warnings), 2)

        settings, warnings = load_settings("not a table")
        self.assertEqual(settings, VanishSettings())
        self.assertEqual(len(warnings), 1)


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.uuid = UUID("00000000-0000-0001-0000-000000000002")
        self.identity = PlayerIdentity(self.uuid, "Steve", 7, 12)
        self.registry = VanishRegistry("staff")

    def test_state_transitions_and_duplicate_requests(self) -> None:
        self.assertTrue(self.registry.vanish(self.identity))
        self.assertFalse(self.registry.vanish(self.identity))
        self.assertTrue(self.registry.is_vanished(self.uuid))
        self.assertEqual(self.registry.unvanish(self.uuid), self.identity)
        self.assertIsNone(self.registry.unvanish(self.uuid))

    def test_only_tagged_or_vanished_viewers_are_authorized(self) -> None:
        other = UUID("00000000-0000-0000-0000-000000000099")
        self.registry.vanish(self.identity)
        self.assertTrue(self.registry.can_see_vanished(self.uuid, []))
        self.assertTrue(self.registry.can_see_vanished(other, ["staff"]))
        self.assertFalse(self.registry.can_see_vanished(other, ["admin"]))
        self.assertFalse(self.registry.can_see_vanished(other, None))

    def test_clear_returns_previous_sessions(self) -> None:
        self.registry.vanish(self.identity)
        self.assertEqual(self.registry.clear(), (self.identity,))
        self.assertEqual(self.registry.identities(), ())


if __name__ == "__main__":
    unittest.main()
