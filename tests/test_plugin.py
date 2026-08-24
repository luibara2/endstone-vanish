"""Adapter tests using a small, explicit Endstone surface stub."""

from __future__ import annotations

import importlib
import inspect
import sys
import types
import unittest
from pathlib import Path
from uuid import UUID

SOURCE_ROOT = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))


class CommandSender:
    def __init__(self) -> None:
        self.messages: list[object] = []

    def send_message(self, message: object) -> None:
        self.messages.append(message)


class Player(CommandSender):
    pass


class Command:
    def __init__(self, name: str) -> None:
        self.name = name


class EventPriority:
    HIGHEST = 4


def event_handler(function=None, **_kwargs):
    if function is not None:
        return function
    return lambda decorated: decorated


class Plugin:
    def __init__(self) -> None:
        self.registered = []
        self.saved_default_config = False

    def register_events(self, listener) -> None:
        self.registered.append(listener)

    def save_default_config(self) -> None:
        self.saved_default_config = True


def _install_endstone_stubs() -> None:
    endstone = types.ModuleType("endstone")
    endstone.Player = Player

    command = types.ModuleType("endstone.command")
    command.Command = Command
    command.CommandSender = CommandSender

    event = types.ModuleType("endstone.event")
    event.EventPriority = EventPriority
    event.event_handler = event_handler
    for name in (
        "PacketSendEvent",
        "PlayerChatEvent",
        "PlayerCommandEvent",
        "PlayerDeathEvent",
        "PlayerJoinEvent",
        "PlayerQuitEvent",
        "PlayerSkinChangeEvent",
        "ServerListPingEvent",
    ):
        setattr(event, name, type(name, (), {}))

    plugin = types.ModuleType("endstone.plugin")
    plugin.Plugin = Plugin

    endstone.command = command
    endstone.event = event
    endstone.plugin = plugin
    sys.modules["endstone"] = endstone
    sys.modules["endstone.command"] = command
    sys.modules["endstone.event"] = event
    sys.modules["endstone.plugin"] = plugin


_install_endstone_stubs()
VanishPlugin = importlib.import_module("endstone_vanish.plugin").VanishPlugin
protocol = importlib.import_module("endstone_vanish.protocol")
PlayerIdentity = importlib.import_module("endstone_vanish.state").PlayerIdentity


class FakeLogger:
    def __init__(self) -> None:
        self.infos: list[str] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def info(self, message: str) -> None:
        self.infos.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)


class FakeTask:
    def __init__(self, callback, delay: int, period: int) -> None:
        self.callback = callback
        self.delay = delay
        self.period = period


class FakeScheduler:
    def __init__(self) -> None:
        self.tasks: list[FakeTask] = []
        self.cancelled_plugins: list[object] = []

    def run_task(self, _plugin, callback, delay=0, period=0) -> FakeTask:
        task = FakeTask(callback, delay, period)
        self.tasks.append(task)
        return task

    def cancel_tasks(self, plugin) -> None:
        self.cancelled_plugins.append(plugin)


class FakeServer:
    def __init__(self, players: list[Player], protocol_version: int = 2168) -> None:
        self.online_players = players
        self.protocol_version = protocol_version
        self.max_players = 20
        self.scheduler = FakeScheduler()


class FakePlayer(Player):
    def __init__(
        self,
        name: str,
        player_uuid: str,
        actor_id: int,
        runtime_id: int,
        tags: tuple[str, ...] = (),
    ) -> None:
        super().__init__()
        self.name = name
        self.unique_id = UUID(player_uuid)
        self.id = actor_id
        self.runtime_id = runtime_id
        self.scoreboard_tags = list(tags)
        self.packets: list[tuple[int, bytes]] = []

    def send_packet(self, packet_id: int, payload: bytes) -> None:
        self.packets.append((packet_id, payload))


class FakeEvent:
    def __init__(self, **values) -> None:
        self.__dict__.update(values)
        self.is_cancelled = False

    def cancel(self) -> None:
        self.is_cancelled = True


SUBJECT_UUID = "00000000-0000-0001-0000-000000000002"
NORMAL_UUID = "00000000-0000-0000-0000-000000000010"
ADMIN_UUID = "00000000-0000-0000-0000-000000000011"
OTHER_UUID = "00000000-0000-0000-0000-000000000012"


class _LocatorGroups(dict):
    """A stable group handle per actor id, for any actor a test invents."""

    def __missing__(self, actor_id: int) -> UUID:
        group = UUID(int=0xA0 + actor_id)
        self[actor_id] = group
        return group


LOCATOR_GROUP_FOR = _LocatorGroups()


class VanishPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.subject = FakePlayer("Steve", SUBJECT_UUID, 7, 12)
        self.normal = FakePlayer("Alex", NORMAL_UUID, 8, 13)
        self.admin = FakePlayer("Admin", ADMIN_UUID, 9, 14, ("admin",))
        self.server = FakeServer([self.subject, self.normal, self.admin])
        self.plugin = VanishPlugin()
        self.plugin.server = self.server
        self.plugin.config = {}
        self.plugin.logger = FakeLogger()
        self.plugin.on_enable()

    def seed(self, player: FakePlayer) -> None:
        self.plugin._cache.add_player[player.unique_id] = b"server-add-player"
        self.plugin._cache.player_list_add[player.unique_id] = b"server-list-entry"
        # The locator marker is waypoint-driven, and the group handle is only ever
        # learned from a server packet - so seed one, or the removal cannot be sent.
        self.plugin._cache.locator_group[player.id] = LOCATOR_GROUP_FOR[player.id]
        self.plugin._cache.locator_add[LOCATOR_GROUP_FOR[player.id]] = b"waypoint"

    def enter(self, player: FakePlayer | None = None) -> None:
        target = player or self.subject
        self.seed(target)
        self.assertTrue(self.plugin.on_command(target, Command("vanish"), []))

    def test_metadata_permission_and_enable_lifecycle(self) -> None:
        self.assertEqual(VanishPlugin.api_version, "0.11")
        self.assertEqual(VanishPlugin.permissions["vanish.command"]["default"], "op")
        self.assertEqual(
            VanishPlugin.commands["vanish"]["permissions"], ["vanish.command"]
        )
        self.assertEqual(self.plugin.registered, [self.plugin])
        self.assertTrue(self.plugin.saved_default_config)
        task = self.server.scheduler.tasks[0]
        self.assertEqual((task.delay, task.period), (20, 20))
        for handler_name in (
            "on_packet_send",
            "on_player_chat",
            "on_player_command",
            "on_player_join",
            "on_player_quit",
            "on_player_death",
            "on_player_skin_change",
            "on_server_list_ping",
        ):
            parameter = next(iter(inspect.signature(getattr(self.plugin, handler_name)).parameters.values()))
            self.assertTrue(inspect.isclass(parameter.annotation), handler_name)

    def test_unsupported_protocol_refuses_before_registering(self) -> None:
        plugin = VanishPlugin()
        plugin.server = FakeServer([], protocol_version=9999)
        plugin.config = {}
        plugin.logger = FakeLogger()
        with self.assertRaisesRegex(RuntimeError, "refuses to enable"):
            plugin.on_enable()
        self.assertEqual(plugin.registered, [])

    def test_malformed_config_warns_and_uses_defaults(self) -> None:
        plugin = VanishPlugin()
        plugin.server = FakeServer([])
        plugin.config = {"admin_tag": [], "sync_period_ticks": 0}
        plugin.logger = FakeLogger()
        plugin.on_enable()
        self.assertEqual(plugin._registry.admin_tag, "admin")
        self.assertEqual(len(plugin.logger.warnings), 2)
        self.assertEqual(plugin.server.scheduler.tasks[0].period, 20)

    def test_command_rejects_console_and_arguments_but_not_missing_cache(self) -> None:
        console = CommandSender()
        self.assertTrue(self.plugin.on_command(console, Command("vanish"), []))
        self.assertIn("Only an in-game player", str(console.messages[-1]))

        self.assertFalse(
            self.plugin.on_command(self.subject, Command("vanish"), ["unexpected"])
        )
        self.assertEqual(self.subject.messages[-1], "Usage: /vanish")

        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.assertTrue(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertTrue(self.plugin._cache.ready(self.subject.unique_id))
        # No seed() in this test, so no LocatorBar waypoint was ever seen for this
        # player. A group handle is only ever learned from the server, so the
        # removal is omitted rather than addressed to an invented handle.
        self.assertEqual([item[0] for item in self.normal.packets], [14, 63])
        self.assertEqual(self.subject.messages[-1], "You are now vanished.")

    def test_solo_player_can_vanish_and_unvanish_without_packet_cache(self) -> None:
        self.server.online_players = [self.subject]

        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.assertTrue(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertTrue(self.plugin._cache.ready(self.subject.unique_id))
        self.assertEqual(self.subject.packets, [])

        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.assertFalse(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertEqual(self.subject.packets, [])
        self.assertEqual(self.subject.messages[-1], "You are visible again.")

    def test_fallback_restore_reveals_player_to_regular_viewer(self) -> None:
        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.normal.packets.clear()

        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.assertEqual([item[0] for item in self.normal.packets], [63, 12, 326])
        self.assertEqual(
            protocol.parse_add_player_header(self.normal.packets[1][1]),
            (self.subject.unique_id, self.subject.name, self.subject.runtime_id),
        )

    def test_vanish_hides_only_from_regular_viewers(self) -> None:
        self.enter()
        self.assertTrue(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertEqual([item[0] for item in self.normal.packets], [341, 14, 63])
        self.assertEqual(self.admin.packets, [])
        self.assertEqual(self.subject.messages[-1], "You are now vanished.")

    def test_unvanish_replays_server_packets_only_to_hidden_viewers(self) -> None:
        self.enter()
        self.normal.packets.clear()
        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        self.assertFalse(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertEqual([item[0] for item in self.normal.packets], [63, 12, 326, 341])
        self.assertEqual(self.admin.packets, [])
        self.assertEqual(self.subject.messages[-1], "You are visible again.")

    def test_vanished_players_can_see_each_other(self) -> None:
        other = FakePlayer("Ghost", OTHER_UUID, 20, 30)
        self.server.online_players.append(other)
        self.seed(other)
        self.plugin._cache.ensure_fallback(
            self.plugin._identity(other), self.plugin._replay_profile(other)
        )
        self.plugin._registry.vanish(self.plugin._identity(other))
        self.enter()
        self.assertEqual([item[0] for item in self.subject.packets], [63, 12, 326, 341])
        self.assertNotIn(14, [item[0] for item in other.packets])

    def test_packet_firewall_and_malformed_fail_closed(self) -> None:
        self.enter()
        normal_move = FakeEvent(
            packet_id=19,
            payload=protocol.encode_uvarint(self.subject.runtime_id) + b"move",
            player=self.normal,
        )
        self.plugin.on_packet_send(normal_move)
        self.assertTrue(normal_move.is_cancelled)

        admin_move = FakeEvent(
            packet_id=19,
            payload=protocol.encode_uvarint(self.subject.runtime_id) + b"move",
            player=self.admin,
        )
        self.plugin.on_packet_send(admin_move)
        self.assertFalse(admin_move.is_cancelled)

        malformed = FakeEvent(packet_id=63, payload=b"\x01\x01", player=self.normal)
        self.plugin.on_packet_send(malformed)
        self.assertTrue(malformed.is_cancelled)
        self.assertTrue(any("failed closed" in item for item in self.plugin.logger.warnings))

    def test_locator_marker_is_removed_and_coordinates_stay_blocked(self) -> None:
        self.enter()
        # A LocatorBar removal is what actually clears the marker. Removing the
        # actor, removing the player-list entry, a PlayerLocation hide and moving
        # the marker out of range were all tried against a live client and none of
        # them cleared it - the bar is waypoint-driven.
        self.assertEqual(self.normal.packets[0][0], protocol.LOCATOR_BAR)
        removal = protocol.parse_locator_bar(self.normal.packets[0][1])
        self.assertEqual(removal[0].group, LOCATOR_GROUP_FOR[self.subject.id])
        self.assertEqual(removal[0].action, protocol.LOCATOR_ACTION_REMOVE)
        self.assertEqual(self.normal.packets[1][0], protocol.REMOVE_ACTOR)
        self.assertEqual(self.normal.packets[2][0], protocol.PLAYER_LIST)

        coordinates = FakeEvent(
            packet_id=protocol.PLAYER_LOCATION,
            payload=protocol.player_location_coordinates(
                self.plugin._identity(self.subject),
                protocol.ReplayProfile(x=10.0, y=20.0, z=30.0),
            ),
            player=self.normal,
        )
        self.plugin.on_packet_send(coordinates)
        self.assertTrue(coordinates.is_cancelled)

        legitimate_hide = FakeEvent(
            packet_id=protocol.PLAYER_LOCATION,
            payload=protocol.player_location_hide(
                self.plugin._identity(self.subject)
            ),
            player=self.normal,
        )
        self.plugin.on_packet_send(legitimate_hide)
        self.assertFalse(legitimate_hide.is_cancelled)

        rejected_hide = FakeEvent(
            packet_id=protocol.PLAYER_LOCATION,
            # The old hardcoded-zero second field: announces HiddenLocation and
            # then claims CoordinatesLocation, which the client cannot read.
            payload=protocol.encode_varint64(self.subject.id) + b"\x01\x00",
            player=self.normal,
        )
        self.plugin.on_packet_send(rejected_hide)
        self.assertTrue(rejected_hide.is_cancelled)

        self.normal.packets.clear()
        self.assertTrue(self.plugin.on_command(self.subject, Command("vanish"), []))
        # Reveal now ends with the LocatorBar waypoint replay, so the PlayerLocation
        # is no longer the last packet - find it rather than indexing from the end.
        location = next(
            payload
            for packet_id, payload in self.normal.packets
            if packet_id == protocol.PLAYER_LOCATION
        )
        restored = protocol.parse_player_location(location)
        self.assertFalse(restored.hidden)
        self.assertEqual(self.normal.packets[-1][0], protocol.LOCATOR_BAR)

    def test_unknown_prelogin_viewer_is_treated_as_unauthorized(self) -> None:
        self.enter()
        event = FakeEvent(
            packet_id=93,
            payload=protocol.uuid_to_wire(self.subject.unique_id) + b"skin",
            player=None,
        )
        self.plugin.on_packet_send(event)
        self.assertTrue(event.is_cancelled)

    def test_list_is_filtered_for_regular_but_not_privileged_viewers(self) -> None:
        self.enter()
        normal_event = FakeEvent(player=self.normal, command="/minecraft:list")
        self.plugin.on_player_command(normal_event)
        self.assertTrue(normal_event.is_cancelled)
        self.assertNotIn("Steve", " ".join(map(str, self.normal.messages)))
        self.assertIn("Alex", " ".join(map(str, self.normal.messages)))

        admin_event = FakeEvent(player=self.admin, command="list")
        self.plugin.on_player_command(admin_event)
        self.assertFalse(admin_event.is_cancelled)

    def test_chat_death_and_skin_messages_only_reach_privileged(self) -> None:
        self.enter()
        self.subject.messages.clear()
        self.admin.messages.clear()
        self.normal.messages.clear()

        chat = FakeEvent(
            player=self.subject,
            message="secret",
            format="<{}> {}",
            recipients=[self.subject, self.normal, self.admin],
        )
        self.plugin.on_player_chat(chat)
        self.assertTrue(chat.is_cancelled)
        self.assertIn("<Steve> secret", self.subject.messages)
        self.assertIn("<Steve> secret", self.admin.messages)
        self.assertNotIn("<Steve> secret", self.normal.messages)

        death = FakeEvent(player=self.subject, death_message="Steve died")
        self.plugin.on_player_death(death)
        self.assertIsNone(death.death_message)
        self.assertIn("Steve died", self.subject.messages)
        self.assertIn("Steve died", self.admin.messages)
        self.assertNotIn("Steve died", self.normal.messages)

        skin = FakeEvent(player=self.subject, skin_change_message="Steve changed skin")
        self.plugin.on_player_skin_change(skin)
        self.assertIsNone(skin.skin_change_message)
        self.assertIn("Steve changed skin", self.admin.messages)
        self.assertNotIn("Steve changed skin", self.normal.messages)

    def test_quit_clears_session_cache_and_reconnect_is_visible(self) -> None:
        self.enter()
        self.admin.messages.clear()
        quit_event = FakeEvent(player=self.subject, quit_message="Steve left")
        self.plugin.on_player_quit(quit_event)
        self.assertIsNone(quit_event.quit_message)
        self.assertIn("Steve left", self.admin.messages)
        self.assertFalse(self.plugin._registry.is_vanished(self.subject.unique_id))
        self.assertFalse(self.plugin._cache.ready(self.subject.unique_id))

        replacement = FakePlayer("Steve", SUBJECT_UUID, 70, 120)
        self.server.online_players = [replacement, self.normal, self.admin]
        join_event = FakeEvent(player=replacement, join_message="Steve joined")
        self.plugin.on_player_join(join_event)
        self.assertFalse(self.plugin._registry.is_vanished(replacement.unique_id))
        self.assertEqual(join_event.join_message, "Steve joined")

    def test_join_initialization_hides_or_reveals_by_admin_tag(self) -> None:
        self.enter()
        newcomer = FakePlayer("New", OTHER_UUID, 20, 30)
        self.server.online_players.append(newcomer)
        self.plugin.on_player_join(FakeEvent(player=newcomer, join_message="joined"))
        self.server.scheduler.tasks[-1].callback()
        self.assertEqual([item[0] for item in newcomer.packets], [341, 14, 63])

        privileged = FakePlayer(
            "Staff", "00000000-0000-0000-0000-000000000013", 21, 31, ("admin",)
        )
        self.server.online_players.append(privileged)
        self.plugin.on_player_join(FakeEvent(player=privileged, join_message="joined"))
        self.server.scheduler.tasks[-1].callback()
        self.assertEqual([item[0] for item in privileged.packets], [63, 12, 326, 341])

    def test_tag_changes_resynchronize_and_disable_restores_regular_viewer(self) -> None:
        self.enter()
        self.normal.packets.clear()
        self.normal.scoreboard_tags.append("admin")
        self.plugin._sync_viewers()
        self.assertEqual([item[0] for item in self.normal.packets], [63, 12, 326, 341])

        self.normal.packets.clear()
        self.normal.scoreboard_tags.clear()
        self.plugin._sync_viewers()
        self.assertEqual([item[0] for item in self.normal.packets], [341, 14, 63])

        self.normal.packets.clear()
        self.admin.packets.clear()
        self.plugin.on_disable()
        self.assertEqual([item[0] for item in self.normal.packets], [63, 12, 326, 341])
        self.assertEqual(self.admin.packets, [])
        self.assertEqual(self.plugin._registry.identities(), ())
        self.assertEqual(self.server.scheduler.cancelled_plugins, [self.plugin])

    def test_server_list_ping_excludes_vanished_sessions(self) -> None:
        self.enter()
        event = FakeEvent(num_players=3)
        self.plugin.on_server_list_ping(event)
        self.assertEqual(event.num_players, 2)


if __name__ == "__main__":
    unittest.main()
