"""Endstone adapter for the protocol-pinned vanish firewall."""

from uuid import UUID

from endstone import Player
from endstone.command import Command, CommandSender
from endstone.event import (
    EventPriority,
    PacketSendEvent,
    PlayerChatEvent,
    PlayerCommandEvent,
    PlayerDeathEvent,
    PlayerJoinEvent,
    PlayerQuitEvent,
    PlayerSkinChangeEvent,
    ServerListPingEvent,
    event_handler,
)
from endstone.plugin import Plugin

from .protocol import (
    PLAYER_LIST,
    PacketCache,
    ProtocolError,
    ReplayProfile,
    SUPPORTED_PROTOCOL,
    LOCATOR_BAR,
    filter_locator_bar,
    filter_player_list,
    packet_mentions_hidden,
)
from .settings import load_settings
from .state import PlayerIdentity, VanishRegistry


class VanishPlugin(Plugin):
    """Hide vanished players from unauthorized viewers at the packet boundary."""

    api_version = "0.11"

    commands = {
        "vanish": {
            "description": "Toggle your vanished state for this session.",
            "usages": ["/vanish"],
            "permissions": ["vanish.command"],
        }
    }

    permissions = {
        "vanish.command": {
            "description": "Allow a player to toggle vanish mode.",
            "default": "op",
        }
    }

    def on_enable(self) -> None:
        protocol = int(self.server.protocol_version)
        if protocol != SUPPORTED_PROTOCOL:
            raise RuntimeError(
                "Vanish refuses to enable: Bedrock protocol "
                f"{protocol} is unsupported (required: {SUPPORTED_PROTOCOL})."
            )

        self.save_default_config()
        settings, warnings = load_settings(self.config)
        for warning in warnings:
            self.logger.warning(f"Vanish configuration: {warning}")

        self._registry = VanishRegistry(settings.admin_tag)
        self._cache = PacketCache()
        self._control_depth = 0
        self._viewer_access: dict[UUID, bool] = {}
        self._warned_packet_ids: set[int] = set()
        for player in self.server.online_players:
            self._viewer_access[self._uuid(player)] = self._is_privileged(player)

        self.register_events(self)
        self._sync_task = self.server.scheduler.run_task(
            self,
            self._sync_viewers,
            delay=settings.sync_period_ticks,
            period=settings.sync_period_ticks,
        )
        self.logger.info(
            f"Vanish enabled for protocol {SUPPORTED_PROTOCOL} "
            f"(admin tag: {settings.admin_tag})."
        )

    def on_disable(self) -> None:
        registry = getattr(self, "_registry", None)
        cache = getattr(self, "_cache", None)
        if registry is None or cache is None:
            return

        self.server.scheduler.cancel_tasks(self)
        identities = registry.identities()
        for identity in identities:
            for viewer in list(self.server.online_players):
                if self._uuid(viewer) == identity.uuid:
                    continue
                if self._is_privileged(viewer):
                    continue
                try:
                    self._set_visible(viewer, identity, visible=True)
                except ProtocolError:
                    self.logger.error(
                        f"Could not restore {identity.name} while disabling: "
                        "replay cache is incomplete."
                    )
        registry.clear()
        cache.clear()
        self._viewer_access.clear()
        self.logger.info("Vanish disabled; session state cleared.")

    def on_command(
        self, sender: CommandSender, command: Command, args: list[str]
    ) -> bool:
        if command.name.lower() != "vanish":
            return False
        if args:
            sender.send_message("Usage: /vanish")
            return False
        if not isinstance(sender, Player):
            sender.send_message("Only an in-game player can use /vanish.")
            return True

        player_uuid = self._uuid(sender)
        if self._registry.is_vanished(player_uuid):
            return self._leave_vanish(sender)
        return self._enter_vanish(sender)

    def _enter_vanish(self, player: Player) -> bool:
        player_uuid = self._uuid(player)
        identity = self._identity(player)
        if self._cache.ensure_fallback(identity, self._replay_profile(player)):
            self.logger.warning(
                "Server-authored replay was unavailable; using a protocol-2168 "
                "fallback until the server emits replacement packets."
            )
        regular_viewers = [
            viewer
            for viewer in self.server.online_players
            if self._uuid(viewer) != player_uuid and not self._is_privileged(viewer)
        ]
        if not self._registry.vanish(identity):
            player.send_message("You are already vanished.")
            return True

        for viewer in regular_viewers:
            self._set_visible(viewer, identity, visible=False)

        # A newly vanished player becomes an authorized viewer and must receive
        # any players that were already hidden from them.
        self._viewer_access[player_uuid] = True
        for other in self._registry.identities():
            if other.uuid != player_uuid:
                self._set_visible(player, other, visible=True)
        player.send_message("You are now vanished.")
        return True

    def _leave_vanish(self, player: Player) -> bool:
        player_uuid = self._uuid(player)
        current_identity = self._identity(player)
        self._cache.ensure_fallback(current_identity, self._replay_profile(player))

        # These viewers did not have the actor before the state transition.
        viewers_to_reveal = [
            viewer
            for viewer in self.server.online_players
            if self._uuid(viewer) != player_uuid and not self._is_privileged(viewer)
        ]
        identity = self._registry.unvanish(player_uuid)
        if identity is None:
            player.send_message("You are not vanished.")
            return True

        for viewer in viewers_to_reveal:
            self._set_visible(viewer, identity, visible=True)

        still_privileged = self._is_privileged(player)
        self._viewer_access[player_uuid] = still_privileged
        if not still_privileged:
            for other in self._registry.identities():
                self._set_visible(player, other, visible=False)
        player.send_message("You are visible again.")
        return True

    @event_handler(priority=EventPriority.HIGHEST, ignore_cancelled=True)
    def on_packet_send(self, event: PacketSendEvent) -> None:
        if self._control_depth:
            return

        try:
            self._cache.capture(event.packet_id, event.payload)
        except ProtocolError:
            self._warn_packet_once(event.packet_id, "could not cache malformed payload")

        hidden = self._registry.identities()
        if not hidden:
            return

        viewer = event.player
        if viewer is not None:
            self._sync_viewer(viewer)
            if self._is_privileged(viewer):
                return

        try:
            if event.packet_id == PLAYER_LIST:
                filtered = filter_player_list(event.payload, self._registry.uuids())
                if filtered is None:
                    event.cancel()
                elif filtered != event.payload:
                    event.payload = filtered
                return
            if event.packet_id == LOCATOR_BAR:
                # Filtered per waypoint rather than cancelled wholesale. One packet
                # carries waypoints for several players, so dropping all of it
                # freezes the locator bar for everyone on the server for as long as
                # anyone is vanished - and stops the vanished player's own marker
                # from ever being removed, because the removal is a 341 too.
                hidden_actor_ids = frozenset(identity.actor_id for identity in hidden)
                hidden_groups = frozenset(
                    group
                    for group in (
                        self._cache.locator_group_for(identity.actor_id)
                        for identity in hidden
                    )
                    if group is not None
                )
                filtered = filter_locator_bar(
                    event.payload, hidden_actor_ids, hidden_groups
                )
                if filtered is None:
                    event.cancel()
                elif filtered != event.payload:
                    event.payload = filtered
                return
            if packet_mentions_hidden(event.packet_id, event.payload, hidden):
                event.cancel()
        except ProtocolError:
            # An identity-bearing packet that cannot be parsed must never be
            # allowed through to an unauthorized or not-yet-logged-in client.
            event.cancel()
            self._warn_packet_once(event.packet_id, "cancelled malformed identity payload")

    @event_handler(priority=EventPriority.HIGHEST, ignore_cancelled=True)
    def on_player_chat(self, event: PlayerChatEvent) -> None:
        if not self._registry.is_vanished(self._uuid(event.player)):
            return
        # Endstone 0.11 exposes recipients through a read-only, by-value Python
        # list. Mutating that list does not change the native event, so cancel
        # the vanilla broadcast and deliver the formatted message explicitly.
        event.cancel()
        try:
            message = event.format.format(event.player.name, event.message)
        except (IndexError, KeyError, ValueError):
            message = f"<{event.player.name}> {event.message}"
        self._broadcast_privileged(message)

    @event_handler(priority=EventPriority.HIGHEST, ignore_cancelled=True)
    def on_player_command(self, event: PlayerCommandEvent) -> None:
        command_line = event.command.lstrip("/").strip()
        if not command_line:
            return
        command_name = command_line.split(maxsplit=1)[0].lower()
        if command_name not in {"list", "minecraft:list"}:
            return
        if self._is_privileged(event.player):
            return

        visible = [
            player.name
            for player in self.server.online_players
            if not self._registry.is_vanished(self._uuid(player))
        ]
        event.cancel()
        event.player.send_message(
            f"There are {len(visible)}/{self.server.max_players} players online:"
        )
        event.player.send_message(", ".join(visible) if visible else "No visible players.")

    @event_handler(priority=EventPriority.HIGHEST)
    def on_player_join(self, event: PlayerJoinEvent) -> None:
        player_uuid = self._uuid(event.player)
        self._viewer_access[player_uuid] = self._is_privileged(event.player)
        player = event.player
        self.server.scheduler.run_task(
            self, lambda: self._initialize_joined_viewer(player), delay=1
        )

    @event_handler(priority=EventPriority.HIGHEST)
    def on_player_quit(self, event: PlayerQuitEvent) -> None:
        player_uuid = self._uuid(event.player)
        was_vanished = self._registry.is_vanished(player_uuid)
        if was_vanished and event.quit_message is not None:
            message = event.quit_message
            event.quit_message = None
            self._broadcast_privileged(message, exclude=player_uuid)

        self._registry.remove_session(player_uuid)
        self._cache.forget(player_uuid)
        self._viewer_access.pop(player_uuid, None)

    @event_handler(priority=EventPriority.HIGHEST)
    def on_player_death(self, event: PlayerDeathEvent) -> None:
        if not self._registry.is_vanished(self._uuid(event.player)):
            return
        if event.death_message is not None:
            message = event.death_message
            event.death_message = None
            self._broadcast_privileged(message)

    @event_handler(priority=EventPriority.HIGHEST, ignore_cancelled=True)
    def on_player_skin_change(self, event: PlayerSkinChangeEvent) -> None:
        if not self._registry.is_vanished(self._uuid(event.player)):
            return
        if event.skin_change_message is not None:
            message = event.skin_change_message
            event.skin_change_message = None
            self._broadcast_privileged(message)

    @event_handler(priority=EventPriority.HIGHEST)
    def on_server_list_ping(self, event: ServerListPingEvent) -> None:
        # A server-list ping has no authenticated viewer, so its count must be
        # the public (ordinary-viewer) count.
        event.num_players = max(0, event.num_players - len(self._registry.identities()))

    def _initialize_joined_viewer(self, player: Player) -> None:
        try:
            # The player may have left during the one-tick initialization delay.
            if player not in self.server.online_players:
                return
            privileged = self._is_privileged(player)
            self._viewer_access[self._uuid(player)] = privileged
            for identity in self._registry.identities():
                if identity.uuid == self._uuid(player):
                    continue
                try:
                    self._set_visible(player, identity, visible=privileged)
                except ProtocolError:
                    self.logger.warning(
                        f"Could not initialize vanish visibility for {player.name}: "
                        "cache incomplete."
                    )
        except (ReferenceError, RuntimeError):
            # Endstone player wrappers can become invalid after a disconnect.
            return

    def _sync_viewers(self) -> None:
        online_ids: set[UUID] = set()
        for viewer in list(self.server.online_players):
            viewer_uuid = self._uuid(viewer)
            online_ids.add(viewer_uuid)
            self._sync_viewer(viewer)
        for stale in set(self._viewer_access) - online_ids:
            self._viewer_access.pop(stale, None)

    def _sync_viewer(self, viewer: Player) -> None:
        viewer_uuid = self._uuid(viewer)
        current = self._is_privileged(viewer)
        previous = self._viewer_access.get(viewer_uuid, current)
        self._viewer_access[viewer_uuid] = current
        if current == previous:
            return
        for identity in self._registry.identities():
            if identity.uuid == viewer_uuid:
                continue
            try:
                self._set_visible(viewer, identity, visible=current)
            except ProtocolError:
                self.logger.warning(
                    f"Could not update vanish visibility for {viewer.name}: "
                    "cache incomplete."
                )

    def _set_visible(
        self, viewer: Player, identity: PlayerIdentity, *, visible: bool
    ) -> None:
        if self._uuid(viewer) == identity.uuid:
            return
        packets = (
            self._cache.reveal_packets(identity.uuid)
            if visible
            else self._cache.hide_packets(identity)
        )
        self._control_depth += 1
        try:
            for packet_id, payload in packets:
                viewer.send_packet(packet_id, payload)
        finally:
            self._control_depth -= 1

    def _broadcast_privileged(self, message: object, exclude: UUID | None = None) -> None:
        for player in list(self.server.online_players):
            player_uuid = self._uuid(player)
            if player_uuid != exclude and self._is_privileged(player):
                player.send_message(message)

    def _is_privileged(self, player: Player) -> bool:
        return self._registry.can_see_vanished(
            self._uuid(player), getattr(player, "scoreboard_tags", ())
        )

    @staticmethod
    def _uuid(player: Player) -> UUID:
        value = player.unique_id
        return value if isinstance(value, UUID) else UUID(str(value))

    @classmethod
    def _identity(cls, player: Player) -> PlayerIdentity:
        return PlayerIdentity(
            uuid=cls._uuid(player),
            name=player.name,
            actor_id=int(player.id),
            runtime_id=int(player.runtime_id),
        )

    @classmethod
    def _replay_profile(cls, player: Player) -> ReplayProfile:
        location = getattr(player, "location", None)
        velocity = getattr(player, "velocity", None)
        skin = getattr(player, "skin", None)
        skin_width, skin_height, skin_data = cls._rgba_snapshot(
            getattr(skin, "image", None)
        )
        cape_width, cape_height, cape_data = cls._rgba_snapshot(
            getattr(skin, "cape_image", None), default_size=0
        )

        game_mode = getattr(getattr(player, "game_mode", None), "name", "SURVIVAL")
        game_type = {
            "SURVIVAL": 0,
            "CREATIVE": 1,
            "ADVENTURE": 2,
            "SPECTATOR": 6,
        }.get(str(game_mode).upper(), 0)
        return ReplayProfile(
            x=cls._number(location, "x"),
            y=cls._number(location, "y"),
            z=cls._number(location, "z"),
            velocity_x=cls._number(velocity, "x"),
            velocity_y=cls._number(velocity, "y"),
            velocity_z=cls._number(velocity, "z"),
            pitch=cls._number(location, "pitch"),
            yaw=cls._number(location, "yaw"),
            game_type=game_type,
            is_operator=bool(getattr(player, "is_op", False)),
            fly_speed=cls._number(player, "fly_speed", 0.05),
            walk_speed=cls._number(player, "walk_speed", 0.1),
            xuid=str(getattr(player, "xuid", "") or ""),
            skin_id=str(getattr(skin, "id", "") or "Standard_Custom"),
            skin_width=skin_width,
            skin_height=skin_height,
            skin_data=skin_data,
            cape_id=str(getattr(skin, "cape_id", "") or ""),
            cape_width=cape_width,
            cape_height=cape_height,
            cape_data=cape_data,
        )

    @staticmethod
    def _number(source: object, attribute: str, default: float = 0.0) -> float:
        try:
            return float(getattr(source, attribute))
        except (AttributeError, TypeError, ValueError):
            return default

    @staticmethod
    def _rgba_snapshot(image: object, default_size: int = 64) -> tuple[int, int, bytes]:
        try:
            shape = tuple(int(value) for value in image.shape)  # type: ignore[attr-defined]
            raw = bytes(image.tobytes())  # type: ignore[attr-defined]
            if len(shape) == 3 and shape[2] == 4 and len(raw) == shape[0] * shape[1] * 4:
                return shape[1], shape[0], raw
            if len(shape) == 3 and shape[2] == 3 and len(raw) == shape[0] * shape[1] * 3:
                rgba = bytearray()
                for offset in range(0, len(raw), 3):
                    rgba.extend(raw[offset : offset + 3])
                    rgba.append(255)
                return shape[1], shape[0], bytes(rgba)
        except (AttributeError, TypeError, ValueError):
            pass
        if default_size <= 0:
            return 0, 0, b""
        return default_size, default_size, b"\xff\xff\xff\xff" * (default_size**2)

    def _warn_packet_once(self, packet_id: int, reason: str) -> None:
        if packet_id in self._warned_packet_ids:
            return
        self._warned_packet_ids.add(packet_id)
        self.logger.warning(
            f"Packet {packet_id}: {reason}; privacy policy failed closed."
        )
