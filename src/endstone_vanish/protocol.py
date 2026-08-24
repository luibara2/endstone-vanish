"""Bedrock protocol 2168 helpers used by the per-viewer packet firewall.

This module deliberately supports exactly one protocol.  The plugin checks the
server protocol before registering the listener so a protocol change cannot
silently turn a parse failure into a privacy leak.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import pack, unpack_from
from uuid import UUID

from .state import PlayerIdentity

SUPPORTED_PROTOCOL = 2168

ADD_PLAYER = 12
REMOVE_ACTOR = 14
PLAYER_LIST = 63
PLAYER_SKIN = 93
PLAYER_LOCATION = 326
LOCATOR_BAR = 341


class ProtocolError(ValueError):
    """Raised when a protocol-2168 payload is malformed or inconsistent."""


def encode_uvarint(value: int) -> bytes:
    if value < 0:
        raise ValueError("an unsigned varint cannot encode a negative value")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_varint64(value: int) -> bytes:
    if not -(1 << 63) <= value < (1 << 63):
        raise ValueError("signed varint64 is out of range")
    zigzag = (value << 1) ^ (value >> 63)
    return encode_uvarint(zigzag)


def uuid_to_wire(value: UUID) -> bytes:
    """Encode a Bedrock UUID: MSB uint64 LE followed by LSB uint64 LE."""

    integer = value.int
    most = integer >> 64
    least = integer & ((1 << 64) - 1)
    return most.to_bytes(8, "little") + least.to_bytes(8, "little")


def uuid_from_wire(value: bytes) -> UUID:
    if len(value) != 16:
        raise ProtocolError("a UUID must contain 16 bytes")
    most = int.from_bytes(value[:8], "little")
    least = int.from_bytes(value[8:], "little")
    return UUID(int=(most << 64) | least)


class BufferReader:
    """Small, bounds-checked reader for fields needed by this plugin."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise ProtocolError("packet ended while reading a field")
        start = self.offset
        self.offset += length
        return self.data[start : self.offset]

    def skip(self, length: int) -> None:
        self.take(length)

    def uvarint(self, *, bits: int = 64) -> int:
        value = 0
        max_bytes = 5 if bits <= 32 else 10
        for index in range(max_bytes):
            byte = self.take(1)[0]
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                if value >= 1 << bits:
                    raise ProtocolError("unsigned varint is out of range")
                return value
        raise ProtocolError("unterminated unsigned varint")

    def varint(self, *, bits: int = 64) -> int:
        encoded = self.uvarint(bits=bits)
        value = (encoded >> 1) ^ -(encoded & 1)
        lower = -(1 << (bits - 1))
        upper = 1 << (bits - 1)
        if not lower <= value < upper:
            raise ProtocolError("signed varint is out of range")
        return value

    def string_bytes(self) -> bytes:
        return self.take(self.uvarint(bits=32))

    def string(self) -> str:
        try:
            return self.string_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProtocolError("packet contains invalid UTF-8") from exc

    def uuid(self) -> UUID:
        return uuid_from_wire(self.take(16))


@dataclass(frozen=True, slots=True)
class PlayerListEntry:
    variant: int
    action: int
    uuid: UUID
    raw: bytes

    @property
    def is_add(self) -> bool:
        return self.variant == 1 and self.action == 0

    @property
    def is_remove(self) -> bool:
        return self.variant == 0 and self.action == 1


@dataclass(frozen=True, slots=True)
class ReplayProfile:
    """Live player properties used only when server-authored replay is absent."""

    x: float = 0.0
    y: float = 0.0
    z: float = 0.0
    velocity_x: float = 0.0
    velocity_y: float = 0.0
    velocity_z: float = 0.0
    pitch: float = 0.0
    yaw: float = 0.0
    game_type: int = 0
    is_operator: bool = False
    fly_speed: float = 0.05
    walk_speed: float = 0.1
    xuid: str = ""
    skin_id: str = "Standard_Custom"
    skin_width: int = 64
    skin_height: int = 64
    skin_data: bytes = b""
    cape_id: str = ""
    cape_width: int = 0
    cape_height: int = 0
    cape_data: bytes = b""


@dataclass(frozen=True, slots=True)
class PlayerLocationRecord:
    actor_id: int
    hidden: bool
    position: tuple[float, float, float] | None


def _skip_skin_image(reader: BufferReader) -> None:
    reader.skip(8)  # width and height, little-endian uint32
    reader.string_bytes()


def _skip_serialized_skin(reader: BufferReader) -> None:
    # id, playFab id, resource patch
    for _ in range(3):
        reader.string_bytes()
    _skip_skin_image(reader)

    for _ in range(reader.uvarint(bits=32)):
        _skip_skin_image(reader)
        # AnimatedImageData is SkinImage, then AnimatedTextureType and
        # AnimationExpression as *uvarint32* with a float between them - not the
        # three fixed uint32/float/uint32 words an older protocol used. Skipping
        # 12 bytes here over-reads by six per frame and desynchronises the rest
        # of the skin, so every player with an animated (persona/4D) skin failed
        # to cache and fell back to a synthesised entry. A classic skin has zero
        # frames, so this loop never ran and those players worked - which is why
        # it looked like the bug followed one PC rather than one skin type.
        reader.uvarint(bits=32)  # AnimatedTextureType
        reader.skip(4)  # Frames, float
        reader.uvarint(bits=32)  # AnimationExpression

    _skip_skin_image(reader)
    # geometry, minimum engine version, animation, cape id, full id
    for _ in range(5):
        reader.string_bytes()
    reader.skip(1)  # arm-size enum (uint8)
    reader.skip(4)  # packed Color (int32)

    for _ in range(reader.uvarint(bits=32)):
        reader.string_bytes()  # piece id
        reader.skip(4)  # piece type enum (uint32)
        reader.skip(16)  # pack UUID
        reader.skip(1)  # default-piece bool
        reader.string_bytes()  # product id

    for _ in range(reader.uvarint(bits=32)):
        reader.string_bytes()  # PieceType is name-coded in this map
        reader.skip(16)  # four packed Colors

    reader.skip(5)  # premium/persona/cape/primary/override bools
    reader.string_bytes()  # trusted skin flag is name-coded
    reader.string_bytes()  # profile hash, added in protocol 2168


def parse_player_list(payload: bytes) -> tuple[PlayerListEntry, ...]:
    reader = BufferReader(payload)
    count = reader.uvarint(bits=32)
    if count > 10_000:
        raise ProtocolError("player-list entry count is unreasonable")
    entries: list[PlayerListEntry] = []
    for _ in range(count):
        start = reader.offset
        variant = reader.uvarint(bits=32)
        action = reader.take(1)[0]
        player_uuid = reader.uuid()
        if variant == 0:
            if action != 1:
                raise ProtocolError("remove entry has an invalid action")
        elif variant == 1:
            if action != 0:
                raise ProtocolError("add entry has an invalid action")
            reader.varint(bits=64)  # actor unique id
            reader.string_bytes()  # player name
            reader.string_bytes()  # XUID
            reader.string_bytes()  # platform online id
            reader.skip(4)  # build platform int32
            _skip_serialized_skin(reader)
            reader.skip(3)  # teacher, host and sub-client bools
            reader.skip(4)  # player color
        else:
            raise ProtocolError(f"unknown player-list entry variant {variant}")
        entries.append(
            PlayerListEntry(
                variant=variant,
                action=action,
                uuid=player_uuid,
                raw=payload[start : reader.offset],
            )
        )
    if reader.offset != len(payload):
        raise ProtocolError("player-list packet has trailing bytes")
    return tuple(entries)


def player_list_packet(entries: tuple[bytes, ...] | list[bytes]) -> bytes:
    return encode_uvarint(len(entries)) + b"".join(entries)


def player_list_remove(player_uuid: UUID) -> bytes:
    # count=1, variant 0 selects RemoveEntry, action 1 means REMOVE.
    return b"\x01\x00\x01" + uuid_to_wire(player_uuid)


LOCATOR_ACTION_NONE = 0
LOCATOR_ACTION_ADD = 1
LOCATOR_ACTION_REMOVE = 2
LOCATOR_ACTION_UPDATE = 3


@dataclass(frozen=True, slots=True)
class LocatorBarEntry:
    """One waypoint out of a LocatorBar packet.

    The locator bar is waypoint-driven: a marker exists because a packet 341 put
    it there, and it goes away when a packet 341 removes it. PlayerLocation (326)
    only moves an existing marker, which is why hiding or banishing through 326
    never cleared one.
    """

    group: UUID
    action: int
    actor_id: int | None
    raw: bytes


def parse_locator_bar(payload: bytes) -> tuple[LocatorBarEntry, ...]:
    """Parse a protocol-2168 LocatorBar packet into its waypoints."""

    reader = BufferReader(payload)
    count = reader.uvarint(bits=32)
    if count > 40_000:
        raise ProtocolError("locator-bar waypoint count is unreasonable")
    entries: list[LocatorBarEntry] = []
    for _ in range(count):
        start = reader.offset
        group = reader.uuid()
        reader.skip(4)  # UpdateFlag, uint32
        if reader.take(1)[0]:
            reader.skip(1)  # IsVisible
        if reader.take(1)[0]:
            reader.skip(12)  # WorldPosition, Vec3
            reader.varint(bits=32)  # dimension
        if reader.take(1)[0]:
            reader.string_bytes()  # TexturePath
        if reader.take(1)[0]:
            reader.skip(8)  # IconSize, Vec2
        if reader.take(1)[0]:
            reader.skip(4)  # Color, packed int32
        if reader.take(1)[0]:
            reader.skip(1)  # ClientPositionAuthority
        actor_id = reader.varint(bits=64) if reader.take(1)[0] else None
        action = reader.take(1)[0]
        entries.append(
            LocatorBarEntry(group, action, actor_id, payload[start : reader.offset])
        )
    if reader.offset != len(payload):
        raise ProtocolError("locator-bar packet has trailing bytes")
    return tuple(entries)


def locator_bar_packet(entries: tuple[bytes, ...] | list[bytes]) -> bytes:
    return encode_uvarint(len(entries)) + b"".join(entries)


def locator_bar_remove(group: UUID) -> bytes:
    """A LocatorBar packet that deletes one waypoint group.

    Every optional field is absent, so this is a bare handle plus the remove
    action - the same shape the server sends when a player quits, which is what
    makes their marker disappear.
    """

    return locator_bar_packet(
        [
            b"".join(
                (
                    uuid_to_wire(group),
                    pack("<I", 0),  # UpdateFlag
                    b"\x00" * 7,  # every optional field absent
                    bytes((LOCATOR_ACTION_REMOVE,)),
                )
            )
        ]
    )


def filter_locator_bar(
    payload: bytes, hidden_actor_ids: frozenset[int], hidden_groups: frozenset[UUID]
) -> bytes | None:
    """Drop the waypoints belonging to hidden players, keep everyone else's.

    Cancelling the whole packet instead - which is what treating 341 as opaque
    amounted to - freezes the locator bar for every player on the server for as
    long as anyone is vanished, and stops the vanished player's own marker from
    ever being removed. Returns None when nothing survives.
    """

    kept = [
        entry.raw
        for entry in parse_locator_bar(payload)
        if entry.group not in hidden_groups
        and (entry.actor_id is None or entry.actor_id not in hidden_actor_ids)
    ]
    return locator_bar_packet(kept) if kept else None


def player_location_at(identity: PlayerIdentity, x: float, y: float, z: float) -> bytes:
    """Encode a protocol-2168 locator-bar coordinates update at an explicit point."""

    return b"".join(
        (
            encode_varint64(identity.actor_id),
            # CoordinatesLocation is 0, and 0 is the same byte in both of this
            # packet's two encodings - see player_location_hide for the pair.
            b"\x00\x00",
            pack("<fff", x, y, z),
        )
    )


def player_location_coordinates(
    identity: PlayerIdentity, profile: ReplayProfile
) -> bytes:
    """Encode a protocol-2168 locator-bar coordinates update."""

    return player_location_at(identity, profile.x, profile.y, profile.z)


def player_location_hide(identity: PlayerIdentity) -> bytes:
    """Encode a protocol-2168 PlayerLocation hide for one player.

    Kept for completeness and to pin the encoding, but **not used by
    hide_packets** - see there for why. HiddenLocation does not remove a locator
    marker; it leaves one behind at the last known position.
    """

    # The variant is written twice in two different encodings: uvarint32, then
    # zigzag varint32. HiddenLocation is 1, so that is 0x01 then 0x02.
    #
    # 0x02 0x02 fails because the first field is unsigned, not zigzag. 0x01 0x00
    # fails for the opposite reason: a decoder assigns the variant from the first
    # field and then overwrites it from the second, so a zero there announces
    # HiddenLocation and immediately claims CoordinatesLocation, and the client
    # goes looking for a Vec3 that was never written. gophertunnel had the same
    # hardcoded zero and fixed it in 1d9d0fc, "Fix double type encoding".
    return encode_varint64(identity.actor_id) + b"\x01\x02"


def parse_player_location(payload: bytes) -> PlayerLocationRecord:
    """Parse the protocol-2168 tagged PlayerLocation payload."""

    reader = BufferReader(payload)
    actor_id = reader.varint(bits=64)
    variant = reader.uvarint(bits=32)
    packet_type = reader.varint(bits=32)
    if variant == 0 and packet_type == 0:
        position = unpack_from("<fff", reader.take(12))
        hidden = False
    elif variant == 1 and packet_type == 1:
        position = None
        hidden = True
    else:
        raise ProtocolError("player-location variant and type do not match")
    if reader.offset != len(payload):
        raise ProtocolError("player-location packet has trailing bytes")
    return PlayerLocationRecord(actor_id, hidden, position)


def _wire_bytes(value: bytes) -> bytes:
    return encode_uvarint(len(value)) + value


def _wire_string(value: str) -> bytes:
    return _wire_bytes(value.encode("utf-8"))


def _validated_skin(profile: ReplayProfile) -> tuple[int, int, bytes]:
    expected = profile.skin_width * profile.skin_height * 4
    if profile.skin_width > 0 and profile.skin_height > 0 and len(profile.skin_data) == expected:
        return profile.skin_width, profile.skin_height, profile.skin_data
    # A visible, valid classic skin is safer than refusing vanish because the
    # optional skin snapshot was unavailable.
    return 64, 64, b"\xff\xff\xff\xff" * (64 * 64)


def _validated_cape(profile: ReplayProfile) -> tuple[int, int, bytes]:
    expected = profile.cape_width * profile.cape_height * 4
    if profile.cape_width > 0 and profile.cape_height > 0 and len(profile.cape_data) == expected:
        return profile.cape_width, profile.cape_height, profile.cape_data
    return 0, 0, b""


def fallback_player_list_entry(identity: PlayerIdentity, profile: ReplayProfile) -> bytes:
    """Build a minimal classic-skin PlayerList AddEntry for protocol 2168."""

    skin_width, skin_height, skin_data = _validated_skin(profile)
    cape_width, cape_height, cape_data = _validated_cape(profile)
    skin_id = profile.skin_id or "Standard_Custom"
    resource_patch = '{"geometry":{"default":"geometry.humanoid.custom"}}'
    serialized_skin = b"".join(
        (
            _wire_string(skin_id),
            _wire_string(""),  # PlayFab id is not exposed by Endstone.
            _wire_string(resource_patch),
            pack("<II", skin_width, skin_height),
            _wire_bytes(skin_data),
            encode_uvarint(0),  # animated images
            pack("<II", cape_width, cape_height),
            _wire_bytes(cape_data),
            _wire_string(""),  # geometry data; resource patch selects built-in geometry
            _wire_string(""),  # minimum engine version
            _wire_string(""),  # animation data
            _wire_string(profile.cape_id),
            _wire_string(skin_id),
            b"\x01",  # WIDE arm-size enum
            pack("<i", -1),  # opaque white skin color
            encode_uvarint(0),  # persona pieces
            encode_uvarint(0),  # persona tint map
            b"\x00\x00\x00\x01\x00",  # skin flags; primary user=true
            _wire_string("TRUE"),
            _wire_string(""),  # profile hash
        )
    )
    return b"".join(
        (
            encode_uvarint(1),  # union variant selects AddEntry
            b"\x00",  # action ADD
            uuid_to_wire(identity.uuid),
            encode_varint64(identity.actor_id),
            _wire_string(identity.name),
            _wire_string(profile.xuid),
            _wire_string(""),  # platform online id is not exposed by Endstone
            pack("<i", -1),  # unknown build platform
            serialized_skin,
            b"\x00\x00\x00",  # teacher, host, sub-client
            pack("<i", -1),
        )
    )


def fallback_add_player(identity: PlayerIdentity, profile: ReplayProfile) -> bytes:
    """Build a minimal valid AddPlayer payload for protocol 2168."""

    permission = 2 if profile.is_operator else 1
    command_permission = 2 if profile.is_operator else 0
    abilities = b"".join(
        (
            pack("<q", identity.actor_id),
            bytes((permission, command_permission)),
            encode_uvarint(1),
            pack(
                "<HIIfff",
                1,  # BASE abilities layer
                0,
                0,
                profile.fly_speed,
                1.0,
                profile.walk_speed,
            ),
        )
    )
    return b"".join(
        (
            uuid_to_wire(identity.uuid),
            _wire_string(identity.name),
            encode_uvarint(identity.runtime_id),
            _wire_string(""),  # platform chat id
            pack("<fff", profile.x, profile.y, profile.z),
            pack(
                "<fff",
                profile.velocity_x,
                profile.velocity_y,
                profile.velocity_z,
            ),
            pack("<ff", profile.pitch, profile.yaw),
            pack("<f", profile.yaw),
            b"\x00" * 8,  # empty cerealized carried item
            encode_varint64(profile.game_type),
            encode_uvarint(0),  # synchronized actor data
            encode_uvarint(0),  # integer properties
            encode_uvarint(0),  # float properties
            abilities,
            encode_uvarint(0),  # actor links
            _wire_string(""),  # device id is intentionally not replayed
            pack("<i", -1),  # unknown build platform
        )
    )


def filter_player_list(payload: bytes, hidden: frozenset[UUID]) -> bytes | None:
    """Remove hidden add entries; return None when nothing may be sent."""

    entries = parse_player_list(payload)
    kept = [entry.raw for entry in entries if not (entry.is_add and entry.uuid in hidden)]
    if not kept:
        return None
    if len(kept) == len(entries):
        return payload
    return player_list_packet(kept)


def parse_add_player_header(payload: bytes) -> tuple[UUID, str, int]:
    reader = BufferReader(payload)
    player_uuid = reader.uuid()
    name = reader.string()
    runtime_id = reader.uvarint(bits=64)
    return player_uuid, name, runtime_id


class PacketCache:
    """Replayable server-authored packets, indexed without storing private logs."""

    def __init__(self) -> None:
        self.add_player: dict[UUID, bytes] = {}
        self.player_list_add: dict[UUID, bytes] = {}
        self.player_skin: dict[UUID, bytes] = {}
        self.player_location: dict[UUID, bytes] = {}
        # The locator bar is waypoint-driven, and a waypoint is addressed by its
        # group handle rather than by the player it follows, so the link between
        # the two has to be learned from the packets themselves.
        self.locator_group: dict[int, UUID] = {}
        self.locator_add: dict[UUID, bytes] = {}
        self._actor_uuids: dict[int, UUID] = {}

    def capture(self, packet_id: int, payload: bytes) -> None:
        if packet_id == ADD_PLAYER:
            player_uuid, _name, _runtime_id = parse_add_player_header(payload)
            self.add_player[player_uuid] = bytes(payload)
        elif packet_id == PLAYER_LIST:
            for entry in parse_player_list(payload):
                if entry.is_add:
                    self.player_list_add[entry.uuid] = entry.raw
                elif entry.is_remove:
                    self.forget(entry.uuid)
        elif packet_id == PLAYER_SKIN:
            reader = BufferReader(payload)
            self.player_skin[reader.uuid()] = bytes(payload)
        elif packet_id == PLAYER_LOCATION:
            location = parse_player_location(payload)
            player_uuid = self._actor_uuids.get(location.actor_id)
            if player_uuid is not None and not location.hidden:
                self.player_location[player_uuid] = bytes(payload)
        elif packet_id == LOCATOR_BAR:
            for entry in parse_locator_bar(payload):
                if entry.actor_id is not None:
                    self.locator_group[entry.actor_id] = entry.group
                if entry.action == LOCATOR_ACTION_REMOVE:
                    self.locator_add.pop(entry.group, None)
                else:
                    self.locator_add[entry.group] = entry.raw

    def ready(self, player_uuid: UUID) -> bool:
        return player_uuid in self.add_player and player_uuid in self.player_list_add

    def ensure_fallback(self, identity: PlayerIdentity, profile: ReplayProfile) -> bool:
        """Fill missing replay records and report whether fallback was needed."""

        used_fallback = not self.ready(identity.uuid)
        self.add_player.setdefault(identity.uuid, fallback_add_player(identity, profile))
        self.player_list_add.setdefault(
            identity.uuid, fallback_player_list_entry(identity, profile)
        )
        self._actor_uuids[identity.actor_id] = identity.uuid
        self.player_location[identity.uuid] = player_location_coordinates(
            identity, profile
        )
        return used_fallback

    def reveal_packets(self, player_uuid: UUID) -> tuple[tuple[int, bytes], ...]:
        if not self.ready(player_uuid):
            raise ProtocolError("replay cache is incomplete for this player")
        packets: list[tuple[int, bytes]] = [
            (PLAYER_LIST, player_list_packet([self.player_list_add[player_uuid]])),
            (ADD_PLAYER, self.add_player[player_uuid]),
        ]
        skin = self.player_skin.get(player_uuid)
        if skin is not None:
            packets.append((PLAYER_SKIN, skin))
        location = self.player_location.get(player_uuid)
        if location is not None:
            packets.append((PLAYER_LOCATION, location))
        waypoint = self.locator_waypoint_for(player_uuid)
        if waypoint is not None:
            packets.append((LOCATOR_BAR, locator_bar_packet([waypoint])))
        return tuple(packets)

    def locator_waypoint_for(self, player_uuid: UUID) -> bytes | None:
        """The last waypoint seen for this player, ready to be replayed."""

        for actor_id, mapped_uuid in self._actor_uuids.items():
            if mapped_uuid != player_uuid:
                continue
            group = self.locator_group.get(actor_id)
            if group is not None:
                return self.locator_add.get(group)
        return None

    def locator_group_for(self, actor_id: int) -> UUID | None:
        return self.locator_group.get(actor_id)

    def hide_packets(self, identity: PlayerIdentity) -> tuple[tuple[int, bytes], ...]:
        """Exactly what the client sees when a player logs out, and nothing more.

        There is deliberately no PlayerLocation hide here. Sending one leaves a
        dead marker on every viewer's locator bar: the client keeps the entry at
        the last position it was told about, and neither the actor removal nor the
        player-list removal clears it afterwards. Coordinate updates for a hidden
        player are already blocked by the firewall, so the marker just sits there
        at stale coordinates, pointing at nothing.

        Confirmed by comparison: a player who simply quits sends these two packets
        and their marker disappears. The hide was the only difference.
        """

        packets: list[tuple[int, bytes]] = []
        group = self.locator_group.get(identity.actor_id)
        if group is not None:
            # This is what actually clears the locator marker. Removing the actor
            # and the player-list entry does not, and neither does a PlayerLocation
            # hide - the marker outlives all three.
            packets.append((LOCATOR_BAR, locator_bar_remove(group)))
        packets.append((REMOVE_ACTOR, encode_varint64(identity.actor_id)))
        packets.append((PLAYER_LIST, player_list_remove(identity.uuid)))
        return tuple(packets)

    def forget(self, player_uuid: UUID) -> None:
        self.add_player.pop(player_uuid, None)
        self.player_list_add.pop(player_uuid, None)
        self.player_skin.pop(player_uuid, None)
        self.player_location.pop(player_uuid, None)
        for actor_id, mapped_uuid in tuple(self._actor_uuids.items()):
            if mapped_uuid == player_uuid:
                self._actor_uuids.pop(actor_id, None)

    def clear(self) -> None:
        self.add_player.clear()
        self.player_list_add.clear()
        self.player_skin.clear()
        self.player_location.clear()
        self._actor_uuids.clear()


# Packets whose first field is the referenced player identifier.  RemoveActor is
# intentionally absent: removals are safe and are required to enforce vanish.
_FIRST_RUNTIME_PACKETS = frozenset(
    {
        18,  # MoveActorAbsolute
        19,  # MovePlayer
        27,  # ActorEvent
        28,  # MobEffect
        29,  # UpdateAttributes
        31,  # MobEquipment
        32,  # MobArmorEquipment
        36,  # PlayerAction
        39,  # SetActorData
        40,  # SetActorMotion
        75,  # ShowCredits
        98,  # NpcRequest
        111,  # MoveActorDelta
        113,  # SetLocalPlayerAsInitialized
        138,  # Emote
        152,  # EmoteList
        157,  # MotionPredictionHints
        318,  # MovementEffect
    }
)

_FIRST_UNIQUE_PACKETS = frozenset(
    {
        11,  # StartGame
        13,  # AddActor
        15,  # AddItemActor
        22,  # AddPainting
        65,  # LegacyTelemetryEvent
        73,  # Camera
        74,  # BossEvent
        155,  # DebugInfo
        182,  # ChangeMobProperty
        325,  # PlayerUpdateEntityOverrides
    }
)

# These packets can carry position/identity records in nested optional payloads
# without a reliable top-level discriminator. Blocking the whole packet while
# vanish is active is intentionally conservative.
_PRIVACY_AMBIGUOUS_PACKETS = frozenset(
    {
        67,  # ClientboundMapItemData (tracked-actor markers)
        328,  # PrimitiveShapes (optional actor attachment)
    }
)


def _contains_hidden_signature(payload: bytes, identities: tuple[PlayerIdentity, ...]) -> bool:
    for identity in identities:
        if uuid_to_wire(identity.uuid) in payload:
            return True
        encoded_name = identity.name.encode("utf-8")
        if encoded_name and encode_uvarint(len(encoded_name)) + encoded_name in payload:
            return True
    return False


def _read_first_uvarint(payload: bytes) -> int:
    return BufferReader(payload).uvarint(bits=64)


def _read_first_varint(payload: bytes) -> int:
    return BufferReader(payload).varint(bits=64)


def _special_actor_ids(packet_id: int, payload: bytes) -> tuple[set[int], set[int]]:
    """Return (actor unique ids, actor runtime ids) for non-leading fields."""

    reader = BufferReader(payload)
    unique: set[int] = set()
    runtime: set[int] = set()
    if packet_id == 17:  # TakeItemActor
        runtime.add(reader.uvarint())
        runtime.add(reader.uvarint())
    elif packet_id == 19:  # MovePlayer: player id, movement data, riding id
        runtime.add(reader.uvarint())
        reader.skip(26)
        runtime.add(reader.uvarint())
    elif packet_id == 33:  # Interact: action byte, target runtime id
        reader.skip(1)
        runtime.add(reader.uvarint())
    elif packet_id == 41:  # SetActorLink / ActorLink
        unique.add(reader.varint())
        unique.add(reader.varint())
    elif packet_id in {44, 304}:  # Animate / AgentAnimation
        reader.skip(1)
        runtime.add(reader.uvarint())
    elif packet_id == 45:  # Respawn: Vec3, state, runtime id
        reader.skip(13)
        runtime.add(reader.uvarint())
    elif packet_id == 118:  # SpawnParticleEffect: dimension byte, unique id
        reader.skip(1)
        unique.add(reader.varint())
    elif packet_id == 151:  # game type varint32, target unique id
        reader.varint(bits=32)
        unique.add(reader.varint())
    elif packet_id == 158:  # AnimateEntity
        for _ in range(3):
            reader.string_bytes()
        reader.skip(4)
        reader.string_bytes()
        reader.skip(4)
        count = reader.uvarint(bits=32)
        if count > 10_000:
            raise ProtocolError("animate-entity count is unreasonable")
        for _ in range(count):
            runtime.add(reader.uvarint())
    elif packet_id == 46:  # ContainerOpen: two bytes, BlockPos, unique id
        reader.skip(2)
        reader.varint(bits=32)
        reader.uvarint(bits=32)
        reader.varint(bits=32)
        unique.add(reader.varint())
    elif packet_id in {80, 81}:  # trade/equip headers before unique ids
        reader.skip(2)
        reader.varint(bits=32)
        if packet_id == 80:
            reader.varint(bits=32)
            unique.add(reader.varint())
            unique.add(reader.varint())
        else:
            unique.add(reader.varint())
    elif packet_id == 123:  # LevelSoundEvent
        reader.string_bytes()
        reader.skip(12)
        reader.varint(bits=32)
        reader.string_bytes()
        reader.skip(2)
        unique.add(unpack_from("<q", reader.take(8))[0])
    elif packet_id in {73, 74}:  # Camera / BossEvent begin with two unique ids
        unique.add(reader.varint())
        unique.add(reader.varint())
    elif packet_id == 108:  # SetScore, cerealized per-entry variants in 2168
        count = reader.uvarint(bits=32)
        if count > 10_000:
            raise ProtocolError("score entry count is unreasonable")
        for _ in range(count):
            variant = reader.uvarint(bits=32)
            reader.string_bytes()  # restated action enum name
            reader.varint()  # scoreboard id
            if variant == 0:  # RemoveScore
                present = reader.take(1)[0]
                if present not in {0, 1}:
                    raise ProtocolError("invalid optional flag in score packet")
                if present:
                    reader.string_bytes()
            elif variant in {1, 2, 3}:
                reader.string_bytes()  # objective
                reader.skip(4)  # score value int32
                if variant in {1, 2}:
                    unique.add(reader.varint())
                else:
                    reader.string_bytes()
            else:
                raise ProtocolError(f"unknown score entry variant {variant}")
        if reader.offset != len(payload):
            raise ProtocolError("score packet has trailing bytes")
    elif packet_id == 112:  # SetScoreboardIdentity
        packet_type = reader.take(1)[0]
        if packet_type not in {0, 1}:
            raise ProtocolError("invalid scoreboard identity action")
        count = reader.uvarint(bits=32)
        if count > 10_000:
            raise ProtocolError("scoreboard identity count is unreasonable")
        for _ in range(count):
            reader.varint()  # scoreboard id
            present = reader.take(1)[0]
            if present not in {0, 1}:
                raise ProtocolError("invalid scoreboard identity optional flag")
            if present:
                unique.add(reader.varint())
        if reader.offset != len(payload):
            raise ProtocolError("scoreboard identity packet has trailing bytes")
    return unique, runtime


def packet_mentions_hidden(
    packet_id: int, payload: bytes, identities: tuple[PlayerIdentity, ...]
) -> bool:
    """Return whether a protocol-2168 packet exposes any hidden identity.

    Malformed identity-bearing packets raise ProtocolError.  The caller must
    cancel them (fail closed), never pass them through after an exception.
    """

    if not identities:
        return False
    hidden_uuids = frozenset(identity.uuid for identity in identities)
    runtime_ids = frozenset(identity.runtime_id for identity in identities)
    actor_ids = frozenset(identity.actor_id for identity in identities)

    if packet_id == PLAYER_LIST:
        # This packet is rewritten entry-by-entry by the event adapter.
        return False
    if packet_id == ADD_PLAYER:
        player_uuid, _name, _runtime_id = parse_add_player_header(payload)
        return player_uuid in hidden_uuids
    if packet_id == REMOVE_ACTOR:
        return False
    if packet_id == PLAYER_LOCATION:
        location = parse_player_location(payload)
        # A hidden-location update removes an existing locator marker and is
        # therefore safe. Coordinate updates for vanished players are blocked.
        return location.actor_id in actor_ids and not location.hidden
    if packet_id in _PRIVACY_AMBIGUOUS_PACKETS:
        return True
    if packet_id in _FIRST_RUNTIME_PACKETS and _read_first_uvarint(payload) in runtime_ids:
        return True
    if packet_id in _FIRST_UNIQUE_PACKETS and _read_first_varint(payload) in actor_ids:
        return True
    unique, runtime = _special_actor_ids(packet_id, payload)
    if unique & actor_ids or runtime & runtime_ids:
        return True
    return _contains_hidden_signature(payload, identities)
