from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from endstone_vanish.protocol import (
    ADD_PLAYER,
    LOCATOR_BAR,
    PLAYER_LIST,
    PLAYER_LOCATION,
    PLAYER_SKIN,
    PacketCache,
    ProtocolError,
    ReplayProfile,
    encode_uvarint,
    encode_varint64,
    fallback_add_player,
    fallback_player_list_entry,
    filter_player_list,
    packet_mentions_hidden,
    parse_add_player_header,
    parse_player_location,
    parse_player_list,
    player_location_coordinates,
    player_location_hide,
    LOCATOR_ACTION_REMOVE,
    filter_locator_bar,
    locator_bar_packet,
    parse_locator_bar,
    player_list_packet,
    player_list_remove,
    uuid_from_wire,
    uuid_to_wire,
)
from endstone_vanish.state import PlayerIdentity


STEVE_UUID = UUID("00000000-0000-0001-0000-000000000002")
ALEX_UUID = UUID("00000000-0000-0000-0000-000000000099")


def string(value: str | bytes) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return encode_uvarint(len(raw)) + raw


def add_player_payload(
    player_uuid: UUID = STEVE_UUID, name: str = "Steve", runtime_id: int = 12
) -> bytes:
    # Only the header is needed by the cache/filter; the suffix stands in for
    # the complete server-authored AddPlayer body that is retained byte-for-byte.
    return uuid_to_wire(player_uuid) + string(name) + encode_uvarint(runtime_id) + b"body"


def animated_frame(texture_type: int = 1, frames: float = 4.0, expression: int = 2) -> bytes:
    """One AnimatedImageData: a SkinImage, then uvarint / float / uvarint.

    The two enums are uvarint32, not the fixed uint32 words an older protocol
    used, so a real frame is six bytes past the image rather than twelve.
    """

    return b"".join(
        [
            struct.pack("<II", 1, 1),
            string(b"\x00\x00\x00\x00"),
            encode_uvarint(texture_type),
            struct.pack("<f", frames),
            encode_uvarint(expression),
        ]
    )


LOCATOR_GROUP = UUID("00000000-0000-0000-0000-0000000000aa")


def locator_waypoint(
    group: UUID = LOCATOR_GROUP,
    actor_id: int | None = 7,
    action: int = 1,
    *,
    with_position: bool = True,
) -> bytes:
    """One waypoint entry: handle, UpdateFlag, seven optionals, action."""

    parts = [uuid_to_wire(group), struct.pack("<I", 0)]
    parts.append(b"\x01\x01")  # IsVisible present, true
    if with_position:
        parts.append(b"\x01" + struct.pack("<fff", 1.0, 2.0, 3.0) + encode_varint64(0)[:1])
    else:
        parts.append(b"\x00")
    parts.append(b"\x00")  # TexturePath absent
    parts.append(b"\x00")  # IconSize absent
    parts.append(b"\x00")  # Color absent
    parts.append(b"\x00")  # ClientPositionAuthority absent
    if actor_id is None:
        parts.append(b"\x00")
    else:
        parts.append(b"\x01" + encode_varint64(actor_id))
    parts.append(bytes((action,)))
    return b"".join(parts)

def player_list_add_entry(
    player_uuid: UUID = STEVE_UUID,
    name: str = "Steve",
    actor_id: int = 7,
    animations: int = 0,
) -> bytes:
    skin = b"".join(
        [
            string("sid"),
            string("pfid"),
            string("patch"),
            struct.pack("<II", 1, 1),
            string(b"\x00\x00\x00\x00"),
            encode_uvarint(animations),
            b"".join(animated_frame() for _ in range(animations)),
            struct.pack("<II", 1, 1),
            string(b"\x00\x00\x00\x00"),
            string("geo"),
            string("1.0.0"),
            string("anim"),
            string("cid"),
            string("fid"),
            b"\x01",  # WIDE
            struct.pack("<i", 0x01020304),
            encode_uvarint(0),  # persona pieces
            encode_uvarint(0),  # tint map
            b"\x01\x00\x00\x01\x00",
            string("TRUE"),
            string("hash"),
        ]
    )
    return b"".join(
        [
            encode_uvarint(1),  # variant selects AddEntry
            b"\x00",  # action ADD
            uuid_to_wire(player_uuid),
            encode_varint64(actor_id),
            string(name),
            string("xuid"),
            string("pcid"),
            struct.pack("<i", 8),
            skin,
            b"\x00\x01\x00",
            struct.pack("<i", 0x05060708),
        ]
    )


class PrimitiveTests(unittest.TestCase):
    def test_uuid_wire_layout_matches_protocol(self) -> None:
        expected = bytes.fromhex("01000000000000000200000000000000")
        self.assertEqual(uuid_to_wire(STEVE_UUID), expected)
        self.assertEqual(uuid_from_wire(expected), STEVE_UUID)

    def test_signed_varint_uses_zigzag(self) -> None:
        self.assertEqual(encode_varint64(7), b"\x0e")
        self.assertEqual(encode_varint64(-1), b"\x01")
        with self.assertRaises(ValueError):
            encode_uvarint(-1)

    def test_add_player_header(self) -> None:
        self.assertEqual(
            parse_add_player_header(add_player_payload()),
            (STEVE_UUID, "Steve", 12),
        )
        with self.assertRaises(ProtocolError):
            parse_add_player_header(b"short")


class PlayerListTests(unittest.TestCase):
    def test_parse_protocol_2168_add_and_remove_variants(self) -> None:
        add = player_list_add_entry()
        remove = player_list_remove(ALEX_UUID)[1:]
        entries = parse_player_list(player_list_packet([add, remove]))
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0].is_add)
        self.assertEqual(entries[0].uuid, STEVE_UUID)
        self.assertTrue(entries[1].is_remove)
        self.assertEqual(entries[1].uuid, ALEX_UUID)

    def test_remove_packet_has_exact_2168_shape(self) -> None:
        payload = player_list_remove(STEVE_UUID)
        self.assertEqual(len(payload), 19)
        self.assertEqual(payload[:3], b"\x01\x00\x01")

    def test_filter_removes_only_hidden_add_entries(self) -> None:
        hidden = player_list_add_entry(STEVE_UUID, "Steve", 7)
        visible = player_list_add_entry(ALEX_UUID, "Alex", 8)
        remove = player_list_remove(STEVE_UUID)[1:]
        payload = player_list_packet([hidden, visible, remove])
        filtered = filter_player_list(payload, frozenset({STEVE_UUID}))
        self.assertIsNotNone(filtered)
        entries = parse_player_list(filtered or b"")
        self.assertEqual([entry.uuid for entry in entries], [ALEX_UUID, STEVE_UUID])
        self.assertTrue(entries[1].is_remove)

    def test_filter_cancels_packet_when_all_entries_are_hidden_adds(self) -> None:
        payload = player_list_packet([player_list_add_entry()])
        self.assertIsNone(filter_player_list(payload, frozenset({STEVE_UUID})))

    def test_malformed_player_list_is_rejected(self) -> None:
        with self.assertRaises(ProtocolError):
            parse_player_list(b"\x01\x01\x00")
        with self.assertRaises(ProtocolError):
            parse_player_list(player_list_packet([player_list_add_entry()]) + b"x")


class CacheAndFirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = PlayerIdentity(STEVE_UUID, "Steve", 7, 12)
        self.cache = PacketCache()
        self.add_player = add_player_payload()
        self.list_payload = player_list_packet([player_list_add_entry()])

    def test_cache_requires_both_server_authored_replay_packets(self) -> None:
        self.cache.capture(ADD_PLAYER, self.add_player)
        self.assertFalse(self.cache.ready(STEVE_UUID))
        self.cache.capture(PLAYER_LIST, self.list_payload)
        self.assertTrue(self.cache.ready(STEVE_UUID))
        reveal = self.cache.reveal_packets(STEVE_UUID)
        self.assertEqual([packet_id for packet_id, _ in reveal], [PLAYER_LIST, ADD_PLAYER])

        skin = uuid_to_wire(STEVE_UUID) + b"skin"
        self.cache.capture(PLAYER_SKIN, skin)
        self.assertEqual(
            [packet_id for packet_id, _ in self.cache.reveal_packets(STEVE_UUID)],
            [PLAYER_LIST, ADD_PLAYER, PLAYER_SKIN],
        )

    def test_fallback_packets_are_parseable_and_fill_an_empty_cache(self) -> None:
        profile = ReplayProfile(
            x=1.0,
            y=2.0,
            z=3.0,
            velocity_x=4.0,
            velocity_y=5.0,
            velocity_z=6.0,
            pitch=7.0,
            yaw=8.0,
            skin_width=1,
            skin_height=1,
            skin_data=b"\x01\x02\x03\x04",
        )
        add_player = fallback_add_player(self.identity, profile)
        list_entry = fallback_player_list_entry(self.identity, profile)

        self.assertEqual(
            parse_add_player_header(add_player),
            (STEVE_UUID, "Steve", self.identity.runtime_id),
        )
        self.assertEqual(
            struct.unpack_from("<fff", add_player, 24),
            (1.0, 2.0, 3.0),
        )
        parsed_entries = parse_player_list(player_list_packet([list_entry]))
        self.assertEqual(len(parsed_entries), 1)
        self.assertTrue(parsed_entries[0].is_add)
        self.assertEqual(parsed_entries[0].uuid, STEVE_UUID)

        self.assertTrue(self.cache.ensure_fallback(self.identity, profile))
        self.assertTrue(self.cache.ready(STEVE_UUID))
        self.assertFalse(self.cache.ensure_fallback(self.identity, ReplayProfile()))
        self.assertEqual(self.cache.add_player[STEVE_UUID], add_player)

    def test_player_location_coordinates_and_client_compatible_hide(self) -> None:
        coordinates = player_location_coordinates(
            self.identity, ReplayProfile(x=1.0, y=2.0, z=3.0)
        )
        self.assertEqual(
            coordinates,
            b"\x0e\x00\x00"
            + struct.pack("<fff", 1.0, 2.0, 3.0),
        )
        parsed = parse_player_location(coordinates)
        self.assertEqual(parsed.actor_id, 7)
        self.assertFalse(parsed.hidden)
        self.assertEqual(parsed.position, (1.0, 2.0, 3.0))

        hidden = player_location_hide(self.identity)
        # The variant twice, in two encodings: uvarint32 1, then zigzag varint32 1.
        self.assertEqual(hidden, b"\x0e\x01\x02")
        self.assertTrue(parse_player_location(hidden).hidden)
        # Both ways of getting the double encoding wrong. 0x02 0x02 reads the
        # first field as zigzag when it is unsigned; 0x01 0x00 leaves the second
        # at the old hardcoded zero, which tells the client "coordinates" and
        # sends it looking for a Vec3 that was never written. Either one is a
        # BadPacket (90) disconnect on Minecraft for Windows 1.26.4403.
        for wrong in (b"\x0e\x02\x02", b"\x0e\x01\x00"):
            with self.assertRaises(ProtocolError):
                parse_player_location(wrong)

    def test_player_list_entry_with_animated_skin_frames_parses(self) -> None:
        """A persona / 4D skin carries animated frames; a classic skin carries none.

        This is the case the rest of the fixtures never covered, and the one that
        actually broke. AnimatedImageData ends in uvarint / float / uvarint, and
        skipping a fixed twelve bytes over-reads by six per frame. The entry then
        failed to parse, the player got no server-authored replay cached, and the
        synthesised fallback took over - which is what disconnected their viewers.
        Only players with animated skins were affected, so it looked like the bug
        followed a particular PC rather than a particular skin.
        """

        for frames in (1, 2, 5):
            payload = player_list_packet([player_list_add_entry(animations=frames)])

            entries = parse_player_list(payload)

            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0].is_add)
            self.assertEqual(entries[0].uuid, STEVE_UUID)
            # The whole entry has to be consumed exactly, or the next one in a
            # multi-entry packet lands on the wrong byte.
            self.assertEqual(entries[0].raw, payload[1:])

    def test_animated_and_classic_entries_stay_aligned_in_one_packet(self) -> None:
        payload = player_list_packet(
            [
                player_list_add_entry(animations=3),
                player_list_add_entry(player_uuid=ALEX_UUID, name="Alex", actor_id=8),
            ]
        )

        entries = parse_player_list(payload)

        self.assertEqual([e.uuid for e in entries], [STEVE_UUID, ALEX_UUID])

    def test_server_packets_replace_fallback_packets(self) -> None:
        self.cache.ensure_fallback(self.identity, ReplayProfile())
        self.cache.capture(ADD_PLAYER, self.add_player)
        self.cache.capture(PLAYER_LIST, self.list_payload)
        self.assertEqual(self.cache.add_player[STEVE_UUID], self.add_player)
        self.assertEqual(
            self.cache.player_list_add[STEVE_UUID], player_list_add_entry()
        )

    def test_cache_forget_and_incomplete_reveal(self) -> None:
        with self.assertRaises(ProtocolError):
            self.cache.reveal_packets(STEVE_UUID)
        self.cache.capture(ADD_PLAYER, self.add_player)
        self.cache.capture(PLAYER_LIST, self.list_payload)
        self.cache.forget(STEVE_UUID)
        self.assertFalse(self.cache.ready(STEVE_UUID))

    def test_hide_packets_remove_the_waypoint_then_the_player(self) -> None:
        """Clearing the locator marker takes a LocatorBar removal and nothing else.

        Removing the actor and the player-list entry does not clear it, a
        PlayerLocation hide strands one at the last known position, and moving the
        marker far away does not move it either - all three were tried against a
        live client, twice with the proxy taken out of the path. The bar is
        waypoint-driven, so only a packet 341 can delete a marker.
        """

        self.cache.capture(LOCATOR_BAR, locator_bar_packet([locator_waypoint()]))

        hide = self.cache.hide_packets(self.identity)

        self.assertEqual([packet_id for packet_id, _ in hide], [LOCATOR_BAR, 14, 63])
        removal = parse_locator_bar(hide[0][1])
        self.assertEqual(len(removal), 1)
        self.assertEqual(removal[0].group, LOCATOR_GROUP)
        self.assertEqual(removal[0].action, LOCATOR_ACTION_REMOVE)
        self.assertEqual(hide[1], (14, b"\x0e"))
        self.assertEqual(hide[2], (63, player_list_remove(STEVE_UUID)))

    def test_hide_packets_skip_the_waypoint_when_none_was_seen(self) -> None:
        """A group handle can only be learned from the server; never invent one."""

        hide = self.cache.hide_packets(self.identity)

        self.assertEqual([packet_id for packet_id, _ in hide], [14, 63])

    def test_reveal_replays_the_waypoint(self) -> None:
        self.cache.capture(LOCATOR_BAR, locator_bar_packet([locator_waypoint()]))
        self.cache.ensure_fallback(self.identity, ReplayProfile())

        reveal = self.cache.reveal_packets(STEVE_UUID)

        self.assertEqual(reveal[-1][0], LOCATOR_BAR)
        replayed = parse_locator_bar(reveal[-1][1])
        self.assertEqual(replayed[0].group, LOCATOR_GROUP)
        self.assertEqual(replayed[0].actor_id, 7)

    def test_a_removal_forgets_the_cached_waypoint(self) -> None:
        self.cache.capture(LOCATOR_BAR, locator_bar_packet([locator_waypoint()]))
        self.cache.capture(
            LOCATOR_BAR,
            locator_bar_packet([locator_waypoint(action=LOCATOR_ACTION_REMOVE)]),
        )

        self.assertIsNone(self.cache.locator_add.get(LOCATOR_GROUP))

    def test_filter_keeps_other_players_waypoints(self) -> None:
        """The collateral damage of cancelling the whole packet, pinned.

        One LocatorBar packet carries waypoints for several players. Dropping all
        of it froze every marker on the server for as long as anyone was vanished.
        """

        other = UUID("00000000-0000-0000-0000-0000000000bb")
        payload = locator_bar_packet(
            [locator_waypoint(), locator_waypoint(group=other, actor_id=99)]
        )

        filtered = filter_locator_bar(payload, frozenset({7}), frozenset({LOCATOR_GROUP}))

        self.assertIsNotNone(filtered)
        kept = parse_locator_bar(filtered)
        self.assertEqual([entry.group for entry in kept], [other])

    def test_filter_cancels_when_nothing_survives(self) -> None:
        payload = locator_bar_packet([locator_waypoint()])

        self.assertIsNone(
            filter_locator_bar(payload, frozenset({7}), frozenset({LOCATOR_GROUP}))
        )

    def test_a_waypoint_without_an_actor_id_is_left_alone(self) -> None:
        """Server waypoints that follow nobody are not a privacy concern."""

        payload = locator_bar_packet([locator_waypoint(actor_id=None)])

        filtered = filter_locator_bar(payload, frozenset({7}), frozenset())

        self.assertEqual(filtered, payload)

    def test_firewall_blocks_spawn_move_skin_and_embedded_name(self) -> None:
        identities = (self.identity,)
        self.assertTrue(packet_mentions_hidden(ADD_PLAYER, self.add_player, identities))
        self.assertTrue(packet_mentions_hidden(19, encode_uvarint(12) + b"move", identities))
        self.assertTrue(
            packet_mentions_hidden(PLAYER_SKIN, uuid_to_wire(STEVE_UUID) + b"skin", identities)
        )
        self.assertTrue(packet_mentions_hidden(200, string("Steve"), identities))
        visible_move = encode_uvarint(99) + b"\x00" * 26 + encode_uvarint(99)
        self.assertFalse(packet_mentions_hidden(19, visible_move, identities))
        self.assertFalse(packet_mentions_hidden(14, encode_varint64(7), identities))

    def test_firewall_blocks_locator_coordinates_but_allows_locator_hide(self) -> None:
        identities = (self.identity,)
        coordinates = player_location_coordinates(
            self.identity, ReplayProfile(x=1.0, y=2.0, z=3.0)
        )
        self.assertTrue(
            packet_mentions_hidden(PLAYER_LOCATION, coordinates, identities)
        )
        self.assertFalse(
            packet_mentions_hidden(
                PLAYER_LOCATION, player_location_hide(self.identity), identities
            )
        )

        other = PlayerIdentity(ALEX_UUID, "Alex", 99, 100)
        self.assertFalse(
            packet_mentions_hidden(
                PLAYER_LOCATION,
                player_location_coordinates(other, ReplayProfile()),
                identities,
            )
        )

    def test_firewall_parses_nonleading_actor_ids(self) -> None:
        identities = (self.identity,)
        self.assertTrue(packet_mentions_hidden(44, b"\x01" + encode_uvarint(12), identities))
        self.assertTrue(
            packet_mentions_hidden(
                41, encode_varint64(7) + encode_varint64(99), identities
            )
        )
        respawn = b"\x00" * 13 + encode_uvarint(12)
        self.assertTrue(packet_mentions_hidden(45, respawn, identities))

        # Protocol-2168 SetScore ChangePlayer entry referencing actor id 7.
        score = b"".join(
            [
                encode_uvarint(1),
                encode_uvarint(1),
                string("ChangePlayer"),
                encode_varint64(1),
                string("objective"),
                struct.pack("<i", 5),
                encode_varint64(7),
            ]
        )
        self.assertTrue(packet_mentions_hidden(108, score, identities))

        scoreboard_identity = b"".join(
            [b"\x00", encode_uvarint(1), encode_varint64(1), b"\x01", encode_varint64(7)]
        )
        self.assertTrue(packet_mentions_hidden(112, scoreboard_identity, identities))

    def test_ambiguous_map_shape_and_waypoint_packets_are_blocked(self) -> None:
        identities = (self.identity,)
        self.assertTrue(packet_mentions_hidden(67, b"map", identities))
        self.assertTrue(packet_mentions_hidden(328, b"shapes", identities))
        # 341 is no longer opaque: it is parsed and filtered per waypoint, because
        # cancelling the packet freezes the bar for everyone and makes the vanished
        # player's own marker unremovable.
        self.assertFalse(
            packet_mentions_hidden(LOCATOR_BAR, locator_bar_packet([locator_waypoint()]), identities)
        )

    def test_malformed_identity_packet_raises_for_fail_closed_adapter(self) -> None:
        with self.assertRaises(ProtocolError):
            packet_mentions_hidden(19, b"\x80", (self.identity,))


if __name__ == "__main__":
    unittest.main()
