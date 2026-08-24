# Endstone Vanish

A protocol-pinned, per-viewer vanish plugin for [Endstone](https://github.com/EndstoneMC/endstone). It removes vanished players from ordinary clients while keeping them visible to trusted staff and other vanished players.

> [!IMPORTANT]
> This release targets **Endstone 0.11.9**, **Bedrock Dedicated Server 1.26.44**, and **Bedrock protocol 2168**. The plugin refuses to enable on another protocol because an outdated packet layout could reveal a vanished player.

## What it does

- Adds a session-scoped `/vanish` toggle.
- Removes vanished players from the world, player list, locator bar, `/list`, and the public server-list player count for ordinary viewers.
- Filters subsequent identity-bearing packets, including movement, skin, metadata, equipment, animation, effects, scoreboard data, maps, and waypoints.
- Restricts chat, death, quit, and skin-change messages from vanished players to authorized viewers.
- Re-evaluates staff access while the server is running, so adding or removing the configured scoreboard tag updates visibility automatically.
- Restores hidden players when they unvanish or when the plugin is disabled.

Authorized viewers are players who are themselves vanished or who carry the configured staff scoreboard tag. Command permission and visibility are intentionally separate: an operator can use `/vanish` by default, but still needs the staff tag to see somebody else who is vanished.

## Compatibility

| Component | Supported version |
| --- | --- |
| Endstone | `0.11.9` / API `0.11` |
| Bedrock Dedicated Server | `1.26.44` |
| Bedrock network protocol | `2168` |
| Python | `3.11+` |

Endstone does not currently expose a native player-visibility API, so this plugin uses the writable [`PacketSendEvent`](https://endstone.dev/latest/reference/python/event/#endstone.event.PacketSendEvent) and protocol layouts published by [EndstoneMC/bedrock-protocol](https://github.com/EndstoneMC/bedrock-protocol) and [EndstoneMC/protocol-docs](https://github.com/EndstoneMC/protocol-docs).

Minecraft for Windows `1.26.4403` requires the locator-hide packet's nested compatibility value to remain zero. The schema-looking logical `HIDE` value is deliberately not emitted because it was observed to disconnect the client with `BadPacket (90)`.

## Installation

1. Build the wheel as described below, or download it from a trusted build.
2. Copy `endstone_vanish-0.1.7-py3-none-any.whl` into the server's `plugins/` directory.
3. Start an Endstone `0.11.9` server running BDS `1.26.44`.
4. Confirm that the log reports protocol `2168` and that Vanish enabled successfully.

Do not bypass the protocol check or install this build on a different Bedrock release.

## Usage

| Item | Value |
| --- | --- |
| Command | `/vanish` |
| Permission | `vanish.command` |
| Default permission | operators only (`op`) |
| Console | rejected; the command is player-only |

The command accepts no arguments. Run it once to vanish and again to become visible.

Grant a staff member visibility with Minecraft's tag command:

```text
/tag PlayerName add admin
```

If you change the tag in the configuration, use that value in the command as well.

## Configuration

On first enable, Endstone copies the packaged `config.toml` into the plugin data directory:

```toml
# Players with this scoreboard tag can see vanished players.
admin_tag = "admin"

# How often to check for tag changes (20 ticks = 1 second).
sync_period_ticks = 20
```

`admin_tag` must be a non-empty string. `sync_period_ticks` must be an integer from `1` through `1200`. Missing or incorrectly typed values produce a warning and use safe defaults; invalid TOML prevents the plugin from enabling before packet handlers are registered.

Vanish state is deliberately not persistent. Quitting, reconnecting, restarting the server, or disabling the plugin clears it.

## Build and test

From the repository root:

```powershell
python -m unittest discover -s tests -v
python -m hatchling build -t wheel
```

The deployable artifact is written to `dist/endstone_vanish-0.1.7-py3-none-any.whl`. Continuous integration runs the test suite across supported Python versions and uploads the built wheel.

## Verification status

The automated suite covers state transitions, authorization, lifecycle behavior, configuration validation, exact protocol encodings, malformed-packet handling, replay caching, and packet filtering. Those tests use framework stubs; they do not replace a Bedrock client test.

Before production use, validate the plugin on an isolated server with three clients:

1. Join alone, toggle `/vanish` twice, and confirm both transitions work without a rejoin.
2. Join as a normal player, an `admin`-tagged player, and the player being vanished.
3. Confirm only the normal client loses the actor, player-list entry, and locator marker.
4. Exercise movement, teleporting, dimension changes, respawning, skin changes, emotes, equipment, effects, death, chat, `/list`, maps, waypoints, and scoreboard changes.
5. Add and remove the admin tag while a player is vanished and confirm immediate resynchronization.
6. Unvanish, reconnect, and disable/re-enable the plugin; confirm no client retains a ghost or missing actor.
7. Ping the server and confirm its public online count excludes vanished sessions.

## Security boundary

Vanish is an in-game network filter, not an access-control boundary inside the server process. The console, logs, other plugins, and Endstone's `server.online_players` API still know that the player exists. Server-side collision, mob targeting, item pickup, and world changes continue and may allow other players to infer a vanished player's presence.

Another plugin can disclose information through custom messages or packets containing only derived world effects. Because Endstone has no native visibility API, this project should not be described as universally packet-complete until the smoke test above passes with the exact server version and plugin set in use. Malformed identity packets are cancelled and ambiguous map/shape packets are handled conservatively so the filter fails closed where the public API permits it.

Please report suspected disclosure or permission-bypass vulnerabilities privately; see [SECURITY.md](SECURITY.md). For reproducible non-security bugs, use the repository's bug-report template.

## License

Endstone Vanish is licensed under the [Apache License 2.0](LICENSE). Endstone and Minecraft are separate projects and are not affiliated with this repository.
