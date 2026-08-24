# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub's [security advisory form](https://github.com/luibara2/endstone-vanish/security/advisories/new). Include the affected version, server and client versions, reproduction steps, expected impact, and any relevant packet capture or proof of concept. Remove unrelated player data, access tokens, and server addresses before attaching logs or captures.

## In scope

The most important reports are:

- a vanished player's identity, position, skin, messages, or player-list presence reaching an unauthorized client on the supported protocol;
- a malformed packet causing the visibility filter to fail open;
- bypassing the `vanish.command` permission or the configured viewer tag;
- a remotely reachable crash or resource-exhaustion problem introduced by this plugin.

## Out of scope

- Information visible to the server console, logs, Endstone APIs, or other in-process plugins.
- Presence inferred from server-side gameplay such as collision, mob behavior, item pickup, or world changes.
- Unsupported Endstone, BDS, client, or Bedrock protocol versions.
- Vulnerabilities in Minecraft, Bedrock Dedicated Server, Endstone, or another plugin that are not caused by this project.

## Supported versions

Security fixes are made on `main` and released from the latest supported version. This project does not maintain long-term support branches. The current build is intentionally pinned to the exact versions documented in the README.
