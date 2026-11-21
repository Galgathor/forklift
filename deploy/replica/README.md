# Replica deployment

Use **Directory Servers → Add server** to download a private, preconfigured Compose project. The primary connection is inherited from first-launch setup. The new Linux machine needs Docker, private routing and reachable WebUI HTTPS; it does not need an existing LDAP installation.

The generated archive embeds [Compose](../../backend/assets/replica.compose.yaml), [Dockerfile](../../backend/assets/replica.Dockerfile) and the [fixed-operation runtime](../../backend/assets/replica.py). Compose prepares protected enrollment permissions automatically. All later directory maintenance uses the WebUI.

See [the replication guide](../../docs/replication.md) for ports, trust, enrollment, certificate/credential rotation and failure behavior.
