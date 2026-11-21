# Replica deployment

Use **Directory Servers → Generate deployment** to obtain a complete stack scoped to the registered replica, with an expiring one-use enrollment token and the correct provider trust. A generic static Compose file cannot safely invent those values.

The canonical templates embedded in each archive are [Compose](../../backend/assets/replica.compose.yaml), [Dockerfile](../../backend/assets/replica.Dockerfile), [prepare script](../../backend/assets/replica.prepare.sh) and [runtime](../../backend/assets/replica.py). They are compiled into the manager and build independently on the second Docker host.

Installation and recovery: [replication guide](../../docs/replication.md).
