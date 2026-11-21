# Standalone replica stack

This Compose project runs only a replica. Use the same Forklift release/revision as your manager; a second source repository is unnecessary.

1. In Forklift, open **Directory Servers → Add server**, enter the new host's private address and select **Generate join configuration**.
2. Clone this repository on that Linux/Docker machine. Save the copied `FORKLIFT_REPLICA_JOIN=...` line in `deploy/replica/.env`. A Git-based Docker hosting UI can deploy `deploy/replica/compose.yaml` with that environment variable instead.
3. From `deploy/replica`, start the stack:

   ```sh
   docker compose up -d --build
   ```

4. Wait for confirmed synchronization in Forklift. No archive transfer/extraction or separate certificate copy is required. Later credential, certificate and restart operations use the WebUI.

The public primary CA is included. For private WebUI HTTPS PKI, paste its public CA into the optional field before generating the configuration. The replica generates its private key locally and validates HTTPS/LDAPS certificates.

The join setting contains a 15-minute, one-use secret. Encoding is not encryption: protect `.env`, keep it out of Git, and do not share the join line in logs or tickets. Generating another line invalidates the previous one. After successful enrollment, the setting can be removed; persistent replica state supports restarts independently of the manager/primary. Keep its data volume.

See [replication operations](../../docs/replication.md) for private ports, routing, trust, client failover and recovery. The older generated archive remains an API compatibility option, not a prerequisite for this stack.
