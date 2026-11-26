import { Help } from "./Help";
import { NodePairing, PairingCard, useNodePairing } from "./NodePairing";
import { Database, Trash2 } from "lucide-react";
export type DirectoryNode = {
  id: string;
  name: string;
  endpoint: string;
  provider?: string;
  role: "primary" | "replica" | "provider";
  state: string;
  enrollment_state?: string;
  reachable: boolean;
  checked_at: number | null;
  last_sync_at?: number | null;
  context_csn?: string[] | null;
  expires_at?: number;
  error?: string | null;
  certificate_rotation_pending?: boolean;
  credential_rotated_at?: number | null;
  credential_epoch?: number;
  address?: string;
  control_port?: number;
  pending_epoch?: number | null;
  provider_needs_update?: boolean;
};
export type DirectoryHealth = {
  servers: DirectoryNode[];
  primary_available: boolean;
  checked_at: number;
};
type Props = {
  health: DirectoryHealth;
  busy: boolean;
  readOnly: boolean;
  api: (path: string, method?: string, body?: unknown) => Promise<unknown>;
  perform: (f: () => Promise<void>) => Promise<void>;
  refresh: () => Promise<void>;
};
const labels: Record<string, string> = {
  ready: "Ready",
  pending: "Awaiting enrollment",
  redeeming: "Enrollment in progress",
  enrolled: "Enrolled",
  expired: "Enrollment expired",
  failed: "Enrollment failed",
  restore_required: "Restored snapshot · reseed required",
  synchronized: "Synchronization confirmed",
  catching_up: "Catching up",
  unreachable: "Unreachable / TLS error",
  unavailable: "LDAP query failed",
  primary_unavailable: "Directory Server unavailable · sync unconfirmed",
};
const date = (timestamp?: number | null) =>
  timestamp ? new Date(timestamp * 1000).toLocaleString() : "Not confirmed";
export function Servers({
  health,
  busy,
  readOnly,
  api,
  perform,
  refresh,
}: Props) {
  const pairing = useNodePairing(api, refresh);
  async function rotateCredential(node: DirectoryNode) {
    if (
      !confirm(
        "Rotate and apply this replica's credentials now? Forklift restarts its directory and verifies the management response; check synchronization afterward.",
      )
    )
      return;
    await perform(async () => {
      await api(`replicas/${node.id}/credential`, "POST", {
        acknowledge: true,
      });
      await refresh();
    });
  }

  return (
    <>
      <section className="panel">
        <div className="table-toolbar">
          <div>
            <div className="heading-help">
              <h2>
                Directory servers{" "}
                <span className="muted">{health.servers.length}</span>
              </h2>
              <Help label="Directory server enrollment">
                To add a directory server, approve pairing here and choose
                Join Existing Installation on the new node. Once it has synced,
                add it to your Linux sign-in settings for backup access. A
                disconnected node cannot receive new password changes or
                account restrictions.
              </Help>
            </div>
            <small>
              Checked {date(health.checked_at)} · verified LDAP connections
            </small>
          </div>
        </div>
        <NodePairing pairing={pairing} disabled={busy || readOnly} />
        <div className="server-grid">
          {health.servers.map((node) => (
            <section key={node.id} className="server-card">
              <div className="panel-title">
                <div className="identity">
                  <span className="avatar">
                    <Database size={18} />
                  </span>
                  <div>
                    <h3>{node.name}</h3>
                    <small>Directory Server</small>
                  </div>
                </div>
                {node.role === "replica" && (
                  <div className="actions">
                    <button
                      aria-label="Remove server"
                      disabled={busy || readOnly}
                      onClick={() => {
                        if (
                          confirm(
                            "Stop this replica first, then remove it and revoke its replication bind identity? Its remote data and existing LDAP connections are not destroyed.",
                          )
                        )
                          perform(async () => {
                            await api(`replicas/${node.id}`, "DELETE");
                            await refresh();
                          });
                      }}
                    >
                      <Trash2 size={17} />
                    </button>
                  </div>
                )}
              </div>
              <span
                className={
                  ["ready", "synchronized"].includes(node.state)
                    ? "pill"
                    : "badge"
                }
              >
                {labels[node.state] || node.state}
              </span>
              <dl>
                <div>
                  <dt>
                    {node.role === "primary"
                      ? "Private directory address"
                      : "Private directory address"}
                  </dt>
                  <dd>{node.endpoint}</dd>
                </div>
                {node.provider && (
                  <div>
                    <dt>Provider</dt>
                    <dd>{node.provider}</dd>
                  </div>
                )}
                <div>
                  <dt>LDAP connectivity</dt>
                  <dd>
                    {node.reachable
                      ? "Verified bind and query"
                      : node.enrollment_state === "pending"
                        ? "Not enrolled"
                        : "Not confirmed"}
                  </dd>
                </div>
                {node.role !== "primary" && (
                  <div>
                    <dt>Last confirmed synchronization</dt>
                    <dd>{date(node.last_sync_at)}</dd>
                  </div>
                )}
                {node.enrollment_state === "pending" && !!node.expires_at && (
                  <div>
                    <dt>Enrollment expires</dt>
                    <dd>{date(node.expires_at)}</dd>
                  </div>
                )}
              </dl>
              {node.role === "replica" &&
                node.enrollment_state === "enrolled" && (
                  <details>
                    <summary>Credentials & certificate rotation</summary>
                    <p className="hint">
                      Credential update issued:{" "}
                      {date(node.credential_rotated_at)} · epoch{" "}
                      {node.credential_epoch ?? 0}. Issued time does not confirm
                      remote deployment.
                    </p>
                    <button
                      className="secondary"
                      disabled={busy || readOnly || node.provider_needs_update}
                      onClick={() => rotateCredential(node)}
                    >
                      {node.pending_epoch
                        ? "Resume credential update"
                        : "Rotate and apply credentials"}
                    </button>
                    {node.provider_needs_update && (
                      <button
                        className="secondary"
                        disabled={busy || readOnly}
                        onClick={() =>
                          perform(async () => {
                            await api(`replicas/${node.id}/reconnect`, "POST", {
                              acknowledge: true,
                            });
                            await refresh();
                          })
                        }
                      >
                        Reconnect to the local Directory Server
                      </button>
                    )}
                    <button
                      className="secondary"
                      disabled={busy || readOnly}
                      onClick={() => {
                        if (
                          confirm(
                            "Restart this replica's directory process while preserving its data?",
                          )
                        )
                          perform(async () => {
                            await api(`replicas/${node.id}/restart`, "POST", {
                              acknowledge: true,
                            });
                            await refresh();
                          });
                      }}
                    >
                      Restart directory
                    </button>
                    {node.certificate_rotation_pending ? (
                      <>
                        <div className="help-row">
                          <button
                            className="secondary"
                            disabled={busy || readOnly || !!node.pending_epoch}
                            onClick={() => {
                              if (
                                confirm(
                                  "Client trust is deployed. Activate the candidate, verify it and retire the previous key?",
                                )
                              )
                                perform(async () => {
                                  await api(
                                    `replicas/${node.id}/certificate/finalize`,
                                    "POST",
                                    { acknowledge: true },
                                  );
                                  await refresh();
                                });
                            }}
                          >
                            Activate and verify certificate
                          </button>
                          <Help label="Activating a replica certificate">
                            First install updated trust files on the Linux
                            machines that use this replica. Then activate its
                            new certificate here. Forklift checks the change
                            before retiring the old certificate. Download and
                            install the final client configurations afterward.
                          </Help>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="help-row">
                          <button
                            className="secondary"
                            disabled={busy || readOnly || !!node.pending_epoch}
                            onClick={() =>
                              perform(async () => {
                                await api(
                                  `replicas/${node.id}/certificate`,
                                  "POST",
                                  { acknowledge: true },
                                );
                                await refresh();
                              })
                            }
                          >
                            Generate renewal certificate
                          </button>
                          <Help label="Staging a replica certificate">
                            Forklift creates the new certificate on this server.
                            Its private key stays there. You do not need to
                            upload a certificate or run commands.
                          </Help>
                        </div>
                      </>
                    )}
                  </details>
                )}
              {pairing.status?.peers
                .filter((peer) => peer.server_id === node.id)
                .map((peer) => (
                  <PairingCard
                    key={peer.id}
                    peer={peer}
                    pairing={pairing}
                    disabled={busy || readOnly}
                  />
                ))}
              {node.error && <p className="hint server-error">{node.error}</p>}
              {node.context_csn?.length ? (
                <details>
                  <summary>Synchronization context</summary>
                  <code>{node.context_csn.join("\n")}</code>
                </details>
              ) : null}
            </section>
          ))}
          {pairing.status?.peers
            .filter(
              (peer) =>
                !health.servers.some((node) => node.id === peer.server_id),
            )
            .map((peer) => (
              <section className="server-card" key={peer.id}>
                <h3>
                  {peer.server_id
                    ? "Directory node"
                    : peer.active
                      ? "Unassigned pairing"
                      : "Pending node"}
                </h3>
                <PairingCard
                  peer={peer}
                  pairing={pairing}
                  disabled={busy || readOnly}
                />
              </section>
            ))}
        </div>
      </section>
    </>
  );
}
