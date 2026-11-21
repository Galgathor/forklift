import { useState } from "react";
import { ReplicaWizard } from "./ReplicaWizard";
import {
  Database,
  Plus,
  Download,
  Trash2,
  ShieldCheck,
  Activity,
} from "lucide-react";
export type DirectoryNode = {
  id: string;
  name: string;
  endpoint: string;
  provider?: string;
  role: "primary" | "replica";
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
  ready: "Primary ready",
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
  primary_unavailable: "Primary unavailable · sync unconfirmed",
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
  const [adding, setAdding] = useState(false),
    [resuming, setResuming] = useState<DirectoryNode | undefined>();
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
            <h2>
              Directory servers{" "}
              <span className="muted">{health.servers.length}</span>
            </h2>
            <small>
              Checked {date(health.checked_at)} · verified LDAP connections
            </small>
          </div>
          <button
            className="primary"
            disabled={busy || readOnly}
            onClick={() => {
              setResuming(undefined);
              setAdding(true);
            }}
          >
            <Plus size={17} />
            Add server
          </button>
        </div>
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
                    <small>
                      {node.role === "primary"
                        ? "Read / write primary"
                        : "Read / authentication replica"}
                    </small>
                  </div>
                </div>
                {node.role === "replica" && (
                  <div className="actions">
                    {["pending", "failed", "expired"].includes(node.state) && (
                      <button
                        title="Generate join configuration"
                        aria-label="Generate replica deployment"
                        disabled={busy || readOnly}
                        onClick={() => {
                          setResuming(node);
                          setAdding(true);
                        }}
                      >
                        <Download size={18} /> Continue setup
                      </button>
                    )}
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
                {node.role === "replica" && (
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
                        Reconnect to current primary
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
                        <p className="hint">
                          The candidate certificate is already trusted by
                          Forklift. Deploy updated trust bundles to affected
                          Linux clients before activation. Activation verifies
                          the actual new certificate, retires the previous
                          private pair and marks client bundles for final trust
                          export.
                        </p>
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
                      </>
                    ) : (
                      <>
                        <p className="hint">
                          Forklift generates the candidate directly on this
                          server. Its private key stays there; no command or
                          certificate upload is required.
                        </p>
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
                      </>
                    )}
                  </details>
                )}
              {node.error && <p className="hint server-error">{node.error}</p>}
              {node.context_csn?.length ? (
                <details>
                  <summary>Synchronization context</summary>
                  <code>{node.context_csn.join("\n")}</code>
                </details>
              ) : null}
            </section>
          ))}
        </div>
      </section>
      <section className="callout">
        <ShieldCheck size={24} />
        <div>
          <h3>Client failover</h3>
          <p>
            After synchronization is confirmed, add the replica to each Linux
            host’s endpoints and deploy a new host bundle to include its pinned
            certificate. Synchronization status is sampled; revocations made
            during an outage cannot reach an isolated replica.
          </p>
        </div>
      </section>
      <section className="panel">
        <div className="panel-title">
          <h2>Enroll a second Docker host</h2>
          <Activity size={18} />
        </div>
        <ol className="steps">
          <li>
            Open Add server. The primary address comes from your initial setup.
          </li>
          <li>
            Enter the new machine’s name and private address. It only needs
            Docker; Forklift creates the new directory and its TLS certificate.
          </li>
          <li>
            Generate a join configuration, paste it into the standalone replica
            stack in deploy/replica, and start that Compose stack.
          </li>
          <li>
            Wait for confirmed synchronization here, then update your Linux
            client configurations.
          </li>
        </ol>
        <p className="hint">
          Manager HTTPS is required for enrollment. Replicas generate private
          keys locally; no CA signing key is copied. See docs/replication.md for
          network, trust, recovery and certificate-lifecycle details.
        </p>
      </section>
      {adding && (
        <ReplicaWizard
          existing={resuming}
          health={health}
          readOnly={readOnly}
          api={api}
          refresh={refresh}
          close={() => setAdding(false)}
        />
      )}
    </>
  );
}
