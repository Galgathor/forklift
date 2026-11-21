import { useState } from "react";
import {
  Database,
  Plus,
  Download,
  Trash2,
  X,
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
};
export type DirectoryHealth = {
  servers: DirectoryNode[];
  primary_available: boolean;
  checked_at: number;
};
type Props = {
  health: DirectoryHealth;
  csrf: string;
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
  csrf,
  busy,
  readOnly,
  api,
  perform,
  refresh,
}: Props) {
  const [adding, setAdding] = useState(false),
    [error, setError] = useState(""),
    [saving, setSaving] = useState(false);
  async function download(node: DirectoryNode) {
    if (
      !confirm(
        "This private deployment bundle contains a one-use enrollment token valid for 15 minutes. Enroll only a trusted server: replication includes password hashes. Generate the bundle?",
      )
    )
      return;
    await perform(async () => {
      const r = await fetch(`/api/replicas/${node.id}/bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ acknowledge: true }),
      });
      if (!r.ok) {
        const v = await r.json();
        throw Error(v.error || "Unable to generate deployment");
      }
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `forklift-replica-${node.id}.tar.gz`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
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
              setError("");
              setAdding(true);
            }}
          >
            <Plus size={17} />
            Add server
          </button>
        </div>
        <p className="hint">
          One writable primary, independent read-only replicas. Native OpenLDAP
          Syncrepl keeps identities and passwords synchronized. No automatic
          promotion.
        </p>
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
                        title="Generate deployment bundle"
                        aria-label="Generate replica deployment"
                        disabled={busy || readOnly}
                        onClick={() => download(node)}
                      >
                        <Download size={18} />
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
                  <dt>LDAPS endpoint</dt>
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
          <h3>Authentication keeps running independently.</h3>
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
            Add its reachable LDAPS DNS endpoint and the primary endpoint it
            will use.
          </li>
          <li>
            Generate a deployment bundle, transfer it privately and extract it
            on that server.
          </li>
          <li>
            Run <code>./prepare.sh</code>, set its private bind address in{" "}
            <code>.env</code>, then run{" "}
            <code>docker compose up -d --build</code> before the token expires.
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
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Add directory server"
          >
            <div className="panel-title">
              <h2>Add read-only replica</h2>
              <button aria-label="Close" onClick={() => setAdding(false)}>
                <X />
              </button>
            </div>
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const form = new FormData(e.currentTarget);
                setSaving(true);
                setError("");
                try {
                  await api(
                    "directory-servers",
                    "POST",
                    Object.fromEntries(form),
                  );
                  setAdding(false);
                  await refresh();
                } catch (e) {
                  setError((e as Error).message);
                } finally {
                  setSaving(false);
                }
              }}
            >
              <label>
                Friendly name
                <input
                  name="name"
                  placeholder="Garage directory"
                  maxLength={100}
                  required
                />
              </label>
              <label>
                Replica LDAPS endpoint
                <input
                  name="endpoint"
                  placeholder="ldaps://ldap2.homelab.internal:636"
                  required
                />
              </label>
              <label>
                Primary LDAPS endpoint, reachable from the replica
                <input
                  name="provider"
                  placeholder="ldaps://ldap1.homelab.internal:636"
                  required
                />
              </label>
              <p className="hint">
                The replica DNS name must point to its private address. Its
                provider must present a certificate signed by this
                installation’s CA. A private, one-use deployment bundle is
                generated after registration.
              </p>
              <button className="primary" disabled={saving}>
                {saving ? "Registering…" : "Register replica"}
              </button>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
