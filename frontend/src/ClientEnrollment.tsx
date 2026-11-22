import { useState } from "react";
import { X } from "lucide-react";
import { FieldHelp, Help } from "./Help";
import { ClientReplica } from "./ClientReplica";
import { ClientDiagnostics } from "./ClientDiagnostics";
import { ClientMonitoring } from "./ClientMonitoring";
import { ConfirmDialog } from "./ConfirmDialog";
export type ClientIdentity = {
  hostname: string;
  fqdn: string | null;
  os: string;
  os_version: string;
  architecture: string;
  kernel: string;
  client_version: string;
  addresses: { interface: string; address: string }[];
  capabilities: string[];
};
export type ClientRecord = {
  id: string;
  identity: ClientIdentity;
  key_fingerprint: string;
  state: string;
  host_id: string | null;
  created_at: number;
  expires_at: number;
  enrolled_at: number | null;
  last_contact: number | null;
  credentials?: {
    generation: number;
    rotated_at: number | null;
    next_rotation_at: number;
    rotation_due: boolean;
    pending: {
      id: string;
      expires_at: number;
      key_fingerprint: string;
      expired: boolean;
    } | null;
  };
  monitoring?: {
    diagnostics?: {
      health: string;
      active_issues: number;
      received_at: number | null;
      fresh: boolean;
    };
    connectivity: string;
    received_at: number | null;
    interval: number | null;
    offline_after: number;
    interfaces: string[];
    inventory: ClientIdentity | null;
    dns: { state: string; error?: string | null } | null;
  };
};
type Inventory = {
  id: string;
  name: string;
  hostname: string;
  revision: number;
  client?: ClientRecord | null;
};
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
const date = (at: number | null) =>
  at ? new Date(at * 1000).toLocaleString() : "Not yet confirmed";
function Machine({
  client,
  live = false,
}: {
  client: ClientRecord;
  live?: boolean;
}) {
  const i = (live && client.monitoring?.inventory) || client.identity;
  return (
    <dl>
      <div>
        <dt>Hostname</dt>
        <dd>{i.hostname}</dd>
      </div>
      <div>
        <dt>FQDN</dt>
        <dd>{i.fqdn || "Not reported"}</dd>
      </div>
      <div>
        <dt>
          {live && client.monitoring?.inventory
            ? "Reported system"
            : "Enrollment system"}
        </dt>
        <dd>
          {i.os} {i.os_version} · {i.architecture}
        </dd>
      </div>
      <div>
        <dt>Kernel</dt>
        <dd>{i.kernel}</dd>
      </div>
      <div>
        <dt>Client version</dt>
        <dd>{i.client_version}</dd>
      </div>
      <div>
        <dt>
          {live && client.monitoring?.inventory
            ? "Reported addresses"
            : "Enrollment addresses"}
        </dt>
        <dd>
          {i.addresses.map((a) => (
            <div key={a.interface + a.address}>
              {a.interface}: {a.address}
            </div>
          ))}
        </dd>
      </div>
      <div>
        <dt>Machine key</dt>
        <dd>
          <code>{client.key_fingerprint}</code>
        </dd>
      </div>
    </dl>
  );
}
export function ClientEnrollment({
  api,
  hosts,
  close,
  refresh,
}: {
  api: Api;
  hosts: Inventory[];
  close: () => void;
  refresh: () => Promise<void>;
}) {
  const [code, setCode] = useState(""),
    [pending, setPending] = useState<ClientRecord | null>(null),
    [target, setTarget] = useState(""),
    [name, setName] = useState(""),
    [verified, setVerified] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [approved, setApproved] = useState(false);
  async function perform(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="overlay">
      <section
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Join existing machine"
      >
        <div className="panel-title">
          <div className="heading-help">
            <h2>Join existing machine</h2>
            <Help label="Machine pairing">
              Run forklift-client join on the Linux machine and enter its code
              here before it expires. Check that the displayed name, addresses
              and key fingerprint match that machine. Pairing enables
              monitoring; it does not set up Linux or SSH sign-in.
            </Help>
          </div>
          <button
            type="button"
            disabled={busy}
            aria-label="Close machine pairing"
            onClick={close}
          >
            <X />
          </button>
        </div>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {!pending ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void perform(async () => {
                const found = (await api("clients/lookup", "POST", {
                  code,
                })) as ClientRecord;
                setPending(found);
                setName(found.identity.hostname);
              });
            }}
          >
            <label>
              Pairing code
              <input
                aria-label="Pairing code"
                value={code}
                maxLength={9}
                autoComplete="off"
                placeholder="K7M2-P9Q4"
                onChange={(e) => setCode(e.target.value.toUpperCase())}
                required
              />
            </label>
            <button className="primary" disabled={busy}>
              {busy ? "Finding…" : "Find machine"}
            </button>
          </form>
        ) : (
          <>
            <Machine client={pending} />
            {approved ? (
              <>
                <p role="status">
                  Enrollment approved. The client can now finish pairing on the
                  machine.
                </p>
                <button className="secondary" onClick={close}>
                  Done
                </button>
              </>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void perform(async () => {
                    const host = hosts.find((h) => h.id === target);
                    await api(`clients/${pending.id}/approve`, "POST", {
                      name,
                      host_id: target || null,
                      host_revision: host?.revision || null,
                      acknowledge: verified,
                    });
                    setApproved(true);
                    await refresh();
                  });
                }}
              >
                <FieldHelp
                  label="Linking machine inventory"
                  caption="Inventory target"
                  help={
                    <>
                      Create a host entry or choose an existing one to link.
                      Check the machine carefully; matching names or addresses
                      do not automatically link hosts. Linking keeps its login
                      groups and DNS settings. Revoke the old client before
                      replacing it.
                    </>
                  }
                >
                  <select
                    aria-label="Inventory target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  >
                    <option value="">Create a new host</option>
                    {hosts
                      .filter(
                        (h) =>
                          !h.client ||
                          !["approved", "active"].includes(h.client.state),
                      )
                      .map((h) => (
                        <option key={h.id} value={h.id}>
                          {h.name} · {h.hostname}
                        </option>
                      ))}
                  </select>
                </FieldHelp>
                {!target && (
                  <label>
                    Friendly host name
                    <input
                      aria-label="Friendly host name"
                      value={name}
                      required
                      maxLength={100}
                      onChange={(e) => setName(e.target.value)}
                    />
                  </label>
                )}
                <small>Pairing expires {date(pending.expires_at)}</small>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={verified}
                    onChange={(e) => setVerified(e.target.checked)}
                  />
                  I verified this machine and the selected inventory target.
                </label>
                <div className="wizard-actions">
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy}
                    onClick={() => {
                      setPending(null);
                      setVerified(false);
                      setTarget("");
                    }}
                  >
                    Back
                  </button>
                  <button className="primary" disabled={busy || !verified}>
                    {busy ? "Approving…" : "Approve enrollment"}
                  </button>
                </div>
              </form>
            )}
          </>
        )}
      </section>
    </div>
  );
}
export function ClientDetails({
  client,
  api,
  close,
  refresh,
}: {
  client: ClientRecord;
  api: Api;
  close: () => void;
  refresh: () => Promise<void>;
}) {
  const [rotate, setRotate] = useState(false),
    [rotationNotice, setRotationNotice] = useState("");
  const supportsRotation = (
    client.monitoring?.inventory || client.identity
  ).capabilities.includes("rotation-v1");
  const [confirm, setConfirm] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <>
      <div className="overlay">
        <section
          className="dialog"
          role="dialog"
          aria-modal="true"
          aria-label="Client enrollment details"
        >
          <div className="panel-title">
            <div className="heading-help">
              <h2>Client enrollment</h2>
              <Help label="Client enrollment details">
                This information comes from the client. It may be out of date
                when the machine is offline. Recent contact confirms the client
                can reach Forklift, not that Linux sign-in works.
              </Help>
            </div>
            <button aria-label="Close client details" onClick={close}>
              <X />
            </button>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
            </div>
          )}
          <Machine client={client} live />
          <dl>
            <div>
              <dt>Enrollment</dt>
              <dd>{client.state.replaceAll("_", " ")}</dd>
            </div>
            <div>
              <dt>Host ID</dt>
              <dd>{client.host_id}</dd>
            </div>
            <div>
              <dt>Approved</dt>
              <dd>{date(client.enrolled_at)}</dd>
            </div>
            <div>
              <dt>Last contact</dt>
              <dd>{date(client.last_contact)}</dd>
            </div>
          </dl>
          <div className="heading-help">
            <h3>Client connection keys</h3>
            <Help label="Machine credential rotation">
              Clients replace their connection key automatically after 30 days.
              You can request an earlier replacement here. The change happens
              when the client next connects and can resume after an
              interruption. If a machine may be compromised, revoke its identity
              and investigate it; changing the key alone is not enough.
            </Help>
          </div>
          <dl>
            <div>
              <dt>Generation</dt>
              <dd>{client.credentials?.generation || 1}</dd>
            </div>
            <div>
              <dt>Last rotation</dt>
              <dd>{date(client.credentials?.rotated_at || null)}</dd>
            </div>
            <div>
              <dt>Rotation state</dt>
              <dd>
                {!supportsRotation
                  ? "Client upgrade required"
                  : client.credentials?.pending
                    ? client.credentials.pending.expired
                      ? "Unconfirmed rotation expired"
                      : "Awaiting new-key confirmation"
                    : client.credentials?.rotation_due
                      ? "Rotation due"
                      : "Current"}
              </dd>
            </div>
          </dl>
          {rotationNotice && <p role="status">{rotationNotice}</p>}
          {client.state === "active" && (
            <button
              className="secondary"
              disabled={
                !supportsRotation || busy || client.credentials?.rotation_due
              }
              onClick={() => setRotate(true)}
            >
              Replace client connection key
            </button>
          )}
          <ClientReplica client={client} api={api} refresh={refresh} />
          <ClientDiagnostics client={client} api={api} refresh={refresh} />
          <ClientMonitoring client={client} api={api} refresh={refresh} />
          {["active", "approved"].includes(client.state) && (
            <button className="secondary" onClick={() => setConfirm(true)}>
              Revoke client identity
            </button>
          )}
        </section>
      </div>
      {rotate && (
        <ConfirmDialog
          title="Replace client connection key?"
          confirmLabel="Request rotation"
          busy={busy}
          cancel={() => setRotate(false)}
          confirm={() => {
            setBusy(true);
            void api(`clients/${client.id}/rotate`, "POST", {
              acknowledge: true,
            })
              .then(async () => {
                setRotate(false);
                setRotationNotice(
                  "Rotation requested. The client will process it at its next contact.",
                );
                await refresh();
              })
              .catch((e) => {
                setError(e.message);
                setRotate(false);
              })
              .finally(() => setBusy(false));
          }}
        >
          <p>
            Replace this client’s connection key at its next check-in. Its host
            entry, access settings and DNS records stay unchanged.
          </p>
        </ConfirmDialog>
      )}
      {confirm && (
        <ConfirmDialog
          title="Revoke client identity?"
          confirmLabel="Revoke identity"
          busy={busy}
          cancel={() => setConfirm(false)}
          confirm={() => {
            setBusy(true);
            void api(`clients/${client.id}/revoke`, "POST", {
              acknowledge: true,
            })
              .then(async () => {
                await refresh();
                close();
              })
              .catch((e) => {
                setError(e.message);
                setConfirm(false);
              })
              .finally(() => setBusy(false));
          }}
        >
          <p>
            This stops the client from contacting Forklift. Host inventory, DNS
            records and Linux authentication configuration remain.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}
