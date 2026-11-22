import { useState } from "react";
import { X } from "lucide-react";
import { FieldHelp, Help } from "./Help";
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
function Machine({ client }: { client: ClientRecord }) {
  const i = client.identity;
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
        <dt>Enrollment system</dt>
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
        <dt>Enrollment addresses</dt>
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
              Run forklift-client join on the Linux machine, then enter its
              short-lived pairing code here. Verify the hostname, addresses and
              key fingerprint shown on that machine. These details are
              self-reported. Enrollment monitors the host; it does not install
              or configure SSSD, PAM, NSS, SSH or DNS.
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
                      Create a new host or explicitly link this machine to an
                      existing inventory record. Forklift never merges by
                      hostname or address. Revoke an existing client identity
                      before replacing it. Linking preserves login groups, DNS
                      ownership and the host ID.
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
                System identity and addresses were reported during pairing. Last
                contact confirms a credential-authenticated session, not
                continuous monitoring or successful Linux authentication. Live
                inventory and diagnostics will appear only when supported.
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
          <Machine client={client} />
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
          {["active", "approved"].includes(client.state) && (
            <button className="secondary" onClick={() => setConfirm(true)}>
              Revoke client identity
            </button>
          )}
        </section>
      </div>
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
