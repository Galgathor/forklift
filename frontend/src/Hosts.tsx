import { useState } from "react";
import {
  Server,
  Plus,
  Pencil,
  Trash2,
  Download,
  X,
  ShieldCheck,
} from "lucide-react";
export type Host = {
  id: string;
  name: string;
  hostname: string;
  endpoints: string[];
  allowed_groups: string[];
  revision: number;
  exported_revision: number | null;
  exported_at: number | null;
};
type Props = {
  hosts: Host[];
  groups: string[];
  csrf: string;
  busy: boolean;
  refresh: () => Promise<void>;
  api: (path: string, method?: string, body?: unknown) => Promise<unknown>;
  perform: (f: () => Promise<void>) => Promise<void>;
};
export function Hosts({
  hosts,
  groups,
  csrf,
  busy,
  refresh,
  api,
  perform,
}: Props) {
  const [editing, setEditing] = useState<Host | null | undefined>(undefined),
    [error, setError] = useState(""),
    [saving, setSaving] = useState(false),
    [query, setQuery] = useState("");
  async function download(host: Host) {
    const warning = host.exported_at
      ? "This creates a new host bind password and invalidates previous bundles. Redeploy immediately; existing SSSD LDAP connections may continue until reconnected."
      : "This bundle contains a dedicated read-only bind credential. Keep it private and deploy it only to this host.";
    if (!confirm(warning + " Generate configuration?")) return;
    await perform(async () => {
      const r = await fetch(`/api/hosts/${host.id}/bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ revision: host.revision, rotate: true }),
      });
      if (!r.ok) {
        const v = await r.json();
        throw Error(v.error || "Export failed");
      }
      const blob = await r.blob(),
        url = URL.createObjectURL(blob),
        a = document.createElement("a");
      a.href = url;
      a.download = `forklift-${host.hostname}.tar.gz`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      await refresh();
    });
  }
  return (
    <>
      <section className="panel">
        <div className="table-toolbar">
          <h2>
            Linux hosts <span className="muted">{hosts.length}</span>
          </h2>
          <button
            className="primary"
            onClick={() => {
              setError("");
              setEditing(null);
            }}
          >
            <Plus size={17} />
            Register host
          </button>
        </div>
        <p className="hint">
          Register a host, select its login groups, then generate and deploy its
          configuration. Deployment and reachability are not monitored.
        </p>
        <input
          aria-label="Search hosts"
          placeholder="Search hostnames or login groups…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {!hosts.length ? (
          <div className="empty">
            <Server size={36} />
            <h2>Bring your Linux hosts together.</h2>
            <p className="muted">
              Use conventional SSSD, PAM and SSH password authentication. A host
              configuration grants no sudo privileges.
            </p>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Permitted login groups</th>
                  <th>Configuration</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {hosts
                  .filter((h) =>
                    JSON.stringify(h)
                      .toLowerCase()
                      .includes(query.toLowerCase()),
                  )
                  .map((h) => (
                    <tr key={h.id}>
                      <td>
                        <strong>{h.name}</strong>
                        <small>{h.hostname}</small>
                        <small>{h.endpoints.join(", ")}</small>
                      </td>
                      <td>{h.allowed_groups.join(", ")}</td>
                      <td>
                        <span
                          className={
                            h.revision === h.exported_revision
                              ? "pill"
                              : "badge"
                          }
                        >
                          {h.exported_revision === null
                            ? "Not exported"
                            : h.revision === h.exported_revision
                              ? "Configuration exported"
                              : "Needs new export"}
                        </span>
                        <small>
                          Revision {h.revision}
                          {h.exported_at
                            ? " · " +
                              new Date(h.exported_at * 1000).toLocaleString()
                            : ""}
                        </small>
                      </td>
                      <td>
                        <div className="actions">
                          <button
                            disabled={busy}
                            title="Generate configuration (rotates bind credential)"
                            aria-label="Generate configuration"
                            onClick={() => download(h)}
                          >
                            <Download size={17} />
                          </button>
                          <button
                            aria-label="Edit host"
                            onClick={() => {
                              setError("");
                              setEditing(h);
                            }}
                          >
                            <Pencil size={16} />
                          </button>
                          <button
                            aria-label="Delete host"
                            onClick={() => {
                              if (
                                confirm(
                                  `Delete ${h.name} and revoke its LDAP bind credential? Remove its configuration from the host separately.`,
                                )
                              )
                                perform(async () => {
                                  await api(`hosts/${h.id}`, "DELETE");
                                  await refresh();
                                });
                            }}
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="callout">
        <ShieldCheck size={24} />
        <div>
          <h3>Access is enforced on your Linux host.</h3>
          <p>
            Deploy the complete bundle with the Ansible role or manual guide in
            docs/linux-clients.md. Group membership updates follow LDAP/NSS
            cache expiry; changes to permitted groups require redeployment.
            Local recovery accounts remain available.
          </p>
        </div>
      </section>
      {editing !== undefined && (
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Host configuration"
          >
            <div className="panel-title">
              <h2>{editing ? "Edit" : "Register"} Linux host</h2>
              <button aria-label="Close" onClick={() => setEditing(undefined)}>
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
                  const body = {
                    name: String(form.get("name")),
                    hostname: String(form.get("hostname")),
                    endpoints: String(form.get("endpoints"))
                      .split(",")
                      .map((s) => s.trim())
                      .filter(Boolean),
                    allowed_groups: form.getAll("allowed_groups").map(String),
                    ...(editing ? { revision: editing.revision } : {}),
                  };
                  await api(
                    editing ? `hosts/${editing.id}` : "hosts",
                    editing ? "PUT" : "POST",
                    body,
                  );
                  setEditing(undefined);
                  await refresh();
                } catch (err) {
                  setError((err as Error).message);
                } finally {
                  setSaving(false);
                }
              }}
            >
              <label>
                Friendly name
                <input
                  name="name"
                  defaultValue={editing?.name || ""}
                  placeholder="Backup server"
                  maxLength={100}
                  required
                />
              </label>
              <label>
                Hostname
                <input
                  name="hostname"
                  defaultValue={editing?.hostname || ""}
                  placeholder="backup.homelab.internal"
                  required
                />
              </label>
              <label>
                LDAPS endpoints (comma separated, in failover order)
                <input
                  name="endpoints"
                  defaultValue={editing?.endpoints.join(", ") || ""}
                  placeholder="ldaps://ldap.homelab.internal:636"
                  required
                />
              </label>
              <p className="hint">
                Use addresses reachable from this host, with certificate DNS
                names signed by your installation CA. The internal Docker
                hostname “ldap” usually cannot be used by other machines.
              </p>
              <fieldset className="host-groups">
                <legend>Permitted login groups</legend>
                {groups.map((g) => (
                  <label className="checkbox" key={g}>
                    <input
                      type="checkbox"
                      name="allowed_groups"
                      value={g}
                      defaultChecked={editing?.allowed_groups.includes(g)}
                    />
                    {g}
                  </label>
                ))}
              </fieldset>
              <p className="hint">
                Choose at least one group. Exported policy applies to LDAP users
                signing in through SSH/PAM; local accounts retain their existing
                policy. Each export rotates the host’s read-only bind
                credential.
              </p>
              <button className="primary" disabled={saving}>
                {saving ? "Saving…" : "Save host"}
              </button>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
