import { Help, FieldHelp } from "./Help";
import { useState } from "react";
import { Server, Plus, Pencil, Trash2, Download, X } from "lucide-react";
type DnsConfig = {
  zone: string;
  fqdn: string;
  ipv4: string;
  ipv6: string | null;
  reverse: boolean;
};
export type HostDnsStatus = {
  state: string;
  error?: string;
  warnings: string[];
  managed_values: number;
  checked_at?: number | null;
};
export type Host = {
  dns?: DnsConfig | null;
  dns_status?: HostDnsStatus | null;
  id: string;
  name: string;
  hostname: string;
  endpoints: string[];
  allowed_groups: string[];
  revision: number;
  exported_revision: number | null;
  exported_at: number | null;
  directory_id?: string | null;
  directory_role?: string | null;
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
    [query, setQuery] = useState(""),
    [dnsEnabled, setDnsEnabled] = useState(false),
    [zones, setZones] = useState<string[]>([]),
    [zoneError, setZoneError] = useState(""),
    [removing, setRemoving] = useState<Host | null>(null),
    [notice, setNotice] = useState("");
  async function open(host: Host | null) {
    setError("");
    setZoneError("");
    setEditing(host);
    setDnsEnabled(!!host?.dns);
    setZones([]);
    try {
      const value = (await api("dns")) as {
        available: boolean;
        error?: string;
        zones: { name: string; managed: boolean }[];
      };
      setZones(
        value.zones
          .filter((z) => z.managed && !z.name.endsWith(".arpa."))
          .map((z) => z.name),
      );
      if (!value.available)
        setZoneError(
          value.error ||
            "DNS is unavailable. Settings can be saved for later retry.",
        );
    } catch (e) {
      setZoneError((e as Error).message);
    }
  }
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
      {notice && (
        <div className="hint" role="status">
          {notice}
        </div>
      )}
      <section className="panel">
        <div className="table-toolbar">
          <div className="heading-help">
            <h2>
              Hosts <span className="muted">{hosts.length}</span>
            </h2>
            <Help label="Host inventory and access">
              Directory machines appear automatically, including the primary.
              These inventory records do not grant SSH access. Select login
              groups and deploy client configuration only when you want
              centralized Linux login.
              <h3>Client configuration</h3>
              <p>
                Deploy the complete bundle with the Ansible role or manual guide
                in docs/linux-clients.md. Group membership updates follow
                LDAP/NSS cache expiry; changes to permitted groups require
                redeployment. Local recovery accounts remain available.
              </p>
            </Help>
          </div>
          <button
            className="primary"
            onClick={() => {
              void open(null);
            }}
          >
            <Plus size={17} />
            Register host
          </button>
        </div>

        <input
          aria-label="Search hosts"
          placeholder="Search hostnames or login groups…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {!hosts.length ? (
          <div className="empty">
            <Server size={36} />
            <h2>No hosts registered</h2>
            <p className="muted">Register a host to configure Linux login.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Permitted login groups</th>
                  <th>Configuration</th>
                  <th>DNS</th>
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
                        {h.directory_role && (
                          <span className="pill">
                            {h.directory_role === "primary"
                              ? "Primary directory"
                              : "Directory replica"}
                          </span>
                        )}
                        <small>{h.hostname}</small>
                        <small>{h.endpoints.join(", ")}</small>
                      </td>
                      <td>
                        {h.allowed_groups.join(", ") || "SSH not configured"}
                      </td>
                      <td>
                        <span
                          className={
                            h.revision === h.exported_revision
                              ? "pill"
                              : "badge"
                          }
                        >
                          {h.exported_revision === null
                            ? h.directory_id && !h.allowed_groups.length
                              ? "Inventory only"
                              : "Not exported"
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
                        {h.dns?.fqdn && <small>{h.dns.fqdn}</small>}
                        <span
                          className={
                            h.dns_status &&
                            ["applied", "removed", "retained"].includes(
                              h.dns_status.state,
                            )
                              ? "pill"
                              : "badge"
                          }
                        >
                          {h.dns_status?.state.replaceAll("_", " ") ||
                            "Unmanaged"}
                        </span>
                        {h.dns_status?.checked_at && (
                          <small>
                            Last applied{" "}
                            {new Date(
                              h.dns_status.checked_at * 1000,
                            ).toLocaleString()}
                          </small>
                        )}
                        {h.dns_status?.error && (
                          <small role="alert">{h.dns_status.error}</small>
                        )}
                        {h.dns_status?.warnings.map((w, i) => (
                          <small key={i}>{w}</small>
                        ))}
                        {(h.dns ||
                          (h.dns_status &&
                            !["retained", "removed"].includes(
                              h.dns_status.state,
                            ))) && (
                          <button
                            disabled={busy}
                            onClick={() =>
                              perform(async () => {
                                const status = (await api(
                                  `dns/hosts/${h.id}/reconcile`,
                                  "POST",
                                  {},
                                )) as HostDnsStatus;
                                setNotice(
                                  status.error || "DNS records reconciled.",
                                );
                                await refresh();
                              })
                            }
                          >
                            Reconcile DNS
                          </button>
                        )}
                      </td>
                      <td>
                        <div className="actions">
                          <button
                            disabled={busy || !h.allowed_groups.length}
                            title="Generate configuration (rotates bind credential)"
                            aria-label="Generate configuration"
                            onClick={() => download(h)}
                          >
                            <Download size={17} />
                          </button>
                          <button
                            aria-label="Edit host"
                            onClick={() => {
                              void open(h);
                            }}
                          >
                            <Pencil size={16} />
                          </button>
                          <button
                            disabled={!!h.directory_id}
                            title={
                              h.directory_id
                                ? "Manage this machine through Directory Servers"
                                : undefined
                            }
                            aria-label="Delete host"
                            onClick={() => setRemoving(h)}
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
                    dns: dnsEnabled
                      ? {
                          zone: String(form.get("dns_zone")),
                          fqdn: String(form.get("dns_fqdn")),
                          ipv4: String(form.get("dns_ipv4")),
                          ipv6: String(form.get("dns_ipv6") || "") || null,
                          reverse: form.has("dns_reverse"),
                        }
                      : null,
                    dns_apply: form.has("dns_apply"),
                    dns_cleanup: String(form.get("dns_cleanup") || "keep"),
                  };
                  const saved = (await api(
                    editing ? `hosts/${editing.id}` : "hosts",
                    editing ? "PUT" : "POST",
                    body,
                  )) as Host;
                  setNotice(
                    saved.dns_status?.error
                      ? `Host saved. DNS needs attention: ${saved.dns_status.error}`
                      : saved.dns_status?.state === "needs_apply"
                        ? "Host saved. Reconcile DNS to apply its pending settings."
                        : "Host saved.",
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
                  readOnly={!!editing?.directory_id}
                  defaultValue={editing?.hostname || ""}
                  placeholder="backup.homelab.internal"
                  required
                />
              </label>
              <FieldHelp
                label="LDAP endpoints"
                help={
                  <>
                    Use addresses reachable from this host, with certificate DNS
                    names signed by your installation CA. The internal Docker
                    hostname “ldap” usually cannot be used by other machines.
                  </>
                }
                caption={
                  <>LDAPS endpoints (comma separated, in failover order)</>
                }
              >
                <input
                  name="endpoints"
                  defaultValue={
                    editing?.endpoints.join(", ") ||
                    hosts
                      .find((h) => h.directory_id === "primary")
                      ?.endpoints.join(", ") ||
                    ""
                  }
                  placeholder="ldaps://ldap.homelab.internal:1636"
                  required
                />
              </FieldHelp>

              <fieldset className="host-groups">
                <legend>
                  <span className="help-row">
                    Permitted login groups
                    <Help label="Permitted login groups">
                      Choose login groups to configure SSH access. Hosts managed
                      only in DNS can leave these empty. Exported policy applies
                      to LDAP users signing in through SSH/PAM; local accounts
                      retain their existing policy. Each export rotates the
                      host’s read-only bind credential.
                    </Help>
                  </span>
                </legend>
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

              <fieldset>
                <legend>DNS registration</legend>
                <label className="checkbox">
                  <input
                    type="checkbox"
                    checked={dnsEnabled}
                    onChange={(e) => setDnsEnabled(e.target.checked)}
                  />
                  Manage this host’s DNS records
                </label>
                {zoneError && (
                  <p className="hint" role="status">
                    {zoneError}
                  </p>
                )}
                {dnsEnabled && (
                  <>
                    <FieldHelp
                      label="Choosing a DNS zone"
                      caption={<>DNS zone</>}
                      help={
                        <>
                          Create a forward zone in DNS before registering a new
                          name.
                        </>
                      }
                    >
                      <select
                        name="dns_zone"
                        aria-label="DNS zone"
                        defaultValue={editing?.dns?.zone || ""}
                        required
                      >
                        <option value="">Select a managed forward zone</option>
                        {[
                          ...new Set([
                            ...zones,
                            ...(editing?.dns?.zone ? [editing.dns.zone] : []),
                          ]),
                        ].map((z) => (
                          <option key={z} value={z}>
                            {z}
                          </option>
                        ))}
                      </select>
                    </FieldHelp>

                    <label>
                      DNS name
                      <input
                        name="dns_fqdn"
                        aria-label="DNS name"
                        defaultValue={
                          editing?.dns?.fqdn || editing?.hostname || ""
                        }
                        placeholder="server.example.test."
                        required
                      />
                    </label>
                    <label>
                      IPv4 address
                      <input
                        name="dns_ipv4"
                        aria-label="IPv4 address"
                        defaultValue={editing?.dns?.ipv4 || ""}
                        placeholder="192.168.1.50"
                        required
                      />
                    </label>
                    <label>
                      IPv6 address (optional)
                      <input
                        name="dns_ipv6"
                        aria-label="IPv6 address (optional)"
                        defaultValue={editing?.dns?.ipv6 || ""}
                        placeholder="fd00::50"
                      />
                    </label>
                    <div className="help-row checkbox-help">
                      <label className="checkbox">
                        <input
                          type="checkbox"
                          name="dns_reverse"
                          defaultChecked={editing?.dns?.reverse ?? true}
                        />
                        Create matching reverse DNS
                      </label>
                      <Help label="Host DNS registration">
                        Every address needs a matching managed reverse zone when
                        reverse DNS is enabled. Unrelated records are preserved.
                        DNS registration does not grant SSH access. Changing the
                        inventory hostname does not change this DNS name; review
                        both fields.
                      </Help>
                    </div>
                  </>
                )}
                {!dnsEnabled && (editing?.dns || editing?.dns_status) && (
                  <label>
                    Existing managed DNS records
                    <select
                      name="dns_cleanup"
                      aria-label="Existing managed DNS records"
                      defaultValue="keep"
                    >
                      <option value="keep">
                        Keep records and release ownership
                      </option>
                      <option value="delete">
                        Delete only this host’s managed values
                      </option>
                    </select>
                  </label>
                )}
                <div className="help-row checkbox-help">
                  <label className="checkbox">
                    <input type="checkbox" name="dns_apply" defaultChecked />
                    Apply DNS changes after saving
                  </label>
                  <Help label="Applying host DNS changes">
                    You can save settings without applying DNS, then use
                    Reconcile DNS. If DNS is unavailable, the host remains saved
                    and can be retried.
                  </Help>
                </div>
              </fieldset>
              <button className="primary" disabled={saving}>
                {saving ? "Saving…" : "Save host"}
              </button>
            </form>
          </section>
        </div>
      )}
      {removing && (
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Delete host"
          >
            <h2>Delete {removing.name}?</h2>
            <p>
              This revokes the LDAP bind credential. Remove client configuration
              from the machine separately.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const choice = String(
                  new FormData(e.currentTarget).get("dns") || "keep",
                );
                void perform(async () => {
                  const result = (await api(
                    `hosts/${removing.id}?revision=${removing.revision}&dns=${choice}`,
                    "DELETE",
                  )) as { dns_status?: HostDnsStatus };
                  setNotice(
                    result.dns_status?.error
                      ? `Host deleted. DNS cleanup needs retry in DNS: ${result.dns_status.error}`
                      : "Host deleted.",
                  );
                  setRemoving(null);
                  await refresh();
                });
              }}
            >
              {(removing.dns || removing.dns_status) && (
                <label>
                  Managed DNS records
                  <select
                    name="dns"
                    aria-label="Managed DNS records"
                    defaultValue="keep"
                  >
                    <option value="keep">
                      Keep records and release ownership
                    </option>
                    <option value="delete">
                      Delete only this host’s managed values
                    </option>
                  </select>
                </label>
              )}
              <button className="danger" disabled={busy}>
                Delete host
              </button>
              <button type="button" onClick={() => setRemoving(null)}>
                Cancel
              </button>
            </form>
          </section>
        </div>
      )}
    </>
  );
}
