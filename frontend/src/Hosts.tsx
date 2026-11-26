import {
  ClientEnrollment,
  ClientDetails,
  type ClientRecord,
} from "./ClientEnrollment";
import { Help, FieldHelp } from "./Help";
import { useEffect, useState } from "react";
import { Server, Plus, Pencil, Trash2, X } from "lucide-react";
import {
  HostDnsFields,
  hostDnsFromForm,
  reportedIpv4,
  type HostDnsConfig,
} from "./HostDnsFields";
export type HostDnsStatus = {
  state: string;
  error?: string;
  warnings: string[];
  managed_values: number;
  checked_at?: number | null;
};
export type Host = {
  client?: ClientRecord | null;
  dns?: HostDnsConfig | null;
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
  busy: boolean;
  refresh: () => Promise<void>;
  api: (path: string, method?: string, body?: unknown) => Promise<unknown>;
  perform: (f: () => Promise<void>) => Promise<void>;
};
export function Hosts({ hosts, groups, busy, refresh, api, perform }: Props) {
  const [joining, setJoining] = useState(false),
    [clientDetailsId, setClientDetails] = useState<string | null>(null);
  const clientDetails = hosts.find(
    (h) => h.client?.id === clientDetailsId,
  )?.client;
  useEffect(() => {
    const timer = window.setInterval(() => {
      void refresh().catch(() => {});
    }, 30000);
    return () => window.clearInterval(timer);
  }, [refresh]);
  const [editing, setEditing] = useState<Host | null | undefined>(undefined),
    [error, setError] = useState(""),
    [saving, setSaving] = useState(false),
    [query, setQuery] = useState(""),
    [hostname, setHostname] = useState(""),
    [removing, setRemoving] = useState<Host | null>(null),
    [notice, setNotice] = useState("");
  function open(host: Host | null) {
    setError("");
    setHostname(host?.hostname || "");
    setEditing(host);
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
              Directory servers appear here automatically. Adding a host does
              not enable SSH login. To use directory accounts for Linux sign-in,
              choose the allowed groups and follow the Linux client guide. Local
              recovery accounts keep their existing access.
            </Help>
          </div>
          <div className="wizard-actions">
            <button
              className="primary"
              disabled={busy}
              onClick={() => setJoining(true)}
            >
              Join via Code
            </button>
            <button
              className="secondary"
              onClick={() => {
                open(null);
              }}
            >
              <Plus size={17} />
              Join Manually
            </button>
          </div>
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
                  <th>Client</th>
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
                          <span className="pill">Directory Server</span>
                        )}
                        <small>{h.hostname}</small>
                        <small>{h.endpoints.join(", ")}</small>
                      </td>
                      <td>
                        {h.allowed_groups.join(", ") || "SSH not configured"}
                      </td>
                      <td>
                        {h.client ? (
                          <>
                            <button
                              className="secondary"
                              onClick={() => setClientDetails(h.client!.id)}
                            >
                              {h.client.state === "active"
                                ? "Client enrolled"
                                : "Client " +
                                  h.client.state.replaceAll("_", " ")}
                            </button>
                            <small>
                              {h.client.monitoring?.connectivity.replaceAll(
                                "_",
                                " ",
                              ) || "Not reporting"}
                            </small>
                            <small>
                              {h.client.monitoring?.diagnostics?.health ||
                                "Health unknown"}{" "}
                              ·{" "}
                              {h.client.monitoring?.diagnostics
                                ?.active_issues || 0}{" "}
                              active issues
                            </small>
                            <small>
                              v
                              {
                                (
                                  h.client.monitoring?.inventory ||
                                  h.client.identity
                                ).client_version
                              }
                            </small>
                            <small>
                              {h.client.monitoring?.inventory?.addresses
                                .map((a) => a.address)
                                .join(", ")}
                            </small>
                            <small>
                              {h.client.monitoring?.received_at
                                ? "Last heartbeat " +
                                  new Date(
                                    h.client.monitoring.received_at * 1000,
                                  ).toLocaleString()
                                : "Heartbeat not reported"}
                            </small>
                          </>
                        ) : (
                          <span className="muted">Manual inventory</span>
                        )}
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
                      </td>
                      <td>
                        <div className="actions">
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

      {joining && (
        <ClientEnrollment
          api={api}
          hosts={hosts}
          close={() => setJoining(false)}
          refresh={refresh}
        />
      )}
      {clientDetails && (
        <ClientDetails
          client={clientDetails}
          api={api}
          close={() => setClientDetails(null)}
          refresh={refresh}
        />
      )}
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
                    dns: hostDnsFromForm(form),
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
                      : "Host saved.",
                  );
                  try {
                    await refresh();
                  } finally {
                    setEditing(undefined);
                  }
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
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="backup.homelab.internal"
                  required
                />
              </label>
              <FieldHelp
                label="LDAP endpoints"
                help={
                  <>
                    Use encrypted LDAP addresses that this host can reach. The
                    certificate must match the server name. Other machines
                    usually cannot reach Docker’s internal name ldap.
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
                      Choose which directory groups may sign in to this host.
                      Review the host’s sign-in configuration after changing
                      this list. Leave it empty for a host used only for DNS.
                      This does not change local account permissions.
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

              <HostDnsFields
                api={api}
                hostname={hostname}
                initial={editing?.dns}
                suggestedIp={reportedIpv4(
                  (
                    editing?.client?.monitoring?.inventory ||
                    editing?.client?.identity
                  )?.addresses || [],
                )}
                hasExistingRecords={!!(editing?.dns || editing?.dns_status)}
              />
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
              This cancels the host’s directory access password. Remove the
              client settings from the machine separately.
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
