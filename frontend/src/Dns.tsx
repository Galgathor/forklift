import { useEffect, useState } from "react";
import { Plus, RefreshCw, Pencil, Trash2, X, Download } from "lucide-react";
type RecordSet = {
  name: string;
  type: string;
  ttl: number;
  revision: string;
  records: { content: string; disabled: boolean }[];
  auto_ptr?: boolean;
};
type Zone = {
  name: string;
  kind: string;
  serial: number;
  managed: boolean;
  record_count: number;
  revision: string;
  rrsets: RecordSet[];
};
type Overview = {
  available: boolean;
  error?: string;
  server: {
    api_available: boolean;
    service_available: boolean | null;
    authoritative_answer?: boolean | null;
    version?: string;
    role: string;
    replication: string;
    probe_zone?: string;
    address?: string;
    port?: number;
  };
  zones: Zone[];
  changes: { id: string; status: string; error?: string }[];
  errors: { at: number; action: string; target: string }[];
};
type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
export function Dns({ api }: { api: Api }) {
  const [overview, setOverview] = useState<Overview | null>(null),
    [selected, setSelected] = useState<Zone | null>(null),
    [query, setQuery] = useState(""),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false),
    [creating, setCreating] = useState(false),
    [editing, setEditing] = useState<RecordSet | null | undefined>(),
    [soa, setSoa] = useState(false);
  async function load(name = selected?.name) {
    const value = (await api("dns")) as Overview;
    setOverview(value);
    if (name && value.available && value.zones.some((z) => z.name === name))
      setSelected(await api(`dns/zones/${encodeURIComponent(name)}`));
    else if (name) setSelected(null);
  }
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, []);
  async function perform(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function outcome(result: any) {
    if (result.status === "needs_retry")
      setError(
        `DNS change ${result.id} is incomplete: ${result.error}. Review pending changes below.`,
      );
    else if (result.warnings?.length) setNotice(result.warnings.join(" "));
    await load();
  }
  const records =
    selected?.rrsets.filter((r) =>
      `${r.name} ${r.type} ${r.records.map((v) => v.content).join(" ")}`
        .toLowerCase()
        .includes(query.toLowerCase()),
    ) || [];
  const pending = !!overview?.changes.length;
  return (
    <>
      {error && !creating && editing === undefined && !soa && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <p role="status" className="hint">
          {notice}
        </p>
      )}
      <section className="panel">
        <div className="panel-title">
          <h2>DNS overview</h2>
          <button
            aria-label="Refresh DNS"
            disabled={busy}
            onClick={() => perform(() => load())}
          >
            <RefreshCw size={17} />
          </button>
        </div>
        {!overview ? (
          <p className="muted">Checking PowerDNS…</p>
        ) : (
          <>
            {!overview.available && (
              <div className="error" role="status">
                {overview.error}
              </div>
            )}
            <dl>
              <div>
                <dt>Management API</dt>
                <dd>
                  {overview.server.api_available ? "Connected" : "Unavailable"}
                </dd>
              </div>
              <div>
                <dt>Authoritative UDP probe</dt>
                <dd>
                  {overview.server.service_available === null
                    ? "Unknown"
                    : overview.server.service_available
                      ? overview.server.authoritative_answer === true
                        ? `Authoritative answer · ${overview.server.probe_zone}`
                        : overview.server.probe_zone
                          ? "Responding; authoritative answer not confirmed"
                          : "Responding · no zones configured"
                      : "Not responding"}
                </dd>
              </div>
              <div>
                <dt>Zones / records</dt>
                <dd>
                  {overview.available
                    ? `${overview.zones.length} / ${overview.zones.reduce((n, z) => n + z.record_count, 0)}`
                    : "Unknown"}
                </dd>
              </div>
              <div>
                <dt>Server</dt>
                <dd>
                  {overview.server.address}:{overview.server.port} · PowerDNS{" "}
                  {overview.server.version || "version unavailable"}
                </dd>
              </div>
              <div>
                <dt>Role / replication</dt>
                <dd>Standalone authoritative · replication not configured</dd>
              </div>
            </dl>
            <p className="hint">
              The probe queries PowerDNS inside its container. Client network
              reachability depends on the published DNS address, port and
              firewall. DNS continues serving if Forklift is offline.
            </p>
            <button
              className="secondary"
              disabled={busy || !overview.available}
              onClick={() =>
                perform(async () => {
                  if (
                    confirm(
                      "Rotate the DNS API credential? This briefly restarts PowerDNS. Existing zones are preserved.",
                    )
                  ) {
                    await api("dns/rotate", "POST", { acknowledge: true });
                    await load();
                    setNotice("DNS API credential rotated.");
                  }
                })
              }
            >
              Rotate API credential
            </button>
          </>
        )}
      </section>
      {!!overview?.changes.length && (
        <section className="panel">
          <h2>Pending DNS changes</h2>
          <p className="hint">
            Forward and reverse changes can partially succeed. Retry checks
            current record sets before applying missing steps. Review and keep
            applied steps if you need to resolve a conflict manually.
          </p>
          {overview.changes.map((c) => (
            <div className="event" key={c.id}>
              <div>
                <strong>{c.id}</strong>
                <p className="hint">{c.error || c.status}</p>
                <button
                  disabled={busy}
                  onClick={() =>
                    perform(async () =>
                      outcome(
                        await api(`dns/changes/${c.id}/retry`, "POST", {}),
                      ),
                    )
                  }
                >
                  Retry
                </button>
                <button
                  disabled={busy}
                  onClick={() =>
                    perform(async () => {
                      if (
                        confirm(
                          "Keep any already-applied records and close this pending operation? Review its forward and reverse values first.",
                        )
                      ) {
                        await api(`dns/changes/${c.id}/abandon`, "POST", {
                          acknowledge: true,
                        });
                        await load();
                      }
                    })
                  }
                >
                  Review complete; keep applied steps
                </button>
              </div>
            </div>
          ))}
        </section>
      )}
      <section className="panel">
        <div className="panel-title">
          <h2>Zones</h2>
          <button
            className="primary"
            disabled={busy || !overview?.available}
            onClick={() => {
              setError("");
              setCreating(true);
            }}
          >
            <Plus size={16} />
            Create zone
          </button>
        </div>
        {!overview?.zones.length ? (
          <p className="muted">
            No zones available. Create a forward or private reverse zone after
            PowerDNS is ready.
          </p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Zone</th>
                  <th>Kind</th>
                  <th>SOA serial</th>
                  <th>Records</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {overview.zones.map((z) => (
                  <tr key={z.name}>
                    <td>
                      <button
                        disabled={busy}
                        onClick={() =>
                          perform(async () => {
                            setSelected(
                              await api(
                                `dns/zones/${encodeURIComponent(z.name)}`,
                              ),
                            );
                            setQuery("");
                          })
                        }
                      >
                        {z.name}
                      </button>
                    </td>
                    <td>
                      {z.kind}
                      {!z.managed && " · read only"}
                    </td>
                    <td>{z.serial}</td>
                    <td>{z.record_count}</td>
                    <td>
                      <button
                        aria-label={`Delete zone ${z.name}`}
                        disabled={busy || !z.managed || pending}
                        onClick={() =>
                          perform(async () => {
                            const fresh = await api(
                              `dns/zones/${encodeURIComponent(z.name)}`,
                            );
                            const typed = prompt(
                              `Delete ${z.name} and ALL its records? Enter the exact zone name including the final dot:`,
                            );
                            if (typed === null) return;
                            await api(
                              `dns/zones/${encodeURIComponent(z.name)}`,
                              "DELETE",
                              {
                                acknowledge: true,
                                confirm_name: typed,
                                expected_revision: fresh.revision,
                              },
                            );
                            await load();
                          })
                        }
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {selected && (
        <section className="panel">
          <div className="panel-title dns-heading">
            <h2>{selected.name}</h2>
            <div className="actions">
              <a
                className="secondary download-link"
                href={`/api/dns/zones/${encodeURIComponent(selected.name)}/export`}
                download
              >
                <Download size={15} />
                Export zone
              </a>
              <button
                className="secondary"
                disabled={busy || !selected.managed || pending}
                onClick={() => setSoa(true)}
              >
                Zone settings / SOA
              </button>
              <button
                className="primary"
                disabled={busy || !selected.managed || pending}
                onClick={() => setEditing(null)}
              >
                <Plus size={16} />
                Add record set
              </button>
            </div>
          </div>
          <input
            aria-label="Search DNS records"
            placeholder="Search names, types or values…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>TTL</th>
                  <th>Values</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.name + r.type}>
                    <td>{r.name}</td>
                    <td>{r.type}</td>
                    <td>{r.ttl}</td>
                    <td>
                      {r.records.map((v) => (
                        <div className="dns-value" key={v.content}>
                          {v.content}
                          {v.disabled ? " (disabled)" : ""}
                        </div>
                      ))}
                    </td>
                    <td>
                      <div className="actions">
                        <button
                          aria-label={`Edit ${r.name} ${r.type}`}
                          disabled={busy || !selected.managed || pending}
                          onClick={() =>
                            r.type === "SOA" ? setSoa(true) : setEditing(r)
                          }
                        >
                          <Pencil size={16} />
                        </button>
                        <button
                          aria-label={`Delete ${r.name} ${r.type}`}
                          disabled={
                            busy ||
                            !selected.managed ||
                            pending ||
                            r.type === "SOA" ||
                            (r.type === "NS" && r.name === selected.name)
                          }
                          onClick={() =>
                            perform(async () => {
                              if (
                                confirm(
                                  `Delete the entire ${r.type} record set at ${r.name}?`,
                                )
                              )
                                await outcome(
                                  await api(
                                    `dns/zones/${encodeURIComponent(selected.name)}/records`,
                                    "POST",
                                    {
                                      name: r.name,
                                      type: r.type,
                                      ttl: r.ttl,
                                      values: [],
                                      delete: true,
                                      acknowledge: true,
                                      expected_revision: r.revision,
                                    },
                                  ),
                                );
                            })
                          }
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
        </section>
      )}
      {!!overview?.errors.length && (
        <section className="panel">
          <h2>Recent DNS errors</h2>
          {overview.errors.map((e, i) => (
            <div className="event" key={i}>
              <div>
                {e.action} · {e.target}
                <small>{new Date(e.at * 1000).toLocaleString()}</small>
              </div>
            </div>
          ))}
        </section>
      )}
      {creating && (
        <ZoneForm
          error={error}
          close={() => setCreating(false)}
          busy={busy}
          save={(body) =>
            perform(async () => {
              const zone = await api("dns/zones", "POST", body);
              setCreating(false);
              setSelected(zone);
              await load(zone.name);
            })
          }
        />
      )}
      {selected && editing !== undefined && (
        <RecordForm
          error={error}
          zone={selected}
          record={editing}
          busy={busy}
          close={() => setEditing(undefined)}
          save={(body) =>
            perform(async () => {
              const result = await api(
                `dns/zones/${encodeURIComponent(selected.name)}/records`,
                "POST",
                body,
              );
              setEditing(undefined);
              await outcome(result);
            })
          }
        />
      )}
      {selected && soa && (
        <SoaForm
          error={error}
          zone={selected}
          busy={busy}
          close={() => setSoa(false)}
          save={(body) =>
            perform(async () => {
              const result = await api(
                `dns/zones/${encodeURIComponent(selected.name)}`,
                "PUT",
                body,
              );
              setSoa(false);
              await outcome(result);
            })
          }
        />
      )}
    </>
  );
}
function Dialog({
  title,
  close,
  children,
  error,
}: {
  title: string;
  close: () => void;
  children: React.ReactNode;
  error?: string;
}) {
  return (
    <div className="overlay">
      <section
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="panel-title">
          <h2>{title}</h2>
          <button aria-label="Close DNS dialog" onClick={close}>
            <X />
          </button>
        </div>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {children}
      </section>
    </div>
  );
}
function ZoneForm({
  busy,
  error,
  close,
  save,
}: {
  busy: boolean;
  error: string;
  close: () => void;
  save: (v: unknown) => void;
}) {
  const [kind, setKind] = useState("forward");
  return (
    <Dialog title="Create DNS zone" close={close} error={error}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const v = Object.fromEntries(new FormData(e.currentTarget));
          save({
            ...v,
            kind,
            ttl: Number(v.ttl),
            nameserver_address: v.nameserver_address || null,
          });
        }}
      >
        <label>
          Zone type
          <select
            aria-label="Zone type"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
          >
            <option value="forward">Forward</option>
            <option value="reverse4">Private IPv4 reverse</option>
            <option value="reverse6">ULA IPv6 reverse</option>
          </select>
        </label>
        <label>
          {kind === "reverse4" ? "Private network (CIDR)" : "Zone name"}
          <input
            name="name"
            required
            placeholder={
              kind === "reverse4"
                ? "10.0.20.0/24"
                : kind === "reverse6"
                  ? "d.f.ip6.arpa."
                  : "ad.ilpe.me"
            }
          />
        </label>
        {kind === "reverse4" && (
          <p className="hint">
            Use aligned /8, /16 or /24 RFC1918 networks. 10.0.20.0/24 becomes
            20.0.10.in-addr.arpa.
          </p>
        )}
        <label>
          Primary nameserver
          <input name="nameserver" required placeholder="ns1.ad.ilpe.me." />
        </label>
        <label>
          Nameserver address
          <input name="nameserver_address" placeholder="10.0.20.2" />
        </label>
        <p className="hint">
          An in-zone nameserver requires an address. This creates its A or AAAA
          record. Additional nameservers can be added by editing the NS record
          set.
        </p>
        <label>
          Initial TTL (seconds)
          <input
            name="ttl"
            type="number"
            defaultValue={300}
            min={0}
            max={2147483647}
            required
          />
        </label>
        <button className="primary" disabled={busy}>
          Create zone
        </button>
      </form>
    </Dialog>
  );
}
function RecordForm({
  zone,
  record,
  busy,
  error,
  close,
  save,
}: {
  zone: Zone;
  record: RecordSet | null;
  busy: boolean;
  error: string;
  close: () => void;
  save: (v: unknown) => void;
}) {
  const [type, setType] = useState(record?.type || "A");
  return (
    <Dialog
      title={record ? "Edit DNS record set" : "Add DNS record set"}
      close={close}
      error={error}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const v = Object.fromEntries(new FormData(e.currentTarget));
          save({
            name: v.name,
            type,
            ttl: Number(v.ttl),
            values: String(v.values)
              .split("\n")
              .map((v) => v.trim())
              .filter(Boolean),
            expected_revision: record?.revision || null,
            auto_ptr: (type === "A" || type === "AAAA") && v.auto_ptr === "on",
          });
        }}
      >
        <label>
          Record name
          <input
            name="name"
            defaultValue={record?.name || ""}
            readOnly={!!record}
            placeholder="monolith or @"
          />
        </label>
        <p className="hint">
          Relative names belong to {zone.name} Use @ for the zone apex. A fully
          qualified name must end in this zone.
        </p>
        <label>
          Record type
          <select
            aria-label="Record type"
            value={type}
            disabled={!!record}
            onChange={(e) => setType(e.target.value)}
          >
            {["A", "AAAA", "CNAME", "PTR", "TXT", "MX", "SRV", "NS"].map(
              (t) => (
                <option key={t}>{t}</option>
              ),
            )}
          </select>
        </label>
        <label>
          TTL (seconds)
          <input
            name="ttl"
            type="number"
            min={0}
            max={2147483647}
            defaultValue={record?.ttl ?? 300}
            required
          />
        </label>
        <label>
          Record values
          <textarea
            aria-label="Record values"
            name="values"
            rows={5}
            defaultValue={
              record?.records.map((r) => r.content).join("\n") || ""
            }
            required
          />
        </label>
        <p className="hint">
          One value per line. This edits the complete record set; retain values
          you want to keep. TXT: "text". MX: 10 mail.example. SRV: 0 5 389
          ldap.example. Targets use full DNS names.
        </p>
        {(type === "A" || type === "AAAA") && (
          <label className="checkbox">
            <input
              type="checkbox"
              name="auto_ptr"
              defaultChecked={!!record?.auto_ptr}
            />
            Manage matching PTR records
          </label>
        )}
        <p className="hint">
          Automatic PTR requires a matching managed reverse zone.
          Forward/reverse writes can partially succeed; pending changes provide
          safe retries. Manually edited PTR values are preserved.
        </p>
        <button className="primary" disabled={busy}>
          Save record set
        </button>
      </form>
    </Dialog>
  );
}
function SoaForm({
  zone,
  busy,
  error,
  close,
  save,
}: {
  zone: Zone;
  busy: boolean;
  error: string;
  close: () => void;
  save: (v: unknown) => void;
}) {
  const record = zone.rrsets.find(
    (r) => r.type === "SOA" && r.name === zone.name,
  );
  const parts = record?.records[0]?.content.split(/\s+/) || [];
  return (
    <Dialog title="DNS zone settings" close={close} error={error}>
      <p className="hint">
        SOA serials increase automatically on API changes. This is a standalone
        zone; secondary enrollment and transfers are not configured in Phase 1.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const v = Object.fromEntries(new FormData(e.currentTarget));
          save({
            ...v,
            ttl: Number(v.ttl),
            refresh: Number(v.refresh),
            retry: Number(v.retry),
            expire: Number(v.expire),
            minimum: Number(v.minimum),
            expected_revision: record?.revision,
          });
        }}
      >
        <label>
          SOA primary nameserver
          <input name="primary" defaultValue={parts[0]} required />
        </label>
        <label>
          SOA contact (DNS mailbox form)
          <input name="contact" defaultValue={parts[1]} required />
        </label>
        {[
          ["refresh", "Refresh", parts[3]],
          ["retry", "Retry", parts[4]],
          ["expire", "Expiry", parts[5]],
          ["minimum", "Negative cache TTL", parts[6]],
          ["ttl", "SOA TTL", record?.ttl],
        ].map(([name, label, value]) => (
          <label key={name}>
            {label} (seconds)
            <input
              name={String(name)}
              type="number"
              min={0}
              max={2147483647}
              defaultValue={value}
              required
            />
          </label>
        ))}
        <button className="primary" disabled={busy || !record}>
          Save zone settings
        </button>
      </form>
    </Dialog>
  );
}
