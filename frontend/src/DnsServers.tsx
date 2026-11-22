import { Help, FieldHelp } from "./Help";
import { useEffect, useState } from "react";
import { Copy, Plus, RefreshCw, X } from "lucide-react";
type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type Probe = {
  responding: boolean;
  authoritative: boolean;
  serial: number | null;
};
type Node = {
  id: string;
  name: string;
  address: string;
  dns_port: number;
  control_port: number;
  zones: string[];
  revision: number;
  state: string;
  checked_at?: number;
  last_sync_at?: number;
  error?: string;
  transfers_revoked: boolean;
  certificate_expires_at?: string;
  credential_epoch: number;
  pending_epoch?: number | null;
  rotation?: string | null;
  certificate_rotation_pending?: boolean;
  report: {
    state?: string;
    api_available?: boolean | null;
    zones?: {
      name: string;
      synchronized: boolean;
      expected_serial: number | null;
      udp: Probe;
      tcp: Probe;
      primary: Probe;
      last_check?: number;
    }[];
  };
};
type Inventory = {
  primary: { address: string; dns_port: number } | null;
  servers: Node[];
};
export function DnsServers({ api, zones }: { api: Api; zones: string[] }) {
  const [inventory, setInventory] = useState<Inventory | null>(null),
    [editing, setEditing] = useState<Node | null | undefined>(),
    [joining, setJoining] = useState<Node | null>(null),
    [join, setJoin] = useState<{
      join_config: string;
      expires_at: number;
    } | null>(null),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  async function load() {
    setInventory(await api("dns/servers"));
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
  const date = (v?: number) =>
    v ? new Date(v * 1000).toLocaleString() : "Never confirmed";
  return (
    <section className="panel">
      <div className="panel-title">
        <div className="heading-help">
          <h2>DNS servers</h2>
          <Help label="DNS replication">
            The primary server accepts changes. Secondary servers keep copies
            and can answer DNS requests when the primary or Forklift is offline.
            Forklift checks the copies before showing them as synchronized. Keep
            server management ports private. Zone transfers verify the sender
            but do not encrypt the records; use a trusted private network or
            VPN.
          </Help>
        </div>
        <button
          disabled={busy}
          aria-label="Refresh DNS servers"
          onClick={() => perform(load)}
        >
          <RefreshCw size={17} />
        </button>
      </div>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <p role="status" className="hint">
          {notice}
        </p>
      )}

      {inventory && (
        <details open={!inventory.primary}>
          <summary>Primary DNS endpoint</summary>
          <form
            key={JSON.stringify(inventory.primary)}
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              void perform(async () => {
                await api("dns/primary", "PUT", {
                  address: String(f.get("address")),
                  dns_port: Number(f.get("dns_port")),
                  acknowledge: f.has("acknowledge"),
                });
                await load();
                setNotice(
                  "Primary endpoint saved. Reconcile enrolled nodes if the address changed.",
                );
              });
            }}
          >
            <label>
              Primary private IPv4 address
              <input
                aria-label="Primary private IPv4 address"
                name="address"
                defaultValue={inventory.primary?.address || ""}
                placeholder="192.168.1.2"
                required
              />
            </label>
            <FieldHelp
              label="Primary DNS endpoint"
              help={
                <>
                  Choose the private address and DNS port published by your
                  primary DNS container. Other machines cannot reach the default
                  localhost address. This is separate from LDAP and the WebUI.
                  If port 53 is already in use, choose another address or port.
                </>
              }
              caption={<>Published primary DNS port</>}
            >
              <input
                aria-label="Published primary DNS port"
                name="dns_port"
                type="number"
                min="1"
                max="65535"
                defaultValue={inventory.primary?.dns_port || 53}
                required
              />
            </FieldHelp>

            <label className="checkbox">
              <input name="acknowledge" type="checkbox" required />
              This endpoint is reachable from the secondary over TCP and UDP.
            </label>
            <button className="primary" disabled={busy}>
              Save primary DNS endpoint
            </button>
          </form>
        </details>
      )}
      <div className="table-toolbar">
        <h3>Secondary servers</h3>
        <button
          className="primary"
          disabled={busy || !inventory?.primary}
          onClick={() => {
            setError("");
            setEditing(null);
          }}
        >
          <Plus size={17} />
          Add DNS secondary
        </button>
      </div>
      {!inventory ? (
        <p className="hint">Loading servers…</p>
      ) : !inventory.servers.length ? (
        <p className="hint">No secondaries enrolled.</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Server / role</th>
                <th>State</th>
                <th>Last check / confirmed sync</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {inventory.servers.map((n) => (
                <tr key={n.id}>
                  <td>
                    <strong>{n.name}</strong>
                    <small>
                      {n.address}:{n.dns_port} · Secondary
                    </small>
                    <small>
                      Private HTTPS management: {n.address}:{n.control_port}
                    </small>
                    <small>
                      {n.zones.length} assigned zones · Connection key version{" "}
                      {n.credential_epoch}
                      {n.pending_epoch ? ` → ${n.pending_epoch} pending` : ""}
                    </small>
                    {n.certificate_expires_at && (
                      <small>
                        Certificate expires {n.certificate_expires_at}
                      </small>
                    )}
                  </td>
                  <td>
                    <span
                      className={
                        n.report.state === "synchronized" ? "pill" : "badge"
                      }
                    >
                      {n.state === "enrolled"
                        ? n.rotation
                          ? `Credential rotation: ${n.rotation.replaceAll("_", " ")}`
                          : n.certificate_rotation_pending
                            ? "Certificate rotation pending"
                            : n.report.state?.replaceAll("_", " ") ||
                              "Not checked"
                        : n.state}
                    </span>
                    {n.error && <small role="status">{n.error}</small>}
                    {n.transfers_revoked && (
                      <small>Primary transfer authorization revoked</small>
                    )}
                  </td>
                  <td>
                    <small>Checked: {date(n.checked_at)}</small>
                    <small>Confirmed sync: {date(n.last_sync_at)}</small>
                  </td>
                  <td>
                    <div className="actions">
                      {["pending", "failed"].includes(n.state) && (
                        <button
                          disabled={busy}
                          onClick={() => {
                            setJoining(n);
                            setJoin(null);
                            setError("");
                          }}
                        >
                          Generate DNS join
                        </button>
                      )}
                      {n.state === "enrolled" && (
                        <>
                          <button
                            disabled={
                              busy ||
                              !!n.rotation ||
                              n.certificate_rotation_pending
                            }
                            onClick={() => setEditing(n)}
                          >
                            Assign zones
                          </button>
                          <button
                            disabled={
                              busy ||
                              !!n.rotation ||
                              n.certificate_rotation_pending
                            }
                            onClick={() =>
                              perform(async () => {
                                const result = await api(
                                  `dns/servers/${n.id}/reconcile`,
                                  "POST",
                                  {},
                                );
                                setNotice(
                                  result.error ||
                                    "Configuration applied; check synchronization next.",
                                );
                                await load();
                              })
                            }
                          >
                            Reconcile DNS server
                          </button>
                          <button
                            disabled={busy}
                            onClick={() =>
                              perform(async () => {
                                await api(
                                  `dns/servers/${n.id}/check`,
                                  "POST",
                                  {},
                                );
                                await load();
                              })
                            }
                          >
                            Check synchronization
                          </button>
                          <button
                            disabled={busy || n.certificate_rotation_pending}
                            onClick={() =>
                              perform(async () => {
                                if (
                                  !confirm(
                                    "Replace the passwords used to copy and manage DNS on this server? Forklift checks that copying still works before removing the old access.",
                                  )
                                )
                                  return;
                                const value = await api(
                                  `dns/servers/${n.id}/credentials`,
                                  "POST",
                                  { acknowledge: true },
                                );
                                setNotice(
                                  value.error ||
                                    "DNS credentials rotated and old permissions retired.",
                                );
                                await load();
                              })
                            }
                          >
                            {n.rotation
                              ? "Resume DNS credential rotation"
                              : "Rotate DNS credentials"}
                          </button>
                          {!n.certificate_rotation_pending && (
                            <button
                              disabled={busy || !!n.rotation}
                              onClick={() =>
                                perform(async () => {
                                  if (
                                    !confirm(
                                      "Stage a new private HTTPS certificate on this DNS node? Its private key remains on that machine.",
                                    )
                                  )
                                    return;
                                  await api(
                                    `dns/servers/${n.id}/certificate`,
                                    "POST",
                                    { acknowledge: true },
                                  );
                                  await load();
                                })
                              }
                            >
                              Stage DNS certificate
                            </button>
                          )}
                          {n.certificate_rotation_pending && (
                            <button
                              disabled={busy || !!n.rotation}
                              onClick={() =>
                                perform(async () => {
                                  if (
                                    !confirm(
                                      "Activate the staged certificate, verify a connection pinned only to the new identity, and retire old trust?",
                                    )
                                  )
                                    return;
                                  const value = await api(
                                    `dns/servers/${n.id}/certificate/finalize`,
                                    "POST",
                                    { acknowledge: true },
                                  );
                                  setNotice(
                                    value.error ||
                                      "DNS certificate activated and old trust retired.",
                                  );
                                  await load();
                                })
                              }
                            >
                              Finish DNS certificate rotation
                            </button>
                          )}
                        </>
                      )}
                      <button
                        disabled={busy}
                        onClick={() =>
                          perform(async () => {
                            if (
                              !confirm(
                                `Revoke ${n.name}'s zone transfers and delete its managed secondary zones? Stop/remove its Docker stack separately.`,
                              )
                            )
                              return;
                            const result = await api(
                              `dns/servers/${n.id}`,
                              "DELETE",
                              { acknowledge: true },
                            );
                            setNotice(
                              result.removed
                                ? "DNS node removed."
                                : result.server.error,
                            );
                            await load();
                          })
                        }
                      >
                        {n.state === "removing"
                          ? "Retry removal"
                          : "Remove DNS server"}
                      </button>
                      {n.state === "removing" && n.transfers_revoked && (
                        <button
                          disabled={busy}
                          onClick={() =>
                            perform(async () => {
                              if (
                                !confirm(
                                  "Forget this node while retaining its cached DNS data? Its transfers are revoked. Stop/remove its stack in your Docker hosting interface; it may otherwise answer old data until zones expire.",
                                )
                              )
                                return;
                              await api(`dns/servers/${n.id}`, "DELETE", {
                                acknowledge: true,
                                retain_data: true,
                              });
                              await load();
                            })
                          }
                        >
                          Keep data; forget node
                        </button>
                      )}
                    </div>
                    {n.report.zones && (
                      <details>
                        <summary>Zone diagnostics</summary>
                        {n.report.zones.map((z) => (
                          <div key={z.name}>
                            <strong>{z.name}</strong>
                            <small>
                              {z.synchronized
                                ? "Synchronization confirmed"
                                : "Synchronization not confirmed"}{" "}
                              · primary serial {z.expected_serial ?? "unknown"}
                            </small>
                            <small>
                              Secondary UDP{" "}
                              {z.udp.authoritative
                                ? z.udp.serial
                                : "no authoritative SOA"}{" "}
                              · TCP{" "}
                              {z.tcp.authoritative
                                ? z.tcp.serial
                                : "no authoritative SOA"}
                            </small>
                            <small>
                              Primary from secondary:{" "}
                              {z.primary.authoritative
                                ? z.primary.serial
                                : "unreachable / no authoritative SOA"}
                            </small>
                          </div>
                        ))}
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing !== undefined && (
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label={editing ? "Assign DNS zones" : "Add DNS secondary"}
          >
            <div className="panel-title">
              <h2>{editing ? "Assign DNS zones" : "Add DNS secondary"}</h2>
              <button
                aria-label="Close DNS server dialog"
                onClick={() => setEditing(undefined)}
              >
                <X />
              </button>
            </div>
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const f = new FormData(e.currentTarget);
                void perform(async () => {
                  const selected = f.getAll("zones").map(String);
                  if (editing)
                    await api(`dns/servers/${editing.id}/assignments`, "PUT", {
                      zones: selected,
                      revision: editing.revision,
                    });
                  else {
                    const n = await api("dns/servers", "POST", {
                      name: String(f.get("name")),
                      address: String(f.get("address")),
                      dns_port: Number(f.get("dns_port")),
                      control_port: Number(f.get("control_port")),
                      zones: selected,
                    });
                    setJoining(n);
                    setJoin(null);
                  }
                  setEditing(undefined);
                  await load();
                  setNotice(
                    editing
                      ? "Assignments saved. Reconcile this server to apply zone additions/removals."
                      : "Server registered. Generate its one-time join configuration.",
                  );
                });
              }}
            >
              {!editing && (
                <>
                  <label>
                    DNS server name
                    <input
                      aria-label="DNS server name"
                      name="name"
                      placeholder="Secondary DNS"
                      maxLength={100}
                      required
                    />
                  </label>
                  <label>
                    Secondary private IPv4 address
                    <input
                      aria-label="Secondary private IPv4 address"
                      name="address"
                      placeholder="192.168.1.3"
                      required
                    />
                  </label>
                  <label>
                    Secondary DNS port
                    <input
                      aria-label="Secondary DNS port"
                      name="dns_port"
                      type="number"
                      min="1"
                      max="65535"
                      defaultValue={53}
                      required
                    />
                  </label>
                  <FieldHelp
                    label="Secondary DNS deployment"
                    help={
                      <>
                        Choose the new Docker host’s private address and two
                        unused ports. Forklift creates the DNS service and its
                        certificates for you.
                      </>
                    }
                    caption={<>Private DNS management port</>}
                  >
                    <input
                      aria-label="Private DNS management port"
                      name="control_port"
                      type="number"
                      min="1"
                      max="65535"
                      defaultValue={9544}
                      required
                    />
                  </FieldHelp>
                </>
              )}
              <fieldset className="host-groups">
                <legend>
                  <span className="help-row">
                    Zones to replicate
                    <Help label="DNS zone assignments">
                      Choose the zones this server should copy. Removing a zone
                      here removes only its secondary copy; the primary records
                      stay unchanged. Add new zones to this list when you want
                      them copied. Your network’s DNS resolver must be set up to
                      use both servers.
                    </Help>
                  </span>
                </legend>
                {[...new Set([...zones, ...(editing?.zones || [])])].map(
                  (z) => (
                    <label key={z} className="checkbox">
                      <input
                        name="zones"
                        type="checkbox"
                        value={z}
                        defaultChecked={
                          editing
                            ? editing.zones.includes(z)
                            : zones.length <= 32
                        }
                      />
                      {z}
                    </label>
                  ),
                )}
              </fieldset>

              <button className="primary" disabled={busy}>
                Save DNS server
              </button>
            </form>
          </section>
        </div>
      )}
      {joining && (
        <div className="overlay">
          <section
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Deploy DNS secondary"
          >
            <div className="panel-title">
              <h2>Deploy DNS secondary</h2>
              <button
                aria-label="Close DNS enrollment"
                onClick={() => {
                  setJoining(null);
                  setJoin(null);
                }}
              >
                <X />
              </button>
            </div>
            <p>
              {joining.name} · {joining.address}:{joining.dns_port}
            </p>
            {!join ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const f = new FormData(e.currentTarget);
                  void perform(async () => {
                    setJoin(
                      await api(
                        `dns/servers/${joining.id}/deployment`,
                        "POST",
                        {
                          acknowledge: f.has("acknowledge"),
                          manager_ca:
                            String(f.get("manager_ca") || "").trim() || null,
                        },
                      ),
                    );
                    await load();
                  });
                }}
              >
                <FieldHelp
                  label="Manager HTTPS trust"
                  caption={<>Manager HTTPS CA (optional)</>}
                  help={
                    <>
                      The new machine must be able to reach Forklift over HTTPS.
                      Leave the certificate field blank for a publicly trusted
                      certificate, or supply the public certificate for your
                      private certificate authority.
                    </>
                  }
                >
                  <textarea
                    aria-label="Manager HTTPS CA (optional)"
                    name="manager_ca"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </FieldHelp>
                <label className="checkbox">
                  <input type="checkbox" name="acknowledge" required />I will
                  keep the one-time join configuration private.
                </label>
                <button className="primary" disabled={busy}>
                  Generate DNS join configuration
                </button>
              </form>
            ) : (
              <>
                <FieldHelp
                  label="Deploy the DNS secondary"
                  caption={<>DNS join configuration</>}
                  help={
                    <>
                      Use the same Forklift release on the second Docker host.
                      Open deploy/dns-secondary and save the join setting below
                      in that stack’s environment. Start the stack before{" "}
                      {date(join.expires_at)}. Then choose Check synchronization
                      here. Keep its storage volume when restarting: it holds
                      the server’s saved records and keys.
                    </>
                  }
                >
                  <textarea
                    aria-label="DNS join configuration"
                    readOnly
                    value={join.join_config}
                  />
                </FieldHelp>
                <button
                  disabled={busy}
                  onClick={() =>
                    perform(async () => {
                      await navigator.clipboard.writeText(join.join_config);
                      setNotice("DNS join configuration copied.");
                    })
                  }
                >
                  <Copy size={17} />
                  Copy DNS join configuration
                </button>
              </>
            )}
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
          </section>
        </div>
      )}
    </section>
  );
}
