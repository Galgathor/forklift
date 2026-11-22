import { useEffect, useState } from "react";
import { FieldHelp, Help } from "./Help";
import type { ClientRecord } from "./ClientEnrollment";
type Selector = { interface: string; address: string | null };
type Policy = {
  offline_after: number;
  dns_updates: boolean;
  ipv4: Selector | null;
  ipv6: Selector | null;
};
type Event = { id: string; at: number; kind: string; detail: unknown };
type Settings = { policy: Policy; revision: number; history: Event[] };
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
export function ClientMonitoring({
  client,
  api,
  refresh,
}: {
  client: ClientRecord;
  api: Api;
  refresh: () => Promise<void>;
}) {
  const [settings, setSettings] = useState<Settings | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [saved, setSaved] = useState(false);
  const m = client.monitoring;
  async function load() {
    setError("");
    try {
      setSettings(
        (await api(`hosts/${client.host_id}/monitoring`)) as Settings,
      );
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    let active = true;
    void api(`hosts/${client.host_id}/monitoring`)
      .then((v) => {
        if (active) setSettings(v as Settings);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [client.host_id]);
  function change(changes: Partial<Policy>) {
    if (settings)
      setSettings({ ...settings, policy: { ...settings.policy, ...changes } });
    setSaved(false);
  }
  const latest = m?.inventory;
  const addresses = latest?.addresses || [];
  function selector(family: "ipv4" | "ipv6") {
    if (!settings) return null;
    const value = settings.policy[family];
    const candidates = addresses.filter((a) =>
      family === "ipv4" ? !a.address.includes(":") : a.address.includes(":"),
    );
    const interfaces = [...new Set(candidates.map((a) => a.interface))];
    if (value && !interfaces.includes(value.interface))
      interfaces.push(value.interface);
    return (
      <div className="form-grid" key={family}>
        <FieldHelp
          label={`${family} interface`}
          caption={family === "ipv4" ? "IPv4 interface" : "IPv6 interface"}
          help="Follow an interface only when it has one eligible address of this family. Pin an address to avoid ambiguity on multihomed interfaces. A missing or ambiguous selection pauses DNS updates."
        >
          <select
            value={value?.interface || ""}
            onChange={(e) =>
              change({
                [family]: e.target.value
                  ? { interface: e.target.value, address: null }
                  : null,
              })
            }
          >
            <option value="">
              {family === "ipv4" ? "Select interface" : "Keep configured IPv6"}
            </option>
            {interfaces.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </FieldHelp>
        <FieldHelp
          label={`${family} address`}
          caption="Address selection"
          help="Follow uses the interface's sole eligible address as it changes. A pinned address must still be present in inventory; Forklift never chooses the first of several addresses."
        >
          <select
            disabled={!value}
            value={value?.address || ""}
            onChange={(e) =>
              value &&
              change({
                [family]: { ...value, address: e.target.value || null },
              })
            }
          >
            <option value="">Follow sole interface address</option>
            {value?.address &&
              !candidates.some(
                (a) =>
                  a.interface === value.interface &&
                  a.address === value.address,
              ) && (
                <option value={value.address}>
                  {value.address} (not reported)
                </option>
              )}
            {candidates
              .filter((a) => a.interface === value?.interface)
              .map((a) => (
                <option key={a.address} value={a.address}>
                  {a.address}
                </option>
              ))}
          </select>
        </FieldHelp>
      </div>
    );
  }
  return (
    <section className="client-monitoring">
      <div className="heading-help">
        <h3>Monitoring</h3>
        <Help label="Host monitoring">
          Heartbeat freshness is measured on the server. Online means the client
          reported recently; authentication health checks arrive in a later
          milestone. The offline threshold is at least three configured
          heartbeat intervals. Manual inventory has no offline status.
        </Help>
      </div>
      <dl>
        <div>
          <dt>Connection</dt>
          <dd>{m?.connectivity.replaceAll("_", " ") || "Not reporting"}</dd>
        </div>
        <div>
          <dt>Last heartbeat</dt>
          <dd>
            {m?.received_at
              ? new Date(m.received_at * 1000).toLocaleString()
              : "Not reported"}
          </dd>
        </div>
        <div>
          <dt>Offline after</dt>
          <dd>{m?.offline_after || 900} seconds</dd>
        </div>
        <div>
          <dt>Interfaces</dt>
          <dd>{m?.interfaces.join(", ") || "Not reported"}</dd>
        </div>
        <div>
          <dt>DNS update</dt>
          <dd>{m?.dns?.state.replaceAll("_", " ") || "Not reported"}</dd>
        </div>
      </dl>
      {m?.dns?.error && (
        <div className="error" role="status">
          {m.dns.error}
        </div>
      )}
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {settings && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            setSaved(false);
            void api(`hosts/${client.host_id}/monitoring`, "PUT", {
              policy: settings.policy,
              revision: settings.revision,
            })
              .then(async (value) => {
                setSettings(value as Settings);
                setSaved(true);
                await refresh();
              })
              .catch((e) => setError(e.message))
              .finally(() => setBusy(false));
          }}
        >
          <FieldHelp
            label="Offline threshold"
            caption="Offline threshold (seconds)"
            help="Use 90–10800 seconds. The effective threshold is the greater of this setting and three reported heartbeat intervals. Offline transitions and recovery are recorded without requiring the client to report its own outage."
          >
            <input
              type="number"
              min={90}
              max={10800}
              required
              value={settings.policy.offline_after}
              onChange={(e) =>
                change({ offline_after: Number(e.target.value) })
              }
            />
          </FieldHelp>
          <div className="field-heading">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={settings.policy.dns_updates}
                onChange={(e) => change({ dns_updates: e.target.checked })}
              />
              Automatically update managed DNS addresses
            </label>
            <Help label="Automatic client DNS updates">
              Configure and apply this host's DNS first. Updates require
              existing host ownership, preserve unrelated values, and follow
              only your selected interfaces or addresses. Hostnames and FQDNs
              stay under administrator control. Inventory can succeed while DNS
              needs retry; the next heartbeat retries current intent. A
              replacement client must be authorized again.
            </Help>
          </div>
          {settings.policy.dns_updates && (
            <>
              {selector("ipv4")}
              {selector("ipv6")}
            </>
          )}
          <div className="wizard-actions">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => void load()}
            >
              Reload monitoring
            </button>
            <button className="primary" disabled={busy}>
              {busy ? "Saving…" : "Save monitoring"}
            </button>
          </div>
          {saved && (
            <p role="status">
              Monitoring settings saved. DNS changes apply on the next
              heartbeat.
            </p>
          )}
        </form>
      )}
      <div className="heading-help">
        <h3>History</h3>
        <Help label="Client history">
          The latest 100 server-timestamped monitoring events are retained.
          Reload monitoring to fetch newer history. Inventory is self-reported
          by this machine; it does not prove a successful password login.
        </Help>
      </div>
      {!settings?.history.length ? (
        <p className="muted">No monitoring events yet.</p>
      ) : (
        <ul className="client-history">
          {[...settings.history].reverse().map((e) => (
            <li key={e.id}>
              <strong>{e.kind.replaceAll("_", " ")}</strong>{" "}
              <small>{new Date(e.at * 1000).toLocaleString()}</small>
              <details>
                <summary>Event details</summary>
                <pre>{JSON.stringify(e.detail, null, 2)}</pre>
              </details>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
