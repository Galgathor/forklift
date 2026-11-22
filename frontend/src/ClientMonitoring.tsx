import { useEffect, useState } from "react";
import { FieldHelp, Help } from "./Help";
import type { ClientRecord } from "./ClientEnrollment";
type Selector = { interface: string; address: string | null };
type Policy = {
  offline_after: number;
  dns_updates: boolean;
  ipv4: Selector | null;
  ipv6: Selector | null;
  diagnostics: {
    authentication: boolean;
    ssh: boolean;
    domain: string;
    test_user: string | null;
    test_group: string | null;
    ssh_source: string | null;
    ssh_source_name: string | null;
    ssh_local: string | null;
    ssh_port: number;
    failure_threshold: number;
  };
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
          help="Choose the network connection to follow. If it has several addresses, select one explicitly. Updates pause if the selected address is missing or unclear."
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
          help="Follow tracks address changes when there is only one address to choose from. Select a specific address if this connection has several."
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
          Online means the client has reported recently. It does not mean every
          service is healthy. Forklift marks a client offline after enough
          reports are missed. Hosts without the client are not marked offline
          for missing reports.
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
            help="Choose how long to wait before marking a client offline, from 90 to 10800 seconds. Forklift always allows at least three missed reports."
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
              Set up and apply this host’s DNS records first. Then choose the
              network address Forklift should follow. Other hosts’ records and
              your chosen DNS names stay unchanged. If a DNS update fails, the
              client can still report its status and Forklift will retry. A
              replacement client needs fresh approval.
            </Help>
          </div>
          {settings.policy.dns_updates && (
            <>
              {selector("ipv4")}
              {selector("ipv6")}
            </>
          )}
          <div className="heading-help">
            <h3>Diagnostic expectations</h3>
            <Help label="Diagnostic expectations">
              Choose which sign-in and SSH settings to check. These checks only
              read settings; they do not change them or try a password login.
              Test users and groups are looked up without passwords. Missing
              results do not mean an old problem is fixed.
            </Help>
          </div>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={settings.policy.diagnostics.authentication}
              onChange={(e) =>
                change({
                  diagnostics: {
                    ...settings.policy.diagnostics,
                    authentication: e.target.checked,
                  },
                })
              }
            />
            Check Linux authentication configuration
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={settings.policy.diagnostics.ssh}
              onChange={(e) =>
                change({
                  diagnostics: {
                    ...settings.policy.diagnostics,
                    ssh: e.target.checked,
                  },
                })
              }
            />
            Check SSH configuration
          </label>
          <div className="form-grid">
            {(
              [
                ["domain", "SSSD domain"],
                ["test_user", "Test username"],
                ["test_group", "Test group"],
                ["ssh_source", "SSH source address"],
                ["ssh_source_name", "SSH source hostname"],
                ["ssh_local", "SSH local address"],
              ] as const
            ).map(([key, label]) => (
              <FieldHelp
                key={key}
                label={label}
                caption={label}
                help={
                  key === "ssh_source_name"
                    ? "Optional name of the machine connecting over SSH. Leave blank to check using its IP address."
                    : "Enter the connection details you want to check. This only checks SSH settings; it does not change them or try to sign in."
                }
              >
                <input
                  value={settings.policy.diagnostics[key] || ""}
                  maxLength={key === "ssh_source_name" ? 253 : 64}
                  onChange={(e) =>
                    change({
                      diagnostics: {
                        ...settings.policy.diagnostics,
                        [key]: e.target.value || null,
                      },
                    })
                  }
                />
              </FieldHelp>
            ))}
            <FieldHelp
              label="SSH diagnostic port"
              caption="SSH port"
              help="Check that SSH answers at this address and port. No password is sent and no sign-in is attempted."
            >
              <input
                type="number"
                min={1}
                max={65535}
                value={settings.policy.diagnostics.ssh_port}
                onChange={(e) =>
                  change({
                    diagnostics: {
                      ...settings.policy.diagnostics,
                      ssh_port: Number(e.target.value),
                    },
                  })
                }
              />
            </FieldHelp>
            <FieldHelp
              label="Issue failure threshold"
              caption="Consecutive failing reports"
              help="Choose how many failed checks, from 1 to 5, should open an issue. A successful check closes it. Missing results leave it open."
            >
              <input
                type="number"
                min={1}
                max={5}
                value={settings.policy.diagnostics.failure_threshold}
                onChange={(e) =>
                  change({
                    diagnostics: {
                      ...settings.policy.diagnostics,
                      failure_threshold: Number(e.target.value),
                    },
                  })
                }
              />
            </FieldHelp>
          </div>
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
          Shows the latest 100 host events. Reload to see newer events. Reports
          come from the client and do not prove that password sign-in works.
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
