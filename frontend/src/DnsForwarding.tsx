import { useEffect, useState } from "react";
import { Help, FieldHelp } from "./Help";

type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type Upstream = { address: string; port: number };
type Settings = {
  enabled: boolean;
  upstreams: Upstream[];
  allowed_clients: string[];
};

export function DnsForwarding({ api }: { api: Api }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [upstreams, setUpstreams] = useState<Upstream[]>([]);
  const [networks, setNetworks] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  useEffect(() => {
    api("dns/forwarding")
      .then((value) => {
        setSettings(value.settings);
        setUpstreams(
          value.settings.upstreams.length
            ? value.settings.upstreams
            : [{ address: "", port: 53 }],
        );
        setNetworks(value.settings.allowed_clients.join("\n"));
      })
      .catch((e) => setError(e.message));
  }, []);
  return (
    <section className="panel">
      <div className="heading-help">
        <h2>DNS forwarding</h2>
        <Help label="DNS forwarding">
          Forklift answers managed zones locally and sends other queries to your
          upstream DNS servers. Updated DNS peers copy these settings
          automatically and keep using them during an outage. Each peer answers
          the managed zones assigned to it.
        </Help>
      </div>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {notice && <p role="status">{notice}</p>}
      {settings && (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            setNotice("");
            try {
              const value = await api("dns/forwarding", "PUT", {
                enabled: settings.enabled,
                upstreams: upstreams
                  .filter((p) => p.address.trim())
                  .map((p) => ({ ...p, address: p.address.trim() })),
                allowed_clients: networks.split(/\s+/).filter(Boolean),
              });
              setSettings(value.settings);
              setNotice("DNS forwarding settings saved.");
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label className="checkbox">
            <input
              type="checkbox"
              checked={settings.enabled}
              disabled={busy}
              onChange={(e) =>
                setSettings({ ...settings, enabled: e.target.checked })
              }
            />
            Forward queries for other zones
          </label>
          {upstreams.map((peer, index) => (
            <div key={index} className="form-grid">
              <FieldHelp
                label={`Upstream DNS server ${index + 1}`}
                caption={<>Upstream DNS server {index + 1}</>}
                help={
                  <>
                    Enter another DNS server’s IP address, such as 192.168.1.1.
                    Do not use Forklift itself or a server that sends the same
                    queries back to Forklift.
                  </>
                }
              >
                <input
                  aria-label={`Upstream DNS server ${index + 1}`}
                  value={peer.address}
                  disabled={busy}
                  placeholder="192.168.1.1"
                  onChange={(e) =>
                    setUpstreams(
                      upstreams.map((p, i) =>
                        i === index ? { ...p, address: e.target.value } : p,
                      ),
                    )
                  }
                />
              </FieldHelp>
              <label>
                Upstream port {index + 1}
                <input
                  aria-label={`Upstream port ${index + 1}`}
                  type="number"
                  min="1"
                  max="65535"
                  value={peer.port}
                  disabled={busy}
                  onChange={(e) =>
                    setUpstreams(
                      upstreams.map((p, i) =>
                        i === index
                          ? { ...p, port: Number(e.target.value) }
                          : p,
                      ),
                    )
                  }
                />
              </label>
              {upstreams.length > 1 && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    setUpstreams(upstreams.filter((_, i) => i !== index))
                  }
                >
                  Remove upstream {index + 1}
                </button>
              )}
            </div>
          ))}
          {upstreams.length < 4 && (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                setUpstreams([...upstreams, { address: "", port: 53 }])
              }
            >
              Add upstream DNS server
            </button>
          )}
          <FieldHelp
            label="Networks allowed to forward"
            caption={<>Networks allowed to forward</>}
            help={
              <>
                Enter one private network per line, such as 192.168.1.0/24. Only
                these clients can send queries upstream. Managed zones remain
                available as before. Never make forwarding available to the
                public internet.
              </>
            }
          >
            <textarea
              aria-label="Networks allowed to forward"
              rows={3}
              value={networks}
              required
              disabled={busy}
              onChange={(e) => setNetworks(e.target.value)}
            />
          </FieldHelp>
          <button className="primary" disabled={busy}>
            Save DNS forwarding
          </button>
        </form>
      )}
    </section>
  );
}
