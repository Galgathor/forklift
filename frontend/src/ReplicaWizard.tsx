import { useEffect, useState } from "react";
import { Copy, X, CheckCircle2 } from "lucide-react";
import type { DirectoryHealth, DirectoryNode } from "./Servers";
type Props = {
  existing?: DirectoryNode;
  health: DirectoryHealth;
  readOnly: boolean;
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  refresh: () => Promise<void>;
  close: () => void;
};
type Setup = {
  manager_url: string;
  https_ready: boolean;
  primary: { endpoint: string };
};
export function ReplicaWizard({
  existing,
  health,
  readOnly,
  api,
  refresh,
  close,
}: Props) {
  const [setup, setSetup] = useState<Setup | null>(null),
    [name, setName] = useState(existing?.name || ""),
    [address, setAddress] = useState(existing?.address || ""),
    [hostname, setHostname] = useState(
      existing ? new URL(existing.endpoint).hostname : "",
    ),
    [port, setPort] = useState(
      existing ? Number(new URL(existing.endpoint).port || 1636) : 1636,
    ),
    [controlPort, setControlPort] = useState(existing?.control_port || 9443),
    [created, setCreated] = useState(existing),
    [join, setJoin] = useState<{
      join_config: string;
      expires_at: number;
    } | null>(null),
    [managerCa, setManagerCa] = useState(""),
    [copied, setCopied] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    void api("replication/setup")
      .then(setSetup)
      .catch((e) => setError(e.message));
  }, []);
  async function generate() {
    setBusy(true);
    setError("");
    try {
      let node = created;
      if (!node) {
        node = (await api("directory-servers", "POST", {
          name,
          address,
          hostname: hostname || address,
          port,
          control_port: controlPort,
        })) as DirectoryNode;
        setCreated(node);
      }
      const value = await api(`replicas/${node.id}/deployment`, "POST", {
        acknowledge: true,
        manager_ca: managerCa.trim() || null,
      });
      setJoin(value);
      setCopied(false);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const current = created
    ? health.servers.find((node) => node.id === created.id)
    : undefined;
  return (
    <div className="overlay">
      <section
        className="dialog replica-wizard"
        role="dialog"
        aria-modal="true"
        aria-label="Add directory server"
      >
        <div className="panel-title">
          <div>
            <h2>Add a replica</h2>
          </div>
          <button aria-label="Close setup" onClick={close}>
            <X />
          </button>
        </div>
        <p className="setup-intro">
          The new machine needs Linux and Docker. Its primary connection is
          inherited from setup.
        </p>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {setup && (
          <p className="hint">
            Copies from {setup.primary.endpoint}. Enrolls through{" "}
            {setup.manager_url}. These settings are inherited automatically.
          </p>
        )}
        {setup && !setup.https_ready && (
          <div className="error" role="status">
            Configure WebUI HTTPS in Settings before enrolling a replica. The
            management URL and the directory's private listener are separate
            connections.
          </div>
        )}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void generate();
          }}
        >
          <label>
            Friendly name
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={100}
              required
              readOnly={!!created}
            />
          </label>
          <label>
            New machine's private IPv4 address
            <input
              value={address}
              onChange={(e) => setAddress(e.target.value.trim())}
              placeholder="192.168.1.20"
              required
              readOnly={!!created}
            />
          </label>
          <details>
            <summary>Advanced: DNS name and ports</summary>
            <label>
              Stable DNS name (optional)
              <input
                value={hostname}
                onChange={(e) => setHostname(e.target.value.trim())}
                placeholder="Leave blank to use the private IP"
                readOnly={!!created}
              />
            </label>
            <p className="hint">
              A private IP needs no DNS record. If you choose a name, make it
              resolve to this private address.
            </p>
            <label>
              Encrypted directory port
              <input
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(Number(e.target.value))}
                readOnly={!!created}
              />
            </label>
            <label>
              Private management port
              <input
                type="number"
                min={1}
                max={65535}
                value={controlPort}
                onChange={(e) => setControlPort(Number(e.target.value))}
                readOnly={!!created}
              />
            </label>
          </details>
          <details>
            <summary>Private HTTPS certificate authority (optional)</summary>
            <label>
              WebUI HTTPS CA certificate
              <textarea
                value={managerCa}
                onChange={(e) => setManagerCa(e.target.value)}
                rows={4}
                placeholder="-----BEGIN CERTIFICATE-----"
                spellCheck={false}
              />
            </label>
            <p className="hint">
              Leave blank for a publicly trusted WebUI certificate. For private
              PKI, paste its public CA certificate here. Never paste a private
              key.
            </p>
          </details>
          <p className="hint">
            Allow the manager to reach both private ports and Linux clients to
            reach the directory port. The new machine must reach the primary and
            the WebUI HTTPS address. No existing LDAP installation, manual
            certificate generation or administrator script is needed.
          </p>
          <button
            className="primary"
            disabled={busy || readOnly || !setup?.https_ready}
          >
            {busy
              ? "Generating…"
              : join
                ? "Generate new join configuration"
                : "Generate join configuration"}
          </button>
        </form>
        {join && (
          <>
            <h3>Deploy the replica</h3>
            <ol className="steps">
              <li>
                Clone the Forklift repository on the new machine, using the same
                release as this manager. Open <code>deploy/replica</code>. A
                Docker hosting UI can also deploy this repository’s replica
                Compose file.
              </li>
              <li>
                Paste the configuration below into{" "}
                <code>deploy/replica/.env</code>, or set{" "}
                <code>FORKLIFT_REPLICA_JOIN</code> in your Docker hosting UI. It
                contains a temporary secret; do not commit it.
              </li>
              <li>
                Start the replica Compose stack and wait here for confirmed
                synchronization. No archive or certificate transfer is required.
              </li>
            </ol>
            <label>
              Join configuration
              <textarea
                aria-label="Join configuration"
                readOnly
                value={join.join_config}
                rows={4}
                spellCheck={false}
                onFocus={(e) => e.currentTarget.select()}
              />
            </label>
            <button
              className="secondary"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(join.join_config);
                  setCopied(true);
                } catch {
                  setError(
                    "Clipboard is unavailable. Select and copy the join configuration above.",
                  );
                }
              }}
            >
              <Copy size={16} />
              {copied ? "Copied" : "Copy join configuration"}
            </button>
            <p className="hint">
              Expires {new Date(join.expires_at * 1000).toLocaleString()}.
              Generating a new configuration invalidates the previous one.
            </p>
            <details>
              <summary>Docker Compose installation command</summary>
              <pre>
                <code>{"cd deploy/replica\ndocker compose up -d --build"}</code>
              </pre>
            </details>
            <p className="hint">
              The primary’s public CA is included. The replica generates its
              private key locally and enrolls over verified HTTPS. After
              enrollment, you can remove the temporary join setting; future
              restarts use persistent configuration. SSH access still requires
              choosing login groups and deploying the host’s client
              configuration.
            </p>
            <span
              className={current?.state === "synchronized" ? "pill" : "badge"}
              role="status"
            >
              {current?.state === "synchronized" ? (
                <>
                  <CheckCircle2 size={16} />
                  Synchronization confirmed
                </>
              ) : current?.enrollment_state === "enrolled" ? (
                "Enrolled · checking synchronization"
              ) : (
                "Waiting for enrollment"
              )}
            </span>
            {current?.error && (
              <p className="hint server-error">{current.error}</p>
            )}
            <button
              className="secondary"
              disabled={busy}
              onClick={() => refresh()}
            >
              Refresh connection
            </button>
          </>
        )}
      </section>
    </div>
  );
}
