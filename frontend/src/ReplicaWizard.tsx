import { useEffect, useState } from "react";
import { Download, X, CheckCircle2 } from "lucide-react";
import type { DirectoryHealth, DirectoryNode } from "./Servers";
type Props = {
  existing?: DirectoryNode;
  health: DirectoryHealth;
  csrf: string;
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
  csrf,
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
    [downloaded, setDownloaded] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    void api("replication/setup")
      .then(setSetup)
      .catch((e) => setError(e.message));
  }, []);
  async function download() {
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
      const r = await fetch(`/api/replicas/${node.id}/bundle`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ acknowledge: true }),
      });
      if (!r.ok) {
        const v = await r.json();
        throw Error(v.error);
      }
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `forklift-replica-${node.id}.tar.gz`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloaded(true);
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
            <p className="eyebrow">NEW DIRECTORY SERVER</p>
            <h2>Add a replica</h2>
          </div>
          <button aria-label="Close setup" onClick={close}>
            <X />
          </button>
        </div>
        <p className="setup-intro">
          The primary was configured during Forklift setup. The new machine only
          needs Linux and Docker. Forklift installs its LDAP directory, manages
          its certificates and applies future credential changes from this
          WebUI.
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
            void download();
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
            <Download size={16} />
            {busy
              ? "Preparing deployment…"
              : downloaded
                ? "Download fresh enrollment"
                : "Download deployment"}
          </button>
        </form>
        {downloaded && (
          <>
            <h3>Install the new machine</h3>
            <ol className="steps">
              <li>
                Transfer the private archive and extract it on the new Docker
                host.
              </li>
              <li>
                Start the included Compose stack using Docker Compose or your
                Docker hosting UI. Permission preparation and enrollment run
                automatically.
              </li>
              <li>
                Return here and wait for confirmed synchronization. The machine
                is already registered in Hosts; SSH access remains unconfigured
                until you explicitly choose login groups and deploy its client
                configuration.
              </li>
            </ol>
            <details>
              <summary>Docker Compose installation command</summary>
              <pre>
                <code>docker compose up -d --build</code>
              </pre>
            </details>
            <p className="hint">
              This is initial stack deployment. All subsequent directory
              credentials, certificates and reconnect/restart actions are
              managed in Forklift. The one-use enrollment expires 15 minutes
              after generation. For private WebUI PKI, place its public CA at
              enrollment/manager-ca.crt before starting.
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
