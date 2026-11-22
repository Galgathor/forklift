import { Help, FieldHelp } from "./Help";
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
            <div className="heading-help">
              <h2>Add a replica</h2>
              <Help label="Replica prerequisites">
                Use a Linux machine with Docker installed. Forklift copies the
                directory from your primary server automatically. The new
                machine must be able to reach Forklift over HTTPS and connect to
                the primary directory. Forklift must also be able to reach the
                new server’s directory and management ports. You do not need to
                install LDAP or create certificates yourself.
              </Help>
            </div>
          </div>
          <button aria-label="Close setup" onClick={close}>
            <X />
          </button>
        </div>

        {error && (
          <div className="error" role="alert">
            {error}
          </div>
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
            <FieldHelp
              label="Replica DNS names"
              help={
                <>
                  Use a private IP address to avoid extra DNS setup. If you use
                  a name, make sure it points to this address.
                </>
              }
              caption={<>Stable DNS name (optional)</>}
            >
              <input
                value={hostname}
                onChange={(e) => setHostname(e.target.value.trim())}
                placeholder="Leave blank to use the private IP"
                readOnly={!!created}
              />
            </FieldHelp>

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
            <FieldHelp
              label="Private HTTPS trust"
              help={
                <>
                  Leave this blank if browsers already trust your Forklift HTTPS
                  certificate. Otherwise paste the public certificate for the
                  authority that issued it. Never paste a private key.
                </>
              }
              caption={<>WebUI HTTPS CA certificate</>}
            >
              <textarea
                value={managerCa}
                onChange={(e) => setManagerCa(e.target.value)}
                rows={4}
                placeholder="-----BEGIN CERTIFICATE-----"
                spellCheck={false}
              />
            </FieldHelp>
          </details>

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
            <div className="heading-help">
              <h3>Deploy the replica</h3>
              <Help label="Deploy the replica">
                Use the same Forklift release on the new machine. Save the join
                configuration in deploy/replica/.env, then start the Compose
                stack in that folder. Keep this configuration private: it
                contains a temporary password. Wait for Synchronized before
                using the replica for sign-ins. Its saved data survives
                restarts. For an enrolled Forklift Client, you can instead
                deploy from Hosts → Client enrolled → LDAP replica service.
              </Help>
            </div>

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
