import { useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { useMaintenance } from "./MaintenanceJobs";
import { BackupRestore } from "./StorageControls";
type Props = {
  api: (path: string, method?: string, body?: unknown) => Promise<any>;
  completed: () => Promise<void>;
};
type Network = { address: string; hostname: string; port: number };
export function SetupWizard({ api, completed }: Props) {
  const jobs = useMaintenance();
  const [token, setToken] = useState(""),
    [step, setStep] = useState(0),
    [interfaces, setInterfaces] = useState<{ name: string; address: string }[]>(
      [],
    ),
    [network, setNetwork] = useState<Network>({
      address: "",
      hostname: "",
      port: 1636,
    }),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [restore, setRestore] = useState(false);
  async function perform(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="auth">
      <section className="auth-card setup-wizard">
        <div className="brand">
          <img
            src="/forklift.png"
            alt=""
            width={40}
            height={40}
            className="brand-icon"
          />
          forklift
        </div>
        <p className="eyebrow">FIRST-TIME SETUP</p>
        <h1>
          {restore ? "Restore your directory" : "A home for your identities."}
        </h1>
        <p className="hint">
          Forklift creates the primary directory, certificates and protected
          storage. Configure this server here once; later replicas inherit its
          connection details.
        </p>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {step === 0 && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              perform(async () => {
                const value = await api("setup/inspect", "POST", { token });
                setInterfaces(value.interfaces);
                const address = value.interfaces[0]?.address || "";
                setNetwork({ address, hostname: address, port: 1636 });
                setStep(1);
              });
            }}
          >
            <label>
              One-time installation key
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
                autoComplete="current-password"
              />
            </label>
            <p className="hint">
              Use the key chosen in your Docker deployment settings. If you left
              it blank, the initializer generated a key in its local container
              log.
            </p>
            <button className="primary" disabled={busy}>
              {busy
                ? "Checking storage and directory readiness…"
                : "Check installation"}
            </button>
          </form>
        )}
        {step === 1 && (
          <>
            <div className="pill">
              <CheckCircle2 size={15} /> Storage and supervisor ready
            </div>
            <h2>Your primary directory server</h2>
            <p className="hint">
              Select the private address of this Docker host. Linux clients and
              future replicas will connect here. Its encrypted listener and
              certificate are configured automatically; you do not need an
              existing LDAP endpoint.
            </p>
            <label>
              Private interface
              <select
                value={network.address}
                onChange={(e) =>
                  setNetwork({
                    ...network,
                    address: e.target.value,
                    hostname: e.target.value,
                  })
                }
              >
                {interfaces.map((v) => (
                  <option key={v.address} value={v.address}>
                    {v.address} · {v.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Server address (IP or optional DNS name)
              <input
                value={network.hostname}
                onChange={(e) =>
                  setNetwork({ ...network, hostname: e.target.value.trim() })
                }
                required
              />
            </label>
            <p className="hint">
              The private IP needs no DNS changes. If you choose a DNS name,
              point it to this interface in your network DNS.
            </p>
            <details>
              <summary>Advanced: encrypted directory port</summary>
              <label>
                Directory port
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={network.port}
                  onChange={(e) =>
                    setNetwork({ ...network, port: Number(e.target.value) })
                  }
                />
              </label>
              <p className="hint">
                Default 1636 avoids privileged host ports. Keep this port
                reachable on your private network; LDAP traffic does not use
                NPM’s HTTP proxy.
              </p>
            </details>
            <div className="wizard-actions">
              <button className="secondary" onClick={() => setStep(0)}>
                Back
              </button>
              <button
                className="primary"
                disabled={!network.address || !network.hostname}
                onClick={() => setStep(2)}
              >
                Continue
              </button>
            </div>
          </>
        )}
        {step === 2 && (
          <>
            <div className="wizard-actions">
              <button
                className={!restore ? "primary" : "secondary"}
                onClick={() => setRestore(false)}
              >
                New directory
              </button>
              <button
                className={restore ? "primary" : "secondary"}
                onClick={() => setRestore(true)}
              >
                Restore a backup
              </button>
            </div>
            {restore ? (
              <BackupRestore bootstrapToken={token} network={network} />
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  const values = Object.fromEntries(
                    new FormData(e.currentTarget),
                  );
                  perform(async () => {
                    await api("setup", "POST", {
                      ...values,
                      token,
                      network,
                      public_url: window.location.origin,
                    });
                    await completed();
                  });
                }}
              >
                <label>
                  Directory name
                  <input
                    name="name"
                    defaultValue="Homelab"
                    required
                    maxLength={100}
                  />
                </label>
                <label>
                  Directory base DN
                  <input
                    name="base"
                    defaultValue="dc=homelab,dc=internal"
                    required
                  />
                  <small>
                    Choose once. Forklift handles the LDAP structure
                    automatically.
                  </small>
                </label>
                <label>
                  Administrator username
                  <input name="username" required autoComplete="username" />
                </label>
                <label>
                  Administrator password
                  <input
                    name="password"
                    type="password"
                    minLength={14}
                    required
                    autoComplete="new-password"
                  />
                </label>
                <p className="hint">
                  Primary: {network.hostname}:{network.port}. It will
                  automatically appear in Hosts. Registration does not install
                  SSH authentication or grant login privileges.
                </p>
                <button className="primary" disabled={busy || jobs.active}>
                  {busy ? "Creating your directory…" : "Initialize directory"}
                </button>
              </form>
            )}
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setStep(1)}
            >
              Back to server settings
            </button>
          </>
        )}
      </section>
    </div>
  );
}
