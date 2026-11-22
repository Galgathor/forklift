import { Help, FieldHelp } from "./Help";
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
        <div className="heading-help">
          <h1>{restore ? "Restore your directory" : "Set up Forklift"}</h1>
          <Help label="Initial setup">
            Create your directory and administrator account, or restore a
            backup.
          </Help>
        </div>

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
            <FieldHelp
              label="Installation key"
              help={
                <>
                  Enter the installation key from your Docker settings. If you
                  did not choose one, find the generated key in the initialize
                  container’s logs.
                </>
              }
              caption={<>One-time installation key</>}
            >
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
                autoComplete="current-password"
              />
            </FieldHelp>

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
            <div className="heading-help">
              <h2>Your primary directory server</h2>
              <Help label="Primary directory server">
                Choose this Docker host’s private network address. Linux
                machines and replicas will connect to it. Forklift sets up
                encrypted LDAP access and the certificate for you.
              </Help>
            </div>

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
            <FieldHelp
              label="Directory server address"
              help={
                <>
                  Use a private IP address, or a DNS name that points to this
                  network address.
                </>
              }
              caption={<>Server address (IP or optional DNS name)</>}
            >
              <input
                value={network.hostname}
                onChange={(e) =>
                  setNetwork({ ...network, hostname: e.target.value.trim() })
                }
                required
              />
            </FieldHelp>

            <details>
              <summary>Advanced: encrypted directory port</summary>
              <FieldHelp
                label="Directory port"
                help={
                  <>
                    Linux machines connect to this port for encrypted directory
                    access. Keep it reachable on your private network. It is
                    separate from the WebUI’s HTTPS port.
                  </>
                }
                caption={<>Directory port</>}
              >
                <input
                  type="number"
                  min={1}
                  max={65535}
                  value={network.port}
                  onChange={(e) =>
                    setNetwork({ ...network, port: Number(e.target.value) })
                  }
                />
              </FieldHelp>
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
                <FieldHelp
                  label="Directory base DN"
                  help={
                    <>
                      This is the directory’s permanent internal name, for
                      example dc=example,dc=test. Choose it carefully: it cannot
                      be changed later.
                    </>
                  }
                  caption={<>Directory base DN</>}
                >
                  <input
                    name="base"
                    defaultValue="dc=homelab,dc=internal"
                    required
                  />
                </FieldHelp>
                <label>
                  Administrator username
                  <input name="username" required autoComplete="username" />
                </label>
                <label>
                  <span className="field-name">Administrator password</span>
                  <input
                    name="password"
                    type="password"
                    minLength={14}
                    required
                    autoComplete="new-password"
                  />
                </label>

                <div className="help-row action-help">
                  <button className="primary" disabled={busy || jobs.active}>
                    {busy ? "Creating your directory…" : "Initialize directory"}
                  </button>
                  <Help label="Primary host registration">
                    This server connects at {network.hostname}:{network.port}.
                    It appears in Hosts automatically. Adding it does not enable
                    Linux sign-in.
                  </Help>
                </div>
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
