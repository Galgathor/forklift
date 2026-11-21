import { useEffect, useState } from "react";
import { CheckCircle2, Copy, Download, X } from "lucide-react";
import type { DirectoryHealth, DirectoryNode } from "./Servers";
type Props = {
  existing?: DirectoryNode;
  health: DirectoryHealth;
  csrf: string;
  readOnly: boolean;
  api: (path: string, method?: string, body?: unknown) => Promise<unknown>;
  refresh: () => Promise<void>;
  close: () => void;
};
type Setup = {
  manager_url: string;
  https_ready: boolean;
  primary_endpoint: string | null;
};
const dns = (s: string) =>
  s.length <= 253 &&
  !/^\d+(\.\d+){3}$/.test(s) &&
  s
    .split(".")
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
const privateIP = (s: string) => {
  const n = s.split(".").map(Number);
  return (
    /^\d+\.\d+\.\d+\.\d+$/.test(s) &&
    n.every((v) => v >= 0 && v <= 255) &&
    (n[0] === 10 ||
      (n[0] === 172 && n[1] >= 16 && n[1] <= 31) ||
      (n[0] === 192 && n[1] === 168))
  );
};
function Command({ children }: { children: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => setCopied(false), [children]);
  return (
    <div className="setup-command">
      <pre>
        <code>{children}</code>
      </pre>
      <button
        type="button"
        className="secondary"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(children);
            setCopied(true);
          } catch {
            setCopied(false);
          }
        }}
      >
        <Copy size={15} />
        {copied ? "Copied" : "Copy command"}
      </button>
    </div>
  );
}
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
    [step, setStep] = useState(0),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [primary, setPrimary] = useState(""),
    [primaryIP, setPrimaryIP] = useState(""),
    [primaryPort, setPrimaryPort] = useState(636);
  const [name, setName] = useState(existing?.name || ""),
    [hostname, setHostname] = useState(
      existing ? new URL(existing.endpoint).hostname : "",
    ),
    [address, setAddress] = useState(""),
    [port, setPort] = useState(
      existing ? Number(new URL(existing.endpoint).port || 636) : 636,
    );
  const [created, setCreated] = useState<DirectoryNode | undefined>(existing),
    [downloaded, setDownloaded] = useState(false);
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
  useEffect(() => {
    void perform(async () => {
      const s = (await api("replication/setup")) as Setup;
      setSetup(s);
      const endpoint = existing?.provider || s.primary_endpoint;
      if (endpoint) {
        const u = new URL(endpoint);
        setPrimary(u.hostname);
        setPrimaryPort(Number(u.port || 636));
      }
    });
  }, []);
  const validPrimary = dns(primary) && primaryPort > 0 && primaryPort <= 65535;
  const validReplica =
    dns(hostname) &&
    privateIP(address) &&
    port > 0 &&
    port <= 65535 &&
    !!name.trim();
  const primaryCommand =
    validPrimary && privateIP(primaryIP)
      ? `python3 scripts/forklift-admin.py prepare-replication --hostname ${primary} --bind ${primaryIP} --port ${primaryPort}`
      : "Enter the primary DNS name and private IPv4 address to generate its preparation command.";
  const current = created
    ? health.servers.find((n) => n.id === created.id)
    : undefined;
  async function deploy() {
    if (!validReplica)
      throw Error(
        "Enter a friendly name, lowercase DNS name and private IPv4 address for the new server.",
      );
    let node = created;
    if (!node) {
      node = (await api("directory-servers", "POST", {
        name,
        endpoint: `ldaps://${hostname}:${port}`,
        provider: `ldaps://${primary}:${primaryPort}`,
      })) as DirectoryNode;
      setCreated(node);
    }
    const r = await fetch(`/api/replicas/${node.id}/bundle`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ acknowledge: true, bind_address: address }),
    });
    if (!r.ok) {
      const v = await r.json();
      throw Error(
        v.error ||
          "Could not create deployment. Retry to download a fresh bundle.",
      );
    }
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = `forklift-replica-${node.id}.tar.gz`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setDownloaded(true);
    await refresh();
  }
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
            <p className="eyebrow">GUIDED SERVER SETUP</p>
            <h2>Add a directory replica</h2>
          </div>
          <button aria-label="Close setup" onClick={close}>
            <X />
          </button>
        </div>
        <ol className="wizard-progress" aria-label="Setup progress">
          {["Existing server", "New machine", "Install & connect"].map(
            (label, i) => (
              <li key={label} aria-current={step === i ? "step" : undefined}>
                {i + 1}. {label}
              </li>
            ),
          )}
        </ol>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        {!setup ? (
          <p className="muted">Loading setup requirements…</p>
        ) : (
          <>
            <p className="setup-intro">
              You only need a second Linux machine with Docker installed.
              Forklift installs OpenLDAP, creates its TLS certificate and
              configures replication.{" "}
              <strong>
                Do not install or configure LDAP on the new machine first.
              </strong>
            </p>
            {step === 0 && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void perform(async () => {
                    await api("replication/primary/check", "POST", {
                      hostname: primary,
                      port: primaryPort,
                    });
                    setStep(1);
                  });
                }}
              >
                <h3>1. Make your existing Forklift directory reachable</h3>
                <p className="hint">
                  Your primary directory already exists: it was created during
                  Forklift setup. By default it is available only inside Docker.
                  Prepare it once so the new machine can securely copy
                  identities from it.
                </p>
                {!setup.https_ready && (
                  <div className="error" role="status">
                    First enable HTTPS for the Forklift WebUI through Nginx
                    Proxy Manager and set FORKLIFT_PUBLIC_URL to that HTTPS
                    address. Current address: {setup.manager_url}. Enrollment
                    needs this address; it is separate from the directory
                    connection below.
                  </div>
                )}
                <label>
                  Existing server DNS name
                  <input
                    value={primary}
                    disabled={!!created}
                    onChange={(e) => setPrimary(e.target.value.trim())}
                    placeholder="directory.home.arpa"
                    required
                    maxLength={253}
                  />
                </label>
                <p className="hint">
                  Choose a LAN DNS name pointing to the Docker host already
                  running Forklift. Both the new machine and Forklift must
                  resolve it. This is the directory server’s name, which can
                  differ from the WebUI hostname.
                </p>
                <details open={!setup.primary_endpoint}>
                  <summary>First replica? Prepare the existing server</summary>
                  <label>
                    Existing Docker host private IPv4 address
                    <input
                      value={primaryIP}
                      onChange={(e) => setPrimaryIP(e.target.value.trim())}
                      placeholder="192.168.1.10"
                    />
                  </label>
                  <p className="hint">
                    Create the DNS record {primary || "directory.home.arpa"} →{" "}
                    {primaryIP || "this private address"} in your LAN DNS. Then
                    run this in the Forklift checkout on the{" "}
                    <strong>existing Docker host</strong>. It adds the
                    certificate name and publishes the encrypted directory port
                    on this private interface. It preserves directory data and
                    briefly restarts the directory.
                  </p>
                  <Command>{primaryCommand}</Command>
                  <p className="hint">
                    Allow TCP {primaryPort} from the new server and manager to
                    this address. Do not send this traffic through an NPM HTTP
                    Proxy Host. You do not need another LDAP installation or
                    LDIF commands.
                  </p>
                </details>
                <details>
                  <summary>Advanced: primary directory port</summary>
                  <label>
                    Primary port
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={primaryPort}
                      disabled={!!created}
                      onChange={(e) => setPrimaryPort(Number(e.target.value))}
                      required
                    />
                  </label>
                </details>
                <p className="hint">
                  For later replicas, the saved address is filled in
                  automatically. Check confirms DNS, encrypted connectivity and
                  the exact primary certificate from Forklift; it sends no LDAP
                  credentials. The new machine checks its own connection before
                  enrolling.
                </p>
                <button
                  className="primary"
                  disabled={
                    busy || readOnly || !setup.https_ready || !validPrimary
                  }
                >
                  {busy ? "Checking primary…" : "Check primary & continue"}
                </button>
              </form>
            )}
            {step === 1 && (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (validReplica) setStep(2);
                  else
                    setError(
                      "Use a lowercase DNS name and a private LAN IPv4 address.",
                    );
                }}
              >
                <h3>2. Tell Forklift about the new machine</h3>
                <p className="hint">
                  This machine does not need an existing LDAPS endpoint. The
                  downloaded stack creates it, including its certificate and
                  replication settings.
                </p>
                <label>
                  Friendly name
                  <input
                    value={name}
                    maxLength={100}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Garage server"
                    required
                    disabled={!!created}
                  />
                </label>
                <label>
                  New server DNS name
                  <input
                    value={hostname}
                    maxLength={253}
                    onChange={(e) => setHostname(e.target.value.trim())}
                    placeholder="directory2.home.arpa"
                    required
                    disabled={!!created}
                  />
                </label>
                <label>
                  New Docker host private IPv4 address
                  <input
                    value={address}
                    onChange={(e) => setAddress(e.target.value.trim())}
                    placeholder="192.168.1.20"
                    required
                  />
                </label>
                <p className="hint">
                  Create the LAN DNS record {hostname || "directory2.home.arpa"}{" "}
                  → {address || "the new host’s private address"}. This address
                  will be preconfigured in the download. Allow Forklift and your
                  Linux clients to reach its directory port. Nothing needs to be
                  listening there yet.
                </p>
                <details>
                  <summary>Advanced: new directory port</summary>
                  <label>
                    New server port
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={port}
                      onChange={(e) => setPort(Number(e.target.value))}
                      required
                      disabled={!!created}
                    />
                  </label>
                </details>
                <div className="wizard-actions">
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => setStep(0)}
                  >
                    Back
                  </button>
                  <button
                    className="primary"
                    disabled={busy || readOnly || !validReplica}
                  >
                    Review deployment
                  </button>
                </div>
              </form>
            )}
            {step === 2 && (
              <>
                <h3>3. Install on the new Docker host</h3>
                <dl>
                  <div>
                    <dt>Copy from existing server</dt>
                    <dd>
                      {primary}:{primaryPort}
                    </dd>
                  </div>
                  <div>
                    <dt>Install new replica</dt>
                    <dd>
                      {hostname}:{port}
                    </dd>
                  </div>
                  <div>
                    <dt>Listen on private address</dt>
                    <dd>{address}</dd>
                  </div>
                  <div>
                    <dt>Connect to Forklift</dt>
                    <dd>{setup.manager_url}</dd>
                  </div>
                </dl>
                <p className="hint">
                  The new machine must reach the primary directory above and
                  Forklift’s HTTPS address. The download includes the private
                  bind address, port, certificate trust and a one-use enrollment
                  credential. Only generate it when you are ready to install; it
                  expires after 15 minutes. The replica is trusted
                  authentication infrastructure and receives password hashes.
                </p>
                <button
                  className="primary"
                  disabled={busy || readOnly}
                  onClick={() => perform(deploy)}
                >
                  <Download size={16} />
                  {busy
                    ? "Creating deployment…"
                    : downloaded
                      ? "Download a fresh deployment"
                      : "Download deployment"}
                </button>
                {downloaded && created && (
                  <>
                    <p className="hint">
                      <strong>On the new machine:</strong> transfer the
                      downloaded archive privately into your current directory,
                      then run:
                    </p>
                    <Command>{`mkdir -p -m 700 forklift-replica\ntar -xzf forklift-replica-${created.id}.tar.gz -C forklift-replica\ncd forklift-replica\n./start.sh`}</Command>
                    <p className="hint">
                      No LDAP installation, certificate generation or .env
                      editing is needed. Keep the deployment directory private.
                      For an expired, never-enrolled deployment, stop its stack
                      before extracting a fresh download into that directory and
                      rerunning ./start.sh. A configured directory is never
                      reset. If the WebUI uses a private HTTPS CA, place its
                      public CA file at enrollment/manager-ca.crt before
                      starting.
                    </p>
                    <div
                      className={
                        current?.state === "synchronized" ? "pill" : "badge"
                      }
                      role="status"
                    >
                      {current?.state === "synchronized" ? (
                        <>
                          <CheckCircle2 size={16} /> Synchronization confirmed
                        </>
                      ) : current?.state === "catching_up" ? (
                        "Connected · copying directory data"
                      ) : current?.enrollment_state === "enrolled" ? (
                        "Enrolled · checking synchronization"
                      ) : (
                        "Waiting for the new machine to enroll"
                      )}
                    </div>
                    {current?.error && (
                      <p className="hint server-error">{current.error}</p>
                    )}
                    <p className="hint">
                      Status updates every 30 seconds. Once synchronization is
                      confirmed, add this server to your Linux hosts and deploy
                      their updated host bundles to enable authentication
                      failover.
                    </p>
                    <button
                      className="secondary"
                      disabled={busy}
                      onClick={() => perform(refresh)}
                    >
                      Check connection now
                    </button>
                  </>
                )}
                <div className="wizard-actions">
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => setStep(1)}
                  >
                    Back
                  </button>
                  <button className="secondary" onClick={close}>
                    {downloaded ? "Close setup" : "Cancel"}
                  </button>
                </div>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}
