import { useEffect, useState } from "react";
import { Download, KeyRound, RefreshCw } from "lucide-react";
import { useMaintenance } from "./MaintenanceJobs";
export type DirectoryNetwork = {
  address: string;
  hostname: string;
  port: number;
  endpoint?: string;
};
type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
export function StorageControls({
  csrf,
  api,
  network,
}: {
  csrf: string;
  api: Api;
  network: DirectoryNetwork;
}) {
  const jobs = useMaintenance();
  const [publicUrl, setPublicUrl] = useState(window.location.origin);
  const [recipient, setRecipient] = useState(""),
    [backups, setBackups] = useState<
      { id: string; sha256: string; bytes: number; at: number }[]
    >([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [editing, setEditing] = useState(false),
    [addresses, setAddresses] = useState<{ name: string; address: string }[]>(
      [],
    ),
    [draft, setDraft] = useState(network);
  async function load() {
    const value = await api("maintenance");
    setBackups(value.backups || []);
    if (value.backup_recipient) setRecipient(value.backup_recipient);
  }
  useEffect(() => {
    void load().catch((e) => setError(e.message));
  }, []);
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
  async function launch(body: unknown) {
    const ticket = await api("maintenance/jobs", "POST", body);
    jobs.start(ticket);
  }
  return (
    <>
      <section className="panel">
        <h2>Backups & recovery</h2>
        <p className="hint">
          Backups contain directory data, matching metadata and installation
          secrets. Forklift pauses directory writes and drains application
          requests while producing an age-encrypted snapshot. Keep the recovery
          key and trusted checksum in separate protected storage.
        </p>
        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <button
          className="secondary"
          disabled={busy}
          onClick={() =>
            perform(async () => {
              if (
                !confirm(
                  "Generate and download a new private recovery key? Save it independently. Older backups still require their original keys.",
                )
              )
                return;
              const r = await fetch("/api/maintenance/keys", {
                method: "POST",
                headers: { "X-CSRF-Token": csrf },
              });
              if (!r.ok) {
                const v = await r.json();
                throw Error(v.error);
              }
              setRecipient(r.headers.get("X-Age-Recipient") || "");
              download(await r.blob(), "forklift-recovery.txt");
            })
          }
        >
          <KeyRound size={16} />
          Generate recovery key
        </button>
        <label>
          Public backup recipient
          <input
            value={recipient}
            onChange={(e) => setRecipient(e.target.value.trim())}
            placeholder="age1…"
          />
        </label>
        <button
          className="primary"
          disabled={busy || !recipient.startsWith("age1")}
          onClick={() =>
            perform(() => launch({ action: "backup", recipient, max_gib: 8 }))
          }
        >
          Create encrypted backup
        </button>
        <div className="panel-title">
          <h3>Stored encrypted backups</h3>
          <button
            aria-label="Refresh backups"
            disabled={busy}
            onClick={() => perform(load)}
          >
            <RefreshCw size={16} />
          </button>
        </div>
        {!backups.length ? (
          <p className="muted">
            No backups yet. Generate a recovery key, save it, then create your
            first backup.
          </p>
        ) : (
          backups.map((backup) => (
            <div className="event" key={backup.id}>
              <div>
                <strong>{new Date(backup.at * 1000).toLocaleString()}</strong>
                <small>
                  {Math.ceil(backup.bytes / 1024)} KiB · {backup.id}
                </small>
                <details>
                  <summary>Creation checksum</summary>
                  <code>{backup.sha256}</code>
                </details>
                <a
                  className="secondary download-link"
                  href={`/api/maintenance/backups/${backup.id}`}
                  download
                >
                  <Download size={15} />
                  Download backup
                </a>
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() =>
                    perform(async () => {
                      if (
                        confirm(
                          "Delete this encrypted server copy? Keep an independent verified backup before deleting.",
                        )
                      ) {
                        await api(`maintenance/backups/${backup.id}`, "DELETE");
                        await load();
                      }
                    })
                  }
                >
                  Delete server copy
                </button>
              </div>
            </div>
          ))
        )}
      </section>
      <section className="panel">
        <BackupRestore csrf={csrf} network={network} />
      </section>
      <section className="panel">
        <h2>WebUI address</h2>
        <p className="hint">
          Configure DNS and your NPM HTTPS Proxy Host first. Applying a new
          public origin revokes sessions and opens the new address. The
          management port mapping is part of initial Docker deployment.
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            perform(async () => {
              if (
                confirm(
                  "The new reverse proxy address is ready. Save it and sign out all sessions?",
                )
              ) {
                const value = await api("settings/public-url", "POST", {
                  url: publicUrl,
                  acknowledge: true,
                });
                window.location.assign(value.url);
              }
            });
          }}
        >
          <label>
            Public URL
            <input
              type="url"
              value={publicUrl}
              onChange={(e) => setPublicUrl(e.target.value)}
              required
            />
          </label>
          <button className="secondary" disabled={busy}>
            Apply public URL
          </button>
        </form>
      </section>
      <section className="panel">
        <h2>Directory credentials & network</h2>
        <p className="hint">
          These actions run through the constrained maintenance service. No
          Docker or shell access is granted to the manager. Credential rotation
          revokes all administrator sessions and verifies the new LDAP bind
          before completing.
        </p>
        <button
          className="secondary"
          disabled={busy}
          onClick={() =>
            perform(async () => {
              if (
                confirm(
                  "Rotate the manager and monitor credentials and sign out all administrators? LDAP user passwords remain unchanged.",
                )
              )
                await launch({ action: "rotate-service", acknowledge: true });
            })
          }
        >
          Rotate service credentials
        </button>
        <button
          className="secondary"
          disabled={busy}
          onClick={() =>
            perform(async () => {
              if (
                confirm(
                  "Renew the primary certificate and briefly pause its directory? The installation CA is preserved.",
                )
              )
                await launch({ action: "renew-primary", acknowledge: true });
            })
          }
        >
          Renew primary certificate
        </button>
        <dl>
          <div>
            <dt>Primary address</dt>
            <dd>
              {network.hostname}:{network.port}
            </dd>
          </div>
          <div>
            <dt>Private interface</dt>
            <dd>{network.address}</dd>
          </div>
        </dl>
        <button
          className="secondary"
          disabled={busy}
          onClick={() =>
            perform(async () => {
              const info = await api("maintenance/inspect");
              setAddresses(info.interfaces || []);
              setDraft(network);
              setEditing(!editing);
            })
          }
        >
          Change primary network settings
        </button>
        {editing && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              perform(async () => {
                if (
                  confirm(
                    "Update the primary listener and certificate? Update Linux client configurations afterward and reconnect any replicas still using the old primary address.",
                  )
                )
                  await launch({
                    action: "configure-primary",
                    acknowledge: true,
                    network: draft,
                  });
              });
            }}
          >
            <label>
              Private address
              <select
                value={draft.address}
                onChange={(e) =>
                  setDraft({ ...draft, address: e.target.value })
                }
              >
                {addresses.map((item) => (
                  <option key={item.address} value={item.address}>
                    {item.address} · {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Server address (IP or DNS name)
              <input
                value={draft.hostname}
                onChange={(e) =>
                  setDraft({ ...draft, hostname: e.target.value.trim() })
                }
                required
              />
            </label>
            <label>
              Encrypted directory port
              <input
                type="number"
                min={1}
                max={65535}
                value={draft.port}
                onChange={(e) =>
                  setDraft({ ...draft, port: Number(e.target.value) })
                }
                required
              />
            </label>
            <button className="primary" disabled={busy}>
              Apply network settings
            </button>
          </form>
        )}
      </section>
    </>
  );
}
function download(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function BackupRestore({
  csrf = "",
  bootstrapToken,
  network,
}: {
  csrf?: string;
  bootstrapToken?: string;
  network: DirectoryNetwork;
}) {
  const jobs = useMaintenance();
  const [file, setFile] = useState<File | null>(null),
    [identity, setIdentity] = useState<File | null>(null),
    [uploaded, setUploaded] = useState<{ id: string; sha256: string } | null>(
      null,
    ),
    [checksum, setChecksum] = useState(""),
    [floor, setFloor] = useState(1000000),
    [fenced, setFenced] = useState(false),
    [ack, setAck] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const headers = () => ({
    "X-CSRF-Token": csrf,
    ...(bootstrapToken ? { "X-Bootstrap-Token": bootstrapToken } : {}),
  });
  async function start(action: "verify" | "restore") {
    setBusy(true);
    setError("");
    try {
      if (!identity || identity.size > 8192)
        throw Error(
          "Select the private age recovery key saved when this backup was created.",
        );
      let input = uploaded;
      if (!input) {
        if (!file) throw Error("Select the encrypted backup archive.");
        const form = new FormData();
        form.append("archive", file);
        const r = await fetch("/api/maintenance/uploads", {
          method: "POST",
          headers: headers(),
          body: form,
        });
        const value = await r.json();
        if (!r.ok) throw Error(value.error);
        input = value;
        setUploaded(value);
      }
      if (!/^[a-f0-9]{64}$/.test(checksum) || checksum !== input!.sha256)
        throw Error(
          "Paste the trusted creation-time SHA-256 from your independently saved receipt. It must match the uploaded archive.",
        );
      const r = await fetch("/api/maintenance/jobs", {
        method: "POST",
        headers: { ...headers(), "Content-Type": "application/json" },
        body: JSON.stringify({
          action,
          upload_id: input!.id,
          sha256: checksum,
          identity: await identity.text(),
          max_gib: 8,
          ...(action === "restore"
            ? {
                uid_floor: floor,
                original_fenced: fenced,
                acknowledge: ack,
                network,
              }
            : {}),
        }),
      });
      const ticket = await r.json();
      if (!r.ok) throw Error(ticket.error);
      jobs.start({ ...ticket, bootstrapToken, bootstrap: !!bootstrapToken });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <h2>Verify or restore a backup</h2>
      <p className="hint">
        Verification checks age authentication, file hashes, SQLite integrity
        and native LDAP readability before any directory data is replaced. The
        private recovery key is held only for this operation and never saved to
        the metadata or logs.
      </p>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      <label>
        Encrypted archive (.age)
        <input
          type="file"
          accept=".age"
          onChange={(e) => {
            setFile(e.target.files?.[0] || null);
            setUploaded(null);
          }}
        />
      </label>
      {uploaded && (
        <p className="hint">
          Uploaded ciphertext checksum (compare with your separate receipt):{" "}
          <code>{uploaded.sha256}</code>
        </p>
      )}
      <label>
        Trusted creation-time SHA-256
        <input
          value={checksum}
          maxLength={64}
          onChange={(e) => setChecksum(e.target.value.trim().toLowerCase())}
          placeholder="Paste the checksum from your saved receipt"
        />
      </label>
      <label>
        Private recovery key file
        <input
          type="file"
          onChange={(e) => setIdentity(e.target.files?.[0] || null)}
        />
      </label>
      <button
        className="secondary"
        disabled={busy || (!file && !uploaded) || !identity || !checksum}
        onClick={() => start("verify")}
      >
        {busy ? "Uploading and validating…" : "Verify backup"}
      </button>
      <details>
        <summary>Restore and replace this directory</summary>
        <p className="hint">
          The current installation is snapshotted for rollback before
          replacement. Fence the original primary and every old replica before
          starting a recovered directory. Archived passwords may restore access
          revoked after the backup.
        </p>
        <label>
          Future UID/GID floor
          <input
            type="number"
            min={10001}
            max={2147483647}
            value={floor}
            onChange={(e) => setFloor(Number(e.target.value))}
          />
        </label>
        <p className="hint">
          Choose a value above every ID ever allocated, including accounts
          created and deleted after this snapshot. Forklift cannot reconstruct
          missing allocation history.
        </p>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={fenced}
            onChange={(e) => setFenced(e.target.checked)}
          />
          The original primary and old replicas are fenced.
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
          />
          Replace this installation. I know the administrator credentials from
          this backup.
        </label>
        <button
          className="primary"
          disabled={
            busy ||
            !fenced ||
            !ack ||
            (!file && !uploaded) ||
            !identity ||
            !checksum
          }
          onClick={() => start("restore")}
        >
          Restore directory
        </button>
      </details>
    </>
  );
}
