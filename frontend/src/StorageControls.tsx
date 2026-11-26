import { Help, FieldHelp } from "./Help";
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
      {
        id: string;
        sha256: string;
        bytes: number;
        at: number;
        dns_included?: boolean;
      }[]
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
        <div className="heading-help">
          <h2>Backups & recovery</h2>
          <Help label="Backup scope">
            Backups include directory data, primary DNS records, Forklift
            settings and the keys needed to restore them. Changes pause briefly
            while the backup is prepared. DNS can still answer requests. Keep
            the recovery key and backup checksum somewhere safe, separate from
            the backup file.
          </Help>
        </div>

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
                  {backup.dns_included
                    ? " · LDAP + primary DNS"
                    : " · Legacy/unknown scope; verify before restore"}
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
        <div className="heading-help">
          <h2>WebUI address</h2>
          <Help label="WebUI address">
            Set up your DNS name and HTTPS reverse proxy before changing this
            address. Saving the new address signs everyone out and opens the new
            location. Change the published port in your Docker deployment
            settings if needed.
          </Help>
        </div>

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
        <div className="heading-help">
          <h2>Directory credentials & network</h2>
          <Help label="Directory maintenance">
            Use these controls to maintain the directory. Replacing service
            passwords signs all administrators out. Forklift checks the new
            passwords before completing the change.
          </Help>
        </div>

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
          Replace service passwords
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
      <div className="heading-help">
        <h2>Verify or restore a backup</h2>
        <Help label="Backup verification">
          Forklift unlocks the backup and checks that its files and databases
          can be read before restoring anything. A full restore needs a backup
          that includes DNS. The recovery key is used only for this operation
          and is not saved.
        </Help>
      </div>

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
        <summary>
          <span className="help-row">
            Restore and replace this installation
            <Help label="Restoring an installation">
              Forklift saves the current installation first so it can roll back
              if restoration fails. Disconnect the old primary servers and
              replicas before using the restored installation. Restoring an
              older backup can bring back accounts or passwords that were later
              disabled or changed.
            </Help>
          </span>
        </summary>

        <FieldHelp
          label="Future UID and GID floor"
          help={
            <>
              Choose a number higher than any account or group number used
              before, including deleted accounts. Forklift cannot recover
              numbers assigned after this backup was made.
            </>
          }
          caption={<>Starting account/group number</>}
        >
          <input
            type="number"
            min={10001}
            max={2147483647}
            value={floor}
            onChange={(e) => setFloor(Number(e.target.value))}
          />
        </FieldHelp>

        <label className="checkbox">
          <input
            type="checkbox"
            checked={fenced}
            onChange={(e) => setFenced(e.target.checked)}
          />
          I have disconnected the old directory and DNS servers and all old
          replicas.
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
          />
          Replace this installation. I know the administrator login saved in
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
