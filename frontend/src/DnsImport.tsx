import { Help, FieldHelp } from "./Help";
import { useState } from "react";
import { X } from "lucide-react";
type Set = {
  name: string;
  type: string;
  ttl: number;
  records: { content: string; disabled: boolean }[];
};
type Preview = {
  expected_revision: string;
  plan_hash: string;
  changes: { name: string; type: string; before: Set | null; after: Set }[];
  warnings: string[];
};
type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
export function DnsImport({
  api,
  zone,
  close,
  complete,
}: {
  api: Api;
  zone: string;
  close: () => void;
  complete: (result: any) => Promise<void>;
}) {
  const [file, setFile] = useState<File | null>(null),
    [mode, setMode] = useState("merge"),
    [data, setData] = useState<unknown>(null),
    [preview, setPreview] = useState<Preview | null>(null),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [confirmed, setConfirmed] = useState(false),
    [name, setName] = useState("");
  const path = `dns/zones/${encodeURIComponent(zone)}`;
  return (
    <div className="overlay">
      <section
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Import DNS records"
      >
        <div className="panel-title">
          <div className="heading-help">
            <h2>Import DNS records</h2>
            <Help label="Supported import files">
              Import Forklift JSON exports or PowerDNS zone JSON containing
              name/zone and rrsets. BIND text and server configuration
              directives are not imported. SOA is preserved; edit its settings
              separately. Maximum file size: 240 KiB.
            </Help>
          </div>
          <button disabled={busy} aria-label="Close DNS import" onClick={close}>
            <X />
          </button>
        </div>

        {error && (
          <div className="error" role="alert">
            {error}
          </div>
        )}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            try {
              if (!file || file.size > 240 * 1024)
                throw Error("Select a JSON zone file no larger than 240 KiB.");
              const parsed = JSON.parse(await file.text());
              const value = await api(`${path}/import/preview`, "POST", {
                data: parsed,
                mode,
              });
              setData(parsed);
              setPreview(value);
              setConfirmed(false);
              setName("");
            } catch (e) {
              setError((e as Error).message);
              setPreview(null);
            } finally {
              setBusy(false);
            }
          }}
        >
          <label>
            Zone JSON file
            <input
              aria-label="Zone JSON file"
              type="file"
              accept="application/json,.json"
              disabled={busy}
              required
              onChange={(e) => {
                setFile(e.target.files?.[0] || null);
                setPreview(null);
              }}
            />
          </label>
          <FieldHelp
            label="Import behavior"
            help={
              <>
                Unlisted record sets remain. Replacing a listed set can remove
                values. Forward and reverse imports are separate; no PTRs are
                created automatically. Changed sets release automatic PTR/host
                ownership and may need review in Hosts.
              </>
            }
            caption={<>Import behavior</>}
          >
            <select
              aria-label="Import behavior"
              disabled={busy}
              value={mode}
              onChange={(e) => {
                setMode(e.target.value);
                setPreview(null);
              }}
            >
              <option value="merge">
                Merge values; preserve existing TTLs and disabled flags
              </option>
              <option value="replace">Replace listed record sets</option>
            </select>
          </FieldHelp>

          <button className="secondary" disabled={busy || !file}>
            {busy ? "Checking…" : "Preview DNS import"}
          </button>
        </form>
        {preview && (
          <>
            <h3>{preview.changes.length} record sets will change</h3>
            {preview.warnings.map((w, i) => (
              <p className="hint" key={i}>
                {w}
              </p>
            ))}
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Record</th>
                    <th>Current</th>
                    <th>After import</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.changes.map((c) => (
                    <tr key={c.name + c.type}>
                      <td>
                        {c.name}
                        <small>{c.type}</small>
                      </td>
                      <td>
                        {c.before?.records.map((v) => (
                          <small key={v.content}>
                            {v.content}
                            {v.disabled ? " (disabled)" : ""}
                          </small>
                        ))}
                        <small>
                          {c.before ? `TTL ${c.before.ttl}` : "New set"}
                        </small>
                      </td>
                      <td>
                        {c.after.records.map((v) => (
                          <small key={v.content}>
                            {v.content}
                            {v.disabled ? " (disabled)" : ""}
                          </small>
                        ))}
                        <small>TTL {c.after.ttl}</small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                setError("");
                try {
                  const result = await api(`${path}/import`, "POST", {
                    data,
                    mode,
                    expected_revision: preview.expected_revision,
                    plan_hash: preview.plan_hash,
                    acknowledge: confirmed,
                    confirm_name: name,
                  });
                  await complete(result);
                } catch (e) {
                  setError((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <label>
                Confirm import zone
                <input
                  aria-label="Confirm import zone"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={zone}
                  required
                  disabled={busy}
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  disabled={busy}
                />
                I reviewed these DNS record changes.
              </label>

              <div className="help-row action-help">
                <button
                  className="primary"
                  disabled={
                    busy ||
                    !confirmed ||
                    name !== zone ||
                    !preview.changes.length
                  }
                >
                  {busy ? "Applying…" : "Apply DNS import"}
                </button>
                <Help label="Interrupted imports">
                  Changes across record sets can partially succeed. Pending DNS
                  changes provide safe retry or explicit retention of
                  already-applied values.
                </Help>
              </div>
            </form>
          </>
        )}
      </section>
    </div>
  );
}
