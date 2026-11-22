import { NetworkChecks } from "./NetworkChecks";
import { Help } from "./Help";
import { useEffect, useState } from "react";
import { StorageControls, type DirectoryNetwork } from "./StorageControls";
import { Download, RefreshCw, ShieldCheck } from "lucide-react";
type Event = {
  id: number;
  at: number;
  actor: string;
  action: string;
  target: string;
};
type Page = { events: Event[]; next_cursor: number | null };
type Status = {
  version: string;
  schema: number;
  active_sessions: number;
  recovery_required: boolean;
  certificates: {
    label: string;
    status: string;
    days_remaining?: number;
    not_after?: number;
    fingerprint?: string;
  }[];
  maintenance: {
    id: string;
    at: number;
    kind: string;
    status: string;
    artifact: string;
    sha256: string;
    detail: string;
  }[];
};
type Props = {
  busy: boolean;
  readOnly: boolean;
  directory: { name: string; base: string; network: DirectoryNetwork };
  csrf: string;
  api: (path: string, method?: string, body?: unknown) => Promise<unknown>;
  perform: (f: () => Promise<void>) => Promise<void>;
  refresh: () => Promise<void>;
  signedOut: () => void;
};
const date = (at?: number) =>
  at ? new Date(at * 1000).toLocaleString() : "Unavailable";
export function Operations({
  busy,
  readOnly,
  directory,
  csrf,
  api,
  perform,
  refresh,
  signedOut,
}: Props) {
  const [status, setStatus] = useState<Status | null>(null);
  const [audit, setAudit] = useState<Page | null>(null);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  async function load() {
    setStatus((await api("operations")) as Status);
    setAudit(
      (await api("audit?limit=50&q=" + encodeURIComponent(search))) as Page,
    );
  }
  useEffect(() => {
    void perform(load);
  }, [search]);
  return (
    <>
      <NetworkChecks api={api} />
      <section className="panel">
        <div className="panel-title">
          <h2>Installation & recovery</h2>
          <button
            disabled={busy}
            onClick={() => perform(load)}
            aria-label="Refresh operations"
          >
            <RefreshCw size={18} />
          </button>
        </div>
        <dl>
          <div>
            <dt>Directory</dt>
            <dd>
              {directory.name} · {directory.base}
            </dd>
          </div>
          <div>
            <dt>Release / metadata schema</dt>
            <dd>
              {status ? `v${status.version} / ${status.schema}` : "Loading…"}
            </dd>
          </div>
          <div>
            <dt>Administrator group</dt>
            <dd>administrators</dd>
          </div>
        </dl>
        {status?.recovery_required && (
          <div className="recovery-review">
            <h3>Restored directory: review before enabling writes</h3>
            <p>
              Disconnect the old primary and all old replicas. Review the
              restored network settings and choose a starting account/group
              number higher than every number used since the backup. Rebuild
              replica copies and update Linux client settings. Restoring this
              backup may bring back old accounts and passwords that were later
              removed or changed.
            </p>
            <button
              className="primary"
              disabled={busy}
              onClick={() => {
                if (
                  confirm(
                    "I have disconnected the old servers, checked account numbers and network settings, and will rebuild replicas and update Linux client settings. Allow changes now?",
                  )
                )
                  perform(async () => {
                    await api("recovery/complete", "POST", {
                      acknowledge: true,
                    });
                    await load();
                    await refresh();
                  });
              }}
            >
              Complete recovery review
            </button>
          </div>
        )}
        <div className="panel-title">
          <p>{status?.active_sessions ?? "…"} active administrative sessions</p>
          <button
            className="secondary"
            disabled={busy || readOnly}
            onClick={() => {
              if (
                confirm("Sign out every administrator, including this session?")
              )
                perform(async () => {
                  await api("sessions/revoke", "POST", { acknowledge: true });
                  signedOut();
                });
            }}
          >
            Revoke all sessions
          </button>
        </div>
      </section>
      <StorageControls csrf={csrf} api={api} network={directory.network} />
      <section className="panel">
        <div className="heading-help">
          <h2>Certificate lifecycle</h2>
          <Help label="Certificate lifecycle">
            Certificates protect connections between machines. These dates show
            when the saved certificates expire. A remote server may still be
            using an older certificate. When replacing a replica certificate,
            update the affected Linux machines’ trust files before activating
            it.
          </Help>
        </div>

        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Certificate</th>
                <th>Expiry</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {status?.certificates.map((c) => (
                <tr key={c.label}>
                  <td>
                    <strong>{c.label}</strong>
                    {c.fingerprint && (
                      <details>
                        <summary>SHA-256 fingerprint</summary>
                        <code>{c.fingerprint}</code>
                      </details>
                    )}
                  </td>
                  <td>{date(c.not_after)}</td>
                  <td>
                    <span className={c.status === "valid" ? "pill" : "badge"}>
                      {c.status.replaceAll("_", " ")}
                      {c.days_remaining !== undefined &&
                        ` · ${c.days_remaining} days`}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <div className="heading-help">
          <h2>Maintenance history</h2>
          <Help label="Maintenance history">
            Review previous backup and maintenance jobs here. Keep backup
            checksums somewhere separate; restoring a backup also restores its
            older history.
          </Help>
        </div>

        {!status?.maintenance.length ? (
          <p className="muted">No maintenance operations recorded.</p>
        ) : (
          status.maintenance.map((e) => (
            <div className="event" key={e.id}>
              <ShieldCheck size={17} />
              <div>
                <strong>
                  {e.kind} · {e.status}
                </strong>
                <small>
                  {date(e.at)} · {e.artifact || e.id}
                </small>
                <p className="hint">{e.detail}</p>
                {e.sha256 && (
                  <details>
                    <summary>Backup SHA-256</summary>
                    <code>{e.sha256}</code>
                  </details>
                )}
              </div>
            </div>
          ))
        )}
      </section>
      <section className="panel">
        <div className="table-toolbar">
          <div className="heading-help">
            <h2>Administrative audit log</h2>
            <Help label="Audit exports">
              Events are listed newest first. Each download includes up to 5,000
              matching events. The API supports downloading older pages when you
              need a longer history.
            </Help>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setSearch(query);
            }}
          >
            <label>
              Search events
              <input
                value={query}
                maxLength={128}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Actor, action or target"
              />
            </label>
            <button className="secondary" disabled={busy}>
              Search
            </button>
          </form>
        </div>

        <a
          className="secondary download-link"
          href={"/api/audit/export?q=" + encodeURIComponent(search)}
          download="forklift-audit.ndjson"
        >
          <Download size={16} /> Export NDJSON
        </a>
        <div className="events">
          {audit?.events.map((e) => (
            <div className="event" key={e.id}>
              <ShieldCheck size={17} />
              <div>
                <strong>
                  {e.actor}: {e.action} · {e.target}
                </strong>
                <small>{date(e.at)}</small>
              </div>
            </div>
          ))}
          {audit && !audit.events.length && (
            <p className="muted">No matching events.</p>
          )}
        </div>
        {audit?.next_cursor && (
          <button
            className="secondary"
            disabled={busy}
            onClick={() =>
              perform(async () => {
                const page = (await api(
                  `audit?limit=50&before=${audit.next_cursor}&q=${encodeURIComponent(search)}`,
                )) as Page;
                setAudit({
                  events: [...audit.events, ...page.events],
                  next_cursor: page.next_cursor,
                });
              })
            }
          >
            Load older events
          </button>
        )}
      </section>
    </>
  );
}
