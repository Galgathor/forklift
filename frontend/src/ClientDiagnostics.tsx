import { useEffect, useState } from "react";
import { NetworkChecks } from "./NetworkChecks";
import { Help } from "./Help";
import type { ClientRecord } from "./ClientEnrollment";
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
type Check = {
  id: string;
  status: string;
  severity: string;
  summary: string;
  details: string;
  remediation: string;
  at: number;
};
type Issue = {
  id: string;
  check_id: string;
  state: string;
  severity: string;
  summary: string;
  details: string;
  remediation: string;
  first_detected: number;
  last_detected: number;
  last_checked: number;
  resolved_at: number | null;
  verification: string;
  acknowledged: boolean;
};
type Result = {
  checks: Check[];
  issues: Issue[];
  received_at: number;
  profile_revision: string;
};
const date = (value: number | null) =>
  value ? new Date(value * 1000).toLocaleString() : "Not reported";
export function ClientDiagnostics({
  client,
  api,
  refresh,
}: {
  client: ClientRecord;
  api: Api;
  refresh: () => Promise<void>;
}) {
  const [data, setData] = useState<Result | null>(null),
    [tab, setTab] = useState("Issues"),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const status = client.monitoring?.diagnostics;
  async function load() {
    setError("");
    try {
      setData((await api(`hosts/${client.host_id}/diagnostics`)) as Result);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    let active = true;
    void api(`hosts/${client.host_id}/diagnostics`)
      .then((v) => {
        if (active) setData(v as Result);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [client.host_id, status?.received_at, status?.active_issues]);
  const checks =
    data?.checks.filter((c) =>
      tab === "Network"
        ? c.id.startsWith("network.")
        : tab === "DNS"
          ? c.id.startsWith("dns.")
          : tab === "SSH"
            ? c.id.startsWith("ssh.")
            : !c.id.startsWith("dns.") &&
              !c.id.startsWith("ssh.") &&
              !c.id.startsWith("network."),
    ) || [];
  return (
    <section className="client-monitoring">
      <div className="panel-title">
        <div className="heading-help">
          <h3>Host health</h3>
          <Help label="Diagnostic health">
            These read-only observations are reported by the enrolled machine.
            They do not prove successful password authentication. Unknown,
            unsupported, stale or missing results never prove recovery.
            Acknowledging an issue does not resolve it. New diagnostic
            expectations retire superseded issues separately from positive
            recovery.
          </Help>
        </div>
        <button className="secondary" onClick={() => void load()}>
          Refresh diagnostics
        </button>
      </div>
      <dl>
        <div>
          <dt>Health</dt>
          <dd>{status?.health || "unknown"}</dd>
        </div>
        <div>
          <dt>Active issues</dt>
          <dd>{status?.active_issues || 0}</dd>
        </div>
        <div>
          <dt>Last diagnostic report</dt>
          <dd>
            {date(status?.received_at || null)}
            {status?.received_at && !status.fresh
              ? " · stale expectations or report"
              : ""}
          </dd>
        </div>
      </dl>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      <div
        className="diagnostic-tabs"
        role="tablist"
        aria-label="Host diagnostic sections"
      >
        {["Network", "DNS", "Authentication", "SSH", "Issues"].map((name) => (
          <button
            key={name}
            role="tab"
            aria-selected={tab === name}
            className={tab === name ? "primary" : "secondary"}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>
      {tab === "Network" && (
        <NetworkChecks api={api} hostId={client.host_id || undefined} />
      )}
      <div role="tabpanel" aria-label={`${tab} diagnostics`}>
        {!data ? (
          <p className="muted">Loading diagnostics…</p>
        ) : tab === "Issues" ? (
          <>
            {!data.issues.length ? (
              <p className="muted">No recorded issues.</p>
            ) : (
              <ul className="client-history">
                {[...data.issues].reverse().map((i) => (
                  <li key={i.id}>
                    <div className="heading-help">
                      <strong>{i.summary}</strong>
                      <Help label={`Issue ${i.check_id}`}>
                        {i.details}
                        <p>{i.remediation}</p>
                        <p>
                          First detected: {date(i.first_detected)}. Last
                          detected: {date(i.last_detected)}. Last checked:{" "}
                          {date(i.last_checked)}. Resolved:{" "}
                          {date(i.resolved_at)}.
                        </p>
                      </Help>
                    </div>
                    <span className={i.state === "active" ? "badge" : "pill"}>
                      {i.state} · {i.severity}
                    </span>
                    <small>
                      {i.check_id} · last observation:{" "}
                      {i.verification.replaceAll("_", " ")}
                    </small>
                    {i.acknowledged ? (
                      <small>Acknowledged</small>
                    ) : (
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => {
                          setBusy(true);
                          void api(
                            `hosts/${client.host_id}/issues/${i.id}`,
                            "POST",
                            { action: "acknowledge" },
                          )
                            .then(async () => {
                              await load();
                              await refresh();
                            })
                            .catch((e) => setError(e.message))
                            .finally(() => setBusy(false));
                        }}
                      >
                        Acknowledge issue
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </>
        ) : !checks.length ? (
          <p className="muted">No checks reported for this section.</p>
        ) : (
          <ul className="client-history">
            {checks.map((c) => (
              <li key={c.id}>
                <div className="heading-help">
                  <strong>{c.summary}</strong>
                  <Help label={`Check ${c.id}`}>
                    {c.details}
                    <p>{c.remediation}</p>
                    <p>
                      Client observation: {date(c.at)}. Server receipt:{" "}
                      {date(data.received_at)}.
                    </p>
                  </Help>
                </div>
                <span className={c.status === "pass" ? "pill" : "badge"}>
                  {c.status}
                </span>
                <small>{c.id}</small>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}
