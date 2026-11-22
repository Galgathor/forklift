import { useState } from "react";
import { Help } from "./Help";
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
type Check = {
  label: string;
  address: string;
  port: number;
  transport: string;
  status: string;
  details: string;
  source: string;
  checked_at: number;
};
type Observation = {
  host_id: string;
  host: string;
  fresh: boolean;
  received_at: number;
  check: { summary: string; status: string; details: string };
};
type Result = { checks: Check[]; observations: Observation[] };
export function NetworkChecks({ api, hostId }: { api: Api; hostId?: string }) {
  const [data, setData] = useState<Result | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <section className={hostId ? "client-monitoring" : "panel"}>
      <div className="panel-title">
        <div className="heading-help">
          <h3>{hostId ? "Inbound port check" : "Network port checks"}</h3>
          <Help label="Network port verification">
            These checks test connections between specific machines. Success
            from one machine does not mean every machine can connect. A failed
            check may mean a service is stopped, a port is closed, or the
            network is unavailable. No settings or firewall rules are changed.
            To test SSH access from Forklift, choose the host address and SSH
            port in its diagnostic settings.
          </Help>
        </div>
        <button
          className="secondary"
          disabled={busy}
          onClick={() => {
            setBusy(true);
            setError("");
            void api(
              hostId ? `hosts/${hostId}/network-checks` : "network/checks",
              "POST",
              {},
            )
              .then((v) => setData(v as Result))
              .catch((e) => setError(e.message))
              .finally(() => setBusy(false));
          }}
        >
          {busy ? "Checking…" : "Check ports"}
        </button>
      </div>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {data && (
        <>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Service / source</th>
                  <th>Destination</th>
                  <th>Transport</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {data.checks.map((c, i) => (
                  <tr key={i}>
                    <td>
                      <div className="heading-help">
                        <strong>{c.label}</strong>
                        <Help label={`${c.label} result`}>
                          {c.details}
                          <p>
                            Source: {c.source}. Checked:{" "}
                            {new Date(c.checked_at * 1000).toLocaleString()}.
                          </p>
                        </Help>
                      </div>
                    </td>
                    <td>
                      {c.address}:{c.port}
                    </td>
                    <td>{c.transport}</td>
                    <td>
                      <span className={c.status === "pass" ? "pill" : "badge"}>
                        {c.status === "pass" ? "Reachable" : c.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!data.checks.length && (
            <p className="muted">
              No enabled service address is available for this check.
            </p>
          )}
          {data.observations.length > 0 && (
            <>
              <h4>Client network observations</h4>
              <ul className="client-history">
                {data.observations.map((o, i) => (
                  <li key={i}>
                    <div className="heading-help">
                      <strong>
                        {o.host} · {o.check.summary}
                      </strong>
                      <Help label="Client network observation">
                        {o.check.details}
                        <p>
                          Received:{" "}
                          {new Date(o.received_at * 1000).toLocaleString()}.
                          Reported by this client. Forklift has not checked the
                          machine independently.
                        </p>
                      </Help>
                    </div>
                    <span
                      className={
                        o.fresh && o.check.status === "pass" ? "pill" : "badge"
                      }
                    >
                      {o.fresh ? o.check.status : "Stale / inactive"}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
          {!hostId && !data.observations.length && (
            <p className="muted">No client network reports received.</p>
          )}
        </>
      )}
    </section>
  );
}
