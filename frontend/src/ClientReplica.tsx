import { useEffect, useState } from "react";
import { Help, FieldHelp } from "./Help";
import { ConfirmDialog } from "./ConfirmDialog";
import type { ClientRecord } from "./ClientEnrollment";
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
type Job = {
  id: string;
  directory_id: string;
  stage: string;
  error: string | null;
  address: string;
  port: number;
  control_port: number;
  attempt: number;
  updated_at: number;
};
type Result = {
  deployment: Job | null;
  replica: {
    state: string;
    reachable: boolean;
    last_sync_at: number | null;
    error: string | null;
  } | null;
};
export function ClientReplica({
  client,
  api,
  refresh,
}: {
  client: ClientRecord;
  api: Api;
  refresh: () => Promise<void>;
}) {
  const [data, setData] = useState<Result | null>(null),
    [address, setAddress] = useState(""),
    [port, setPort] = useState(1636),
    [control, setControl] = useState(9443),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [confirm, setConfirm] = useState<string | null>(null);
  const inventory = client.monitoring?.inventory;
  const capable = inventory?.capabilities.includes("replica-deploy-v1");
  const addresses = [
    ...new Set(
      inventory?.addresses
        .map((a) => a.address)
        .filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a)) || [],
    ),
  ];
  const path = `hosts/${client.host_id}/replica-deployment`;
  async function load() {
    try {
      setData((await api(path)) as Result);
      setError("");
    } catch (e) {
      setData((previous) =>
        previous ? { ...previous, replica: null } : previous,
      );
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
  }, [client.host_id]);
  const job = data?.deployment;
  return (
    <section className="client-monitoring">
      <div className="heading-help">
        <h3>LDAP replica service</h3>
        <Help label="Client replica deployment">
          The native client builds the approved replica component shipped with
          its installed version and starts a dedicated Docker Compose project.
          Docker Engine and the Compose plugin must already be installed and
          running. No Git checkout or manual join configuration is needed.
          Deployment changes only this Forklift service; it never rewrites SSSD,
          PAM/NSS, SSH, resolver settings or firewall rules. Each replica keeps
          its own persistent volume. Service startup and confirmed LDAP
          synchronization are separate. The manager must reach the selected
          private LDAP/control ports, and the host must reach the primary and
          management HTTPS.
        </Help>
      </div>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {!data ? (
        <p className="muted">Loading deployment state…</p>
      ) : job ? (
        <>
          <dl>
            <div>
              <dt>Deployment</dt>
              <dd>
                {job.stage === "awaiting_sync"
                  ? "Service running"
                  : job.stage.replaceAll("_", " ")}
              </dd>
            </div>
            <div>
              <dt>Address</dt>
              <dd>{job.address}</dd>
            </div>
            <div>
              <dt>LDAP / control TCP ports</dt>
              <dd>
                {job.port} / {job.control_port}
              </dd>
            </div>
            <div>
              <dt>Directory synchronization</dt>
              <dd>{data.replica?.state || "Not confirmed"}</dd>
            </div>
            <div>
              <dt>Last confirmed synchronization</dt>
              <dd>
                {data.replica?.last_sync_at
                  ? new Date(data.replica.last_sync_at * 1000).toLocaleString()
                  : "Not confirmed"}
              </dd>
            </div>
          </dl>
          {job.error && (
            <div className="error" role="alert">
              {job.error}
            </div>
          )}
          {data.replica?.error && (
            <div className="error" role="alert">
              {data.replica.error}
            </div>
          )}
          {["failed", "cancelled"].includes(job.stage) && (
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setConfirm("retry")}
            >
              Retry deployment
            </button>
          )}
          {["queued", "preparing", "failed"].includes(job.stage) && (
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setConfirm("cancel")}
            >
              Cancel deployment
            </button>
          )}
        </>
      ) : (
        <>
          <FieldHelp
            label="Replica address"
            caption="Replica address"
            help="Choose a current private IPv4 address reported by this client. Forklift verifies it again before starting services."
          >
            <select
              value={address}
              onChange={(e) => setAddress(e.target.value)}
            >
              <option value="">Select an address</option>
              {addresses.map((a) => (
                <option key={a}>{a}</option>
              ))}
            </select>
          </FieldHelp>
          <label>
            LDAP TCP port
            <input
              type="number"
              min={1024}
              max={65535}
              value={port}
              onChange={(e) => setPort(Number(e.target.value))}
            />
          </label>
          <FieldHelp
            label="Replica control TCP port"
            caption="Replica control TCP port"
            help="Restrict this pinned-TLS control listener to the Forklift manager's private network. It accepts fixed LDAP lifecycle operations."
          >
            <input
              type="number"
              min={1024}
              max={65535}
              value={control}
              onChange={(e) => setControl(Number(e.target.value))}
            />
          </FieldHelp>
          <button
            className="primary"
            disabled={
              !capable ||
              !address ||
              client.state !== "active" ||
              busy ||
              !Number.isInteger(port) ||
              !Number.isInteger(control) ||
              port < 1024 ||
              port > 65535 ||
              control < 1024 ||
              control > 65535 ||
              port === control
            }
            onClick={() => setConfirm("deploy")}
          >
            Deploy LDAP replica
          </button>
          {!capable && (
            <p className="muted">
              Requires client 0.5 with Docker available and a fresh inventory
              report.
            </p>
          )}
        </>
      )}
      {confirm && (
        <ConfirmDialog
          title={
            confirm === "deploy"
              ? "Deploy LDAP replica?"
              : confirm === "retry"
                ? "Retry replica deployment?"
                : "Cancel replica deployment?"
          }
          confirmLabel={
            confirm === "deploy"
              ? "Deploy replica"
              : confirm === "retry"
                ? "Retry deployment"
                : "Cancel deployment"
          }
          busy={busy}
          cancel={() => setConfirm(null)}
          confirm={() => {
            setBusy(true);
            setError("");
            void api(
              confirm === "deploy" ? path : path + "/action",
              "POST",
              confirm === "deploy"
                ? { address, port, control_port: control, acknowledge: true }
                : { action: confirm, acknowledge: true },
            )
              .then(async () => {
                setConfirm(null);
                await load();
                await refresh();
              })
              .catch((e) => {
                setError(e.message);
                setConfirm(null);
              })
              .finally(() => setBusy(false));
          }}
        >
          <dl>
            <div>
              <dt>Machine</dt>
              <dd>
                {client.monitoring?.inventory?.hostname ||
                  client.identity.hostname}
              </dd>
            </div>
            <div>
              <dt>Private address</dt>
              <dd>{job?.address || address}</dd>
            </div>
            <div>
              <dt>LDAP / control TCP ports</dt>
              <dd>
                {job?.port || port} / {job?.control_port || control}
              </dd>
            </div>
          </dl>
          <p>
            {confirm === "cancel"
              ? "Cancel deployment authorization. Any existing container and replica data are retained; this does not stop a running service."
              : "Create or resume the dedicated Forklift replica service on this enrolled machine. Existing host authentication, resolver configuration and unrelated services remain under administrator control."}
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
