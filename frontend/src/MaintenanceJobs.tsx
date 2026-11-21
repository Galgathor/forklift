import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { Activity, CheckCircle2, Download, ShieldCheck } from "lucide-react";
type Working = {
  id?: string;
  csrf?: string;
  bootstrapToken?: string;
  bootstrap?: boolean;
};
type Context = { active: boolean; start: (ticket?: Working) => void };
const Jobs = createContext<Context>({ active: false, start: () => {} });
export const useMaintenance = () => useContext(Jobs);
export function MaintenanceProvider({ children }: { children: ReactNode }) {
  const [working, setWorking] = useState<Working | null>(null);
  return (
    <Jobs.Provider
      value={{ active: !!working, start: (ticket = {}) => setWorking(ticket) }}
    >
      <div inert={!!working}>{children}</div>
      {working &&
        createPortal(
          <Progress
            working={working}
            close={() => {
              setWorking(null);
              window.dispatchEvent(new Event("forklift:maintenance-complete"));
            }}
          />,
          document.body,
        )}
    </Jobs.Provider>
  );
}
type Job = {
  id: string;
  action?: string;
  status: string;
  phase?: string;
  error?: string;
  result?: {
    reauthenticate?: boolean;
    sha256?: string;
    artifact?: string;
    validated?: boolean;
    id_high_water?: number;
    base?: string;
    recovery_required?: boolean;
    rolled_back?: boolean;
  };
};
function Progress({ working, close }: { working: Working; close: () => void }) {
  const [job, setJob] = useState<Job | null>(null),
    [csrf, setCsrf] = useState(working.csrf || ""),
    [error, setError] = useState(""),
    [key, setKey] = useState(working.bootstrapToken || ""),
    [needsKey, setNeedsKey] = useState(false),
    [busy, setBusy] = useState(false);
  const headers = () => ({ ...(key ? { "X-Bootstrap-Token": key } : {}) });
  async function poll() {
    try {
      const r = await fetch("/api/maintenance/current", { headers: headers() });
      const value = await r.json();
      if (r.status === 401) {
        const status = await fetch("/api/status").then((r) => r.json());
        if (!status.maintenance) {
          setJob({
            id: "",
            status: "completed",
            result: { reauthenticate: true },
          });
          setError("The operation has finished. Sign in to continue.");
          return;
        }
        setNeedsKey(true);
        setError(
          working.bootstrap
            ? "Re-enter the installation key used to start this setup operation."
            : "This operation requires its original administrator session. If it has expired and the directory cannot start, use emergency account recovery.",
        );
        return;
      }
      if (!r.ok)
        throw Error(value.error || "Unable to read maintenance status");
      setNeedsKey(false);
      setError("");
      setJob(value.job);
      setCsrf(value.csrf);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void poll();
    const id = setInterval(() => void poll(), 1500);
    return () => clearInterval(id);
  }, [key]);
  async function recover(action: string) {
    setBusy(true);
    setError("");
    try {
      const r = await fetch("/api/maintenance/recover", {
        method: "POST",
        headers: {
          ...headers(),
          "Content-Type": "application/json",
          "X-CSRF-Token": csrf,
        },
        body: JSON.stringify({ action }),
      });
      const v = await r.json();
      if (!r.ok) throw Error(v.error);
      setJob({ ...job!, status: "starting" });
      await poll();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const completed = job?.status === "completed",
    failed = job?.status === "failed",
    recovery = job?.status === "needs_resume";
  return (
    <div className="overlay">
      <section
        className="dialog maintenance-progress"
        role="dialog"
        aria-modal="true"
        aria-label="Directory maintenance"
      >
        <div className="panel-title">
          <h2>
            {completed
              ? "Maintenance complete"
              : recovery
                ? "Maintenance needs recovery"
                : "Directory maintenance"}
          </h2>
          {completed ? <CheckCircle2 /> : <Activity />}
        </div>
        <p className="hint">
          Forklift coordinates directory writes and consistent storage
          snapshots. The management interface stays available. Configured
          replicas continue authentication independently.
        </p>
        <div className={completed ? "pill" : "badge"} role="status">
          {job?.action?.replaceAll("-", " ") || "Preparing operation"} ·{" "}
          {job?.status.replaceAll("_", " ") || "Connecting"}
        </div>
        {job?.phase && (
          <p className="hint">Phase: {job.phase.replaceAll("_", " ")}</p>
        )}
        {(error || job?.error) && (
          <div className="error" role="alert">
            {error || job?.error}
          </div>
        )}
        {needsKey && working.bootstrap && (
          <label>
            Installation key
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              autoComplete="current-password"
            />
          </label>
        )}
        {job?.result?.validated && (
          <p className="hint">
            Archive verified: {job.result.base}. Archived Unix ID high-water
            mark: {job.result.id_high_water}. Restoration still requires
            explicit fencing and an ID floor above every allocation since the
            snapshot.
          </p>
        )}
        {job?.result?.sha256 && (
          <div className="recovery-review">
            <strong>Trusted backup receipt</strong>
            <p className="hint">
              Save this checksum separately from the encrypted archive. You will
              need it to verify a future recovery.
            </p>
            <code>{job.result.sha256}</code>
            <button
              className="secondary"
              onClick={() => {
                const url = URL.createObjectURL(
                  new Blob(
                    [JSON.stringify({ id: job.id, ...job.result }, null, 2)],
                    { type: "application/json" },
                  ),
                );
                const a = document.createElement("a");
                a.href = url;
                a.download = "forklift-backup-receipt.json";
                a.click();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
              }}
            >
              <Download size={16} />
              Save receipt
            </button>
          </div>
        )}
        {completed && job.result?.artifact && (
          <a
            className="secondary download-link"
            href={`/api/maintenance/backups/${job.id}`}
            download
          >
            <Download size={16} />
            Download encrypted backup
          </a>
        )}
        {job?.result?.reauthenticate && (
          <p className="hint">
            Administrative sessions were revoked. Sign in with the current
            directory administrator credentials to continue.
          </p>
        )}
        {job?.result?.recovery_required && (
          <p className="hint">
            Restored directory writes remain paused until the recovery review in
            Settings is complete. Old replicas are quarantined and must be
            fenced and reenrolled.
          </p>
        )}
        {recovery && (
          <div className="wizard-actions">
            <button
              className="primary"
              disabled={busy}
              onClick={() => recover("resume")}
            >
              Resume operation
            </button>
            {job.action === "restore" && (
              <button
                className="secondary"
                disabled={busy}
                onClick={() => {
                  if (
                    confirm(
                      "Roll back this interrupted restore to the coherent snapshot taken immediately before it?",
                    )
                  )
                    void recover("rollback");
                }}
              >
                Roll back restore
              </button>
            )}
          </div>
        )}
        {completed || failed ? (
          <button className="primary" onClick={close}>
            {job?.result?.reauthenticate
              ? "Continue to sign in"
              : "Back to management"}
          </button>
        ) : (
          <p className="secure">
            <ShieldCheck size={16} />
            You may close this browser; the operation continues. Reopen Forklift
            with this same session to recover interrupted work.
          </p>
        )}
        <button className="secondary" onClick={() => poll()}>
          Refresh status
        </button>
      </section>
    </div>
  );
}
