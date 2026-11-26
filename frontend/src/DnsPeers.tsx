import { useEffect, useState } from "react";
import { ConfirmDialog } from "./ConfirmDialog";
import { Help } from "./Help";

type Api = (path: string, method?: string, body?: unknown) => Promise<any>;
type PeerStatus = {
  coordinator: string | null;
  applied_revision: string | null;
  error: string | null;
  peers: { id: string; active: boolean; expires: number; directory: boolean }[];
};

export function DnsPeers({
  api,
  onStatus,
}: {
  api: Api;
  onStatus: (joined: boolean) => void;
}) {
  const [status, setStatus] = useState<PeerStatus | null>(null);
  const [invite, setInvite] = useState<{
    url: string;
    key: string;
    directory?: boolean;
  } | null>(null);
  const [revoke, setRevoke] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    const result: PeerStatus = await api("dns/peers");
    setStatus(result);
    onStatus(!!result.coordinator);
  }

  useEffect(() => {
    const refresh = () => void load().catch((e: Error) => setError(e.message));
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => window.clearInterval(timer);
  }, []);

  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="heading-help">
        <h2>DNS manager pairing</h2>
        <Help label="DNS manager pairing">
          Pair an empty DNS server with the manager where you already edit DNS.
          Administrators on the paired manager can edit the shared zones. Its
          DNS server keeps answering from its last copy during an outage.
        </Help>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {status?.coordinator ? (
        <>
          <p>DNS coordinator {status.coordinator}</p>
          <p role="status">
            {status.error ||
              (status.applied_revision
                ? "Local DNS copy applied"
                : "Waiting for the first DNS copy")}
          </p>
        </>
      ) : (
        status && (
          <>
            <button
              disabled={busy}
              onClick={() =>
                perform(async () => {
                  setInvite(await api("dns/peers", "POST", {}));
                })
              }
            >
              Approve DNS pairing
            </button>
            <button
              disabled={busy}
              onClick={() =>
                perform(async () => {
                  const pairing = await api(
                    "directory/peers/invite",
                    "POST",
                    {},
                  );
                  setInvite({ ...pairing, directory: true });
                })
              }
            >
              Approve directory and DNS node
            </button>
            {invite && (
              <>
                <p>
                  {invite.directory
                    ? "Choose Join existing installation on the new node and enter this key within ten minutes."
                    : "Enter this key on the other manager within ten minutes."}
                </p>
                <label>
                  Coordinator address
                  <input readOnly value={invite.url} />
                </label>
                <label>
                  One-time DNS pairing key
                  <input readOnly value={invite.key} />
                </label>
                <button onClick={() => setInvite(null)}>
                  Hide pairing key
                </button>
              </>
            )}
            {status.peers.map((peer) => (
              <div className="event" key={peer.id}>
                <span>
                  {peer.id} · {peer.directory ? "Directory and DNS" : "DNS"} ·{" "}
                  {peer.active ? "Paired" : "Awaiting pairing"}
                </span>
                <button disabled={busy} onClick={() => setRevoke(peer.id)}>
                  Revoke pairing
                </button>
              </div>
            ))}
          </>
        )
      )}
      {status && (!status.coordinator || status.error) && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            const body = Object.fromEntries(new FormData(e.currentTarget));
            void perform(async () => {
              await api("dns/peer/join", "POST", body);
              window.location.reload();
            });
          }}
        >
          <label>
            DNS coordinator HTTPS address
            <input
              name="url"
              type="url"
              defaultValue={status.coordinator || ""}
              readOnly={!!status.coordinator}
              placeholder="https://forklift.example.test"
              required
            />
          </label>
          <label>
            DNS pairing key
            <input name="key" type="password" autoComplete="off" required />
          </label>
          <button disabled={busy}>
            {status.coordinator
              ? "Replace DNS pairing"
              : "Join DNS coordinator"}
          </button>
        </form>
      )}
      {revoke && (
        <ConfirmDialog
          title={`Revoke DNS pairing ${revoke}?`}
          confirmLabel="Revoke pairing"
          busy={busy}
          cancel={() => setRevoke(null)}
          confirm={() =>
            perform(async () => {
              await api(`dns/peers/${revoke}`, "DELETE");
              setRevoke(null);
            })
          }
        >
          This manager will stop receiving updates and submitting edits. It will
          keep serving the last DNS records it received. Pair it again to resume
          synchronization.
        </ConfirmDialog>
      )}
    </section>
  );
}
