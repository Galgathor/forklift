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
        <h2>Node pairing</h2>
        <Help label="Node pairing">
          Approve a new node here, then enter the pairing key in its setup
          wizard. Forklift connects the directory and DNS automatically.
        </Help>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {status?.coordinator ? (
        <p role="status">
          {status.error ||
            (status.applied_revision
              ? "Local DNS copy applied"
              : "Waiting for the first DNS copy")}
        </p>
      ) : (
        status && (
          <>
            <button
              disabled={busy}
              onClick={() =>
                perform(async () => {
                  const pairing = await api(
                    "directory/peers/invite",
                    "POST",
                    {},
                  );
                  setInvite(pairing);
                })
              }
            >
              Approve node pairing
            </button>
            {invite && (
              <>
                <p>
                  Choose Join existing installation on the new node and enter
                  this key within ten minutes.
                </p>
                <label>
                  Installation address
                  <input readOnly value={invite.url} />
                </label>
                <label>
                  One-time pairing key
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
      {revoke && (
        <ConfirmDialog
          title={`Revoke node pairing ${revoke}?`}
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
          This node will lose access to shared updates. It will keep serving its
          last DNS copy.
          {status?.peers.find((peer) => peer.id === revoke)?.directory &&
            " It can still accept sign-ins using its last directory copy."}
          {
            " Remove its addresses from client settings and shut it down to stop it from serving."
          }
        </ConfirmDialog>
      )}
    </section>
  );
}
