import { useEffect, useRef, useState } from "react";
import { ConfirmDialog } from "./ConfirmDialog";
import { Help } from "./Help";

type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
type Peer = {
  id: string;
  active: boolean;
  directory: boolean;
  server_id: string | null;
};
type PeerStatus = {
  coordinator: string | null;
  applied_revision: string | null;
  error: string | null;
  peers: Peer[];
};
type Invite = { id: string; url: string; key: string };

export function useNodePairing(api: Api, refreshServers: () => Promise<void>) {
  const [status, setStatus] = useState<PeerStatus | null>(null);
  const [invite, setInvite] = useState<Invite | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const knownServers = useRef<string | undefined>(undefined);
  async function load() {
    const next = (await api("dns/peers")) as PeerStatus;
    const servers = next.peers
      .flatMap((peer) => peer.server_id ?? [])
      .sort()
      .join(",");
    const changed =
      knownServers.current !== undefined && knownServers.current !== servers;
    knownServers.current = servers;
    setStatus(next);
    if (changed) await refreshServers();
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

  return {
    status,
    invite,
    error,
    busy,
    hide: () => setInvite(null),
    approve: () =>
      perform(async () => {
        setInvite((await api("directory/peers/invite", "POST", {})) as Invite);
      }),
    revoke: (id: string) =>
      perform(async () => {
        await api(`dns/peers/${id}`, "DELETE");
        setInvite((current) => (current?.id === id ? null : current));
      }),
  };
}

type Pairing = ReturnType<typeof useNodePairing>;

function CopyField({ label, value }: { label: string; value: string }) {
  const [message, setMessage] = useState("");
  return (
    <div>
      <div className="help-row pairing-copy">
        <label>
          {label}
          <input readOnly value={value} />
        </label>
        <button
          type="button"
          aria-label={`Copy ${label.toLowerCase()}`}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setMessage("Copied.");
            } catch {
              setMessage("Clipboard unavailable. Select and copy the field.");
            }
          }}
        >
          Copy
        </button>
      </div>
      {message && <small role="status">{message}</small>}
    </div>
  );
}

export function NodePairing({
  pairing,
  disabled,
}: {
  pairing: Pairing;
  disabled: boolean;
}) {
  const { status, invite, error, busy } = pairing;
  return (
    <section className="panel">
      <div className="heading-help">
        <h3>Node pairing</h3>
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
          <button
            className="primary"
            disabled={disabled || busy}
            onClick={pairing.approve}
          >
            Approve node pairing
          </button>
        )
      )}
      {invite && (
        <>
          <p>
            Choose Join existing installation on the new node and enter this key
            within ten minutes.
          </p>
          <CopyField
            key={invite.id + "/address"}
            label="Installation address"
            value={invite.url}
          />
          <CopyField
            key={invite.id + "/key"}
            label="One-time pairing key"
            value={invite.key}
          />
          <button onClick={pairing.hide}>Hide pairing key</button>
        </>
      )}
    </section>
  );
}

export function PairingCard({
  peer,
  pairing,
  disabled,
}: {
  peer: Peer;
  pairing: Pairing;
  disabled: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  return (
    <div className="help-row pairing-status">
      <code>{peer.id}</code>
      <span>{peer.active ? "Paired" : "Awaiting pairing"}</span>
      <button
        disabled={disabled || pairing.busy}
        onClick={() => setConfirming(true)}
      >
        Revoke pairing
      </button>
      {confirming && (
        <ConfirmDialog
          title={`Revoke node pairing ${peer.id}?`}
          confirmLabel="Revoke pairing"
          busy={pairing.busy}
          cancel={() => setConfirming(false)}
          confirm={async () => {
            await pairing.revoke(peer.id);
            setConfirming(false);
          }}
        >
          This node will lose access to shared updates. It will keep serving its
          last DNS copy.
          {peer.directory &&
            " It can still accept sign-ins using its last directory copy."}
          {
            " Remove its addresses from client settings and shut it down to stop it from serving."
          }
        </ConfirmDialog>
      )}
    </div>
  );
}
