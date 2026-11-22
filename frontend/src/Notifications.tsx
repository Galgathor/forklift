import { useEffect, useRef, useState } from "react";
import { Bell, X } from "lucide-react";
import { Help } from "./Help";
type Api = (path: string, method?: string, body?: unknown) => Promise<unknown>;
type Notice = {
  id: number;
  host_name: string;
  summary: string;
  kind: string;
  issue_state: string;
  severity: string;
  at: number;
  acknowledged: boolean;
  dismissed: boolean;
};
export function Notifications({ api }: { api: Api }) {
  const trigger = useRef<HTMLButtonElement>(null),
    panel = useRef<HTMLElement>(null);
  const [items, setItems] = useState<Notice[]>([]),
    [open, setOpen] = useState(false),
    [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    const section = panel.current;
    const trap = (e: KeyboardEvent) => {
      if (e.key !== "Tab" || !section?.contains(e.target as Node)) return;
      const buttons = [
        ...section.querySelectorAll<HTMLButtonElement>(
          "button:not([disabled])",
        ),
      ];
      const first = buttons[0],
        last = buttons[buttons.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    };
    section?.addEventListener("keydown", trap);
    return () => {
      section?.removeEventListener("keydown", trap);
      trigger.current?.focus();
    };
  }, [open]);
  async function load() {
    try {
      const value = (await api("notifications")) as { notifications: Notice[] };
      setItems(value.notifications);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
  }, []);
  const unseen = items.filter((n) => !n.acknowledged && !n.dismissed).length;
  async function action(id: number, action: string) {
    try {
      await api(`notifications/${id}`, "POST", { action });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <>
      <button
        ref={trigger}
        aria-label="Host notifications"
        aria-expanded={open}
        onClick={() => {
          setOpen(!open);
          void load();
        }}
      >
        <Bell size={18} />
        {unseen > 0 && <span className="count">{unseen}</span>}
      </button>
      {open && (
        <div
          className="overlay"
          onKeyDown={(e) => {
            if (e.key === "Escape" && !e.defaultPrevented) setOpen(false);
          }}
        >
          <section
            ref={panel}
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Host notifications"
          >
            <div className="panel-title">
              <div className="heading-help">
                <h2>Host notifications</h2>
                <Help label="Host notifications">
                  Notifications tell you when a problem starts or changes. Mark
                  one as seen, or dismiss it to hide it. Neither action fixes or
                  closes the problem. These choices are shared with other
                  administrators.
                </Help>
              </div>
              <button
                autoFocus
                aria-label="Close notifications"
                onClick={() => setOpen(false)}
              >
                <X />
              </button>
            </div>
            {error && (
              <div className="error" role="alert">
                {error}
              </div>
            )}
            {!items.some((n) => !n.dismissed) ? (
              <p className="muted">No notifications.</p>
            ) : (
              <ul className="client-history">
                {items
                  .filter((n) => !n.dismissed)
                  .map((n) => (
                    <li key={n.id}>
                      <strong>
                        {n.host_name} · {n.summary}
                      </strong>
                      <small>
                        {n.kind.replaceAll("_", " ")} · issue {n.issue_state} ·{" "}
                        {new Date(n.at * 1000).toLocaleString()}
                      </small>
                      {!n.acknowledged && (
                        <button
                          className="secondary"
                          onClick={() => void action(n.id, "acknowledge")}
                        >
                          Mark as seen
                        </button>
                      )}
                      <button
                        className="secondary"
                        onClick={() => void action(n.id, "dismiss")}
                      >
                        Dismiss notification
                      </button>
                    </li>
                  ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </>
  );
}
