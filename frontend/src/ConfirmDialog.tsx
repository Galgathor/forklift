import { useEffect, useId, useRef, type ReactNode } from "react";
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  busy,
  cancel,
  confirm,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  busy: boolean;
  cancel: () => void;
  confirm: () => void;
}) {
  const id = useId(),
    panel = useRef<HTMLElement>(null),
    first = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    first.current?.focus();
    return () => previous?.focus();
  }, []);
  return (
    <div className="overlay confirm-overlay">
      <section
        ref={panel}
        className="dialog"
        role="alertdialog"
        tabIndex={-1}
        aria-busy={busy}
        aria-modal="true"
        aria-labelledby={id}
        onKeyDown={(e) => {
          if (e.key === "Escape" && !busy) {
            e.preventDefault();
            cancel();
          }
          if (e.key === "Tab") {
            const nodes = [
              ...(panel.current?.querySelectorAll<HTMLElement>(
                "button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href]",
              ) || []),
            ];
            if (!nodes.length) {
              e.preventDefault();
              panel.current?.focus();
              return;
            }
            const target = e.shiftKey ? nodes.at(-1) : nodes[0];
            if (
              document.activeElement === (e.shiftKey ? nodes[0] : nodes.at(-1))
            ) {
              e.preventDefault();
              target?.focus();
            }
          }
        }}
      >
        <h2 id={id}>{title}</h2>
        <div className="confirm-description">{children}</div>
        <div className="wizard-actions">
          <button
            ref={first}
            type="button"
            className="secondary"
            disabled={busy}
            onClick={cancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={confirm}
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
