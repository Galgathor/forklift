import {
  cloneElement,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { Info, X } from "lucide-react";

type Props = { label: string; children: ReactNode };

export function Help({ label, children }: Props) {
  const id = useId();
  const trigger = useRef<HTMLButtonElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  function position() {
    const button = trigger.current;
    const popover = panel.current;
    if (!button || !popover) return;
    const bounds = button.getBoundingClientRect();
    if (bounds.bottom < 0 || bounds.top > window.innerHeight) {
      popover.hidePopover();
      return;
    }
    const width = popover.offsetWidth;
    const height = popover.offsetHeight;
    const gap = 8;
    const edge = 12;
    const left = Math.max(
      edge,
      Math.min(bounds.left, window.innerWidth - width - edge),
    );
    const below = bounds.bottom + gap;
    const preferredTop =
      below + height <= window.innerHeight - edge
        ? below
        : Math.max(edge, bounds.top - height - gap);
    const top = Math.max(
      edge,
      Math.min(preferredTop, window.innerHeight - height - edge),
    );
    popover.style.left = `${left}px`;
    popover.style.top = `${top}px`;
  }
  useEffect(() => {
    if (!open) return;
    function update(event: Event) {
      if (event.target instanceof Node && panel.current?.contains(event.target))
        return;
      position();
    }
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [open]);
  return (
    <span className="help">
      <button
        ref={trigger}
        type="button"
        className="info-button"
        aria-label={`About ${label}`}
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={id}
        popoverTarget={id}
      >
        <Info size={16} aria-hidden="true" />
      </button>
      {createPortal(
        <div
          ref={panel}
          id={id}
          popover="auto"
          role="dialog"
          aria-label={`Help: ${label}`}
          className="help-popover"
          onToggle={(event) => {
            const visible = event.currentTarget.matches(":popover-open");
            setOpen(visible);
            if (visible) position();
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              panel.current?.hidePopover();
              trigger.current?.focus();
            }
          }}
        >
          <div className="help-title">
            <strong>{label}</strong>
            <button
              type="button"
              aria-label={`Close help: ${label}`}
              onClick={() => {
                panel.current?.hidePopover();
                trigger.current?.focus();
              }}
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
          <div className="help-content">{children}</div>
        </div>,
        document.body,
      )}
    </span>
  );
}

export function FieldHelp({
  label,
  caption,
  help,
  children,
}: {
  label: string;
  caption: ReactNode;
  help: ReactNode;
  children: ReactElement<{ id?: string }>;
}) {
  const generatedId = useId();
  const id = children.props.id || generatedId;
  return (
    <div className="field-help">
      <div className="field-heading">
        <label htmlFor={id}>{caption}</label>
        {help && <Help label={label}>{help}</Help>}
      </div>
      {cloneElement(children, { id })}
    </div>
  );
}
