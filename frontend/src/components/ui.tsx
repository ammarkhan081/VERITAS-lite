import { useEffect, useId, useRef, type ReactNode } from "react";
import { AlertCircle, Check, Circle, LoaderCircle, X } from "lucide-react";
import type { CampaignPhase, CampaignStatus } from "../types";

export function formatPercent(value: number | null | undefined): string {
  return value == null || !Number.isFinite(value) ? "—" : `${Math.round(value * 100)}%`;
}

export function formatDate(value: string | null | undefined, withTime = true): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, withTime
    ? { dateStyle: "medium", timeStyle: "short" }
    : { dateStyle: "medium" }).format(date);
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

export function labelize(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function containTabFocus(event: KeyboardEvent, root: HTMLElement | null) {
  if (event.key !== "Tab" || !root) return;
  const items = Array.from(root.querySelectorAll<HTMLElement>(
    'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
  )).filter((item) => item.offsetParent !== null);
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && (document.activeElement === first || document.activeElement === root)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === root)) {
    event.preventDefault();
    first.focus();
  }
}

export function StatusBadge({ status, label }: { status: CampaignStatus | CampaignPhase; label?: string }) {
  const normalized = String(status).toLowerCase();
  const kind = ["completed", "healthy", "passed", "accepted", "report"].includes(normalized)
    ? "success"
    : ["failed", "cancelled", "error"].includes(normalized)
      ? "danger"
      : ["paused", "patch", "held_out"].includes(normalized)
        ? "warning"
        : ["running", "attack", "verify", "retest", "baseline"].includes(normalized)
          ? "active"
          : "neutral";
  const Icon = kind === "success" ? Check : kind === "danger" ? AlertCircle : kind === "active" ? LoaderCircle : Circle;
  return (
    <span className={`status status--${kind}`}>
      <Icon size={13} aria-hidden="true" className={kind === "active" ? "spin-subtle" : undefined} />
      <span>{label ?? labelize(String(status))}</span>
    </span>
  );
}

export function Button({
  children,
  variant = "secondary",
  size = "md",
  type = "button",
  className = "",
  disabled,
  onClick,
  title,
}: {
  children: ReactNode;
  variant?: "primary" | "secondary" | "quiet" | "danger";
  size?: "sm" | "md";
  type?: "button" | "submit";
  className?: string;
  disabled?: boolean;
  onClick?: () => void;
  title?: string;
}) {
  return (
    <button
      className={`button button--${variant} button--${size} ${className}`.trim()}
      type={type}
      disabled={disabled}
      onClick={onClick}
      title={title}
    >
      {children}
    </button>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: ReactNode;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-header">
      <div className="page-heading">
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

export function SectionHeading({
  title,
  description,
  action,
  className = "",
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`section-heading ${className}`.trim()}>
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Metric({
  label,
  value,
  detail,
  tone = "default",
}: {
  label: string;
  value: string;
  detail?: string;
  tone?: "default" | "good" | "caution" | "bad";
}) {
  return (
    <div className={`metric metric--${tone}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {detail && <div className="metric-detail">{detail}</div>}
    </div>
  );
}

export function LoadingBlock({ label = "Loading campaign data" }: { label?: string }) {
  return (
    <div className="state-block" role="status" aria-live="polite">
      <LoaderCircle size={17} className="spin-subtle" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyBlock({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return (
    <div className="empty-block">
      <div className="empty-mark" aria-hidden="true"><Circle size={18} /></div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function ErrorBlock({
  title = "Could not load data",
  message,
  onRetry,
}: {
  title?: string;
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="error-block" role="alert">
      <div className="error-icon"><AlertCircle size={17} aria-hidden="true" /></div>
      <div className="error-copy"><strong>{title}</strong><p>{message}</p></div>
      {onRetry && <Button size="sm" onClick={onRetry}>Try again</Button>}
    </div>
  );
}

export function Toast({ message, kind = "success", onClose }: { message: string; kind?: "success" | "error"; onClose: () => void }) {
  useEffect(() => {
    const timer = window.setTimeout(onClose, 4200);
    return () => window.clearTimeout(timer);
  }, [onClose]);
  return (
    <div className={`toast toast--${kind}`} role={kind === "error" ? "alert" : "status"}>
      <span>{message}</span>
      <button className="icon-button toast-close" aria-label="Dismiss notification" onClick={onClose}><X size={16} /></button>
    </div>
  );
}

export function Dialog({
  title,
  description,
  children,
  onClose,
  size = "normal",
}: {
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  size?: "normal" | "wide";
}) {
  const dialogId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      containTabFocus(event, dialogRef.current);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      prior?.focus();
    };
  }, [onClose]);
  return (
    <div className="overlay" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div
        ref={dialogRef}
        className={`dialog ${size === "wide" ? "dialog--wide" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${dialogId}-title`}
        aria-describedby={description ? `${dialogId}-description` : undefined}
        tabIndex={-1}
      >
        <div className="dialog-heading">
          <div><h2 id={`${dialogId}-title`}>{title}</h2>{description && <p id={`${dialogId}-description`}>{description}</p>}</div>
          <button className="icon-button" onClick={onClose} aria-label="Close dialog"><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Drawer({
  title,
  description,
  onClose,
  children,
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const drawerId = useId();
  const drawerRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const prior = document.activeElement as HTMLElement | null;
    drawerRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      containTabFocus(event, drawerRef.current);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      prior?.focus();
    };
  }, [onClose]);
  return (
    <div className="overlay overlay--right" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside
        ref={drawerRef}
        className="detail-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${drawerId}-title`}
        aria-describedby={description ? `${drawerId}-description` : undefined}
        tabIndex={-1}
      >
        <div className="drawer-heading">
          <div><h2 id={`${drawerId}-title`}>{title}</h2>{description && <p id={`${drawerId}-description`}>{description}</p>}</div>
          <button className="icon-button" onClick={onClose} aria-label="Close details"><X size={18} /></button>
        </div>
        <div className="drawer-content">{children}</div>
      </aside>
    </div>
  );
}
