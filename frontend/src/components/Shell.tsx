import { useEffect, useState } from "react";
import { FlaskConical, Menu, PanelsTopLeft, ShieldCheck, X } from "lucide-react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";

const navigation = [
  { to: "/", label: "Overview", icon: PanelsTopLeft, end: true },
  { to: "/campaigns", label: "Campaigns", icon: FlaskConical, end: false },
];

const compactQuery = "(max-width: 760px)";

function routeTitle(pathname: string): string {
  if (pathname === "/") return "Overview";
  if (pathname.startsWith("/campaigns/")) return "Campaign workspace";
  if (pathname.startsWith("/campaigns")) return "Campaigns";
  return "Workspace";
}

export default function Shell() {
  const [compact, setCompact] = useState(() => window.matchMedia(compactQuery).matches);
  const [sidebarOpen, setSidebarOpen] = useState(() => !window.matchMedia(compactQuery).matches);
  const location = useLocation();

  useEffect(() => {
    const media = window.matchMedia(compactQuery);
    const updateLayout = () => {
      setCompact(media.matches);
      setSidebarOpen(!media.matches);
    };
    media.addEventListener("change", updateLayout);
    return () => media.removeEventListener("change", updateLayout);
  }, []);

  useEffect(() => {
    if (compact) setSidebarOpen(false);
  }, [location.pathname, compact]);

  useEffect(() => {
    if (!compact || !sidebarOpen) return;
    const trigger = document.querySelector<HTMLButtonElement>(".navigation-toggle");
    const closeButton = document.querySelector<HTMLButtonElement>(".mobile-nav-close");
    const previous = document.activeElement as HTMLElement | null;
    closeButton?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setSidebarOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const items = Array.from(document.querySelectorAll<HTMLElement>(
        ".mobile-sidebar a[href], .mobile-sidebar button:not(:disabled)",
      )).filter((item) => item.offsetParent !== null);
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      if (compact) trigger?.focus();
      else previous?.focus();
    };
  }, [compact, sidebarOpen]);

  const nav = (id: string) => (
    <>
      <div className="sidebar-brand">
        <Link to="/" className="brand-lockup" aria-label="VERITAS-lite overview">
          <span className="brand-mark"><ShieldCheck size={19} strokeWidth={1.8} /></span>
          <span className="brand-name">VERITAS<span>-lite</span></span>
        </Link>
        <span className="brand-caption">Agent reliability</span>
      </div>
      <div className="nav-label">Workspace</div>
      <nav id={id} aria-label="Primary navigation" className="primary-nav">
        {navigation.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end} className={({ isActive }) => `nav-link ${isActive ? "nav-link--active" : ""}`}>
            <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>
    </>
  );

  return (
    <div className={`app-frame ${!sidebarOpen ? "app-frame--sidebar-closed" : ""}`}>
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <aside className="sidebar" aria-label="Workspace sidebar" aria-hidden={compact || !sidebarOpen}>
        {nav("primary-navigation")}
      </aside>
      {compact && sidebarOpen && (
        <div className="mobile-nav-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) setSidebarOpen(false); }}>
          <aside className="mobile-sidebar" role="dialog" aria-modal="true" aria-label="Primary navigation">
            <button className="icon-button mobile-nav-close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation"><X size={18} /></button>
            {nav("mobile-primary-navigation")}
          </aside>
        </div>
      )}
      <div className="workspace">
        <header className="topbar">
          <div className="topbar-leading">
            <button
              className="icon-button navigation-toggle"
              onClick={() => setSidebarOpen((open) => !open)}
              aria-label={compact ? (sidebarOpen ? "Close navigation" : "Open navigation") : (sidebarOpen ? "Collapse navigation" : "Expand navigation")}
              aria-expanded={sidebarOpen}
            ><Menu size={19} /></button>
            <div className="breadcrumbs"><span>Workspace</span><span className="breadcrumb-separator">/</span><strong>{routeTitle(location.pathname)}</strong></div>
          </div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}><Outlet /></main>
        <footer className="app-footer"><span>VERITAS-lite</span><span>Agent security evaluation</span></footer>
      </div>
    </div>
  );
}
