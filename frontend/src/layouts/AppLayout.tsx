import { NavLink, Outlet } from "react-router-dom";
import { Logo } from "../components/Logo";

const links = [
  { to: "/", label: "Scanner" },
  { to: "/history", label: "History" },
  { to: "/dashboard", label: "Dashboard" },
  { to: "/about", label: "Methodology" },
  { to: "/docs", label: "Docs" },
];

export function AppLayout() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-slate-800 bg-navy-900/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-3">
          <Logo />
          <nav aria-label="Main" className="flex flex-wrap gap-1">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === "/"}
                className={({ isActive }) =>
                  `rounded-md px-3 py-2 text-sm ${isActive ? "bg-navy-700 text-white" : "text-slate-300 hover:bg-navy-800"}`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8">
        <Outlet />
      </main>
      <footer className="border-t border-slate-800 bg-navy-900">
        <div className="mx-auto flex max-w-6xl flex-wrap gap-4 px-4 py-6 text-sm text-slate-400">
          <p className="mr-auto">LinkShield does not guarantee that any URL is safe.</p>
          <NavLink to="/about" className="hover:text-white">
            About
          </NavLink>
          <NavLink to="/privacy" className="hover:text-white">
            Privacy Policy
          </NavLink>
          <NavLink to="/terms" className="hover:text-white">
            Terms
          </NavLink>
          <NavLink to="/docs" className="hover:text-white">
            Documentation
          </NavLink>
        </div>
      </footer>
    </div>
  );
}
