import { NavLink, Outlet } from 'react-router-dom'
import { Activity, AlertTriangle, BookOpenCheck, Briefcase, Crosshair, FlaskConical, Grid3x3, LayoutDashboard, LogOut, Radar, Server, Settings, ShieldCheck, Workflow } from 'lucide-react'
import { useAuth } from '../auth'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alerts', icon: AlertTriangle },
  { to: '/assets', label: 'Assets', icon: Server },
  { to: '/events', label: 'Events', icon: Activity },
  { to: '/cases', label: 'Cases', icon: Briefcase },
  { to: '/hunt', label: 'Hunt lab', icon: Crosshair },
  { to: '/mitre', label: 'MITRE map', icon: Grid3x3 },
  { to: '/response', label: 'Response plans', icon: Workflow },
  { to: '/validation', label: 'Validation', icon: FlaskConical },
  { to: '/ot', label: 'OT discovery', icon: Radar },
  { to: '/compliance', label: 'Compliance', icon: BookOpenCheck },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export default function Layout() {
  const { user, logout } = useAuth()
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-slate-800 bg-slate-950 p-3 md:flex">
        <div className="mb-4 flex items-center gap-2 px-2 text-lg font-semibold text-white"><ShieldCheck className="text-indigo-400" /> SOC Platform</div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) =>
              `flex items-center gap-2 rounded-lg px-2 py-1.5 text-sm ${isActive ? 'bg-indigo-600/20 text-indigo-200' : 'text-slate-400 hover:bg-slate-800/60 hover:text-slate-200'}`}>
              <Icon size={16} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-800 pt-3 text-xs text-slate-400">
          <div className="truncate">{user?.email}</div>
          <div className="mb-2 capitalize">{user?.role}</div>
          <button className="btn-ghost w-full justify-center" onClick={logout}><LogOut size={14} /> Sign out</button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-6">
        <nav className="mb-4 flex gap-1 overflow-x-auto md:hidden">
          {NAV.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `whitespace-nowrap rounded-full px-3 py-1 text-xs ${isActive ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-300'}`}>{label}</NavLink>
          ))}
        </nav>
        <Outlet />
      </main>
    </div>
  )
}
