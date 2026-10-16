import React from 'react'
import { Shield, LayoutDashboard, AlertTriangle, FileText, Terminal, Scale, Moon, Sun, LogOut } from 'lucide-react'

export type TabType = 'dashboard' | 'alerts' | 'events' | 'ingest' | 'rules'

interface NavbarProps {
  activeTab: TabType
  onTabChange: (tab: TabType) => void
  username: string
  theme: 'dark' | 'light'
  onToggleTheme: () => void
  onLogout: () => void
  onOpenLogin?: () => void
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onTabChange,
  username,
  theme,
  onToggleTheme,
  onLogout,
  onOpenLogin,
}) => {
  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="size-4" /> },
    { id: 'alerts', label: 'Alerts', icon: <AlertTriangle className="size-4" /> },
    { id: 'events', label: 'Event Explorer', icon: <FileText className="size-4" /> },
    { id: 'ingest', label: 'Ingestion & Lab', icon: <Terminal className="size-4" /> },
    { id: 'rules', label: 'Detection Rules', icon: <Scale className="size-4" /> },
  ]

  return (
    <header className="sticky top-0 z-40 w-full border-b border-white/10 bg-[#0c0e14]/90 backdrop-blur-md px-6 py-2.5 transition-colors light:bg-white/90 light:border-slate-200">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-2.5 font-bold tracking-tight text-white light:text-slate-900 select-none">
          <div className="flex size-7 items-center justify-center rounded-md bg-gradient-to-br from-sky-600 to-sky-700 text-white shadow-sm shadow-sky-600/30">
            <Shield className="size-4" />
          </div>
          <span className="text-base tracking-tight font-bold">PySIEM</span>
          <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-sky-400">
            SOC
          </span>
        </div>

        {/* Segmented Navigation (shadcn TabsList) */}
        <nav className="inline-flex items-center gap-1 rounded-xl border border-white/10 bg-[#151821] p-1 light:bg-slate-100 light:border-slate-200">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`inline-flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs font-medium transition-all select-none ${
                  isActive
                    ? 'border border-white/10 bg-[#0c0e14] text-white shadow-sm light:border-slate-300 light:bg-white light:text-slate-900'
                    : 'text-slate-400 hover:bg-white/5 hover:text-white light:text-slate-600 light:hover:bg-slate-200/60 light:hover:text-slate-900'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            )
          })}
        </nav>

        {/* User & Theme Actions */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onToggleTheme}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#151821] px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white light:border-slate-200 light:bg-slate-100 light:text-slate-700 light:hover:bg-slate-200"
            title="Toggle theme"
          >
            {theme === 'dark' ? <Sun className="size-3.5 text-amber-400" /> : <Moon className="size-3.5 text-sky-600" />}
            <span>{theme === 'dark' ? 'Light' : 'Dark'}</span>
          </button>

          {username ? (
            <>
              <div className="flex items-center gap-2 rounded-full border border-white/10 bg-[#151821] px-3 py-1 font-mono text-xs text-slate-300 light:border-slate-200 light:bg-slate-100 light:text-slate-700">
                <span className="relative flex size-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex size-2 rounded-full bg-emerald-500"></span>
                </span>
                <span>{username}</span>
              </div>

              <button
                onClick={onLogout}
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#151821] px-2.5 py-1 text-xs font-medium text-slate-400 transition hover:bg-rose-500/10 hover:border-rose-500/30 hover:text-rose-400 light:border-slate-200 light:bg-slate-100 light:text-slate-600 cursor-pointer"
                title="Sign out of console"
              >
                <LogOut className="size-3.5" />
                <span>Logout</span>
              </button>
            </>
          ) : (
            <button
              onClick={onOpenLogin}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-500 px-3 py-1 text-xs font-semibold text-white shadow-sm shadow-sky-500/20 hover:bg-sky-400 transition cursor-pointer"
            >
              <Shield className="size-3.5" />
              <span>Sign In</span>
            </button>
          )}
        </div>
      </div>
    </header>
  )
}
