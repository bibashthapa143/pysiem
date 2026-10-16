import React, { useState } from 'react'
import { Shield } from 'lucide-react'

interface LoginModalProps {
  isOpen: boolean
  onLogin: (user: string, pass: string) => Promise<void>
  onContinueDemo?: () => void
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onLogin, onContinueDemo }) => {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('adminpassword123')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await onLogin(username, password)
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Ensure FastAPI is running on port 8000.')
    } finally {
      setLoading(false)
    }
  }

  const fillDefaults = () => {
    setUsername('admin')
    setPassword('adminpassword123')
    setError('')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-md p-4 animate-in fade-in duration-200">
      <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-[#0c0e14] p-6 shadow-2xl animate-in zoom-in-95 duration-200 light:bg-white light:border-slate-200">
        <div className="flex items-center gap-3 mb-2">
          <div className="flex size-9 items-center justify-center rounded-lg bg-gradient-to-br from-sky-600 to-sky-700 text-white shadow-md shadow-sky-600/30">
            <Shield className="size-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white light:text-slate-900 leading-tight">
              PySIEM Security Console
            </h2>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              SOC Analyst Authentication
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-400 mb-4 leading-relaxed">
          Sign in with authorized credentials to access live SOC telemetry, alerts, and investigations.
        </p>

        {error && (
          <div className="mb-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-400 leading-relaxed">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">
              Username
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-[#151821] px-3.5 py-2 text-xs text-white outline-none focus:border-sky-500 light:bg-slate-100 light:border-slate-200 light:text-slate-900"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-semibold text-slate-400">
                Password
              </label>
              <button
                type="button"
                onClick={fillDefaults}
                className="text-[11px] text-sky-400 hover:text-sky-300 transition underline underline-offset-2"
              >
                Autofill default
              </button>
            </div>
            <input
              type="password"
              required
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-white/10 bg-[#151821] px-3.5 py-2 text-xs text-white outline-none focus:border-sky-500 light:bg-slate-100 light:border-slate-200 light:text-slate-900"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-sky-500 py-2.5 text-xs font-semibold text-white shadow-lg shadow-sky-500/20 transition hover:bg-sky-400 disabled:opacity-50 mt-1 cursor-pointer"
          >
            {loading ? 'Authenticating...' : 'Sign In to PySIEM'}
          </button>

          {onContinueDemo && (
            <button
              type="button"
              onClick={onContinueDemo}
              className="w-full rounded-lg border border-white/10 bg-[#151821] py-2 text-xs font-medium text-slate-300 hover:bg-white/5 transition light:bg-slate-100 light:border-slate-200 light:text-slate-700 cursor-pointer"
            >
              Explore Console in Demo Mode &rarr;
            </button>
          )}

          <div className="pt-2 text-center">
            <span className="text-[10px] text-slate-500">
              Default credentials: <code className="text-slate-400 font-mono">admin</code> / <code className="text-slate-400 font-mono">adminpassword123</code>
            </span>
          </div>
        </form>
      </div>
    </div>
  )
}
