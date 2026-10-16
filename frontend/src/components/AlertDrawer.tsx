import React from 'react'
import type { SiemAlert } from '../types/siem'
import { X, ExternalLink, ArrowRight, AlertTriangle } from 'lucide-react'

interface AlertDrawerProps {
  alert: SiemAlert | null
  onClose: () => void
  onUpdateStatus: (alertId: number, status: 'new' | 'acknowledged' | 'closed') => void
  onInvestigateIp: (ip: string) => void
}

export const AlertDrawer: React.FC<AlertDrawerProps> = ({
  alert,
  onClose,
  onUpdateStatus,
  onInvestigateIp,
}) => {
  if (!alert) return null

  const isBreach = alert.rule_id === 'ssh_failure_then_success'
  const srcIp = alert.details?.src_ip || ''

  const getMitreUrl = (tag?: string) => {
    if (!tag) return null
    const clean = String(tag).trim()
    const match = clean.match(/^T(\d+)(?:\.(\d+))?$/i)
    if (!match) return null
    const tech = `T${match[1]}`
    const sub = match[2]
    return sub ? `https://attack.mitre.org/techniques/${tech}/${sub}/` : `https://attack.mitre.org/techniques/${tech}/`
  }

  const mitreUrl = getMitreUrl(alert.mitre_tag || alert.mitre_attack)

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="flex h-full w-full max-w-lg flex-col border-l border-white/10 bg-[#0c0e14] shadow-2xl animate-in slide-in-from-right duration-250 light:bg-white light:border-slate-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 p-5 light:border-slate-200">
          <div className="flex items-center gap-2.5">
            <span
              className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${
                alert.severity === 'critical'
                  ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                  : alert.severity === 'high'
                  ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                  : alert.severity === 'medium'
                  ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                  : 'border-sky-500/30 bg-sky-500/10 text-sky-400'
              }`}
            >
              {alert.severity}
            </span>
            <h2 className="text-base font-bold text-white light:text-slate-900">
              Alert Investigation
            </h2>
          </div>
          <button
            onClick={onClose}
            className="flex size-7 items-center justify-center rounded-lg border border-white/10 text-slate-400 hover:bg-white/10 hover:text-white transition light:border-slate-200 light:hover:bg-slate-100"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* Potential Breach Banner */}
          {isBreach && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4">
              <div className="flex items-center gap-2 font-bold text-xs text-rose-400 mb-1">
                <AlertTriangle className="size-4 text-rose-400" />
                <span>Potential Credential Breach Detected</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed light:text-slate-700">
                Multiple authentication failures were immediately followed by a successful login. Investigate credentials and host sessions immediately.
              </p>
            </div>
          )}

          {/* Incident Overview Card */}
          <div className="rounded-xl border border-white/10 bg-[#151821] p-4 space-y-3 light:bg-slate-50 light:border-slate-200">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Incident Overview
            </h3>

            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="block text-[11px] text-slate-400">Rule ID</span>
                <span className="font-mono text-white light:text-slate-900 font-medium">{alert.rule_id}</span>
              </div>
              <div>
                <span className="block text-[11px] text-slate-400">Correlated Events</span>
                <span className="font-mono text-sky-400 font-semibold">{alert.event_count}</span>
              </div>
              <div>
                <span className="block text-[11px] text-slate-400">Triage Status</span>
                <span className="font-semibold uppercase text-amber-400">{alert.status}</span>
              </div>
              <div>
                <span className="block text-[11px] text-slate-400">Last Seen (UTC)</span>
                <span className="font-mono text-slate-300 light:text-slate-700">{alert.last_seen}</span>
              </div>
            </div>

            {alert.mitre_tag && (
              <div className="border-t border-white/5 pt-2.5 flex items-center justify-between text-xs">
                <span className="text-slate-400">MITRE ATT&amp;CK:</span>
                {mitreUrl ? (
                  <a
                    href={mitreUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 font-mono text-purple-300 hover:underline"
                  >
                    <span>{alert.mitre_tag}</span>
                    <ExternalLink className="size-3" />
                  </a>
                ) : (
                  <span className="font-mono text-purple-300">{alert.mitre_tag}</span>
                )}
              </div>
            )}
          </div>

          {/* Attack Context Details */}
          {alert.details && (
            <div className="rounded-xl border border-white/10 bg-[#151821] p-4 space-y-3 light:bg-slate-50 light:border-slate-200">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Correlated Attack Context
              </h3>
              <div className="space-y-2 text-xs">
                {Object.entries(alert.details).map(([key, val]) => (
                  <div key={key} className="flex justify-between items-center py-1 border-b border-white/5 light:border-slate-200">
                    <span className="text-slate-400 capitalize">{key.replace('_', ' ')}:</span>
                    <span className="font-mono text-white light:text-slate-900 font-medium">
                      {Array.isArray(val) ? val.join(', ') : String(val)}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Description */}
          <div className="rounded-xl border border-white/10 bg-[#151821] p-4 space-y-2 light:bg-slate-50 light:border-slate-200">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Alert Summary
            </h3>
            <p className="text-xs text-slate-300 leading-relaxed light:text-slate-700">
              {alert.description}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-white/10 bg-[#151821] p-4 flex flex-wrap items-center justify-between gap-3 light:bg-slate-50 light:border-slate-200">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Status:</span>
            <div className="inline-flex rounded-lg border border-white/10 bg-[#0c0e14] p-1 light:bg-white light:border-slate-200">
              {(['new', 'acknowledged', 'closed'] as const).map((st) => (
                <button
                  key={st}
                  onClick={() => onUpdateStatus(alert.id, st)}
                  className={`rounded px-2.5 py-1 text-xs font-medium capitalize transition ${
                    alert.status === st
                      ? 'bg-white/20 text-white font-semibold light:bg-slate-900 light:text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {srcIp && (
            <button
              onClick={() => onInvestigateIp(srcIp)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-3 py-1.5 text-xs font-medium text-sky-400 transition hover:bg-sky-500/20"
            >
              <span>Investigate IP</span>
              <ArrowRight className="size-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
