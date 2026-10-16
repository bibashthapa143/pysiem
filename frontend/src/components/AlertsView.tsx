import React from 'react'
import type { SiemAlert } from '../types/siem'
import { RotateCcw, ExternalLink } from 'lucide-react'

interface AlertsViewProps {
  alerts: SiemAlert[]
  statusFilter: string
  onStatusFilterChange: (status: string) => void
  severityFilter: string
  onSeverityFilterChange: (severity: string) => void
  onRefresh: () => void
  onOpenAlert: (alert: SiemAlert) => void
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  statusFilter,
  onStatusFilterChange,
  severityFilter,
  onSeverityFilterChange,
  onRefresh,
  onOpenAlert,
}) => {
  return (
    <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4 light:border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white light:text-slate-900">
            Security Incidents &amp; Alerts
          </h1>
          <p className="text-xs text-slate-400">
            {alerts.length} total alert{alerts.length === 1 ? '' : 's'} matching current criteria
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={statusFilter}
            onChange={(e) => onStatusFilterChange(e.target.value)}
            className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs text-white outline-none focus:border-sky-500 light:bg-slate-100 light:border-slate-200 light:text-slate-900"
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="closed">Closed</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => onSeverityFilterChange(e.target.value)}
            className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs text-white outline-none focus:border-sky-500 light:bg-slate-100 light:border-slate-200 light:text-slate-900"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <button
            onClick={onRefresh}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white light:border-slate-200 light:bg-slate-100 light:text-slate-700"
          >
            <RotateCcw className="size-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-white/10 text-[11px] uppercase tracking-wider text-slate-400 light:border-slate-200">
              <th className="pb-3 font-semibold w-24">Severity</th>
              <th className="pb-3 font-semibold">Alert Title &amp; Description</th>
              <th className="pb-3 font-semibold w-28">MITRE</th>
              <th className="pb-3 font-semibold w-20">Events</th>
              <th className="pb-3 font-semibold w-28">Status</th>
              <th className="pb-3 font-semibold w-40">Last Seen (UTC)</th>
              <th className="pb-3 font-semibold w-24 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 light:divide-slate-100">
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500">
                  No alerts matching current filters
                </td>
              </tr>
            ) : (
              alerts.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => onOpenAlert(a)}
                  className="cursor-pointer transition hover:bg-white/[0.03] light:hover:bg-slate-50"
                >
                  <td className="py-3.5">
                    <span
                      className={`inline-block rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase border ${
                        a.severity === 'critical'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                          : a.severity === 'high'
                          ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                          : a.severity === 'medium'
                          ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                          : 'border-sky-500/30 bg-sky-500/10 text-sky-400'
                      }`}
                    >
                      {a.severity}
                    </span>
                  </td>
                  <td className="py-3.5 pr-4">
                    <div className="font-semibold text-white light:text-slate-900">{a.title}</div>
                    <div className="text-[11px] text-slate-400 line-clamp-1">{a.description}</div>
                  </td>
                  <td className="py-3.5">
                    {a.mitre_tag || a.mitre_attack ? (
                      <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 font-mono text-[11px] text-purple-300">
                        {a.mitre_tag || a.mitre_attack}
                      </span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  <td className="py-3.5 font-mono font-medium text-slate-300 light:text-slate-700">
                    {a.event_count}
                  </td>
                  <td className="py-3.5">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase border ${
                        a.status === 'new'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                          : a.status === 'acknowledged'
                          ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                          : 'border-slate-500/30 bg-slate-500/10 text-slate-400'
                      }`}
                    >
                      {a.status}
                    </span>
                  </td>
                  <td className="py-3.5 font-mono text-[11px] text-slate-400">{a.last_seen}</td>
                  <td className="py-3.5 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        onOpenAlert(a)
                      }}
                      className="inline-flex items-center gap-1 rounded-md border border-white/10 bg-[#151821] px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
                    >
                      <span>Investigate</span>
                      <ExternalLink className="size-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
