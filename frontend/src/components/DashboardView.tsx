import React, { useState } from 'react'
import type { TelemetryDataset } from '../lib/telemetry'
import type { SiemAlert } from '../types/siem'
import {
  RotateCcw,
  Zap,
  Database,
  ArrowRight,
  Activity,
  ShieldAlert,
} from 'lucide-react'

interface DashboardViewProps {
  telemetry: TelemetryDataset
  isLiveMode: boolean
  onToggleLiveMode: (live: boolean) => void
  onRefresh: () => void
  onOpenAlert: (alert: SiemAlert) => void
  onNavigateTab: (tab: 'alerts' | 'events') => void
  onFilterIpInEvents: (ip: string) => void
  onFilterUserInEvents: (user: string) => void
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  telemetry,
  isLiveMode,
  onToggleLiveMode,
  onRefresh,
  onOpenAlert,
  onNavigateTab,
  onFilterIpInEvents,
  onFilterUserInEvents,
}) => {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null)

  // Chart dimensions
  const chartWidth = 900
  const chartHeight = 220
  const padLeft = 40
  const padRight = 20
  const padTop = 20
  const padBottom = 30
  const innerW = chartWidth - padLeft - padRight
  const innerH = chartHeight - padTop - padBottom

  const maxVal = Math.max(100, ...telemetry.buckets.map((b) => b.total))

  const getY = (v: number) => padTop + innerH - (v / maxVal) * innerH
  const getX = (idx: number) => padLeft + (idx / 59) * innerW

  const lineTotalD = telemetry.buckets.reduce((acc, b, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(b.total)}`, '')
  const lineFailD = telemetry.buckets.reduce((acc, b, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(b.failures)}`, '')
  const lineSuccD = telemetry.buckets.reduce((acc, b, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${getX(i)} ${getY(b.successes)}`, '')
  const areaTotalD = `${lineTotalD} L ${getX(59)} ${padTop + innerH} L ${getX(0)} ${padTop + innerH} Z`

  const activeBucket = hoveredIndex !== null ? telemetry.buckets[hoveredIndex] : null

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white light:text-slate-900">
              SOC Operations Dashboard
            </h1>
            <span
              className={`rounded-full px-2.5 py-0.5 text-[11px] font-semibold tracking-wide uppercase border ${
                isLiveMode
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                  : 'border-sky-500/30 bg-sky-500/10 text-sky-400'
              }`}
            >
              {isLiveMode ? '● LIVE DATABASE' : '⚡ DEMO TELEMETRY (60-MIN)'}
            </span>
          </div>
          <p className="mt-1 flex items-center gap-2 text-xs text-slate-400">
            <span>
              {isLiveMode
                ? 'Active SQLite Enterprise Telemetry Store'
                : 'Simulated Enterprise SOC Telemetry (Correlated Anomaly)'}
            </span>
            <span>•</span>
            <span>Real-time correlation enabled</span>
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="inline-flex rounded-lg border border-white/10 bg-[#151821] p-1 light:bg-slate-100 light:border-slate-200">
            <button
              onClick={() => onToggleLiveMode(false)}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition ${
                !isLiveMode
                  ? 'bg-[#0c0e14] text-white shadow-sm light:bg-white light:text-slate-900'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Zap className="size-3.5 text-amber-400" />
              <span>Demo Dataset</span>
            </button>
            <button
              onClick={() => onToggleLiveMode(true)}
              className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition ${
                isLiveMode
                  ? 'bg-[#0c0e14] text-white shadow-sm light:bg-white light:text-slate-900'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Database className="size-3.5 text-emerald-400" />
              <span>Live Database</span>
            </button>
          </div>

          <button
            onClick={onRefresh}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white light:border-slate-200 light:bg-slate-100 light:text-slate-700"
          >
            <RotateCcw className="size-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Priority Incident Queue (Critical & High) */}
      <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm border-l-4 border-l-rose-500 light:bg-white light:border-slate-200 light:border-l-rose-500">
        <div className="mb-4 flex items-center justify-between gap-4 border-b border-white/10 pb-3 light:border-slate-200">
          <div className="flex items-center gap-2.5">
            <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2.5 py-0.5 text-[11px] font-semibold uppercase text-rose-400">
              Priority Queue
            </span>
            <h2 className="text-sm font-semibold text-white light:text-slate-900">
              High &amp; Critical Incidents Requiring Attention
            </h2>
          </div>
          <button
            onClick={() => onNavigateTab('alerts')}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-sky-400 hover:text-sky-300 transition"
          >
            <span>View All Alerts</span>
            <ArrowRight className="size-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-white/10 text-[11px] uppercase tracking-wider text-slate-400 light:border-slate-200">
                <th className="pb-2.5 font-semibold">Severity</th>
                <th className="pb-2.5 font-semibold">Alert Title &amp; Description</th>
                <th className="pb-2.5 font-semibold">MITRE ATT&amp;CK</th>
                <th className="pb-2.5 font-semibold">Status</th>
                <th className="pb-2.5 font-semibold">Last Seen (UTC)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 light:divide-slate-100">
              {telemetry.priorityAlerts.map((a) => (
                <tr
                  key={a.id}
                  onClick={() => onOpenAlert(a)}
                  className="cursor-pointer transition hover:bg-white/[0.03] light:hover:bg-slate-50"
                >
                  <td className="py-3">
                    <span
                      className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase border ${
                        a.severity === 'critical'
                          ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                          : 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                      }`}
                    >
                      {a.severity}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="font-medium text-white light:text-slate-900">{a.title}</div>
                    <div className="text-[11px] text-slate-400 line-clamp-1">{a.description}</div>
                  </td>
                  <td className="py-3">
                    {a.mitre_tag ? (
                      <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 font-mono text-[11px] text-purple-300">
                        {a.mitre_tag}
                      </span>
                    ) : (
                      <span className="text-slate-500">-</span>
                    )}
                  </td>
                  <td className="py-3">
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
                  <td className="py-3 font-mono text-[11px] text-slate-400">{a.last_seen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {/* Critical & High */}
        <div
          onClick={() => onNavigateTab('alerts')}
          className="group cursor-pointer rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm transition-all hover:-translate-y-0.5 hover:border-rose-500/40 light:bg-white light:border-slate-200"
        >
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <span>Critical &amp; High</span>
            <span className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-[10px] text-rose-400">
              Action
            </span>
          </div>
          <div className="mt-3 text-3xl font-bold tracking-tight text-rose-400">
            {telemetry.critHighAlerts}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400 group-hover:text-slate-300">
            <span>Filter priority incidents</span>
            <ArrowRight className="size-3 transition group-hover:translate-x-1" />
          </div>
        </div>

        {/* Active Open Alerts */}
        <div
          onClick={() => onNavigateTab('alerts')}
          className="group cursor-pointer rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm transition-all hover:-translate-y-0.5 hover:border-amber-500/40 light:bg-white light:border-slate-200"
        >
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <span>Active / Open Alerts</span>
            <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-400">
              Triage
            </span>
          </div>
          <div className="mt-3 text-3xl font-bold tracking-tight text-amber-400">
            {telemetry.openAlerts}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400 group-hover:text-slate-300">
            <span>Pending analyst review</span>
            <ArrowRight className="size-3 transition group-hover:translate-x-1" />
          </div>
        </div>

        {/* Total Alerts */}
        <div
          onClick={() => onNavigateTab('alerts')}
          className="group cursor-pointer rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm transition-all hover:-translate-y-0.5 hover:border-sky-500/40 light:bg-white light:border-slate-200"
        >
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <span>Triggered Alerts</span>
            <ShieldAlert className="size-4 text-slate-400" />
          </div>
          <div className="mt-3 text-3xl font-bold tracking-tight text-white light:text-slate-900">
            {telemetry.totalAlerts}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400 group-hover:text-slate-300">
            <span>All correlated detections</span>
            <ArrowRight className="size-3 transition group-hover:translate-x-1" />
          </div>
        </div>

        {/* Total Events */}
        <div
          onClick={() => onNavigateTab('events')}
          className="group cursor-pointer rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm transition-all hover:-translate-y-0.5 hover:border-sky-500/40 light:bg-white light:border-slate-200"
        >
          <div className="flex items-center justify-between text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <span>Ingested Events</span>
            <Activity className="size-4 text-slate-400" />
          </div>
          <div className="mt-3 text-3xl font-bold tracking-tight text-white light:text-slate-900">
            {telemetry.totalEvents.toLocaleString()}
          </div>
          <div className="mt-2 flex items-center gap-1.5 text-xs text-slate-400 group-hover:text-slate-300">
            <span>Explore normalized logs</span>
            <ArrowRight className="size-3 transition group-hover:translate-x-1" />
          </div>
        </div>
      </div>

      {/* Security Events Over Time Timeline Chart */}
      <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-3 light:border-slate-200">
          <div>
            <h2 className="text-sm font-semibold text-white light:text-slate-900">
              Security Events Over Time &amp; Authentication Trends
            </h2>
            <p className="text-xs text-slate-400">
              Event volume and login failure/success trends across the 60-minute telemetry window
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5 text-slate-300 light:text-slate-700">
              <span className="size-2 rounded-full bg-sky-500"></span> All Events
            </span>
            <span className="flex items-center gap-1.5 text-slate-300 light:text-slate-700">
              <span className="size-2 rounded-full bg-rose-500"></span> Failed Logins
            </span>
            <span className="flex items-center gap-1.5 text-slate-300 light:text-slate-700">
              <span className="size-2 rounded-full bg-emerald-500"></span> Successful Logins
            </span>
          </div>
        </div>

        {/* SVG Chart */}
        <div className="relative overflow-hidden">
          <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="w-full h-auto">
            <defs>
              <linearGradient id="area-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#0284c7" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#0284c7" stopOpacity="0.01" />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            {[0, 25, 50, 75, 100].map((pct) => {
              const y = padTop + (innerH * (100 - pct)) / 100
              return (
                <line
                  key={pct}
                  x1={padLeft}
                  y1={y}
                  x2={padLeft + innerW}
                  y2={y}
                  stroke="rgba(255,255,255,0.06)"
                  strokeDasharray="3 3"
                />
              )
            })}

            {/* Area and Lines */}
            <path d={areaTotalD} fill="url(#area-grad)" />
            <path d={lineTotalD} fill="none" stroke="#0284c7" strokeWidth="2.25" strokeLinecap="round" />
            <path d={lineFailD} fill="none" stroke="#f43f5e" strokeWidth="2.25" strokeLinecap="round" />
            <path d={lineSuccD} fill="none" stroke="#22c55e" strokeWidth="2.25" strokeLinecap="round" />

            {/* Hover bar targets */}
            {telemetry.buckets.map((_, i) => {
              const slotW = innerW / 60
              return (
                <rect
                  key={i}
                  x={getX(i) - slotW / 2}
                  y={padTop}
                  width={slotW}
                  height={innerH}
                  fill="transparent"
                  className="cursor-crosshair hover:fill-white/5 transition"
                  onMouseEnter={() => setHoveredIndex(i)}
                  onMouseLeave={() => setHoveredIndex(null)}
                />
              )
            })}

            {/* Crosshair dot on active */}
            {hoveredIndex !== null && (
              <>
                <line
                  x1={getX(hoveredIndex)}
                  y1={padTop}
                  x2={getX(hoveredIndex)}
                  y2={padTop + innerH}
                  stroke="rgba(255,255,255,0.3)"
                  strokeDasharray="2 2"
                />
                <circle
                  cx={getX(hoveredIndex)}
                  cy={getY(telemetry.buckets[hoveredIndex].failures)}
                  r="4"
                  fill="#f43f5e"
                  stroke="#0c0e14"
                  strokeWidth="2"
                />
              </>
            )}
          </svg>

          {/* Floating Tooltip */}
          {activeBucket && (
            <div className="absolute top-2 right-4 rounded-lg border border-white/20 bg-[#151821]/95 p-3 text-xs shadow-xl backdrop-blur-md text-white min-w-[200px] pointer-events-none light:bg-white light:border-slate-300 light:text-slate-900">
              <div className="font-semibold border-b border-white/10 pb-1.5 mb-2 light:border-slate-200">
                Time: {activeBucket.timeLabel} ({activeBucket.minuteOffset}m ago)
              </div>
              <div className="flex justify-between py-0.5 text-slate-300 light:text-slate-700">
                <span>All Events:</span>
                <span className="font-mono font-semibold">{activeBucket.total}</span>
              </div>
              <div className="flex justify-between py-0.5 text-rose-400">
                <span>Failed Logins:</span>
                <span className="font-mono font-semibold">{activeBucket.failures}</span>
              </div>
              <div className="flex justify-between py-0.5 text-emerald-400">
                <span>Successful Logins:</span>
                <span className="font-mono font-semibold">{activeBucket.successes}</span>
              </div>
              {activeBucket.anomalyTag && (
                <div className="mt-2 rounded bg-rose-500/20 border border-rose-500/40 px-2 py-1 text-[11px] font-semibold text-rose-300">
                  ⚠ {activeBucket.anomalyTag}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Analytics Breakdown & Threat Intelligence Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Severity Distribution */}
        <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
          <div className="mb-4 border-b border-white/10 pb-3 light:border-slate-200">
            <h2 className="text-sm font-semibold text-white light:text-slate-900">Alert Severity Distribution</h2>
            <p className="text-xs text-slate-400">Total volume grouped by incident severity</p>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Critical', count: telemetry.severityCounts.critical, color: 'bg-rose-500', total: telemetry.totalAlerts },
              { label: 'High', count: telemetry.severityCounts.high, color: 'bg-orange-500', total: telemetry.totalAlerts },
              { label: 'Medium', count: telemetry.severityCounts.medium, color: 'bg-yellow-500', total: telemetry.totalAlerts },
              { label: 'Low', count: telemetry.severityCounts.low, color: 'bg-sky-500', total: telemetry.totalAlerts },
            ].map((s) => {
              const pct = Math.round((s.count / s.total) * 100) || 0
              return (
                <div key={s.label} className="flex items-center gap-3 text-xs">
                  <span className="w-16 font-medium text-slate-300 light:text-slate-700">{s.label}</span>
                  <div className="flex-1 h-2 rounded-full bg-white/10 overflow-hidden light:bg-slate-200">
                    <div className={`h-full ${s.color} transition-all duration-500`} style={{ width: `${pct}%` }}></div>
                  </div>
                  <span className="w-12 text-right font-mono text-slate-400">{s.count} ({pct}%)</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Authentication Outcomes */}
        <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
          <div className="mb-4 border-b border-white/10 pb-3 light:border-slate-200">
            <h2 className="text-sm font-semibold text-white light:text-slate-900">Authentication Outcomes</h2>
            <p className="text-xs text-slate-400">Outcome distribution across the 60-minute window</p>
          </div>
          <div className="space-y-3">
            {[
              { label: 'Successes', count: telemetry.successfulLogins, color: 'bg-emerald-500' },
              { label: 'Failures', count: telemetry.failedLogins, color: 'bg-rose-500' },
              { label: 'Other Logs', count: telemetry.otherEvents, color: 'bg-slate-500' },
            ].map((o) => {
              const pct = Math.round((o.count / telemetry.totalEvents) * 100) || 0
              return (
                <div key={o.label} className="flex items-center gap-3 text-xs">
                  <span className="w-20 font-medium text-slate-300 light:text-slate-700">{o.label}</span>
                  <div className="flex-1 h-2 rounded-full bg-white/10 overflow-hidden light:bg-slate-200">
                    <div className={`h-full ${o.color} transition-all duration-500`} style={{ width: `${pct}%` }}></div>
                  </div>
                  <span className="w-16 text-right font-mono text-slate-400">{o.count.toLocaleString()} ({pct}%)</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Top Attacking Source IPs */}
        <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
          <div className="mb-4 border-b border-white/10 pb-3 light:border-slate-200">
            <h2 className="text-sm font-semibold text-white light:text-slate-900">Top Attacking Source IPs</h2>
            <p className="text-xs text-slate-400">Click any IP to inspect telemetry in Event Explorer</p>
          </div>
          <div className="space-y-2.5">
            {telemetry.topIps.map((item, idx) => (
              <div
                key={item.ip}
                onClick={() => onFilterIpInEvents(item.ip)}
                className="flex items-center justify-between gap-3 rounded-lg border border-white/5 bg-[#151821] p-2.5 text-xs transition hover:border-sky-500/40 hover:bg-white/[0.04] cursor-pointer light:bg-slate-50 light:border-slate-200"
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs font-semibold text-slate-500">#{idx + 1}</span>
                  <div>
                    <span className="font-mono font-medium text-sky-400 hover:underline">{item.ip}</span>
                    <span className="ml-2 text-[11px] text-slate-400">({item.role})</span>
                  </div>
                </div>
                <span className="rounded border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[11px] text-rose-300">
                  {item.count} attempts
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Targeted Accounts */}
        <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
          <div className="mb-4 border-b border-white/10 pb-3 light:border-slate-200">
            <h2 className="text-sm font-semibold text-white light:text-slate-900">Top Targeted Usernames</h2>
            <p className="text-xs text-slate-400">Click any user to filter in Event Explorer</p>
          </div>
          <div className="space-y-2.5">
            {telemetry.topUsers.map((item, idx) => (
              <div
                key={item.username}
                onClick={() => onFilterUserInEvents(item.username)}
                className="flex items-center justify-between gap-3 rounded-lg border border-white/5 bg-[#151821] p-2.5 text-xs transition hover:border-sky-500/40 hover:bg-white/[0.04] cursor-pointer light:bg-slate-50 light:border-slate-200"
              >
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-xs font-semibold text-slate-500">#{idx + 1}</span>
                  <div>
                    <span className="font-mono font-medium text-amber-400 hover:underline">{item.username}</span>
                    <span className="ml-2 text-[11px] text-slate-400">({item.role})</span>
                  </div>
                </div>
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-[11px] text-amber-300">
                  {item.count} attempts
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
