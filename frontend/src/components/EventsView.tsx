import React from 'react'
import type { SiemEvent } from '../types/siem'
import { Search, RotateCcw, X, ArrowLeft, ArrowRight } from 'lucide-react'

interface EventsViewProps {
  events: SiemEvent[]
  totalEvents: number
  page: number
  limit: number
  onPageChange: (newPage: number) => void
  search: string
  onSearchChange: (val: string) => void
  srcIp: string
  onSrcIpChange: (val: string) => void
  username: string
  onUsernameChange: (val: string) => void
  outcome: string
  onOutcomeChange: (val: string) => void
  timerange: string
  onTimerangeChange: (val: string) => void
  onApplyFilters: () => void
  onClearFilters: () => void
  onOpenEvent: (event: SiemEvent) => void
}

export const EventsView: React.FC<EventsViewProps> = ({
  events,
  totalEvents,
  page,
  limit,
  onPageChange,
  search,
  onSearchChange,
  srcIp,
  onSrcIpChange,
  username,
  onUsernameChange,
  outcome,
  onOutcomeChange,
  timerange,
  onTimerangeChange,
  onApplyFilters,
  onClearFilters,
  onOpenEvent,
}) => {
  const activeChips: { label: string; clear: () => void }[] = []
  if (search) activeChips.push({ label: `Query: ${search}`, clear: () => onSearchChange('') })
  if (srcIp) activeChips.push({ label: `IP: ${srcIp}`, clear: () => onSrcIpChange('') })
  if (username) activeChips.push({ label: `User: ${username}`, clear: () => onUsernameChange('') })
  if (outcome) activeChips.push({ label: `Outcome: ${outcome}`, clear: () => onOutcomeChange('') })
  if (timerange && timerange !== 'all') activeChips.push({ label: `Window: ${timerange}`, clear: () => onTimerangeChange('all') })

  const startRecord = totalEvents > 0 ? page * limit + 1 : 0
  const endRecord = Math.min((page + 1) * limit, totalEvents)
  const maxPage = Math.max(0, Math.ceil(totalEvents / limit) - 1)

  return (
    <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
      {/* Header */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4 light:border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white light:text-slate-900">
            Normalized Security Events
          </h1>
          <p className="text-xs text-slate-400">
            {totalEvents.toLocaleString()} total event{totalEvents === 1 ? '' : 's'} recorded in telemetry store
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={timerange}
            onChange={(e) => onTimerangeChange(e.target.value)}
            className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs text-white outline-none focus:border-sky-500 light:bg-slate-100 light:border-slate-200 light:text-slate-900"
          >
            <option value="all">All Time</option>
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>

          <button
            onClick={onApplyFilters}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 hover:text-white light:border-slate-200 light:bg-slate-100 light:text-slate-700"
          >
            <RotateCcw className="size-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Filter Row */}
      <div className="mb-3 flex flex-wrap items-center gap-2.5">
        <div className="relative flex-2 min-w-[200px]">
          <Search className="absolute left-3 top-2.5 size-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search message, user, IP..."
            value={search}
            onChange={(e) => onSearchChange(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && onApplyFilters()}
            className="w-full rounded-lg border border-white/10 bg-[#11131a] pl-9 pr-3 py-1.5 text-xs text-white outline-none placeholder:text-slate-500 focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
          />
        </div>

        <input
          type="text"
          placeholder="Source IP"
          value={srcIp}
          onChange={(e) => onSrcIpChange(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onApplyFilters()}
          className="flex-1 min-w-[130px] rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 text-xs text-white outline-none placeholder:text-slate-500 focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
        />

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => onUsernameChange(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && onApplyFilters()}
          className="flex-1 min-w-[130px] rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 text-xs text-white outline-none placeholder:text-slate-500 focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
        />

        <select
          value={outcome}
          onChange={(e) => onOutcomeChange(e.target.value)}
          className="rounded-lg border border-white/10 bg-[#11131a] px-3 py-1.5 text-xs text-white outline-none focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
        >
          <option value="">All Outcomes</option>
          <option value="failure">Failure</option>
          <option value="success">Success</option>
        </select>

        <button
          onClick={onApplyFilters}
          className="rounded-lg bg-white px-3.5 py-1.5 text-xs font-semibold text-black transition hover:bg-slate-200 light:bg-slate-900 light:text-white"
        >
          Apply Filters
        </button>

        <button
          onClick={onClearFilters}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Clear All
        </button>
      </div>

      {/* Active Filter Chips */}
      {activeChips.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-2">
          {activeChips.map((c, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-1.5 rounded-full border border-sky-500/30 bg-sky-500/10 px-2.5 py-0.5 text-[11px] font-medium text-sky-300"
            >
              <span>{c.label}</span>
              <button onClick={c.clear} className="hover:text-rose-400">
                <X className="size-3" />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-white/10 text-[11px] uppercase tracking-wider text-slate-400 light:border-slate-200">
              <th className="pb-3 font-semibold w-40">Timestamp (UTC)</th>
              <th className="pb-3 font-semibold w-24">Outcome</th>
              <th className="pb-3 font-semibold w-32">Username</th>
              <th className="pb-3 font-semibold w-32">Source IP</th>
              <th className="pb-3 font-semibold w-16">Port</th>
              <th className="pb-3 font-semibold w-24">Service</th>
              <th className="pb-3 font-semibold w-20">Method</th>
              <th className="pb-3 font-semibold">Raw Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 light:divide-slate-100">
            {events.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No matching events found for current filters
                </td>
              </tr>
            ) : (
              events.map((e, idx) => (
                <tr
                  key={idx}
                  onClick={() => onOpenEvent(e)}
                  className="cursor-pointer transition hover:bg-white/[0.03] light:hover:bg-slate-50"
                >
                  <td className="py-2.5 font-mono text-[11px] text-slate-400">
                    {e.timestamp ? e.timestamp.replace('T', ' ').replace(/\..+$/, '') : '-'}
                  </td>
                  <td className="py-2.5">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase border ${
                        e.outcome === 'success'
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                          : 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                      }`}
                    >
                      {e.outcome}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-white light:text-slate-900 font-medium">
                    {e.username || '-'}
                    {e.invalid_user && (
                      <span className="ml-1.5 rounded bg-rose-500/20 px-1 py-0.2 text-[9px] text-rose-300 border border-rose-500/30">
                        INVALID
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 font-mono text-sky-400">{e.src_ip || '-'}</td>
                  <td className="py-2.5 font-mono text-slate-400">{e.src_port || '-'}</td>
                  <td className="py-2.5 text-slate-300 light:text-slate-700">{e.program || '-'}</td>
                  <td className="py-2.5 text-slate-400">{e.method || '-'}</td>
                  <td className="py-2.5 font-mono text-[11px] text-slate-400 max-w-xs truncate">
                    {e.raw_message || '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-4 border-t border-white/10 pt-4 light:border-slate-200">
        <div className="text-xs text-slate-400">
          Showing {startRecord}-{endRecord} of {totalEvents.toLocaleString()} events
        </div>
        <div className="flex items-center gap-2">
          <button
            disabled={page === 0}
            onClick={() => onPageChange(page - 1)}
            className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 disabled:opacity-40 disabled:pointer-events-none light:border-slate-200 light:bg-slate-100 light:text-slate-700"
          >
            <ArrowLeft className="size-3.5" />
            <span>Previous</span>
          </button>
          <span className="font-mono text-xs text-slate-400 px-2">
            Page {page + 1} of {Math.max(1, maxPage + 1)}
          </span>
          <button
            disabled={page >= maxPage}
            onClick={() => onPageChange(page + 1)}
            className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:bg-white/10 disabled:opacity-40 disabled:pointer-events-none light:border-slate-200 light:bg-slate-100 light:text-slate-700"
          >
            <span>Next</span>
            <ArrowRight className="size-3.5" />
          </button>
        </div>
      </div>
    </div>
  )
}
