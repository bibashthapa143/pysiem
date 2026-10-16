import React, { useState } from 'react'
import type { DetectionRule } from '../types/siem'
import { Search, Clock, Target } from 'lucide-react'

interface RulesViewProps {
  rules: DetectionRule[]
}

export const RulesView: React.FC<RulesViewProps> = ({ rules }) => {
  const [search, setSearch] = useState('')

  const filtered = rules.filter(
    (r) =>
      r.name.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      (r.mitre_attack && r.mitre_attack.toLowerCase().includes(search.toLowerCase())) ||
      r.description.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 pb-4 light:border-slate-200">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white light:text-slate-900">
            Active Detection Rules Catalog
          </h1>
          <p className="text-xs text-slate-400">
            Production YAML rules loaded for stream correlation and threat detection
          </p>
        </div>

        <div className="relative min-w-[220px]">
          <Search className="absolute left-3 top-2.5 size-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search rules, MITRE..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-[#11131a] pl-9 pr-3 py-1.5 text-xs text-white outline-none placeholder:text-slate-500 focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {filtered.length === 0 ? (
          <div className="col-span-2 py-8 text-center text-xs text-slate-500">
            No detection rules match criteria
          </div>
        ) : (
          filtered.map((rule) => (
            <div
              key={rule.id}
              className="flex flex-col justify-between rounded-xl border border-white/10 bg-[#11131a] p-4.5 transition hover:border-white/20 light:bg-slate-50 light:border-slate-200"
            >
              <div>
                <div className="flex items-start justify-between gap-3 mb-2">
                  <h3 className="font-semibold text-sm text-white light:text-slate-900 leading-snug">
                    {rule.name}
                  </h3>
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider border shrink-0 ${
                      rule.severity === 'critical'
                        ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                        : rule.severity === 'high'
                        ? 'border-orange-500/30 bg-orange-500/10 text-orange-400'
                        : rule.severity === 'medium'
                        ? 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400'
                        : 'border-sky-500/30 bg-sky-500/10 text-sky-400'
                    }`}
                  >
                    {rule.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed mb-4">
                  {rule.description}
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-2 border-t border-white/5 pt-3 text-[11px] text-slate-400 light:border-slate-200">
                <div className="flex items-center gap-3">
                  {rule.mitre_attack && (
                    <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 font-mono text-[10px] text-purple-300">
                      MITRE: {rule.mitre_attack}
                    </span>
                  )}
                  {rule.window_seconds && (
                    <span className="flex items-center gap-1 font-mono">
                      <Clock className="size-3 text-slate-500" />
                      <span>{rule.window_seconds}s window</span>
                    </span>
                  )}
                  {rule.threshold && (
                    <span className="flex items-center gap-1 font-mono">
                      <Target className="size-3 text-slate-500" />
                      <span>≥{rule.threshold} hits</span>
                    </span>
                  )}
                </div>

                <span className="font-mono text-[10px] text-slate-500">ID: {rule.id}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
