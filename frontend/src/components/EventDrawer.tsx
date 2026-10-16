import React, { useState } from 'react'
import type { SiemEvent } from '../types/siem'
import { X, Copy, Check } from 'lucide-react'

interface EventDrawerProps {
  event: SiemEvent | null
  onClose: () => void
  onFilterIp: (ip: string) => void
}

export const EventDrawer: React.FC<EventDrawerProps> = ({
  event,
  onClose,
  onFilterIp,
}) => {
  const [copied, setCopied] = useState(false)

  if (!event) return null

  const handleCopy = () => {
    if (event.raw_message) {
      navigator.clipboard.writeText(event.raw_message)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="flex h-full w-full max-w-lg flex-col border-l border-white/10 bg-[#0c0e14] shadow-2xl animate-in slide-in-from-right duration-250 light:bg-white light:border-slate-200">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 p-5 light:border-slate-200">
          <div className="flex items-center gap-2.5">
            <span
              className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider border ${
                event.outcome === 'success'
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400'
                  : 'border-rose-500/30 bg-rose-500/10 text-rose-400'
              }`}
            >
              {event.outcome}
            </span>
            <h2 className="text-base font-bold text-white light:text-slate-900">
              Event Detail
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
          <div className="rounded-xl border border-white/10 bg-[#151821] p-4 space-y-3 light:bg-slate-50 light:border-slate-200">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Normalized Attributes
            </h3>

            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Timestamp (UTC):</span>
                <span className="font-mono text-white light:text-slate-900 font-medium">{event.timestamp}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Target Username:</span>
                <span className="font-mono text-white light:text-slate-900 font-medium">
                  {event.username || '-'}
                  {event.invalid_user && (
                    <span className="ml-1.5 text-[10px] text-rose-400 font-semibold">[INVALID]</span>
                  )}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Source IP:</span>
                <span className="font-mono text-sky-400 font-medium">{event.src_ip || '-'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Source Port:</span>
                <span className="font-mono text-slate-300 light:text-slate-700">{event.src_port || '-'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Host:</span>
                <span className="text-white light:text-slate-900">{event.host || '-'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-white/5 light:border-slate-200">
                <span className="text-slate-400">Service Daemon:</span>
                <span className="text-white light:text-slate-900">{event.program || '-'} (PID {event.pid || '-'})</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Auth Method:</span>
                <span className="text-white light:text-slate-900 capitalize">{event.method || '-'}</span>
              </div>
            </div>
          </div>

          {/* Raw Log Box */}
          <div className="rounded-xl border border-white/10 bg-[#151821] p-4 space-y-2 light:bg-slate-50 light:border-slate-200">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Verbatim Raw Message
            </h3>
            <pre className="rounded-lg border border-white/10 bg-[#06070a] p-3 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed light:bg-slate-100 light:border-slate-200 light:text-slate-800">
              {event.raw_message || 'No raw message string available'}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t border-white/10 bg-[#151821] p-4 flex items-center justify-between gap-3 light:bg-slate-50 light:border-slate-200">
          {event.src_ip ? (
            <button
              onClick={() => onFilterIp(event.src_ip!)}
              className="rounded-lg border border-white/10 bg-[#0c0e14] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 transition light:border-slate-200 light:bg-white light:text-slate-700"
            >
              Filter Events by This IP
            </button>
          ) : <div></div>}

          <button
            onClick={handleCopy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-[#0c0e14] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 transition light:border-slate-200 light:bg-white light:text-slate-700"
          >
            {copied ? <Check className="size-3.5 text-emerald-400" /> : <Copy className="size-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Raw Log'}</span>
          </button>
        </div>
      </div>
    </div>
  )
}
