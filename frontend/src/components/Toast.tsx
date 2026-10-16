import React from 'react'
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from 'lucide-react'

export interface ToastMessage {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  message: string
}

interface ToastContainerProps {
  toasts: ToastMessage[]
  onDismiss: (id: string) => void
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  return (
    <div className="fixed bottom-5 right-5 z-50 flex flex-col gap-2.5 pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto flex items-center justify-between gap-3 min-w-[280px] max-w-sm rounded-xl border p-3.5 shadow-lg backdrop-blur-md animate-in slide-in-from-bottom-2 duration-200 ${
            t.type === 'success'
              ? 'border-emerald-500/30 bg-[#0c0e14]/95 text-emerald-300 border-l-4 border-l-emerald-500 light:bg-white light:text-emerald-900'
              : t.type === 'error'
              ? 'border-rose-500/30 bg-[#0c0e14]/95 text-rose-300 border-l-4 border-l-rose-500 light:bg-white light:text-rose-900'
              : t.type === 'warning'
              ? 'border-amber-500/30 bg-[#0c0e14]/95 text-amber-300 border-l-4 border-l-amber-500 light:bg-white light:text-amber-900'
              : 'border-sky-500/30 bg-[#0c0e14]/95 text-sky-300 border-l-4 border-l-sky-500 light:bg-white light:text-sky-900'
          }`}
        >
          <div className="flex items-center gap-2.5 text-xs font-medium">
            {t.type === 'success' && <CheckCircle2 className="size-4 shrink-0 text-emerald-400" />}
            {t.type === 'error' && <AlertCircle className="size-4 shrink-0 text-rose-400" />}
            {t.type === 'warning' && <AlertTriangle className="size-4 shrink-0 text-amber-400" />}
            {t.type === 'info' && <Info className="size-4 shrink-0 text-sky-400" />}
            <span>{t.message}</span>
          </div>

          <button
            onClick={() => onDismiss(t.id)}
            className="text-slate-400 hover:text-white transition light:hover:text-slate-900"
          >
            <X className="size-3.5" />
          </button>
        </div>
      ))}
    </div>
  )
}
