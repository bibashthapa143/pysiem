import React, { useState } from 'react'
import type { IngestResponse } from '../types/siem'
import { ingestLogs } from '../lib/api'
import { Play, Key, CheckCircle, AlertOctagon, ShieldCheck } from 'lucide-react'

const SAMPLES = {
  hydra: [
    'Oct  9 10:15:02 metasploitable sshd[6200]: Failed password for root from 10.0.2.4 port 40001 ssh2',
    'Oct  9 10:15:05 metasploitable sshd[6202]: Failed password for root from 10.0.2.4 port 40003 ssh2',
    'Oct  9 10:15:08 metasploitable sshd[6204]: Failed password for root from 10.0.2.4 port 40005 ssh2',
    'Oct  9 10:15:11 metasploitable sshd[6206]: Failed password for root from 10.0.2.4 port 40007 ssh2',
    'Oct  9 10:15:14 metasploitable sshd[6208]: Failed password for root from 10.0.2.4 port 40009 ssh2',
    'Oct  9 10:15:17 metasploitable sshd[6210]: Failed password for root from 10.0.2.4 port 40011 ssh2',
  ].join('\n'),

  spray: [
    'Oct  9 11:05:00 metasploitable sshd[6300]: Failed password for admin from 10.0.2.5 port 41001 ssh2',
    'Oct  9 11:05:04 metasploitable sshd[6302]: Failed password for deploy from 10.0.2.5 port 41003 ssh2',
    'Oct  9 11:05:08 metasploitable sshd[6304]: Failed password for ubuntu from 10.0.2.5 port 41005 ssh2',
    'Oct  9 11:05:12 metasploitable sshd[6306]: Failed password for postgres from 10.0.2.5 port 41007 ssh2',
  ].join('\n'),

  invalid: [
    'Oct  9 12:30:01 metasploitable sshd[6400]: Failed password for invalid user admin from 192.168.56.20 port 42001 ssh2',
    'Oct  9 12:30:05 metasploitable sshd[6402]: Failed password for invalid user test from 192.168.56.20 port 42003 ssh2',
    'Oct  9 12:30:09 metasploitable sshd[6404]: Failed password for invalid user oracle from 192.168.56.20 port 42005 ssh2',
    'Oct  9 12:30:13 metasploitable sshd[6406]: Failed password for invalid user guest from 192.168.56.20 port 42007 ssh2',
  ].join('\n'),

  breach: [
    'Oct  9 13:45:10 metasploitable sshd[6500]: Failed password for root from 192.168.56.30 port 43001 ssh2',
    'Oct  9 13:45:18 metasploitable sshd[6502]: Failed password for root from 192.168.56.30 port 43003 ssh2',
    'Oct  9 13:45:27 metasploitable sshd[6504]: Failed password for root from 192.168.56.30 port 43005 ssh2',
    'Oct  9 13:45:41 metasploitable sshd[6506]: Accepted password for root from 192.168.56.30 port 43007 ssh2',
  ].join('\n'),

  legit: [
    'Oct  9 09:02:11 metasploitable sshd[6101]: Accepted publickey for msfadmin from 192.168.56.10 port 51022 ssh2',
    'Oct  9 09:40:55 metasploitable sshd[6103]: Received disconnect from 192.168.56.10: 11: disconnected by user',
  ].join('\n'),
}

interface IngestLabViewProps {
  onIngestSuccess: () => void
}

export const IngestLabView: React.FC<IngestLabViewProps> = ({ onIngestSuccess }) => {
  const [apiKey, setApiKey] = useState('pysiem-ingest-secret-key-12345')
  const [logText, setLogText] = useState(SAMPLES.hydra)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<IngestResponse | null>(null)
  const [error, setError] = useState('')

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault()
    const lines = logText.split('\n').map((l) => l.trim()).filter(Boolean)
    if (lines.length === 0) return

    setLoading(true)
    setError('')
    try {
      const data = await ingestLogs(lines, apiKey)
      setResult(data)
      onIngestSuccess()
    } catch (err: any) {
      setError(err.message || 'Ingestion request failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="rounded-xl border border-white/10 bg-[#0c0e14] p-5 shadow-sm light:bg-white light:border-slate-200">
      <div className="mb-4 border-b border-white/10 pb-4 light:border-slate-200">
        <h1 className="text-xl font-bold tracking-tight text-white light:text-slate-900">
          HTTP Log Ingestion &amp; Attack Simulator
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Send raw SSH syslog lines into PySIEM (<code className="font-mono text-sky-400">POST /api/v1/ingest</code>).
          The correlation engine parses, normalizes to ISO 8601 UTC schema, evaluates detection rules, and triggers real-time alerts.
        </p>
      </div>

      {/* Preset simulation buttons */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider mr-1">
          Attack Presets:
        </span>
        <button
          type="button"
          onClick={() => setLogText(SAMPLES.hydra)}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Hydra Brute Force (6x)
        </button>
        <button
          type="button"
          onClick={() => setLogText(SAMPLES.spray)}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Password Spraying (Multi-User)
        </button>
        <button
          type="button"
          onClick={() => setLogText(SAMPLES.invalid)}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Invalid User Guessing
        </button>
        <button
          type="button"
          onClick={() => setLogText(SAMPLES.breach)}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Failure Then Success (Breach)
        </button>
        <button
          type="button"
          onClick={() => setLogText(SAMPLES.legit)}
          className="rounded-lg border border-white/10 bg-[#151821] px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white hover:bg-white/10 light:border-slate-200 light:bg-slate-100 light:text-slate-700"
        >
          Clean Baseline Session
        </button>
      </div>

      <form onSubmit={handleIngest} className="space-y-4">
        <div>
          <label className="mb-1.5 flex items-center gap-2 text-xs font-semibold text-slate-400">
            <Key className="size-3.5" />
            <span>Ingestion API Key (X-API-Key header):</span>
          </label>
          <input
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="w-full max-w-md rounded-lg border border-white/10 bg-[#11131a] px-3.5 py-1.5 font-mono text-xs text-white outline-none focus:border-sky-500 light:bg-white light:border-slate-300 light:text-slate-900"
          />
        </div>

        <div>
          <label className="mb-1.5 block text-xs font-semibold text-slate-400">
            Raw Syslog Lines (one event per line):
          </label>
          <textarea
            rows={7}
            value={logText}
            onChange={(e) => setLogText(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-[#11131a] p-3 font-mono text-xs text-white outline-none focus:border-sky-500 resize-y light:bg-white light:border-slate-300 light:text-slate-900"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg bg-white px-4 py-2 text-xs font-semibold text-black transition hover:bg-slate-200 disabled:opacity-50 light:bg-slate-900 light:text-white"
        >
          <Play className="size-3.5" />
          <span>{loading ? 'Processing telemetry...' : 'Ingest & Run Detection Engine'}</span>
        </button>
      </form>

      {/* Error notification */}
      {error && (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-400">
          {error}
        </div>
      )}

      {/* Ingestion results */}
      {result && (
        <div className="mt-6 border-t border-white/10 pt-4 light:border-slate-200">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
            Ingestion Results Summary
          </h3>
          <div className="flex flex-wrap gap-3 mb-3">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-sky-500/30 bg-sky-500/10 px-3 py-1 font-mono text-xs font-medium text-sky-400">
              <ShieldCheck className="size-3.5" />
              <span>Events Parsed: {result.events_parsed}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 font-mono text-xs font-medium text-emerald-400">
              <CheckCircle className="size-3.5" />
              <span>Events Stored: {result.events_stored}</span>
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-500/10 px-3 py-1 font-mono text-xs font-medium text-rose-400">
              <AlertOctagon className="size-3.5" />
              <span>Alerts Triggered: {result.alerts_triggered}</span>
            </span>
          </div>

          <details className="mt-3 text-xs text-slate-400 cursor-pointer">
            <summary className="hover:text-white transition">View Full Raw JSON Response</summary>
            <pre className="mt-2 rounded-lg border border-white/10 bg-[#06070a] p-3 font-mono text-[11px] text-slate-300 overflow-x-auto light:bg-slate-50 light:border-slate-200 light:text-slate-800">
              {JSON.stringify(result, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}
