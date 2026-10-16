import { useState, useEffect, useCallback } from 'react'
import { Navbar, type TabType } from './components/Navbar'
import { DashboardView } from './components/DashboardView'
import { AlertsView } from './components/AlertsView'
import { EventsView } from './components/EventsView'
import { IngestLabView } from './components/IngestLabView'
import { RulesView } from './components/RulesView'
import { AlertDrawer } from './components/AlertDrawer'
import { EventDrawer } from './components/EventDrawer'
import { LoginModal } from './components/LoginModal'
import { ToastContainer, type ToastMessage } from './components/Toast'
import {
  getToken,
  getStoredUser,
  setSession,
  clearSession,
  login,
  fetchAlerts,
  fetchEvents,
  fetchRules,
  updateAlertStatus,
} from './lib/api'
import {
  generateUnifiedMockDataset,
  generateMockEvents,
  defaultMockRules,
  type TelemetryDataset,
} from './lib/telemetry'
import type { SiemAlert, SiemEvent, DetectionRule } from './types/siem'

export function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('pysiem_theme') as 'dark' | 'light') || 'dark'
  })
  const [activeTab, setActiveTab] = useState<TabType>('dashboard')
  const [token, setToken] = useState<string>(getToken())
  const [username, setUsername] = useState<string>(getStoredUser())
  const [isLoginOpen, setIsLoginOpen] = useState<boolean>(!getToken())

  // Telemetry state
  const [isLiveMode, setIsLiveMode] = useState(false)
  const [telemetry, setTelemetry] = useState<TelemetryDataset>(() => generateUnifiedMockDataset())

  // Data states
  const [alerts, setAlerts] = useState<SiemAlert[]>(() => telemetry.priorityAlerts)
  const [alertStatusFilter, setAlertStatusFilter] = useState('')
  const [alertSevFilter, setAlertSevFilter] = useState('')

  const [events, setEvents] = useState<SiemEvent[]>(() => generateMockEvents())
  const [totalEvents, setTotalEvents] = useState(5)
  const [eventsPage, setEventsPage] = useState(0)
  const eventsLimit = 25
  const [eventSearch, setEventSearch] = useState('')
  const [eventIp, setEventIp] = useState('')
  const [eventUser, setEventUser] = useState('')
  const [eventOutcome, setEventOutcome] = useState('')
  const [eventTimerange, setEventTimerange] = useState('all')

  const [rules, setRules] = useState<DetectionRule[]>(() => defaultMockRules)

  // Drawer states
  const [selectedAlert, setSelectedAlert] = useState<SiemAlert | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<SiemEvent | null>(null)

  // Toasts
  const [toasts, setToasts] = useState<ToastMessage[]>([])

  const showToast = useCallback((message: string, type: ToastMessage['type'] = 'info') => {
    const id = Math.random().toString(36).slice(2)
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, 3500)
  }, [])

  // Sync theme class
  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.classList.add('light')
    } else {
      document.documentElement.classList.remove('light')
    }
    localStorage.setItem('pysiem_theme', theme)
  }, [theme])

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'))
  }

  // Load Data
  const loadAlertsData = useCallback(async () => {
    try {
      const data = await fetchAlerts({
        status: alertStatusFilter,
        severity: alertSevFilter,
      })
      setAlerts(data.alerts)
    } catch {
      // Fallback to telemetry alerts if demo mode
      if (!isLiveMode) {
        setAlerts(telemetry.priorityAlerts)
      }
    }
  }, [alertStatusFilter, alertSevFilter, isLiveMode, telemetry.priorityAlerts])

  const loadEventsData = useCallback(async () => {
    try {
      const data = await fetchEvents({
        limit: eventsLimit,
        offset: eventsPage * eventsLimit,
        search: eventSearch,
        src_ip: eventIp,
        username: eventUser,
        outcome: eventOutcome,
      })
      setEvents(data.events)
      setTotalEvents(data.total)
    } catch {
      // In demo mode or offline, provide mock events
      if (events.length === 0) {
        const mock = generateMockEvents()
        setEvents(mock)
        setTotalEvents(mock.length)
      }
    }
  }, [eventsPage, eventSearch, eventIp, eventUser, eventOutcome, events.length])

  const loadRulesData = useCallback(async () => {
    try {
      const data = await fetchRules()
      setRules(data.rules)
    } catch {
      // In demo mode or offline, provide mock rules
      setRules((prev) => (prev.length > 0 ? prev : defaultMockRules))
    }
  }, [])

  const refreshAll = useCallback(async () => {
    if (isLiveMode) {
      try {
        const [alertsData, eventsData] = await Promise.all([
          fetchAlerts(),
          fetchEvents({ limit: 1000 }),
        ])
        const evs = eventsData.events
        const succ = evs.filter((e) => e.outcome === 'success').length
        const fail = evs.filter((e) => e.outcome === 'failure').length

        // Top attacking IPs from actual events
        const ipCounts: Record<string, number> = {}
        const userCounts: Record<string, number> = {}
        evs.forEach((e) => {
          if (e.src_ip) ipCounts[e.src_ip] = (ipCounts[e.src_ip] || 0) + 1
          if (e.username) userCounts[e.username] = (userCounts[e.username] || 0) + 1
        })

        const topIps = Object.entries(ipCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([ip, count]) => ({ ip, count, role: 'Active Source' }))

        const topUsers = Object.entries(userCounts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([username, count]) => ({ username, count, role: 'Target Account' }))

        const crits = alertsData.alerts.filter((a) => a.severity === 'critical').length
        const highs = alertsData.alerts.filter((a) => a.severity === 'high').length
        const meds = alertsData.alerts.filter((a) => a.severity === 'medium').length
        const lows = alertsData.alerts.filter((a) => a.severity === 'low').length

        setTelemetry((prev) => ({
          ...prev,
          totalEvents: eventsData.total,
          successfulLogins: succ,
          failedLogins: fail,
          otherEvents: Math.max(0, eventsData.total - succ - fail),
          totalAlerts: alertsData.total,
          openAlerts: alertsData.alerts.filter((a) => a.status === 'new').length,
          critHighAlerts: crits + highs,
          severityCounts: { critical: crits, high: highs, medium: meds, low: lows },
          topIps: topIps.length > 0 ? topIps : prev.topIps,
          topUsers: topUsers.length > 0 ? topUsers : prev.topUsers,
          priorityAlerts: alertsData.alerts.slice(0, 5),
        }))
      } catch {
        showToast('Failed to sync live telemetry from database', 'error')
      }
    } else {
      setTelemetry(generateUnifiedMockDataset())
    }

    loadAlertsData()
    loadEventsData()
    loadRulesData()
    showToast('Telemetry refreshed', 'info')
  }, [isLiveMode, loadAlertsData, loadEventsData, loadRulesData, showToast])

  useEffect(() => {
    if (token) {
      loadAlertsData()
      loadEventsData()
      loadRulesData()
    }
  }, [token, loadAlertsData, loadEventsData, loadRulesData])

  // Auth Handlers
  const handleLogin = async (user: string, pass: string) => {
    const data = await login(user, pass)
    setSession(data.access_token, data.username)
    setToken(data.access_token)
    setUsername(data.username)
    setIsLoginOpen(false)
    showToast(`Authenticated as ${data.username}`, 'success')
  }

  const handleLogout = () => {
    clearSession()
    setToken('')
    setUsername('')
    setIsLoginOpen(true)
    showToast('Signed out of console', 'info')
  }

  // Investigation filters
  const handleFilterIpInEvents = (ip: string) => {
    setEventIp(ip)
    setEventsPage(0)
    setActiveTab('events')
    setSelectedAlert(null)
    setSelectedEvent(null)
  }

  const handleFilterUserInEvents = (user: string) => {
    setEventUser(user)
    setEventsPage(0)
    setActiveTab('events')
    setSelectedAlert(null)
    setSelectedEvent(null)
  }

  // Alert Status Update
  const handleUpdateAlertStatus = async (alertId: number, newStatus: 'new' | 'acknowledged' | 'closed') => {
    try {
      await updateAlertStatus(alertId, newStatus)
      showToast(`Alert #${alertId} status set to ${newStatus}`, 'success')
      loadAlertsData()
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : null))
      }
    } catch {
      // Local optimistic update for mock alerts
      setSelectedAlert((prev) => (prev ? { ...prev, status: newStatus } : null))
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
      )
      showToast(`Updated alert status to ${newStatus}`, 'info')
    }
  }

  return (
    <div className="min-h-screen bg-[#09090b] text-white flex flex-col font-sans light:bg-slate-50 light:text-slate-900">
      <Navbar
        activeTab={activeTab}
        onTabChange={setActiveTab}
        username={username}
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogout={handleLogout}
        onOpenLogin={() => setIsLoginOpen(true)}
      />

      <main className="mx-auto w-full max-w-7xl flex-1 px-6 py-6">
        {activeTab === 'dashboard' && (
          <DashboardView
            telemetry={telemetry}
            isLiveMode={isLiveMode}
            onToggleLiveMode={(live) => {
              setIsLiveMode(live)
              showToast(`Switched to ${live ? 'Live Database' : 'Demo Telemetry'}`, 'info')
            }}
            onRefresh={refreshAll}
            onOpenAlert={setSelectedAlert}
            onNavigateTab={setActiveTab}
            onFilterIpInEvents={handleFilterIpInEvents}
            onFilterUserInEvents={handleFilterUserInEvents}
          />
        )}

        {activeTab === 'alerts' && (
          <AlertsView
            alerts={alerts.length > 0 ? alerts : telemetry.priorityAlerts}
            statusFilter={alertStatusFilter}
            onStatusFilterChange={setAlertStatusFilter}
            severityFilter={alertSevFilter}
            onSeverityFilterChange={setAlertSevFilter}
            onRefresh={loadAlertsData}
            onOpenAlert={setSelectedAlert}
          />
        )}

        {activeTab === 'events' && (
          <EventsView
            events={events}
            totalEvents={totalEvents}
            page={eventsPage}
            limit={eventsLimit}
            onPageChange={setEventsPage}
            search={eventSearch}
            onSearchChange={setEventSearch}
            srcIp={eventIp}
            onSrcIpChange={setEventIp}
            username={eventUser}
            onUsernameChange={setEventUser}
            outcome={eventOutcome}
            onOutcomeChange={setEventOutcome}
            timerange={eventTimerange}
            onTimerangeChange={setEventTimerange}
            onApplyFilters={loadEventsData}
            onClearFilters={() => {
              setEventSearch('')
              setEventIp('')
              setEventUser('')
              setEventOutcome('')
              setEventTimerange('all')
              setEventsPage(0)
            }}
            onOpenEvent={setSelectedEvent}
          />
        )}

        {activeTab === 'ingest' && (
          <IngestLabView
            onIngestSuccess={() => {
              showToast('Logs parsed and evaluated by detection rules', 'success')
              refreshAll()
            }}
          />
        )}

        {activeTab === 'rules' && <RulesView rules={rules} />}
      </main>

      {/* Drawers */}
      <AlertDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onUpdateStatus={handleUpdateAlertStatus}
        onInvestigateIp={handleFilterIpInEvents}
      />

      <EventDrawer
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onFilterIp={handleFilterIpInEvents}
      />

      {/* Login Dialog */}
      <LoginModal
        isOpen={isLoginOpen}
        onLogin={handleLogin}
        onContinueDemo={() => {
          setIsLoginOpen(false)
          showToast('Browsing console in demo mode (Guest)', 'info')
        }}
      />

      {/* Toast notifications */}
      <ToastContainer
        toasts={toasts}
        onDismiss={(id) => setToasts((prev) => prev.filter((t) => t.id !== id))}
      />
    </div>
  )
}

export default App
