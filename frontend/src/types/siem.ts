export interface SiemEvent {
  id?: number
  timestamp: string
  received_at?: string
  host?: string
  program?: string
  pid?: number
  username?: string
  src_ip?: string
  src_port?: number
  method?: string
  activity?: string
  outcome: 'success' | 'failure'
  invalid_user?: boolean
  raw_message?: string
}

export interface SiemAlert {
  id: number
  rule_id: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  mitre_tag?: string
  mitre_attack?: string
  status: 'new' | 'acknowledged' | 'closed'
  event_count: number
  first_seen?: string
  last_seen: string
  details?: Record<string, any>
}

export interface DetectionRule {
  id: string
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  mitre_attack?: string
  type?: string
  window_seconds?: number
  threshold?: number
  group_by?: string[]
}

export interface IngestResponse {
  events_parsed: number
  events_stored: number
  alerts_triggered: number
  alerts?: SiemAlert[]
}
