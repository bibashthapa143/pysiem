/**
 * PySIEM Frontend Application Logic
 * Professional SOC Operations Console
 * Implements strict HTML escaping on all dynamic data to prevent XSS.
 */

// XSS Prevention: Safely escape any string before DOM injection
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

const state = {
  token: localStorage.getItem("pysiem_token") || "",
  username: localStorage.getItem("pysiem_username") || "",
  activeTab: "dashboard",
  eventsPage: 0,
  eventsLimit: 25,
  alertsPage: 0,
  alertsLimit: 25,
  loadedRules: [],
};

// Headers with Bearer token
function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${state.token}`
  };
}

// Check authentication
function checkAuth() {
  const loginModal = document.getElementById("login-modal");
  const userDisplay = document.getElementById("nav-username");
  const logoutBtn = document.getElementById("btn-logout");

  if (!state.token) {
    if (loginModal) loginModal.style.display = "flex";
    if (userDisplay) userDisplay.textContent = "unauthenticated";
    if (logoutBtn) logoutBtn.style.display = "none";
  } else {
    if (loginModal) loginModal.style.display = "none";
    if (userDisplay) userDisplay.textContent = state.username || "admin";
    if (logoutBtn) logoutBtn.style.display = "inline-flex";
    loadCurrentTab();
  }
}

// Switch navigation tabs
function switchTab(tabName) {
  state.activeTab = tabName;
  document.querySelectorAll(".nav-tab").forEach(tab => {
    tab.classList.toggle("active", tab.dataset.tab === tabName);
  });
  document.querySelectorAll(".page-section").forEach(sec => {
    sec.classList.toggle("active", sec.id === `section-${tabName}`);
  });
  loadCurrentTab();
}

function loadCurrentTab() {
  if (!state.token) return;
  if (state.activeTab === "dashboard") loadDashboard();
  else if (state.activeTab === "alerts") loadAlerts();
  else if (state.activeTab === "events") loadEvents();
  else if (state.activeTab === "rules") loadRules();
}

// -------------------------------------------------------------
// Login & Session Management
// -------------------------------------------------------------
async function handleLogin(e) {
  e.preventDefault();
  const user = document.getElementById("login-username").value.trim();
  const pass = document.getElementById("login-password").value;
  const errBox = document.getElementById("login-error");
  if (errBox) errBox.style.display = "none";

  try {
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: user, password: pass })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Authentication failed");
    }
    const data = await res.json();
    state.token = data.access_token;
    state.username = data.username;
    localStorage.setItem("pysiem_token", state.token);
    localStorage.setItem("pysiem_username", state.username);
    checkAuth();
    showToast(`Authenticated as ${state.username}`, "success");
  } catch (err) {
    if (errBox) {
      errBox.textContent = err.message;
      errBox.style.display = "block";
    }
  }
}

function handleLogout() {
  state.token = "";
  state.username = "";
  localStorage.removeItem("pysiem_token");
  localStorage.removeItem("pysiem_username");
  checkAuth();
  showToast("Logged out of PySIEM console", "info");
}

// -------------------------------------------------------------
// Toast Notification System
// -------------------------------------------------------------
function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(8px)";
    setTimeout(() => toast.remove(), 250);
  }, 3200);
}

// -------------------------------------------------------------
// MITRE ATT&CK Helper
// -------------------------------------------------------------
function getMitreUrl(tag) {
  if (!tag) return null;
  const clean = String(tag).trim();
  const match = clean.match(/^T(\d+)(?:\.(\d+))?$/i);
  if (!match) return null;
  const tech = `T${match[1]}`;
  const sub = match[2];
  return sub ? `https://attack.mitre.org/techniques/${tech}/${sub}/` : `https://attack.mitre.org/techniques/${tech}/`;
}

// -------------------------------------------------------------
// -------------------------------------------------------------
// Unified SOC Telemetry Ground Truth Dataset (60-Minute Window)
// -------------------------------------------------------------
function generateUnifiedMockDataset(refTimeMs = Date.now()) {
  // Deterministic baseline distribution across 60 minutes
  // Calibrated to small enterprise perimeter SOC environment
  const succBase = [
    15, 17, 15, 18, 14, 18, 16, 17, 15, 18,
    15, 17, 14, 18, 15, 18, 17, 16, 18, 15,
    16, 16, 18, 15, 17, 15, 15, 17, 18, 16,
    14, 17, 16, 18, 17, 15, 15, 18, 16, 17,
    14, 18, 16, 17, 15, 17, 17, 16, 15, 18,
    16, 17, 15, 18, 16, 17, 15, 18, 16, 17
  ]; // Sum = 980

  const failBase = [
    1, 1, 1, 2, 1, 2, 1, 2, 1, 1, // 0-9
    1, 2, 1, 3, 1, 2, 1, 2, 1, 2, // 10-19
    1, 2, 1, 3, 1,                // 20-24: normal baseline (1-3)
    14, 32, 58, 76, 48, 28, 16, 8, 4, // 25-33: Anomaly 1 - SSH Brute-Force velocity spike (peak 76)
    2, 1, 2, 1, 3, 1, 2, 1, 2, 1, 2, 1, // 34-45: return to baseline
    10, 24, 22, 8,                // 46-49: Anomaly 2 - Credential spray burst (peak 24)
    2, 1, 2, 1, 3, 1, 2, 1, 2, 1  // 50-59: post-incident stabilization / fail2ban active
  ]; // Sum = 420

  const otherBase = [
    8, 9, 6, 10, 8, 9, 10, 7, 9, 7,
    10, 8, 8, 7, 10, 8, 9, 7, 10, 7,
    9, 8, 9, 8, 9, 10, 11, 12, 14, 11,
    10, 9, 7, 9, 8, 10, 8, 8, 7, 10,
    8, 9, 7, 10, 7, 9, 11, 11, 10, 8,
    9, 8, 7, 9, 8, 7, 8, 7, 7, 6
  ]; // Sum = 520

  const buckets = [];
  let sumTotal = 0;
  let sumSuccess = 0;
  let sumFailure = 0;
  let sumOther = 0;

  // Align to current minute boundary for consistent, non-drifting time ticks
  const baseTime = Math.floor(refTimeMs / 60000) * 60000;

  for (let i = 0; i < 60; i++) {
    const minuteOffset = 59 - i;
    const timeMs = baseTime - minuteOffset * 60000;
    const dateObj = new Date(timeMs);
    const timeLabel = `${String(dateObj.getHours()).padStart(2, '0')}:${String(dateObj.getMinutes()).padStart(2, '0')}`;
    const fullIso = dateObj.toISOString();

    const succ = succBase[i];
    const fail = failBase[i];
    const other = otherBase[i];
    const total = succ + fail + other;

    sumTotal += total;
    sumSuccess += succ;
    sumFailure += fail;
    sumOther += other;

    const isSpike = fail >= 14;
    const isCompromise = i === 49;
    const anomalyTag = (i >= 25 && i <= 33)
      ? "Brute-Force Velocity Spike"
      : (i >= 46 && i <= 49 ? "Credential Spray Burst" : null);

    buckets.push({
      minuteIndex: i,
      minuteOffset,
      timeMs,
      timeLabel,
      fullIso,
      total,
      successes: succ,
      failures: fail,
      other,
      isSpike,
      isCompromise,
      anomalyTag
    });
  }

  // Correlated Alert Severity Breakdown (sums exactly to 14 alerts)
  const severityCounts = {
    critical: 2,
    high: 4,
    medium: 5,
    low: 3
  };
  const totalAlerts = 14;
  const openAlerts = 9;

  // Correlated Top Attacking Source IPs (all RFC 1918 / RFC 5737 compliant)
  // Sum of failure attempts strictly matches total failures: 245 + 88 + 46 + 26 + 15 = 420
  const topIps = [
    { ip: "192.168.1.105", count: 245, role: "Primary Brute-Force Actor" },
    { ip: "10.0.4.15", count: 88, role: "Internal Credential Spray" },
    { ip: "172.16.20.88", count: 46, role: "DMZ Service Probes" },
    { ip: "198.51.100.42", count: 26, role: "External Scanner" },
    { ip: "203.0.113.19", count: 15, role: "Dictionary Probe" }
  ];

  // Correlated Top Targeted Accounts
  // Sum of target attempts strictly matches total failures: 215 + 105 + 52 + 32 + 16 = 420
  const topUsers = [
    { username: "root", count: 215, role: "Privileged Superuser" },
    { username: "admin", count: 105, role: "Administrative Console" },
    { username: "deploy", count: 52, role: "CI/CD Service Account" },
    { username: "ubuntu", count: 32, role: "Default Cloud User" },
    { username: "postgres", count: 16, role: "Database Admin" }
  ];

  // Correlated Priority Incidents Queue (matching Critical and High alerts: 2 + 4 = 6)
  // All incident event counts strictly reflect threat intelligence metrics
  const priorityAlerts = [
    {
      id: 101,
      severity: "critical",
      title: "SSH Brute Force Velocity Exceeded",
      description: "High-rate authentication failure burst detected from 192.168.1.105 targeting root and admin.",
      mitre_tag: "T1110.001",
      status: "new",
      event_count: 245,
      rule_id: "ssh_brute_force",
      last_seen: new Date(baseTime - 28 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "192.168.1.105", username: "root" }
    },
    {
      id: 102,
      severity: "critical",
      title: "Privileged Root Credential Access Post-Spray",
      description: "Successful authorization on root account from 10.0.4.15 following password spray burst.",
      mitre_tag: "T1078",
      status: "new",
      event_count: 88,
      rule_id: "ssh_failure_then_success",
      last_seen: new Date(baseTime - 11 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "10.0.4.15", username: "root" }
    },
    {
      id: 103,
      severity: "high",
      title: "SSH Password Spraying Across Multiple Accounts",
      description: "Authentication failures targeting distinct service accounts (admin, deploy, ubuntu) from 10.0.4.15.",
      mitre_tag: "T1110.003",
      status: "acknowledged",
      event_count: 88,
      rule_id: "ssh_password_spraying",
      last_seen: new Date(baseTime - 12 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "10.0.4.15", usernames: ["admin", "deploy", "ubuntu"] }
    },
    {
      id: 104,
      severity: "high",
      title: "Repeated Failed Auths on Administrative Accounts",
      description: "Sequential failed attempts targeting 'deploy' account within sliding correlation window.",
      mitre_tag: "T1110.001",
      status: "new",
      event_count: 46,
      rule_id: "ssh_brute_force",
      last_seen: new Date(baseTime - 22 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "172.16.20.88", username: "deploy" }
    },
    {
      id: 105,
      severity: "high",
      title: "External Port Reconnaissance & Auth Probes",
      description: "Multiple unauthorized connection handshakes originating from documentation subnet 198.51.100.42.",
      mitre_tag: "T1595",
      status: "new",
      event_count: 26,
      rule_id: "ssh_invalid_user_guessing",
      last_seen: new Date(baseTime - 35 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "198.51.100.42", username: "root" }
    },
    {
      id: 106,
      severity: "high",
      title: "Automated Dictionary Scanning Sequence",
      description: "Repeated invalid authentication trials from 203.0.113.19 exceeding baseline threshold.",
      mitre_tag: "T1110.001",
      status: "acknowledged",
      event_count: 15,
      rule_id: "ssh_invalid_user_guessing",
      last_seen: new Date(baseTime - 42 * 60000).toISOString().replace("T", " ").replace(/\..+$/, " UTC"),
      details: { src_ip: "203.0.113.19", username: "postgres" }
    }
  ];

  return {
    windowMinutes: 60,
    startTime: new Date(baseTime - 59 * 60000).toISOString(),
    endTime: new Date(baseTime).toISOString(),
    totalEvents: sumTotal,
    totalAlerts,
    openAlerts,
    critHighAlerts: severityCounts.critical + severityCounts.high,
    successfulLogins: sumSuccess,
    failedLogins: sumFailure,
    otherEvents: sumOther,
    buckets,
    severityCounts,
    outcomeCounts: {
      success: sumSuccess,
      failure: sumFailure
    },
    topIps,
    topUsers,
    priorityAlerts
  };
}

// Monotone Cubic Spline (Fritsch-Carlson algorithm) for natural, overshoot-free curves
function generateMonotonePath(points) {
  if (!points || !points.length) return "";
  if (points.length === 1) return `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  if (points.length === 2) {
    return `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)} L ${points[1].x.toFixed(1)} ${points[1].y.toFixed(1)}`;
  }

  const n = points.length;
  const dxs = new Float64Array(n - 1);
  const dys = new Float64Array(n - 1);
  const ms = new Float64Array(n - 1);

  for (let i = 0; i < n - 1; i++) {
    const dx = points[i + 1].x - points[i].x;
    const dy = points[i + 1].y - points[i].y;
    dxs[i] = dx;
    dys[i] = dy;
    ms[i] = dx !== 0 ? dy / dx : 0;
  }

  const tangents = new Float64Array(n);
  tangents[0] = ms[0];
  tangents[n - 1] = ms[n - 2];

  for (let i = 1; i < n - 1; i++) {
    const mPrev = ms[i - 1];
    const mCur = ms[i];
    if (mPrev * mCur <= 0) {
      tangents[i] = 0;
    } else {
      tangents[i] = (mPrev + mCur) / 2;
    }
  }

  for (let i = 0; i < n - 1; i++) {
    const m = ms[i];
    if (m === 0) {
      tangents[i] = 0;
      tangents[i + 1] = 0;
    } else {
      const alpha = tangents[i] / m;
      const beta = tangents[i + 1] / m;
      const dist = alpha * alpha + beta * beta;
      if (dist > 9) {
        const tau = 3 / Math.sqrt(dist);
        tangents[i] = tau * alpha * m;
        tangents[i + 1] = tau * beta * m;
      }
    }
  }

  let path = `M ${points[0].x.toFixed(1)} ${points[0].y.toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const p1 = points[i];
    const p2 = points[i + 1];
    const dx = dxs[i] / 3;

    const cp1x = p1.x + dx;
    const cp1y = p1.y + tangents[i] * dx;
    const cp2x = p2.x - dx;
    const cp2y = p2.y - tangents[i + 1] * dx;

    path += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
  }

  return path;
}

// Backwards-compatibility alias
const generateSmoothPath = generateMonotonePath;

// -------------------------------------------------------------
// Dashboard Overview & Interactive Analytics Visualizations
// -------------------------------------------------------------
async function loadDashboard() {
  const isDemo = state.telemetryMode !== "live";

  // Update Telemetry Mode Badges & Buttons
  const modeBadge = document.getElementById("telemetry-mode-indicator");
  const sourceLabel = document.getElementById("dashboard-source-label");
  const btnDemo = document.getElementById("btn-telemetry-demo");
  const btnLive = document.getElementById("btn-telemetry-live");

  if (isDemo) {
    if (modeBadge) {
      modeBadge.textContent = "⚡ DEMO TELEMETRY (60-MIN)";
      modeBadge.className = "badge badge-low";
    }
    if (sourceLabel) sourceLabel.textContent = "Simulated Enterprise SOC Telemetry (Correlated Anomaly)";
    if (btnDemo) btnDemo.classList.add("active-status");
    if (btnLive) btnLive.classList.remove("active-status");

    // Unified Mock Dataset Source of Truth
    const mock = generateUnifiedMockDataset();

    const evTotal = document.getElementById("stat-total-events");
    if (evTotal) evTotal.textContent = mock.totalEvents.toLocaleString();

    const alTotal = document.getElementById("stat-total-alerts");
    if (alTotal) alTotal.textContent = mock.totalAlerts;

    const opTotal = document.getElementById("stat-open-alerts");
    if (opTotal) opTotal.textContent = mock.openAlerts;

    const critHigh = document.getElementById("stat-high-critical");
    if (critHigh) critHigh.textContent = mock.critHighAlerts;

    const tsElem = document.getElementById("dashboard-last-updated");
    if (tsElem) tsElem.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;

    // 1. Priority Incident Queue
    renderPriorityAlerts(mock.priorityAlerts);

    // 2. 60-Minute Security Events Line Chart
    renderEventsTimelineChart(mock.buckets, true);

    // 3. Alert Severity Donut Chart
    renderSeverityChart(mock.severityCounts, mock.totalAlerts);

    // 4. Authentication Outcomes Bar
    renderOutcomeChart(mock.outcomeCounts);

    // 5. Ranked Top IPs & Top Users
    renderTopList("top-ips-container", mock.topIps, "ip", "failed attempts");
    renderTopList("top-users-container", mock.topUsers, "username", "failed attempts");

  } else {
    // Live Database Telemetry Mode
    if (modeBadge) {
      modeBadge.textContent = "● LIVE DATABASE TELEMETRY";
      modeBadge.className = "badge badge-success";
    }
    if (sourceLabel) sourceLabel.textContent = "Live SQLite Storage Telemetry";
    if (btnDemo) btnDemo.classList.remove("active-status");
    if (btnLive) btnLive.classList.add("active-status");

    try {
      const res = await fetch("/api/v1/stats", { headers: authHeaders() });
      if (res.status === 401) return handleLogout();
      const stats = await res.json();

      const evTotal = document.getElementById("stat-total-events");
      if (evTotal) evTotal.textContent = (stats.total_events || 0).toLocaleString();

      const alTotal = document.getElementById("stat-total-alerts");
      if (alTotal) alTotal.textContent = stats.total_alerts || 0;

      const opTotal = document.getElementById("stat-open-alerts");
      if (opTotal) opTotal.textContent = stats.open_alerts || 0;

      const criticalCount = stats.severity_counts?.critical || 0;
      const highCount = stats.severity_counts?.high || 0;
      const critHigh = document.getElementById("stat-high-critical");
      if (critHigh) critHigh.textContent = criticalCount + highCount;

      const tsElem = document.getElementById("dashboard-last-updated");
      if (tsElem) tsElem.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;

      // 1. Live Priority Queue
      loadLivePriorityAlerts();

      // 2. Live Events Line Chart
      loadLiveEventsTimeline();

      // 3. Live Severity Donut & Outcomes
      renderSeverityChart(stats.severity_counts || {});
      renderOutcomeChart(stats.outcome_counts || {});

      // 4. Live Ranked IPs & Users
      renderTopList("top-ips-container", stats.top_ips || [], "ip", "events");
      renderTopList("top-users-container", stats.top_users || [], "username", "attempts");

    } catch (err) {
      console.error("Failed to load live dashboard:", err);
      showToast("Failed to refresh live telemetry", "error");
    }
  }
}

// Render Priority Alerts Table from list
function renderPriorityAlerts(alertsList) {
  const container = document.getElementById("priority-alerts-table-body");
  if (!container) return;

  if (!alertsList || !alertsList.length) {
    container.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; color: var(--outcome-success-text); padding: 1.25rem; font-size:0.825rem;">
          ✓ Priority queue clear. No active critical or high incidents require attention.
        </td>
      </tr>
    `;
    return;
  }

  container.innerHTML = "";
  alertsList.forEach(a => {
    const tr = document.createElement("tr");
    tr.className = "clickable-row";
    tr.tabIndex = 0;
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-label", `Investigate ${a.severity} incident: ${a.title}`);
    tr.dataset.alertId = String(a.id);

    tr.innerHTML = `
      <td><span class="badge badge-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
      <td>
        <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(a.title)}</div>
        <div style="font-size:0.75rem; color:var(--text-muted);">${escapeHtml(a.description)}</div>
      </td>
      <td><span class="mitre-pill">${escapeHtml(a.mitre_tag || "N/A")}</span></td>
      <td><span class="badge badge-status-${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></td>
      <td class="mono-cell">${escapeHtml(a.last_seen)}</td>
    `;

    tr.addEventListener("click", () => openAlertDrawer(a.id));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openAlertDrawer(a.id);
      }
    });

    container.appendChild(tr);
  });
}

async function loadLivePriorityAlerts() {
  try {
    const res = await fetch("/api/v1/alerts?limit=25", { headers: authHeaders() });
    if (!res.ok) throw new Error("Failed to load priority alerts");
    const data = await res.json();
    const priority = (data.alerts || []).filter(
      a => (a.severity === "critical" || a.severity === "high") && a.status !== "closed"
    );
    renderPriorityAlerts(priority);
  } catch (err) {
    const container = document.getElementById("priority-alerts-table-body");
    if (container) {
      container.innerHTML = `
        <tr>
          <td colspan="5" style="text-align:center; color: var(--sev-critical-text); padding: 1.25rem;">
            Error retrieving priority alerts: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }
}

// -------------------------------------------------------------
// Chart 1: Security Events Over Time & Authentication Trends
// -------------------------------------------------------------
async function loadLiveEventsTimeline() {
  const container = document.getElementById("chart-events-timeline");
  if (!container) return;

  try {
    const res = await fetch("/api/v1/events?limit=500", { headers: authHeaders() });
    if (!res.ok) throw new Error("Could not fetch events for timeline");
    const data = await res.json();

    const events = data.events || [];
    if (!events.length) {
      container.innerHTML = `
        <div class="chart-empty-state">
          <div class="chart-empty-icon">📊</div>
          <div class="chart-empty-title">No Security Event Telemetry Available</div>
          <div class="chart-empty-desc">The SQLite database currently contains 0 event records. Switch to Demo Telemetry or ingest logs in the Ingestion Lab.</div>
        </div>
      `;
      const subtitle = document.getElementById("events-chart-subtitle");
      if (subtitle) subtitle.textContent = "Zero events recorded in live database";
      return;
    }

    // Bucket live events into 30 minute/hourly buckets
    const sorted = [...events].sort((a, b) => (a.timestamp > b.timestamp ? 1 : -1));
    const startMs = new Date(sorted[0].timestamp).getTime();
    const endMs = new Date(sorted[sorted.length - 1].timestamp).getTime();
    const span = Math.max(endMs - startMs, 60000);
    const bucketCount = Math.min(60, Math.max(12, Math.floor(span / 60000)));
    const bucketStep = span / bucketCount;

    const buckets = [];
    for (let i = 0; i < bucketCount; i++) {
      const bStart = startMs + i * bucketStep;
      const d = new Date(bStart);
      const label = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
      buckets.push({
        minuteIndex: i,
        timeLabel: label,
        fullIso: d.toISOString(),
        total: 0,
        failures: 0,
        successes: 0,
        other: 0,
        isSpike: false,
        minuteOffset: bucketCount - i
      });
    }

    sorted.forEach(e => {
      const ms = new Date(e.timestamp).getTime();
      let bIdx = Math.floor((ms - startMs) / bucketStep);
      if (bIdx >= bucketCount) bIdx = bucketCount - 1;
      if (bIdx < 0) bIdx = 0;
      const b = buckets[bIdx];
      b.total++;
      if (e.outcome === "failure") b.failures++;
      else if (e.outcome === "success") b.successes++;
      else b.other++;
    });

    // Ensure invariants on all buckets
    buckets.forEach(b => {
      b.other = Math.max(0, b.total - (b.failures + b.successes));
      b.isSpike = b.failures >= 15;
    });

    renderEventsTimelineChart(buckets, false);

  } catch (err) {
    container.innerHTML = `
      <div class="chart-empty-state">
        <div class="chart-empty-icon" style="color:var(--sev-critical-text);">⚠</div>
        <div class="chart-empty-title">Failed to load event trend telemetry</div>
        <div class="chart-empty-desc">${escapeHtml(err.message)}</div>
      </div>
    `;
  }
}

function renderEventsTimelineChart(buckets, isDemo = true) {
  const container = document.getElementById("chart-events-timeline");
  const tooltip = document.getElementById("events-timeline-tooltip");
  const subtitle = document.getElementById("events-chart-subtitle");
  if (!container) return;

  if (!buckets || !buckets.length) {
    container.innerHTML = `
      <div class="chart-empty-state">
        <div class="chart-empty-icon">📊</div>
        <div class="chart-empty-title">No Security Event Telemetry Available</div>
        <div class="chart-empty-desc">Ingest raw syslog data or load an attack scenario in the Ingestion Lab to visualize real-time event trends.</div>
      </div>
    `;
    if (subtitle) subtitle.textContent = "Zero events recorded in telemetry window";
    return;
  }

  let totalEvents = 0;
  let totalFails = 0;
  let totalSuccs = 0;
  let totalOther = 0;
  buckets.forEach(b => {
    totalEvents += b.total;
    totalFails += b.failures;
    totalSuccs += b.successes;
    totalOther += (b.other || 0);
  });

  if (subtitle) {
    const rangeText = isDemo ? "60-minute window (Simulated Telemetry)" : `${buckets.length} intervals (Live Storage)`;
    subtitle.textContent = `Tracking ${totalEvents.toLocaleString()} events across ${rangeText} (${totalFails.toLocaleString()} failures, ${totalSuccs.toLocaleString()} successes, ${totalOther.toLocaleString()} other)`;
  }

  // Responsive SVG Geometry
  const width = 820;
  const height = 230;
  const padLeft = 48;
  const padRight = 24;
  const padTop = 24;
  const padBottom = 32;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const maxValRaw = Math.max(...buckets.map(b => b.total), 8);
  // Round up to clean, readable ceiling
  const maxVal = Math.ceil(maxValRaw / 20) * 20 || 20;
  const stepX = chartW / Math.max(buckets.length - 1, 1);

  const ptsTotal = buckets.map((b, i) => ({
    x: padLeft + i * stepX,
    y: padTop + chartH - (b.total / maxVal) * chartH,
    b
  }));
  const ptsFail = buckets.map((b, i) => ({
    x: padLeft + i * stepX,
    y: padTop + chartH - (b.failures / maxVal) * chartH,
    b
  }));
  const ptsSucc = buckets.map((b, i) => ({
    x: padLeft + i * stepX,
    y: padTop + chartH - (b.successes / maxVal) * chartH,
    b
  }));

  // Background Horizontal Gridlines
  let gridSvg = "";
  const gridSteps = 4;
  for (let s = 0; s <= gridSteps; s++) {
    const val = Math.round((maxVal / gridSteps) * s);
    const y = padTop + chartH - (s / gridSteps) * chartH;
    gridSvg += `
      <line class="chart-gridline" x1="${padLeft}" y1="${y}" x2="${padLeft + chartW}" y2="${y}" />
      <text class="chart-axis-text" x="${padLeft - 8}" y="${y + 3}" text-anchor="end">${val}</text>
    `;
  }

  // X-Axis readable time tick labels & vertical guide gridlines (5 evenly spaced intervals, no overlap)
  let xTicksSvg = "";
  const tickCount = Math.min(5, buckets.length);
  for (let t = 0; t < tickCount; t++) {
    const idx = Math.round((t / (tickCount - 1)) * (buckets.length - 1));
    const b = buckets[idx];
    if (!b) continue;
    const x = padLeft + idx * stepX;
    xTicksSvg += `
      <line class="chart-v-gridline" x1="${x}" y1="${padTop}" x2="${x}" y2="${padTop + chartH}" />
      <line x1="${x}" y1="${padTop + chartH}" x2="${x}" y2="${padTop + chartH + 5}" stroke="var(--border-subtle)" />
      <text class="chart-axis-text" x="${x}" y="${padTop + chartH + 18}" text-anchor="middle">${escapeHtml(b.timeLabel)}</text>
    `;
  }

  // Anomaly Bands (correlating to the brute-force burst & password spray)
  let anomalySvg = "";
  if (isDemo && buckets.length === 60) {
    // Anomaly 1: SSH Brute-Force Burst (min 25 to 33)
    const xBurst1Start = padLeft + 24.5 * stepX;
    const xBurst1End = padLeft + 33.5 * stepX;
    const burst1W = xBurst1End - xBurst1Start;

    // Anomaly 2: Credential Spray Burst (min 46 to 49)
    const xBurst2Start = padLeft + 45.5 * stepX;
    const xBurst2End = padLeft + 49.5 * stepX;
    const burst2W = xBurst2End - xBurst2Start;

    anomalySvg = `
      <rect class="chart-anomaly-band" x="${xBurst1Start}" y="${padTop}" width="${burst1W}" height="${chartH}" />
      <text class="chart-anomaly-text" x="${xBurst1Start + 6}" y="${padTop + 14}">⚠ BRUTE FORCE BURST</text>
      <rect class="chart-anomaly-band" x="${xBurst2Start}" y="${padTop}" width="${burst2W}" height="${chartH}" />
      <text class="chart-anomaly-text" x="${xBurst2Start + 6}" y="${padTop + 14}">⚡ SPRAY</text>
    `;
  }

  // Monotone Cubic Spline curves (guaranteed overshoot-free, natural security telemetry lines)
  const lineTotalD = generateMonotonePath(ptsTotal);
  const lineFailD = generateMonotonePath(ptsFail);
  const lineSuccD = generateMonotonePath(ptsSucc);

  const areaTotalD = `${lineTotalD} L ${ptsTotal[ptsTotal.length - 1].x.toFixed(1)} ${(padTop + chartH).toFixed(1)} L ${ptsTotal[0].x.toFixed(1)} ${(padTop + chartH).toFixed(1)} Z`;

  // Anomaly Peak Points & Hover Hitboxes
  let pointsSvg = "";
  let hoverBarsSvg = "";
  const barSlotW = chartW / buckets.length;

  buckets.forEach((b, i) => {
    const x = padLeft + i * stepX;
    const yF = ptsFail[i].y;

    if (b.failures >= 24) {
      pointsSvg += `
        <circle class="chart-point" cx="${x}" cy="${yF}" r="4" stroke="var(--sev-critical-accent)" fill="var(--bg-surface)" stroke-width="2" />
      `;
    }

    if (b.isCompromise) {
      pointsSvg += `
        <circle class="chart-point" cx="${x}" cy="${ptsSucc[i].y}" r="4.5" stroke="#f59e0b" fill="#f59e0b" stroke-width="2" title="Breach correlation marker" />
      `;
    }

    const boxX = x - barSlotW / 2;
    hoverBarsSvg += `
      <rect class="chart-hover-bar" x="${boxX}" y="${padTop}" width="${barSlotW}" height="${chartH}" data-idx="${i}" />
    `;
  });

  container.innerHTML = `
    <svg class="svg-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="Security events over time line chart">
      <defs>
        <linearGradient id="area-grad-total" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--accent-primary)" stop-opacity="0.16" />
          <stop offset="100%" stop-color="var(--accent-primary)" stop-opacity="0.01" />
        </linearGradient>
      </defs>
      <title>Security Events Over Time &amp; Authentication Trends</title>
      <desc>60-minute time-series chart showing total event volume alongside successful and failed login counts</desc>
      ${gridSvg}
      ${xTicksSvg}
      ${anomalySvg}
      <path class="chart-area-fill" fill="url(#area-grad-total)" d="${areaTotalD}" />
      <path class="chart-line" stroke="var(--accent-primary)" d="${lineTotalD}" />
      <path class="chart-line" stroke="var(--sev-critical-accent)" d="${lineFailD}" />
      <path class="chart-line" stroke="#22c55e" d="${lineSuccD}" />
      ${pointsSvg}
      <!-- Crosshair & Tracker Dots -->
      <line id="events-crosshair-line" class="chart-crosshair" x1="0" y1="${padTop}" x2="0" y2="${padTop + chartH}" style="display:none;" />
      <circle id="events-dot-total" class="chart-tracker-dot" r="4.5" fill="var(--bg-surface)" stroke="var(--accent-primary)" stroke-width="2.5" style="display:none;" />
      <circle id="events-dot-fail" class="chart-tracker-dot" r="4.5" fill="var(--bg-surface)" stroke="var(--sev-critical-accent)" stroke-width="2.5" style="display:none;" />
      <circle id="events-dot-succ" class="chart-tracker-dot" r="4.5" fill="var(--bg-surface)" stroke="#22c55e" stroke-width="2.5" style="display:none;" />
      ${hoverBarsSvg}
    </svg>
  `;

  // Interactive Hover Tooltip & Crosshair Handlers
  const crosshairLine = container.querySelector("#events-crosshair-line");
  const dotTotal = container.querySelector("#events-dot-total");
  const dotFail = container.querySelector("#events-dot-fail");
  const dotSucc = container.querySelector("#events-dot-succ");
  const hoverBars = container.querySelectorAll(".chart-hover-bar");

  hoverBars.forEach(bar => {
    const idx = parseInt(bar.dataset.idx, 10);
    const b = buckets[idx];
    if (!b) return;

    bar.addEventListener("mouseenter", (e) => {
      if (!tooltip) return;
      const rect = container.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      tooltip.style.display = "block";
      tooltip.style.left = `${mouseX}px`;
      tooltip.style.top = `${mouseY}px`;

      const x = ptsTotal[idx].x;
      if (crosshairLine) {
        crosshairLine.setAttribute("x1", x);
        crosshairLine.setAttribute("x2", x);
        crosshairLine.style.display = "block";
      }

      if (dotTotal) {
        dotTotal.setAttribute("cx", x);
        dotTotal.setAttribute("cy", ptsTotal[idx].y);
        dotTotal.style.display = "block";
      }
      if (dotFail) {
        dotFail.setAttribute("cx", x);
        dotFail.setAttribute("cy", ptsFail[idx].y);
        dotFail.style.display = "block";
      }
      if (dotSucc) {
        dotSucc.setAttribute("cx", x);
        dotSucc.setAttribute("cy", ptsSucc[idx].y);
        dotSucc.style.display = "block";
      }

      const spikeBadge = b.failures >= 14 ? '<span class="badge badge-critical" style="font-size:0.6rem; padding:0.1rem 0.35rem;">Spike</span>' : '';
      const breachBadge = b.isCompromise ? '<span class="badge badge-medium" style="font-size:0.6rem; padding:0.1rem 0.35rem;">Breach Flag</span>' : '';
      const anomalyNote = b.anomalyTag ? `<div style="font-size:0.68rem; color:var(--sev-critical-text); font-weight:600; margin-top:0.25rem;">⚠ ${escapeHtml(b.anomalyTag)}</div>` : '';

      const failRatio = b.total > 0 ? Math.round((b.failures / b.total) * 100) : 0;

      tooltip.innerHTML = `
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:0.3rem;">
          Time: ${escapeHtml(b.timeLabel)} (${b.minuteOffset}m ago)
        </div>
        <div style="color:var(--text-secondary); display:flex; justify-content:space-between; gap:1.25rem;">
          <span>All Ingested Events:</span> <strong>${b.total}</strong>
        </div>
        <div style="color:var(--sev-critical-text); display:flex; justify-content:space-between; gap:1.25rem;">
          <span>Failed Logins:</span> 
          <span><strong>${b.failures}</strong> (${failRatio}%) ${spikeBadge} ${breachBadge}</span>
        </div>
        <div style="color:#22c55e; display:flex; justify-content:space-between; gap:1.25rem;">
          <span>Successful Logins:</span> <strong>${b.successes}</strong>
        </div>
        <div style="color:var(--text-dim); display:flex; justify-content:space-between; gap:1.25rem; font-size:0.7rem;">
          <span>Other Telemetry:</span> <span>${b.other}</span>
        </div>
        ${anomalyNote}
        <div style="font-size:0.68rem; color:var(--text-dim); margin-top:0.35rem; border-top:1px solid var(--border-subtle); padding-top:0.25rem;">
          Click interval to inspect in Event Explorer &rarr;
        </div>
      `;
    });

    bar.addEventListener("mousemove", (e) => {
      if (!tooltip) return;
      const rect = container.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      tooltip.style.left = `${mouseX}px`;
      tooltip.style.top = `${mouseY}px`;
    });

    bar.addEventListener("mouseleave", () => {
      if (tooltip) tooltip.style.display = "none";
      if (crosshairLine) crosshairLine.style.display = "none";
      if (dotTotal) dotTotal.style.display = "none";
      if (dotFail) dotFail.style.display = "none";
      if (dotSucc) dotSucc.style.display = "none";
    });

    bar.addEventListener("click", () => {
      if (tooltip) tooltip.style.display = "none";
      switchTab("events");
      showToast(`Inspecting telemetry window for interval ${b.timeLabel}`, "info");
    });
  });
}

// -------------------------------------------------------------
// Chart 2: Alert Severity Distribution (Proportional Donut)
// -------------------------------------------------------------
function renderSeverityChart(counts, explicitTotal = null) {
  const container = document.getElementById("chart-severity");
  if (!container) return;

  const sevs = [
    { key: "critical", label: "Critical", color: "var(--sev-critical-accent)" },
    { key: "high", label: "High", color: "var(--sev-high-accent)" },
    { key: "medium", label: "Medium", color: "var(--sev-medium-accent)" },
    { key: "low", label: "Low", color: "var(--sev-low-accent)" },
  ];

  const total = explicitTotal !== null ? explicitTotal : sevs.reduce((acc, s) => acc + (counts[s.key] || 0), 0);

  if (total === 0) {
    container.innerHTML = `
      <div class="chart-empty-state" style="padding: 1.5rem 0.5rem;">
        <div class="chart-empty-icon" style="font-size:1.25rem;">🛡</div>
        <div class="chart-empty-title" style="font-size:0.8rem;">No Security Alerts Generated</div>
        <div class="chart-empty-desc">System clean. All correlation rules evaluated with zero threshold violations.</div>
      </div>
    `;
    return;
  }

  // Generate SVG Donut with exact mathematical proportions
  const cx = 70;
  const cy = 70;
  const R = 56;
  const r = 38;
  let currentAngle = -Math.PI / 2;
  let slicesSvg = "";

  sevs.forEach(s => {
    const val = counts[s.key] || 0;
    if (val === 0) return;
    const sliceAngle = (val / total) * 2 * Math.PI;
    const endAngle = currentAngle + sliceAngle;

    const x1 = cx + R * Math.cos(currentAngle);
    const y1 = cy + R * Math.sin(currentAngle);
    const x2 = cx + R * Math.cos(endAngle);
    const y2 = cy + R * Math.sin(endAngle);
    const x3 = cx + r * Math.cos(endAngle);
    const y3 = cy + r * Math.sin(endAngle);
    const x4 = cx + r * Math.cos(currentAngle);
    const y4 = cy + r * Math.sin(currentAngle);
    const largeArc = sliceAngle > Math.PI ? 1 : 0;

    let pathD = "";
    if (val === total) {
      pathD = `
        M ${cx} ${cy - R}
        A ${R} ${R} 0 1 1 ${cx} ${cy + R}
        A ${R} ${R} 0 1 1 ${cx} ${cy - R}
        M ${cx} ${cy - r}
        A ${r} ${r} 0 1 0 ${cx} ${cy + r}
        A ${r} ${r} 0 1 0 ${cx} ${cy - r}
        Z
      `;
    } else {
      pathD = `M ${x1} ${y1} A ${R} ${R} 0 ${largeArc} 1 ${x2} ${y2} L ${x3} ${y3} A ${r} ${r} 0 ${largeArc} 0 ${x4} ${y4} Z`;
    }

    slicesSvg += `
      <path class="donut-slice" d="${pathD}" fill="${s.color}" data-sev="${s.key}" tabindex="0" role="button" aria-label="${s.label} alerts: ${val}" title="Click to filter by ${s.label} (${val} alerts)" />
    `;
    currentAngle = endAngle;
  });

  // Interactive Legend with Exact Counts & Proportions
  let legendHtml = `<div class="donut-legend">`;
  sevs.forEach(s => {
    const val = counts[s.key] || 0;
    const pct = total > 0 ? Math.round((val / total) * 100) : 0;
    legendHtml += `
      <div class="donut-legend-row" data-sev="${s.key}" role="button" tabindex="0" title="Filter alerts by ${s.label}">
        <span style="display:flex; align-items:center; gap:0.4rem;">
          <span class="badge badge-${s.key}">${s.label}</span>
        </span>
        <span style="font-family:var(--font-mono); font-weight:600; font-size:0.775rem;">
          ${val} <span style="font-size:0.7rem; color:var(--text-dim);">(${pct}%)</span>
        </span>
      </div>
    `;
  });
  legendHtml += `</div>`;

  container.innerHTML = `
    <div class="donut-wrapper">
      <div class="donut-svg-container">
        <svg viewBox="0 0 140 140" class="svg-chart" role="img" aria-label="Alert severity distribution donut chart">
          ${slicesSvg}
          <text class="donut-center-num" x="${cx}" y="${cy - 2}">${total}</text>
          <text class="donut-center-lbl" x="${cx}" y="${cy + 13}">TOTAL ALERTS</text>
        </svg>
      </div>
      ${legendHtml}
    </div>
  `;

  // Attach Filter Routes
  const triggerFilter = (sevKey) => {
    switchTab("alerts");
    const sevSelect = document.getElementById("filter-alert-severity");
    if (sevSelect) {
      sevSelect.value = sevKey;
      loadAlerts();
    }
  };

  container.querySelectorAll(".donut-slice, .donut-legend-row").forEach(elem => {
    const sevKey = elem.dataset.sev;
    elem.addEventListener("click", () => triggerFilter(sevKey));
    elem.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        triggerFilter(sevKey);
      }
    });
  });
}

// -------------------------------------------------------------
// Chart 3: Authentication Outcomes & Ratio Analysis
// -------------------------------------------------------------
function renderOutcomeChart(counts) {
  const container = document.getElementById("chart-outcomes");
  if (!container) return;
  const successes = counts.success || 0;
  const failures = counts.failure || 0;
  const total = successes + failures;

  if (total === 0) {
    container.innerHTML = `
      <div class="chart-empty-state" style="padding:1.5rem 0.5rem;">
        <div class="chart-empty-icon" style="font-size:1.25rem;">🔐</div>
        <div class="chart-empty-title" style="font-size:0.8rem;">No Authentication Records</div>
        <div class="chart-empty-desc">Telemetry has not recorded any login attempts yet.</div>
      </div>
    `;
    return;
  }

  const succPct = ((successes / total) * 100).toFixed(1);
  const failPct = ((failures / total) * 100).toFixed(1);

  // Clear warning state when failure ratio is elevated (>= 20%)
  const elevatedFail = parseFloat(failPct) >= 20.0;

  container.innerHTML = `
    <div style="font-size:0.75rem; margin-bottom:0.6rem; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.4rem;">
      <span style="color:${elevatedFail ? 'var(--sev-high-text)' : 'var(--outcome-success-text)'}; font-weight:600; display:flex; align-items:center; gap:0.35rem;">
        <span>${elevatedFail ? '⚠' : '✓'}</span>
        ${elevatedFail ? `Elevated Failure Velocity (${failPct}% failure rate)` : `Normal Authentication Baseline (${succPct}% success rate)`}
      </span>
      <span style="font-family:var(--font-mono); font-size:0.725rem; color:var(--text-dim);">${total.toLocaleString()} total attempts</span>
    </div>

    <!-- Segmented Proportion Meter -->
    <div class="ranked-bar-track" style="height:9px; display:flex; margin-bottom:0.75rem;">
      <div style="width: ${succPct}%; background-color: #22c55e;" title="Success: ${successes.toLocaleString()} (${succPct}%)"></div>
      <div style="width: ${failPct}%; background-color: var(--sev-critical-accent);" title="Failure: ${failures.toLocaleString()} (${failPct}%)"></div>
    </div>

    <!-- Detail Breakdown Rows -->
    <div class="bar-chart-row clickable-row" id="row-filter-success" role="button" tabindex="0" title="Click to view successful events in Event Explorer" style="margin-bottom:0.4rem;">
      <span class="bar-label" style="display:flex; align-items:center; gap:0.35rem;">
        <span class="chart-legend-dot" style="background:#22c55e;"></span> SUCCESS
      </span>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${succPct}%; background-color: #22c55e;"></div>
      </div>
      <span class="bar-count">${escapeHtml(successes.toLocaleString())} <span style="font-size:0.65rem; color:var(--text-dim);">(${succPct}%)</span></span>
    </div>

    <div class="bar-chart-row clickable-row" id="row-filter-failure" role="button" tabindex="0" title="Click to view failure events in Event Explorer">
      <span class="bar-label" style="display:flex; align-items:center; gap:0.35rem;">
        <span class="chart-legend-dot" style="background:var(--sev-critical-accent);"></span> FAILURE
      </span>
      <div class="bar-track">
        <div class="bar-fill" style="width: ${failPct}%; background-color: var(--sev-critical-accent);"></div>
      </div>
      <span class="bar-count" style="color:var(--sev-critical-text);">${escapeHtml(failures.toLocaleString())} <span style="font-size:0.65rem; color:var(--text-dim);">(${failPct}%)</span></span>
    </div>
  `;

  const filterOutcome = (outKey) => {
    switchTab("events");
    const outSelect = document.getElementById("filter-event-outcome");
    if (outSelect) {
      outSelect.value = outKey;
      state.eventsPage = 0;
      loadEvents();
    }
  };

  const succRow = document.getElementById("row-filter-success");
  if (succRow) {
    succRow.addEventListener("click", () => filterOutcome("success"));
    succRow.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        filterOutcome("success");
      }
    });
  }

  const failRow = document.getElementById("row-filter-failure");
  if (failRow) {
    failRow.addEventListener("click", () => filterOutcome("failure"));
    failRow.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        filterOutcome("failure");
      }
    });
  }
}

// -------------------------------------------------------------
// Chart 4: Top Attacking Source IPs & Targeted Usernames
// -------------------------------------------------------------
function renderTopList(elementId, items, keyName, unitLabel = "attempts") {
  const container = document.getElementById(elementId);
  if (!container) return;
  if (!items || !items.length) {
    container.innerHTML = `<div style="color: var(--text-dim); font-size: 0.775rem; padding:0.75rem 0.5rem; text-align:center;">No activity recorded yet</div>`;
    return;
  }

  // Consistent sorting: highest event count first
  const sortedItems = [...items].sort((a, b) => (b.count || 0) - (a.count || 0));
  const maxVal = Math.max(...sortedItems.map(i => i.count || 0), 1);
  const isIp = keyName === "ip";

  container.innerHTML = "";
  sortedItems.forEach((item, idx) => {
    const val = String(item[keyName] || "unknown");
    const cnt = item.count || 0;
    const pct = Math.round((cnt / maxVal) * 100);

    const row = document.createElement("div");
    row.className = "ranked-bar-row";
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.setAttribute("title", `Click to investigate ${isIp ? 'IP' : 'user'} ${val} in Event Explorer`);

    row.innerHTML = `
      <span class="rank-badge">#${idx + 1}</span>
      <span class="mono-cell ${isIp ? 'clickable-ip' : ''}" style="width: 140px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(val)}</span>
      <div class="ranked-bar-track">
        <div class="ranked-bar-fill" style="width: ${pct}%;"></div>
      </div>
      <span class="badge badge-low" style="font-family:var(--font-mono); font-size:0.7rem; flex-shrink:0;">${escapeHtml(cnt.toLocaleString())} ${escapeHtml(unitLabel)}</span>
    `;

    const openInEvents = () => {
      switchTab("events");
      if (isIp) {
        const ipInput = document.getElementById("filter-event-ip");
        if (ipInput) {
          ipInput.value = val;
          state.eventsPage = 0;
          loadEvents();
        }
      } else {
        const userInput = document.getElementById("filter-event-user");
        if (userInput) {
          userInput.value = val;
          state.eventsPage = 0;
          loadEvents();
        }
      }
    };

    row.addEventListener("click", openInEvents);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openInEvents();
      }
    });

    container.appendChild(row);
  });
}



// -------------------------------------------------------------
// Alert Investigation Drawer
// -------------------------------------------------------------
let currentActiveAlertId = null;

async function openAlertDrawer(alertId) {
  currentActiveAlertId = alertId;
  const drawer = document.getElementById("alert-drawer");
  const body = document.getElementById("alert-drawer-body");
  const title = document.getElementById("alert-drawer-title");
  const badge = document.getElementById("alert-drawer-sev-badge");
  const statusActions = document.getElementById("alert-drawer-status-actions");

  if (!drawer) return;
  drawer.style.display = "flex";
  body.innerHTML = '<div style="padding:2rem; text-align:center; color:var(--text-muted);">Loading alert telemetry...</div>';

  try {
    const res = await fetch(`/api/v1/alerts/${alertId}`, { headers: authHeaders() });
    if (!res.ok) throw new Error("Could not load alert details");
    const a = await res.json();

    title.textContent = a.title || "Alert Investigation";
    badge.className = `badge badge-${escapeHtml(a.severity)}`;
    badge.textContent = a.severity;

    // Update active status button styling
    if (statusActions) {
      statusActions.querySelectorAll("button").forEach(btn => {
        btn.classList.toggle("active-status", btn.dataset.status === a.status);
      });
    }

    // Connect Investigate IP button
    const invIpBtn = document.getElementById("btn-drawer-investigate-ip");
    const srcIp = a.details?.src_ip || "";
    if (invIpBtn) {
      if (srcIp) {
        invIpBtn.style.display = "inline-flex";
        invIpBtn.onclick = () => {
          closeAlertDrawer();
          switchTab("events");
          const ipInput = document.getElementById("filter-event-ip");
          if (ipInput) {
            ipInput.value = srcIp;
            loadEvents();
          }
        };
      } else {
        invIpBtn.style.display = "none";
      }
    }

    // Build Drawer Body Content
    const content = document.createElement("div");
    content.style.display = "flex";
    content.style.flexDirection = "column";
    content.style.gap = "1rem";

    // 1. Compromise Banner for failure_then_success
    if (a.rule_id === "ssh_failure_then_success") {
      const banner = document.createElement("div");
      banner.className = "compromise-banner";
      
      const bHeader = document.createElement("div");
      bHeader.className = "compromise-banner-header";
      bHeader.innerHTML = "<span>⚠</span> Potential Credential Breach Detected";
      
      const bDesc = document.createElement("div");
      bDesc.className = "compromise-banner-desc";
      bDesc.textContent = (
        "Multiple authentication failures were immediately followed by a successful login. " +
        "Investigate credentials and host sessions immediately to confirm whether this access was authorized."
      );
      
      banner.appendChild(bHeader);
      banner.appendChild(bDesc);
      content.appendChild(banner);
    }

    // 2. Incident Overview Metadata Card
    const metaCard = document.createElement("div");
    metaCard.className = "drawer-section";

    const metaTitle = document.createElement("div");
    metaTitle.className = "drawer-section-title";
    metaTitle.textContent = "Incident Overview";
    metaCard.appendChild(metaTitle);

    const metaGrid = document.createElement("div");
    metaGrid.className = "drawer-meta-grid";

    const fields = [
      { label: "Rule ID", val: a.rule_id, mono: true },
      { label: "Severity", val: a.severity.toUpperCase(), badge: `badge-${a.severity}` },
      { label: "Correlated Events", val: a.event_count, badge: "badge-low" },
      { label: "Triage Status", val: a.status.toUpperCase(), badge: `badge-status-${a.status}` },
      { label: "First Seen", val: a.first_seen, mono: true },
      { label: "Last Seen", val: a.last_seen, mono: true },
    ];

    fields.forEach(f => {
      const item = document.createElement("div");
      item.className = "meta-item";
      const lbl = document.createElement("span");
      lbl.className = "meta-label";
      lbl.textContent = f.label;
      const val = document.createElement("span");
      val.className = "meta-value" + (f.mono ? " mono-cell" : "");
      if (f.badge) {
        val.innerHTML = `<span class="badge ${f.badge}">${escapeHtml(f.val)}</span>`;
      } else {
        val.textContent = f.val;
      }
      item.appendChild(lbl);
      item.appendChild(val);
      metaGrid.appendChild(item);
    });
    metaCard.appendChild(metaGrid);

    // MITRE ATT&CK reference
    if (a.mitre_tag) {
      const mitreRow = document.createElement("div");
      mitreRow.style.marginTop = "0.75rem";
      mitreRow.style.fontSize = "0.775rem";
      mitreRow.style.display = "flex";
      mitreRow.style.alignItems = "center";
      mitreRow.style.gap = "0.5rem";

      const mitreLbl = document.createElement("span");
      mitreLbl.className = "meta-label";
      mitreLbl.textContent = "MITRE ATT&CK:";

      const mitreUrl = getMitreUrl(a.mitre_tag);
      if (mitreUrl) {
        const link = document.createElement("a");
        link.href = mitreUrl;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.className = "mitre-pill";
        link.textContent = `${a.mitre_tag} ↗`;
        mitreRow.appendChild(mitreLbl);
        mitreRow.appendChild(link);
      } else {
        const pill = document.createElement("span");
        pill.className = "mitre-pill";
        pill.textContent = a.mitre_tag;
        mitreRow.appendChild(mitreLbl);
        mitreRow.appendChild(pill);
      }
      metaCard.appendChild(mitreRow);
    }

    content.appendChild(metaCard);

    // 3. Attack Context Section (IP, Usernames)
    const ctxCard = document.createElement("div");
    ctxCard.className = "drawer-section";
    const ctxTitle = document.createElement("div");
    ctxTitle.className = "drawer-section-title";
    ctxTitle.textContent = "Source & Target Attributes";
    ctxCard.appendChild(ctxTitle);

    const ctxGrid = document.createElement("div");
    ctxGrid.className = "drawer-meta-grid";

    // Source IP
    const ipItem = document.createElement("div");
    ipItem.className = "meta-item";
    const ipLbl = document.createElement("span");
    ipLbl.className = "meta-label";
    ipLbl.textContent = "Source IP";
    const ipVal = document.createElement("span");
    ipVal.className = "meta-value mono-cell";
    if (srcIp) {
      ipVal.innerHTML = `<span class="clickable-ip" title="Click to filter Event Explorer">${escapeHtml(srcIp)}</span>`;
      ipVal.querySelector(".clickable-ip").onclick = () => {
        closeAlertDrawer();
        switchTab("events");
        const ipInput = document.getElementById("filter-event-ip");
        if (ipInput) {
          ipInput.value = srcIp;
          loadEvents();
        }
      };
    } else {
      ipVal.textContent = "N/A";
    }
    ipItem.appendChild(ipLbl);
    ipItem.appendChild(ipVal);
    ctxGrid.appendChild(ipItem);

    // Targeted Users
    const uItem = document.createElement("div");
    uItem.className = "meta-item";
    const uLbl = document.createElement("span");
    uLbl.className = "meta-label";
    uLbl.textContent = "Targeted Accounts";
    const uVal = document.createElement("span");
    uVal.className = "meta-value";

    const usernames = a.details?.usernames || a.details?.distinct_values || (a.details?.username ? [a.details.username] : []);
    if (usernames.length) {
      uVal.textContent = usernames.join(", ");
    } else {
      uVal.textContent = "N/A";
    }
    uItem.appendChild(uLbl);
    uItem.appendChild(uVal);
    ctxGrid.appendChild(uItem);

    ctxCard.appendChild(ctxGrid);
    content.appendChild(ctxCard);

    // 4. Description and Matched Events
    const descCard = document.createElement("div");
    descCard.className = "drawer-section";
    const descTitle = document.createElement("div");
    descTitle.className = "drawer-section-title";
    descTitle.textContent = "Rule Detection Details";
    descCard.appendChild(descTitle);

    const descText = document.createElement("p");
    descText.style.fontSize = "0.8rem";
    descText.style.color = "var(--text-muted)";
    descText.style.marginBottom = "0.75rem";
    descText.textContent = a.description || "No description provided.";
    descCard.appendChild(descText);

    // If success event present in details (from failure_then_success)
    if (a.details?.successful_login) {
      const succBox = document.createElement("div");
      succBox.style.background = "var(--outcome-success-bg)";
      succBox.style.border = "1px solid var(--outcome-success-border)";
      succBox.style.borderRadius = "var(--radius-sm)";
      succBox.style.padding = "0.65rem";
      succBox.style.marginBottom = "0.75rem";

      const sTitle = document.createElement("div");
      sTitle.style.fontWeight = "600";
      sTitle.style.color = "var(--outcome-success-text)";
      sTitle.style.fontSize = "0.775rem";
      sTitle.textContent = "✓ Successful Login Event Captured:";
      succBox.appendChild(sTitle);

      const sPre = document.createElement("pre");
      sPre.className = "code-box";
      sPre.style.maxHeight = "120px";
      sPre.style.marginTop = "0.35rem";
      sPre.textContent = JSON.stringify(a.details.successful_login, null, 2);
      succBox.appendChild(sPre);

      descCard.appendChild(succBox);
    }

    content.appendChild(descCard);

    // 5. Alert Investigation Timeline (Chronological Sequence)
    const timelineCard = document.createElement("div");
    timelineCard.className = "drawer-section";
    const tlTitle = document.createElement("div");
    tlTitle.className = "drawer-section-title";
    tlTitle.innerHTML = `
      <span>Alert Investigation Timeline</span>
      <span style="font-size:0.675rem; font-family:var(--font-mono); color:var(--text-dim);">Chronological Sequence</span>
    `;
    timelineCard.appendChild(tlTitle);

    const tlContainer = document.createElement("div");
    tlContainer.id = "drawer-timeline-container";
    tlContainer.innerHTML = '<div style="font-size:0.75rem; color:var(--text-dim); padding:0.5rem 0;">Analyzing event chronology...</div>';
    timelineCard.appendChild(tlContainer);
    content.appendChild(timelineCard);

    // 6. Recent Correlated Raw Events from this Source IP
    if (srcIp) {
      const rawCard = document.createElement("div");
      rawCard.className = "drawer-section";
      const rawTitle = document.createElement("div");
      rawTitle.className = "drawer-section-title";
      rawTitle.textContent = `Related Raw Logs (${srcIp})`;
      rawCard.appendChild(rawTitle);

      const rawPre = document.createElement("pre");
      rawPre.className = "code-box";
      rawPre.textContent = "Fetching related logs...";
      rawCard.appendChild(rawPre);
      content.appendChild(rawCard);

      fetch(`/api/v1/events?src_ip=${encodeURIComponent(srcIp)}&limit=35`, { headers: authHeaders() })
        .then(r => r.json())
        .then(evData => {
          const events = evData.events || [];
          if (events.length) {
            rawPre.textContent = events.map(e => e.raw_message || `${e.timestamp} ${e.outcome}`).join("\n");
            renderDrawerTimeline(events, a, tlContainer);
          } else {
            rawPre.textContent = "No additional raw logs found.";
            tlContainer.innerHTML = '<div style="font-size:0.75rem; color:var(--text-dim); padding:0.5rem 0;">No individual event records found in database.</div>';
          }
        })
        .catch((err) => {
          rawPre.textContent = "Could not fetch additional raw logs.";
          tlContainer.innerHTML = `<div style="font-size:0.75rem; color:var(--sev-critical-text);">Failed to load timeline: ${escapeHtml(err.message)}</div>`;
        });
    } else {
      tlContainer.innerHTML = '<div style="font-size:0.75rem; color:var(--text-dim); padding:0.5rem 0;">No source IP bound to this alert for correlation.</div>';
    }

    body.innerHTML = "";
    body.appendChild(content);

  } catch (err) {
    body.innerHTML = `<div style="color:var(--sev-critical-text); padding:1rem;">Error: ${escapeHtml(err.message)}</div>`;
  }
}

function renderDrawerTimeline(events, alert, container) {
  if (!events || !events.length) {
    container.innerHTML = '<div style="font-size:0.75rem; color:var(--text-dim); padding:0.5rem 0;">No events available for timeline.</div>';
    return;
  }

  // Sort events chronologically ascending (earliest to latest)
  const sorted = [...events].sort((a, b) => (a.timestamp > b.timestamp ? 1 : -1));

  const listDiv = document.createElement("div");
  listDiv.className = "timeline-container";

  let failStreak = 0;

  sorted.forEach((e) => {
    const isSuccess = e.outcome === "success";
    const isFailure = e.outcome === "failure";

    // Detect breach transition milestone:
    if (isSuccess && failStreak >= 1) {
      const breachBanner = document.createElement("div");
      breachBanner.className = "timeline-breach-callout";
      breachBanner.innerHTML = `
        <span>🚨</span>
        <span>Breach Milestone: Successful authentication for "${escapeHtml(e.username || 'user')}" following ${failStreak} consecutive failure(s)!</span>
      `;
      listDiv.appendChild(breachBanner);
      failStreak = 0;
    } else if (isFailure) {
      failStreak++;
    }

    const node = document.createElement("div");
    node.className = "timeline-node";

    const dot = document.createElement("div");
    dot.className = `timeline-dot ${isSuccess ? 'dot-success' : 'dot-failure'}`;
    node.appendChild(dot);

    const card = document.createElement("div");
    card.className = "timeline-card";

    let timeDisplay = e.timestamp;
    if (timeDisplay.includes("T")) {
      timeDisplay = timeDisplay.split("T")[1].replace("Z", " UTC");
    }

    card.innerHTML = `
      <div class="timeline-header">
        <span class="timeline-timestamp">${escapeHtml(timeDisplay)}</span>
        <span class="badge ${isSuccess ? 'badge-success' : 'badge-failure'}">${escapeHtml(e.outcome)}</span>
      </div>
      <div style="font-size:0.775rem; color:var(--text-primary); margin-bottom:0.2rem;">
        <strong>${escapeHtml(e.username || '(empty)')}</strong> 
        ${e.invalid_user ? '<span class="badge badge-failure" style="font-size:0.6rem; padding:0 0.3rem;">INVALID USER</span>' : ''}
        <span style="color:var(--text-muted); font-size:0.7rem; margin-left:0.35rem;">via ${escapeHtml(e.program || 'sshd')} (port ${escapeHtml(e.src_port || '-')})</span>
      </div>
      <div style="font-size:0.7rem; font-family:var(--font-mono); color:var(--text-dim); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:480px;">
        ${escapeHtml(e.raw_message || e.activity || '-')}
      </div>
    `;

    node.appendChild(card);
    listDiv.appendChild(node);
  });

  container.innerHTML = "";
  container.appendChild(listDiv);
}


function closeAlertDrawer() {
  const drawer = document.getElementById("alert-drawer");
  if (drawer) {
    drawer.style.display = "none";
  }
  currentActiveAlertId = null;
}

// -------------------------------------------------------------
// Alerts View
// -------------------------------------------------------------
async function loadAlerts() {
  const statusFilter = document.getElementById("filter-alert-status")?.value || "";
  const sevFilter = document.getElementById("filter-alert-severity")?.value || "";

  let url = `/api/v1/alerts?limit=${state.alertsLimit}&offset=${state.alertsPage * state.alertsLimit}`;
  if (statusFilter) url += `&status=${encodeURIComponent(statusFilter)}`;
  if (sevFilter) url += `&severity=${encodeURIComponent(sevFilter)}`;

  try {
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) return handleLogout();
    const data = await res.json();
    const tbody = document.getElementById("alerts-table-body");
    const label = document.getElementById("alerts-count-label");
    if (label) label.textContent = `${data.total} total alerts`;

    if (!data.alerts || !data.alerts.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-dim); padding: 2rem;">No alerts matching current filters</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    for (const a of data.alerts) {
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-label", `View alert ${a.title}`);
      tr.dataset.alertId = String(a.id);

      tr.innerHTML = `
        <td><span class="badge badge-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span></td>
        <td>
          <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(a.title)}</div>
          <div style="font-size:0.75rem; color: var(--text-muted);">${escapeHtml(a.description)}</div>
        </td>
        <td><span class="mitre-pill">${escapeHtml(a.mitre_tag || "N/A")}</span></td>
        <td><span class="badge badge-low">${escapeHtml(a.event_count)}</span></td>
        <td><span class="badge badge-status-${escapeHtml(a.status)}">${escapeHtml(a.status)}</span></td>
        <td class="mono-cell">${escapeHtml(a.last_seen)}</td>
        <td class="action-cell">
          <select class="select-field alert-status-select" style="padding: 0.2rem 0.5rem; font-size: 0.725rem;" aria-label="Change alert status">
            <option value="new" ${a.status === 'new' ? 'selected' : ''}>New</option>
            <option value="acknowledged" ${a.status === 'acknowledged' ? 'selected' : ''}>Acknowledged</option>
            <option value="closed" ${a.status === 'closed' ? 'selected' : ''}>Closed</option>
          </select>
        </td>
      `;

      // Select dropdown handler
      const select = tr.querySelector(".alert-status-select");
      if (select) {
        select.addEventListener("click", (e) => e.stopPropagation());
        select.addEventListener("change", (e) => {
          e.stopPropagation();
          updateAlertStatus(a.id, select.value);
        });
      }

      // Row click opens drawer
      tr.addEventListener("click", () => openAlertDrawer(a.id));
      tr.addEventListener("keydown", (e) => {
        if (e.target === tr && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          openAlertDrawer(a.id);
        }
      });

      tbody.appendChild(tr);
    }
  } catch (err) {
    console.error("Failed to load alerts:", err);
  }
}

async function updateAlertStatus(alertId, newStatus) {
  try {
    const res = await fetch(`/api/v1/alerts/${alertId}/status`, {
      method: "PATCH",
      headers: authHeaders(),
      body: JSON.stringify({ status: newStatus })
    });
    if (!res.ok) throw new Error("Failed to update alert status");
    showToast(`Alert #${alertId} status changed to ${newStatus}`, "success");
    loadAlerts();
    if (state.activeTab === "dashboard") {
      loadDashboard();
    }
    if (currentActiveAlertId === alertId) {
      const statusActions = document.getElementById("alert-drawer-status-actions");
      if (statusActions) {
        statusActions.querySelectorAll("button").forEach(btn => {
          btn.classList.toggle("active-status", btn.dataset.status === newStatus);
        });
      }
    }
  } catch (err) {
    showToast("Error updating status: " + err.message, "error");
  }
}

// -------------------------------------------------------------
// Events View & Event Detail Drawer
// -------------------------------------------------------------
let currentLoadedEvents = [];
let eventSortAsc = false;

function openEventDrawer(eventIndex) {
  const ev = currentLoadedEvents[eventIndex];
  if (!ev) return;

  const drawer = document.getElementById("event-drawer");
  const body = document.getElementById("event-drawer-body");
  const title = document.getElementById("event-drawer-title");
  const badge = document.getElementById("event-drawer-outcome-badge");
  const copyBtn = document.getElementById("btn-event-copy-raw");
  const filterIpBtn = document.getElementById("btn-event-filter-this-ip");

  if (!drawer) return;
  drawer.style.display = "flex";

  title.textContent = `Event #${ev.id || (eventIndex + 1)}`;
  const outcomeClass = ev.outcome === 'success' ? 'badge-success' : 'badge-failure';
  badge.className = `badge ${outcomeClass}`;
  badge.textContent = ev.outcome.toUpperCase();

  if (copyBtn) {
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(ev.raw_message || "");
        showToast("Raw log copied to clipboard", "success");
      } catch (err) {
        showToast("Clipboard copy not permitted by browser", "error");
      }
    };
  }

  if (filterIpBtn) {
    if (ev.src_ip) {
      filterIpBtn.style.display = "inline-flex";
      filterIpBtn.textContent = `Filter Events by ${ev.src_ip}`;
      filterIpBtn.onclick = () => {
        closeEventDrawer();
        const ipInput = document.getElementById("filter-event-ip");
        if (ipInput) ipInput.value = ev.src_ip;
        state.eventsPage = 0;
        loadEvents();
      };
    } else {
      filterIpBtn.style.display = "none";
    }
  }

  body.innerHTML = "";
  const content = document.createElement("div");
  content.style.display = "flex";
  content.style.flexDirection = "column";
  content.style.gap = "1rem";

  // Metadata Card
  const metaCard = document.createElement("div");
  metaCard.className = "drawer-section";
  const metaTitle = document.createElement("div");
  metaTitle.className = "drawer-section-title";
  metaTitle.textContent = "Normalized Event Attributes";
  metaCard.appendChild(metaTitle);

  const metaGrid = document.createElement("div");
  metaGrid.className = "drawer-meta-grid";

  const fields = [
    { label: "Timestamp (UTC)", val: ev.timestamp, mono: true },
    { label: "Outcome", val: ev.outcome.toUpperCase(), badge: outcomeClass },
    { label: "Account Username", val: ev.username || "(empty)", mono: true },
    { label: "Invalid User Flag", val: ev.invalid_user ? "YES (Invalid)" : "NO (Valid)", badge: ev.invalid_user ? "badge-failure" : "badge-low" },
    { label: "Source IP", val: ev.src_ip || "N/A", mono: true },
    { label: "Source Port", val: ev.src_port || "N/A", mono: true },
    { label: "Host", val: ev.host || "unknown", mono: true },
    { label: "Program Service", val: `${ev.program || 'unknown'}[${ev.pid || '-'}]`, mono: true },
    { label: "Auth Method", val: ev.method || "N/A" },
    { label: "Activity Category", val: ev.activity || "authentication" },
  ];

  fields.forEach(f => {
    const item = document.createElement("div");
    item.className = "meta-item";
    const lbl = document.createElement("span");
    lbl.className = "meta-label";
    lbl.textContent = f.label;
    const val = document.createElement("span");
    val.className = "meta-value" + (f.mono ? " mono-cell" : "");
    if (f.badge) {
      val.innerHTML = `<span class="badge ${f.badge}">${escapeHtml(f.val)}</span>`;
    } else {
      val.textContent = f.val;
    }
    item.appendChild(lbl);
    item.appendChild(val);
    metaGrid.appendChild(item);
  });
  metaCard.appendChild(metaGrid);
  content.appendChild(metaCard);

  // Raw Verbatim Log Section
  const rawCard = document.createElement("div");
  rawCard.className = "drawer-section";
  const rawTitle = document.createElement("div");
  rawTitle.className = "drawer-section-title";
  rawTitle.textContent = "Verbatim Raw Log Entry";
  rawCard.appendChild(rawTitle);

  const rawBox = document.createElement("pre");
  rawBox.className = "code-box";
  rawBox.textContent = ev.raw_message || "(Empty raw log)";
  rawCard.appendChild(rawBox);
  content.appendChild(rawCard);

  body.appendChild(content);
}

function closeEventDrawer() {
  const drawer = document.getElementById("event-drawer");
  if (drawer) {
    drawer.style.display = "none";
  }
}

function renderFilterChips(filters) {
  const container = document.getElementById("event-filter-chips");
  if (!container) return;
  container.innerHTML = "";

  const chips = [];
  if (filters.q) chips.push({ label: `Search: "${filters.q}"`, clearKey: "search" });
  if (filters.ip) chips.push({ label: `IP: ${filters.ip}`, clearKey: "ip" });
  if (filters.user) chips.push({ label: `User: ${filters.user}`, clearKey: "user" });
  if (filters.outcome) chips.push({ label: `Outcome: ${filters.outcome}`, clearKey: "outcome" });
  if (filters.timerange && filters.timerange !== "all") {
    chips.push({ label: `Window: ${filters.timerange}`, clearKey: "timerange" });
  }

  if (!chips.length) return;

  chips.forEach(c => {
    const chip = document.createElement("span");
    chip.className = "filter-chip";
    chip.textContent = c.label;

    const btn = document.createElement("button");
    btn.className = "filter-chip-remove";
    btn.setAttribute("aria-label", `Remove filter ${c.label}`);
    btn.textContent = "×";
    btn.onclick = () => {
      if (c.clearKey === "search") document.getElementById("filter-event-search").value = "";
      if (c.clearKey === "ip") document.getElementById("filter-event-ip").value = "";
      if (c.clearKey === "user") document.getElementById("filter-event-user").value = "";
      if (c.clearKey === "outcome") document.getElementById("filter-event-outcome").value = "";
      if (c.clearKey === "timerange") document.getElementById("filter-event-timerange").value = "all";
      state.eventsPage = 0;
      loadEvents();
    };

    chip.appendChild(btn);
    container.appendChild(chip);
  });
}

async function loadEvents() {
  const q = document.getElementById("filter-event-search")?.value.trim() || "";
  const ip = document.getElementById("filter-event-ip")?.value.trim() || "";
  const user = document.getElementById("filter-event-user")?.value.trim() || "";
  const outcome = document.getElementById("filter-event-outcome")?.value || "";
  const timerange = document.getElementById("filter-event-timerange")?.value || "all";

  let startTime = "";
  const nowMs = Date.now();
  if (timerange === "1h") {
    startTime = new Date(nowMs - 3600 * 1000).toISOString();
  } else if (timerange === "24h") {
    startTime = new Date(nowMs - 24 * 3600 * 1000).toISOString();
  } else if (timerange === "7d") {
    startTime = new Date(nowMs - 7 * 24 * 3600 * 1000).toISOString();
  }

  renderFilterChips({ q, ip, user, outcome, timerange });

  let url = `/api/v1/events?limit=${state.eventsLimit}&offset=${state.eventsPage * state.eventsLimit}`;
  if (q) url += `&q=${encodeURIComponent(q)}`;
  if (ip) url += `&src_ip=${encodeURIComponent(ip)}`;
  if (user) url += `&username=${encodeURIComponent(user)}`;
  if (outcome) url += `&outcome=${encodeURIComponent(outcome)}`;
  if (startTime) url += `&start_time=${encodeURIComponent(startTime)}`;

  try {
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) return handleLogout();
    const data = await res.json();
    const tbody = document.getElementById("events-table-body");
    const countLabel = document.getElementById("events-count-label");
    if (countLabel) countLabel.textContent = `${data.total} total events`;

    currentLoadedEvents = data.events || [];

    if (eventSortAsc) {
      currentLoadedEvents.sort((a, b) => (a.timestamp > b.timestamp ? 1 : -1));
    } else {
      currentLoadedEvents.sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
    }

    const total = data.total || 0;
    const startIdx = total === 0 ? 0 : state.eventsPage * state.eventsLimit + 1;
    const endIdx = Math.min((state.eventsPage + 1) * state.eventsLimit, total);
    const totalPages = Math.max(1, Math.ceil(total / state.eventsLimit));

    const pageInfo = document.getElementById("events-pagination-info");
    if (pageInfo) pageInfo.textContent = `Showing ${startIdx}–${endIdx} of ${total} events`;

    const pageIndicator = document.getElementById("events-page-indicator");
    if (pageIndicator) pageIndicator.textContent = `Page ${state.eventsPage + 1} of ${totalPages}`;

    const prevBtn = document.getElementById("btn-events-prev");
    if (prevBtn) prevBtn.disabled = state.eventsPage === 0;

    const nextBtn = document.getElementById("btn-events-next");
    if (nextBtn) nextBtn.disabled = (state.eventsPage + 1) >= totalPages;

    if (!currentLoadedEvents.length) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color: var(--text-dim); padding: 2rem;">No matching events found for current filters</td></tr>`;
      return;
    }

    tbody.innerHTML = "";
    currentLoadedEvents.forEach((e, idx) => {
      const outcomeClass = e.outcome === 'success' ? 'badge-success' : 'badge-failure';
      const tr = document.createElement("tr");
      tr.className = "clickable-row";
      tr.tabIndex = 0;
      tr.setAttribute("role", "button");
      tr.setAttribute("aria-label", `View event details for ${e.username || 'unknown'} from ${e.src_ip || 'unknown'}`);
      tr.dataset.eventIndex = String(idx);

      tr.innerHTML = `
        <td class="mono-cell">${escapeHtml(e.timestamp)}</td>
        <td><span class="badge ${outcomeClass}">${escapeHtml(e.outcome)}</span></td>
        <td>
          <strong style="color:var(--text-primary);">${escapeHtml(e.username || "(empty)")}</strong> 
          ${e.invalid_user ? '<span class="badge badge-failure" style="font-size:0.6rem; margin-left:0.25rem;">INVALID</span>' : ''}
        </td>
        <td class="mono-cell clickable-ip" title="Click to filter by this IP">${escapeHtml(e.src_ip || "-")}</td>
        <td class="mono-cell">${escapeHtml(e.src_port || "-")}</td>
        <td>${escapeHtml(e.program)}[${escapeHtml(e.pid || "-")}]</td>
        <td>${escapeHtml(e.method || "-")}</td>
        <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">
          ${escapeHtml(e.raw_message || "-")}
        </td>
      `;

      const ipTd = tr.querySelector(".clickable-ip");
      if (ipTd && e.src_ip) {
        ipTd.addEventListener("click", (evt) => {
          evt.stopPropagation();
          const ipInput = document.getElementById("filter-event-ip");
          if (ipInput) ipInput.value = e.src_ip;
          state.eventsPage = 0;
          loadEvents();
        });
      }

      tr.addEventListener("click", () => openEventDrawer(idx));
      tr.addEventListener("keydown", (evt) => {
        if (evt.target === tr && (evt.key === "Enter" || evt.key === " ")) {
          evt.preventDefault();
          openEventDrawer(idx);
        }
      });

      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load events:", err);
    showToast("Error loading events: " + err.message, "error");
  }
}

// -------------------------------------------------------------
// Rules Catalog View
// -------------------------------------------------------------
async function loadRules() {
  try {
    const res = await fetch("/api/v1/rules", { headers: authHeaders() });
    const data = await res.json();
    state.loadedRules = data.rules || [];
    renderRulesCatalog();
  } catch (err) {
    console.error("Failed to load rules:", err);
  }
}

function renderRulesCatalog() {
  const container = document.getElementById("rules-grid-container");
  if (!container) return;

  const searchInput = document.getElementById("filter-rule-search");
  const query = searchInput ? searchInput.value.toLowerCase().trim() : "";

  const filtered = state.loadedRules.filter(r => {
    if (!query) return true;
    return (
      (r.name && r.name.toLowerCase().includes(query)) ||
      (r.description && r.description.toLowerCase().includes(query)) ||
      (r.mitre_attack && r.mitre_attack.toLowerCase().includes(query)) ||
      (r.severity && r.severity.toLowerCase().includes(query))
    );
  });

  if (!filtered.length) {
    container.innerHTML = `<p style="color: var(--text-dim); padding:1rem; text-align:center;">No detection rules match criteria.</p>`;
    return;
  }

  let html = `<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem;">`;
  for (const r of filtered) {
    const mitreUrl = getMitreUrl(r.mitre_attack);
    const mitreHtml = mitreUrl
      ? `<a href="${mitreUrl}" target="_blank" rel="noopener noreferrer" class="mitre-pill">${escapeHtml(r.mitre_attack)} ↗</a>`
      : `<span class="mitre-pill">${escapeHtml(r.mitre_attack)}</span>`;

    html += `
      <div class="card" style="display:flex; flex-direction:column; justify-content:space-between;">
        <div>
          <div class="card-header" style="margin-bottom:0.6rem; padding-bottom:0.5rem;">
            <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
              <span class="badge badge-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span>
              <strong style="font-size:0.875rem; color:var(--text-primary);">${escapeHtml(r.name)}</strong>
            </div>
            ${mitreHtml}
          </div>
          <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.85rem; line-height:1.4;">${escapeHtml(r.description)}</p>
        </div>
        <div style="background:var(--bg-surface-elevated); padding:0.6rem 0.75rem; border-radius:var(--radius-sm); border:1px solid var(--border-subtle); display:flex; flex-wrap:wrap; gap:0.75rem; font-size:0.725rem; color:var(--text-dim); font-family:var(--font-mono);">
          <span><strong>TYPE:</strong> ${escapeHtml(r.type)}</span>
          <span><strong>THRESHOLD:</strong> ${escapeHtml(r.threshold)}</span>
          <span><strong>WINDOW:</strong> ${escapeHtml(r.window_seconds)}s</span>
          <span><strong>GROUP BY:</strong> ${escapeHtml(JSON.stringify(r.group_by))}</span>
        </div>
      </div>
    `;
  }
  html += `</div>`;
  container.innerHTML = html;
}

// -------------------------------------------------------------
// Ingestion Console & Attack Simulation Scenarios
// -------------------------------------------------------------
function setIngestSample(scenarioType) {
  let lines = [];
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const dStr = "Oct 09";

  if (scenarioType === "hydra") {
    lines = [
      `${dStr} 10:00:01 metasploitable sshd[6101]: Failed password for root from 192.168.18.205 port 42100 ssh2`,
      `${dStr} 10:00:02 metasploitable sshd[6102]: Failed password for root from 192.168.18.205 port 42102 ssh2`,
      `${dStr} 10:00:03 metasploitable sshd[6103]: Failed password for root from 192.168.18.205 port 42104 ssh2`,
      `${dStr} 10:00:04 metasploitable sshd[6104]: Failed password for root from 192.168.18.205 port 42106 ssh2`,
      `${dStr} 10:00:05 metasploitable sshd[6105]: Failed password for root from 192.168.18.205 port 42108 ssh2`,
      `${dStr} 10:00:06 metasploitable sshd[6106]: Failed password for root from 192.168.18.205 port 42110 ssh2`,
    ];
  } else if (scenarioType === "spray") {
    lines = [
      `${dStr} 11:10:01 metasploitable sshd[7101]: Failed password for admin from 10.0.5.88 port 51000 ssh2`,
      `${dStr} 11:10:02 metasploitable sshd[7102]: Failed password for msfadmin from 10.0.5.88 port 51002 ssh2`,
      `${dStr} 11:10:03 metasploitable sshd[7103]: Failed password for postgres from 10.0.5.88 port 51004 ssh2`,
      `${dStr} 11:10:04 metasploitable sshd[7104]: Failed password for user from 10.0.5.88 port 51006 ssh2`,
    ];
  } else if (scenarioType === "invalid") {
    lines = [
      `${dStr} 12:20:01 metasploitable sshd[8101]: Failed password for invalid user ghost from 172.16.1.40 port 33100 ssh2`,
      `${dStr} 12:20:02 metasploitable sshd[8102]: Failed password for invalid user phantom from 172.16.1.40 port 33102 ssh2`,
      `${dStr} 12:20:03 metasploitable sshd[8103]: Failed password for invalid user shadow from 172.16.1.40 port 33104 ssh2`,
      `${dStr} 12:20:04 metasploitable sshd[8104]: Failed password for invalid user daemon from 172.16.1.40 port 33106 ssh2`,
    ];
  } else if (scenarioType === "breach") {
    lines = [
      `${dStr} 14:00:01 metasploitable sshd[9101]: Failed password for root from 198.51.100.22 port 58001 ssh2`,
      `${dStr} 14:00:02 metasploitable sshd[9102]: Failed password for root from 198.51.100.22 port 58002 ssh2`,
      `${dStr} 14:00:03 metasploitable sshd[9103]: Failed password for root from 198.51.100.22 port 58003 ssh2`,
      `${dStr} 14:00:04 metasploitable sshd[9104]: Accepted password for root from 198.51.100.22 port 58004 ssh2`,
    ];
  } else if (scenarioType === "legit") {
    lines = [
      `${dStr} 09:15:20 metasploitable sshd[4001]: Accepted password for msfadmin from 192.168.1.105 port 55400 ssh2`,
      `${dStr} 09:15:25 metasploitable sshd[4002]: Received disconnect from 192.168.1.105: 11: disconnected by user`,
    ];
  }

  const inputArea = document.getElementById("ingest-input-text");
  if (inputArea) inputArea.value = lines.join("\n");
  showToast(`Loaded ${scenarioType} attack preset into ingestion buffer`, "info");
}

async function handleIngestSubmit(e) {
  e.preventDefault();
  const rawText = document.getElementById("ingest-input-text").value.trim();
  const apiKey = document.getElementById("ingest-api-key").value.trim() || "pysiem-ingest-secret-key-12345";
  const container = document.getElementById("ingest-response-container");
  const summaryCards = document.getElementById("ingest-summary-cards");
  const detailsBox = document.getElementById("ingest-details-collapsible");
  const resultBox = document.getElementById("ingest-result");

  if (!rawText) return;

  const lines = rawText.split("\n").map(l => l.trim()).filter(Boolean);

  try {
    const res = await fetch("/api/v1/ingest", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": apiKey
      },
      body: JSON.stringify({ lines })
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Ingestion request failed");
    }
    const data = await res.json();

    if (container) container.style.display = "block";

    if (summaryCards) {
      summaryCards.style.display = "flex";
      summaryCards.innerHTML = `
        <span class="badge badge-success" style="font-size:0.775rem; padding:0.35rem 0.65rem;">✓ ${escapeHtml(data.events_stored || 0)} Events Normalized</span>
        <span class="badge ${data.alerts_generated ? 'badge-critical' : 'badge-low'}" style="font-size:0.775rem; padding:0.35rem 0.65rem;">${escapeHtml(data.alerts_generated || 0)} Alerts Generated</span>
        <span class="badge badge-low" style="font-size:0.775rem; padding:0.35rem 0.65rem;">${escapeHtml(data.ignored_count || 0)} Ignored Noise</span>
        <span class="badge badge-low" style="font-size:0.775rem; padding:0.35rem 0.65rem;">${escapeHtml(data.unrecognized_count || 0)} Unrecognized</span>
      `;
    }

    if (detailsBox) detailsBox.style.display = "block";
    if (resultBox) resultBox.textContent = JSON.stringify(data, null, 2);

    showToast(`Successfully ingested ${data.events_stored || 0} events (${data.alerts_generated || 0} alerts)`, "success");
    loadDashboard();
  } catch (err) {
    if (container) container.style.display = "block";
    if (summaryCards) {
      summaryCards.style.display = "flex";
      summaryCards.innerHTML = `<span class="badge badge-failure">Ingestion Error: ${escapeHtml(err.message)}</span>`;
    }
    if (resultBox) resultBox.textContent = err.message;
    showToast("Ingestion failed: " + err.message, "error");
  }
}

// -------------------------------------------------------------
// Theme Management (Light / Dark Mode)
// -------------------------------------------------------------
function initTheme() {
  const saved = localStorage.getItem("pysiem_theme") || "dark";
  document.body.classList.toggle("light-theme", saved === "light");
  const toggleBtn = document.getElementById("btn-theme-toggle");
  if (toggleBtn) {
    toggleBtn.textContent = saved === "light" ? "🌙 Dark Mode" : "☀️ Light Mode";
  }
}

function toggleTheme() {
  const isLight = document.body.classList.toggle("light-theme");
  const newTheme = isLight ? "light" : "dark";
  localStorage.setItem("pysiem_theme", newTheme);
  const toggleBtn = document.getElementById("btn-theme-toggle");
  if (toggleBtn) {
    toggleBtn.textContent = isLight ? "🌙 Dark Mode" : "☀️ Light Mode";
  }
  showToast(`Switched to ${newTheme} theme`, "info");
}

// -------------------------------------------------------------
// Initialization & Global Event Listeners
// -------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  // Forms & Auth
  const loginForm = document.getElementById("login-form");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  const logoutBtn = document.getElementById("btn-logout");
  if (logoutBtn) logoutBtn.addEventListener("click", handleLogout);

  const ingestForm = document.getElementById("ingest-form");
  if (ingestForm) ingestForm.addEventListener("submit", handleIngestSubmit);

  // Attack Presets
  const btnHydra = document.getElementById("btn-sample-attack");
  if (btnHydra) btnHydra.addEventListener("click", () => setIngestSample("hydra"));

  const btnSpray = document.getElementById("btn-sample-spray");
  if (btnSpray) btnSpray.addEventListener("click", () => setIngestSample("spray"));

  const btnInvalid = document.getElementById("btn-sample-invalid");
  if (btnInvalid) btnInvalid.addEventListener("click", () => setIngestSample("invalid"));

  const btnBreach = document.getElementById("btn-sample-breach");
  if (btnBreach) btnBreach.addEventListener("click", () => setIngestSample("breach"));

  const btnLegit = document.getElementById("btn-sample-legit");
  if (btnLegit) btnLegit.addEventListener("click", () => setIngestSample("legit"));

  // Drawer accessibility listeners
  const closeAlertBtn = document.getElementById("btn-close-alert-drawer");
  if (closeAlertBtn) closeAlertBtn.addEventListener("click", closeAlertDrawer);

  const alertDrawerOverlay = document.getElementById("alert-drawer");
  if (alertDrawerOverlay) {
    alertDrawerOverlay.addEventListener("click", (e) => {
      if (e.target === alertDrawerOverlay) closeAlertDrawer();
    });
  }

  const closeEventBtn = document.getElementById("btn-close-event-drawer");
  if (closeEventBtn) closeEventBtn.addEventListener("click", closeEventDrawer);

  const eventDrawerOverlay = document.getElementById("event-drawer");
  if (eventDrawerOverlay) {
    eventDrawerOverlay.addEventListener("click", (e) => {
      if (e.target === eventDrawerOverlay) closeEventDrawer();
    });
  }

  // Keyboard shortcut: Escape closes drawers
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeAlertDrawer();
      closeEventDrawer();
    }
  });

  // Drawer status actions
  const statusActions = document.getElementById("alert-drawer-status-actions");
  if (statusActions) {
    statusActions.querySelectorAll("button").forEach(btn => {
      btn.addEventListener("click", () => {
        if (currentActiveAlertId && btn.dataset.status) {
          updateAlertStatus(currentActiveAlertId, btn.dataset.status);
        }
      });
    });
  }

  // Dashboard KPI Cards & Controls
  const refreshBtn = document.getElementById("btn-dashboard-refresh");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadDashboard();
      showToast("Dashboard telemetry refreshed", "info");
    });
  }

  const btnDemo = document.getElementById("btn-telemetry-demo");
  if (btnDemo) {
    btnDemo.addEventListener("click", () => {
      state.telemetryMode = "demo";
      loadDashboard();
      showToast("Switched to Demo Telemetry (60-Min Dataset)", "info");
    });
  }

  const btnLive = document.getElementById("btn-telemetry-live");
  if (btnLive) {
    btnLive.addEventListener("click", () => {
      state.telemetryMode = "live";
      loadDashboard();
      showToast("Switched to Live Database Telemetry", "info");
    });
  }

  const viewAllBtn = document.getElementById("btn-view-all-alerts");
  if (viewAllBtn) {
    viewAllBtn.addEventListener("click", () => switchTab("alerts"));
  }

  const kpiCritHigh = document.getElementById("kpi-card-critical-high");
  if (kpiCritHigh) {
    const handleCritHigh = () => {
      switchTab("alerts");
      const sevSelect = document.getElementById("filter-alert-severity");
      if (sevSelect) {
        sevSelect.value = "high";
        loadAlerts();
      }
    };
    kpiCritHigh.addEventListener("click", handleCritHigh);
    kpiCritHigh.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleCritHigh();
      }
    });
  }

  const kpiOpenAlerts = document.getElementById("kpi-card-open-alerts");
  if (kpiOpenAlerts) {
    const handleOpen = () => {
      switchTab("alerts");
      const statusSelect = document.getElementById("filter-alert-status");
      if (statusSelect) {
        statusSelect.value = "new";
        loadAlerts();
      }
    };
    kpiOpenAlerts.addEventListener("click", handleOpen);
    kpiOpenAlerts.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleOpen();
      }
    });
  }

  const kpiTotalAlerts = document.getElementById("kpi-card-total-alerts");
  if (kpiTotalAlerts) {
    const handleTotal = () => {
      switchTab("alerts");
      const sevSelect = document.getElementById("filter-alert-severity");
      const statusSelect = document.getElementById("filter-alert-status");
      if (sevSelect) sevSelect.value = "";
      if (statusSelect) statusSelect.value = "";
      loadAlerts();
    };
    kpiTotalAlerts.addEventListener("click", handleTotal);
    kpiTotalAlerts.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleTotal();
      }
    });
  }

  const kpiTotalEvents = document.getElementById("kpi-card-total-events");
  if (kpiTotalEvents) {
    const handleEvents = () => switchTab("events");
    kpiTotalEvents.addEventListener("click", handleEvents);
    kpiTotalEvents.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleEvents();
      }
    });
  }

  // Event Explorer Controls
  const applyEvFiltersBtn = document.getElementById("btn-apply-event-filters");
  if (applyEvFiltersBtn) {
    applyEvFiltersBtn.addEventListener("click", () => {
      state.eventsPage = 0;
      loadEvents();
    });
  }

  // Allow Enter key to trigger filters in Event Explorer input fields
  ["filter-event-search", "filter-event-ip", "filter-event-user"].forEach(id => {
    const elem = document.getElementById(id);
    if (elem) {
      elem.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          state.eventsPage = 0;
          loadEvents();
        }
      });
    }
  });

  const clearEvFiltersBtn = document.getElementById("btn-clear-event-filters");
  if (clearEvFiltersBtn) {
    clearEvFiltersBtn.addEventListener("click", () => {
      document.getElementById("filter-event-search").value = "";
      document.getElementById("filter-event-ip").value = "";
      document.getElementById("filter-event-user").value = "";
      document.getElementById("filter-event-outcome").value = "";
      const trSelect = document.getElementById("filter-event-timerange");
      if (trSelect) trSelect.value = "all";
      state.eventsPage = 0;
      loadEvents();
      showToast("Event filters cleared", "info");
    });
  }

  const refreshEventsBtn = document.getElementById("btn-events-refresh");
  if (refreshEventsBtn) {
    refreshEventsBtn.addEventListener("click", () => {
      loadEvents();
      showToast("Event list refreshed", "info");
    });
  }

  const timeRangeSelect = document.getElementById("filter-event-timerange");
  if (timeRangeSelect) {
    timeRangeSelect.addEventListener("change", () => {
      state.eventsPage = 0;
      loadEvents();
    });
  }

  const thTimestamp = document.getElementById("th-event-timestamp");
  if (thTimestamp) {
    thTimestamp.addEventListener("click", () => {
      eventSortAsc = !eventSortAsc;
      const indicator = document.getElementById("sort-timestamp-indicator");
      if (indicator) indicator.textContent = eventSortAsc ? "▲" : "▼";
      loadEvents();
    });
  }

  const prevEventsBtn = document.getElementById("btn-events-prev");
  if (prevEventsBtn) {
    prevEventsBtn.addEventListener("click", () => {
      if (state.eventsPage > 0) {
        state.eventsPage--;
        loadEvents();
      }
    });
  }

  const nextEventsBtn = document.getElementById("btn-events-next");
  if (nextEventsBtn) {
    nextEventsBtn.addEventListener("click", () => {
      state.eventsPage++;
      loadEvents();
    });
  }

  // Rules Catalog Search Filter
  const ruleSearchInput = document.getElementById("filter-rule-search");
  if (ruleSearchInput) {
    ruleSearchInput.addEventListener("input", renderRulesCatalog);
  }

  // Theme Toggle Button
  const themeToggleBtn = document.getElementById("btn-theme-toggle");
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener("click", toggleTheme);
  }

  // Navigation Tabs
  document.querySelectorAll(".nav-tab").forEach(tab => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });

  initTheme();
  checkAuth();
});
