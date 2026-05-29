// API client configuration
const API_BASE = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") ? "http://localhost:8000" : "";

// State manager
const state = {
  token: localStorage.getItem("token") || null,
  user: null,
  activeTab: "dashboard",
  reports: [],
  dashboardStats: null,
  expandedFindings: {}
};

// ── Theme bootstrap (runs before first paint) ──────────────────────────────
(function () {
  const saved = localStorage.getItem("theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
})();

// Initialization
document.addEventListener("DOMContentLoaded", () => {
  // Apply saved theme and sync icons
  const savedTheme = localStorage.getItem("theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcons(savedTheme);

  setupEventListeners();
  initApp();

  // Re-render Lucide icons after DOM is ready
  if (window.lucide) window.lucide.createIcons();
});

// App flow routers
async function initApp() {
  if (state.token) {
    const success = await fetchUserProfile();
    if (success) {
      showMainApp();
      switchTab("dashboard");
    } else {
      showAuthScreen();
    }
  } else {
    showAuthScreen();
  }
}

function showAuthScreen() {
  document.getElementById("auth-view").style.display = "flex";
  document.getElementById("app-view").style.display = "none";
}

function showMainApp() {
  document.getElementById("auth-view").style.display = "none";
  document.getElementById("app-view").style.display = "flex";
  
  // Set user info
  document.getElementById("nav-user-name").textContent = state.user.username;
  document.getElementById("nav-user-role").textContent = state.user.role.toUpperCase();
  
  // Admin privileges check
  const isAdmin = state.user.role === "admin";
  const adminTabLink = document.getElementById("sidebar-admin-link");
  if (isAdmin) {
    adminTabLink.style.display = "flex";
  } else {
    adminTabLink.style.display = "none";
  }
}

// ── Theme management ─────────────────────────────────────────────────────────
function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const next = current === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
  updateThemeIcons(next);
}

function updateThemeIcons(theme) {
  // Landing page icon
  const landingIcon = document.getElementById("landing-theme-icon");
  if (landingIcon) {
    landingIcon.setAttribute("data-lucide", theme === "dark" ? "sun" : "moon");
  }
  // Dashboard navbar icon
  const appIcon = document.getElementById("app-theme-icon");
  if (appIcon) {
    appIcon.setAttribute("data-lucide", theme === "dark" ? "sun" : "moon");
  }
  // Re-render icons after updating data-lucide attribute
  if (window.lucide) window.lucide.createIcons();
}

// ── Auth Modal helpers (exposed globally for inline onclick) ─────────────────
window.showAuthModal = function (type) {
  const modal = document.getElementById("auth-modal");
  const loginCard  = document.getElementById("login-card");
  const registerCard = document.getElementById("register-card");
  if (!modal) return;

  // Clear any previous errors
  ["login-error", "register-error"].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.style.display = "none"; el.textContent = ""; }
  });

  if (type === "register") {
    loginCard.style.display  = "none";
    registerCard.style.display = "block";
  } else {
    loginCard.style.display  = "block";
    registerCard.style.display = "none";
  }
  modal.style.display = "flex";
};

window.hideAuthModal = function () {
  const modal = document.getElementById("auth-modal");
  if (modal) modal.style.display = "none";
};

// ── Google Auth simulation ────────────────────────────────────────────────────
async function handleGoogleAuth(flow) {
  // Simulate Google OAuth: auto-register or auto-login a demo Google user.
  const googleUser = {
    username: "google_user",
    email: "demo@gmail.com",
    password: "GoogleDemo@2025!",
    full_name: "Google Demo User"
  };

  const btn = flow === "login"
    ? document.getElementById("google-login-btn")
    : document.getElementById("google-register-btn");
  const errorId = flow === "login" ? "login-error" : "register-error";
  const errorDiv = document.getElementById(errorId);

  if (btn) { btn.disabled = true; btn.textContent = "Connecting…"; }

  // First try to login; if 401 → register then login
  try {
    const tryLogin = async () => {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: googleUser.username, password: googleUser.password })
      });
      return res;
    };

    let res = await tryLogin();

    if (res.status === 401 || res.status === 422) {
      // Account doesn't exist yet — register first
      const regRes = await fetch(`${API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(googleUser)
      });
      if (!regRes.ok) {
        const regData = await regRes.json();
        throw new Error(regData.detail || "Google sign-up failed");
      }
      res = await tryLogin();
    }

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Google auth failed");

    localStorage.setItem("token", data.access_token);
    state.token = data.access_token;
    state.user = data.user;

    window.hideAuthModal();
    showMainApp();
    switchTab("dashboard");
  } catch (err) {
    if (errorDiv) {
      errorDiv.textContent = err.message;
      errorDiv.style.display = "block";
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" width="16" height="16" style="fill:currentColor;flex-shrink:0"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335"/></svg> Continue with Google`;
    }
  }
}

// Global Event listeners setup
function setupEventListeners() {
  // ── Theme toggles ──────────────────────────────────────────────────────────
  const landingToggle = document.getElementById("landing-theme-toggle");
  if (landingToggle) landingToggle.addEventListener("click", toggleTheme);
  const appToggle = document.getElementById("app-theme-toggle");
  if (appToggle) appToggle.addEventListener("click", toggleTheme);

  // ── Auth modal backdrop close ──────────────────────────────────────────────
  const authModal = document.getElementById("auth-modal");
  if (authModal) {
    authModal.addEventListener("click", (e) => {
      if (e.target === authModal) window.hideAuthModal();
    });
  }

  // ── Google auth buttons ───────────────────────────────────────────────────
  const googleLoginBtn = document.getElementById("google-login-btn");
  if (googleLoginBtn) googleLoginBtn.addEventListener("click", () => handleGoogleAuth("login"));
  const googleRegisterBtn = document.getElementById("google-register-btn");
  if (googleRegisterBtn) googleRegisterBtn.addEventListener("click", () => handleGoogleAuth("register"));

  // ── Tab navigation ────────────────────────────────────────────────────────
  document.querySelectorAll(".sidebar-link").forEach(link => {
    link.addEventListener("click", (e) => {
      const tabName = e.currentTarget.getAttribute("data-tab");
      switchTab(tabName);
    });
  });

  // Auth Card Switches
  document.getElementById("switch-to-register").addEventListener("click", () => {
    document.getElementById("login-card").style.display = "none";
    document.getElementById("register-card").style.display = "block";
  });
  document.getElementById("switch-to-login").addEventListener("click", () => {
    document.getElementById("register-card").style.display = "none";
    document.getElementById("login-card").style.display = "block";
  });

  // Login action handler
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errorDiv = document.getElementById("login-error");
    errorDiv.style.display = "none";
    
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;
    const submitBtn = e.target.querySelector("button[type=submit]");
    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Authenticating..."; }

    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Authentication failed");

      localStorage.setItem("token", data.access_token);
      state.token = data.access_token;
      state.user = data.user;
      
      window.hideAuthModal();
      showMainApp();
      switchTab("dashboard");
    } catch (err) {
      errorDiv.textContent = err.message;
      errorDiv.style.display = "block";
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Authenticate "; }
    }
  });

  // Register action handler
  document.getElementById("register-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const errorDiv = document.getElementById("register-error");
    errorDiv.style.display = "none";

    const fullName = document.getElementById("register-name").value.trim();
    const email = document.getElementById("register-email").value.trim();
    const username = document.getElementById("register-username").value.trim();
    const password = document.getElementById("register-password").value;
    const confirmPassword = document.getElementById("register-password-confirm").value;
    const submitBtn = e.target.querySelector("button[type=submit]");

    // Client-side validation
    if (password !== confirmPassword) {
      errorDiv.textContent = "Passwords do not match.";
      errorDiv.style.display = "block";
      return;
    }
    if (password.length < 8) {
      errorDiv.textContent = "Password must be at least 8 characters.";
      errorDiv.style.display = "block";
      return;
    }

    if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = "Creating Account..."; }

    try {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, username, password, full_name: fullName })
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Registration failed");

      localStorage.setItem("token", data.access_token);
      state.token = data.access_token;
      state.user = data.user;

      window.hideAuthModal();
      showMainApp();
      switchTab("dashboard");
    } catch (err) {
      errorDiv.textContent = err.message;
      errorDiv.style.display = "block";
    } finally {
      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = "Create Account"; }
    }
  });

  // Logout handler
  document.getElementById("logout-button").addEventListener("click", () => {
    localStorage.removeItem("token");
    state.token = null;
    state.user = null;
    showAuthScreen();
    if (window.lucide) window.lucide.createIcons();
  });

  // Web scan trigger
  document.getElementById("web-scan-form").addEventListener("submit", handleWebScan);

  // APK scan trigger
  document.getElementById("apk-scan-form").addEventListener("submit", handleAPKScan);

  // APK File drag drop events
  const fileInput = document.getElementById("apk-scan-file");
  const dropzoneText = document.getElementById("dropzone-text");
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      dropzoneText.textContent = `Selected: ${fileInput.files[0].name}`;
    }
  });

  // Sync / Refresh buttons
  document.querySelectorAll(".refresh-telemetry-btn").forEach(b => b.addEventListener("click", fetchDashboardStats));
  document.querySelectorAll(".refresh-reports-btn").forEach(b => b.addEventListener("click", fetchReports));
  document.querySelectorAll(".refresh-admin-btn").forEach(b => b.addEventListener("click", fetchAdminConsoleData));
}

// Fetch user metadata profile
async function fetchUserProfile() {
  try {
    const response = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    state.user = await response.json();
    return true;
  } catch (err) {
    localStorage.removeItem("token");
    state.token = null;
    return false;
  }
}

// Tab navigation handler
function switchTab(tabName) {
  state.activeTab = tabName;
  
  // Update sidebar UI links
  document.querySelectorAll(".sidebar-link").forEach(link => {
    if (link.getAttribute("data-tab") === tabName) {
      link.classList.add("active");
    } else {
      link.classList.remove("active");
    }
  });

  // Update panels UI
  document.querySelectorAll(".view-panel").forEach(panel => {
    if (panel.id === `${tabName}-view`) {
      panel.classList.add("active");
    } else {
      panel.classList.remove("active");
    }
  });

  // Trigger loads based on active view tab
  if (tabName === "dashboard") {
    fetchDashboardStats();
  } else if (tabName === "reports") {
    fetchReports();
  } else if (tabName === "admin") {
    fetchAdminConsoleData();
  }
}

// Dashboard statistics loader
async function fetchDashboardStats() {
  try {
    const response = await fetch(`${API_BASE}/api/dashboard/stats`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    const stats = await response.json();
    state.dashboardStats = stats;
    
    // Render stats
    document.getElementById("stat-scans").textContent = stats.total_scans;
    document.getElementById("stat-score").textContent = `${stats.average_score}/100`;
    document.getElementById("stat-vulns").textContent = stats.total_vulnerabilities;
    document.getElementById("stat-criticals").textContent = stats.critical_issues;

    renderSeverityChart(stats.severity_distribution);
    renderRecentScans(stats.recent_scans);
  } catch (err) {
    console.error("Telemetry failed:", err);
  }
}

// Render dynamic severity distribution
function renderSeverityChart(distribution) {
  const container = document.getElementById("severity-chart-container");
  container.innerHTML = "";

  const items = [
    { label: "Critical", value: distribution.critical, color: "var(--color-critical)" },
    { label: "High", value: distribution.high, color: "var(--color-high)" },
    { label: "Medium", value: distribution.medium, color: "var(--color-medium)" },
    { label: "Low", value: distribution.low, color: "var(--color-low)" }
  ];

  const maxVal = Math.max(...items.map(i => i.value), 1);

  items.forEach(item => {
    const heightPercent = Math.min((item.value / maxVal) * 100, 100);
    const col = document.createElement("div");
    col.style.display = "flex";
    col.style.flexDirection = "column";
    col.style.alignItems = "center";
    col.style.gap = "0.5rem";
    col.style.flex = "1";

    col.innerHTML = `
      <span style="font-size: 0.8rem; font-weight: 700; color: var(--color-text-primary);">${item.value}</span>
      <div style="width: 32px; height: ${Math.max(heightPercent * 1.5, 8)}px; background: ${item.color}; border-radius: 6px 6px 0 0; transition: height 0.5s ease;"></div>
      <span style="font-size: 0.7rem; color: var(--color-text-secondary);">${item.label}</span>
    `;
    container.appendChild(col);
  });
}

// Render recent scan entries
function renderRecentScans(scans) {
  const list = document.getElementById("recent-scans-list");
  list.innerHTML = "";

  if (scans.length === 0) {
    list.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--color-text-muted); font-size: 0.85rem;">No security assessments recorded yet.</div>`;
    return;
  }

  scans.forEach(scan => {
    const entry = document.createElement("div");
    entry.style.display = "flex";
    entry.style.alignItems = "center";
    entry.style.justifyContent = "space-between";
    entry.style.padding = "1rem";
    entry.style.background = "var(--color-bg-elevated)";
    entry.style.border = "1px solid var(--color-border)";
    entry.style.borderRadius = "12px";

    const badgeClass = scan.scan_type === "web" ? "badge-info" : "badge-medium";
    
    entry.innerHTML = `
      <div style="display: flex; align-items: center; gap: 0.75rem;">
        <span class="badge ${badgeClass}">${scan.scan_type}</span>
        <div>
          <span style="font-weight: 600; font-size: 0.85rem; color: var(--color-text-primary); display: block;">${scan.target}</span>
          <span style="font-size: 0.7rem; color: var(--color-text-muted); display: block; margin-top: 0.15rem;">${new Date(scan.created_at).toLocaleString()}</span>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 1rem;">
        <div style="text-align: right;">
          <span style="font-size: 0.7rem; color: var(--color-text-muted); display: block;">Score</span>
          <span style="font-weight: 800; font-size: 0.95rem; color: var(--color-accent-light);">${scan.security_score}</span>
        </div>
      </div>
    `;
    list.appendChild(entry);
  });
}

// Launch Web scan operation
async function handleWebScan(e) {
  e.preventDefault();
  const urlInput = document.getElementById("web-scan-url").value;
  const depth = document.getElementById("web-scan-depth").value;
  
  const loading = document.getElementById("web-scan-loading");
  const resultsDiv = document.getElementById("web-scan-results");
  const form = document.getElementById("web-scan-form");

  loading.style.display = "flex";
  resultsDiv.style.display = "none";
  form.style.pointerEvents = "none";

  let targetUrl = urlInput.trim();
  if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
    targetUrl = "https://" + targetUrl;
  }

  try {
    const response = await fetch(`${API_BASE}/api/scans/web`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${state.token}`
      },
      body: JSON.stringify({ url: targetUrl, scan_depth: depth })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan request failed");

    renderScanResult("web", data);
  } catch (err) {
    alert(err.message);
  } finally {
    loading.style.display = "none";
    form.style.pointerEvents = "auto";
  }
}

// Launch APK decompilation and static scan
async function handleAPKScan(e) {
  e.preventDefault();
  const fileInput = document.getElementById("apk-scan-file");
  if (fileInput.files.length === 0) {
    alert("Please select an APK file to scan.");
    return;
  }

  const file = fileInput.files[0];
  const loading = document.getElementById("apk-scan-loading");
  const resultsDiv = document.getElementById("apk-scan-results");
  const form = document.getElementById("apk-scan-form");

  loading.style.display = "flex";
  resultsDiv.style.display = "none";
  form.style.pointerEvents = "none";

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch(`${API_BASE}/api/scans/apk`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${state.token}`
      },
      body: formData
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "APK Analysis failed");

    renderScanResult("apk", data);
  } catch (err) {
    alert(err.message);
  } finally {
    loading.style.display = "none";
    form.style.pointerEvents = "auto";
  }
}

// Render dynamic results (For both Web and APK)
function renderScanResult(type, result) {
  const container = document.getElementById(`${type}-scan-results`);
  container.innerHTML = "";
  container.style.display = "flex";

  const countsGridHtml = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem;">
      <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.15); padding: 1rem; border-radius: 12px; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 800; color: var(--color-critical);">${result.critical_count}</div>
        <span style="font-size: 0.65rem; color: var(--color-text-secondary); text-transform: uppercase;">Critical</span>
      </div>
      <div style="background: rgba(249, 115, 22, 0.08); border: 1px solid rgba(249, 115, 22, 0.15); padding: 1rem; border-radius: 12px; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 800; color: var(--color-high);">${result.high_count}</div>
        <span style="font-size: 0.65rem; color: var(--color-text-secondary); text-transform: uppercase;">High</span>
      </div>
      <div style="background: rgba(234, 179, 8, 0.08); border: 1px solid rgba(234, 179, 8, 0.15); padding: 1rem; border-radius: 12px; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 800; color: var(--color-medium);">${result.medium_count}</div>
        <span style="font-size: 0.65rem; color: var(--color-text-secondary); text-transform: uppercase;">Medium</span>
      </div>
      <div style="background: rgba(59, 130, 246, 0.08); border: 1px solid rgba(59, 130, 246, 0.15); padding: 1rem; border-radius: 12px; text-align: center;">
        <div style="font-size: 1.5rem; font-weight: 800; color: var(--color-low);">${result.low_count}</div>
        <span style="font-size: 0.65rem; color: var(--color-text-secondary); text-transform: uppercase;">Low</span>
      </div>
    </div>
  `;

  const severityClass = result.security_score >= 80 ? 'badge-low' : result.security_score >= 55 ? 'badge-medium' : 'badge-critical';

  let html = `
    <!-- Top Summary Banner -->
    <div class="glass-card" style="padding: 1.5rem; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h2 style="font-size: 1.25rem; font-weight: 800; color: var(--color-text-primary);">${result.target}</h2>
        <p style="font-size: 0.75rem; color: var(--color-text-muted); margin-top: 0.25rem;">Scan duration: ${result.scan_duration}s | Score: <span class="badge ${severityClass}">${result.security_score}</span></p>
      </div>
      <div style="display: flex; gap: 0.75rem;">
        <button class="btn btn-primary" onclick="compilePDFReport('${result.id}')">Compile Report</button>
        <a class="btn btn-secondary" href="/api/reports/export/${result.id}/json" target="_blank">Export JSON</a>
      </div>
    </div>

    <!-- Severity counts -->
    ${countsGridHtml}
  `;

  // Findings lists
  if (result.vulnerabilities.length === 0) {
    html += `
      <div class="glass-card" style="padding: 3rem; text-align: center; color: var(--color-text-secondary);">
        <i data-lucide="shield-check" style="width: 3rem; height: 3rem; color: #10b981; margin-bottom: 1rem;"></i>
        <div style="font-weight: 700; color: var(--color-text-primary);">No Vulnerabilities Detected</div>
        <p style="font-size: 0.8rem; margin-top: 0.25rem;">Configuration complies with security standard guidelines.</p>
      </div>
    `;
  } else {
    html += `<div style="display: flex; flex-direction: column; gap: 0.5rem;">`;
    result.vulnerabilities.forEach(vuln => {
      const vulnId = vuln.id || Math.random().toString(36).substr(2, 9);
      let severityBadge = "badge-info";
      if (vuln.severity.toLowerCase() === "critical") severityBadge = "badge-critical";
      else if (vuln.severity.toLowerCase() === "high") severityBadge = "badge-high";
      else if (vuln.severity.toLowerCase() === "medium") severityBadge = "badge-medium";
      else if (vuln.severity.toLowerCase() === "low") severityBadge = "badge-low";

      html += `
        <div class="details-item" id="vuln-card-${vulnId}">
          <div class="details-header" onclick="toggleDetailsCard('${vulnId}')">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <span class="badge ${severityBadge}">${vuln.severity}</span>
              <span style="font-weight: 600; font-size: 0.85rem; color: var(--color-text-primary);">${vuln.name}</span>
            </div>
            <span style="font-size: 0.75rem; color: var(--color-text-muted);">${vuln.category}</span>
          </div>
          <div class="details-body" id="vuln-body-${vulnId}">
            <div style="display: flex; flex-direction: column; gap: 1rem;">
              <div>
                <strong style="color:var(--color-text-primary); display:block; margin-bottom:0.25rem;">Description:</strong>
                <p style="color:var(--color-text-secondary);">${vuln.description || "N/A"}</p>
              </div>
              <div>
                <strong style="color:var(--color-text-primary); display:block; margin-bottom:0.25rem;">Impact:</strong>
                <p style="color:var(--color-text-secondary);">${vuln.impact || "N/A"}</p>
              </div>
              ${vuln.evidence ? `
              <div>
                <strong style="color:var(--color-text-primary); display:block; margin-bottom:0.25rem;">Evidence:</strong>
                <pre style="background:var(--color-bg-elevated); padding:0.75rem; border-radius:8px; font-family:var(--font-mono); font-size:0.75rem; overflow-x:auto; color:var(--color-accent-light);">${vuln.evidence}</pre>
              </div>` : ''}
              <div>
                <strong style="color:#10b981; display:block; margin-bottom:0.25rem;">Remediation Action Plan:</strong>
                <p style="color:var(--color-text-secondary); white-space: pre-line; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); padding: 0.75rem; border-radius: 8px;">${vuln.remediation || "N/A"}</p>
              </div>
            </div>
          </div>
        </div>
      `;
    });
    html += `</div>`;
  }

  container.innerHTML = html;
  lucide.createIcons();
}

// Toggle findings details item card expansion
window.toggleDetailsCard = function(vulnId) {
  const card = document.getElementById(`vuln-card-${vulnId}`);
  const body = document.getElementById(`vuln-body-${vulnId}`);
  if (card.classList.contains("expanded")) {
    card.classList.remove("expanded");
    body.style.display = "none";
  } else {
    card.classList.add("expanded");
    body.style.display = "block";
  }
};

// Initiate PDF compile trigger
window.compilePDFReport = async function(scanId) {
  try {
    const response = await fetch(`${API_BASE}/api/reports/generate/${scanId}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    alert("Compliance PDF Report successfully compiled! Navigate to the Security Reports section to download.");
  } catch (err) {
    alert("Report generation failed.");
  }
};

// Fetch compliance reports logs
async function fetchReports() {
  const tableBody = document.getElementById("reports-table-body");
  tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 2rem; color: var(--color-text-muted);">Syncing reports logs...</td></tr>`;

  try {
    const response = await fetch(`${API_BASE}/api/reports/`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    const reports = await response.json();
    state.reports = reports;

    tableBody.innerHTML = "";
    if (reports.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 2rem; color: var(--color-text-muted);">No reports compiled. Trigger scans to create them.</td></tr>`;
      return;
    }

    reports.forEach(report => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td style="font-weight: 600; color: var(--color-text-primary);">${report.title}</td>
        <td><span class="badge badge-info">${report.format}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.75rem;">${(parseInt(report.file_size)/1024).toFixed(1)} KB</td>
        <td style="color: var(--color-text-muted);">${new Date(report.created_at).toLocaleDateString()}</td>
        <td style="text-align: right;">
          <div style="display: inline-flex; gap: 0.5rem;">
            <button class="btn btn-secondary" style="padding: 0.4rem 0.6rem;" onclick="downloadReport('${report.id}', '${report.title}')">
              <i data-lucide="download" style="width: 0.95rem; height: 0.95rem; color: var(--color-accent-light)"></i>
            </button>
            <button class="btn btn-secondary" style="padding: 0.4rem 0.6rem;" onclick="printReport('${report.id}')">
              <i data-lucide="printer" style="width: 0.95rem; height: 0.95rem; color: #eab308"></i>
            </button>
          </div>
        </td>
      `;
      tableBody.appendChild(tr);
    });
    lucide.createIcons();
  } catch (err) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align: center; padding: 2rem; color: var(--color-critical);">Could not connect to reports registry.</td></tr>`;
  }
}

// Download PDF blob trigger
window.downloadReport = async function(reportId, title) {
  try {
    const response = await fetch(`${API_BASE}/api/reports/download/${reportId}`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${title}.pdf`;
    document.body.appendChild(a);
    a.click();
    a.remove();
  } catch (err) {
    alert("Download failed.");
  }
};

// Print PDF blob trigger
window.printReport = async function(reportId) {
  try {
    const response = await fetch(`${API_BASE}/api/reports/download/${reportId}`, {
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    iframe.src = url;
    document.body.appendChild(iframe);
    iframe.contentWindow.print();
  } catch (err) {
    alert("Printing failed.");
  }
};

// Fetch admin console profiles & logs
async function fetchAdminConsoleData() {
  const usersTable = document.getElementById("admin-users-table");
  const auditLogsDiv = document.getElementById("admin-audit-logs");
  const metricsGrid = document.getElementById("admin-metrics-grid");

  usersTable.innerHTML = `<tr><td colspan="3" style="text-align: center; padding: 1.5rem; color: var(--color-text-muted);">Syncing users list...</td></tr>`;
  auditLogsDiv.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--color-text-muted); font-size: 0.85rem;">Syncing audit log entries...</div>`;

  try {
    const [usersResp, statsResp, logsResp] = await Promise.all([
      fetch(`${API_BASE}/api/admin/users`, { headers: { "Authorization": `Bearer ${state.token}` } }),
      fetch(`${API_BASE}/api/admin/stats`, { headers: { "Authorization": `Bearer ${state.token}` } }),
      fetch(`${API_BASE}/api/admin/audit-logs`, { headers: { "Authorization": `Bearer ${state.token}` } })
    ]);

    if (!usersResp.ok || !statsResp.ok || !logsResp.ok) throw new Error();

    const users = await usersResp.json();
    const stats = await statsResp.json();
    const logs = await logsResp.json();

    // Render Metrics
    metricsGrid.innerHTML = `
      <div class="glass-card metric-card">
        <div>
          <span style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-secondary); text-transform: uppercase;">Operator Profiles</span>
          <div class="metric-value">${stats.total_users}</div>
        </div>
        <div style="padding: 0.75rem; background: var(--color-bg-elevated); border-radius: 12px; color: var(--color-accent);"><i data-lucide="users" style="width: 1.5rem; height: 1.5rem;"></i></div>
      </div>
      <div class="glass-card metric-card">
        <div>
          <span style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-secondary); text-transform: uppercase;">Total Scans Executed</span>
          <div class="metric-value">${stats.total_scans}</div>
        </div>
        <div style="padding: 0.75rem; background: var(--color-bg-elevated); border-radius: 12px; color: var(--color-info);"><i data-lucide="database" style="width: 1.5rem; height: 1.5rem;"></i></div>
      </div>
      <div class="glass-card metric-card">
        <div>
          <span style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-secondary); text-transform: uppercase;">Reports Compiled</span>
          <div class="metric-value">${stats.total_reports}</div>
        </div>
        <div style="padding: 0.75rem; background: var(--color-bg-elevated); border-radius: 12px; color: #f59e0b;"><i data-lucide="file-text" style="width: 1.5rem; height: 1.5rem;"></i></div>
      </div>
      <div class="glass-card metric-card">
        <div>
          <span style="font-size: 0.7rem; font-weight: 700; color: var(--color-text-secondary); text-transform: uppercase;">Audit Entries</span>
          <div class="metric-value">${stats.total_audit_logs}</div>
        </div>
        <div style="padding: 0.75rem; background: var(--color-bg-elevated); border-radius: 12px; color: #10b981;"><i data-lucide="clipboard-list" style="width: 1.5rem; height: 1.5rem;"></i></div>
      </div>
    `;

    // Render Users Table
    usersTable.innerHTML = "";
    users.forEach(u => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>
          <span style="font-weight: 600; color:var(--color-text-primary); display:block;">${u.username}</span>
          <span style="font-size:0.75rem; color:var(--color-text-muted);">${u.email}</span>
        </td>
        <td>
          <select class="input-field" style="padding: 0.35rem 0.5rem; width: 130px; font-size: 0.75rem; cursor: pointer;" onchange="updateUserRole('${u.id}', this.value)">
            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Administrator</option>
            <option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analyst</option>
            <option value="user" ${u.role === 'user' ? 'selected' : ''}>User</option>
          </select>
        </td>
        <td style="text-align: right;">
          <button class="btn btn-secondary" style="padding: 0.4rem 0.75rem; color: var(--color-critical);" onclick="revokeOperator('${u.id}')">Revoke</button>
        </td>
      `;
      usersTable.appendChild(tr);
    });

    // Render Audit Logs
    auditLogsDiv.innerHTML = "";
    if (logs.length === 0) {
      auditLogsDiv.innerHTML = `<div style="text-align: center; padding: 1.5rem; color: var(--color-text-muted); font-size: 0.85rem;">No audit logs stored.</div>`;
    } else {
      logs.forEach(log => {
        const item = document.createElement("div");
        item.style.padding = "0.75rem";
        item.style.background = "var(--color-bg-elevated)";
        item.style.border = "1px solid var(--color-border)";
        item.style.borderRadius = "8px";
        item.style.fontSize = "0.75rem";
        item.style.display = "flex";
        item.style.flexDirection = "column";
        item.style.gap = "0.15rem";

        item.innerHTML = `
          <div style="display: flex; align-items: center; justify-content: space-between;">
            <span style="font-weight: 700; color: var(--color-accent-light); text-transform: uppercase;">${log.action}</span>
            <span style="font-size: 0.65rem; color: var(--color-text-muted);">${new Date(log.created_at).toLocaleTimeString()}</span>
          </div>
          <span style="color: var(--color-text-secondary);">Element: ${log.resource_type || "system"}</span>
        `;
        auditLogsDiv.appendChild(item);
      });
    }

    lucide.createIcons();
  } catch (err) {
    console.error("Could not sync admin telemetry:", err);
  }
}

// Update operator permissions role
window.updateUserRole = async function(userId, role) {
  try {
    const response = await fetch(`${API_BASE}/api/admin/users/${userId}/role?role=${role}`, {
      method: "PUT",
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    alert(`Operator permissions changed successfully.`);
    fetchAdminConsoleData();
  } catch (err) {
    alert("Access denied. Admin authorization required.");
  }
};

// Delete user account profile
window.revokeOperator = async function(userId) {
  if (!confirm("Are you sure you want to revoke this analyst's access?")) return;
  try {
    const response = await fetch(`${API_BASE}/api/admin/users/${userId}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${state.token}` }
    });
    if (!response.ok) throw new Error();
    alert("Analyst access successfully revoked.");
    fetchAdminConsoleData();
  } catch (err) {
    alert("Failed to revoke operator access.");
  }
};
