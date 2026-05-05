function showOnboarding() {
  if (!localStorage.getItem("multicidr_onboarded")) {
    document.getElementById("onboardingModal").style.display = "flex";
  }
}

function closeOnboarding() {
  localStorage.setItem("multicidr_onboarded", "true");
  document.getElementById("onboardingModal").style.display = "none";
}

const CSRF = () => {
  const m = document.querySelector('meta[name="zoraxy.csrf.Token"]');
  return m ? m.getAttribute("content") : "";
};

const fmt = (n) =>
  (typeof n === "number" ? n : parseInt(n) || 0).toLocaleString();

const fmtT = (t) => {
  if (!t) return "Never";
  const d = new Date(t);
  if (isNaN(d) || d.getFullYear() < 2000) return "Never";
  return d.toLocaleString();
};

const fmtAgo = (t) => {
  if (!t) return "";
  const d = new Date(t);
  if (isNaN(d) || d.getFullYear() < 2000) return "";
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};

function toast(msg, type = "inf") {
  const w = document.getElementById("toastWrap");
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  const icons = { ok: "✓", err: "✕", inf: "ℹ" };
  t.innerHTML = `<span>${icons[type] || "ℹ"}</span><span>${msg}</span>`;
  w.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

async function api(path, body) {
  const opts =
    body !== undefined
      ? {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": CSRF(),
          },
          body: JSON.stringify(body),
        }
      : { method: "GET" };
  const r = await fetch(path, opts);
  if (!r.ok) {
    const t = await r.text();
    throw new Error(t.trim() || r.statusText);
  }
  return r.json();
}

let _state = null;

function renderStats(d) {
  const statusEl = document.getElementById("statStatus");
  if (d.refreshing) {
    statusEl.innerHTML = `<span class="pill pill-loading"><span class="spin"></span> Refreshing…</span>`;
  } else if (d.loaded) {
    statusEl.innerHTML = `<span class="pill pill-active">Active</span>`;
  } else if ((d.source_count || 0) === 0) {
    statusEl.innerHTML = `<span class="pill pill-idle">No sources</span>`;
  } else {
    statusEl.innerHTML = `<span class="pill pill-offline">Not loaded</span>`;
  }

  document.getElementById("statSources").textContent =
    `${d.enabled_count || 0} / ${d.source_count || 0}`;
  document.getElementById("statRanges").textContent = fmt(
    d.unique_entries || 0,
  );
  document.getElementById("statBlocked").textContent = fmt(
    d.blocked_count || 0,
  );
  document.getElementById("statRefresh").textContent = fmtT(d.last_refresh);

  document.getElementById("sourceCount").textContent = d.source_count || 0;
  document.getElementById("lastBuilt").textContent = d.last_refresh
    ? `Built ${fmtAgo(d.last_refresh)}`
    : "";
}

function renderSources(sources) {
  const el = document.getElementById("sourceList");
  if (!sources || sources.length === 0) {
    el.innerHTML = `
      <div class="empty-state">
        <div class="icon">🛡</div>
        <h3>No sources configured yet</h3>
        <p>Add a URL to a plain-text CIDR blocklist above.<br>The plugin will download and apply it automatically.</p>
      </div>`;
    return;
  }

  el.innerHTML = sources
    .map((s) => {
      const hasError = s.last_error && s.last_error.length > 0;
      const hasLoaded = s.loaded_entries > 0;
      const lastRef = fmtAgo(s.last_refresh);

      const proto = [
        s.supports_ipv4 ? `<span class="proto-tag v4">IPv4</span>` : "",
        s.supports_ipv6 ? `<span class="proto-tag v6">IPv6</span>` : "",
      ]
        .filter(Boolean)
        .join("");

      const errorTag = hasError
        ? `<div class="error-tag">⚠ ${escHtml(s.last_error)}</div>`
        : "";

      const metaItems = [
        { label: "Entries", val: hasLoaded ? fmt(s.unique_entries) : "—" },
        { label: "Hits", val: fmt(s.hits) },
        { label: "Updated", val: lastRef || "—" },
      ]
        .map(
          (m) => `
      <div class="source-meta-item">
        <span class="label">${m.label}</span>
        <strong>${m.val}</strong>
      </div>`,
        )
        .join("");

      return `
    <div class="source-item${s.enabled ? "" : " disabled"}" id="src-${s.id}">
      <div class="source-top">
        <div style="flex:1;min-width:0">
          <div class="source-name">${escHtml(s.name)}</div>
          <div class="source-url"><a href="${escHtml(s.url)}" target="_blank" rel="noopener">${escHtml(s.url)}</a></div>
          ${errorTag}
          ${proto ? `<div class="proto-tags">${proto}</div>` : ""}
        </div>
        <div class="source-actions">
          <label class="toggle-wrap" title="${s.enabled ? "Disable" : "Enable"} this source">
            <span class="toggle">
              <input type="checkbox" ${s.enabled ? "checked" : ""} onchange="toggleSource('${s.id}',this.checked)"/>
              <span class="toggle-slider"></span>
            </span>
          </label>
          <button class="btn btn-ghost btn-sm btn-icon" onclick="refreshSource('${s.id}')" title="Re-fetch this source now">⟳</button>
          <button class="btn btn-danger btn-sm btn-icon" onclick="removeSource('${s.id}','${escHtml(s.name)}')" title="Remove source">✕</button>
        </div>
      </div>
      <div class="source-meta">${metaItems}</div>
    </div>`;
    })
    .join("");
}

function escHtml(s) {
  if (!s) return "";
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function load() {
  try {
    const d = await api("api/status");
    _state = d;
    renderStats(d);
    renderSources(d.sources || []);
  } catch (e) {
    document.getElementById("statStatus").innerHTML =
      `<span class="pill pill-offline">Unreachable</span>`;
  }
}

async function addSource() {
  const urlEl = document.getElementById("addUrl");
  const nameEl = document.getElementById("addName");
  const btn = document.getElementById("addBtn");
  const msg = document.getElementById("addMsg");

  const url = urlEl.value.trim();
  const name = nameEl.value.trim();
  if (!url) {
    urlEl.focus();
    return;
  }

  btn.disabled = true;
  msg.textContent = "Fetching list…";

  try {
    await api("api/source/add", { url, name, enabled: true });
    urlEl.value = "";
    nameEl.value = "";
    msg.textContent = "";
    toast("Source added — fetching in background…", "ok");
    setTimeout(load, 1200);
    setTimeout(load, 5000);
  } catch (e) {
    msg.textContent = "";
    toast("Error: " + e.message, "err");
  } finally {
    btn.disabled = false;
  }
}

async function toggleSource(id, enabled) {
  try {
    await api("api/source/update", { id, enabled });
    setTimeout(load, 800);
  } catch (e) {
    toast("Failed to update: " + e.message, "err");
    load();
  }
}

async function refreshSource(id) {
  try {
    await api("api/source/refresh", { id });
    toast("Refresh started…", "inf");
    setTimeout(load, 2000);
    setTimeout(load, 8000);
  } catch (e) {
    toast("Error: " + e.message, "err");
  }
}

async function removeSource(id, name) {
  if (
    !confirm(
      `Remove "${name}"?\n\nThis will remove it from the blocklist immediately.`,
    )
  )
    return;
  try {
    await api("api/source/remove", { id });
    toast("Source removed.", "ok");
    setTimeout(load, 800);
  } catch (e) {
    toast("Error: " + e.message, "err");
  }
}

async function refreshAll() {
  const btn = document.getElementById("refreshBtn");
  const icon = document.getElementById("refreshIcon");
  btn.disabled = true;
  icon.innerHTML = '<span class="spin"></span>';
  try {
    await api("api/refresh", {});
    toast("Refresh started — lists downloading…", "inf");
    setTimeout(() => {
      load();
      btn.disabled = false;
      icon.textContent = "⟳";
    }, 2500);
    setTimeout(load, 8000);
  } catch (e) {
    toast("Error: " + e.message, "err");
    btn.disabled = false;
    icon.textContent = "⟳";
  }
}

async function resetHits() {
  if (!confirm("Reset all hit counters to zero?")) return;
  try {
    await api("api/reset-hits", {});
    toast("Hit counters reset.", "ok");
    setTimeout(load, 300);
  } catch (e) {
    toast("Error: " + e.message, "err");
  }
}

showOnboarding();
load();
setInterval(load, 20000);
