function showOnboarding() {
  if (!localStorage.getItem("multicidr_onboarded")) {
    document.getElementById("onboardingModal").style.display = "flex";
  }
}
function closeOnboarding() {
  localStorage.setItem("multicidr_onboarded", "true");
  document.getElementById("onboardingModal").style.display = "none";
}

const CSRF = () =>
  document
    .querySelector('meta[name="zoraxy.csrf.Token"]')
    ?.getAttribute("content") || "";
const fmt = (n) =>
  (typeof n === "number" ? n : parseInt(n) || 0).toLocaleString();
const fmtT = (t) => {
  if (!t) return "Never";
  const d = new Date(t);
  return isNaN(d) || d.getFullYear() < 2000 ? "Never" : d.toLocaleString();
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
  el.innerHTML = "";
  if (!sources || sources.length === 0) {
    el.innerHTML = `<div class="empty-state"><div class="icon">🛡</div><h3>No sources configured yet</h3><p>Add a URL to a plain-text CIDR blocklist above.<br>The plugin will download and apply it automatically.</p></div>`;
    return;
  }

  const tpl = document.getElementById("source-item-tpl").content;
  const fragment = document.createDocumentFragment();

  sources.forEach((s) => {
    const node = tpl.cloneNode(true);
    const item = node.querySelector(".source-item");
    item.id = `src-${s.id}`;
    if (!s.enabled) item.classList.add("disabled");

    node.querySelector(".source-name").textContent = s.name;
    const urlLink = node.querySelector(".source-url a");
    urlLink.href = s.url;
    urlLink.textContent = s.url;

    const errTag = node.querySelector(".error-tag");
    if (s.last_error) {
      errTag.style.display = "flex";
      errTag.querySelector(".error-text").textContent = s.last_error;
    }

    const protoBox = node.querySelector(".proto-tags");
    if (s.supports_ipv4) {
      const tag = document.createElement("span");
      tag.className = "proto-tag v4";
      tag.textContent = "IPv4";
      protoBox.appendChild(tag);
    }
    if (s.supports_ipv6) {
      const tag = document.createElement("span");
      tag.className = "proto-tag v6";
      tag.textContent = "IPv6";
      protoBox.appendChild(tag);
    }

    node.querySelector("input[data-action='toggle']").checked = s.enabled;

    const metaBox = node.querySelector(".source-meta");
    const meta = [
      {
        label: "Entries",
        val: s.loaded_entries > 0 ? fmt(s.unique_entries) : "—",
      },
      { label: "Hits", val: fmt(s.hits) },
      { label: "Updated", val: s.last_refresh ? fmtAgo(s.last_refresh) : "—" },
    ];
    meta.forEach((m) => {
      const div = document.createElement("div");
      div.className = "source-meta-item";
      div.innerHTML = `<span class="label">${m.label}</span><strong>${m.val}</strong>`;
      metaBox.appendChild(div);
    });

    // Attach dataset for event delegation
    node.querySelectorAll("[data-action]").forEach((btn) => {
      btn.dataset.id = s.id;
      if (btn.dataset.action === "remove") btn.dataset.name = s.name;
    });

    fragment.appendChild(node);
  });

  el.appendChild(fragment);
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

function removeSource(id, name) {
  showConfirm(
    'Remove "' + name + '"?',
    "This will remove it from the blocklist immediately.",
    async () => {
      try {
        await api("api/source/remove", { id });
        toast("Source removed.", "ok");
        setTimeout(load, 800);
      } catch (e) {
        toast("Error: " + e.message, "err");
      }
    },
  );
}

function showConfirm(title, message, onConfirm) {
  let modal = document.getElementById("confirmModal");
  if (!modal) {
    const tpl = document
      .getElementById("confirm-modal-tpl")
      .content.cloneNode(true);
    modal = tpl.querySelector(".confirm-backdrop");
    document.body.appendChild(modal);
  }
  document.getElementById("confirmTitle").textContent = title;
  document.getElementById("confirmMsg").textContent = message;
  modal.style.display = "flex";

  const close = () => {
    modal.style.display = "none";
  };
  document.getElementById("confirmCancel").onclick = close;
  modal.onclick = (e) => {
    if (e.target === modal) close();
  };
  document.getElementById("confirmOk").onclick = () => {
    close();
    onConfirm();
  };
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
  showConfirm(
    "Reset hit counters?",
    "All hit counters will be reset to zero.",
    async () => {
      try {
        await api("api/reset-hits", {});
        toast("Hit counters reset.", "ok");
        setTimeout(load, 300);
      } catch (e) {
        toast("Error: " + e.message, "err");
      }
    },
  );
}

document.addEventListener("DOMContentLoaded", () => {
  showOnboarding();
  load();
  setInterval(load, 20000);

  const list = document.getElementById("sourceList");
  list.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const { action, id, name } = btn.dataset;
    if (action === "refresh") refreshSource(id);
    if (action === "remove") removeSource(id, name);
  });
  list.addEventListener("change", (e) => {
    const el = e.target.closest("[data-action='toggle']");
    if (!el) return;
    toggleSource(el.dataset.id, el.checked);
  });
});
