(() => {
  const TOKEN = window.__NS_TOKEN__;
  const $ = (id) => document.getElementById(id);

  const headers = () => ({
    "X-NetworkSweeper-Token": TOKEN,
    "Content-Type": "application/json",
  });

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { ...headers(), ...(opts.headers || {}) },
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || res.statusText);
    }
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("application/json")) return res.json();
    return res.text();
  }

  function formatVersion(v) {
    const raw = String(v || "").trim();
    if (!raw) return "";
    return raw.startsWith("v") ? raw : "v" + raw;
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function chips(items, soft = false) {
    if (!items || !items.length) {
      return `<span class="chip soft">none</span>`;
    }
    return items
      .map((item) => `<span class="chip${soft ? " soft" : ""}">${escapeHtml(item)}</span>`)
      .join("");
  }

  // Consent
  $("consent-check").addEventListener("change", (e) => {
    $("consent-continue").disabled = !e.target.checked;
  });
  $("consent-continue").addEventListener("click", () => {
    $("consent").hidden = true;
    $("main").hidden = false;
    init();
  });

  // Tabs — toggle hidden for a11y + single active panel
  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.tab;
      document.querySelectorAll(".tabs button").forEach((b) => {
        const on = b === btn;
        b.classList.toggle("active", on);
        b.setAttribute("aria-selected", on ? "true" : "false");
      });
      document.querySelectorAll(".tab").forEach((panel) => {
        const on = panel.id === "tab-" + id;
        panel.classList.toggle("active", on);
        panel.hidden = !on;
      });
    });
  });

  let pollTimer = null;

  async function init() {
    $("version").textContent = formatVersion(window.__NS_VERSION__);

    const [session, ifaces, plat] = await Promise.all([
      api("/api/session"),
      api("/api/interfaces"),
      api("/api/platform"),
    ]);

    if (session.elevated) $("elevated-badge").hidden = false;
    $("custom-optin").checked = !!session.customOptIn;
    $("updates-optin").checked = !!session.updatesOptIn;

    renderNetworkContext(ifaces);
    if (ifaces.localSubnets?.length) {
      $("targets").placeholder = ifaces.localSubnets.join(", ");
    }
    renderPlatform(plat);

    try {
      const results = await api("/api/results");
      if (results && results.hosts) renderResults(results);
    } catch (_) {}
  }

  function renderNetworkContext(ifaces) {
    const live = (ifaces.interfaces || []).filter((i) => !i.isLoopback);
    const ifaceHtml = live.length
      ? `<ul class="iface-list">${live
          .map(
            (i) => `<li>
              <strong>${escapeHtml(i.name)}</strong>
              <span>${escapeHtml((i.cidrs || []).join(" · ") || (i.ipv4 || []).join(" · "))}</span>
            </li>`
          )
          .join("")}</ul>`
      : `<p class="empty">No non-loopback IPv4 interfaces detected.</p>`;

    $("network-context").innerHTML = `
      <div class="context-section">
        <p class="context-label">Local subnets</p>
        <div class="chip-row">${chips(ifaces.localSubnets)}</div>
      </div>
      <div class="context-section">
        <p class="context-label">Interfaces</p>
        ${ifaceHtml}
      </div>
      <div class="context-section">
        <p class="context-label">Discovery ports</p>
        <div class="chip-row">${chips((ifaces.discoveryPorts || []).map(String), true)}</div>
      </div>
      <div class="context-section">
        <p class="context-label">Findings ports</p>
        <div class="chip-row">${chips((ifaces.findingsPorts || []).map(String), true)}</div>
      </div>
    `;
  }

  function renderPlatform(plat) {
    const caps = (plat.capabilities || [])
      .map(
        (c) => `<li>
          <div><strong>${escapeHtml(c.name)}</strong><span class="status">${escapeHtml(c.status)}</span></div>
          <div class="muted">${escapeHtml(c.detail)}</div>
        </li>`
      )
      .join("");
    const notes = (plat.notes || []).map((n) => `<li>${escapeHtml(n)}</li>`).join("");
    $("platform").innerHTML = `
      <p class="muted" style="margin:0 0 0.85rem">OS: ${escapeHtml(plat.os)} / ${escapeHtml(plat.arch)} · elevated: ${plat.elevated}</p>
      <ul class="cap-list">${caps}</ul>
      <h4 style="margin:1rem 0 0.4rem;font-size:0.95rem">Notes</h4>
      <ul class="notes">${notes}</ul>
    `;
  }

  function renderResults(data) {
    const hosts = data.hosts || [];
    const portsByIP = Object.create(null);
    for (const p of data.ports || []) {
      portsByIP[p.ip] = p.ports || [];
    }

    $("host-count").textContent = String(hosts.length);

    if (!hosts.length) {
      $("hosts").innerHTML = `<p class="empty">No hosts discovered. Silent/firewalled devices may be invisible without Deep discovery.</p>`;
    } else {
      const rows = hosts
        .map((h) => {
          const ports = portsByIP[h.ip] || [];
          const portHtml = ports.length
            ? `<div class="port-list">${ports
                .map((x) => `<span class="port-pill">${escapeHtml(x.port)}/${escapeHtml(x.service)}</span>`)
                .join("")}</div>`
            : "—";
          return `<tr>
            <td class="mono">${escapeHtml(h.ip)}</td>
            <td class="mono">${escapeHtml(h.mac || "—")}</td>
            <td>${escapeHtml(h.vendor || "—")}</td>
            <td>${escapeHtml(h.hostname || "—")}</td>
            <td class="mono">${escapeHtml((h.aliveVia || []).join(", ") || "—")}</td>
            <td>${portHtml}</td>
          </tr>`;
        })
        .join("");

      $("hosts").innerHTML = `<div class="table-wrap"><table>
        <thead><tr>
          <th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Alive via</th><th>Open ports</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`;
    }

    const findings = data.findings || [];
    $("finding-count").textContent = String(findings.length);
    if (!findings.length) {
      $("findings").innerHTML = `<p class="empty">No findings yet. Run a scan from Overview.</p>`;
    } else {
      $("findings").innerHTML = findings
        .map(
          (f) => `<article class="finding">
            <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
            <h4>${escapeHtml(f.title)}</h4>
            <p>${escapeHtml(f.description)}</p>
            <p><strong style="color:var(--fg)">Host:</strong> ${escapeHtml(f.hostIp)}${
              f.port ? ` · port ${f.port}` : ""
            }</p>
            <p><strong style="color:var(--fg)">Remediation:</strong> ${escapeHtml(f.remediation)}</p>
          </article>`
        )
        .join("");
    }

    if (data.warning) {
      $("discovery-banner").textContent = data.warning;
    }
  }

  $("scan-btn").addEventListener("click", async () => {
    const status = $("scan-status");
    status.textContent = "Starting scan…";
    status.classList.add("is-busy");
    const raw = $("targets").value.trim();
    const targets = raw ? raw.split(/[,\s]+/).filter(Boolean) : [];
    try {
      await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({
          targets,
          deep: $("deep").checked,
          customOptIn: $("custom-optin").checked,
        }),
      });
      pollStatus();
    } catch (e) {
      status.classList.remove("is-busy");
      status.textContent = "Error: " + e.message;
    }
  });

  function pollStatus() {
    if (pollTimer) clearInterval(pollTimer);
    const status = $("scan-status");
    pollTimer = setInterval(async () => {
      try {
        const st = await api("/api/scan/status");
        if (st.running) {
          status.classList.add("is-busy");
          status.textContent = st.progress || "Scanning…";
          return;
        }
        clearInterval(pollTimer);
        pollTimer = null;
        status.classList.remove("is-busy");
        status.textContent = "Scan finished";
        const results = await api("/api/results");
        renderResults(results);
      } catch (e) {
        status.classList.remove("is-busy");
        status.textContent = e.message;
      }
    }, 600);
  }

  function download(path) {
    const a = document.createElement("a");
    a.href = path + (path.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN);
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  $("export-json").addEventListener("click", () => download("/api/export?format=json"));
  $("export-csv").addEventListener("click", () => download("/api/export?format=csv"));

  async function saveSettings() {
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({
        customOptIn: $("custom-optin").checked,
        updatesOptIn: $("updates-optin").checked,
      }),
    });
  }
  $("custom-optin").addEventListener("change", saveSettings);
  $("updates-optin").addEventListener("change", saveSettings);

  $("check-update").addEventListener("click", async () => {
    const out = $("update-result");
    try {
      await saveSettings();
      const res = await api("/api/update", { method: "POST", body: "{}" });
      out.hidden = false;
      out.textContent = JSON.stringify(res, null, 2);
    } catch (e) {
      out.hidden = false;
      out.textContent = e.message;
    }
  });
})();
