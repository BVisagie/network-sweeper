(() => {
  const TOKEN = window.__NS_TOKEN__;
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

  const $ = (id) => document.getElementById(id);

  // Consent gate
  $("consent-check").addEventListener("change", (e) => {
    $("consent-continue").disabled = !e.target.checked;
  });
  $("consent-continue").addEventListener("click", () => {
    $("consent").hidden = true;
    $("main").hidden = false;
    init();
  });

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tabs button").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      btn.classList.add("active");
      $("tab-" + btn.dataset.tab).classList.add("active");
    });
  });

  let pollTimer = null;

  async function init() {
    $("version").textContent = "v" + (window.__NS_VERSION__ || "");
    const session = await api("/api/session");
    if (session.elevated) {
      $("elevated-badge").hidden = false;
    }
    $("custom-optin").checked = !!session.customOptIn;
    $("updates-optin").checked = !!session.updatesOptIn;

    const ifaces = await api("/api/interfaces");
    $("ifaces").textContent = JSON.stringify(
      {
        localSubnets: ifaces.localSubnets,
        discoveryPorts: ifaces.discoveryPorts,
        findingsPorts: ifaces.findingsPorts,
        interfaces: ifaces.interfaces.filter((i) => !i.isLoopback),
      },
      null,
      2
    );
    if (ifaces.localSubnets?.length) {
      $("targets").placeholder = ifaces.localSubnets.join(", ");
    }

    const plat = await api("/api/platform");
    renderPlatform(plat);

    try {
      const results = await api("/api/results");
      if (results && results.hosts) renderResults(results);
    } catch (_) {}
  }

  function renderPlatform(plat) {
    const caps = (plat.capabilities || [])
      .map(
        (c) =>
          `<li><div><strong>${escapeHtml(c.name)}</strong> <span class="status">${escapeHtml(
            c.status
          )}</span></div><div class="muted">${escapeHtml(c.detail)}</div></li>`
      )
      .join("");
    const notes = (plat.notes || []).map((n) => `<li>${escapeHtml(n)}</li>`).join("");
    $("platform").innerHTML = `
      <p class="muted">OS: ${escapeHtml(plat.os)} / ${escapeHtml(plat.arch)} · elevated: ${plat.elevated}</p>
      <ul class="cap-list">${caps}</ul>
      <h4>Notes</h4>
      <ul class="notes">${notes}</ul>
    `;
  }

  function renderResults(data) {
    const hosts = data.hosts || [];
    const portsByIP = {};
    (data.ports || []).forEach((p) => {
      portsByIP[p.ip] = (p.ports || [])
        .map((x) => `${x.port}/${x.service}`)
        .join(", ");
    });
    $("host-count").textContent = `(${hosts.length})`;
    if (!hosts.length) {
      $("hosts").innerHTML = `<p class="muted">No hosts discovered. Silent/firewalled devices may be invisible without Deep discovery.</p>`;
    } else {
      $("hosts").innerHTML = `<table>
        <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th><th>Alive via</th><th>Open ports</th></tr></thead>
        <tbody>
          ${hosts
            .map(
              (h) => `<tr>
            <td>${escapeHtml(h.ip)}</td>
            <td>${escapeHtml(h.mac || "—")}</td>
            <td>${escapeHtml(h.vendor || "—")}</td>
            <td>${escapeHtml(h.hostname || "—")}</td>
            <td>${escapeHtml((h.aliveVia || []).join(", "))}</td>
            <td>${escapeHtml(portsByIP[h.ip] || "—")}</td>
          </tr>`
            )
            .join("")}
        </tbody>
      </table>`;
    }

    const findings = data.findings || [];
    $("finding-count").textContent = `(${findings.length})`;
    if (!findings.length) {
      $("findings").innerHTML = `<p class="muted">No findings yet. Run a scan.</p>`;
    } else {
      $("findings").innerHTML = findings
        .map(
          (f) => `<article class="finding">
          <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
          <h4>${escapeHtml(f.title)}</h4>
          <p>${escapeHtml(f.description)}</p>
          <p class="muted"><strong>Host:</strong> ${escapeHtml(f.hostIp)}${
            f.port ? ` · port ${f.port}` : ""
          }</p>
          <p><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>
        </article>`
        )
        .join("");
    }
    if (data.warning) {
      $("discovery-banner").innerHTML = escapeHtml(data.warning);
    }
  }

  $("scan-btn").addEventListener("click", async () => {
    $("scan-status").textContent = "Starting scan…";
    const raw = $("targets").value.trim();
    const targets = raw
      ? raw.split(/[,\s]+/).filter(Boolean)
      : [];
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
      $("scan-status").textContent = "Error: " + e.message;
    }
  });

  function pollStatus() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      try {
        const st = await api("/api/scan/status");
        $("scan-status").textContent = st.running
          ? st.progress || "Scanning…"
          : "Scan finished";
        if (!st.running) {
          clearInterval(pollTimer);
          pollTimer = null;
          const results = await api("/api/results");
          renderResults(results);
        }
      } catch (e) {
        $("scan-status").textContent = e.message;
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
    try {
      await saveSettings();
      const res = await api("/api/update", { method: "POST", body: "{}" });
      $("update-result").textContent = JSON.stringify(res, null, 2);
    } catch (e) {
      $("update-result").textContent = e.message;
    }
  });

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
})();
