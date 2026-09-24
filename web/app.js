(() => {
  const TOKEN = window.__NS_TOKEN__;
  const CONSENT_KEY = "ns-consent-ok";
  const STALE_MS = 24 * 60 * 60 * 1000;
  const $ = (id) => document.getElementById(id);

  // Beginner-friendly blurbs for findings ports (keep short).
  const PORT_HELP = {
    21: "File transfer service (FTP). Often sends passwords without encryption.",
    22: "Secure remote login (SSH). Common for administering servers.",
    23: "Old remote login (Telnet). Passwords can be read in transit — usually a risk.",
    25: "Email sending service (SMTP). Misconfigured mail relays can be abused.",
    53: "DNS — translates names like example.com into IP addresses.",
    80: "Website or device web page over HTTP (not encrypted).",
    110: "Email download (POP3). Often unencrypted unless upgraded.",
    111: "RPC port mapper. Used by some Unix/network services.",
    135: "Windows RPC endpoint. Used by remote Windows management tools.",
    139: "Legacy Windows file/printer sharing (NetBIOS).",
    143: "Email access (IMAP). Lets apps read mailboxes.",
    443: "Secure website or device web page (HTTPS).",
    445: "Windows file and printer sharing (SMB).",
    993: "Encrypted email access (IMAPS).",
    995: "Encrypted email download (POP3S).",
    1433: "Microsoft SQL Server database.",
    1521: "Oracle database listener.",
    3306: "MySQL / MariaDB database.",
    3389: "Windows Remote Desktop — full remote control of the PC.",
    5432: "PostgreSQL database.",
    5900: "VNC remote screen sharing.",
    6379: "Redis data store. Dangerous if reachable without a password.",
    8000: "Alternate web / app server port.",
    8080: "Alternate web or proxy port (often admin UIs).",
    8443: "Alternate secure web (HTTPS) port.",
    9200: "Elasticsearch search engine API.",
    27017: "MongoDB database.",
    2375: "Docker engine API without TLS — often a serious exposure.",
    2376: "Docker engine API with TLS.",
    5000: "Dev / alternate web service port.",
    8888: "Alternate web / notebook-style service port.",
    9100: "Network printer raw printing port.",
  };

  // How the host was first noticed during discovery.
  const VIA_HELP = {
    icmp:
      "Found with a ping (ICMP). The device answered even if it keeps most ports closed — useful for quiet phones, TVs, and IoT.",
    arp:
      "Found with ARP on your local network (“who has this IP?”). Catches devices that ignore ping and don’t open common ports. Needs Deep discovery + elevation on Linux/macOS.",
    "arp-cache":
      "Found in your computer’s own ARP cache: the device answered “who has this IP?” when we tried to connect, even though every discovery port was closed. No elevation needed. A device that just left the network can linger here for a minute.",
  };

  const METHOD_LABEL = {
    tcp: "TCP discovery",
    icmp: "ping",
    "arp-sweep": "ARP sweep",
    "arp-cache": "ARP cache",
    ports: "port check",
    services: "service probes",
    names: "name lookups",
    ssdp: "UPnP",
    snmp: "SNMP",
  };

  const PHASES = [
    { key: "discovery", label: "Discovery", from: 0, to: 70 },
    { key: "ports", label: "Ports", from: 70, to: 85 },
    { key: "services", label: "Services", from: 85, to: 90 },
    { key: "names", label: "Names", from: 90, to: 94 },
    { key: "identity", label: "UPnP / SNMP", from: 94, to: 98 },
    { key: "saving", label: "Saving", from: 98, to: 100 },
  ];

  const STATE_LABEL = {
    completed: "Completed",
    canceled: "Stopped early",
    timed_out: "Hit the time limit",
    failed: "Failed",
    running: "Running",
    starting: "Starting",
  };

  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  const CATEGORY_LABEL = {
    observation: "Observation",
    exposure: "Potential exposure",
    issue: "Configuration issue",
  };

  const STATUS_LABEL = {
    full: "Available",
    elevated: "Needs elevation",
    partial: "Partial",
    deferred: "Not built yet",
    unavailable: "Unavailable",
  };

  const STATUS_LEGEND = {
    full: "Works with your current privileges",
    elevated: "Feature needs Admin / root — not the same as “app is elevated”",
    partial: "Works with limits on this OS",
    deferred: "Not implemented yet",
    unavailable: "Not possible here",
  };

  // ---------- small helpers ----------

  // Device-supplied text is escaped, and bidi controls are dropped so a name
  // cannot visually reorder itself ("gnp.exe" shown as "exe.png").
  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function stripBidi(s) {
    return String(s ?? "").replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g, "");
  }

  /** Decode common entities that sometimes arrive in titles / UPnP names. */
  function humanizeText(s) {
    return String(s ?? "")
      .replace(/&quot;|&#34;/gi, '"')
      .replace(/&#39;|&apos;/gi, "'")
      .replace(/&lt;/gi, "<")
      .replace(/&gt;/gi, ">")
      .replace(/&nbsp;/gi, " ")
      .replace(/&amp;/gi, "&")
      .replace(/\s+/g, " ")
      .trim();
  }

  function tipAttr(text) {
    return escapeHtml(String(text || "")).replace(/\n/g, " · ");
  }

  function chips(items, soft = false) {
    if (!items || !items.length) return `<span class="chip soft">none</span>`;
    return items.map((item) => `<span class="chip${soft ? " soft" : ""}">${escapeHtml(item)}</span>`).join("");
  }

  function plural(n, word, many) {
    return `${n} ${n === 1 ? word : many || word + "s"}`;
  }

  function fmtNumber(n) {
    return Number(n || 0).toLocaleString();
  }

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d)) return "";
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function ago(iso) {
    if (!iso) return "";
    const ms = Date.now() - new Date(iso).getTime();
    if (isNaN(ms)) return "";
    const min = Math.round(ms / 60000);
    if (min < 1) return "just now";
    if (min < 60) return `${min} min ago`;
    const h = Math.round(min / 60);
    if (h < 48) return plural(h, "hour") + " ago";
    return plural(Math.round(h / 24), "day") + " ago";
  }

  function methodsText(methods) {
    return (methods || []).map((m) => METHOD_LABEL[m] || m).join(", ");
  }

  function portHelpText(port, service) {
    const n = Number(port);
    if (PORT_HELP[n]) return PORT_HELP[n];
    return `Port ${n} (${service || "network service"}). An open service on this device — check whether you recognize it.`;
  }

  function viaText(via) {
    const raw = String(via || "").trim();
    const key = raw.toLowerCase();
    if (VIA_HELP[key]) return VIA_HELP[key];
    const m = key.match(/^tcp\/(\d+)$/);
    if (m) return `Accepted a TCP connection on discovery port ${m[1]}.`;
    return "How this device was first noticed.";
  }

  function portEnrichLines(op) {
    const lines = [];
    if (op.protocol) lines.push(`Answered as ${op.protocol}`);
    else if (op.probe === "no-answer") lines.push("Probe got no recognizable answer");
    if (op.httpTitle) lines.push(`Title: ${op.httpTitle}`);
    if (op.httpServer) lines.push(`Server: ${op.httpServer}`);
    if (op.tlsCommonName) lines.push(`TLS CN: ${op.tlsCommonName}`);
    if (op.tlsIssuer) lines.push(`TLS issuer: ${op.tlsIssuer}`);
    if (op.tlsNotAfter && !String(op.tlsNotAfter).startsWith("0001")) {
      const d = String(op.tlsNotAfter).slice(0, 10);
      lines.push(op.tlsExpired ? `TLS expired: ${d}` : `TLS valid until: ${d}`);
    }
    if (op.tlsSelfSigned) lines.push("Self-signed certificate");
    if (op.banner) lines.push(`Banner: ${op.banner}`);
    return lines;
  }

  function portPill(op) {
    const extra = portEnrichLines(op);
    const help = portHelpText(op.port, op.service) + (extra.length ? "\n" + extra.join("\n") : "");
    const label = `${op.port}/${op.service || "service"}`;
    const tip = tipAttr(help);
    const confirmed = op.protocol ? " confirmed" : "";
    return `<span class="port-pill${confirmed}" tabindex="0" data-tip="${tip}" aria-label="${escapeHtml(label)}: ${tip}"><span class="port-pill-label">${escapeHtml(label)}</span></span>`;
  }

  function identityHint(h, ports) {
    if (h && h.upnpFriendlyName) return String(h.upnpFriendlyName).slice(0, 64);
    if (h && h.snmpSysDescr) return String(h.snmpSysDescr).slice(0, 64);
    for (const key of ["httpTitle", "tlsCommonName", "httpServer", "banner"]) {
      for (const p of ports || []) if (p[key]) return String(p[key]).slice(0, 64);
    }
    return "";
  }

  function elevationHowTo(os) {
    switch (os) {
      case "windows":
        return {
          short: "Run as administrator",
          detail:
            "Close this app, then right-click the Network Sweeper .exe → Run as administrator. Deep discovery (ping) works more reliably that way. Active ARP is not available on Windows in this version.",
        };
      case "darwin":
        return {
          short: "Restart with sudo",
          detail:
            "Close this app, then in Terminal run: sudo ./network-sweeper-darwin-arm64 (or the amd64 build). Enter your Mac password when prompted. Deep discovery then uses ping and ARP. Elevated runs do not save history unless you pass --data-dir.",
        };
      case "linux":
        return {
          short: "Restart with sudo",
          detail:
            "Close this app, then run: sudo ./network-sweeper-linux-amd64 (or arm64). Deep discovery needs root for ping and ARP on most distros. Elevated runs do not save history unless you pass --data-dir.",
        };
      default:
        return {
          short: "Run with administrator / root privileges",
          detail: "Relaunch Network Sweeper with elevated privileges for Deep discovery (ICMP ping; ARP on Linux/macOS).",
        };
    }
  }

  function privilegeLabel(os, isElevated) {
    if (isElevated) return os === "windows" ? "Running as Administrator" : "Running with root (sudo)";
    return os === "windows" ? "Running as standard user" : "Running without root";
  }

  // ---------- state ----------

  const state = {
    session: null,
    ifaces: null,
    plat: null,
    inv: null, // /api/inventory
    history: [],
    selected: null, // Set of checked local CIDRs
    preview: null,
    scanId: "",
    polling: null,
    lastPct: 0,
    sort: { key: "ip", dir: 1 },
    findingStatus: "open",
    findingSev: "all",
    currentDeviceId: "",
    justScanned: false,
  };

  // ---------- API ----------

  async function api(path, opts = {}) {
    let res;
    try {
      res = await fetch(path, {
        ...opts,
        headers: { "X-NetworkSweeper-Token": TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
      });
    } catch (e) {
      setDisconnected(true);
      throw new Error("Network Sweeper is not reachable.");
    }
    setDisconnected(false);
    if (!res.ok) {
      const text = await res.text();
      throw new Error((text || res.statusText).trim());
    }
    const ct = res.headers.get("content-type") || "";
    return ct.includes("application/json") ? res.json() : res.text();
  }

  const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

  let reconnectTimer = null;
  function setDisconnected(down) {
    $("disconnected").hidden = !down;
    if (down && !reconnectTimer) {
      reconnectTimer = setInterval(async () => {
        try {
          await api("/api/session");
          clearInterval(reconnectTimer);
          reconnectTimer = null;
          refreshAll();
        } catch (_) {}
      }, 3000);
    }
  }

  // ---------- consent and tabs ----------

  function unlockDashboard() {
    if ($("consent").hidden) return;
    $("consent").hidden = true;
    $("main").hidden = false;
    init();
  }

  async function prepConsent() {
    // Listeners first, so a tick made while subnets load is not lost.
    $("consent-check").addEventListener("change", (e) => {
      $("consent-continue").disabled = !e.target.checked;
    });
    $("consent-continue").addEventListener("click", () => {
      try {
        sessionStorage.setItem(CONSENT_KEY, "1");
      } catch (_) {}
      unlockDashboard();
    });
    $("consent-continue").disabled = !$("consent-check").checked;
    try {
      const ifaces = await api("/api/interfaces");
      state.ifaces = ifaces;
      $("consent-subnets").innerHTML = chips(ifaces.localSubnets || []);
    } catch (_) {
      $("consent-subnets").innerHTML = `<span class="chip soft">Could not load subnets yet</span>`;
    }
    let ok = false;
    try {
      ok = sessionStorage.getItem(CONSENT_KEY) === "1";
    } catch (_) {}
    if (ok && !$("consent").hidden) unlockDashboard();
  }

  function activateTab(id, focus = true) {
    document.querySelectorAll(".tabs button").forEach((b) => {
      const on = b.dataset.tab === id;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
      b.tabIndex = on ? 0 : -1;
    });
    document.querySelectorAll(".tab").forEach((panel) => {
      const on = panel.id === "tab-" + id;
      panel.classList.toggle("active", on);
      panel.hidden = !on;
    });
    if (focus) document.getElementById("tabbtn-" + id)?.focus();
    if (id === "changes") loadChanges();
  }

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
    btn.addEventListener("keydown", (e) => {
      const tabs = [...document.querySelectorAll(".tabs button")];
      const i = tabs.indexOf(btn);
      let next = -1;
      if (e.key === "ArrowRight") next = (i + 1) % tabs.length;
      else if (e.key === "ArrowLeft") next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === "Home") next = 0;
      else if (e.key === "End") next = tabs.length - 1;
      if (next >= 0) {
        e.preventDefault();
        activateTab(tabs[next].dataset.tab);
      }
    });
  });

  function showCapabilities() {
    activateTab("settings", false);
    $("capabilities").scrollIntoView({ block: "start" });
    $("capabilities").querySelector("h3")?.setAttribute("tabindex", "-1");
    $("capabilities").querySelector("h3")?.focus();
  }
  $("caps-link").addEventListener("click", showCapabilities);

  // ---------- init ----------

  async function init() {
    $("version").textContent = formatVersion(window.__NS_VERSION__);
    try {
      const [session, ifaces, plat] = await Promise.all([api("/api/session"), api("/api/interfaces"), api("/api/platform")]);
      state.session = session;
      state.ifaces = ifaces;
      state.plat = plat;
    } catch (e) {
      $("scan-status").textContent = e.message;
      return;
    }
    renderPrivilege();
    renderScope();
    renderPlatform(state.plat);
    renderPortLists(state.ifaces);
    $("custom-optin").checked = !!state.session.customOptIn;
    $("updates-optin").checked = !!state.session.updatesOptIn;
    await refreshAll();
    updatePreview();
    // Resume a scan that was running when the page loaded.
    try {
      const st = await api("/api/scan/status");
      if (st.running && st.scan) {
        state.scanId = st.scan.id;
        setScanning(true);
        pollStatus();
      }
    } catch (_) {}
  }

  function formatVersion(v) {
    const raw = String(v || "").trim();
    if (!raw) return "";
    return raw.startsWith("v") ? raw : "v" + raw;
  }

  async function refreshAll() {
    await loadInventory();
    await loadHistory();
    if (!$("tab-changes").hidden) loadChanges();
  }

  function renderPrivilege() {
    const os = state.plat.os || "unknown";
    const elevated = !!state.session.elevated;
    const priv = $("priv-badge");
    priv.textContent = privilegeLabel(os, elevated);
    priv.classList.toggle("is-elevated", elevated);
    priv.classList.toggle("is-standard", !elevated);
    priv.title = elevated
      ? "This process has elevated privileges. Deep discovery can use ping (and ARP on Linux/macOS)."
      : elevationHowTo(os).detail;

    const how = elevationHowTo(os);
    const deepHint = $("deep-hint");
    deepHint.hidden = false;
    if (elevated) {
      deepHint.textContent =
        os === "windows"
          ? "Ready — ping available with your current privileges."
          : "Ready — ping and ARP available with your current privileges.";
    } else if (os === "windows") {
      deepHint.innerHTML = `Ping may still work without Admin. Prefer <button type="button" class="text-link" id="priv-help-link">${escapeHtml(how.short)}</button> for quieter devices.`;
    } else {
      deepHint.innerHTML = `Some quiet devices may stay hidden. <button type="button" class="text-link" id="priv-help-link">${escapeHtml(how.short)}</button>`;
    }
    $("priv-help-link")?.addEventListener("click", showCapabilities);
  }

  function renderStorage(storage) {
    const badge = $("storage-badge");
    badge.hidden = false;
    badge.classList.toggle("is-warn", storage.mode !== "persistent");
    if (storage.mode === "persistent") {
      badge.textContent = "History saved";
      badge.title = `Scan history and device notes are saved in ${storage.dir}`;
      $("storage-status").textContent = `History and device notes are saved in ${storage.dir}.`;
    } else {
      badge.textContent = "History not saved";
      badge.title = storage.reason || "History is kept in memory for this session only.";
      $("storage-status").textContent =
        (storage.reason || "History is kept in memory for this session only.") +
        " Comparisons still work between scans in this session.";
    }
  }

  // ---------- scope and preview ----------

  function renderScope() {
    const subnets = state.ifaces.subnets || [];
    if (!state.selected) state.selected = new Set(subnets.filter((s) => s.fits).map((s) => s.cidr));
    const limit = state.ifaces.addressLimit || 1024;
    if (!subnets.length) {
      $("scope-subnets").innerHTML = `<p class="empty">No local IPv4 networks detected. Enter a range below.</p>`;
      return;
    }
    $("scope-subnets").innerHTML = subnets
      .map((s) => {
        const id = "scope-" + s.cidr.replace(/[^0-9a-z]/gi, "-");
        const ifaces = (s.interfaces || []).join(", ");
        const size = s.fits
          ? `${fmtNumber(s.addresses)} addresses`
          : `${fmtNumber(s.addresses)} addresses — too large for one scan (limit ${fmtNumber(limit)}). Enter a smaller range below, such as a /24 inside it.`;
        return `<label class="check scope-item${s.fits ? "" : " too-large"}" for="${id}">
          <input type="checkbox" id="${id}" data-cidr="${escapeHtml(s.cidr)}" ${state.selected.has(s.cidr) ? "checked" : ""} ${s.fits ? "" : "disabled"} />
          <span><strong class="mono">${escapeHtml(s.cidr)}</strong>${ifaces ? ` <span class="muted">· ${escapeHtml(ifaces)}</span>` : ""}
          <small>${escapeHtml(size)}</small></span>
        </label>`;
      })
      .join("");
    $("scope-subnets").querySelectorAll("input[data-cidr]").forEach((cb) => {
      cb.addEventListener("change", () => {
        if (cb.checked) state.selected.add(cb.dataset.cidr);
        else state.selected.delete(cb.dataset.cidr);
        updatePreview();
      });
    });
  }

  function scanTargets() {
    const extra = $("targets").value.trim();
    const list = [...(state.selected || [])];
    if (extra) list.push(...extra.split(/[,\s]+/).filter(Boolean));
    return list;
  }

  let previewTimer = null;
  function updatePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 200);
  }

  async function runPreview() {
    const el = $("preview");
    const targets = scanTargets();
    if (!targets.length) {
      state.preview = null;
      el.className = "preview is-warn";
      el.textContent = "Select at least one network, or enter a range.";
      syncScanButton();
      return;
    }
    try {
      const res = await post("/api/scan/preview", {
        targets,
        deep: $("deep").checked,
        customOptIn: $("custom-optin").checked,
      });
      state.preview = res;
      const p = res.plan || {};
      if (res.ok) {
        el.className = "preview";
        el.innerHTML = `Will check <strong>${fmtNumber(p.addresses)}</strong> ${p.addresses === 1 ? "address" : "addresses"} in ${plural(
          (p.ranges || []).length,
          "range"
        )} <span class="mono">${escapeHtml((p.ranges || []).join(", "))}</span> using ${escapeHtml(methodsText(p.methods))}. Limit ${fmtNumber(p.limit)} per scan.`;
      } else {
        el.className = "preview is-warn";
        el.innerHTML =
          escapeHtml(res.problem || "This selection cannot be scanned.") +
          (res.needsOptIn ? ` <button type="button" class="text-link" id="optin-link">Allow custom ranges in Settings</button>` : "");
        $("optin-link")?.addEventListener("click", () => {
          activateTab("settings", false);
          $("custom-optin").focus();
        });
      }
    } catch (e) {
      state.preview = null;
      el.className = "preview is-warn";
      el.textContent = e.message;
    }
    syncScanButton();
  }

  function syncScanButton() {
    const running = !!state.polling;
    $("scan-btn").disabled = running || !(state.preview && state.preview.ok);
  }

  $("targets").addEventListener("input", updatePreview);
  $("deep").addEventListener("change", updatePreview);

  // ---------- scanning ----------

  function setScanning(running) {
    $("stop-btn").hidden = !running;
    $("progress").hidden = !running;
    if (running) {
      state.lastPct = 0;
      $("progress-bar").style.width = "0%";
      $("live").innerHTML = "";
      $("phases").innerHTML = "";
    }
    syncScanButton();
  }

  async function startScan(targets, label) {
    const status = $("scan-status");
    status.textContent = label || "Starting scan…";
    status.classList.add("is-busy");
    setScanNote("");
    try {
      const res = await post("/api/scan", {
        targets,
        deep: $("deep").checked,
        customOptIn: $("custom-optin").checked,
      });
      state.scanId = res.id || "";
      setScanning(true);
      pollStatus();
    } catch (e) {
      status.classList.remove("is-busy");
      status.textContent = "Could not start: " + e.message;
      setScanning(false);
    }
  }

  $("scan-btn").addEventListener("click", () => startScan(scanTargets()));

  $("stop-btn").addEventListener("click", async () => {
    try {
      await post("/api/scan/cancel", { id: state.scanId });
      $("scan-status").textContent = "Stopping… results so far are kept.";
    } catch (e) {
      $("scan-status").textContent = e.message;
    }
  });

  function phasePercent(run) {
    const ph = PHASES.find((p) => p.key === run.phase);
    if (!ph) return run.phase === "done" ? 100 : 0;
    const frac = run.total > 0 ? Math.min(1, run.done / run.total) : 0;
    return ph.from + (ph.to - ph.from) * frac;
  }

  function renderProgress(run) {
    const idx = PHASES.findIndex((p) => p.key === run.phase);
    $("phases").innerHTML = PHASES.map((p, i) => {
      const cls = i < idx || run.phase === "done" ? "done" : i === idx ? "current" : "";
      let count = "";
      if (i === idx && run.total > 0) count = ` <span class="phase-count">${fmtNumber(run.done)}/${fmtNumber(run.total)}</span>`;
      return `<li class="${cls}"${i === idx ? ' aria-current="step"' : ""}>${escapeHtml(p.label)}${count}</li>`;
    }).join("");
    // Never move the bar backwards, even if a phase reports fewer counts.
    state.lastPct = Math.max(state.lastPct, phasePercent(run));
    $("progress-bar").style.width = Math.round(state.lastPct) + "%";
    const found = run.found || [];
    $("live").innerHTML = found.length
      ? `<p class="context-label">Found so far (${found.length})</p><div class="chip-row">${found
          .slice(-60)
          .map((f) => `<span class="chip soft" title="${escapeHtml(f.via)}"><span class="mono">${escapeHtml(f.ip)}</span></span>`)
          .join("")}${found.length > 60 ? `<span class="chip soft">+${found.length - 60} earlier</span>` : ""}</div>`
      : "";
  }

  function pollStatus() {
    if (state.polling) clearInterval(state.polling);
    const status = $("scan-status");
    state.polling = setInterval(async () => {
      let st;
      try {
        st = await api("/api/scan/status");
      } catch (e) {
        return; // the disconnected banner shows; keep polling
      }
      const run = st.scan;
      if (!run || (state.scanId && run.id !== state.scanId)) return;
      if (st.running) {
        status.classList.add("is-busy");
        const ph = PHASES.find((p) => p.key === run.phase);
        status.textContent = `Scanning — ${ph ? ph.label.toLowerCase() : "starting"}${run.found?.length ? ` · ${plural(run.found.length, "device")} found` : ""}`;
        renderProgress(run);
        return;
      }
      clearInterval(state.polling);
      state.polling = null;
      setScanning(false);
      status.classList.remove("is-busy");
      const ended = {
        completed: "Scan finished.",
        canceled: "Scan stopped early. Results so far were kept and are marked partial.",
        timed_out: "Scan hit the time limit. Results so far were kept and are marked partial.",
        failed: "Scan failed" + (run.error ? ": " + run.error : "."),
      };
      status.textContent = (ended[run.state] || "Scan finished.") + (run.finishedAt ? ` (${fmtTime(run.finishedAt)})` : "");
      setScanNote(run.saveError ? "These results are shown but were not saved: " + run.saveError : "");
      state.justScanned = true; // point Changes at the newest two scans
      $("profile-select").value = ""; // show the network just scanned
      await refreshAll();
      state.justScanned = false;
      if (state.currentDeviceId && !$("modal").hidden) openDevice(state.currentDeviceId, false);
    }, 700);
    syncScanButton();
  }

  function setScanNote(text) {
    const el = $("scan-note");
    el.hidden = !text;
    el.textContent = text || "";
  }

  // ---------- inventory ----------

  async function loadInventory() {
    const profile = $("profile-select").value;
    try {
      state.inv = await api("/api/inventory" + (profile ? "?profile=" + encodeURIComponent(profile) : ""));
    } catch (e) {
      return;
    }
    renderStorage(state.inv.storage);
    renderProfiles();
    renderSummary();
    renderBanners();
    renderFilterOptions();
    renderDevices();
    renderFindings();
    renderSettingsData();
  }

  function renderProfiles() {
    const profiles = state.inv.profiles || [];
    const sel = $("profile-select");
    $("profile-pick").hidden = profiles.length < 2;
    sel.innerHTML = profiles
      .map((p) => `<option value="${escapeHtml(p.id)}" ${p.id === state.inv.profileId ? "selected" : ""}>${escapeHtml(p.name)}</option>`)
      .join("");
  }

  $("profile-select").addEventListener("change", () => refreshAll());

  function devices() {
    return state.inv?.devices || [];
  }

  function devIP(d) {
    return d.last?.host?.ip || d.address || "";
  }

  function devName(d) {
    if (d.name) return d.name;
    const h = d.last?.host || {};
    return humanizeText(h.hostname || identityHint(h, d.last?.ports) || h.vendor || "");
  }

  // Covered by the latest scan's ranges but not observed by it.
  function notSeen(d) {
    return !d.seenInLatest && d.inLatestScope;
  }

  function openFindings(d) {
    return (d.findings || []).filter((f) => f.review.status !== "acknowledged");
  }

  function worstSeverity(list) {
    let best = null;
    for (const f of list) if (best === null || SEV_RANK[f.severity] < SEV_RANK[best]) best = f.severity;
    return best;
  }

  function renderSummary() {
    const list = devices();
    const latest = state.inv.latestScan;
    const el = $("summary");
    if (!list.length && !latest) {
      el.hidden = true;
      return;
    }
    const seen = list.filter((d) => d.seenInLatest).length;
    const missing = list.filter(notSeen).length;
    const fresh = list.filter((d) => d.new).length;
    let services = 0;
    for (const d of list) if (d.seenInLatest) services += (d.last?.ports || []).length;
    const open = list.flatMap(openFindings);
    const sev = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length]));
    el.hidden = false;
    el.innerHTML = `
      <span class="sum-chip"><strong>${seen}</strong> in latest scan</span>
      ${fresh ? `<span class="sum-chip accent"><strong>${fresh}</strong> new</span>` : ""}
      ${missing ? `<span class="sum-chip soft"><strong>${missing}</strong> not seen</span>` : ""}
      <span class="sum-chip"><strong>${services}</strong> open services</span>
      ${sev.critical ? `<span class="sum-chip sev-critical"><strong>${sev.critical}</strong> critical</span>` : ""}
      ${sev.high ? `<span class="sum-chip sev-high"><strong>${sev.high}</strong> high</span>` : ""}
      ${sev.medium ? `<span class="sum-chip sev-medium"><strong>${sev.medium}</strong> medium</span>` : ""}
      ${latest ? `<span class="sum-chip soft" title="${escapeHtml(fmtTime(latest.finishedAt))}">Last scan ${escapeHtml(ago(latest.finishedAt))}</span>` : ""}
    `;
  }

  function renderBanners() {
    const out = [];
    const st = state.inv.storage || {};
    if (st.mode === "unavailable") out.push({ cls: "is-error", text: st.reason });
    if (st.lastError) out.push({ cls: "is-error", text: "Saving failed: " + st.lastError + " Results stay visible and can be exported." });
    const latest = state.inv.latestScan;
    if (latest) {
      if (latest.partial) {
        const how = latest.state === "timed_out" ? "hit the time limit" : latest.state === "failed" ? "failed" : "was stopped early";
        out.push({
          cls: "is-warn",
          text: `The latest scan ${how}, so its results are partial. Devices marked “not seen” may simply not have been checked.`,
        });
      }
      if (Date.now() - new Date(latest.finishedAt).getTime() > STALE_MS) {
        out.push({ cls: "is-warn", text: `The latest scan is from ${fmtTime(latest.finishedAt)}. Scan again for a current picture.` });
      }
    }
    $("inventory-banners").innerHTML = out.map((b) => `<div class="banner ${b.cls}">${escapeHtml(b.text)}</div>`).join("");
  }

  function renderFilterOptions() {
    const list = devices();
    const fill = (id, values) => {
      const sel = $(id);
      const cur = sel.value;
      const opts = [...new Set(values.filter(Boolean))].sort((a, b) => String(a).localeCompare(String(b), undefined, { numeric: true }));
      sel.innerHTML =
        `<option value="">Any</option>` +
        opts.map((v) => `<option value="${escapeHtml(v)}" ${String(v) === cur ? "selected" : ""}>${escapeHtml(v)}</option>`).join("");
    };
    fill(
      "f-service",
      list.flatMap((d) => (d.last?.ports || []).map((p) => `${p.port}/${p.service}`))
    );
    fill("f-vendor", list.map((d) => d.last?.host?.vendor));
    fill("f-tag", list.flatMap((d) => d.tags || []));
  }

  function deviceMatches(d) {
    const q = $("host-filter").value.trim().toLowerCase();
    if (q) {
      const h = d.last?.host || {};
      const hints = (d.last?.ports || []).flatMap((p) => [p.httpTitle, p.httpServer, p.tlsCommonName, p.banner, p.service]);
      const blob = [devIP(d), d.mac, d.name, d.notes, ...(d.tags || []), h.hostname, h.vendor, h.upnpFriendlyName, h.snmpSysDescr, ...hints]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!blob.includes(q)) return false;
    }
    const svc = $("f-service").value;
    if (svc && !(d.last?.ports || []).some((p) => `${p.port}/${p.service}` === svc)) return false;
    const vendor = $("f-vendor").value;
    if (vendor && d.last?.host?.vendor !== vendor) return false;
    const tag = $("f-tag").value;
    if (tag && !(d.tags || []).includes(tag)) return false;
    const seen = $("f-seen").value;
    if (seen === "new" && !d.new) return false;
    if (seen === "latest" && !d.seenInLatest) return false;
    if (seen === "missing" && !notSeen(d)) return false;
    const fs = $("f-findings").value;
    if (fs === "open" && !openFindings(d).length) return false;
    if (fs === "acknowledged" && !(d.findings || []).some((f) => f.review.status === "acknowledged")) return false;
    if (fs === "none" && (d.findings || []).length) return false;
    return true;
  }

  const SORTERS = {
    ip: (d) => devIP(d).split(".").map((n) => n.padStart(3, "0")).join("."),
    name: (d) => devName(d).toLowerCase() || "￿",
    vendor: (d) => (d.last?.host?.vendor || "￿").toLowerCase(),
    services: (d) => -(d.last?.ports || []).length,
    findings: (d) => {
      const w = worstSeverity(openFindings(d));
      return w === null ? 9 : SEV_RANK[w];
    },
    seen: (d) => -new Date(d.lastSeen).getTime(),
  };

  const COLUMNS = [
    { key: "ip", label: "Address" },
    { key: "name", label: "Name" },
    { key: "vendor", label: "Vendor" },
    { key: "services", label: "Services" },
    { key: "findings", label: "Findings" },
    { key: "seen", label: "Last seen" },
  ];

  function renderDevices() {
    const all = devices();
    const list = all.filter(deviceMatches);
    const sorter = SORTERS[state.sort.key] || SORTERS.ip;
    list.sort((a, b) => {
      const x = sorter(a);
      const y = sorter(b);
      return (x < y ? -1 : x > y ? 1 : 0) * state.sort.dir;
    });
    const filtered = list.length !== all.length;
    $("host-count").textContent = filtered ? `${list.length} / ${all.length}` : String(all.length);

    const focusKey = document.activeElement?.dataset?.focusKey;
    if (!all.length) {
      $("hosts").innerHTML = `<div class="empty-coach">
        <p class="empty">No devices yet. Choose networks above and press Scan.</p>
        <ul class="notes">
          <li>Guest Wi‑Fi or AP/client isolation can hide other devices.</li>
          <li>Try <strong>Deep discovery</strong> (and elevate with sudo / Run as administrator).</li>
          <li>Confirm you’re on the right network interface/subnet.</li>
        </ul>
      </div>`;
      return;
    }
    if (!list.length) {
      $("hosts").innerHTML = `<div class="empty-coach"><p class="empty">No devices match these filters.</p>
        <button type="button" class="ghost compact" id="clear-filters">Clear filters</button></div>`;
      $("clear-filters").addEventListener("click", clearFilters);
      return;
    }

    const head = COLUMNS.map((c) => {
      const active = state.sort.key === c.key;
      const aria = active ? (state.sort.dir === 1 ? "ascending" : "descending") : "none";
      const arrow = active ? (state.sort.dir === 1 ? "▲" : "▼") : "";
      return `<th aria-sort="${aria}" class="col-${c.key}"><button type="button" class="sort-btn" data-sort="${c.key}" data-focus-key="sort-${c.key}">${escapeHtml(
        c.label
      )}<span class="sort-arrow" aria-hidden="true">${arrow}</span></button></th>`;
    }).join("");

    const rows = list
      .map((d) => {
        const h = d.last?.host || {};
        const ports = d.last?.ports || [];
        const name = devName(d);
        const open = openFindings(d);
        const worst = worstSeverity(open);
        const badges = [];
        if (d.new) badges.push(`<span class="tag-pill new">New</span>`);
        if (notSeen(d)) badges.push(`<span class="tag-pill missing" title="The latest scan covered this address but did not observe the device">Not seen</span>`);
        if (h.isSelf) badges.push(`<span class="tag-pill self">This device</span>`);
        if (h.isGateway) badges.push(`<span class="tag-pill gw">Gateway</span>`);
        if (d.uncertain?.length) badges.push(`<span class="tag-pill guess" title="${escapeHtml(d.uncertain.join(" "))}">Identity uncertain</span>`);
        const tags = (d.tags || []).map((t) => `<span class="tag-pill user">${escapeHtml(t)}</span>`).join("");
        const findings = (d.findings || []).length
          ? worst
            ? `<span class="sev ${escapeHtml(worst)}">${escapeHtml(worst)}</span> <span class="muted">${open.length} open</span>`
            : `<span class="muted">${(d.findings || []).length} acknowledged</span>`
          : `<span class="muted">—</span>`;
        return `<tr tabindex="0" data-device="${escapeHtml(d.id)}" data-focus-key="row-${escapeHtml(d.id)}" aria-label="${escapeHtml(
          `${devIP(d)} ${name}`
        )}, open details">
          <td class="col-ip"><span class="mono ip">${escapeHtml(devIP(d))}</span><div class="badge-row">${badges.join("")}</div></td>
          <td class="col-name"><div class="name-primary${name ? "" : " name-empty"}" title="${escapeHtml(name)}">${escapeHtml(name || "Unknown")}</div>${
            tags ? `<div class="badge-row">${tags}</div>` : ""
          }</td>
          <td class="col-vendor"><span class="clip" title="${escapeHtml(h.vendor || "")}">${escapeHtml(humanizeText(h.vendor || "—"))}</span></td>
          <td class="col-services">${
            ports.length
              ? `<div class="port-list">${ports.slice(0, 4).map(portPill).join("")}${ports.length > 4 ? `<span class="port-more">+${ports.length - 4}</span>` : ""}</div>`
              : `<span class="muted">—</span>`
          }</td>
          <td class="col-findings">${findings}</td>
          <td class="col-seen"><span title="${escapeHtml(fmtTime(d.lastSeen))}">${escapeHtml(ago(d.lastSeen))}</span></td>
        </tr>`;
      })
      .join("");

    $("hosts").innerHTML = `<div class="table-wrap"><table class="hosts-table devices-table">
      <caption class="sr-only">Devices. Select a row to open its details.</caption>
      <thead><tr>${head}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

    $("hosts").querySelectorAll("[data-sort]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const key = btn.dataset.sort;
        state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : 1 };
        renderDevices();
      });
    });
    $("hosts").querySelectorAll("tr[data-device]").forEach((tr) => {
      tr.addEventListener("click", (e) => {
        if (e.target.closest("button, a")) return;
        openDevice(tr.dataset.device);
      });
      tr.addEventListener("keydown", (e) => {
        if (e.target !== tr) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          openDevice(tr.dataset.device);
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          const sib = e.key === "ArrowDown" ? tr.nextElementSibling : tr.previousElementSibling;
          sib?.focus();
        }
      });
    });
    bindFloatTips($("hosts"));
    if (focusKey) document.querySelector(`[data-focus-key="${CSS.escape(focusKey)}"]`)?.focus();
  }

  function clearFilters() {
    $("host-filter").value = "";
    for (const id of ["f-service", "f-vendor", "f-tag", "f-seen", "f-findings"]) $(id).value = "";
    renderDevices();
    $("host-filter").focus();
  }

  for (const id of ["host-filter", "f-service", "f-vendor", "f-tag", "f-seen", "f-findings"]) {
    $(id).addEventListener(id === "host-filter" ? "input" : "change", () => renderDevices());
  }

  // ---------- device detail ----------

  async function openDevice(id, focus = true) {
    let d;
    try {
      d = await api("/api/devices/" + encodeURIComponent(id));
    } catch (e) {
      return;
    }
    state.currentDeviceId = id;
    const h = d.last?.host || {};
    const ports = d.last?.ports || [];
    const name = devName(d);

    const identityRows = [
      ["Identified by", d.basis === "mac" ? "MAC address" : "IP address only"],
      ["MAC", d.mac || h.mac || "—"],
      ["Vendor", h.vendor || (h.privateMac ? "Private (randomised) MAC — no maker to look up" : "—")],
      ["Hostname", h.hostname || "—"],
      ["UPnP name", h.upnpFriendlyName || ""],
      ["SNMP", h.snmpSysDescr || ""],
      ["First seen", fmtTime(d.firstSeen)],
      ["Last seen", `${fmtTime(d.lastSeen)}${d.seenInLatest ? "" : " (not in the latest scan)"}`],
    ].filter(([, v]) => v);

    const certs = ports.filter((p) => p.tlsCommonName || p.tlsIssuer);
    const html = `
      <section class="detail-section">
        <h3>Your notes</h3>
        <form id="annotate-form" class="annotate">
          <label class="field"><span>Name</span><input id="a-name" type="text" maxlength="80" value="${escapeHtml(d.name || "")}" placeholder="${escapeHtml(
            name || "Give this device a name"
          )}" /></label>
          <label class="field"><span>Tags <small class="muted">(comma separated)</small></span><input id="a-tags" type="text" maxlength="400" value="${escapeHtml(
            (d.tags || []).join(", ")
          )}" /></label>
          <label class="field"><span>Notes</span><textarea id="a-notes" rows="3" maxlength="4000">${escapeHtml(d.notes || "")}</textarea></label>
          <div class="form-actions">
            <button type="submit" class="primary">Save notes</button>
            <button type="button" class="ghost" id="rescan-device" ${devIP(d) ? "" : "disabled"}>Rescan this device</button>
            <span id="annotate-status" class="status-line" aria-live="polite"></span>
          </div>
        </form>
      </section>
      <section class="detail-section">
        <h3>Identity</h3>
        <dl class="kv">${identityRows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`).join("")}</dl>
        ${(d.uncertain || []).map((u) => `<p class="banner is-warn">${escapeHtml(u)}</p>`).join("")}
        ${
          (h.aliveVia || []).length
            ? `<p class="context-label">How it was found</p><ul class="plain">${h.aliveVia
                .map((v) => `<li><span class="via-chip">${escapeHtml(v)}</span> <span class="muted small">${escapeHtml(viaText(v))}</span></li>`)
                .join("")}</ul>`
            : ""
        }
      </section>
      <section class="detail-section">
        <h3>Addresses</h3>
        <ul class="plain">${(d.addresses || [])
          .map((a) => `<li><span class="mono">${escapeHtml(a.ip)}</span> <span class="muted">${escapeHtml(fmtTime(a.first))} – ${escapeHtml(fmtTime(a.last))}</span></li>`)
          .join("")}</ul>
      </section>
      <section class="detail-section">
        <h3>Services (${ports.length})</h3>
        ${
          ports.length
            ? `<ul class="plain services">${ports
                .map(
                  (p) => `<li><span class="mono">${escapeHtml(p.port)}/${escapeHtml(p.service)}</span>
                  ${p.protocol ? `<span class="tag-pill self">confirmed ${escapeHtml(p.protocol)}</span>` : `<span class="tag-pill">port only</span>`}
                  ${portEnrichLines(p)
                    .filter((l) => !l.startsWith("Answered as"))
                    .map((l) => `<div class="muted small">${escapeHtml(l)}</div>`)
                    .join("")}</li>`
                )
                .join("")}</ul>`
            : `<p class="muted">No findings ports answered in the latest observation.</p>`
        }
      </section>
      ${
        certs.length
          ? `<section class="detail-section"><h3>Certificates</h3><ul class="plain">${certs
              .map(
                (p) =>
                  `<li><span class="mono">:${escapeHtml(p.port)}</span> ${escapeHtml(p.tlsCommonName || "(no CN)")} <span class="muted">· issuer ${escapeHtml(
                    p.tlsIssuer || "?"
                  )} · ${p.tlsExpired ? "expired" : "valid until"} ${escapeHtml(String(p.tlsNotAfter || "").slice(0, 10))}${
                    p.tlsSelfSigned ? " · self-signed" : ""
                  }</span></li>`
              )
              .join("")}</ul></section>`
          : ""
      }
      <section class="detail-section">
        <h3>Findings (${(d.findings || []).length})</h3>
        ${(d.findings || []).length ? (d.findings || []).map((f) => findingCard(f)).join("") : `<p class="muted">None in the latest observation.</p>`}
      </section>
      <section class="detail-section">
        <h3>Observation history</h3>
        ${
          (d.history || []).length
            ? `<div class="table-wrap"><table class="mini-table"><thead><tr><th>Scan</th><th>Address</th><th>Open ports</th><th>Findings</th></tr></thead><tbody>${[...d.history]
                .reverse()
                .map(
                  (e) => `<tr><td>${escapeHtml(fmtTime(e.at))}${e.partial ? ` <span class="tag-pill guess">partial</span>` : ""}</td><td class="mono">${escapeHtml(
                    e.ip
                  )}</td><td class="mono">${escapeHtml((e.ports || []).join(", ") || "—")}</td><td>${escapeHtml(e.findings)}</td></tr>`
                )
                .join("")}</tbody></table></div>`
            : `<p class="muted">No retained scans include this device.</p>`
        }
      </section>`;

    openModal(name || devIP(d) || "Device", devIP(d) + (d.mac ? " · " + d.mac : ""), html, focus);
    const body = $("modal-body");
    $("annotate-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const tags = $("a-tags")
        .value.split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const out = $("annotate-status");
      try {
        const res = await post("/api/devices/" + encodeURIComponent(id), { name: $("a-name").value, notes: $("a-notes").value, tags });
        out.textContent = res.saveError ? "Changed for this session, but saving failed: " + res.saveError : "Saved.";
        $("modal-title").textContent = stripBidi(res.device.name || name || devIP(d));
        await loadInventory();
      } catch (err) {
        out.textContent = err.message;
      }
    });
    $("rescan-device").addEventListener("click", () => {
      const ip = devIP(d);
      closeModal();
      activateTab("devices", false);
      startScan([ip + "/32"], `Rescanning ${ip}…`);
    });
    bindReviewControls(body, () => openDevice(id, false));
    bindFloatTips(body);
  }

  // ---------- findings ----------

  function findingKey(f) {
    return f.rule + "/" + (f.port || 0);
  }

  function findingCard(f) {
    const review = f.review || { status: "open" };
    const evidence = (f.evidence || [])
      .map(
        (e) =>
          `<li><span class="ev-method">${escapeHtml(e.method)}</span> ${escapeHtml(e.summary)}${e.endpoint ? ` <span class="mono muted">${escapeHtml(e.endpoint)}</span>` : ""}</li>`
      )
      .join("");
    const reviewHtml =
      review.status === "open"
        ? `<div class="review-row">
            <label class="field compact grow"><span class="sr-only">Note for ${escapeHtml(f.title)}</span><input type="text" maxlength="1000" placeholder="Why this is expected (optional)" data-review-note /></label>
            <button type="button" class="ghost compact" data-review="ack" data-key="${escapeHtml(findingKey(f))}" data-device-id="${escapeHtml(f.deviceId)}">Acknowledge</button>
          </div>`
        : `<div class="review-row">
            <span class="review-state ${escapeHtml(review.status)}">${
              review.status === "reopened" ? "Reopened: the evidence changed since you acknowledged it" : "Acknowledged"
            }${review.note ? ` — “${escapeHtml(review.note)}”` : ""}</span>
            ${
              review.status === "reopened"
                ? `<button type="button" class="ghost compact" data-review="ack" data-key="${escapeHtml(findingKey(f))}" data-device-id="${escapeHtml(f.deviceId)}">Acknowledge again</button>`
                : ""
            }
            <button type="button" class="ghost compact" data-review="open" data-key="${escapeHtml(findingKey(f))}" data-device-id="${escapeHtml(f.deviceId)}">Reopen</button>
          </div>`;
    return `<article class="finding${review.status === "acknowledged" ? " is-acked" : ""}">
      <div class="finding-tags">
        <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
        <span class="tag-pill conf-${escapeHtml(f.confidence)}" title="${
          f.confidence === "confirmed" ? "A response from the device backs this." : "Only an open port backs this."
        }">${escapeHtml(f.confidence)}</span>
        <span class="tag-pill">${escapeHtml(CATEGORY_LABEL[f.category] || f.category)}</span>
        ${f.port ? `<span class="tag-pill mono">port ${escapeHtml(f.port)}</span>` : ""}
      </div>
      <h4>${escapeHtml(f.title)}</h4>
      <p>${escapeHtml(f.description)}</p>
      ${evidence ? `<p class="fg small"><strong>Why it appeared</strong></p><ul class="evidence">${evidence}</ul>` : ""}
      ${f.unknown ? `<p class="small"><strong class="fg">Still unknown:</strong> ${escapeHtml(f.unknown)}</p>` : ""}
      <p class="small"><strong class="fg">What to try:</strong> ${escapeHtml(f.remediation)}</p>
      ${f.deviceId ? reviewHtml : ""}
    </article>`;
  }

  function bindReviewControls(root, after) {
    root.querySelectorAll("[data-review]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ack = btn.dataset.review === "ack";
        const note = btn.closest(".review-row")?.querySelector("[data-review-note]")?.value || "";
        await setReview(btn.dataset.deviceId, btn.dataset.key, ack, note);
        after?.();
      });
    });
    root.querySelectorAll("[data-open-device]").forEach((btn) => {
      btn.addEventListener("click", () => openDevice(btn.dataset.openDevice));
    });
  }

  async function setReview(deviceId, key, acknowledged, note) {
    try {
      const res = await post("/api/devices/" + encodeURIComponent(deviceId) + "/review", { key, acknowledged, note });
      if (res.saveError) setScanNote("Review changed for this session, but saving failed: " + res.saveError);
    } catch (e) {
      $("scan-status").textContent = e.message;
    }
    await loadInventory();
  }

  function renderFindings() {
    const all = devices().flatMap((d) => (d.findings || []).map((f) => ({ ...f, _device: d })));
    const byStatus = {
      open: all.filter((f) => f.review.status !== "acknowledged"),
      acknowledged: all.filter((f) => f.review.status === "acknowledged"),
      all,
    };
    $("finding-count").textContent = String(byStatus.open.length);
    $("status-filters").innerHTML = [
      ["open", "Needs review"],
      ["acknowledged", "Acknowledged"],
      ["all", "All"],
    ]
      .map(
        ([k, label]) =>
          `<button type="button" class="filter-chip${state.findingStatus === k ? " active" : ""}" aria-pressed="${state.findingStatus === k}" data-status="${k}">${label} (${byStatus[k].length})</button>`
      )
      .join("");
    const pool = byStatus[state.findingStatus];
    $("sev-filters").innerHTML = ["all", ...SEVERITIES]
      .map((s) => {
        const n = s === "all" ? pool.length : pool.filter((f) => f.severity === s).length;
        return `<button type="button" class="filter-chip${state.findingSev === s ? " active" : ""}" aria-pressed="${state.findingSev === s}" data-sev="${s}">${s} (${n})</button>`;
      })
      .join("");
    $("status-filters")
      .querySelectorAll("[data-status]")
      .forEach((b) =>
        b.addEventListener("click", () => {
          state.findingStatus = b.dataset.status;
          renderFindings();
          $("status-filters").querySelector(`[data-status="${b.dataset.status}"]`)?.focus();
        })
      );
    $("sev-filters")
      .querySelectorAll("[data-sev]")
      .forEach((b) =>
        b.addEventListener("click", () => {
          state.findingSev = b.dataset.sev;
          renderFindings();
          $("sev-filters").querySelector(`[data-sev="${b.dataset.sev}"]`)?.focus();
        })
      );

    const list = state.findingSev === "all" ? pool : pool.filter((f) => f.severity === state.findingSev);
    if (!all.length) {
      $("findings").innerHTML = `<p class="empty">No findings yet. Run a scan from Devices.</p>`;
      return;
    }
    if (!list.length) {
      $("findings").innerHTML = `<p class="empty">Nothing here with these filters.</p>`;
      return;
    }
    const open = new Set([...$("findings").querySelectorAll("details[open]")].map((el) => el.dataset.host));
    const groups = new Map();
    for (const f of list) {
      if (!groups.has(f.deviceId)) groups.set(f.deviceId, []);
      groups.get(f.deviceId).push(f);
    }
    const order = [...groups.keys()].sort((a, b) => {
      const wa = Math.min(...groups.get(a).map((f) => SEV_RANK[f.severity]));
      const wb = Math.min(...groups.get(b).map((f) => SEV_RANK[f.severity]));
      return wa - wb || devIP(groups.get(a)[0]._device).localeCompare(devIP(groups.get(b)[0]._device), undefined, { numeric: true });
    });
    $("findings").innerHTML = `<div class="host-risk-list">${order
      .map((id) => {
        const items = groups.get(id).sort((x, y) => SEV_RANK[x.severity] - SEV_RANK[y.severity]);
        const d = items[0]._device;
        const counts = SEVERITIES.map((s) => {
          const n = items.filter((f) => f.severity === s).length;
          return n ? `<span class="sev ${s}">${n} ${s}</span>` : "";
        }).join("");
        return `<details class="host-risk-group" data-host="${escapeHtml(id)}"${open.has(id) ? " open" : ""}>
          <summary>
            <div class="host-risk-summary">
              <div>
                <div class="host-risk-ip mono">${escapeHtml(devIP(d))}</div>
                ${devName(d) ? `<div class="host-risk-name">${escapeHtml(devName(d))}</div>` : ""}
                ${d.seenInLatest ? "" : `<div class="muted small">Last seen ${escapeHtml(ago(d.lastSeen))}; not in the latest scan</div>`}
              </div>
              <div class="host-risk-chips">${counts}<span class="count-pill">${items.length}</span></div>
            </div>
          </summary>
          <div class="host-risk-items">
            ${items.map((f) => findingCard(f)).join("")}
            <button type="button" class="ghost compact" data-open-device="${escapeHtml(id)}">Open device</button>
          </div>
        </details>`;
      })
      .join("")}</div>`;
    bindReviewControls($("findings"), null);
  }

  // ---------- history and changes ----------

  async function loadHistory() {
    const profile = state.inv?.profileId;
    try {
      const res = await api("/api/history" + (profile ? "?profile=" + encodeURIComponent(profile) : ""));
      state.history = res.scans || [];
    } catch (_) {
      return;
    }
    $("history-count").textContent = String(state.history.length);
    const opt = (s) =>
      `<option value="${escapeHtml(s.id)}">${escapeHtml(fmtTime(s.finishedAt))} · ${plural(s.hosts, "device")}${s.partial ? " · partial" : ""}</option>`;
    for (const [id, offset] of [
      ["cmp-current", 0],
      ["cmp-previous", 1],
    ]) {
      const sel = $(id);
      const cur = sel.value;
      sel.innerHTML = state.history.map(opt).join("");
      if (cur && state.history.some((s) => s.id === cur) && !state.justScanned) sel.value = cur;
      else if (state.history[offset]) sel.value = state.history[offset].id;
    }
    if (!state.history.length) {
      $("history").innerHTML = `<p class="empty">No saved scans yet.</p>`;
      return;
    }
    $("history").innerHTML = `<div class="table-wrap"><table class="hosts-table mini-table">
      <caption class="sr-only">Retained scans, newest first</caption>
      <thead><tr><th>When</th><th>Result</th><th>Ranges</th><th>Methods</th><th>Devices</th><th>Findings</th><th><span class="sr-only">Export</span></th></tr></thead>
      <tbody>${state.history
        .map(
          (s) => `<tr>
          <td>${escapeHtml(fmtTime(s.finishedAt))}</td>
          <td>${escapeHtml(STATE_LABEL[s.state] || s.state)}${s.partial ? ` <span class="tag-pill guess">partial</span>` : ""}</td>
          <td class="mono">${escapeHtml((s.ranges || []).join(", "))}</td>
          <td>${escapeHtml(methodsText(s.methods))}</td>
          <td>${escapeHtml(s.hosts)}</td>
          <td>${escapeHtml(s.findings)}</td>
          <td class="nowrap"><button type="button" class="ghost compact" data-export-scan="${escapeHtml(s.id)}" data-format="json">JSON</button>
            <button type="button" class="ghost compact" data-export-scan="${escapeHtml(s.id)}" data-format="csv">CSV</button></td>
        </tr>`
        )
        .join("")}</tbody></table></div>`;
    $("history")
      .querySelectorAll("[data-export-scan]")
      .forEach((b) => b.addEventListener("click", () => download(`/api/export?scan=${encodeURIComponent(b.dataset.exportScan)}&format=${b.dataset.format}`)));
  }

  $("cmp-current").addEventListener("change", loadChanges);
  $("cmp-previous").addEventListener("change", loadChanges);

  const CHANGE_SECTIONS = [
    ["newDevices", "New devices", () => ""],
    ["addressChanges", "Address changes", (c) => `${c.from} → ${c.to}`],
    ["newServices", "Newly observed services", (c) => `${c.port}/${c.service}`],
    ["closedServices", "Services now refusing connections", (c) => `${c.port}/${c.service}`],
    ["certChanges", "Certificate changes", (c) => `:${c.port} ${c.field}: ${c.from || "—"} → ${c.to || "—"}`],
    ["newFindings", "New findings", (c) => `${c.severity} · ${c.title}`],
    ["changedFindings", "Findings that changed", (c) => `${c.title}: ${c.from} → ${c.to}`],
    ["resolvedFindings", "Findings resolved", (c) => c.title],
    ["notObserved", "Not observed this time", () => ""],
    ["unansweredServices", "Services that did not answer this time", (c) => `${c.port}/${c.service}`],
    ["findingsNotSeen", "Findings not reported this time", (c) => c.title],
  ];

  async function loadChanges() {
    const el = $("changes");
    const cur = $("cmp-current").value;
    const prev = $("cmp-previous").value;
    if (state.history.length < 2) {
      el.innerHTML = `<p class="empty">Changes appear after two scans of the same network.</p>`;
      return;
    }
    if (cur === prev) {
      el.innerHTML = `<p class="empty">Pick two different scans.</p>`;
      return;
    }
    const q = new URLSearchParams({ profile: state.inv?.profileId || "", current: cur, previous: prev });
    let c;
    try {
      c = await api("/api/changes?" + q.toString());
    } catch (e) {
      el.innerHTML = `<p class="banner is-error">${escapeHtml(e.message)}</p>`;
      return;
    }
    if (c.error) {
      el.innerHTML = `<p class="banner is-error">${escapeHtml(c.error)}</p>`;
      return;
    }
    const head = `<p class="help">Comparing the scan finished <strong>${escapeHtml(fmtTime(c.current.finishedAt))}</strong>${
      c.current.partial ? " (partial)" : ""
    } with the one finished <strong>${escapeHtml(fmtTime(c.previous.finishedAt))}</strong>${c.previous.partial ? " (partial)" : ""}.</p>`;
    const scope = (c.scope || []).length ? `<div class="banner is-warn"><ul class="plain">${c.scope.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul></div>` : "";
    const sections = CHANGE_SECTIONS.filter(([k]) => (c[k] || []).length)
      .map(
        ([k, label, detail]) => `<section class="change-group">
          <h4>${escapeHtml(label)} <span class="count-pill">${c[k].length}</span></h4>
          <ul class="plain change-list">${c[k]
            .map(
              (x) => `<li><button type="button" class="text-link" data-open-device="${escapeHtml(x.deviceId)}"><span class="mono">${escapeHtml(x.ip)}</span>${
                x.name ? ` ${escapeHtml(humanizeText(x.name))}` : ""
              }</button>${detail(x) ? ` <span>${escapeHtml(detail(x))}</span>` : ""}${x.note ? ` <span class="muted small">${escapeHtml(x.note)}</span>` : ""}</li>`
            )
            .join("")}</ul></section>`
      )
      .join("");
    el.innerHTML = head + scope + (sections || `<p class="empty">No differences between these scans.</p>`);
    el.querySelectorAll("[data-open-device]").forEach((b) => b.addEventListener("click", () => openDevice(b.dataset.openDevice)));
  }

  // ---------- settings ----------

  function renderSettingsData() {
    const p = (state.inv.profiles || []).find((x) => x.id === state.inv.profileId);
    $("profile-name").value = p ? p.name : "";
    $("profile-name").disabled = !p;
    $("profile-save").disabled = !p;
    $("retention").value = state.inv.retention || 100;
  }

  $("profile-save").addEventListener("click", async () => {
    try {
      await post("/api/profiles/" + encodeURIComponent(state.inv.profileId), { name: $("profile-name").value });
      $("data-result").textContent = "Network renamed.";
      await loadInventory();
    } catch (e) {
      $("data-result").textContent = e.message;
    }
  });

  $("retention-save").addEventListener("click", async () => {
    try {
      await post("/api/settings", { retention: Number($("retention").value) });
      $("data-result").textContent = "Saved.";
      await refreshAll();
    } catch (e) {
      $("data-result").textContent = e.message;
    }
  });

  $("delete-history").addEventListener("click", async () => {
    if (!confirm("Delete every saved scan? Device names, notes, tags, and reviews are kept.")) return;
    try {
      await post("/api/history/delete", { what: "scans" });
      $("data-result").textContent = "Scan history deleted.";
      await refreshAll();
    } catch (e) {
      $("data-result").textContent = e.message;
    }
  });

  $("delete-all").addEventListener("click", async () => {
    if (!confirm("Delete all saved data: scans, devices, names, notes, tags, and reviews? This cannot be undone.")) return;
    try {
      await post("/api/history/delete", { what: "all" });
      $("data-result").textContent = "All saved data deleted.";
      $("profile-select").innerHTML = "";
      await refreshAll();
    } catch (e) {
      $("data-result").textContent = e.message;
    }
  });

  async function saveSettings() {
    await post("/api/settings", {
      customOptIn: $("custom-optin").checked,
      updatesOptIn: $("updates-optin").checked,
    });
  }
  $("custom-optin").addEventListener("change", () => saveSettings().then(updatePreview));
  $("updates-optin").addEventListener("change", saveSettings);

  $("check-update").addEventListener("click", async () => {
    const out = $("update-result");
    out.hidden = false;
    out.className = "update-result";
    out.textContent = "Checking…";
    try {
      await saveSettings();
      if (!$("updates-optin").checked) {
        out.textContent = "Enable “Allow update checks” first.";
        return;
      }
      const res = await post("/api/update", {});
      if (res.error) {
        out.classList.add("is-error");
        out.innerHTML = `<p>${escapeHtml(res.message || res.error)}</p>`;
        return;
      }
      out.classList.add(res.updateAvailable ? "is-update" : "is-ok");
      let html = `<p>${escapeHtml(res.message || "Check complete.")}</p>`;
      if (res.releaseUrl) {
        html += `<p><a href="${escapeHtml(res.releaseUrl)}" target="_blank" rel="noopener noreferrer">Open release page</a></p>`;
      }
      out.innerHTML = html;
    } catch (e) {
      out.classList.add("is-error");
      out.textContent = e.message;
    }
  });

  function renderPortLists(ifaces) {
    $("port-lists").innerHTML = `
      <p class="context-label">Discovery ports</p>
      <p class="port-inline mono">${escapeHtml((ifaces.discoveryPorts || []).join(", ") || "—")}</p>
      <p class="context-label">Findings ports</p>
      <p class="port-inline mono">${escapeHtml((ifaces.findingsPorts || []).join(", ") || "—")}</p>
    `;
  }

  function renderPlatform(plat) {
    const os = plat.os || "unknown";
    const isElevated = !!plat.elevated;
    const how = elevationHowTo(os);
    const meta = `
      <div class="priv-card ${isElevated ? "is-elevated" : "is-standard"}">
        <div class="priv-card-top">
          <span class="priv-card-label">App privileges</span>
        </div>
        <p class="priv-card-help">${
          isElevated ? "Deep discovery can use ICMP ping (and ARP on Linux/macOS) with your current privileges." : escapeHtml(how.detail)
        }</p>
      </div>
      <div class="meta-chips">
        <span class="meta-chip"><span class="k">OS</span><span class="v">${escapeHtml(os)}</span></span>
        <span class="meta-chip"><span class="k">Arch</span><span class="v">${escapeHtml(plat.arch)}</span></span>
      </div>`;
    const legend = Object.entries(STATUS_LEGEND)
      .map(([k, v]) => `<li><span class="status-pill ${escapeHtml(k)}">${escapeHtml(STATUS_LABEL[k] || k)}</span> ${escapeHtml(v)}</li>`)
      .join("");
    const caps = (plat.capabilities || [])
      .map(
        (c) => `<li>
          <div class="cap-top"><strong>${escapeHtml(c.name)}</strong><span class="status-pill ${escapeHtml(c.status)}">${escapeHtml(STATUS_LABEL[c.status] || c.status)}</span></div>
          <div class="muted">${escapeHtml(c.detail)}</div>
        </li>`
      )
      .join("");
    const notes = (plat.notes || []).map((n) => `<li>${escapeHtml(n)}</li>`).join("");
    $("platform").innerHTML = `
      ${meta}
      <p class="context-label">Capability status legend</p>
      <ul class="status-legend">${legend}</ul>
      <ul class="cap-list">${caps}</ul>
      <h4 class="subhead">Notes</h4>
      <ul class="notes">${notes}</ul>
    `;
  }

  // ---------- export ----------

  function download(path) {
    const a = document.createElement("a");
    a.href = path + (path.includes("?") ? "&" : "?") + "token=" + encodeURIComponent(TOKEN);
    a.download = "";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }
  // "Latest scan" is the selected network's newest retained scan.
  function exportLatest(format) {
    const id = state.inv?.latestScan?.id;
    download("/api/export?format=" + format + (id ? "&scan=" + encodeURIComponent(id) : ""));
  }
  $("export-json").addEventListener("click", () => exportLatest("json"));
  $("export-csv").addEventListener("click", () => exportLatest("csv"));
  $("export-inventory").addEventListener("click", () =>
    download("/api/export?what=inventory" + (state.inv?.profileId ? "&profile=" + encodeURIComponent(state.inv.profileId) : ""))
  );

  // ---------- modal ----------

  let modalReturnFocus = null;

  function openModal(title, sub, html, focus = true) {
    const modal = $("modal");
    const wasOpen = !modal.hidden;
    if (!wasOpen) modalReturnFocus = document.activeElement;
    $("modal-title").textContent = stripBidi(title);
    $("modal-sub").textContent = stripBidi(sub || "");
    const scroll = $("modal-body").scrollTop;
    $("modal-body").innerHTML = html;
    modal.hidden = false;
    document.body.classList.add("modal-open");
    if (wasOpen) $("modal-body").scrollTop = scroll;
    if (focus && !wasOpen) modal.querySelector(".modal-close")?.focus();
  }

  function closeModal() {
    const modal = $("modal");
    if (modal.hidden) return;
    modal.hidden = true;
    document.body.classList.remove("modal-open");
    $("modal-body").innerHTML = "";
    state.currentDeviceId = "";
    hideFloatTip();
    if (modalReturnFocus && document.contains(modalReturnFocus)) modalReturnFocus.focus();
    modalReturnFocus = null;
  }

  $("modal").addEventListener("click", (e) => {
    if (e.target.closest("[data-close-modal]")) closeModal();
  });

  // Keep Tab inside the dialog while it is open.
  $("modal").addEventListener("keydown", (e) => {
    if (e.key !== "Tab") return;
    const focusable = [
      ...$("modal").querySelectorAll(
        '.modal-dialog button:not([disabled]), .modal-dialog input:not([disabled]), .modal-dialog textarea, .modal-dialog select, .modal-dialog a[href], .modal-dialog [tabindex="0"]'
      ),
    ].filter((el) => el.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  });

  // ---------- tooltips ----------

  const floatTip = $("float-tip");

  function hideFloatTip() {
    floatTip.hidden = true;
    floatTip.textContent = "";
  }

  function showFloatTip(anchor) {
    const text = anchor?.getAttribute("data-tip");
    if (!text) {
      hideFloatTip();
      return;
    }
    floatTip.textContent = text;
    floatTip.hidden = false;
    const rect = anchor.getBoundingClientRect();
    const tipRect = floatTip.getBoundingClientRect();
    const margin = 8;
    let left = rect.left;
    let top = rect.bottom + margin;
    if (left + tipRect.width > window.innerWidth - margin) left = Math.max(margin, window.innerWidth - tipRect.width - margin);
    if (top + tipRect.height > window.innerHeight - margin) top = Math.max(margin, rect.top - tipRect.height - margin);
    floatTip.style.left = `${Math.round(left)}px`;
    floatTip.style.top = `${Math.round(top)}px`;
  }

  function bindFloatTips(root) {
    root.querySelectorAll("[data-tip]").forEach((el) => {
      el.addEventListener("mouseenter", () => showFloatTip(el));
      el.addEventListener("mouseleave", hideFloatTip);
      el.addEventListener("focus", () => showFloatTip(el));
      el.addEventListener("blur", hideFloatTip);
    });
  }

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!floatTip.hidden) hideFloatTip();
      else closeModal();
    }
  });
  window.addEventListener("scroll", hideFloatTip, true);
  window.addEventListener("resize", hideFloatTip);

  prepConsent();
})();
