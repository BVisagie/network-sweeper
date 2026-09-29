(() => {
  const TOKEN = window.__NS_TOKEN__;
  const CONSENT_KEY = "ns-consent-ok";
  const SETUP_KEY = "ns-scan-setup";
  const FILTERS_KEY = "ns-device-filters";
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

  // portPill shows port/service, or just the port number when short.
  function portPill(op, short = false) {
    const extra = portEnrichLines(op);
    const help = portHelpText(op.port, op.service) + (extra.length ? "\n" + extra.join("\n") : "");
    const label = `${op.port}/${op.service || "service"}`;
    const tip = tipAttr(help);
    const confirmed = op.protocol ? " confirmed" : "";
    return `<span class="port-pill${confirmed}" tabindex="0" data-tip="${tip}" aria-label="${escapeHtml(label)}: ${tip}"><span class="port-pill-label">${escapeHtml(
      short ? String(op.port) : label
    )}</span></span>`;
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
    stopping: false,
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
      if (e.name === "AbortError") throw e; // stopped on purpose
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
    $("tabs").hidden = false;
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
    // One network bar, shown above whichever inventory view is open.
    const slot = document.querySelector(`[data-net-slot="${id}"]`);
    if (slot && !slot.contains($("network-bar"))) slot.appendChild($("network-bar"));
    if (focus) document.getElementById("tabbtn-" + id)?.focus();
    if (id === "changes") loadChanges();
    if (id === "settings") loadAiSettings();
    if (id === "analyze") {
      $("tabbtn-analyze").classList.remove("has-news");
      aiOpen();
    }
  }

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
    btn.addEventListener("keydown", (e) => {
      const tabs = [...document.querySelectorAll(".tabs button")].filter((b) => !b.hidden);
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

  // showSettingsPanel opens Settings at one panel and moves focus to its heading.
  function showSettingsPanel(id) {
    activateTab("settings", false);
    const heading = $(id).querySelector("h3");
    $(id).scrollIntoView({ block: "start" });
    heading?.setAttribute("tabindex", "-1");
    heading?.focus({ preventScroll: true });
  }
  const showCapabilities = () => showSettingsPanel("capabilities");
  $("caps-link").addEventListener("click", showCapabilities);
  $("priv-badge").addEventListener("click", showCapabilities);
  $("storage-badge").addEventListener("click", () => showSettingsPanel("storage"));

  // ---------- init ----------

  async function init() {
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
    // Scan setup starts open until there is an inventory; after that it
    // opens the way the user last left it.
    setSetupOpen(!devices().length || remembered(SETUP_KEY) === "open", false);
    updatePreview();
    // Resume a scan that was running when the page loaded.
    try {
      const st = await api("/api/scan/status");
      if (st.running && st.scan) {
        state.scanId = st.scan.id;
        $("strip-phase").textContent = "Scanning…";
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
    priv.hidden = false;
    priv.textContent = privilegeLabel(os, elevated);
    priv.classList.toggle("is-warn", !elevated);
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
  let previewSeq = 0;
  function updatePreview() {
    // The last plan no longer describes the selection. Drop it (and any
    // preview still in flight) so the summary follows the selection itself
    // until the new preview arrives.
    state.preview = null;
    previewSeq++;
    renderScanSummary();
    clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 200);
  }

  // renderScanSummary fills the toolbar's one-line account of the next scan:
  // its ranges, Deep discovery, and (once previewed) how many addresses.
  function renderScanSummary() {
    const plan = state.preview?.ok ? state.preview.plan : null;
    const ranges = plan ? plan.ranges || [] : scanTargets();
    const deep = $("deep").checked;
    const unelevated = deep && state.session && !state.session.elevated && state.plat?.os !== "windows";
    const deepText = deep ? (unelevated ? "on (not elevated)" : "on") : "off";
    const parts = [
      ranges.length ? `<span class="mono">${escapeHtml(ranges.join(", "))}</span>` : "no networks selected",
      `<span class="wide-only">Deep discovery</span><span class="narrow-only">Deep</span> ${deepText}`,
    ];
    if (plan) parts.push(escapeHtml(plural(plan.addresses, "address", "addresses")));
    const el = $("scan-summary");
    el.innerHTML = parts.join(" · ");
    el.parentElement.title = `Next scan: ${ranges.join(", ") || "no networks selected"} · Deep discovery ${deepText}${
      plan ? " · " + plural(plan.addresses, "address", "addresses") : ""
    }`;
  }

  function setSetupOpen(open, save) {
    $("scan-setup").hidden = !open;
    $("setup-toggle").setAttribute("aria-expanded", String(open));
    $("scanbar").classList.toggle("is-open", open);
    if (save) remember(SETUP_KEY, open ? "open" : "closed");
  }
  $("setup-toggle").addEventListener("click", () => setSetupOpen($("scan-setup").hidden, true));

  async function runPreview() {
    const mine = ++previewSeq;
    const el = $("preview");
    const targets = scanTargets();
    if (!targets.length) {
      state.preview = null;
      el.className = "preview is-warn";
      el.textContent = "Select at least one network, or enter a range.";
      renderScanSummary();
      syncScanButton();
      return;
    }
    try {
      const res = await post("/api/scan/preview", {
        targets,
        deep: $("deep").checked,
        customOptIn: $("custom-optin").checked,
      });
      if (mine !== previewSeq) return; // the selection changed while this was in flight
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
      if (mine !== previewSeq) return;
      state.preview = null;
      el.className = "preview is-warn";
      el.textContent = e.message;
    }
    renderScanSummary();
    syncScanButton();
  }

  function syncScanButton() {
    const running = !!state.polling;
    $("scan-btn").disabled = running || !(state.preview && state.preview.ok);
    $("scan-btn").textContent = running ? "Scanning…" : "Scan";
    $("analyze-btn").hidden = running || !state.inv?.latestScan;
    syncInspectorBar();
    syncAnalyzeTab();
  }

  $("targets").addEventListener("input", updatePreview);
  $("deep").addEventListener("change", updatePreview);

  // ---------- scanning ----------

  function setScanning(running) {
    $("scan-strip").hidden = !running;
    document.body.classList.toggle("is-scanning", running);
    state.stopping = false;
    // A scan's ranges and options are fixed once it starts, and deleting
    // history under it would lose it: lock those controls until it ends.
    // (Disabling the fieldset keeps each too-large subnet's own disabled flag.)
    document.querySelector("fieldset.scope").disabled = running;
    ["deep", "custom-optin", "delete-history", "delete-all"].forEach((id) => ($(id).disabled = running));
    $("scan-locked").hidden = !running;
    $("data-locked").hidden = !running;
    if (running) {
      state.lastPct = 0;
      setStripProgress(0);
      $("strip-detail").textContent = "";
    }
    syncScanButton();
  }

  function setStripProgress(pct) {
    $("progress-bar").style.width = pct + "%";
    $("strip-bar").setAttribute("aria-valuenow", String(pct));
  }

  async function startScan(targets, label) {
    const status = $("scan-status");
    status.textContent = "";
    setScanNote("");
    $("strip-phase").textContent = label || "Starting scan…";
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
      status.textContent = "Could not start: " + e.message;
      setScanning(false);
      return status.textContent;
    }
    return "";
  }

  $("scan-btn").addEventListener("click", () => startScan(scanTargets()));

  $("stop-btn").addEventListener("click", async () => {
    try {
      await post("/api/scan/cancel", { id: state.scanId });
      state.stopping = true;
      $("strip-phase").textContent = "Stopping… results so far are kept.";
    } catch (e) {
      $("strip-detail").textContent = e.message;
    }
  });

  function phasePercent(run) {
    const ph = PHASES.find((p) => p.key === run.phase);
    if (!ph) return run.phase === "done" ? 100 : 0;
    const frac = run.total > 0 ? Math.min(1, run.done / run.total) : 0;
    return ph.from + (ph.to - ph.from) * frac;
  }

  // renderProgress updates the strip under the app bar. Only the phase name
  // is announced; the counters change too often to read out.
  function renderProgress(run) {
    const idx = PHASES.findIndex((p) => p.key === run.phase);
    const ph = PHASES[idx];
    // Never move the bar backwards, even if a phase reports fewer counts.
    state.lastPct = Math.max(state.lastPct, phasePercent(run));
    setStripProgress(Math.round(state.lastPct));
    if (!state.stopping) $("strip-phase").textContent = ph ? `Scanning · ${ph.label}` : "Starting scan…";
    const detail = [];
    if (ph) detail.push(`step ${idx + 1} of ${PHASES.length}`);
    if (ph && run.total > 0) detail.push(`${fmtNumber(run.done)}/${fmtNumber(run.total)}`);
    detail.push(plural((run.found || []).length, "device") + " found");
    $("strip-detail").textContent = detail.join(" · ");
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
        renderProgress(run);
        return;
      }
      clearInterval(state.polling);
      state.polling = null;
      setScanning(false);
      const ended = {
        completed: "Scan finished.",
        canceled: "Scan stopped early. Results so far were kept and are marked partial.",
        timed_out: "Scan hit the time limit. Results so far were kept and are marked partial.",
        failed: "Scan failed" + (run.error ? ": " + run.error : "."),
      };
      status.textContent = (ended[run.state] || "Scan finished.") + (run.finishedAt ? ` (${fmtTime(run.finishedAt)})` : "");
      if (insp.rescanning && insp.rescanning === insp.id) $("insp-status").textContent = ended[run.state]?.replace(/^Scan/, "Rescan") || "Rescan finished.";
      insp.rescanning = "";
      setScanNote(run.saveError ? "These results are shown but were not saved: " + run.saveError : "");
      if (run.state === "completed") setSetupOpen(false, false);
      state.justScanned = true; // point Changes at the newest two scans
      $("profile-select").value = ""; // show the network just scanned
      await refreshAll();
      state.justScanned = false;
      aiNudge();
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
    syncScanButton();
    refreshInspector();
  }

  // renderProfiles fills the network bar: the saved network being shown
  // (a picker once there are several), its subnet, and its last scan.
  function renderProfiles() {
    const profiles = state.inv.profiles || [];
    const cur = profiles.find((p) => p.id === state.inv.profileId);
    $("network-bar").hidden = !cur;
    $("profile-pick").hidden = profiles.length < 2;
    $("network-name").hidden = profiles.length >= 2;
    $("network-name").textContent = cur?.name || "";
    $("profile-select").innerHTML = profiles
      .map((p) => `<option value="${escapeHtml(p.id)}" ${p.id === state.inv.profileId ? "selected" : ""}>${escapeHtml(p.name)}</option>`)
      .join("");
    const latest = state.inv.latestScan;
    const meta = [];
    if (cur?.subnet && !cur.name.includes(cur.subnet)) meta.push(`<span class="mono">${escapeHtml(cur.subnet)}</span>`);
    if (latest) {
      // A day-old scan is flagged here rather than in a banner of its own.
      const stale = Date.now() - new Date(latest.finishedAt).getTime() > STALE_MS;
      meta.push(
        stale
          ? `<span class="is-stale" title="The latest scan is from ${escapeHtml(fmtTime(latest.finishedAt))}. Scan again for a current picture.">last scan ${escapeHtml(
              ago(latest.finishedAt)
            )}, may be out of date</span>`
          : `<span title="${escapeHtml(fmtTime(latest.finishedAt))}">last scan ${escapeHtml(ago(latest.finishedAt))}</span>`
      );
    }
    $("network-meta").innerHTML = meta.join(" · ");
    $("network-meta").title = $("network-meta").textContent;
  }

  $("profile-select").addEventListener("change", async () => {
    const want = $("profile-select").value;
    if (drafts.size || dlg.open) {
      $("profile-select").value = state.inv.profileId; // until the edits are settled
      if (!(await requestCloseInspector("profile"))) return;
      $("profile-select").value = want;
    }
    refreshAll();
  });

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
    `;
  }

  function renderBanners() {
    const out = [];
    const st = state.inv.storage || {};
    if (st.mode === "unavailable") out.push({ cls: "is-error", text: st.reason });
    if (st.lastError) out.push({ cls: "is-error", text: "Saving failed: " + st.lastError + " Results stay visible and can be exported." });
    const latest = state.inv.latestScan;
    if (latest?.partial) {
      const how = latest.state === "timed_out" ? "hit the time limit" : latest.state === "failed" ? "failed" : "was stopped early";
      out.push({
        cls: "is-warn",
        text: `The latest scan ${how}, so its results are partial. Devices marked “not seen” may simply not have been checked.`,
      });
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

  // Six columns on wide tables. Narrower, one Device column stands for
  // address, name and vendor together, and CSS shows it instead of those
  // three (container queries on .hosts-panel).
  const IDENTITY_KEYS = ["ip", "name", "vendor"];
  const COLUMNS = [
    { key: "ip", label: "Address", cls: "c-ip" },
    { key: "name", label: "Name", cls: "c-name" },
    { key: "vendor", label: "Vendor", cls: "c-vendor" },
    { key: "ip", label: "Device", cls: "c-device", identity: true },
    { key: "services", label: "Services", cls: "c-services" },
    { key: "findings", label: "Findings", cls: "c-findings" },
    { key: "seen", label: "Last seen", cls: "c-seen" },
  ];

  const FILTERS = [
    ["f-service", "Service"],
    ["f-vendor", "Vendor"],
    ["f-tag", "Tag"],
    ["f-seen", "Seen"],
    ["f-findings", "Findings"],
  ];

  // Each device's name is rendered twice (six-column and Device layouts);
  // only one is ever visible.
  const visibleIn = (root, selector) => [...(root?.querySelectorAll(selector) || [])].find((el) => el.offsetParent !== null);

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
    renderFilterChips();
    renderSortControls();

    const focusKey = document.activeElement?.dataset?.focusKey;
    // Search, Filters and sort have nothing to act on until there are devices.
    document.querySelector(".hosts-panel").classList.toggle("is-empty", !all.length);
    if (!all.length) {
      $("hosts").innerHTML = `<div class="empty-coach">
        <p class="empty">No devices yet. Choose networks in Scan setup and press Scan.</p>
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
      return;
    }

    const head = COLUMNS.map((c) => {
      const active = c.identity ? IDENTITY_KEYS.includes(state.sort.key) : state.sort.key === c.key;
      const aria = active ? (state.sort.dir === 1 ? "ascending" : "descending") : "none";
      const arrow = active ? (state.sort.dir === 1 ? "▲" : "▼") : "";
      const by = c.identity && active && state.sort.key !== "ip" ? ` <span class="sort-by">by ${state.sort.key}</span>` : "";
      return `<th aria-sort="${aria}" class="${c.cls}"><button type="button" class="sort-btn" data-sort="${c.key}"${
        c.identity ? " data-identity" : ""
      } data-focus-key="sort-${c.cls}">${escapeHtml(c.label)}${by}<span class="sort-arrow" aria-hidden="true">${arrow}</span></button></th>`;
    }).join("");

    const rows = list
      .map((d) => {
        const h = d.last?.host || {};
        const ports = d.last?.ports || [];
        const ip = escapeHtml(devIP(d));
        const name = devName(d);
        const vendor = escapeHtml(humanizeText(h.vendor || ""));
        const open = openFindings(d);
        const worst = worstSeverity(open);
        const badges = [];
        if (d.new) badges.push(`<span class="tag-pill new">New</span>`);
        if (notSeen(d)) badges.push(`<span class="tag-pill missing" title="The latest scan covered this address but did not observe the device">Not seen</span>`);
        if (h.isSelf) badges.push(`<span class="tag-pill self">This device</span>`);
        if (h.isGateway) badges.push(`<span class="tag-pill gw">Gateway</span>`);
        if (d.uncertain?.length) badges.push(`<span class="tag-pill guess" title="${escapeHtml(d.uncertain.join(" "))}">Identity uncertain</span>`);
        if (drafts.has(d.id)) {
          const title = drafts.get(d.id).unwritten ? "Its name, tags or notes are not saved to disk yet" : "Its name, tags or notes have unsaved changes";
          badges.push(`<span class="tag-pill draft" title="${title}">Unsaved</span>`);
        }
        const badgeHtml = badges.join("");
        const tags = (d.tags || []).map((t) => `<span class="tag-pill user">${escapeHtml(t)}</span>`).join("");
        const findings = (d.findings || []).length
          ? worst
            ? `<span class="sev ${escapeHtml(worst)}">${escapeHtml(worst)}</span> <span class="muted">${open.length} open</span>`
            : `<span class="muted">${(d.findings || []).length} acknowledged</span>`
          : `<span class="muted">—</span>`;
        const link = `<button type="button" class="device-link${name ? "" : " name-empty"}" data-open="${escapeHtml(d.id)}" data-focus-key="dev-${escapeHtml(
          d.id
        )}" title="${escapeHtml(name)}" aria-label="${escapeHtml(`${name || "Unknown device"}, ${devIP(d)}: open details`)}">${escapeHtml(name || "Unknown")}</button>`;
        const shown = ports.slice(0, 4);
        const more = ports.length > 4 ? `<span class="port-more">+${ports.length - 4}</span>` : "";
        const services = ports.length
          ? `<div class="port-list svc-full">${shown.map((p) => portPill(p)).join("")}${more}</div><div class="port-list svc-short">${shown
              .map((p) => portPill(p, true))
              .join("")}${more}</div>`
          : `<span class="muted">—</span>`;
        return `<tr data-device="${escapeHtml(d.id)}"${d.id === state.currentDeviceId ? ' aria-selected="true"' : ""}>
          <td class="c-ip"><span class="mono ip">${ip}</span>${badgeHtml ? `<div class="badge-row">${badgeHtml}</div>` : ""}</td>
          <td class="c-name">${link}${tags ? `<div class="badge-row">${tags}</div>` : ""}</td>
          <td class="c-vendor"><span class="clip" title="${vendor}">${vendor || "—"}</span></td>
          <td class="c-device"><div class="ident-top">${link}${badgeHtml}${tags}</div><div class="ident-sub"><span class="mono">${ip}</span>${
            vendor ? ` · <span title="${vendor}">${vendor}</span>` : ""
          }</div></td>
          <td class="c-services">${services}</td>
          <td class="c-findings">${findings}</td>
          <td class="c-seen"><span title="${escapeHtml(fmtTime(d.lastSeen))}">${escapeHtml(ago(d.lastSeen))}</span></td>
        </tr>`;
      })
      .join("");

    $("hosts").innerHTML = `<div class="table-wrap"><table class="hosts-table devices-table">
      <caption class="sr-only">Devices. Choose a device's name to open its details.</caption>
      <thead><tr>${head}</tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
    bindFloatTips($("hosts"));
    if (focusKey) visibleIn($("hosts"), `[data-focus-key="${CSS.escape(focusKey)}"]`)?.focus();
  }

  // Sorting, row clicks, and moving between devices with the arrow keys are
  // bound once on the table's container, which is re-rendered in place.
  $("hosts").addEventListener("click", (e) => {
    const sort = e.target.closest("[data-sort]");
    if (sort) {
      const key = sort.dataset.sort;
      const same = "identity" in sort.dataset ? IDENTITY_KEYS.includes(state.sort.key) : state.sort.key === key;
      state.sort = same ? { key: state.sort.key, dir: -state.sort.dir } : { key, dir: 1 };
      renderDevices();
      return;
    }
    if (e.target.closest("#clear-filters")) return clearFilters();
    const link = e.target.closest("[data-open]");
    if (link) return openDevice(link.dataset.open, { from: link });
    const tr = e.target.closest("tr[data-device]");
    if (tr && !e.target.closest("button, a")) openDevice(tr.dataset.device, { from: visibleIn(tr, ".device-link") });
  });

  $("hosts").addEventListener("keydown", (e) => {
    if (!e.target.matches(".device-link") || (e.key !== "ArrowDown" && e.key !== "ArrowUp")) return;
    e.preventDefault();
    let tr = e.target.closest("tr");
    let next = null;
    while (!next && (tr = e.key === "ArrowDown" ? tr.nextElementSibling : tr.previousElementSibling)) next = visibleIn(tr, ".device-link");
    next?.focus();
  });

  // markOpenRow flags the device whose details are open, without a re-render.
  function markOpenRow() {
    $("hosts")
      .querySelectorAll("tr[data-device]")
      .forEach((tr) => {
        if (tr.dataset.device === state.currentDeviceId) tr.setAttribute("aria-selected", "true");
        else tr.removeAttribute("aria-selected");
      });
  }

  function renderSortControls() {
    const asc = state.sort.dir === 1;
    $("sort-select").value = state.sort.key;
    $("sort-dir").textContent = asc ? "▲" : "▼";
    $("sort-dir").setAttribute("aria-label", `Reverse the order (now ${asc ? "ascending" : "descending"})`);
    $("sort-dir").title = asc ? "Ascending: select to reverse" : "Descending: select to reverse";
  }

  $("sort-select").addEventListener("change", () => {
    state.sort = { key: $("sort-select").value, dir: 1 };
    renderDevices();
  });
  $("sort-dir").addEventListener("click", () => {
    state.sort = { ...state.sort, dir: -state.sort.dir };
    renderDevices();
  });

  // renderFilterChips shows each active secondary filter as a removable chip,
  // so they stay visible while the Filters panel is closed.
  function renderFilterChips() {
    const active = FILTERS.filter(([id]) => $(id).value);
    $("filter-count").hidden = !active.length;
    $("filter-count").textContent = String(active.length);
    $("filters-toggle").setAttribute("aria-label", active.length ? `Filters, ${active.length} active` : "Filters");
    $("filter-chips").hidden = !active.length;
    $("filter-chips").innerHTML = active.length
      ? active
          .map(([id, label]) => {
            const sel = $(id);
            const text = sel.options[sel.selectedIndex]?.text || sel.value;
            return `<button type="button" class="filter-token" data-clear="${id}" aria-label="Remove filter ${escapeHtml(label)}: ${escapeHtml(
              text
            )}">${escapeHtml(label)}: <strong>${escapeHtml(text)}</strong><span class="filter-x" aria-hidden="true">×</span></button>`;
          })
          .join("") + `<button type="button" class="ghost filters-clear" id="filters-clear">Clear all</button>`
      : "";
  }

  $("filter-chips").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-clear]");
    if (chip) {
      const next = chip.nextElementSibling?.dataset.clear;
      $(chip.dataset.clear).value = "";
      renderDevices();
      ($("filter-chips").querySelector(next ? `[data-clear="${next}"]` : "[data-clear]") || $("filters-toggle")).focus();
    } else if (e.target.closest("#filters-clear")) {
      for (const [id] of FILTERS) $(id).value = "";
      renderDevices();
      $("filters-toggle").focus();
    }
  });

  function setFiltersOpen(open, save) {
    $("device-filters").hidden = !open;
    $("filters-toggle").setAttribute("aria-expanded", String(open));
    if (save) remember(FILTERS_KEY, open ? "open" : "closed");
  }
  $("filters-toggle").addEventListener("click", () => setFiltersOpen($("device-filters").hidden, true));
  setFiltersOpen(remembered(FILTERS_KEY) === "open", false);

  function clearFilters() {
    $("host-filter").value = "";
    for (const [id] of FILTERS) $(id).value = "";
    renderDevices();
    $("host-filter").focus();
  }

  $("host-filter").addEventListener("input", () => renderDevices());
  for (const [id] of FILTERS) $(id).addEventListener("change", () => renderDevices());

  // ---------- device inspector ----------

  // The inspector shows one device: docked beside the current view on wide
  // windows (a non-modal <dialog>), or as a full-window modal <dialog> on
  // narrower ones. Unsaved names, tags and notes live in `drafts`, one per
  // device, so refreshes, resizing and switching devices never lose them;
  // only Discard does.
  const INSP_WIDTH_KEY = "ns-inspector-width";
  const INSP_MIN = 360;
  const wideInspector = window.matchMedia("(min-width: 1200px)");
  const dlg = $("inspector");
  const insp = {
    id: "", // the device shown
    seq: 0, // latest detail request: older responses are ignored
    device: null, // its last loaded details
    origin: null, // the control that opened the inspector, for focus on close
    originKey: "",
    width: Number(remembered(INSP_WIDTH_KEY, "400")) || 400, // as chosen; applied clamped to the window
    saving: false,
    rescanning: "", // device whose rescan the inspector started
  };
  // device id -> { name, tags, notes, label, unwritten }. `unwritten` marks
  // edits the server kept in memory but could not write to disk: they stay a
  // draft until a save reaches the disk, even where the fields now match.
  const drafts = new Map();
  const reviewNotes = new Map(); // "deviceId|findingKey" -> acknowledgement note not yet sent

  const annotationsOf = (d) => ({ name: d?.name || "", tags: (d?.tags || []).join(", "), notes: d?.notes || "" });
  // Compared the way the server cleans them, so "Printer " or "B, a" is no change.
  const tagKey = (s) => [...new Set(s.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean))].sort().join(",");
  const sameAnnotations = (a, b) => a.name.trim() === b.name.trim() && tagKey(a.tags) === tagKey(b.tags) && a.notes.trim() === b.notes.trim();
  const listDevice = (id) => devices().find((d) => d.id === id);
  const baseDevice = (id) => (insp.device?.id === id ? insp.device : listDevice(id));

  // openDevice shows a device. `from` is the control that asked, so focus
  // can go back to it on close.
  async function openDevice(id, { from = document.activeElement, refresh = false } = {}) {
    if (!id) return;
    const outside = from && from !== document.body && !dlg.contains(from);
    if (!dlg.open) {
      insp.origin = outside ? from : null;
      insp.originKey = outside ? from.dataset?.focusKey || "" : "";
      showInspector(true);
    } else if (outside && !refresh) {
      insp.origin = from;
      insp.originKey = from.dataset?.focusKey || "";
    }
    const switching = id !== insp.id;
    if (switching) {
      insp.id = id;
      insp.device = null;
      insp.rescanning = "";
      $("insp-status").textContent = "";
      showPlaceholder(id);
    }
    state.currentDeviceId = id;
    markOpenRow();
    const mine = ++insp.seq;
    let d;
    try {
      d = await api("/api/devices/" + encodeURIComponent(id));
    } catch (e) {
      if (mine === insp.seq) showInspectorError(e.message);
      return;
    }
    if (mine !== insp.seq) return; // another device was chosen meanwhile
    insp.device = d;
    renderInspector(d, !switching);
  }

  const refreshInspector = () => (dlg.open && insp.id ? openDevice(insp.id, { refresh: true }) : null);

  function showInspector(first) {
    const wide = wideInspector.matches;
    const had = dlg.contains(document.activeElement) ? document.activeElement : null;
    // Switching mode: the close event this queues finds the dialog open
    // again, and is ignored.
    if (dlg.open) dlg.close();
    $("workspace").classList.toggle("has-side", wide);
    setInspectorWidth(insp.width, false);
    if (wide) dlg.show();
    else dlg.showModal();
    if (first) dlg.focus();
    else had?.focus({ preventScroll: true });
  }

  wideInspector.addEventListener("change", () => {
    if (dlg.open) showInspector(false);
  });

  dlg.addEventListener("close", () => {
    if (dlg.open) return;
    $("workspace").classList.remove("has-side");
    insp.id = "";
    insp.device = null;
    insp.seq++;
    state.currentDeviceId = "";
    markOpenRow();
    hideFloatTip();
    const back =
      insp.origin && document.contains(insp.origin) && insp.origin.offsetParent !== null
        ? insp.origin
        : insp.originKey
          ? visibleIn(document, `[data-focus-key="${CSS.escape(insp.originKey)}"]`)
          : null;
    back?.focus();
    insp.origin = null;
  });

  // Other close requests on the modal inspector (Escape is handled on
  // keydown below): ask about unsaved edits first.
  dlg.addEventListener("cancel", (e) => {
    e.preventDefault();
    requestCloseInspector();
  });
  $("insp-close").addEventListener("click", () => requestCloseInspector());

  async function requestCloseInspector(action = "close") {
    if (!(await settleDrafts(action))) return false;
    if (dlg.open) dlg.close();
    return true;
  }

  // settleDrafts offers Save, Discard or Cancel for unsaved edits. It returns
  // true when the caller may go ahead.
  async function settleDrafts(action) {
    if (!drafts.size) return true;
    const choice = await askUnsaved(action);
    if (choice === "discard") {
      drafts.clear();
      if (insp.id) fillAnnotations(insp.id, baseDevice(insp.id), false);
      renderDevices();
      syncInspectorBar();
      return true;
    }
    if (choice !== "save" || !(await saveAllDrafts())) return false;
    if (drafts.size) {
      // Typed while the save was in flight: those are still unsaved.
      $("insp-status").textContent = "You made more changes while saving. Save or discard them first.";
      return false;
    }
    return true;
  }

  function askUnsaved(action) {
    const names = [...drafts.values()].map((d) => `“${d.label}”`);
    const list = names.length > 1 ? names.slice(0, -1).join(", ") + " and " + names.at(-1) : names[0];
    $("guard-text").textContent = `You have unsaved changes to ${list}. Save them before ${action === "profile" ? "switching network" : "closing"}?`;
    const g = $("guard");
    g.returnValue = "";
    g.showModal();
    return new Promise((resolve) => g.addEventListener("close", () => resolve(g.returnValue || "cancel"), { once: true }));
  }

  // noteDraft keeps the draft in step with the three fields.
  function noteDraft() {
    const id = insp.id;
    if (!id) return;
    const cur = { name: $("insp-name").value, tags: $("insp-tags").value, notes: $("insp-notes").value };
    const base = baseDevice(id);
    const prev = drafts.get(id);
    const had = !!prev;
    if (sameAnnotations(cur, annotationsOf(base)) && !prev?.unwritten) drafts.delete(id);
    else drafts.set(id, { ...cur, label: cur.name.trim() || devName(base || {}) || devIP(base || {}) || "this device", unwritten: !!prev?.unwritten });
    if (had !== drafts.has(id)) renderDevices(); // the row's Unsaved mark
    syncInspectorBar();
  }

  for (const id of ["insp-name", "insp-tags", "insp-notes"]) $(id).addEventListener("input", noteDraft);
  $("insp-name").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      saveCurrent();
    }
  });
  $("insp-notes").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) saveCurrent();
  });

  // fillAnnotations shows the device's draft, else its saved values. On a
  // refresh the field being typed in is left alone.
  function fillAnnotations(id, base, keepFocused) {
    const v = drafts.get(id) || annotationsOf(base);
    for (const [el, val] of [
      [$("insp-name"), v.name],
      [$("insp-tags"), v.tags],
      [$("insp-notes"), v.notes],
    ]) {
      if (!(keepFocused && document.activeElement === el)) el.value = val;
    }
  }

  function syncInspectorBar() {
    const draft = drafts.get(insp.id);
    $("insp-save").disabled = !draft || insp.saving;
    $("insp-dirty").hidden = !draft;
    $("insp-dirty").textContent = draft?.unwritten ? "Not saved to disk" : "Unsaved changes";
    const running = !!state.polling;
    const ip = devIP(baseDevice(insp.id) || {});
    $("insp-rescan").textContent = running ? "Stop scan" : "Rescan";
    $("insp-rescan").disabled = !running && !ip;
    $("insp-rescan").title = running ? "Stop the scan that is running" : ip ? `Scan ${ip} again` : "";
  }

  // saveDraft sends a device's draft. It clears the draft only when what was
  // sent is still the latest edit and it reached the disk. Edits typed while
  // the request was in flight stay a draft, and so do edits the server kept
  // in memory but could not write (saveError), so Save can try again.
  async function saveDraft(id) {
    const sent = drafts.get(id);
    if (!sent) return { ok: true };
    const tags = sent.tags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    let res;
    try {
      res = await post("/api/devices/" + encodeURIComponent(id), { name: sent.name, notes: sent.notes, tags });
    } catch (e) {
      return { ok: false, error: e.message, label: sent.label }; // the draft stays
    }
    const saved = res.device;
    const shown = id === insp.id && saved;
    if (shown) {
      insp.device = saved;
      fillHeader(saved);
    }
    const now = drafts.get(id);
    if (res.saveError) {
      drafts.set(id, { ...(now || sent), unwritten: true });
      return { ok: false, error: `it was changed for this session but not written to disk (${res.saveError})`, label: sent.label };
    }
    if (now === sent) {
      drafts.delete(id);
      if (shown) fillAnnotations(id, saved, false);
    } else if (now) {
      // Newer edits: they stay unless they match what was just saved.
      const newer = { ...now, unwritten: false };
      if (saved && sameAnnotations(newer, annotationsOf(saved))) drafts.delete(id);
      else drafts.set(id, newer);
    }
    return { ok: true, newer: drafts.has(id) };
  }

  async function saveCurrent() {
    if (!drafts.has(insp.id) || insp.saving) return;
    insp.saving = true;
    syncInspectorBar();
    $("insp-status").textContent = "Saving…";
    const r = await saveDraft(insp.id);
    insp.saving = false;
    $("insp-status").textContent = !r.ok
      ? `Could not save: ${r.error}. Your changes are kept; try again.`
      : r.newer
        ? "Saved. Your newer changes are not saved yet."
        : "Saved.";
    syncInspectorBar();
    await loadInventory(); // the list shows what the server now holds
  }
  $("insp-save").addEventListener("click", saveCurrent);

  async function saveAllDrafts() {
    const failed = [];
    for (const id of [...drafts.keys()]) {
      const r = await saveDraft(id);
      if (!r.ok) failed.push(`${r.label}: ${r.error}`);
    }
    await loadInventory();
    syncInspectorBar();
    if (failed.length) {
      $("insp-status").textContent = `Could not save ${failed.join("; ")}. Those changes are kept.`;
      return false;
    }
    return true;
  }

  function fillHeader(d) {
    const h = d?.last?.host || {};
    const ip = devIP(d || {});
    const hint = humanizeText(h.hostname || identityHint(h, d?.last?.ports) || h.vendor || "");
    $("insp-name").placeholder = hint || "Name this device";
    $("insp-title").textContent = `Device ${stripBidi(d?.name || hint || ip)}`;
    const mac = d?.mac || h.mac;
    $("insp-sub").innerHTML = [ip && `<span class="mono">${escapeHtml(ip)}</span>`, mac && `<span class="mono">${escapeHtml(mac)}</span>`, h.vendor && escapeHtml(humanizeText(h.vendor))]
      .filter(Boolean)
      .join(" · ");
  }

  // showPlaceholder shows what the device list already knows while the
  // details load: the name and address, and the editable notes.
  function showPlaceholder(id) {
    const d = listDevice(id);
    fillHeader(d || { id });
    fillAnnotations(id, d, false);
    document.querySelectorAll("#insp-body .insp-live").forEach((el) => {
      el.hidden = true;
      el.innerHTML = "";
    });
    $("insp-state").innerHTML = `<p class="muted">Loading details…</p>`;
    $("insp-body").scrollTop = 0;
    syncInspectorBar();
  }

  function showInspectorError(message) {
    $("insp-state").innerHTML = `<div class="banner is-error insp-error"><span>Could not load this device: ${escapeHtml(
      message
    )}</span> <button type="button" class="ghost" id="insp-retry">Retry</button></div>`;
  }

  $("insp-body").addEventListener("click", (e) => {
    if (e.target.closest("#insp-retry")) {
      $("insp-state").innerHTML = `<p class="muted">Loading details…</p>`;
      refreshInspector();
    }
  });

  function renderInspector(d, refresh) {
    const body = $("insp-body");
    const scroll = body.scrollTop;
    const focusKey = body.contains(document.activeElement) ? document.activeElement.dataset.focusKey : "";
    const h = d.last?.host || {};
    const ports = d.last?.ports || [];
    fillHeader(d);
    fillAnnotations(d.id, d, refresh);

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
    $("insp-overview").innerHTML = `<h3>Overview</h3>
      <dl class="kv">${identityRows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`).join("")}</dl>
      ${(d.uncertain || []).map((u) => `<p class="banner is-warn">${escapeHtml(u)}</p>`).join("")}
      ${
        (h.aliveVia || []).length
          ? `<p class="context-label">How it was found</p><ul class="plain">${h.aliveVia
              .map((v) => `<li><span class="via-chip">${escapeHtml(v)}</span> <span class="muted small">${escapeHtml(viaText(v))}</span></li>`)
              .join("")}</ul>`
          : ""
      }
      <p class="context-label">Addresses</p>
      <ul class="plain">${(d.addresses || [])
        .map((a) => `<li><span class="mono">${escapeHtml(a.ip)}</span> <span class="muted small">${escapeHtml(fmtTime(a.first))} – ${escapeHtml(fmtTime(a.last))}</span></li>`)
        .join("")}</ul>`;

    const certs = ports.filter((p) => p.tlsCommonName || p.tlsIssuer);
    $("insp-services").innerHTML = `<h3>Services <span class="count-pill">${ports.length}</span></h3>
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
      ${
        certs.length
          ? `<p class="context-label">Certificates</p><ul class="plain">${certs
              .map(
                (p) =>
                  `<li><span class="mono">:${escapeHtml(p.port)}</span> ${escapeHtml(p.tlsCommonName || "(no CN)")} <span class="muted">· issuer ${escapeHtml(
                    p.tlsIssuer || "?"
                  )} · ${p.tlsExpired ? "expired" : "valid until"} ${escapeHtml(String(p.tlsNotAfter || "").slice(0, 10))}${
                    p.tlsSelfSigned ? " · self-signed" : ""
                  }</span></li>`
              )
              .join("")}</ul>`
          : ""
      }`;

    const findings = d.findings || [];
    $("insp-findings").innerHTML = `<h3>Findings <span class="count-pill">${findings.length}</span></h3>
      ${findings.length ? findings.map((f) => findingCard(f)).join("") : `<p class="muted">None in the latest observation.</p>`}`;

    $("insp-history").innerHTML = `<h3>Observation history</h3>
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
      }`;

    document.querySelectorAll("#insp-body .insp-live").forEach((el) => (el.hidden = false));
    $("insp-state").innerHTML = "";
    bindReviewControls(body);
    bindFloatTips(body);
    if (refresh) {
      body.scrollTop = scroll;
      if (focusKey) visibleIn(body, `[data-focus-key="${CSS.escape(focusKey)}"]`)?.focus({ preventScroll: true });
    }
    syncInspectorBar();
  }

  $("insp-rescan").addEventListener("click", async () => {
    if (state.polling) return $("stop-btn").click();
    const ip = devIP(baseDevice(insp.id) || {});
    if (!ip) return;
    // Behind a modal inspector, Devices is where the scan's results land.
    if (!wideInspector.matches) activateTab("devices", false);
    insp.rescanning = insp.id;
    $("insp-status").textContent = `Rescanning ${ip}…`;
    const problem = await startScan([ip + "/32"], `Rescanning ${ip}…`);
    if (problem) {
      insp.rescanning = "";
      $("insp-status").textContent = problem;
    }
  });

  // The side inspector's width: dragged or set from the keyboard, and
  // remembered. It is shown between 360px and half the window, so a narrow
  // window does not shrink the width chosen for a wider one.
  const inspMax = () => Math.max(INSP_MIN, Math.floor(window.innerWidth / 2));
  const appliedWidth = () => Math.round(Math.min(Math.max(insp.width, INSP_MIN), inspMax()));

  function setInspectorWidth(w, save) {
    insp.width = Math.round(w);
    if (save) {
      insp.width = appliedWidth(); // a drag past the limits stops at them
      remember(INSP_WIDTH_KEY, String(insp.width));
    }
    const width = appliedWidth();
    $("workspace").style.setProperty("--insp-w", width + "px");
    const handle = $("insp-resize");
    handle.setAttribute("aria-valuemax", String(inspMax()));
    handle.setAttribute("aria-valuenow", String(width));
  }

  $("insp-resize").addEventListener("pointerdown", (e) => {
    const handle = e.currentTarget;
    const startX = e.clientX;
    const startW = appliedWidth();
    handle.setPointerCapture(e.pointerId);
    document.body.classList.add("is-resizing");
    const move = (ev) => setInspectorWidth(Math.min(Math.max(startW + (startX - ev.clientX), INSP_MIN), inspMax()), false);
    const up = () => {
      handle.removeEventListener("pointermove", move);
      document.body.classList.remove("is-resizing");
      setInspectorWidth(insp.width, true);
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up, { once: true });
    handle.addEventListener("pointercancel", up, { once: true });
  });

  $("insp-resize").addEventListener("keydown", (e) => {
    const step = e.shiftKey ? 64 : 16;
    const cur = appliedWidth();
    const next = { ArrowLeft: cur + step, ArrowRight: cur - step, Home: INSP_MIN, End: inspMax() }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    setInspectorWidth(next, true);
  });

  window.addEventListener("resize", () => setInspectorWidth(insp.width, false));
  setInspectorWidth(insp.width, false);

  // Unsent acknowledgement notes survive re-renders too.
  document.addEventListener("input", (e) => {
    const key = e.target.dataset?.noteKey;
    if (key) reviewNotes.set(key, e.target.value);
  });

  window.addEventListener("beforeunload", (e) => {
    if (drafts.size) e.preventDefault();
  });

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
    const noteKey = `${f.deviceId}|${findingKey(f)}`;
    const reviewHtml =
      review.status === "open"
        ? `<div class="review-row">
            <label class="field compact grow"><span class="sr-only">Note for ${escapeHtml(f.title)}</span><input type="text" maxlength="1000" placeholder="Why this is expected (optional)" data-review-note data-note-key="${escapeHtml(
              noteKey
            )}" data-focus-key="note-${escapeHtml(noteKey)}" value="${escapeHtml(reviewNotes.get(noteKey) || "")}" /></label>
            <button type="button" class="ghost compact" data-review="ack" data-key="${escapeHtml(findingKey(f))}" data-device-id="${escapeHtml(f.deviceId)}" data-focus-key="ack-${escapeHtml(
              noteKey
            )}">Acknowledge</button>
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
    // Severity, confidence and review status stay on the card; the evidence
    // and review controls fold away.
    const reviewPill =
      review.status === "reopened"
        ? `<span class="tag-pill review-reopened" title="The evidence changed since you acknowledged it">Reopened</span>`
        : review.status === "acknowledged"
          ? `<span class="tag-pill review-acked">Acknowledged</span>`
          : "";
    const more = [
      evidence ? `<p class="fg small"><strong>Why it appeared</strong></p><ul class="evidence">${evidence}</ul>` : "",
      f.unknown ? `<p class="small"><strong class="fg">Still unknown:</strong> ${escapeHtml(f.unknown)}</p>` : "",
      f.deviceId ? reviewHtml : "",
    ].join("");
    return `<article class="finding${review.status === "acknowledged" ? " is-acked" : ""}">
      <div class="finding-tags">
        <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
        <span class="tag-pill conf-${escapeHtml(f.confidence)}" title="${
          f.confidence === "confirmed" ? "A response from the device backs this." : "Only an open port backs this."
        }">${escapeHtml(f.confidence)}</span>
        <span class="tag-pill">${escapeHtml(CATEGORY_LABEL[f.category] || f.category)}</span>
        ${f.port ? `<span class="tag-pill mono">port ${escapeHtml(f.port)}</span>` : ""}
        ${reviewPill}
      </div>
      <h4>${escapeHtml(f.title)}</h4>
      <p>${escapeHtml(f.description)}</p>
      <p class="small"><strong class="fg">What to try:</strong> ${escapeHtml(f.remediation)}</p>
      ${
        more
          ? `<details class="finding-more" data-more-key="${escapeHtml(noteKey)}"${openMore.has(noteKey) ? " open" : ""}>
        <summary>${f.deviceId ? (review.status === "open" ? "Evidence and review" : "Evidence and review note") : "Evidence"}</summary>
        <div class="finding-more-body">${more}</div>
      </details>`
          : ""
      }
    </article>`;
  }

  // Which cards have their evidence open, so re-renders keep them open.
  // (toggle does not bubble, hence the capture listener.)
  const openMore = new Set();
  document.addEventListener(
    "toggle",
    (e) => {
      const key = e.target.dataset?.moreKey;
      if (!key) return;
      if (e.target.open) openMore.add(key);
      else openMore.delete(key);
    },
    true
  );

  // bindReviewControls wires review buttons and "Open device" links in a
  // freshly rendered list. Outcomes are reported inside the inspector when
  // the buttons are there, else on Devices.
  function bindReviewControls(root) {
    const status = dlg.contains(root) ? $("insp-status") : null;
    root.querySelectorAll("[data-review]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const ack = btn.dataset.review === "ack";
        const note = btn.closest(".review-row")?.querySelector("[data-review-note]")?.value || "";
        setReview(btn.dataset.deviceId, btn.dataset.key, ack, note, status);
      });
    });
    root.querySelectorAll("[data-open-device]").forEach((btn) => {
      btn.addEventListener("click", () => openDevice(btn.dataset.openDevice, { from: btn }));
    });
  }

  async function setReview(deviceId, key, acknowledged, note, status) {
    try {
      const res = await post("/api/devices/" + encodeURIComponent(deviceId) + "/review", { key, acknowledged, note });
      reviewNotes.delete(`${deviceId}|${key}`);
      const warn = res.saveError ? "Review changed for this session, but saving failed: " + res.saveError : "";
      if (status) status.textContent = warn;
      else if (warn) setScanNote(warn);
    } catch (e) {
      (status || $("scan-status")).textContent = "Could not change the review: " + e.message;
      return;
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
            <button type="button" class="ghost compact" data-open-device="${escapeHtml(id)}" data-focus-key="fo-${escapeHtml(id)}">Open device</button>
          </div>
        </details>`;
      })
      .join("")}</div>`;
    bindReviewControls($("findings"));
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
    $("history").innerHTML = `<div class="table-wrap"><table class="hosts-table mini-table history-table">
      <caption class="sr-only">Retained scans, newest first</caption>
      <thead><tr><th>When</th><th>Result</th><th>Ranges</th><th>Methods</th><th>Devices</th><th>Findings</th><th><span class="sr-only">Export</span></th></tr></thead>
      <tbody>${state.history
        .map(
          (s) => `<tr>
          <td class="h-when">${escapeHtml(fmtTime(s.finishedAt))}</td>
          <td class="h-result">${escapeHtml(STATE_LABEL[s.state] || s.state)}${s.partial ? ` <span class="tag-pill guess">partial</span>` : ""}</td>
          <td class="h-ranges mono">${escapeHtml((s.ranges || []).join(", "))}</td>
          <td class="h-methods">${escapeHtml(methodsText(s.methods))}</td>
          <td class="h-count" data-label="devices">${escapeHtml(s.hosts)}</td>
          <td class="h-count" data-label="findings">${escapeHtml(s.findings)}</td>
          <td class="h-export nowrap"><button type="button" class="ghost compact" data-export-scan="${escapeHtml(s.id)}" data-format="json">JSON</button>
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

  // [key, heading, detail, one, many]: one and many name a count in the summary.
  const CHANGE_SECTIONS = [
    ["newDevices", "New devices", () => "", "new device", "new devices"],
    ["addressChanges", "Address changes", (c) => `${c.from} → ${c.to}`, "address change", "address changes"],
    ["newServices", "Newly observed services", (c) => `${c.port}/${c.service}`, "new service", "new services"],
    ["closedServices", "Services now refusing connections", (c) => `${c.port}/${c.service}`, "closed service", "closed services"],
    ["certChanges", "Certificate changes", (c) => `:${c.port} ${c.field}: ${c.from || "—"} → ${c.to || "—"}`, "certificate change", "certificate changes"],
    ["newFindings", "New findings", (c) => `${c.severity} · ${c.title}`, "new finding", "new findings"],
    ["changedFindings", "Findings that changed", (c) => `${c.title}: ${c.from} → ${c.to}`, "changed finding", "changed findings"],
    ["resolvedFindings", "Findings resolved", (c) => c.title, "resolved finding", "resolved findings"],
    ["notObserved", "Not observed this time", () => "", "not observed", "not observed"],
    ["unansweredServices", "Services that did not answer this time", (c) => `${c.port}/${c.service}`, "unanswered service", "unanswered services"],
    ["findingsNotSeen", "Findings not reported this time", (c) => c.title, "finding not reported", "findings not reported"],
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
    const present = CHANGE_SECTIONS.filter(([k]) => (c[k] || []).length);
    // Each count jumps to its group.
    const summary = present.length
      ? `<div class="summary-strip change-summary">${present
          .map(([k, , , one, many]) => `<button type="button" class="sum-chip" data-jump="chg-${k}"><strong>${c[k].length}</strong> ${escapeHtml(c[k].length === 1 ? one : many)}</button>`)
          .join("")}</div>`
      : "";
    const sections = present
      .map(
        ([k, label, detail]) => `<section class="change-group" id="chg-${k}" tabindex="-1">
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
    el.innerHTML = head + summary + scope + (sections || `<p class="empty">No differences between these scans.</p>`);
    el.querySelectorAll("[data-jump]").forEach((b) =>
      b.addEventListener("click", () => {
        const group = $(b.dataset.jump);
        group.scrollIntoView({ block: "start" });
        group.focus({ preventScroll: true });
      })
    );
    el.querySelectorAll("[data-open-device]").forEach((b, i) => {
      b.dataset.focusKey = `chg-${i}`;
      b.addEventListener("click", () => openDevice(b.dataset.openDevice, { from: b }));
    });
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
      drafts.clear();
      reviewNotes.clear();
      if (dlg.open) dlg.close();
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

  // Settings → AI analysis: which AI tools are installed, and the local model
  // server address, which it shares with the Analyze tab.
  async function loadAiSettings() {
    aiBind();
    $("set-local-url").value = $("ai-local-url").value;
    await aiLoadBackends();
    renderAiSettings();
  }

  function renderAiSettings() {
    $("ai-found").innerHTML = ai.backends.length
      ? ai.backends
          .map(
            (b) => `<li><span class="ai-found-name">${escapeHtml(b.label)}${
              b.version ? ` <span class="muted mono">${escapeHtml(b.version.replace(/\s*\(.*\)$/, ""))}</span>` : ""
            }</span> <span class="small ${b.available ? "muted" : "ai-unavailable"}">${escapeHtml(b.available ? "Available" : b.reason || "Not available.")}</span></li>`
          )
          .join("")
      : `<li class="muted small">Could not check for AI tools.</li>`;
  }

  $("set-local-check").addEventListener("click", async () => {
    aiBind();
    $("ai-local-url").value = $("set-local-url").value.trim();
    remember(AI_LOCAL_KEY, $("ai-local-url").value);
    await aiLoadBackends();
    renderAiSettings();
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

  // ---------- AI analysis ----------

  // The Analyze tab builds a prompt from the latest scan. After the user
  // acknowledges the risk, it can be copied, or sent to an AI on this
  // computer (the Claude or Codex CLI with tools off, or a local model
  // server). The conversation lives here until the page is reloaded.

  const AI_BACKEND_KEY = "ns-ai-backend";
  const AI_LOCAL_KEY = "ns-ai-local-url";

  const ai = {
    bound: false,
    counts: null, // prompt stats; null while the prompt is loading
    seq: 0,
    scanKey: "", // profile and scan the prompt was built from; "" to rebuild
    promptScan: null, // that scan, which the heading describes during a conversation
    backendSeq: 0,
    startError: "", // why the first send failed, shown where Start is
    key: null, // which device and MAC each prompt reference stands for
    snap: null, // those devices as they were when the conversation started
    showSetup: false, // during a conversation: setup panels instead of devices
    backends: [],
    backendsLoaded: false,
    backend: "",
    consentOpen: true,
    prompt: "", // fixed at the first send
    history: [], // assistant replies and the owner's answers, alternating
    ctrl: null,
    started: 0,
    timer: null,
  };

  function remembered(key, fallback = "") {
    try {
      return localStorage.getItem(key) || fallback;
    } catch {
      return fallback;
    }
  }

  function remember(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // per-viewer convenience only
    }
  }

  const aiTalking = () => ai.history.length > 0 || !!ai.ctrl;
  const aiBackend = () => ai.backends.find((b) => b.id === ai.backend);
  const aiScanKey = () => (state.inv?.latestScan ? (state.inv.profileId || "") + "|" + state.inv.latestScan.id : "");

  // Keeps the tab in step with the inventory: shown once a scan exists, and
  // its prompt rebuilt for a newer scan unless a conversation is under way.
  function syncAnalyzeTab() {
    const latest = state.inv?.latestScan;
    const btn = $("tabbtn-analyze");
    btn.hidden = !latest && !aiTalking();
    if (btn.hidden && !$("tab-analyze").hidden) activateTab("devices", false);
    // A conversation stays about the scan it started from until Start over.
    const scan = (aiTalking() && ai.promptScan) || latest;
    if (scan) $("ai-title").textContent = `Analyze with AI · scan of ${fmtTime(scan.finishedAt)}`;
    // Old or partial data gives old or partial advice: say so, and offer a rescan.
    const notes = [];
    if (scan && Date.now() - new Date(scan.finishedAt).getTime() > STALE_MS) {
      notes.push(`This scan is from ${ago(scan.finishedAt)}, so devices and services may have changed since.`);
    }
    if (scan?.partial) {
      const how = scan.state === "timed_out" ? "hit the time limit" : scan.state === "failed" ? "failed" : "was stopped early";
      notes.push(`It ${how}, so some devices may not have been checked.`);
    }
    $("ai-scan-note").hidden = !notes.length;
    $("ai-scan-note-text").textContent = notes.length ? notes.join(" ") + " Scan again for a current picture." : "";
    if (!$("tab-analyze").hidden) aiRefreshPrompt();
    aiSync();
  }

  function aiOpen() {
    aiBind();
    if (!ai.backendsLoaded) aiLoadBackends();
    aiRefreshPrompt();
    aiSync();
    aiRenderThread();
    requestAnimationFrame(aiReveal);
  }

  function aiRefreshPrompt() {
    const key = aiScanKey();
    if (!key || key === ai.scanKey || aiTalking()) return;
    aiUsePrompt();
  }

  // aiUsePrompt builds the prompt from the latest scan, with the current masks.
  function aiUsePrompt() {
    ai.scanKey = aiScanKey();
    ai.promptScan = state.inv?.latestScan || null;
    aiLoadPrompt();
  }

  async function aiLoadPrompt() {
    const mine = ++ai.seq;
    ai.counts = null;
    aiSync();
    const q = new URLSearchParams({ maskMacs: $("ai-mask-macs").checked ? "1" : "0", maskNames: $("ai-mask-names").checked ? "1" : "0" });
    if (state.inv?.profileId) q.set("profile", state.inv.profileId);
    try {
      const res = await api("/api/analysis-prompt?" + q);
      if (mine !== ai.seq) return;
      $("ai-prompt").value = res.prompt;
      ai.counts = res.stats;
      ai.key = res.key || null;
      $("ai-status").textContent = "";
    } catch (e) {
      if (mine !== ai.seq) return;
      ai.scanKey = ""; // try again on the next refresh
      $("ai-prompt").value = "";
      $("ai-status").textContent = "Could not build the prompt: " + e.message;
    }
    aiSync();
  }

  async function aiLoadBackends() {
    // Only the newest check counts, so an older one cannot report on a
    // server address that has since changed.
    const mine = ++ai.backendSeq;
    ai.backendsLoaded = true;
    try {
      const res = await api("/api/assistant?localUrl=" + encodeURIComponent($("ai-local-url").value.trim()));
      if (mine !== ai.backendSeq) return;
      ai.backends = res.backends || [];
    } catch (e) {
      if (mine !== ai.backendSeq) return;
      $("ai-backends").innerHTML = `<legend class="sr-only">AI to ask</legend><p class="muted small">${escapeHtml("Could not check for AI tools: " + e.message)}</p>`;
      ai.backendsLoaded = false;
      return;
    }
    if (!ai.backends.some((b) => b.id === ai.backend && (b.available || b.id === "local"))) {
      ai.backend = (ai.backends.find((b) => b.available) || ai.backends.find((b) => b.id === "local") || {}).id || "";
    }
    aiRenderBackends();
  }

  function aiRenderBackends() {
    $("ai-backends").innerHTML =
      `<legend class="sr-only">AI to ask</legend>` +
      ai.backends
        .map(
          (b) => `<label class="ai-backend${b.available ? "" : " is-off"}">
            <input type="radio" name="ai-backend" value="${escapeHtml(b.id)}" ${b.id === ai.backend ? "checked" : ""} />
            <span class="ai-backend-text">
              <span class="ai-backend-name">${escapeHtml(b.label)}${b.version ? ` <span class="muted mono">${escapeHtml(b.version.replace(/\s*\(.*\)$/, ""))}</span>` : ""}</span>
              <small class="${b.available ? "muted" : "ai-unavailable"}">${escapeHtml(b.available ? b.note : b.reason || "Not available.")}</small>
            </span>
          </label>`
        )
        .join("");
    $("ai-backends")
      .querySelectorAll('input[name="ai-backend"]')
      .forEach((r) =>
        r.addEventListener("change", () => {
          ai.backend = r.value;
          remember(AI_BACKEND_KEY, r.value);
          aiSync();
        })
      );
    const local = ai.backends.find((b) => b.id === "local");
    const sel = $("ai-local-model");
    const keep = sel.value;
    sel.innerHTML =
      `<option value="">Server default</option>` + (local?.models || []).map((m) => `<option value="${escapeHtml(m)}">${escapeHtml(m)}</option>`).join("");
    // Pick a listed model unless one was chosen: Ollama needs a model name.
    if (keep && [...sel.options].some((o) => o.value === keep)) sel.value = keep;
    else if (local?.models?.length) sel.value = local.models[0];
    aiSync();
  }

  function aiSync() {
    if (!ai.bound) return;
    const ack = $("ai-ack").checked;
    const ok = !!ai.counts && ack;
    const busy = !!ai.ctrl;
    const talking = aiTalking();
    const b = aiBackend();
    const macs = $("ai-mask-macs").checked;
    const names = $("ai-mask-names").checked;

    // Once acknowledged, the notice folds into one line.
    const folded = ack && !ai.consentOpen;
    $("ai-consent").hidden = folded;
    $("ai-consent-summary").hidden = !folded;
    $("ai-consent-text").textContent = `Risk acknowledged · MACs ${macs ? "masked" : "shown"} · names ${names ? "masked" : "shown"}`;
    $("ai-mask-macs").disabled = talking;
    $("ai-mask-names").disabled = talking;

    const area = $("ai-prompt");
    area.disabled = !ok || talking;
    $("ai-copy").disabled = !ok;
    $("ai-download").disabled = !ok;
    $("ai-stats").textContent = ai.counts
      ? `≈${fmtNumber(Math.ceil(area.value.length / 4))} tokens · ${plural(ai.counts.devices, "device")} · ${plural(ai.counts.findings, "finding")}`
      : "";

    document.querySelectorAll('input[name="ai-backend"]').forEach((r) => {
      const info = ai.backends.find((x) => x.id === r.value);
      r.disabled = talking || !(info?.available || info?.id === "local");
    });
    $("ai-local").hidden = ai.backend !== "local";
    ["ai-local-url", "ai-local-model", "ai-local-check"].forEach((id) => ($(id).disabled = talking));

    const replying = ai.history.length > 0;
    $("ai-reply-wrap").hidden = !replying;
    $("ai-reply").disabled = !ok || busy;
    $("ai-hint").hidden = !replying || busy;
    // During a conversation the left column lists the devices it is about;
    // the locked setup folds into one line above, and can still be viewed.
    const setupShown = !talking || ai.showSetup;
    document.querySelectorAll(".ai-p-consent, .ai-p-backend, .ai-p-prompt").forEach((p) => (p.hidden = !setupShown));
    $("ai-devices-panel").hidden = setupShown;
    $("ai-setup-bar").hidden = !talking;
    $("ai-setup-text").textContent = `${b?.label || "AI"} · MACs ${macs ? "masked" : "shown"} · names ${names ? "masked" : "shown"}`;
    $("ai-setup-toggle").setAttribute("aria-expanded", String(ai.showSetup));

    // Before the first reply, Start sits in the middle of the conversation;
    // the composer below appears once there is something to answer.
    $("ai-composer").hidden = !talking;
    $("ai-thread").closest(".ai-conversation").classList.toggle("is-talking", talking);
    $("ai-send").hidden = !replying;
    $("ai-send").disabled = !ok || busy || !b?.available || !$("ai-reply").value.trim();
    $("ai-stop").hidden = !busy;
    $("ai-copy-chat").hidden = !replying;
    $("ai-reset").hidden = !replying || busy;
    $("ai-with").textContent = talking && b ? "· " + b.label : "";

    const key = aiScanKey();
    const moved = talking && ai.scanKey && key && key !== ai.scanKey;
    $("ai-note").hidden = !moved;
    if (moved) {
      const latest = state.inv.latestScan;
      $("ai-note").textContent =
        key.split("|")[0] === ai.scanKey.split("|")[0]
          ? `A newer scan (${fmtTime(latest.finishedAt)}) is available. This conversation is about the earlier one; Start over to analyze the new scan.`
          : "Another network is selected. This conversation is about the earlier one; Start over to analyze the selected network.";
    }
    if (!talking) aiRenderThread();
  }

  function aiRenderThread() {
    const thread = $("ai-thread");
    const b = aiBackend();
    if (!aiTalking()) {
      let text;
      let ready = false;
      if (!$("ai-ack").checked) text = "Read the notice on the left, choose what to mask, then tick “I understand the risk” to begin.";
      else if (!ai.counts) text = "Building the prompt…";
      else if (!b?.available)
        text = ai.backends.some((x) => x.available)
          ? "Choose an AI on the left."
          : "No AI was found on this computer. Install the Claude or Codex CLI, start a local model server, or copy the prompt into any AI chat.";
      else {
        ready = true;
        text = `Sends the prompt (≈${fmtNumber(Math.ceil($("ai-prompt").value.length / 4))} tokens). It will probably ask you a few questions first; answer them here.`;
      }
      thread.innerHTML = `<div class="ai-empty">
        ${ai.startError ? `<p class="banner is-error">${escapeHtml(ai.startError)}</p>` : ""}
        ${ready ? `<button type="button" class="primary large" id="ai-start">Start analysis with ${escapeHtml(b.label)}</button>` : ""}
        <p>${escapeHtml(text)}</p>
      </div>`;
      return;
    }
    const who = b?.label || "AI";
    const items = [`<div class="ai-msg ai-msg-user"><p class="ai-who">You</p><p class="muted small">Sent the prompt (≈${fmtNumber(Math.ceil(ai.prompt.length / 4))} tokens).</p></div>`];
    for (const m of ai.history) {
      items.push(
        m.role === "assistant"
          ? `<div class="ai-msg ai-msg-ai"><p class="ai-who">${escapeHtml(who)}</p><div class="ai-md">${aiLinkRefs(renderMarkdown(m.text))}</div></div>`
          : `<div class="ai-msg ai-msg-user"><p class="ai-who">You</p><div class="ai-plain">${aiLinkRefs(escapeHtml(m.text))}</div></div>`
      );
    }
    if (ai.ctrl) items.push(`<div class="ai-msg ai-msg-ai"><p class="ai-who">${escapeHtml(who)}</p><p class="muted small ai-wait" id="ai-wait">Thinking…</p></div>`);
    thread.innerHTML = items.join("");
    aiRenderDevices();
    // Show a new reply from its first line; otherwise keep the latest in view.
    const last = thread.lastElementChild;
    if (!ai.ctrl && last?.classList.contains("ai-msg-ai")) thread.scrollTop = last.offsetTop - thread.offsetTop - 12;
    else thread.scrollTop = thread.scrollHeight;
  }

  // renderMarkdown shows a reply's headings, lists, emphasis and code. The
  // text is escaped first and only these fixed tags are added: no links, no
  // images, no raw HTML.
  function renderMarkdown(src) {
    const inline = (s) =>
      s
        .split(/`([^`]+)`/)
        .map((part, i) =>
          i % 2
            ? `<code>${part}</code>`
            : part.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/(^|[\s(])[*_]([^*_\s][^*_]*?)[*_](?=[\s).,:;!?]|$)/g, "$1<em>$2</em>")
        )
        .join("");
    const out = [];
    let para = [];
    let list = null; // { tag, items: [] }
    let code = null;
    let table = null;
    const flush = () => {
      if (para.length) out.push(`<p>${inline(para.join(" "))}</p>`);
      para = [];
      if (list) out.push(`<${list.tag}>${list.items.map((it) => `<li>${inline(it)}</li>`).join("")}</${list.tag}>`);
      list = null;
      if (table) out.push(`<pre class="ai-table">${table.join("\n")}</pre>`);
      table = null;
    };
    for (const line of escapeHtml(src).split("\n")) {
      if (code) {
        if (/^\s*```/.test(line)) {
          out.push(`<pre><code>${code.join("\n")}</code></pre>`);
          code = null;
        } else code.push(line);
        continue;
      }
      let m;
      if (/^\s*```/.test(line)) {
        flush();
        code = [];
      } else if (/^\s*\|/.test(line)) {
        if (!table) flush();
        (table ||= []).push(line.trim());
      } else if ((m = line.match(/^(#{1,6})\s+(.*)$/))) {
        flush();
        out.push(`<h4 class="ai-h${Math.min(m[1].length, 3)}">${inline(m[2])}</h4>`);
      } else if (/^\s*(-{3,}|\*{3,})\s*$/.test(line)) {
        flush();
      } else if ((m = line.match(/^\s*([-*+]|\d+[.)])\s+(.*)$/))) {
        const tag = /\d/.test(m[1]) ? "ol" : "ul";
        if (para.length || table || (list && list.tag !== tag && !/^\s{2,}/.test(line))) flush();
        if (!list) list = { tag, items: [] };
        list.items.push(m[2]);
      } else if (!line.trim()) {
        flush();
      } else if (list && /^\s+\S/.test(line)) {
        list.items[list.items.length - 1] += " " + line.trim();
      } else {
        if (list || table) flush();
        para.push(line.trim());
      }
    }
    if (code) out.push(`<pre><code>${code.join("\n")}</code></pre>`);
    flush();
    return out.join("");
  }

  // aiSnapshot records how each referenced device looks now, so the
  // conversation keeps reading the same way even if a device is renamed.
  function aiSnapshot() {
    const byId = new Map(devices().map((d) => [d.id, d]));
    const snap = { devices: new Map(), macs: new Map() };
    for (const r of ai.key?.devices || []) {
      const d = byId.get(r.deviceId);
      const h = d?.last?.host || {};
      const open = d ? openFindings(d) : [];
      snap.devices.set(r.ref, {
        ref: r.ref,
        id: r.deviceId,
        listed: r.listed,
        // Your name, then hostname, then vendor: a service banner is a poor name.
        name: d ? d.name || humanizeText(h.hostname || "") || h.vendor || devName(d) : "",
        ip: d ? devIP(d) : "",
        vendor: d?.last?.host?.vendor || "",
        open: open.length,
        worst: worstSeverity(open),
      });
    }
    for (const m of ai.key?.macs || []) snap.macs.set(m.token, m.mac);
    return snap;
  }

  const AI_REF = /\b(?:device|mac)-\d+\b/g;

  // aiLinkRefs turns device-N and mac-N in rendered (already escaped) text
  // into labelled chips. Unknown references stay as plain text.
  function aiLinkRefs(html) {
    if (!ai.snap) return html;
    return html.replace(AI_REF, (ref) => {
      const d = ai.snap.devices.get(ref);
      if (d) {
        const tip = [d.name && d.ip, d.vendor].filter(Boolean).join(" · ");
        return `<button type="button" class="ai-ref" data-ref="${ref}" data-id="${escapeHtml(d.id)}"${tip ? ` title="${escapeHtml(tip)}"` : ""}>${ref}<span class="ai-ref-name"> · ${escapeHtml(d.name || d.ip || "unknown")}</span></button>`;
      }
      const mac = ai.snap.macs.get(ref);
      return mac ? `<span class="ai-ref-mac" title="${escapeHtml(mac)}">${ref}</span>` : ref;
    });
  }

  // aiMentioned lists the device references in the conversation, first
  // mention first.
  function aiMentioned() {
    const seen = new Set();
    for (const m of ai.history) for (const ref of m.text.match(AI_REF) || []) if (ai.snap?.devices.has(ref)) seen.add(ref);
    return [...seen];
  }

  function aiRenderDevices() {
    if (!ai.snap) return;
    const q = $("ai-dev-filter").value.trim().toLowerCase();
    const match = (d) => !q || [d.ref, d.name, d.ip, d.vendor].some((v) => v.toLowerCase().includes(q));
    const mentioned = aiMentioned();
    const all = [...ai.snap.devices.values()];
    const row = (d) => `<div class="ai-dev" data-ref="${d.ref}">
        <button type="button" class="ai-dev-main" data-id="${escapeHtml(d.id)}" title="Show this device's details">
          <span class="ai-dev-ref mono">${d.ref}</span>
          <span class="ai-dev-name"${d.name ? ` title="${escapeHtml(d.name)}"` : ""}>${d.name ? escapeHtml(d.name) : `<span class="muted">no name</span>`}${d.listed ? "" : ` <span class="tag-pill missing">not in this scan</span>`}</span>
          <span class="ai-dev-ip mono">${escapeHtml(d.ip)}</span>
          ${d.open ? `<span class="sev ${escapeHtml(d.worst)}">${d.open}</span>` : `<span></span>`}
        </button>
        <button type="button" class="ai-mention" data-ref="${d.ref}" title="Mention ${d.ref} in your reply" aria-label="Mention ${d.ref} in your reply">↵</button>
      </div>`;
    const first = mentioned.map((r) => ai.snap.devices.get(r)).filter(match);
    const rest = all.filter((d) => d.listed && !mentioned.includes(d.ref) && match(d));
    let html = "";
    if (first.length) html += `<p class="ai-dev-group">Mentioned</p>` + first.map(row).join("");
    if (rest.length) html += `<p class="ai-dev-group">${first.length ? "Other devices" : "All devices"}</p>` + rest.map(row).join("");
    $("ai-dev-list").innerHTML = html || `<p class="muted small ai-dev-none">No device matches “${escapeHtml(q)}”.</p>`;
    $("ai-dev-count").textContent = String(all.filter((d) => d.listed).length);
  }

  // Hovering a chip lights its device row, and hovering a row lights its chips.
  function aiHot(ref, on) {
    document.querySelectorAll(`#tab-analyze [data-ref="${ref}"]`).forEach((el) => el.classList.toggle("is-hot", on));
    if (on) document.querySelector(`#ai-dev-list .ai-dev[data-ref="${ref}"]`)?.scrollIntoView({ block: "nearest" });
  }

  function aiMention(ref) {
    const box = $("ai-reply");
    const at = box.selectionStart ?? box.value.length;
    const before = box.value.slice(0, at);
    const text = (before && !/\s$/.test(before) ? " " : "") + ref + " ";
    box.value = before + text + box.value.slice(box.selectionEnd ?? at);
    const caret = before.length + text.length;
    aiSync();
    if (!box.disabled) {
      box.focus();
      box.setSelectionRange(caret, caret);
    }
  }

  // aiReveal scrolls the page just enough to show the conversation with its
  // reply box. When the panel is taller than the screen (phones), it shows
  // the latest message from its start instead; the reply box follows it.
  function aiReveal() {
    if (!aiTalking() || $("tab-analyze").hidden) return;
    const panel = $("ai-thread").closest(".ai-conversation");
    const r = panel.getBoundingClientRect();
    if (r.height <= window.innerHeight) {
      if (r.top < 0 || r.bottom > window.innerHeight) panel.scrollIntoView({ block: r.top < 0 ? "start" : "end", behavior: "smooth" });
      return;
    }
    const last = $("ai-thread").lastElementChild;
    if (last) last.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  async function aiSend() {
    const cs = $("ai-chat-status");
    if (!ai.history.length) {
      ai.prompt = $("ai-prompt").value;
      ai.snap = aiSnapshot();
      ai.showSetup = false;
    }
    else ai.history.push({ role: "user", text: $("ai-reply").value.trim() });
    const history = ai.history.slice();
    ai.ctrl = new AbortController();
    ai.started = Date.now();
    ai.startError = "";
    cs.textContent = "";
    aiRenderThread();
    aiSync();
    aiReveal();
    ai.timer = setInterval(() => {
      const w = $("ai-wait");
      if (w) w.textContent = `Thinking… ${Math.round((Date.now() - ai.started) / 1000)} s (a first answer can take a minute or two)`;
    }, 1000);
    try {
      const res = await api("/api/assistant/ask", {
        method: "POST",
        signal: ai.ctrl.signal,
        body: JSON.stringify({
          backend: ai.backend,
          prompt: ai.prompt,
          history,
          localUrl: $("ai-local-url").value.trim(),
          localModel: $("ai-local-model").value,
        }),
      });
      ai.history.push({ role: "assistant", text: res.reply });
      $("ai-reply").value = "";
    } catch (e) {
      // Keep the owner's unanswered reply in the box to send again. A failed
      // start is reported where the Start button is.
      const msg = e.name === "AbortError" ? "Stopped." : e.message;
      if (history.length) {
        $("ai-reply").value = ai.history.pop().text;
        cs.textContent = msg;
      } else {
        ai.startError = msg === "Stopped." ? "Stopped. Start again when you are ready." : msg;
      }
    } finally {
      clearInterval(ai.timer);
      ai.ctrl = null;
    }
    aiRenderThread();
    aiSync();
    if (ai.history.length) $("ai-reply").focus({ preventScroll: true });
    aiReveal();
  }

  function aiBind() {
    if (ai.bound) return;
    ai.bound = true;
    $("ai-local-url").value = remembered(AI_LOCAL_KEY, "http://127.0.0.1:8080");
    ai.backend = remembered(AI_BACKEND_KEY);
    $("ai-ack").addEventListener("change", () => {
      ai.consentOpen = !$("ai-ack").checked;
      aiSync();
    });
    // Change reopens the notice unacknowledged: adjust the masks, then tick again.
    $("ai-consent-edit").addEventListener("click", () => {
      $("ai-ack").checked = false;
      ai.consentOpen = true;
      aiSync();
      $("ai-mask-macs").focus();
    });
    const remask = () => aiUsePrompt();
    $("ai-mask-macs").addEventListener("change", remask);
    $("ai-mask-names").addEventListener("change", remask);
    $("ai-prompt").addEventListener("input", aiSync);
    $("ai-copy").addEventListener("click", async () => {
      const area = $("ai-prompt");
      try {
        await navigator.clipboard.writeText(area.value);
        $("ai-status").textContent = "Copied.";
      } catch {
        $("ai-prompt-details").open = true;
        area.select();
        $("ai-status").textContent = document.execCommand("copy") ? "Copied." : "Could not copy. Select the text and copy it yourself.";
      }
    });
    $("ai-download").addEventListener("click", () => {
      const url = URL.createObjectURL(new Blob([$("ai-prompt").value], { type: "text/markdown" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = "network-sweeper-analysis-prompt.md";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    $("ai-local-check").addEventListener("click", () => {
      remember(AI_LOCAL_KEY, $("ai-local-url").value.trim());
      aiLoadBackends();
    });
    $("ai-reply").addEventListener("input", aiSync);
    $("ai-reply").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && !$("ai-send").disabled) aiSend();
    });
    $("ai-send").addEventListener("click", aiSend);
    $("ai-thread").addEventListener("click", (e) => {
      if (e.target.closest("#ai-start")) aiSend();
      const chip = e.target.closest(".ai-ref[data-id]");
      if (chip) openDevice(chip.dataset.id, { from: chip });
    });
    $("ai-dev-list").addEventListener("click", (e) => {
      const mention = e.target.closest(".ai-mention");
      if (mention) return aiMention(mention.dataset.ref);
      const main = e.target.closest(".ai-dev-main");
      if (main) openDevice(main.dataset.id, { from: main });
    });
    for (const id of ["ai-thread", "ai-dev-list"]) {
      $(id).addEventListener("mouseover", (e) => {
        const el = e.target.closest("[data-ref]");
        if (el && !el.contains(e.relatedTarget)) aiHot(el.dataset.ref, true);
      });
      $(id).addEventListener("mouseout", (e) => {
        const el = e.target.closest("[data-ref]");
        if (el && !el.contains(e.relatedTarget)) aiHot(el.dataset.ref, false);
      });
    }
    $("ai-dev-filter").addEventListener("input", aiRenderDevices);
    // In narrow layouts the device list folds under the conversation.
    $("ai-dev-toggle").addEventListener("click", () => {
      const open = !$("ai-devices-panel").classList.toggle("is-folded");
      $("ai-dev-toggle").setAttribute("aria-expanded", String(open));
      $("ai-dev-toggle").textContent = open ? "Hide" : "Show";
      $("ai-dev-toggle").setAttribute("aria-label", `${open ? "Hide" : "Show"} devices in this analysis`);
    });
    $("ai-devices-panel").classList.add("is-folded");
    $("ai-dev-toggle").setAttribute("aria-label", "Show devices in this analysis");
    $("ai-setup-toggle").addEventListener("click", () => {
      ai.showSetup = !ai.showSetup;
      aiSync();
    });
    $("ai-stop").addEventListener("click", () => ai.ctrl?.abort());
    $("ai-reset").addEventListener("click", () => {
      if (!confirm("Start over? This conversation will be lost.")) return;
      ai.history = [];
      ai.prompt = "";
      ai.startError = "";
      ai.snap = null;
      ai.showSetup = false;
      $("ai-dev-filter").value = "";
      $("ai-chat-status").textContent = "";
      syncAnalyzeTab(); // heading, warning and prompt move to the latest scan
    });
    $("ai-copy-chat").addEventListener("click", async () => {
      const who = aiBackend()?.label || "AI";
      const text = [ai.prompt, ...ai.history.map((m) => `## ${m.role === "assistant" ? who : "You"}\n\n${m.text}`)].join("\n\n");
      try {
        await navigator.clipboard.writeText(text);
        $("ai-chat-status").textContent = "Conversation copied.";
      } catch {
        $("ai-chat-status").textContent = "Could not copy the conversation.";
      }
    });
    window.addEventListener("beforeunload", (e) => {
      if (aiTalking()) e.preventDefault();
    });
  }

  $("analyze-btn").addEventListener("click", () => activateTab("analyze"));

  // aiNudge draws the eye to Analyze once a scan finishes: the button glows
  // briefly, and the tab keeps a dot until it is opened.
  function aiNudge() {
    if (!state.inv?.latestScan) return;
    const b = $("analyze-btn");
    b.classList.remove("is-fresh");
    void b.offsetWidth; // restart the animation
    b.classList.add("is-fresh");
    if ($("tab-analyze").hidden) $("tabbtn-analyze").classList.add("has-news");
  }
  $("analyze-btn").addEventListener("animationend", () => $("analyze-btn").classList.remove("is-fresh"));
  $("ai-rescan").addEventListener("click", () => {
    activateTab("devices", false);
    $("scan-btn").scrollIntoView({ block: "center" });
    $("scan-btn").focus();
  });

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

  // Escape hides a tooltip, else closes the inspector: always when modal,
  // and when the side inspector or the device list has focus. It is handled
  // here, not as the dialog's cancel event, because a browser may skip a
  // cancel listener on a repeated Escape; preventing the keydown stops the
  // browser closing the dialog itself, so the unsaved-edit guard always runs.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented || $("guard").open) return;
    if (!floatTip.hidden) {
      e.preventDefault();
      return hideFloatTip();
    }
    const at = document.activeElement;
    if (dlg.open && (dlg.matches(":modal") || dlg.contains(at) || $("hosts").contains(at) || at === document.body)) {
      e.preventDefault();
      requestCloseInspector();
    }
  });
  window.addEventListener("scroll", hideFloatTip, true);
  window.addEventListener("resize", hideFloatTip);

  $("version").textContent = formatVersion(window.__NS_VERSION__);
  prepConsent();
})();
