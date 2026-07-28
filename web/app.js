(() => {
  const TOKEN = window.__NS_TOKEN__;
  const CONSENT_KEY = "ns-consent-ok";
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
  };

  function tipAttr(text) {
    return escapeHtml(String(text || "")).replace(/\n/g, " · ");
  }

  function portHelpText(port, service) {
    const n = Number(port);
    if (PORT_HELP[n]) return PORT_HELP[n];
    const label = service || "network service";
    return `Port ${n} (${label}). An open service on this device — check whether you recognize it.`;
  }

  function viaTipText(via) {
    const raw = String(via || "").trim();
    const key = raw.toLowerCase();
    if (VIA_HELP[key]) return VIA_HELP[key];
    const m = key.match(/^tcp\/(\d+)$/);
    if (m) {
      const port = Number(m[1]);
      const extra = PORT_HELP[port] ? ` ${PORT_HELP[port]}` : "";
      return `Found because this device accepted a TCP connection on discovery port ${port}.${extra}`;
    }
    return `How we first noticed this device on the network (${raw || "unknown"}).`;
  }

  function portEnrichLines(op) {
    const lines = [];
    if (op.httpTitle) lines.push(`Title: ${op.httpTitle}`);
    if (op.httpServer) lines.push(`Server: ${op.httpServer}`);
    if (op.tlsCommonName) lines.push(`TLS CN: ${op.tlsCommonName}`);
    if (op.tlsIssuer) lines.push(`TLS issuer: ${op.tlsIssuer}`);
    if (op.tlsNotAfter) {
      const d = String(op.tlsNotAfter).slice(0, 10);
      lines.push(op.tlsExpired ? `TLS expired: ${d}` : `TLS valid until: ${d}`);
    } else if (op.tlsExpired) {
      lines.push("TLS certificate expired");
    }
    if (op.tlsSelfSigned) lines.push("Self-signed certificate");
    if (op.banner) lines.push(`Banner: ${op.banner}`);
    return lines;
  }

  function portTipText(op) {
    const base = portHelpText(op.port, op.service);
    const extra = portEnrichLines(op);
    return extra.length ? `${base}\n${extra.join("\n")}` : base;
  }

  function identityHintFromPorts(ports) {
    for (const p of ports || []) {
      if (p.httpTitle) return p.httpTitle;
    }
    for (const p of ports || []) {
      if (p.tlsCommonName) return p.tlsCommonName;
    }
    for (const p of ports || []) {
      if (p.httpServer) return p.httpServer;
    }
    for (const p of ports || []) {
      if (p.banner) return String(p.banner).slice(0, 64);
    }
    return "";
  }

  function identityHintFromHost(h, ports) {
    if (h && h.upnpFriendlyName) return String(h.upnpFriendlyName).slice(0, 64);
    if (h && h.snmpSysDescr) return String(h.snmpSysDescr).slice(0, 64);
    return identityHintFromPorts(ports);
  }

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
            "Close this app, then in Terminal run: sudo ./network-sweeper-darwin-arm64 (or the amd64 build). Enter your Mac password when prompted. Deep discovery then uses ping and ARP.",
        };
      case "linux":
        return {
          short: "Restart with sudo",
          detail:
            "Close this app, then run: sudo ./network-sweeper-linux-amd64 (or arm64). Deep discovery needs root for ping and ARP on most distros.",
        };
      default:
        return {
          short: "Run with administrator / root privileges",
          detail: "Relaunch Network Sweeper with elevated privileges for Deep discovery (ICMP ping; ARP on Linux/macOS).",
        };
    }
  }

  function privilegeLabel(os, isElevated) {
    if (isElevated) {
      if (os === "windows") return "Running as Administrator";
      return "Running with root (sudo)";
    }
    if (os === "windows") return "Running as standard user";
    return "Running without root";
  }

  let lastResults = null;
  let lastIfaces = null;
  let elevated = false;
  let findingFilter = "all";
  let pollTimer = null;

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

  function chips(items, soft = false) {
    if (!items || !items.length) return `<span class="chip soft">none</span>`;
    return items.map((item) => `<span class="chip${soft ? " soft" : ""}">${escapeHtml(item)}</span>`).join("");
  }

  function setScanning(running) {
    $("scan-btn").disabled = running;
    $("stop-btn").hidden = !running;
    $("progress-wrap").hidden = !running;
    if (!running) $("progress-bar").style.width = "0%";
  }

  function updateProgressFromText(progress) {
    const m = String(progress || "").match(/discovery\s+(\d+)\/(\d+)/i);
    if (m) {
      const pct = Math.min(100, Math.round((Number(m[1]) / Math.max(1, Number(m[2]))) * 90));
      $("progress-bar").style.width = pct + "%";
      return;
    }
    if (/scanning ports/i.test(progress || "")) $("progress-bar").style.width = "88%";
    if (/enriching/i.test(progress || "")) $("progress-bar").style.width = "92%";
    if (/resolving hostnames/i.test(progress || "")) $("progress-bar").style.width = "95%";
    if (/lan identity/i.test(progress || "")) $("progress-bar").style.width = "98%";
    if (/done/i.test(progress || "")) $("progress-bar").style.width = "100%";
  }

  function setScanNote(text) {
    const el = $("scan-note");
    if (text && String(text).trim()) {
      el.hidden = false;
      el.textContent = String(text).trim();
    } else {
      el.hidden = true;
      el.textContent = "";
    }
  }

  function unlockDashboard() {
    $("consent").hidden = true;
    $("main").hidden = false;
    init();
  }

  // Consent (session only)
  async function prepConsent() {
    try {
      const ifaces = await api("/api/interfaces");
      lastIfaces = ifaces;
      $("consent-subnets").innerHTML = chips(ifaces.localSubnets || []);
    } catch (_) {
      $("consent-subnets").innerHTML = `<span class="chip soft">Could not load subnets yet</span>`;
    }
    if (sessionStorage.getItem(CONSENT_KEY) === "1") {
      unlockDashboard();
      return;
    }
    $("consent-check").addEventListener("change", (e) => {
      $("consent-continue").disabled = !e.target.checked;
    });
    $("consent-continue").addEventListener("click", () => {
      sessionStorage.setItem(CONSENT_KEY, "1");
      unlockDashboard();
    });
  }

  function activateTab(id) {
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
    const btn = document.getElementById("tabbtn-" + id);
    if (btn) btn.focus();
  }

  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
    btn.addEventListener("keydown", (e) => {
      const tabs = [...document.querySelectorAll(".tabs button")];
      const i = tabs.indexOf(btn);
      if (e.key === "ArrowRight") {
        e.preventDefault();
        activateTab(tabs[(i + 1) % tabs.length].dataset.tab);
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        activateTab(tabs[(i - 1 + tabs.length) % tabs.length].dataset.tab);
      }
    });
  });

  async function init() {
    $("version").textContent = formatVersion(window.__NS_VERSION__);

    const [session, ifaces, plat] = await Promise.all([
      api("/api/session"),
      api("/api/interfaces"),
      api("/api/platform"),
    ]);

    elevated = !!session.elevated;
    const os = plat.os || "unknown";
    const priv = $("priv-badge");
    priv.textContent = privilegeLabel(os, elevated);
    priv.classList.toggle("is-elevated", elevated);
    priv.classList.toggle("is-standard", !elevated);
    priv.title = elevated
      ? "This process has elevated privileges. Deep discovery can use ping (and ARP on Linux/macOS)."
      : elevationHowTo(os).detail;

    $("custom-optin").checked = !!session.customOptIn;
    $("updates-optin").checked = !!session.updatesOptIn;
    lastIfaces = ifaces;

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
      deepHint.innerHTML = `Quiet devices may stay hidden. <button type="button" class="text-link" id="priv-help-link">${escapeHtml(how.short)}</button>`;
    }
    const helpLink = $("priv-help-link");
    if (helpLink) {
      helpLink.addEventListener("click", () => {
        activateTab("limitations");
        $("platform")?.querySelector(".priv-card")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }

    renderNetworkContext(ifaces);
    if (ifaces.localSubnets?.length) {
      $("targets").placeholder = "auto: " + ifaces.localSubnets.join(", ");
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

    const gw = ifaces.gatewayIp
      ? `<div class="context-section"><p class="context-label">Default gateway</p><div class="chip-row"><span class="chip">${escapeHtml(ifaces.gatewayIp)}</span></div></div>`
      : "";

    $("network-context").innerHTML = `
      <div class="context-section">
        <p class="context-label">Local subnets</p>
        <div class="chip-row">${chips(ifaces.localSubnets)}</div>
      </div>
      ${gw}
      <div class="context-section">
        <p class="context-label">Interfaces</p>
        ${ifaceHtml}
      </div>
    `;

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
          isElevated
            ? "Deep discovery can use ICMP ping (and ARP on Linux/macOS) with your current privileges."
            : escapeHtml(how.detail)
        }</p>
      </div>
      <div class="meta-chips">
        <span class="meta-chip"><span class="k">OS</span><span class="v">${escapeHtml(os)}</span></span>
        <span class="meta-chip"><span class="k">Arch</span><span class="v">${escapeHtml(plat.arch)}</span></span>
      </div>`;

    const legend = Object.entries(STATUS_LEGEND)
      .map(
        ([k, v]) =>
          `<li><span class="status-pill ${escapeHtml(k)}">${escapeHtml(STATUS_LABEL[k] || k)}</span> ${escapeHtml(v)}</li>`
      )
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

  function countFindingsBySev(findings) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings || []) {
      if (c[f.severity] != null) c[f.severity]++;
      else c.info++;
    }
    return c;
  }

  function findingsForHost(findings, ip) {
    return (findings || []).filter((f) => f.hostIp === ip);
  }

  function portPill(op) {
    const help = portTipText(op);
    const label = `${op.port}/${op.service || "service"}`;
    const tip = tipAttr(help);
    return `<span class="port-pill" tabindex="0" data-tip="${tip}" aria-label="${escapeHtml(label)}: ${tip}"><span class="port-pill-label">${escapeHtml(label)}</span></span>`;
  }

  function renderPortsCompact(ports, hostIp, limit = 5) {
    if (!ports.length) {
      return `<span class="cell-empty" tabindex="0" data-tip="${tipAttr(
        "No services from the findings list answered. The device can still be alive — try Deep discovery, or it may simply have few open ports."
      )}">None yet</span>`;
    }
    const shown = ports.slice(0, limit);
    const rest = ports.length - shown.length;
    let html = `<div class="port-list">${shown.map(portPill).join("")}`;
    if (rest > 0) {
      html += `<button type="button" class="port-more" data-host-ip="${escapeHtml(hostIp || "")}" aria-label="Show ${rest} more ports" data-tip="${tipAttr(
        `Click to show ${rest} more open port${rest === 1 ? "" : "s"} on this device.`
      )}">+${rest}</button>`;
    }
    html += `</div>`;
    return html;
  }

  function renderAliveVia(via) {
    const items = via || [];
    if (!items.length) {
      return `<span class="cell-empty" tabindex="0" data-tip="${tipAttr(
        "We don’t know which discovery method found this host."
      )}">—</span>`;
    }
    return `<div class="via-list">${items
      .map((v) => {
        const tip = tipAttr(viaTipText(v));
        return `<span class="via-chip" tabindex="0" data-tip="${tip}" aria-label="${escapeHtml(v)}: ${tip}">${escapeHtml(v)}</span>`;
      })
      .join("")}</div>`;
  }

  const floatTip = $("float-tip");
  let tipAnchor = null;

  function hideFloatTip() {
    tipAnchor = null;
    floatTip.hidden = true;
    floatTip.textContent = "";
  }

  function showFloatTip(anchor) {
    const text = anchor?.getAttribute("data-tip");
    if (!text) {
      hideFloatTip();
      return;
    }
    tipAnchor = anchor;
    floatTip.textContent = text;
    floatTip.hidden = false;
    const rect = anchor.getBoundingClientRect();
    const tipRect = floatTip.getBoundingClientRect();
    const margin = 8;
    let left = rect.left;
    let top = rect.bottom + margin;
    if (left + tipRect.width > window.innerWidth - margin) {
      left = Math.max(margin, window.innerWidth - tipRect.width - margin);
    }
    if (top + tipRect.height > window.innerHeight - margin) {
      top = Math.max(margin, rect.top - tipRect.height - margin);
    }
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

  function copyBtn(value, label) {
    if (!value) return "";
    return `<button type="button" class="copy-btn" data-copy="${escapeHtml(value)}" aria-label="Copy ${escapeHtml(label)}" title="Copy ${escapeHtml(label)}">
      <span aria-hidden="true">⧉</span>
    </button>`;
  }

  function renderSummary(data) {
    const hosts = data.hosts || [];
    const ports = data.ports || [];
    let openCount = 0;
    for (const p of ports) openCount += (p.ports || []).length;
    const sev = countFindingsBySev(data.findings);
    const dur = data.durationMs != null ? Math.round(data.durationMs / 1000) + "s" : "";
    const el = $("summary");
    el.hidden = false;
    el.innerHTML = `
      <span class="sum-chip"><strong>${hosts.length}</strong> hosts</span>
      <span class="sum-chip"><strong>${openCount}</strong> open services</span>
      <span class="sum-chip sev-critical"><strong>${sev.critical}</strong> critical</span>
      <span class="sum-chip sev-high"><strong>${sev.high}</strong> high</span>
      <span class="sum-chip sev-medium"><strong>${sev.medium}</strong> medium</span>
      ${dur ? `<span class="sum-chip soft">${escapeHtml(dur)}</span>` : ""}
    `;
  }

  function hostMatchesFilter(h, q, ports) {
    if (!q) return true;
    const hints = (ports || [])
      .flatMap((p) => [p.httpTitle, p.httpServer, p.tlsCommonName, p.banner, p.service])
      .filter(Boolean);
    const blob = [h.ip, h.mac, h.vendor, h.hostname, h.upnpFriendlyName, h.snmpSysDescr, ...hints]
      .join(" ")
      .toLowerCase();
    return blob.includes(q);
  }

  function hostMeta(ip) {
    const h = (lastResults?.hosts || []).find((x) => x.ip === ip);
    if (!h) return { ip, name: "" };
    return { ip, name: h.hostname || h.vendor || "" };
  }

  function hostLabel(ip) {
    const { name } = hostMeta(ip);
    return name ? `${ip} · ${name}` : ip;
  }

  function findingCard(f) {
    return `<article class="finding">
      <span class="sev ${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
      <h4>${escapeHtml(f.title)}</h4>
      <p>${escapeHtml(f.description)}</p>
      ${f.port ? `<p><strong class="fg">Port:</strong> ${escapeHtml(f.port)}</p>` : ""}
      <p><strong class="fg">What to try:</strong> ${escapeHtml(f.remediation)}</p>
    </article>`;
  }

  function groupFindingsByHost(findings) {
    const order = [];
    const map = Object.create(null);
    for (const f of findings || []) {
      const ip = f.hostIp || "unknown";
      if (!map[ip]) {
        map[ip] = [];
        order.push(ip);
      }
      map[ip].push(f);
    }
    // Worst severity first within each host already roughly sorted globally; re-sort groups by worst rank
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    order.sort((a, b) => {
      const wa = Math.min(...map[a].map((f) => rank[f.severity] ?? 9));
      const wb = Math.min(...map[b].map((f) => rank[f.severity] ?? 9));
      if (wa !== wb) return wa - wb;
      return a.localeCompare(b, undefined, { numeric: true });
    });
    return { order, map };
  }

  let lastFocused = null;

  function openRiskModal(ip, findings) {
    const modal = $("risk-modal");
    const list = findings && findings.length ? findings : findingsForHost(lastResults?.findings || [], ip);
    if (!list.length) return;
    lastFocused = document.activeElement;
    $("risk-modal-title").textContent = "Security risks";
    $("risk-modal-sub").textContent = hostLabel(ip);
    const sev = countFindingsBySev(list);
    const summary = [
      sev.critical && `${sev.critical} critical`,
      sev.high && `${sev.high} high`,
      sev.medium && `${sev.medium} medium`,
      sev.low && `${sev.low} low`,
      sev.info && `${sev.info} info`,
    ]
      .filter(Boolean)
      .join(" · ");
    $("risk-modal-body").innerHTML = `
      <p class="help modal-summary">${escapeHtml(summary || `${list.length} finding(s)`)}</p>
      <div class="modal-findings">${list.map(findingCard).join("")}</div>
    `;
    modal.hidden = false;
    document.body.classList.add("modal-open");
    modal.querySelector(".modal-close")?.focus();
  }

  function closeRiskModal() {
    const modal = $("risk-modal");
    if (modal.hidden) return;
    modal.hidden = true;
    document.body.classList.remove("modal-open");
    $("risk-modal-body").innerHTML = "";
    if (lastFocused && typeof lastFocused.focus === "function") lastFocused.focus();
    lastFocused = null;
  }

  function renderHostsTable(data, filterQ) {
    const hosts = data.hosts || [];
    const portsByIP = Object.create(null);
    for (const p of data.ports || []) portsByIP[p.ip] = p.ports || [];
    const findings = data.findings || [];
    const q = (filterQ || "").trim().toLowerCase();
    const filtered = hosts.filter((h) => hostMatchesFilter(h, q, portsByIP[h.ip]));

    $("host-count").textContent = String(filtered.length) + (q ? ` / ${hosts.length}` : "");

    if (!hosts.length) {
      $("hosts").innerHTML = `<div class="empty-coach">
        <p class="empty">No hosts discovered.</p>
        <ul class="notes">
          <li>Guest Wi‑Fi or AP/client isolation can hide other devices.</li>
          <li>Try <strong>Deep discovery</strong> (and elevate with sudo / Run as administrator).</li>
          <li>Confirm you’re on the right network interface/subnet.</li>
        </ul>
      </div>`;
      return;
    }
    if (!filtered.length) {
      $("hosts").innerHTML = `<p class="empty">No hosts match this filter.</p>`;
      return;
    }

    const rows = filtered
      .map((h) => {
        const ports = portsByIP[h.ip] || [];
        const hostFindings = findingsForHost(findings, h.ip);
        const sev = countFindingsBySev(hostFindings);
        const badges = [];
        if (h.isSelf) {
          badges.push(
            `<span class="tag-pill self" tabindex="0" data-tip="${tipAttr(
              "This is the computer running Network Sweeper (one of its own addresses)."
            )}">This device</span>`
          );
        }
        if (h.isGateway) {
          badges.push(
            `<span class="tag-pill gw" tabindex="0" data-tip="${tipAttr(
              "Likely your router / default gateway — the device other hosts use to reach the internet."
            )}">Gateway</span>`
          );
        }
        if (h.likelyRouterGuess) {
          badges.push(
            `<span class="tag-pill guess" tabindex="0" data-tip="${tipAttr(
              "Common home-router address pattern (guess only). Confirm in your router settings if unsure."
            )}">Router?</span>`
          );
        }
        if (sev.critical) {
          badges.push(
            `<button type="button" class="tag-pill risk critical" data-open-risks="${escapeHtml(h.ip)}" data-tip="${tipAttr(
              `${sev.critical} critical finding${sev.critical === 1 ? "" : "s"}. Click to review.`
            )}">${sev.critical} crit</button>`
          );
        } else if (sev.high) {
          badges.push(
            `<button type="button" class="tag-pill risk high" data-open-risks="${escapeHtml(h.ip)}" data-tip="${tipAttr(
              `${sev.high} high-severity finding${sev.high === 1 ? "" : "s"}. Click to review.`
            )}">${sev.high} high</button>`
          );
        } else if (hostFindings.length) {
          badges.push(
            `<button type="button" class="tag-pill risk" data-open-risks="${escapeHtml(h.ip)}" data-tip="${tipAttr(
              `${hostFindings.length} security finding${hostFindings.length === 1 ? "" : "s"}. Click to review.`
            )}">${hostFindings.length}</button>`
          );
        }

        const hint = humanizeText(identityHintFromHost(h, ports));
        const vendor = humanizeText(h.vendor || "");
        const hostname = humanizeText(h.hostname || "");
        const namePrimary = hostname || hint || vendor || "";
        const secondaryParts = [];
        if (hostname && hint && hint !== hostname) secondaryParts.push(hint);
        if (vendor && vendor !== namePrimary) secondaryParts.push(vendor);
        const nameSecondary = secondaryParts.join(" · ");
        const nameTip = namePrimary
          ? tipAttr(
              [
                hostname ? `Hostname: ${hostname}` : "",
                hint && hint !== hostname ? `Identity hint: ${hint}` : "",
                vendor ? `Vendor (from MAC): ${vendor}` : "",
              ]
                .filter(Boolean)
                .join("\n") || namePrimary
            )
          : tipAttr(
              "No hostname, vendor, or service hint yet. Names come from reverse DNS, NetBIOS, mDNS, or device ads (UPnP/SNMP)."
            );
        const namePrimaryHtml = namePrimary
          ? `<div class="name-primary" tabindex="0" data-tip="${nameTip}" title="${escapeHtml(namePrimary)}">${escapeHtml(namePrimary)}</div>`
          : `<div class="name-primary name-empty" tabindex="0" data-tip="${nameTip}">Unknown</div>`;
        const macLabel = h.mac || "No MAC yet";
        const macTip = h.mac
          ? tipAttr(`Hardware (MAC) address ${h.mac}.${vendor ? ` Vendor lookup: ${vendor}.` : " No vendor match in the offline OUI map."}`)
          : tipAttr(
              "No MAC address in the ARP cache yet. MACs appear after the OS talks to the host on this LAN; some adapters or isolation modes never show one."
            );

        return `<tr>
          <td class="col-device">
            <div class="device-primary">
              <span class="mono ip">${escapeHtml(h.ip)}</span>
              ${copyBtn(h.ip, "IP")}
              <span class="badge-row">${badges.join("")}</span>
            </div>
            <div class="device-mac mono">
              <span tabindex="0" data-tip="${macTip}">${escapeHtml(macLabel)}</span>
              ${copyBtn(h.mac, "MAC")}
            </div>
          </td>
          <td class="col-name">
            ${namePrimaryHtml}
            ${nameSecondary ? `<div class="name-secondary" tabindex="0" data-tip="${tipAttr(nameSecondary)}" title="${escapeHtml(nameSecondary)}">${escapeHtml(nameSecondary)}</div>` : ""}
          </td>
          <td class="col-via">${renderAliveVia(h.aliveVia)}</td>
          <td class="col-ports">${renderPortsCompact(ports, h.ip)}</td>
        </tr>`;
      })
      .join("");

    $("hosts").innerHTML = `<div class="table-wrap"><table class="hosts-table">
      <caption class="sr-only">Discovered hosts</caption>
      <colgroup>
        <col class="c-device" />
        <col class="c-name" />
        <col class="c-via" />
        <col class="c-ports" />
      </colgroup>
      <thead><tr>
        <th>Device</th>
        <th>Name / vendor <span class="th-hint">(hover for help)</span></th>
        <th>Found via <span class="th-hint">(hover for help)</span></th>
        <th>Open ports <span class="th-hint">(hover for help)</span></th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;

    $("hosts").querySelectorAll("[data-copy]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(btn.dataset.copy);
          btn.classList.add("copied");
          setTimeout(() => btn.classList.remove("copied"), 900);
        } catch (_) {}
      });
    });
    $("hosts").querySelectorAll(".port-more").forEach((btn) => {
      btn.addEventListener("click", () => {
        const list = btn.closest(".port-list");
        if (!list || list.dataset.expanded === "1") return;
        hideFloatTip();
        const ports = portsByIP[btn.dataset.hostIp] || [];
        list.innerHTML = ports.map(portPill).join("");
        list.dataset.expanded = "1";
        bindFloatTips(list);
      });
    });
    bindFloatTips($("hosts"));
    $("hosts").querySelectorAll("[data-open-risks]").forEach((btn) => {
      btn.addEventListener("click", () => {
        openRiskModal(btn.dataset.openRisks);
      });
    });
  }

  function renderFindings(data) {
    const findings = data?.findings || [];
    $("finding-count").textContent = String(findings.length);

    const sevs = ["all", "critical", "high", "medium", "low", "info"];
    $("sev-filters").innerHTML = sevs
      .map((s) => {
        const n = s === "all" ? findings.length : findings.filter((f) => f.severity === s).length;
        const on = findingFilter === s ? " active" : "";
        return `<button type="button" class="filter-chip${on}" data-sev="${s}">${s} (${n})</button>`;
      })
      .join("");
    $("sev-filters").querySelectorAll("[data-sev]").forEach((btn) => {
      btn.addEventListener("click", () => {
        findingFilter = btn.dataset.sev;
        renderFindings(lastResults);
      });
    });

    const list =
      findingFilter === "all" ? findings : findings.filter((f) => f.severity === findingFilter);

    if (!findings.length) {
      $("findings").innerHTML = `<p class="empty">No findings yet. Run a scan from Overview.</p>`;
      return;
    }
    if (!list.length) {
      $("findings").innerHTML = `<p class="empty">No findings for this severity.</p>`;
      return;
    }

    const { order, map } = groupFindingsByHost(list);
    const startHere = list.filter((f) => f.severity === "critical" || f.severity === "high").slice(0, 3);
    const intro =
      startHere.length && findingFilter === "all"
        ? `<p class="help"><strong>Start here:</strong> ${startHere
            .map((f) => `${escapeHtml(f.title)} (${escapeHtml(f.hostIp)})`)
            .join(" · ")}</p>`
        : "";

    const groups = order
      .map((ip) => {
        const items = map[ip];
        const sev = countFindingsBySev(items);
        const chips = [
          sev.critical && `<span class="sev critical">${sev.critical} critical</span>`,
          sev.high && `<span class="sev high">${sev.high} high</span>`,
          sev.medium && `<span class="sev medium">${sev.medium} medium</span>`,
          sev.low && `<span class="sev low">${sev.low} low</span>`,
          sev.info && `<span class="sev info">${sev.info} info</span>`,
        ]
          .filter(Boolean)
          .join("");
        const meta = hostMeta(ip);
        return `<details class="host-risk-group" data-host="${escapeHtml(ip)}">
          <summary>
            <div class="host-risk-summary">
              <div>
                <div class="host-risk-ip mono">${escapeHtml(ip)}</div>
                ${meta.name ? `<div class="host-risk-name">${escapeHtml(meta.name)}</div>` : ""}
              </div>
              <div class="host-risk-chips">${chips}<span class="count-pill">${items.length}</span></div>
            </div>
          </summary>
          <div class="host-risk-items">
            ${items.map(findingCard).join("")}
            <button type="button" class="ghost compact" data-open-risks="${escapeHtml(ip)}">Open in detail view</button>
          </div>
        </details>`;
      })
      .join("");

    $("findings").innerHTML = intro + `<div class="host-risk-list">${groups}</div>`;
    $("findings").querySelectorAll("[data-open-risks]").forEach((btn) => {
      btn.addEventListener("click", () => openRiskModal(btn.dataset.openRisks));
    });
  }

  function renderResults(data) {
    lastResults = data;
    renderSummary(data);
    renderHostsTable(data, $("host-filter").value);
    renderFindings(data);
    setScanNote(data.warning || "");
  }

  $("host-filter").addEventListener("input", () => {
    if (lastResults) renderHostsTable(lastResults, $("host-filter").value);
  });

  $("scan-btn").addEventListener("click", async () => {
    const status = $("scan-status");
    status.textContent = "Starting scan…";
    status.classList.add("is-busy");
    setScanning(true);
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
      setScanning(false);
      status.classList.remove("is-busy");
      status.textContent = "Error: " + e.message;
    }
  });

  $("stop-btn").addEventListener("click", async () => {
    try {
      await api("/api/scan/cancel", { method: "POST", body: "{}" });
      $("scan-status").textContent = "Stopping…";
    } catch (e) {
      $("scan-status").textContent = e.message;
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
          updateProgressFromText(st.progress);
          return;
        }
        clearInterval(pollTimer);
        pollTimer = null;
        setScanning(false);
        status.classList.remove("is-busy");
        status.textContent = "Scan finished";
        $("progress-bar").style.width = "100%";
        const results = await api("/api/results");
        renderResults(results);
      } catch (e) {
        setScanning(false);
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
    out.hidden = false;
    out.className = "update-result";
    out.textContent = "Checking…";
    try {
      await saveSettings();
      if (!$("updates-optin").checked) {
        out.textContent = "Enable “Allow update checks” first.";
        return;
      }
      const res = await api("/api/update", { method: "POST", body: "{}" });
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

  $("risk-modal").addEventListener("click", (e) => {
    if (e.target.closest("[data-close-modal]")) closeRiskModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeRiskModal();
      hideFloatTip();
    }
  });
  window.addEventListener("scroll", hideFloatTip, true);
  window.addEventListener("resize", hideFloatTip);

  prepConsent();
})();
