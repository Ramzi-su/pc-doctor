// PC Doctor UI: tab routing, live dashboard (Server-Sent Events) and the
// inventory/security views. Loaded as an ES module, so nothing here leaks
// into the global scope shared with app.js.
//
// Security: every value from the API (process names, log lines, file paths,
// user names...) is inserted with textContent / text nodes, never innerHTML,
// so a malicious name like "<img onerror=...>" is displayed, not executed.

const $ = (id) => document.getElementById(id);

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "style") Object.assign(node.style, value); // CSSOM: allowed by our CSP
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node[key] = value;
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) node.append(child);
  }
  return node;
}

async function api(url, options = {}) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(body?.detail) ? body.detail.map((d) => d.msg).join(" ; ") : body?.detail;
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return body;
}

// ---------- formatting ----------

const UNITS = ["o", "Ko", "Mo", "Go", "To"];
function bytes(n) {
  if (n === null || n === undefined) return "—";
  let i = 0;
  while (Math.abs(n) >= 1024 && i < UNITS.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${UNITS[i]}`;
}
const rate = (bps) => `${bytes(bps)}/s`;
const pct = (v) => (v === null || v === undefined ? "—" : `${v.toFixed(0)} %`);
const num = (v, unit = "") => (v === null || v === undefined ? "—" : `${Math.round(v)}${unit}`);

function duration(seconds) {
  const d = Math.floor(seconds / 86400);
  const hrs = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d ? `${d} j ${hrs} h` : hrs ? `${hrs} h ${m} min` : `${m} min`;
}
const dateTime = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "medium" });
const fmtDate = (iso) => (iso ? dateTime.format(new Date(iso)) : "—");

function meter(label, percent, value, { warn = 75, crit = 90 } = {}) {
  const p = Math.max(0, Math.min(100, percent ?? 0));
  const cls = p >= crit ? "fill crit" : p >= warn ? "fill warn" : "fill";
  return h("div", { class: "meter" },
    h("span", {}, label),
    h("div", { class: "bar" }, h("div", { class: cls, style: { width: `${p}%` } })),
    h("span", { class: "val" }, value ?? pct(percent)));
}

function kv(pairs) {
  return h("dl", { class: "kv" }, pairs
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}

function rootOnly(value) {
  return value === "requires root" ? h("span", { class: "tag" }, "nécessite root") : value;
}

function table(target, headers, rows) {
  target.replaceChildren(
    h("thead", {}, h("tr", {}, headers.map((t) => h("th", {}, t)))),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colSpan: headers.length, class: "muted" }, "Rien à afficher"))),
  );
}

const tag = (text, color = "") => h("span", { class: `tag ${color}` }, text);

// Small SVG line chart of the last N values (0-100).
const SVG_NS = "http://www.w3.org/2000/svg";
function sparkline(values) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("preserveAspectRatio", "none");
  const line = document.createElementNS(SVG_NS, "polyline");
  const step = 100 / Math.max(HISTORY - 1, 1);
  const offset = HISTORY - values.length;
  line.setAttribute("points", values.map((v, i) => `${(i + offset) * step},${100 - v}`).join(" "));
  svg.append(line);
  return svg;
}

// ---------- views ----------
// Each view: load() fetches and renders; `every` = auto-refresh period (ms)
// while the tab is visible; enter()/leave() for the live stream.

const views = {};
let current = null;
let timer = null;

function showError(target, err) {
  target.replaceChildren(h("p", { class: "sev sev-critical" }, `Erreur : ${err.message}`));
}

// ===== Dashboard =====

const HISTORY = 60; // 60 samples x 2 s = last 2 minutes
const history = { cpu: [], mem: [] };
let source = null;

function push(list, value) {
  list.push(value);
  if (list.length > HISTORY) list.shift();
}

function renderLive(s) {
  push(history.cpu, s.cpu_percent);
  const memPct = (100 * s.memory_used_bytes) / s.memory_total_bytes;
  push(history.mem, memPct);

  $("live-cpu").replaceChildren(
    h("div", { class: "big" }, pct(s.cpu_percent)),
    h("div", { class: "muted" }, `${num(s.cpu_mhz, " MHz")} · charge ${s.load_average.map((l) => l.toFixed(2)).join(" / ")}`),
    h("div", { class: "cores", title: "Utilisation par cœur" },
      s.cpu_per_core.map((c, i) => h("div", { class: "core", title: `Cœur ${i} : ${pct(c)}` },
        h("div", { style: { height: `${c}%` } })))),
    sparkline(history.cpu),
  );

  $("live-mem").replaceChildren(
    h("div", { class: "big" }, pct(memPct)),
    meter("RAM", memPct, `${bytes(s.memory_used_bytes)} / ${bytes(s.memory_total_bytes)}`),
    s.swap_total_bytes
      ? meter("Swap", (100 * s.swap_used_bytes) / s.swap_total_bytes, `${bytes(s.swap_used_bytes)} / ${bytes(s.swap_total_bytes)}`)
      : null,
    sparkline(history.mem),
  );

  $("live-temps").replaceChildren(...(s.temperatures.length
    ? s.temperatures.map((t) => meter(t.label, t.celsius, `${t.celsius.toFixed(0)} °C`, { warn: 75, crit: 90 }))
    : [h("p", { class: "muted" }, "Aucun capteur lisible")]));

  $("live-gpu").replaceChildren(...(s.gpus.length
    ? s.gpus.map((g) => h("div", {},
      h("h3", {}, g.name),
      g.pstate === "suspended"
        ? h("p", { class: "muted" }, "En veille (économie d'énergie) : non interrogée pour ne pas la réveiller.")
        : [
          meter("Utilisation", g.utilization_percent),
          meter("VRAM", g.memory_total_mib ? (100 * g.memory_used_mib) / g.memory_total_mib : 0,
            `${num(g.memory_used_mib)} / ${num(g.memory_total_mib)} Mo`),
          meter("Temp.", g.temperature_c, num(g.temperature_c, " °C"), { warn: 75, crit: 87 }),
          kv([["Consommation", g.power_w !== null ? `${g.power_w.toFixed(1)} W` : null], ["État", g.pstate]]),
        ]))
    : [h("p", { class: "muted" }, "Pas de GPU NVIDIA (les autres GPU n'exposent pas ces mesures sans root).")]));

  $("live-io").replaceChildren(
    kv([
      ...s.network.filter((n) => n.rx_bps || n.tx_bps || !n.name.startsWith("veth"))
        .map((n) => [n.name, `↓ ${rate(n.rx_bps)}  ↑ ${rate(n.tx_bps)}`]),
      ["Disque", `lecture ${rate(s.disk_read_bps)} · écriture ${rate(s.disk_write_bps)}`],
    ]),
  );

  $("live-sys").replaceChildren(kv([
    ["Allumé depuis", duration(s.uptime_seconds)],
    ["Processus", String(s.process_count)],
    ["Batterie", s.battery_percent !== null
      ? `${pct(s.battery_percent)} ${s.on_ac ? "(sur secteur)" : "(sur batterie)"}` : null],
    ["Mis à jour", fmtDate(s.time)],
  ]));

  $("proc-count").textContent = `(${s.process_count} au total)`;
  table($("live-procs"), ["PID", "Nom", "Utilisateur", "CPU", "Mémoire"],
    s.top_processes.map((p) => h("tr", {},
      h("td", {}, String(p.pid)), h("td", {}, p.name), h("td", {}, p.user ?? "—"),
      h("td", {}, `${p.cpu_percent.toFixed(1)} %`), h("td", {}, bytes(p.memory_bytes)))));
}

const SEV_LABEL = { ok: "OK", info: "Info", warning: "Attention", critical: "Critique" };

async function loadDiagnosis() {
  try {
    const findings = await api("/api/diagnosis");
    $("diagnosis").replaceChildren(...findings.map((f) => h("li", {},
      h("span", { class: `sev sev-${f.severity}` }, SEV_LABEL[f.severity]),
      h("strong", {}, f.area), h("span", {}, f.message))));
  } catch (err) {
    showError($("diagnosis"), err);
  }
}

views.dashboard = {
  every: 30_000,
  load: loadDiagnosis,
  enter() {
    // EventSource = Server-Sent Events: the server pushes a snapshot every
    // 2 s over one long HTTP response; the browser reconnects by itself.
    source = new EventSource("/api/live");
    source.onmessage = (e) => { $("live-dot").classList.add("on"); renderLive(JSON.parse(e.data)); };
    source.onerror = () => $("live-dot").classList.remove("on");
  },
  leave() {
    source?.close(); // stop the stream: no sampling while the tab is hidden
    source = null;
    $("live-dot").classList.remove("on");
  },
};
$("diag-refresh").addEventListener("click", loadDiagnosis);

// ===== Hardware =====

function pciCard(title, dev, extra = []) {
  return h("div", { class: "card" }, h("h2", {}, title), h("h3", {}, dev.device), kv([
    ["Fabricant", dev.vendor],
    ["Intégrateur", dev.subsystem_vendor],
    ["Emplacement PCI", dev.slot],
    ["Pilote", dev.driver],
    ["Révision", dev.revision],
    ...extra,
  ]));
}

views.hardware = {
  every: 30_000,
  async load() {
    const target = $("hardware");
    try {
      const hw = await api("/api/hardware");
      const m = hw.machine;
      target.replaceChildren(
        h("div", { class: "card" }, h("h2", {}, "Machine"), h("h3", {}, m.product ?? "?"), kv([
          ["Fabricant", m.vendor], ["Gamme", m.family], ["Référence (SKU)", m.sku],
          ["N° de série", rootOnly(m.serial)], ["Carte mère", m.board], ["Type", m.chassis_type],
          ["BIOS", [m.bios_vendor, m.bios_version].filter(Boolean).join(" ")],
          ["Date du BIOS", m.bios_date ? `${m.bios_date} (firmware, pas la fabrication)` : null],
        ])),
        h("div", { class: "card" }, h("h2", {}, "Processeur"), h("h3", {}, hw.cpu.model), kv([
          ["Cœurs physiques", hw.cpu.physical_cores], ["Threads", hw.cpu.logical_cores],
          ["Fréquence max", num(hw.cpu.max_mhz, " MHz")],
          ["Virtualisation", hw.cpu.flags_virtualization ?? "non supportée"],
          ["RAM", bytes(hw.memory.total_bytes)], ["Swap", bytes(hw.memory.swap_bytes)],
        ])),
        ...hw.gpus.map((g) => pciCard("Carte graphique", g, [
          ["Mémoire vidéo", g.vram_total_mib ? `${g.vram_total_mib} Mo` : null],
          ["Version pilote", g.driver_version], ["VBIOS", g.vbios_version],
        ])),
        h("div", { class: "card" }, h("h2", {}, "Disques"), hw.disks.map((d) => h("div", {},
          h("h3", {}, `${d.name} — ${d.model ?? "?"}`),
          kv([["Taille", bytes(d.size_bytes)],
            ["Type", d.rotational ? "disque dur (HDD)" : "SSD / flash"],
            ["Amovible", d.removable ? "oui" : "non"]])))),
        h("div", { class: "card" }, h("h2", {}, "Partitions"), hw.partitions.map((p) =>
          meter(p.mountpoint, p.percent, `${bytes(p.used_bytes)} / ${bytes(p.total_bytes)}`))),
        ...hw.batteries.map((b) => h("div", { class: "card" }, h("h2", {}, "Batterie"), h("h3", {}, b.name), kv([
          ["Fabricant", b.manufacturer], ["Modèle", b.model], ["Technologie", b.technology],
          ["Santé", b.health_percent !== null ? `${b.health_percent} % de la capacité d'origine` : null],
          ["Cycles", b.cycle_count ?? "non fourni par la batterie"],
          ["Date de fabrication", b.manufacture_date ?? "non fournie par la batterie"],
        ]), b.health_percent !== null ? meter("Santé", b.health_percent, null, { warn: 101, crit: 101 }) : null)),
        h("div", { class: "card" }, h("h2", {}, "Périphériques USB"),
          h("ul", {}, hw.usb_devices.map((u) => h("li", {}, u)))),
      );
    } catch (err) {
      showError(target, err);
    }
  },
};

// ===== Network =====

const KIND_LABEL = { wifi: "Wi-Fi", ethernet: "Ethernet", loopback: "Boucle locale", virtual: "Virtuelle" };

views.network = {
  every: 5_000,
  async load() {
    const target = $("network");
    try {
      const ifaces = await api("/api/network");
      target.replaceChildren(...ifaces.map((i) => h("div", { class: "card" },
        h("h2", {}, `${i.name}`, tag(i.state, i.state === "up" ? "green" : "")),
        h("h3", {}, i.hardware ? i.hardware.device : KIND_LABEL[i.kind] ?? i.kind),
        kv([
          ["Type", KIND_LABEL[i.kind] ?? i.kind],
          ["Fabricant", i.hardware?.vendor], ["Intégrateur", i.hardware?.subsystem_vendor],
          ["Adresse MAC", i.mac], ["Adresses IP", i.addresses.length ? i.addresses.join("\n") : null],
          ["Vitesse", i.speed_mbps ? `${i.speed_mbps} Mb/s` : null], ["MTU", i.mtu],
          ["Pilote", i.driver ?? i.hardware?.driver], ["Firmware", i.firmware],
          ["Emplacement PCI", i.hardware?.slot],
          ["Reçu / envoyé", `${bytes(i.rx_bytes)} / ${bytes(i.tx_bytes)}`],
          ["Erreurs", i.rx_errors || i.tx_errors ? `${i.rx_errors} reçues, ${i.tx_errors} envoyées` : "aucune"],
        ]))));
    } catch (err) {
      showError(target, err);
    }
  },
};

// ===== Ports =====

let portsData = [];
function renderPorts() {
  const onlyExposed = $("ports-exposed").checked;
  table($("ports"), ["Protocole", "Adresse", "Port", "Accès", "Service probable", "Processus", "Utilisateur"],
    portsData.filter((p) => !onlyExposed || p.exposed).map((p) => h("tr", { class: p.exposed ? "warn" : "" },
      h("td", {}, p.protocol), h("td", { class: "mono" }, p.address), h("td", {}, String(p.port)),
      h("td", {}, p.exposed ? tag("réseau", "orange") : tag("local seulement", "green")),
      h("td", {}, p.service ?? "—"),
      h("td", {}, p.process ? `${p.process} (${p.pid})` : h("span", { class: "muted" }, "caché (autre utilisateur)")),
      h("td", {}, p.user ?? "—"))));
}
views.ports = {
  every: 5_000,
  async load() {
    try {
      portsData = await api("/api/ports");
      renderPorts();
    } catch (err) {
      showError($("ports"), err);
    }
  },
};
$("ports-exposed").addEventListener("change", renderPorts);

// ===== Accounts =====

let accountsData = null;
function renderAccounts() {
  if (!accountsData) return;
  const term = $("accounts-search").value.toLowerCase();
  const match = (...values) => !term || values.some((v) => String(v).toLowerCase().includes(term));
  const onlyHuman = $("users-human").checked;

  table($("users"), ["Nom", "UID", "Dossier", "Shell", "Type", "Groupes"],
    accountsData.users
      .filter((u) => (!onlyHuman || u.human || u.uid === 0) && match(u.name, u.home, u.groups.join(" ")))
      .map((u) => h("tr", { class: u.uid === 0 && u.name !== "root" ? "bad" : u.admin ? "warn" : "" },
        h("td", {}, h("strong", {}, u.name), u.name === accountsData.current_user ? tag("toi", "blue") : null),
        h("td", {}, String(u.uid)), h("td", { class: "mono" }, u.home), h("td", { class: "mono" }, u.shell),
        h("td", {}, u.admin ? tag("admin", "orange") : null, u.human ? tag("humain") : tag("système"),
          u.can_login ? null : tag("sans connexion")),
        h("td", {}, u.groups.map((g) => tag(g))))));

  const onlySensitive = $("groups-sensitive").checked;
  table($("groups"), ["Groupe", "GID", "Membres", "Pourquoi c'est sensible"],
    accountsData.groups
      .filter((g) => (!onlySensitive || g.sensitive || g.members.length) && match(g.name, g.members.join(" ")))
      .map((g) => h("tr", { class: g.sensitive && g.members.length ? "warn" : "" },
        h("td", {}, h("strong", {}, g.name)), h("td", {}, String(g.gid)),
        h("td", {}, g.members.map((m) => tag(m))), h("td", {}, g.why ?? ""))));

  table($("logins"), ["Utilisateur", "Terminal", "Origine", "Début", "Fin / durée"],
    accountsData.logins.filter((l) => match(l.user, l.source)).map((l) => h("tr", {},
      h("td", {}, l.user), h("td", {}, l.terminal), h("td", {}, l.source),
      h("td", {}, fmtDate(l.start)), h("td", {}, l.end))));
}
views.accounts = {
  every: 15_000,
  async load() {
    try {
      accountsData = await api("/api/accounts");
      renderAccounts();
    } catch (err) {
      showError($("users"), err);
    }
  },
};
for (const id of ["users-human", "groups-sensitive"]) $(id).addEventListener("change", renderAccounts);
$("accounts-search").addEventListener("input", renderAccounts);

// ===== Security =====

let suidData = null;
function renderSuid() {
  if (!suidData) {
    $("suid-status").textContent = "Pas encore scanné (≈ 5 s).";
    table($("suid"), ["Fichier", "Type", "Propriétaire", "Mode", "Évaluation"], []);
    return;
  }
  $("suid-status").textContent =
    `${suidData.files.length} fichiers · scanné le ${fmtDate(suidData.scanned_at)} en ${suidData.duration_seconds} s`;
  const onlyUnknown = $("suid-unknown").checked;
  table($("suid"), ["Fichier", "Type", "Propriétaire", "Mode", "Évaluation"],
    suidData.files.filter((f) => !onlyUnknown || !f.known || f.dangerous).map((f) =>
      h("tr", { class: f.dangerous ? "bad" : f.known ? "" : "warn" },
        h("td", { class: "mono" }, f.path), h("td", {}, f.kind), h("td", {}, f.owner),
        h("td", { class: "mono" }, f.mode),
        h("td", {}, f.dangerous ? tag("DANGEREUX : shell root possible", "red")
          : f.known ? tag("standard", "green") : tag("inhabituel : à vérifier", "orange")))));
}

views.security = {
  every: 30_000,
  async load() {
    try {
      const [perms, suid] = await Promise.all([api("/api/permissions"), api("/api/suid")]);
      table($("perm-files"), ["Fichier", "Droits", "Octal", "Propriétaire", "Attendu", "État", "Pourquoi"],
        perms.files.map((f) => h("tr", { class: f.ok ? "" : "bad" },
          h("td", { class: "mono" }, f.path), h("td", { class: "mono" }, f.mode), h("td", { class: "mono" }, f.octal),
          h("td", {}, `${f.owner}:${f.group}`), h("td", {}, f.expected),
          h("td", {}, f.ok ? tag("OK", "green") : tag("TROP OUVERT", "red")), h("td", {}, f.note ?? ""))));
      $("world-writable").replaceChildren(perms.world_writable.length
        ? h("ul", {}, perms.world_writable.map((p) => h("li", { class: "mono" }, p)))
        : h("p", {}, tag("OK", "green"), " aucun fichier système modifiable par tout le monde."));
      suidData = suid;
      renderSuid();
    } catch (err) {
      showError($("perm-files"), err);
    }
  },
};

$("suid-scan").addEventListener("click", async () => {
  const btn = $("suid-scan");
  btn.disabled = true;
  $("suid-status").textContent = "Scan en cours…";
  try {
    // Custom header = CSRF protection (see require_app_header in main.py).
    suidData = await api("/api/suid/scan", { method: "POST", headers: { "X-Requested-With": "pc-doctor" } });
    renderSuid();
  } catch (err) {
    $("suid-status").textContent = `Erreur : ${err.message}`;
  } finally {
    btn.disabled = false;
  }
});
$("suid-unknown").addEventListener("change", renderSuid);

// ===== /var/log files =====

let logFiles = [];
let selectedLog = null;

function renderLogFileList() {
  const term = $("logfile-search").value.toLowerCase();
  $("logfile-list").replaceChildren(...logFiles
    .filter((f) => f.path.toLowerCase().includes(term))
    .map((f) => h("button", {
      type: "button", class: f.path === selectedLog ? "active" : "", title: f.path,
      onclick: () => { selectedLog = f.path; renderLogFileList(); loadLogFile(); },
    }, f.path.replace("/var/log/", ""), h("br"), h("small", {}, `${bytes(f.size_bytes)} · ${fmtDate(f.modified)}`))));
}

let logRequest = null;
async function loadLogFile() {
  if (!selectedLog) return;
  logRequest?.abort();
  logRequest = new AbortController();
  const params = new URLSearchParams({ path: selectedLog, limit: "1000" });
  const text = $("logfile-text").value.trim();
  if (text) params.set("text", text);
  const pre = $("logfile-content");
  const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
  try {
    const data = await api(`/api/logfiles/content?${params}`, { signal: logRequest.signal });
    $("logfile-name").textContent = data.path + (data.truncated ? " (dernières lignes)" : "");
    pre.textContent = data.lines.join("\n") || "(aucune ligne)";
    if (atBottom) pre.scrollTop = pre.scrollHeight; // follow like `tail -f`
  } catch (err) {
    if (err.name !== "AbortError") pre.textContent = `Erreur : ${err.message}`;
  }
}

views.logfiles = {
  every: 5_000,
  async load() {
    try {
      logFiles = await api("/api/logfiles");
      renderLogFileList();
      if ($("logfile-follow").checked) await loadLogFile();
    } catch (err) {
      $("logfile-content").textContent = `Erreur : ${err.message}`;
    }
  },
};
$("logfile-search").addEventListener("input", renderLogFileList);
let textTimer;
$("logfile-text").addEventListener("input", () => { clearTimeout(textTimer); textTimer = setTimeout(loadLogFile, 400); });

// ===== Journal: handled by app.js, nothing to do here =====
views.logs = {};

// ---------- router ----------
// The URL hash (#ports) selects the tab: links work, reload keeps the tab,
// and the browser back button moves between tabs.

function route() {
  const name = location.hash.slice(1) in views ? location.hash.slice(1) : "dashboard";
  if (current === name) return;
  views[current]?.leave?.();
  clearInterval(timer);
  current = name;

  for (const view of document.querySelectorAll(".view")) view.hidden = view.id !== `view-${name}`;
  for (const link of document.querySelectorAll("#tabs a")) {
    link.classList.toggle("active", link.getAttribute("href") === `#${name}`);
  }
  const view = views[name];
  view.enter?.();
  view.load?.();
  if (view.every) timer = setInterval(() => { if (!document.hidden) view.load(); }, view.every);
}

window.addEventListener("hashchange", route);
route();
