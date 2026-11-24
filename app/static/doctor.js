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

// ---------- privileged actions ----------
// Every action: explicit confirmation, then a POST carrying the custom
// header (CSRF guard). The server may open the system password dialog, so
// the request can take as long as the user needs to type it.

let toastTimer;
function toast(message, ok = true) {
  const el = $("toast");
  el.textContent = message;
  el.className = ok === null ? "" : ok ? "ok" : "err"; // null = pending (neutral, stays shown)
  el.hidden = false;
  clearTimeout(toastTimer);
  if (ok !== null) toastTimer = setTimeout(() => { el.hidden = true; }, ok ? 5000 : 10000);
}

async function runAction(url, body, confirmText, button) {
  if (confirmText && !confirm(confirmText)) return false;
  if (button) button.disabled = true;
  toast("En attente… (saisis ton mot de passe si la fenêtre système s'ouvre)", null);
  try {
    const res = await api(url, {
      method: "POST",
      headers: { "X-Requested-With": "pc-doctor", "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    toast(res.message, true);
    return true;
  } catch (err) {
    toast(err.message, false);
    return false;
  } finally {
    if (button) button.disabled = false;
  }
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

  $("proc-count").textContent = `voir les ${s.process_count} processus →`;
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

// ===== Processes =====

let procData = null;
let procSort = { key: "cpu_percent", desc: true };

const PROC_COLUMNS = [
  // [label, sort key, value used for sorting]
  ["PID", "pid", (p) => p.pid],
  ["Nom", "name", (p) => p.name.toLowerCase()],
  ["Utilisateur", "user", (p) => p.user ?? ""],
  ["CPU", "cpu_percent", (p) => p.cpu_percent ?? -1],
  ["Mémoire", "memory_bytes", (p) => p.memory_bytes ?? -1],
  ["Threads", "threads", (p) => p.threads ?? -1],
  ["État", "status", (p) => p.status ?? ""],
  ["Lancé", "started", (p) => p.started ?? ""],
  ["Commande", "cmdline", (p) => p.cmdline ?? ""],
  ["Actions", null, null],
];

const denied = () => h("span", { class: "tag" }, "nécessite root");
const orDenied = (value, fmt = String) => (value === null || value === undefined ? denied() : fmt(value));

function sortProcs(list) {
  const get = PROC_COLUMNS.find((c) => c[1] === procSort.key)[2];
  const dir = procSort.desc ? -1 : 1;
  return [...list].sort((a, b) => (get(a) < get(b) ? -dir : get(a) > get(b) ? dir : 0));
}

// Tree view: depth-first walk from the roots (processes whose parent is not
// in the filtered list), children sorted with the current column.
function treeOrder(list) {
  const byPid = new Map(list.map((p) => [p.pid, p]));
  const children = new Map();
  for (const p of list) {
    const parent = byPid.has(p.ppid) ? p.ppid : 0;
    if (!children.has(parent)) children.set(parent, []);
    children.get(parent).push(p);
  }
  const out = [];
  const walk = (pid, depth) => {
    for (const child of sortProcs(children.get(pid) ?? [])) {
      out.push([child, depth]);
      if (child.pid !== pid) walk(child.pid, depth + 1);
    }
  };
  walk(0, 0);
  return out;
}

function procRow(p, depth = 0) {
  return h("tr", { class: p.status === "zombie" ? "warn" : "" },
    h("td", {}, String(p.pid)),
    h("td", {}, h("span", { style: { paddingLeft: `${depth * 14}px` } }, depth ? "└ " : "", h("strong", {}, p.name)),
      p.kernel_thread ? tag("noyau") : null,
      p.critical ? tag("vital", "orange") : null,
      p.user === procData.current_user ? tag("toi", "blue") : null),
    h("td", {}, orDenied(p.user)),
    h("td", {}, orDenied(p.cpu_percent, (v) => `${v.toFixed(1)} %`)),
    h("td", {}, orDenied(p.memory_bytes, bytes)),
    h("td", {}, orDenied(p.threads)),
    h("td", {}, orDenied(p.status)),
    h("td", {}, orDenied(p.started, fmtDate)),
    h("td", { class: "mono cmd", title: p.cmdline ?? "" },
      p.cmdline === null ? denied() : p.cmdline || h("span", { class: "muted" }, "(thread du noyau)")),
    h("td", { class: "actions" }, killButtons(p)));
}

function killButtons(p) {
  if (p.protected) return h("span", { class: "muted", title: "PID 1, thread du noyau ou PC Doctor" }, "protégé");
  if (!p.started) return denied();
  const mine = p.user === procData.current_user;
  const label = `${p.name} (PID ${p.pid}, utilisateur ${p.user ?? "?"})`;
  const warning = p.critical
    ? "\n\n⚠️ Processus VITAL : ta session graphique, le réseau ou le son peuvent s'arrêter."
    : "";
  const root = mine ? "" : "\n\nIl appartient à un autre utilisateur : ton mot de passe root sera demandé.";
  const send = (signal, verb) => async (e) => {
    const ok = await runAction(`/api/processes/${p.pid}/kill`, { started: p.started, signal },
      `${verb} ${label} ?${warning}${root}`, e.currentTarget);
    if (ok) setTimeout(views.processes.load, 500);
  };
  return [
    h("button", { type: "button", class: "small", title: "SIGTERM : demande au programme de se fermer proprement",
      onclick: send("TERM", "Arrêter") }, "Arrêter"),
    h("button", { type: "button", class: "small danger", title: "SIGKILL : arrêt immédiat, sans sauvegarde",
      onclick: send("KILL", "Forcer l'arrêt de") }, "Forcer"),
  ];
}

function renderProcs() {
  if (!procData) return;
  const term = $("proc-search").value.trim().toLowerCase();
  const mine = $("proc-mine").checked;
  const kernel = $("proc-kernel").checked;
  const list = procData.processes.filter((p) =>
    (!mine || p.user === procData.current_user) &&
    (kernel || !p.kernel_thread) &&
    (!term || [p.pid, p.name, p.user, p.cmdline].some((v) => String(v ?? "").toLowerCase().includes(term))));

  const headers = PROC_COLUMNS.map(([label, key]) => key === null ? h("th", {}, label) : h("th", {
    class: "sortable", title: "Trier",
    onclick: () => {
      procSort = { key, desc: procSort.key === key ? !procSort.desc : key !== "name" && key !== "user" };
      renderProcs();
    },
  }, label, procSort.key === key ? (procSort.desc ? " ▼" : " ▲") : ""));

  const rows = $("proc-tree").checked
    ? treeOrder(list).map(([p, depth]) => procRow(p, depth))
    : sortProcs(list).map((p) => procRow(p));

  const target = $("proc-table");
  target.replaceChildren(
    h("thead", {}, h("tr", {}, headers)),
    h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colSpan: PROC_COLUMNS.length, class: "muted" }, "Aucun processus ne correspond"))),
  );
  $("proc-status").textContent = `${list.length} affichés sur ${procData.total}`;
}

views.processes = {
  every: 3_000,
  async load() {
    if ($("proc-pause").checked && procData) return;
    try {
      procData = await api("/api/processes");
      renderProcs();
    } catch (err) {
      showError($("proc-table"), err);
    }
  },
};
for (const id of ["proc-mine", "proc-kernel", "proc-tree"]) $(id).addEventListener("change", renderProcs);
$("proc-search").addEventListener("input", renderProcs);

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
let firewall = null;

function portActions(p) {
  const base = p.protocol.replace("6", "");
  const what = `le port ${p.port}/${base}`;
  const reload = (ok) => ok && setTimeout(views.ports.load, 500);
  const buttons = [];
  if (p.units.length) {
    const units = p.units.join(" + ");
    buttons.push(
      h("button", { type: "button", class: "small", title: `systemctl stop ${units}`,
        onclick: async (e) => reload(await runAction("/api/ports/stop-service", { protocol: base, port: p.port, disable: false },
          `Arrêter ${units} pour fermer ${what} ?\n\nIl redémarrera au prochain démarrage du PC.`, e.currentTarget)) },
        "Arrêter le service"),
      h("button", { type: "button", class: "small danger", title: `systemctl disable --now ${units}`,
        onclick: async (e) => reload(await runAction("/api/ports/stop-service", { protocol: base, port: p.port, disable: true },
          `Arrêter ET désactiver ${units} ?\n\n${what} restera fermé après redémarrage. ` +
          `Pour annuler plus tard : sudo systemctl enable --now ${units}`, e.currentTarget)) },
        "Désactiver"));
  } else if (p.pid && p.pid > 1 && p.started) {
    buttons.push(h("button", { type: "button", class: "small", title: "SIGTERM au programme qui écoute",
      onclick: async (e) => reload(await runAction(`/api/processes/${p.pid}/kill`, { started: p.started, signal: "TERM" },
        `Arrêter ${p.process} (PID ${p.pid}) pour fermer ${what} ?`, e.currentTarget)) },
      "Arrêter le programme"));
  }
  if (p.exposed && firewall?.installed) {
    buttons.push(
      h("button", { type: "button", class: "small", title: `ufw deny ${p.port}/${base}`,
        onclick: async (e) => reload(await runAction("/api/firewall/rule", { protocol: base, port: p.port, block: true },
          `Bloquer ${what} dans le pare-feu ?\n\nLe programme continue de tourner mais devient injoignable depuis le réseau.` +
          (firewall.enabled ? "" : "\n\n⚠️ Le pare-feu est désactivé : la règle ne s'appliquera qu'après l'avoir activé."),
          e.currentTarget)) },
        "Bloquer"),
      h("button", { type: "button", class: "small", title: `ufw delete deny ${p.port}/${base}`,
        onclick: async (e) => reload(await runAction("/api/firewall/rule", { protocol: base, port: p.port, block: false },
          `Retirer le blocage de ${what} ?`, e.currentTarget)) },
        "Débloquer"));
  }
  return buttons.length ? buttons : h("span", { class: "muted" }, p.pid ? "—" : "révèle d'abord le programme");
}

function renderFirewall() {
  const card = $("firewall");
  if (!firewall?.installed) {
    card.replaceChildren(h("strong", {}, "Pare-feu : "), "ufw n'est pas installé.");
    return;
  }
  card.replaceChildren(
    h("strong", {}, "Pare-feu (ufw) : "),
    firewall.enabled ? tag("activé", "green") : tag("désactivé", "orange"),
    h("span", { class: "muted" }, firewall.enabled
      ? " Les connexions entrantes non autorisées sont bloquées."
      : " Tous les ports « réseau » ci-dessous sont joignables par les autres machines."),
    h("button", {
      type: "button", class: firewall.enabled ? "small" : "small primary",
      onclick: async (e) => {
        const enable = !firewall.enabled;
        const ok = await runAction("/api/firewall/enable", { enabled: enable }, enable
          ? "Activer le pare-feu ?\n\nPar défaut, ufw bloque toutes les connexions ENTRANTES " +
            "(SSH depuis une autre machine, partage réseau…) et laisse passer les sortantes " +
            "(navigation, mises à jour). Ta navigation n'est pas affectée."
          : "Désactiver le pare-feu ?\n\nTous les ports réseau redeviendront joignables.", e.currentTarget);
        if (ok) views.ports.load();
      },
    }, firewall.enabled ? "Désactiver" : "Activer le pare-feu"),
  );
}

function renderPorts() {
  const onlyExposed = $("ports-exposed").checked;
  table($("ports"), ["Protocole", "Adresse", "Port", "Accès", "Service probable", "Processus", "Utilisateur", "Actions"],
    portsData.filter((p) => !onlyExposed || p.exposed).map((p) => h("tr", { class: p.exposed ? "warn" : "" },
      h("td", {}, p.protocol), h("td", { class: "mono" }, p.address), h("td", {}, String(p.port)),
      h("td", {}, p.exposed ? tag("réseau", "orange") : tag("local seulement", "green")),
      h("td", {}, p.service ?? "—", p.units.length ? h("div", { class: "muted mono" }, p.units.join(", ")) : null),
      h("td", {}, p.process
        ? [`${p.process} (${p.pid})`, p.pid === 1 ? h("div", { class: "muted" }, "systemd écoute à la place du service") : null,
          p.revealed ? tag("révélé en root") : null]
        : h("span", { class: "muted" }, "caché (autre utilisateur)")),
      h("td", {}, p.user ?? "—"),
      h("td", { class: "actions" }, portActions(p)))));
}
views.ports = {
  every: 5_000,
  async load() {
    try {
      [portsData, firewall] = await Promise.all([api("/api/ports"), api("/api/firewall")]);
      renderFirewall();
      renderPorts();
    } catch (err) {
      showError($("ports"), err);
    }
  },
};
$("ports-reveal").addEventListener("click", async (e) => {
  if (await runAction("/api/ports/reveal", undefined, null, e.currentTarget)) views.ports.load();
});
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
