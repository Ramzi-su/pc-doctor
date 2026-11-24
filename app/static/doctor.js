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
    // aria-* and data-* only exist as HTML attributes, not as DOM properties.
    else if (key.startsWith("aria-") || key.startsWith("data-")) node.setAttribute(key, value);
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
    const detail = Array.isArray(body?.detail) ? body.detail.map((d) => d.msg.replace(/^Value error, /, "")).join(" ; ") : body?.detail;
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

// ---------- line chart ----------
// Hand-made SVG chart (no library: our CSP only allows our own scripts).
// The viewBox matches the real pixel size, so text is never stretched.
// Hover/focus: a crosshair snaps to the nearest sample and one tooltip
// lists every series at that instant.

const SVG_NS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    // A style="..." attribute is blocked by our CSP (style-src 'self');
    // setting properties through the CSSOM is allowed.
    if (k === "style") for (const [prop, val] of Object.entries(v)) node.style.setProperty(prop, val);
    else node.setAttribute(k, v);
  }
  node.append(...children);
  return node;
}

// Series key: a short line drawn like the series itself (same color, and
// the same dash pattern in forced-colors mode), used in legend and tooltip.
function keyLine(color, k) {
  return svg("svg", { class: "key", width: "22", height: "4", "aria-hidden": "true" },
    svg("line", { class: "line", "data-series": k % 8, x1: 1, x2: 21, y1: 2, y2: 2, style: { stroke: `var(${color})` } }));
}

// Round an axis maximum up to 1, 2 or 5 x 10^n so tick labels stay readable.
function niceMax(value) {
  if (!(value > 0)) return 1;
  const pow = 10 ** Math.floor(Math.log10(value));
  return [1, 2, 5, 10].map((m) => m * pow).find((m) => m >= value);
}

// Same idea for byte rates, in 1024-based units, with steps whose quarters
// stay round (2 Mo/s -> 0.5 / 1 / 1.5 / 2).
function niceBytesMax(value) {
  if (!(value > 0)) return 1024;
  const unit = 1024 ** Math.floor(Math.log(value) / Math.log(1024));
  return unit * [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024].find((m) => m * unit >= value);
}

const HISTORY = 60; // 60 samples x 2 s = last 2 minutes
const MARGIN = { top: 10, right: 92, bottom: 22, left: 52 };

class LineChart {
  /**
   * @param {HTMLElement} el container
   * @param {{format: (v:number)=>string, max?: number, minMax?: number, area?: boolean}} opts
   *   max: fixed axis top (e.g. 100 %); otherwise auto, never below minMax.
   */
  constructor(el, opts) {
    this.opts = { height: 180, ...opts };
    this.hover = null;
    this.showTable = false;
    this.legend = h("div", { class: "legend" });
    // Table view: the accessible twin of the chart. Every value the chart
    // draws can be read here without hovering (and by screen readers).
    this.tableToggle = h("button", {
      type: "button", class: "small table-toggle", "aria-pressed": "false",
      onclick: () => {
        this.showTable = !this.showTable;
        this.tableToggle.setAttribute("aria-pressed", String(this.showTable));
        this.tableToggle.textContent = this.showTable ? "Graphique" : "Tableau";
        this.wrap.hidden = this.showTable;
        this.tableBox.hidden = !this.showTable;
        this.draw();
      },
    }, "Tableau");
    this.svg = svg("svg", { class: "chart", tabindex: "0", role: "img" });
    this.tip = h("div", { class: "chart-tip", hidden: true });
    this.wrap = h("div", { class: "chart-wrap" }, this.svg, this.tip);
    this.tableBox = h("div", { class: "chart-table", hidden: true });
    el.replaceChildren(h("div", { class: "chart-head" }, this.legend, this.tableToggle), this.wrap, this.tableBox);

    this.svg.addEventListener("pointermove", (e) => this.pointer(e));
    this.svg.addEventListener("pointerleave", () => this.setHover(null));
    this.svg.addEventListener("blur", () => this.setHover(null));
    this.svg.addEventListener("keydown", (e) => {
      const n = this.times?.length ?? 0;
      if (!n || !["ArrowLeft", "ArrowRight"].includes(e.key)) return;
      e.preventDefault();
      const cur = this.hover ?? n - 1;
      this.setHover(Math.max(0, Math.min(n - 1, cur + (e.key === "ArrowLeft" ? -1 : 1))));
    });
  }

  /** times: Date[]; series: [{name, color (CSS var), values: (number|null)[]}]
   *  capacity: number of x slots (default: the 2-minute live history). */
  update(times, series, capacity = HISTORY) {
    this.times = times;
    this.series = series;
    this.capacity = Math.max(capacity, times.length);
    this.draw();
  }

  setHover(i) {
    this.hover = i;
    this.draw();
  }

  pointer(e) {
    if (!this.times?.length) return;
    const rect = this.svg.getBoundingClientRect();
    const x = ((e.clientX - rect.left) * this.width) / rect.width;
    const i = Math.round((x - MARGIN.left) / this.step) - this.offset;
    this.setHover(Math.max(0, Math.min(this.times.length - 1, i)));
  }

  draw() {
    const { format, height } = this.opts;
    const series = this.series ?? [];
    const n = this.times?.length ?? 0;
    const W = Math.max(this.wrap.clientWidth, 300);
    const H = height;
    const plotW = W - MARGIN.left - MARGIN.right;
    const plotH = H - MARGIN.top - MARGIN.bottom;
    const cap = this.capacity ?? HISTORY;
    this.width = W;
    this.step = plotW / Math.max(cap - 1, 1);
    this.offset = this.opts.fromLeft ? 0 : cap - n; // live: newest on the right; tests: fill from the left
    this.svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    this.svg.setAttribute("height", H);

    const all = series.flatMap((s) => s.values).filter((v) => v !== null);
    const peak = Math.max(this.opts.minMax ?? 0, ...all);
    const top = this.opts.max ?? (this.opts.bytes ? niceBytesMax(peak) : niceMax(peak));
    const X = (i) => MARGIN.left + (i + this.offset) * this.step;
    const Y = (v) => MARGIN.top + plotH * (1 - Math.min(v, top) / top);

    const nodes = [];
    // Recessive grid: 4 intervals, labels in muted ink.
    for (let k = 0; k <= 4; k++) {
      const v = (top * k) / 4;
      nodes.push(svg("line", { class: k ? "grid" : "baseline", x1: MARGIN.left, x2: W - MARGIN.right, y1: Y(v), y2: Y(v) }));
      nodes.push(svg("text", { class: "tick", x: MARGIN.left - 6, y: Y(v) + 4, "text-anchor": "end" }, format(v)));
    }
    const xLabels = this.opts.xLabels?.(cap) ?? [[0, "−2 min"], [HISTORY / 2, "−1 min"], [HISTORY - 1, "maintenant"]];
    for (const [i, label] of xLabels) {
      nodes.push(svg("text", {
        class: "tick", x: MARGIN.left + i * this.step, y: H - 6,
        "text-anchor": i === 0 ? "start" : i === cap - 1 ? "end" : "middle",
      }, label));
    }

    series.forEach((s, k) => {
      // Gaps (null = no reading, e.g. GPU asleep) break the line.
      let d = "";
      let pen = false;
      s.values.forEach((v, i) => {
        if (v === null) { pen = false; return; }
        d += `${pen ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`;
        pen = true;
      });
      if (!d) return;
      if (this.opts.area && series.length === 1) {
        const first = s.values.findIndex((v) => v !== null);
        nodes.push(svg("path", {
          class: "area", style: { fill: `var(${s.color})` },
          d: `${d}L${X(n - 1)},${Y(0)}L${X(first)},${Y(0)}Z`,
        }));
      }
      // data-series: dash pattern used only in forced-colors mode, where every
      // line gets the same system color (see style.css).
      nodes.push(svg("path", { class: "line", "data-series": k % 8, style: { stroke: `var(${s.color})` }, d }));
    });

    // Direct labels at the line ends (<= 4 series). When two ends are too
    // close, the label moves but a thin leader line ties it back to its
    // line end, so it never floats detached from the line it names.
    if (series.length >= 2 && series.length <= 4) {
      const ends = series
        .map((s) => {
          const i = s.values.findLastIndex((v) => v !== null && v !== undefined);
          return i < 0 ? null : { s, x: X(i), y0: Y(s.values[i]) };
        })
        .filter(Boolean)
        .map((e) => ({ ...e, y: e.y0 }))
        .sort((a, b) => a.y0 - b.y0);
      for (let k = 1; k < ends.length; k++) ends[k].y = Math.max(ends[k].y, ends[k - 1].y + 13);
      const overflow = (ends.at(-1)?.y ?? 0) - (MARGIN.top + plotH);
      const labelX = W - MARGIN.right + 10;
      for (const e of ends) {
        if (overflow > 0) e.y -= overflow;
        if (Math.abs(e.y - e.y0) > 1.5 || labelX - e.x > 12) {
          nodes.push(svg("polyline", {
            class: "leader",
            points: `${e.x + 3},${e.y0} ${labelX - 8},${e.y0} ${labelX - 3},${e.y}`,
          }));
        }
        nodes.push(svg("text", { class: "end-label", x: labelX, y: e.y + 4 }, e.s.name));
      }
    }

    // Crosshair + tooltip.
    this.tip.hidden = this.hover === null;
    if (this.hover !== null && n) {
      const i = this.hover;
      const x = X(i);
      nodes.push(svg("line", { class: "crosshair", x1: x, x2: x, y1: MARGIN.top, y2: MARGIN.top + plotH }));
      for (const s of series) {
        const v = s.values[i];
        if (v !== null && v !== undefined) {
          nodes.push(svg("circle", { class: "dot", cx: x, cy: Y(v), r: 4, style: { fill: `var(${s.color})` } }));
        }
      }
      const ago = Math.round((this.times[n - 1] - this.times[i]) / 1000);
      const when = this.opts.fromLeft
        ? `${Math.round((this.times[i] - this.times[0]) / 1000)} s après le début`
        : ago ? `il y a ${ago} s` : "maintenant";
      this.tip.replaceChildren(
        h("div", { class: "tip-time" }, when),
        ...series.map((s) => h("div", { class: "tip-row" },
          keyLine(s.color, series.indexOf(s)),
          h("strong", {}, s.values[i] === null || s.values[i] === undefined ? "—" : format(s.values[i])),
          h("span", { class: "muted" }, s.name))),
      );
      const left = (x / W) * this.wrap.clientWidth;
      const right = left > this.wrap.clientWidth / 2;
      Object.assign(this.tip.style, right
        ? { left: "", right: `${this.wrap.clientWidth - left + 12}px` }
        : { right: "", left: `${left + 12}px` });
    }
    this.svg.replaceChildren(...nodes);

    // Legend (>= 2 series): line key, name, current value. Text stays in ink colors.
    this.legend.replaceChildren(...(series.length >= 2 ? series.map((s) => {
      const last = [...s.values].reverse().find((v) => v !== null);
      return h("span", { class: "legend-item" },
        keyLine(s.color, series.indexOf(s)),
        s.name, " ", h("strong", {}, last === undefined ? "—" : format(last)));
    }) : []));
    if (this.showTable) this.drawTable();
    this.svg.setAttribute("aria-label", series.map((s) => {
      const last = [...s.values].reverse().find((v) => v !== null);
      return `${s.name} : ${last === undefined ? "aucune donnée" : format(last)}`;
    }).join(", "));
  }

  /** Table twin: one row per sample, newest first, one column per series. */
  drawTable() {
    const { format } = this.opts;
    const times = this.times ?? [];
    const series = this.series ?? [];
    const n = times.length;
    const when = (i) => this.opts.fromLeft
      ? `${Math.round((times[i] - times[0]) / 1000)} s`
      : i === n - 1 ? "maintenant" : `il y a ${Math.round((times[n - 1] - times[i]) / 1000)} s`;
    const rows = [];
    for (let i = n - 1; i >= 0; i--) {
      rows.push(h("tr", {}, h("th", { scope: "row" }, when(i)),
        series.map((s) => h("td", {}, s.values[i] === null || s.values[i] === undefined ? "—" : format(s.values[i])))));
    }
    const scrollTop = this.tableBox.firstChild?.scrollTop ?? 0;
    const table = h("table", { class: "data" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Instant"),
        series.map((s) => h("th", { scope: "col" }, s.name)))),
      h("tbody", {}, rows.length ? rows : h("tr", {}, h("td", { colSpan: series.length + 1, class: "muted" }, "Pas encore de mesure"))));
    const box = h("div", { class: "chart-table-scroll" }, table);
    this.tableBox.replaceChildren(box);
    box.scrollTop = scrollTop; // live refresh must not jump the reader back to the top
  }
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

const samples = []; // last HISTORY snapshots, oldest first
let source = null;
let charts = null;

// One curve per component, named for humans. A sensor keeps the same color
// for the whole session (color follows the entity, never its rank).
const SENSOR_NAMES = {
  coretemp: "CPU", k10temp: "CPU", zenpower: "CPU", nvme: "SSD NVMe", acpitz: "Carte mère",
  iwlwifi_1: "Wi-Fi", amdgpu: "GPU", nouveau: "GPU", radeon: "GPU",
};
const PREFERRED_LABELS = ["Package id 0", "Tctl", "Composite", "edge"];
const sensorName = (sensor) => SENSOR_NAMES[sensor] ?? (sensor.startsWith("pch_") ? "Chipset" : sensor);

function temperatureGroups(s) {
  const groups = new Map();
  for (const t of s.temperatures) {
    const name = sensorName(t.sensor);
    const g = groups.get(name) ?? { preferred: null, max: -Infinity };
    if (PREFERRED_LABELS.includes(t.label)) g.preferred = t.celsius;
    g.max = Math.max(g.max, t.celsius);
    groups.set(name, g);
  }
  const out = new Map([...groups].map(([name, g]) => [name, g.preferred ?? g.max]));
  for (const gpu of s.gpus) if (gpu.temperature_c !== null) out.set("GPU", gpu.temperature_c);
  return out;
}

const tempSlots = new Map();
function tempSlot(name) {
  if (!tempSlots.has(name)) tempSlots.set(name, `--series-${Math.min(tempSlots.size + 1, 8)}`);
  return tempSlots.get(name);
}

// Physical interfaces only: virtual ones (containers, VPN bridges) would
// count the same traffic twice.
const VIRTUAL_IF = /^(lo|veth|docker|br-|virbr|vnet|podman|cni|flannel|tun|tap|wg|proton)/;

function sampleOf(s) {
  const phys = s.network.filter((n) => !VIRTUAL_IF.test(n.name));
  return {
    time: new Date(s.time),
    cpu: s.cpu_percent,
    mem: (100 * s.memory_used_bytes) / s.memory_total_bytes,
    swap: s.swap_total_bytes ? (100 * s.swap_used_bytes) / s.swap_total_bytes : null,
    temps: temperatureGroups(s),
    rx: phys.reduce((a, n) => a + n.rx_bps, 0),
    tx: phys.reduce((a, n) => a + n.tx_bps, 0),
    read: s.disk_read_bps,
    write: s.disk_write_bps,
  };
}

// Status = state, never decoration: reserved colors, always with an icon + label.
const STATUS = {
  good: ["✓", "Normal"], warning: ["!", "Élevé"], serious: ["!", "Très élevé"], critical: ["‼", "Critique"],
};
function level(value, warn, serious, critical) {
  if (value === null || value === undefined) return null;
  return value >= critical ? "critical" : value >= serious ? "serious" : value >= warn ? "warning" : "good";
}

function tile(label, value, sub, status = null) {
  return h("div", { class: "tile" },
    h("div", { class: "tile-head" },
      h("span", { class: "tile-label" }, label),
      status ? h("span", { class: `status status-${status}` }, `${STATUS[status][0]} ${STATUS[status][1]}`) : null),
    h("div", { class: "tile-value" }, value),
    h("div", { class: "tile-sub" }, sub));
}

function renderTiles(s, cur) {
  const cpuTemp = cur.temps.get("CPU") ?? null;
  const gpu = s.gpus[0];
  $("tiles").replaceChildren(
    tile("Processeur", pct(s.cpu_percent), `${num(s.cpu_mhz, " MHz")} · charge ${s.load_average[0].toFixed(2)}`,
      level(s.cpu_percent, 75, 90, 101)),
    tile("Mémoire", pct(cur.mem), `${bytes(s.memory_used_bytes)} / ${bytes(s.memory_total_bytes)}`,
      level(cur.mem, 80, 90, 95)),
    tile("Temp. CPU", cpuTemp === null ? "—" : `${Math.round(cpuTemp)} °C`,
      `max. tous capteurs ${Math.round(Math.max(...cur.temps.values()))} °C`, level(cpuTemp, 75, 85, 95)),
    tile("Carte graphique", gpu ? (gpu.pstate === "suspended" ? "veille" : pct(gpu.utilization_percent)) : "—",
      gpu ? (gpu.pstate === "suspended" ? "économie d'énergie" : `${num(gpu.temperature_c, " °C")} · ${num(gpu.memory_used_mib)} Mo VRAM`) : "pas de mesure",
      gpu && gpu.pstate !== "suspended" ? level(gpu.temperature_c, 75, 85, 92) : null),
    tile("Réseau", `↓ ${rate(cur.rx)}`, `↑ ${rate(cur.tx)}`),
    tile("Disque", `${rate(cur.read + cur.write)}`, `lect. ${rate(cur.read)} · écr. ${rate(cur.write)}`),
    tile("Batterie", s.battery_percent === null ? "—" : pct(s.battery_percent),
      s.battery_percent === null ? "pas de batterie" : s.on_ac ? "sur secteur" : "sur batterie",
      s.battery_percent !== null && !s.on_ac ? (s.battery_percent < 10 ? "critical" : s.battery_percent < 20 ? "warning" : null) : null),
    tile("Système", duration(s.uptime_seconds), `${s.process_count} processus`),
  );
}

function renderLive(s) {
  charts ??= {
    cpu: new LineChart($("chart-cpu"), { format: (v) => `${Math.round(v)} %`, max: 100, area: true }),
    mem: new LineChart($("chart-mem"), { format: (v) => `${Math.round(v)} %`, max: 100, area: true }),
    temp: new LineChart($("chart-temp"), { format: (v) => `${Math.round(v)} °C`, max: 100 }),
    net: new LineChart($("chart-net"), { format: rate, bytes: true, minMax: 16 * 1024 }),
    disk: new LineChart($("chart-disk"), { format: rate, bytes: true, minMax: 128 * 1024 }),
  };
  const cur = sampleOf(s);
  samples.push(cur);
  if (samples.length > HISTORY) samples.shift();
  const times = samples.map((x) => x.time);
  const col = (key) => samples.map((x) => x[key]);

  renderTiles(s, cur);
  charts.cpu.update(times, [{ name: "CPU", color: "--series-1", values: col("cpu") }]);
  charts.mem.update(times, [
    { name: "RAM", color: "--series-1", values: col("mem") },
    ...(cur.swap !== null ? [{ name: "Swap", color: "--series-2", values: col("swap") }] : []),
  ]);
  const tempNames = [...new Set(samples.flatMap((x) => [...x.temps.keys()]))];
  tempNames.forEach(tempSlot); // assign colors in first-seen order
  charts.temp.update(times, tempNames.map((name) => ({
    name, color: tempSlot(name), values: samples.map((x) => x.temps.get(name) ?? null),
  })));
  charts.net.update(times, [
    { name: "Reçu ↓", color: "--series-1", values: col("rx") },
    { name: "Envoyé ↑", color: "--series-2", values: col("tx") },
  ]);
  charts.disk.update(times, [
    { name: "Lecture", color: "--series-1", values: col("read") },
    { name: "Écriture", color: "--series-2", values: col("write") },
  ]);

  $("live-cores").replaceChildren(
    h("div", { class: "muted" }, `Par cœur (${s.cpu_per_core.length})`),
    h("div", { class: "cores" }, s.cpu_per_core.map((c, i) => h("div", { class: "core", title: `Cœur ${i} : ${pct(c)}` },
      h("div", { style: { height: `${c}%` } })))));

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

// ===== Hardware tests =====

let testCharts = null;
let shownTest = null; // id of the run or result displayed in the panel

const TEST_STATUS = {
  running: "En cours…", done: "Terminé", failed: "Impossible", cancelled: "Arrêté", idle: "",
};

function checkList(target, checks) {
  target.replaceChildren(...(checks.length
    ? checks.map((c) => h("li", {},
      h("span", { class: `sev sev-${c.severity}` }, SEV_LABEL[c.severity]),
      h("strong", {}, c.label), h("span", {}, c.value)))
    : [h("li", { class: "muted" }, "Les résultats apparaîtront à la fin du test.")]));
}

function testCard(t, data) {
  const running = data.state.status === "running";
  const last = data.last_results[t.id];
  const worst = last?.checks.some((c) => c.severity === "critical") ? "critical"
    : last?.checks.some((c) => c.severity === "warning") ? "warning" : last ? "ok" : null;
  return h("div", { class: "card test-card" },
    h("h2", {}, t.title, h("span", { class: "muted" }, `≈ ${t.duration_seconds < 60 ? `${t.duration_seconds} s` : `${Math.round(t.duration_seconds / 60)} min`}`)),
    h("p", {}, t.description),
    h("div", {},
      t.tool ? (t.tool_available ? tag(`${t.tool} installé`, "green")
        : [tag(`${t.tool} absent`, "orange"), h("code", { class: "install" }, t.install_hint)]) : null,
      t.needs_root ? tag("mot de passe root", "blue") : null),
    t.tool && !t.tool_available
      ? h("p", { class: "muted" }, {
        smart: "Indispensable pour ce test.",
        gpu: "En attendant : seulement l'état de la carte, sans test de charge 3D.",
      }[t.id] ?? "Un test de secours intégré sera utilisé en attendant.") : null,
    h("div", { class: "row" },
      h("button", {
        type: "button", class: "primary", disabled: running,
        onclick: async (e) => {
          if (await runAction(`/api/hwtests/${t.id}/start`, undefined, null, e.currentTarget)) {
            shownTest = t.id;
            views.tests.load();
          }
        },
      }, "Lancer"),
      last ? h("button", { type: "button", onclick: () => { shownTest = t.id; renderTestPanel(data); } },
        "Dernier résultat ", h("span", { class: `sev sev-${worst}` }, SEV_LABEL[worst])) : null));
}

function renderTestPanel(data) {
  const live = data.state.test_id && data.state.test_id === shownTest;
  const state = live ? data.state : data.last_results[shownTest];
  const panel = $("test-run");
  panel.hidden = !state;
  if (!state) return;
  const info = data.tests.find((t) => t.id === state.test_id);
  $("test-title").textContent = `${info.title} — ${fmtDate(state.started)}`;
  $("test-cancel").hidden = state.status !== "running";
  $("test-status").textContent = TEST_STATUS[state.status];
  $("test-progress").style.width = `${Math.round(state.progress * 100)}%`;
  $("test-percent").textContent = `${Math.round(state.progress * 100)} %`;
  checkList($("test-checks"), state.checks);
  const log = $("test-log");
  log.textContent = state.log.join("\n");
  log.scrollTop = log.scrollHeight;

  // Monitor charts: one per unit (never two scales on one axis).
  const s = state.series;
  const hasSeries = Object.keys(s).length > 0;
  panel.querySelector(".test-charts").hidden = !hasSeries;
  if (!hasSeries) return;
  const opts = (format) => ({
    format, fromLeft: true, height: 150,
    xLabels: (cap) => [[0, "0 s"], [cap - 1, `${cap - 1} s`]],
  });
  testCharts ??= {
    temp: new LineChart($("test-chart-temp"), { ...opts((v) => `${Math.round(v)} °C`), max: 100 }),
    freq: new LineChart($("test-chart-freq"), opts((v) => `${Math.round(v)} MHz`)),
    fan: new LineChart($("test-chart-fan"), { ...opts((v) => `${Math.round(v)}`), minMax: 1000 }),
  };
  const n = Math.max(0, ...Object.values(s).map((v) => v.length));
  const t0 = new Date(state.started).getTime();
  const times = Array.from({ length: n }, (_, i) => new Date(t0 + i * 1000));
  // Running: room for the expected duration; finished: the real one.
  const cap = state.status === "running" ? Math.max(n, info.duration_seconds) : n;
  testCharts.temp.update(times, [
    { name: "CPU", color: "--series-1", values: s["Temp. CPU (°C)"] ?? [] },
    ...(s["Temp. GPU (°C)"] ? [{ name: "GPU", color: "--series-2", values: s["Temp. GPU (°C)"] }] : []),
  ], cap);
  testCharts.freq.update(times, [{ name: "Fréquence", color: "--series-1", values: s["Fréquence CPU (MHz)"] ?? [] }], cap);
  testCharts.fan.update(times, [{ name: "tr/min", color: "--series-3", values: s["Ventilateur (tr/min)"] ?? [] }], cap);
}

views.tests = {
  every: 1_000,
  async load() {
    try {
      const data = await api("/api/hwtests");
      if (data.state.status === "running") shownTest ??= data.state.test_id;
      $("test-list").replaceChildren(...data.tests.map((t) => testCard(t, data)));
      renderTestPanel(data);
    } catch (err) {
      showError($("test-list"), err);
    }
  },
};
$("test-cancel").addEventListener("click", async (e) => {
  await runAction("/api/hwtests/cancel", undefined, null, e.currentTarget);
  views.tests.load();
});

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

const POLICY_LABELS = { allow: "allow : autoriser", deny: "deny : bloquer", reject: "reject : refuser" };
const POLICY_HELP = {
  incoming: ["Entrant", "connexions qui arrivent vers ce PC"],
  outgoing: ["Sortant", "connexions que ce PC ouvre (navigation, mises à jour)"],
  routed: ["Routé", "trafic que ce PC fait passer d'un réseau à un autre (VM, partage de connexion)"],
};
const LOG_LABELS = {
  off: "désactivée", low: "faible : paquets bloqués (limité)", medium: "moyenne : + paquets autorisés suspects",
  high: "élevée : presque tout (bruyant)", full: "complète : tout, sans limite (très bruyant)",
};
const ANY = new Set(["0.0.0.0/0", "::/0", "any"]);
let fwRenderedKey = "";
let fwRulesKey = "";

function firewallSelect(name, labels, current, onChange) {
  const select = h("select", { name, onchange: (e) => onChange(e.currentTarget) },
    current ? null : h("option", { value: "" }, "inconnue"),
    Object.entries(labels).map(([value, label]) => h("option", { value, selected: value === current }, label)));
  return select;
}

function policyConfirm(direction, policy) {
  const [label, help] = POLICY_HELP[direction];
  let text = `Politique par défaut « ${label} » (${help}) : ${policy} ?\n\n` +
    "Elle s'applique à tout ce qu'aucune règle ne mentionne.";
  if (direction === "outgoing" && policy !== "allow")
    text += "\n\n⚠️ Sans règles « allow out », ce PC ne pourra plus rien ouvrir : plus de navigation, " +
      "plus de DNS, plus de mises à jour. N'utilise ça que si tu sais quelles règles ajouter.";
  if (direction === "incoming" && policy === "allow")
    text += "\n\n⚠️ Tous les ports réseau deviennent joignables : le pare-feu ne protège presque plus rien.";
  return text;
}

function renderFirewall() {
  const card = $("firewall");
  const key = JSON.stringify([firewall?.installed, firewall?.enabled, firewall?.policies, firewall?.logging]);
  if (key === fwRenderedKey) return renderFirewallRules();
  fwRenderedKey = key;
  if (!firewall?.installed) {
    card.replaceChildren("ufw n'est pas installé (sudo apt install ufw).");
    $("fw-settings").replaceChildren();
    return;
  }
  card.replaceChildren(
    firewall.enabled ? tag("activé", "green") : tag("désactivé", "orange"),
    h("span", { class: "muted" }, firewall.enabled
      ? " Le trafic est filtré selon les politiques et les règles ci-dessous."
      : " Rien n'est filtré : tous les ports « réseau » ci-dessous sont joignables."),
    h("button", {
      type: "button", class: firewall.enabled ? "small" : "small primary",
      onclick: async (e) => {
        const enable = !firewall.enabled;
        const ok = await runAction("/api/firewall/enable", { enabled: enable }, enable
          ? `Activer le pare-feu ?\n\nEntrant : ${firewall.policies.incoming ?? "?"}, ` +
            `sortant : ${firewall.policies.outgoing ?? "?"}. Avec les réglages habituels ` +
            "(entrant deny, sortant allow), ta navigation n'est pas affectée."
          : "Désactiver le pare-feu ?\n\nTous les ports réseau redeviendront joignables.", e.currentTarget);
        if (ok) views.ports.load();
      },
    }, firewall.enabled ? "Désactiver" : "Activer le pare-feu"),
  );
  const revert = () => { fwRenderedKey = ""; renderFirewall(); };
  $("fw-settings").replaceChildren(
    ...Object.entries(POLICY_HELP).map(([direction, [label, help]]) => h("label", { title: help },
      h("span", {}, `Par défaut — ${label}`),
      firewallSelect(direction, POLICY_LABELS, firewall.policies[direction], async (select) => {
        const ok = await runAction("/api/firewall/default", { direction, policy: select.value },
          policyConfirm(direction, select.value), select);
        ok ? views.ports.load() : revert();
      }))),
    h("label", { title: "Les paquets journalisés apparaissent dans l'onglet Journal ([UFW BLOCK])" },
      h("span", {}, "Journalisation"),
      firewallSelect("logging", LOG_LABELS, firewall.logging, async (select) => {
        const noisy = ["high", "full"].includes(select.value);
        const ok = await runAction("/api/firewall/logging", { level: select.value },
          `Journalisation du pare-feu : ${LOG_LABELS[select.value]} ?` +
          (noisy ? "\n\n⚠️ Ce niveau remplit vite le journal système." : ""), select);
        ok ? views.ports.load() : revert();
      })),
  );
  renderFirewallRules();
}

const where = (address, port, app) =>
  `${ANY.has(address) ? "partout" : address}${app ? ` (app ${app})` : port ? ` port ${port}` : ""}`;

function ruleCommand(r) {
  const dir = r.route ? "routé" : r.direction === "in" ? "entrant" : "sortant";
  const iface = [r.interface_in && `in ${r.interface_in}`, r.interface_out && `out ${r.interface_out}`]
    .filter(Boolean).join(", ");
  return `${r.action} ${dir}${iface ? ` (${iface})` : ""} ${r.protocol === "any" ? "" : r.protocol + " "}` +
    `de ${where(r.from_address, r.from_port, r.from_app)} vers ${where(r.to_address, r.to_port, r.to_app)}`;
}

function renderFirewallRules() {
  const key = firewall?.rules_read_at ?? "";
  if (key === fwRulesKey) return;
  fwRulesKey = key;
  const target = $("fw-rules");
  if (!firewall?.rules) return;
  $("fw-read-at").textContent = `Lues en root le ${fmtDate(firewall.rules_read_at)} ` +
    "(une modification faite dans un terminal n'apparaît qu'à la prochaine lecture).";
  $("fw-reveal").textContent = "Relire les règles (root)";
  target.hidden = false;
  const ACTION_COLORS = { allow: "green", limit: "blue", deny: "red", reject: "red" };
  table(target, ["Action", "Direction", "Protocole", "Source", "Destination", "IP", "Commentaire", ""],
    firewall.rules.map((r) => h("tr", {},
      h("td", {}, tag(r.action, ACTION_COLORS[r.action] ?? ""), r.log ? tag(r.log) : null),
      h("td", {}, r.route ? "routé" : r.direction === "in" ? "↓ entrant" : "↑ sortant",
        r.interface_in || r.interface_out
          ? h("div", { class: "muted mono" }, [r.interface_in, r.interface_out].filter(Boolean).join(" → ")) : null),
      h("td", {}, r.protocol === "any" ? "tous" : r.protocol),
      h("td", { class: "mono" }, where(r.from_address, r.from_port, r.from_app)),
      h("td", { class: "mono" }, where(r.to_address, r.to_port, r.to_app)),
      h("td", {}, r.ipv6 ? "v6" : "v4"),
      h("td", {}, r.comment || h("span", { class: "muted" }, "—")),
      h("td", { class: "actions" }, h("button", {
        type: "button", class: "small danger",
        onclick: async (e) => {
          const both = ANY.has(r.from_address) && ANY.has(r.to_address);
          if (await runAction("/api/firewall/rules/delete", { id: r.id },
            `Supprimer la règle « ${ruleCommand(r)} » ?` +
            (both ? "\n\nLa même règle en IPv4 et en IPv6 sera supprimée ensemble." : ""), e.currentTarget))
            views.ports.load();
        },
      }, "Supprimer")))));
}

// Live preview of the command the form will build (the server builds the
// real one again from the validated fields).
function formRule(form) {
  const data = Object.fromEntries(new FormData(form));
  return {
    action: data.action, direction: data.direction, protocol: data.protocol,
    from_address: data.from_address.trim() || "any", from_port: data.from_port.trim(),
    to_address: data.to_address.trim() || "any", to_port: data.to_port.trim(),
    log: data.log === "on", comment: data.comment.trim(),
  };
}
function previewRule() {
  const r = formRule($("fw-add"));
  $("fw-preview").textContent = ["ufw", r.action, r.direction, r.log && "log",
    r.protocol !== "any" && `proto ${r.protocol}`, `from ${r.from_address}`, r.from_port && `port ${r.from_port}`,
    `to ${r.to_address}`, r.to_port && `port ${r.to_port}`, r.comment && `comment '${r.comment}'`]
    .filter(Boolean).join(" ");
}
$("fw-add").addEventListener("input", previewRule);
$("fw-add").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  const r = formRule(form);
  let text = `Ajouter cette règle ?\n\n${$("fw-preview").textContent}`;
  if (r.action === "allow" && r.direction === "in" && ANY.has(r.from_address) && !r.to_port)
    text += "\n\n⚠️ Sans port, cette règle ouvre TOUS les ports à tout le monde.";
  if (r.action !== "allow" && r.action !== "limit" && r.direction === "out" && ANY.has(r.to_address) && !r.to_port)
    text += "\n\n⚠️ Sans port ni destination, cette règle coupe tout le trafic sortant (internet).";
  if (!firewall?.enabled) text += "\n\nLe pare-feu est désactivé : la règle ne s'appliquera qu'une fois activé.";
  if (await runAction("/api/firewall/rules", r, text, form.querySelector("button[type=submit]"))) {
    form.reset();
    previewRule();
    views.ports.load();
  }
});
previewRule();
$("fw-reveal").addEventListener("click", async (e) => {
  if (await runAction("/api/firewall/rules/reveal", undefined, null, e.currentTarget)) views.ports.load();
});

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
