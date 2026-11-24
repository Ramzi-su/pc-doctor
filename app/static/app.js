"use strict";

// Log messages are untrusted (they may contain HTML from web pages):
// every dynamic value is inserted with textContent, never innerHTML.

const $ = (id) => document.getElementById(id);
const PRIO_LABELS = {
  emerg: "Urgence", alert: "Alerte", crit: "Critique", err: "Erreur",
  warning: "Avertissement", notice: "Notice", info: "Info", debug: "Debug",
};
const QUICK_IDENTS = [
  { label: "Brave", match: (s) => s.toLowerCase().includes("brave") },
  { label: "Firefox", match: (s) => s.toLowerCase().includes("firefox") },
  { label: "Kernel", match: (s) => s === "kernel" },
];

const selectedIdents = new Set();
let allIdents = [];
let currentRequest = null;
let autoTimer = null;

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of children) node.append(child);
  return node;
}

// ---------- Filters UI ----------

async function initPriorities() {
  const prios = await fetchJson("/api/priorities");
  const box = $("priorities");
  for (const p of prios) {
    const input = el("input", { type: "checkbox", value: p.value, checked: true });
    input.addEventListener("change", reload);
    box.append(el("label", { className: "check" }, [
      input, el("span", { className: `dot p-${p.name}` }), PRIO_LABELS[p.name] ?? p.name,
    ]));
  }
}

function setPriorities(maxValue) {
  for (const input of $("priorities").querySelectorAll("input")) {
    input.checked = Number(input.value) <= maxValue;
  }
  reload();
}

async function initIdentifiers() {
  allIdents = await fetchJson("/api/identifiers");
  renderIdentifiers();
  const quick = $("quick-idents");
  for (const q of QUICK_IDENTS) {
    const matches = allIdents.filter(q.match);
    if (!matches.length) continue;
    const btn = el("button", { type: "button", textContent: q.label, title: matches.join(", ") });
    btn.addEventListener("click", () => {
      const allOn = matches.every((m) => selectedIdents.has(m));
      matches.forEach((m) => (allOn ? selectedIdents.delete(m) : selectedIdents.add(m)));
      renderIdentifiers();
      reload();
    });
    quick.append(btn);
  }
}

function renderIdentifiers() {
  const term = $("ident-search").value.toLowerCase();
  // Selected first, then the rest, filtered by the search box.
  const list = [...allIdents]
    .filter((i) => i.toLowerCase().includes(term))
    .sort((a, b) => selectedIdents.has(b) - selectedIdents.has(a));
  const box = $("identifiers");
  box.replaceChildren(...list.map((ident) => {
    const input = el("input", { type: "checkbox", checked: selectedIdents.has(ident) });
    input.addEventListener("change", () => {
      input.checked ? selectedIdents.add(ident) : selectedIdents.delete(ident);
      updateQuickButtons();
      reload();
    });
    return el("label", { className: "check" }, [input, ident]);
  }));
  updateQuickButtons();
}

function updateQuickButtons() {
  $("ident-count").textContent = selectedIdents.size ? `(${selectedIdents.size})` : "";
  const buttons = $("quick-idents").querySelectorAll("button");
  buttons.forEach((btn) => {
    const q = QUICK_IDENTS.find((x) => x.label === btn.textContent);
    const matches = allIdents.filter(q.match);
    btn.classList.toggle("active", matches.every((m) => selectedIdents.has(m)));
  });
}

// ---------- Query ----------

function buildParams() {
  const params = new URLSearchParams();
  const range = $("range").value;
  if (range === "custom") {
    if ($("since").value) params.set("since", $("since").value);
    if ($("until").value) params.set("until", $("until").value);
  } else {
    params.set("since", new Date(Date.now() - Number(range) * 60_000).toISOString());
  }
  for (const input of $("priorities").querySelectorAll("input:checked")) {
    params.append("priorities", input.value);
  }
  selectedIdents.forEach((i) => params.append("identifiers", i));
  const text = $("text").value.trim();
  if (text) params.set("text", text);
  if ($("crash-only").checked) params.set("crash_only", "true");
  params.set("limit", $("limit").value);
  return params;
}

async function fetchJson(url, signal) {
  const res = await fetch(url, { signal });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = Array.isArray(body.detail)
      ? body.detail.map((d) => d.msg).join(" ; ")
      : body.detail;
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return body;
}

async function reload() {
  currentRequest?.abort(); // drop the previous request if still running
  currentRequest = new AbortController();
  setStatus("Chargement…");
  try {
    const data = await fetchJson(`/api/logs?${buildParams()}`, currentRequest.signal);
    renderLogs(data);
  } catch (err) {
    if (err.name !== "AbortError") setStatus(err.message, true);
  }
}

// ---------- Rendering ----------

const dateFmt = new Intl.DateTimeFormat("fr-FR", {
  day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
});

function renderLogs({ entries, truncated }) {
  const counts = {};
  const rows = entries.map((e) => {
    counts[e.priority_name] = (counts[e.priority_name] ?? 0) + 1;
    const msg = el("td", { className: "msg" });
    if (e.crash_hint) msg.append(el("span", { className: "crash-tag", textContent: "CRASH" }));
    msg.append(e.message);
    return el("tr", { className: e.crash_hint ? "crash" : "", title: e.unit ?? "" }, [
      el("td", { textContent: dateFmt.format(new Date(e.timestamp)) }),
      el("td", {}, [el("span", {
        className: `badge p-${e.priority_name}`,
        textContent: PRIO_LABELS[e.priority_name] ?? e.priority_name,
      })]),
      el("td", { textContent: e.identifier }),
      el("td", { textContent: e.pid ?? "" }),
      msg,
    ]);
  });
  $("logs").replaceChildren(...rows);

  const crashCount = entries.filter((e) => e.crash_hint).length;
  setStatus(
    `${entries.length} entrées` +
    (truncated ? " (limite atteinte : entrées plus anciennes non affichées)" : "") +
    (crashCount ? ` — ${crashCount} crash(s) détecté(s)` : ""),
  );
  $("summary").replaceChildren(...Object.entries(counts).map(([name, n]) =>
    el("span", {}, [el("span", { className: `dot p-${name}` }), ` ${n}`])));
}

function setStatus(text, isError = false) {
  $("status").textContent = text;
  $("status").classList.toggle("error", isError);
}

// ---------- Wiring ----------

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function wire() {
  $("range").addEventListener("change", () => {
    $("custom-range").hidden = $("range").value !== "custom";
    reload();
  });
  $("since").addEventListener("change", reload);
  $("until").addEventListener("change", reload);
  $("prio-errors").addEventListener("click", () => setPriorities(3));
  $("prio-all").addEventListener("click", () => setPriorities(7));
  $("ident-search").addEventListener("input", renderIdentifiers);
  $("ident-clear").addEventListener("click", () => {
    selectedIdents.clear();
    renderIdentifiers();
    reload();
  });
  $("text").addEventListener("input", debounce(reload, 400));
  $("crash-only").addEventListener("change", reload);
  $("limit").addEventListener("change", reload);
  $("refresh").addEventListener("click", reload);
  const startAuto = () => {
    clearInterval(autoTimer);
    // Skip refreshes while the Journal tab is hidden: no wasted journalctl calls.
    if ($("auto").checked) {
      autoTimer = setInterval(() => { if (!$("view-logs").hidden) reload(); }, 10_000);
    }
  };
  $("auto").addEventListener("change", startAuto);
  startAuto();
}

async function main() {
  wire();
  try {
    await Promise.all([initPriorities(), initIdentifiers()]);
  } catch (err) {
    setStatus(err.message, true);
    return;
  }
  reload();
}

main();
