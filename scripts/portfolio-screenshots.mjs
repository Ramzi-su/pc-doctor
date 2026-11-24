// Portfolio screenshots of PC Doctor, with personal data masked in the page.
//
// Usage (Node >= 22 for the built-in WebSocket, Google Chrome installed):
//   uv run uvicorn app.main:app --host 127.0.0.1 --port 9100 &
//   node scripts/portfolio-screenshots.mjs http://127.0.0.1:9100 docs/screenshots
//
// Drives headless Chrome through the DevTools protocol. A script injected
// before the page's own code rewrites identifying text (user/host name, MAC,
// private IPs) with documentation values, and hides the rows of the capture
// tooling itself. The application is never modified. Always look at every
// image before publishing it: masking rules cannot know every secret.
import { spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo, hostname } from "node:os";
import { join } from "node:path";
const [base, outDir] = process.argv.slice(2);
if (!base || !outDir) {
  console.error("usage: node scripts/portfolio-screenshots.mjs <base url> <output dir>");
  process.exit(1);
}
const W = 1440, H = 900;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const chrome = spawn("google-chrome", ["--headless=new", "--disable-gpu", "--no-sandbox", "--remote-debugging-port=9334",
  `--user-data-dir=${mkdtempSync(join(tmpdir(), "portfolio-profile-"))}`, "--hide-scrollbars", "about:blank"], { stdio: "ignore" });
let target;
for (let i = 0; i < 40 && !target; i++) {
  await sleep(250);
  try { target = (await (await fetch("http://127.0.0.1:9334/json")).json()).find((t) => t.type === "page"); } catch {}
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r));
let id = 0; const pending = new Map();
ws.addEventListener("message", (e) => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result ?? m.error); pending.delete(m.id); }
  if (m.method === "Runtime.exceptionThrown") console.log("EXCEPTION", m.params.exceptionDetails.exception?.description);
});
const send = (method, params = {}) => new Promise((r) => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });
const js = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true }))?.result?.value;

// Runs in the page before its own scripts: rewrites identifying text forever after.
const names = [...new Set([userInfo().username, hostname()])].filter((n) => /^[\w.-]{3,}$/.test(n));
const MASK = `const NAMES = ${JSON.stringify(names)};` + String.raw`
(() => {
  const ipMap = new Map(), macMap = new Map(), v6Map = new Map();
  const keep4 = (ip) => /^(127\.|0\.0\.0\.0|192\.0\.2\.|1\.1\.1\.1$|255\.)/.test(ip);
  const rules = [
    ...NAMES.map((n) => [new RegExp(n, "g"), () => "user"]),
    [/\benx[0-9a-f]{12}\b/g, () => "usb0"],
    [/\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, (m) => m === "00:00:00:00:00:00" || /^02:00:5e:00:53:/i.test(m) ? m
      : (macMap.get(m) ?? (macMap.set(m, "02:00:5e:00:53:" + (macMap.size + 1).toString(16).padStart(2, "0")), macMap.get(m)))],
    [/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g, (m) => keep4(m) ? m
      : (ipMap.get(m) ?? (ipMap.set(m, "192.0.2." + (ipMap.size + 10)), ipMap.get(m)))],
    [/\bfe80::[0-9a-f:]+/gi, () => "fe80::1"],
    [/\b[23][0-9a-f]{3}:[0-9a-f]{1,4}:[0-9a-f:]{3,}/gi, (m) => /^2001:db8/i.test(m) ? m
      : (v6Map.get(m) ?? (v6Map.set(m, "2001:db8::" + (v6Map.size + 1)), v6Map.get(m)))],
  ];
  // Rows of the capture tooling (Claude, test server, headless Chrome): PIDs set by the script.
  window.__hidePids = new Set();
  const hideRows = () => {
    for (const tr of document.querySelectorAll("#proc-table tbody tr, #live-procs tbody tr, #ports tbody tr")) {
      const cells = tr.cells;
      const first = Number(cells[0]?.textContent);
      const owner = Number((tr.closest("#ports") ? cells[5]?.textContent : "").match(/\((\d+)\)/)?.[1]);
      const hide = window.__hidePids.has(first) || window.__hidePids.has(owner);
      if (hide !== (tr.style.display === "none")) tr.style.display = hide ? "none" : "";
    }
  };
  const fix = (s) => rules.reduce((acc, [re, f]) => acc.replace(re, f), s);
  const walk = (root) => {
    const it = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n; (n = it.nextNode());) { const v = fix(n.nodeValue); if (v !== n.nodeValue) n.nodeValue = v; }
    if (root.querySelectorAll) for (const el of root.querySelectorAll("[title]")) { const v = fix(el.title); if (v !== el.title) el.title = v; }
  };
  new MutationObserver((muts) => { for (const m of muts) walk(m.target.nodeType === 3 ? m.target.parentNode : m.target); hideRows(); })
    .observe(document, { subtree: true, childList: true, characterData: true });
  document.addEventListener("DOMContentLoaded", () => walk(document.body));
})();`;

await send("Runtime.enable");
await send("Page.enable");
await send("Page.addScriptToEvaluateOnNewDocument", { source: MASK });
await send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 2, mobile: false });
const theme = (dark) => send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: dark ? "dark" : "light" }] });

async function shot(name, { full = false } = {}) {
  await sleep(700); // let the mask observer run after the last render
  const params = { format: "png" };
  if (full) {
    // The tab scrolls inside .view: unfold it so the document holds everything.
    await js(`document.body.style.height = "auto"; for (const v of document.querySelectorAll(".view")) v.style.overflow = "visible";`);
    await sleep(300);
    const h = await js("document.documentElement.scrollHeight");
    params.clip = { x: 0, y: 0, width: W, height: Math.max(h, H), scale: 1 };
    params.captureBeyondViewport = true;
  }
  const r = await send("Page.captureScreenshot", params);
  writeFileSync(`${outDir}/${name}.png`, Buffer.from(r.data, "base64"));
  if (full) await js(`document.body.style.height = ""; for (const v of document.querySelectorAll(".view")) v.style.overflow = "";`);
  console.log("saved", name);
}
const go = async (hash, wait) => { await js(`location.hash = "${hash}"`); await sleep(wait); };

await theme(false);
await send("Page.navigate", { url: `${base}/#dashboard` });
await sleep(4000);
// Every descendant of a "claude" process is capture tooling: hide those rows.
const hidden = await js(`fetch("/api/processes").then(r => r.json()).then(({ processes }) => {
  const kids = new Map();
  for (const p of processes) kids.set(p.ppid, [...(kids.get(p.ppid) ?? []), p.pid]);
  const tooling = (p) => p.name === "claude" || /--port 9100|portfolio-profile/.test(p.cmdline ?? "");
  const out = new Set(processes.filter(tooling).map(p => p.pid));
  const stack = [...out];
  while (stack.length) for (const c of kids.get(stack.pop()) ?? []) if (!out.has(c)) { out.add(c); stack.push(c); }
  window.__hidePids = out;
  return out.size;
})`);
console.log("hidden pids:", hidden);
await js(`fetch("/api/hwtests/cpu/start", { method: "POST", headers: { "X-Requested-With": "pc-doctor" } }).then(r => r.status)`);
await sleep(50000);                       // curves rise with the CPU test
await shot("01-dashboard");
await theme(true); await sleep(1500);
await shot("02-dashboard-dark");
await theme(false);
await go("#tests", 30000);                // CPU test finishes
await js(`document.querySelector("#test-run")?.scrollIntoView()`);
await shot("03-hardware-tests", { full: true });
const refreshHidden = () => js(`fetch("/api/processes").then(r => r.json()).then(({ processes }) => {
  const kids = new Map();
  for (const p of processes) kids.set(p.ppid, [...(kids.get(p.ppid) ?? []), p.pid]);
  const stack = processes.filter(p => p.name === "claude" || /--port 9100|portfolio-profile/.test(p.cmdline ?? "")).map(p => p.pid);
  for (const p of stack) window.__hidePids.add(p);
  while (stack.length) for (const c of kids.get(stack.pop()) ?? []) if (!window.__hidePids.has(c)) { window.__hidePids.add(c); stack.push(c); }
})`);
await refreshHidden();
await go("#processes", 4000);
await js(`document.getElementById("proc-tree").click()`); await sleep(1500);
await shot("04-processes-tree");
await go("#ports", 3000);
await shot("05-ports-firewall");
await go("#hardware", 4000);
await shot("06-hardware", { full: true });
await go("#network", 3000);
await shot("07-network");
await go("#security", 4000);
await shot("08-permissions-suid");
await go("#logs", 4000);
// Neutral view for a public image: kernel errors of the last 24 h.
await js(`(() => {
  const range = document.getElementById("range"); range.value = "1440"; range.dispatchEvent(new Event("change"));
  document.getElementById("prio-errors").click();
  [...document.querySelectorAll("#quick-idents button")].find(b => b.textContent.trim() === "Kernel")?.click();
})()`);
await sleep(4000);
await shot("09-journal");
ws.close(); chrome.kill();
