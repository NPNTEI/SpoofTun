"use strict";
let csrf = "";
let tab = "overview";
let timer = null;
const app = document.getElementById("app");
const theme = localStorage.getItem("uut-theme") || "dark";
document.documentElement.setAttribute("data-theme", theme);

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

async function api(path, method = "GET", body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") { opts.headers["Content-Type"] = "application/json"; opts.headers["X-CSRF"] = csrf; opts.body = JSON.stringify(body || {}); }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* ignore */ }
  if (res.status === 401 && path !== "/api/login") { csrf = ""; stopTimer(); render(); }
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

const fmtBytes = (n) => { if (n == null) return "—"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return n.toFixed(i > 1 ? 2 : 0) + " " + u[i]; };
const fmtGiB = (n) => (n / 1073741824).toFixed(1);
const fmtUp = (s) => { if (!s) return "—"; const d = Math.floor(s / 86400), hr = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + "d " + hr + "h" : hr ? hr + "h " + m + "m" : m + "m"; };
const last = (a) => (a && a.length ? a[a.length - 1] : 0);

function note(box, text, ok) { box.replaceChildren(h("div", { class: "msg " + (ok ? "ok" : "err") }, text)); }
function field(label, name, value = "", extra = {}) { return h("label", {}, label, h("input", { name, value, autocomplete: "off", spellcheck: "false", ...extra })); }
function select(label, name, options) { return h("label", {}, label, h("select", { name }, options.map(([v, t]) => h("option", { value: v }, t)))); }
function val(form, name) { const el = form.elements[name]; return el ? el.value.trim() : ""; }

function meter(pct) {
  const total = 20, on = Math.round(pct / 100 * total);
  return h("div", { class: "meter" }, Array.from({ length: total }, (_, i) => h("i", { class: i < on ? "on" : "" })));
}
function bars(values, count = 22) {
  const data = values.slice(-count);
  while (data.length < count) data.unshift(0);
  const top = Math.max(1, ...data);
  const box = h("div", { class: "bars" });
  for (const v of data) { const i = h("i"); i.style.height = Math.max(6, Math.round(v / top * 100)) + "%"; box.append(i); }
  return box;
}
function spark(values) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("class", "spark"); svg.setAttribute("viewBox", "0 0 220 56"); svg.setAttribute("preserveAspectRatio", "none");
  const pts = values.filter((v) => v != null);
  if (pts.length > 1) {
    const top = Math.max(...pts, 1);
    const path = document.createElementNS(NS, "path");
    let d = "";
    values.forEach((v, i) => { const x = i * (220 / Math.max(1, values.length - 1)); const y = v == null ? 54 : 52 - (v / top) * 46; d += (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1); });
    path.setAttribute("d", d); svg.append(path);
  }
  return svg;
}

async function login() {
  const pw = document.getElementById("pw").value;
  try { const r = await api("/api/login", "POST", { password: pw }); csrf = r.csrf; render(); }
  catch (e) { note(document.getElementById("lmsg"), e.message, false); }
}
function renderLogin() {
  app.replaceChildren(h("div", { class: "login" }, h("div", { class: "card" },
    h("h3", {}, "UnUnknownTun"), h("p", { class: "dim" }, "Sign in to the panel"), h("div", { id: "lmsg" }),
    h("label", {}, "Password", h("input", { id: "pw", type: "password", autocomplete: "current-password", onkeydown: (e) => { if (e.key === "Enter") login(); } })),
    h("div", { class: "row" }, h("button", { class: "btn w", onclick: login }, "Sign in")),
    h("p", { class: "dim" }, "Forgot it? Run on the server: ununknowntun panel-password"))));
}

function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }
function startTimer(fn, ms) { stopTimer(); timer = setInterval(fn, ms); }

let tunnelCount = 0;
function shell() {
  const tabs = [["overview", "Overview"], ["tunnels", "Tunnels"], ["test", "Connection test"], ["manage", "Manage"]];
  app.replaceChildren(
    h("header", {}, h("div", { class: "brand" }, h("div", { class: "logo" }, "UUT"), h("div", {}, h("b", { id: "hhost" }, "UnUnknownTun"), h("span", { id: "hsub" }, ""))),
      h("div", { class: "row", style: null }, h("button", { class: "hbtn", onclick: () => { const t = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark"; document.documentElement.setAttribute("data-theme", t); localStorage.setItem("uut-theme", t); } }, "Appearance"),
        h("button", { class: "hbtn", onclick: async () => { await api("/api/logout", "POST"); csrf = ""; stopTimer(); render(); } }, "Log out"))),
    h("div", { class: "wrap" }, h("div", { id: "view" }),
      h("div", { class: "tabs" }, h("div", {}, tabs.map(([id, t]) => h("button", { class: tab === id ? "on" : "", onclick: () => { tab = id; shell(); } }, t, id === "tunnels" ? h("span", { class: "badge" }, tunnelCount) : null))))));
  ({ overview: viewOverview, tunnels: viewTunnels, test: viewTest, manage: viewManage })[tab]();
}

function stat(big, unit, label, sub, pct) {
  return h("div", { class: "cell" }, h("div", { class: "big" }, big, h("small", {}, unit + " " + label)), pct != null ? meter(pct) : null, h("div", { class: "sub" }, sub));
}

async function viewOverview() {
  const view = document.getElementById("view");
  const draw = async () => {
    let s, t;
    try { [s, t] = await Promise.all([api("/api/system"), api("/api/tunnels")]); } catch (e) { view.replaceChildren(h("div", { class: "msg err" }, e.message)); return; }
    tunnelCount = t.tunnels.length;
    document.getElementById("hhost").textContent = s.host;
    document.getElementById("hsub").textContent = "v" + s.version + " · " + s.os;
    const down = last(s.net.rx), up = last(s.net.tx);
    const bad = t.tunnels.filter((x) => !x.running).length;
    const pills = h("div", { class: "pills" },
      bad ? h("div", { class: "pill bad" }, h("i"), bad + " tunnel" + (bad > 1 ? "s are" : " is") + " not running") : (t.tunnels.length ? h("div", { class: "pill" }, h("i"), "All tunnels running") : h("div", { class: "pill warn" }, h("i"), "No tunnels yet: open Manage")),
      location.hostname !== "127.0.0.1" ? h("div", { class: "pill warn" }, h("i"), "Panel is reachable over the network: restrict its port in the firewall") : null);
    view.replaceChildren(
      h("div", { class: "sec" }, "SERVER"),
      h("div", { class: "grid g4" },
        stat(Math.round(s.cpu.now), "%", "Processor", s.cores + " cores · load " + s.load.join(", "), s.cpu.now),
        stat(Math.round(s.mem.pct), "%", "Memory", fmtGiB(s.mem.used) + " / " + fmtGiB(s.mem.total) + " GiB", s.mem.pct),
        stat(Math.round(s.disk.pct), "%", "Disk", fmtGiB(s.disk.used) + " / " + fmtGiB(s.disk.total) + " GiB", s.disk.pct),
        stat(Math.round(s.swap.pct), "%", "Swap", s.swap.total ? fmtGiB(s.swap.used) + " / " + fmtGiB(s.swap.total) + " GiB" : "not configured", s.swap.pct)),
      h("div", { class: "grid g2" },
        h("div", { class: "cell" }, h("div", { class: "big" }, down.toFixed(1), h("small", {}, "Mb/s Download")), bars(s.net.rx), h("div", { class: "sub" }, "peak " + Math.max(0, ...s.net.rx).toFixed(1) + " Mb/s in the last " + s.net.rx.length + " readings")),
        h("div", { class: "cell" }, h("div", { class: "big" }, up.toFixed(1), h("small", {}, "Mb/s Upload")), bars(s.net.tx), h("div", { class: "sub" }, "peak " + Math.max(0, ...s.net.tx).toFixed(1) + " Mb/s in the last " + s.net.tx.length + " readings"))),
      pills,
      h("div", { class: "sec" }, "THIS SERVER"),
      h("div", { class: "total" },
        h("div", { class: "row", style: null }, h("div", {}, h("div", { class: "big" }, fmtBytes(s.net.rx_total + s.net.tx_total)), h("div", { class: "sub" }, "carried since this server booted")),
          h("div", { class: "chips" }, h("span", { class: "chip" }, "↑ " + fmtBytes(s.net.tx_total) + " sent"), h("span", { class: "chip" }, "↓ " + fmtBytes(s.net.rx_total) + " received"), h("span", { class: "chip" }, t.tunnels.filter((x) => x.running).length + "/" + t.tunnels.length + " tunnels"))),
        h("div", { class: "bar" }, h("i"))),
      h("div", { class: "sec" }, "INFO"),
      h("div", { class: "info" },
        h("div", {}, h("small", {}, "HOST"), s.host), h("div", {}, h("small", {}, "VERSION"), "v" + s.version),
        h("div", {}, h("small", {}, "OS"), s.os), h("div", {}, h("small", {}, "UPTIME"), fmtUp(s.uptime))));
    const tot = s.net.rx_total + s.net.tx_total; view.querySelector(".bar i").style.width = (tot ? Math.max(2, Math.round(s.net.tx_total / tot * 100)) : 2) + "%";
  };
  await draw();
  startTimer(draw, 4000);
}

function tunnelCard(t, out, refresh) {
  const act = (name, label, extra = "") => h("button", { class: "btn sm " + extra, onclick: async () => {
    if (name === "remove" && !confirm("Remove tunnel " + t.name + " and its services?")) return;
    try { const r = await api("/api/tunnel/" + t.name + "/" + name, "POST"); note(out, r.text, true); } catch (e) { note(out, e.message, false); }
    setTimeout(refresh, 900);
  } }, label);
  const view = (kind, label) => h("button", { class: "btn sm", onclick: async () => {
    try { const r = await api("/api/tunnel/" + t.name + "/" + kind); out.replaceChildren(h("pre", { class: kind === "link" ? "link" : "" }, r.text)); out.scrollIntoView({ behavior: "smooth", block: "nearest" }); } catch (e) { note(out, e.message, false); }
  } }, label);
  const ms = last(t.ping);
  const pingBox = t.ping.length && t.ping.some((v) => v != null)
    ? [h("div", { class: "ping" }, ms == null ? "timeout" : ms, ms == null ? null : h("small", {}, "ms")), spark(t.ping)]
    : [h("div", { class: "ping none" }, "no ping"), spark([])];
  return h("div", { class: "tc " + (t.running ? "on" : "") },
    h("div", { class: "tt" }, h("div", {}, h("b", {}, t.name), h("small", {}, t.remote || (t.role === "foreign" ? "listens on this server" : ""))),
      h("div", { class: "st" }, h("i"), t.running ? "Online" : "Offline")),
    h("div", { class: "tags" }, h("span", { class: "tag hl" }, t.role), h("span", { class: "tag" }, t.type === "spoof" ? "spoof gre" : "tls 1.3"), h("span", { class: "tag" }, t.detail || "—")),
    pingBox,
    h("div", { class: "meta" }, "up " + fmtUp(t.up) + "   ·   ↓ " + fmtBytes(t.rx) + "   ↑ " + fmtBytes(t.tx)),
    h("div", { class: "tfoot" }, h("div", { class: "acts" }, act("start", "Start"), act("stop", "Stop"), act("restart", "Restart"), view("logs", "Logs"), t.has_link ? view("link", "Link") : null), act("remove", "Remove", "r")));
}

async function viewTunnels() {
  const view = document.getElementById("view");
  const out = h("div", {});
  const grid = h("div", { class: "tg" });
  const draw = async () => {
    let data;
    try { data = await api("/api/tunnels"); } catch (e) { note(out, e.message, false); return; }
    tunnelCount = data.tunnels.length;
    grid.replaceChildren(...data.tunnels.map((t) => tunnelCard(t, out, draw)));
    if (!data.tunnels.length) grid.replaceChildren(h("div", { class: "card" }, h("p", { class: "dim" }, "No tunnels yet. Open Manage: create on the foreign server first, then paste the link on Iran.")));
  };
  view.replaceChildren(
    h("div", { class: "th" }, h("h2", {}, "Tunnels"),
      h("div", { class: "row" }, h("button", { class: "btn", onclick: async () => { try { const r = await api("/api/restart-all", "POST"); note(out, r.text, true); } catch (e) { note(out, e.message, false); } setTimeout(draw, 1000); } }, "Restart all"),
        h("button", { class: "btn w", onclick: () => { tab = "manage"; shell(); } }, "Add tunnel"))),
    grid, out);
  await draw();
  startTimer(draw, 5000);
}

async function submitCreate(kind, form, out, button) {
  button.disabled = true;
  out.replaceChildren(h("div", { class: "msg" }, "Working... this can take up to a minute."));
  const body = {};
  for (const el of form.elements) if (el.name) body[el.name] = el.type === "checkbox" ? el.checked : el.value.trim();
  try {
    const r = await api("/api/create/" + kind, "POST", body);
    const kids = [h("div", { class: "msg " + (r.ok ? "ok" : "err") }, r.ok ? "Done." : "Failed. Read the output below.")];
    if (r.link) kids.push(h("p", {}, "Paste this link into the Iran server (Manage tab):"), h("pre", { class: "link" }, r.link));
    kids.push(h("pre", {}, r.text));
    out.replaceChildren(...kids);
  } catch (e) { note(out, e.message, false); }
  button.disabled = false;
}

async function viewManage() {
  const view = document.getElementById("view");
  let d = { ip: "", iface: "" };
  try { d = await api("/api/defaults"); } catch (e) { /* ignore */ }
  const card = (title, kind, fields, help) => {
    const out = h("div", {});
    const form = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" }, fields));
    const btn = h("button", { class: "btn w", onclick: () => submitCreate(kind, form, out, btn) }, "Create");
    return h("div", { class: "card" }, h("h3", {}, title), help ? h("div", { class: "dim" }, help) : null, form, btn, out);
  };
  const pwOut = h("div", {});
  const pwForm = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" }, h("label", {}, "Current password", h("input", { name: "current", type: "password", autocomplete: "current-password" })), h("label", {}, "New password (10+ characters)", h("input", { name: "new", type: "password", autocomplete: "new-password" }))));
  view.replaceChildren(
    h("div", { class: "th" }, h("h2", {}, "Add tunnel")),
    h("p", { class: "dim" }, "Order: 1) create on the FOREIGN server and copy the link, 2) paste it on the IRAN server."),
    card("Quick TLS tunnel · FOREIGN (creates a link)", "quick-foreign", [field("Name", "name", "tun1"), field("This server public IP", "ip", d.ip), field("Tunnel port", "port", "8443"), field("TLS name (SNI, optional)", "sni", "")], "Direct TLS 1.3, no domain. Iran connects to this port."),
    card("Quick TLS tunnel · IRAN (paste the link)", "quick-iran", [field("Link (uutun://...)", "link"), field("Ports to forward", "ports", "443", { placeholder: "443 or 8080=2083, 8443" }),
      select("Fingerprint", "fingerprint", [["1", "Chrome"], ["2", "Firefox"], ["3", "iOS"]]), field("Sessions (2-32)", "sessions", "8"),
      h("label", {}, "Options", h("span", {}, h("input", { type: "checkbox", name: "advanced" }), " use fingerprint/sessions   ", h("input", { type: "checkbox", name: "fragment" }), " TLS fragment"))], "443 maps Iran 443 to foreign 443. 8080=2083 maps Iran 8080 to foreign 2083."),
    card("Quick SPOOF tunnel · FOREIGN (creates a link)", "spoof-foreign", [field("Name", "name", "spoof1"), field("Iran server IP", "iran_ip"), field("This server real IP", "ip", d.ip), field("Interface", "iface", d.iface || "eth0"),
      select("Who forges the source", "forger", [["iran", "Iran forges (recommended)"], ["foreign", "Foreign forges"]]), field("Forged source IP", "spoof_ip", "", { placeholder: "inside a range that passed the Spoof test" }), field("Service port on this server", "target", "8443")], "Run the Spoof test first (Connection test tab). Needs /dev/net/tun, GRE (protocol 47) open and a real IP on the interface."),
    card("Quick SPOOF tunnel · IRAN (paste the link)", "spoof-iran", [field("Link (uutspoof://...)", "link"), field("Interface", "iface", d.iface || "eth0"), field("Port users connect to (1024-65535)", "port", "8443")]),
    h("div", { class: "card" }, h("h3", {}, "Panel password"), pwForm, h("button", { class: "btn", onclick: async () => {
      try { const r = await api("/api/password", "POST", { current: val(pwForm, "current"), new: val(pwForm, "new") }); note(pwOut, r.text, true); setTimeout(() => { csrf = ""; render(); }, 1500); } catch (e) { note(pwOut, e.message, false); }
    } }, "Change password"), pwOut));
}

async function viewTest() {
  const view = document.getElementById("view");
  const lout = h("div", {});
  const tout = h("div", {});
  const refresh = async () => {
    try {
      const s = await api("/api/test/status");
      lout.replaceChildren(s.running ? h("div", {}, h("div", { class: "msg ok" }, "Listener running. Paste this link on the OTHER server (Tester):"), h("pre", { class: "link" }, s.link), h("pre", {}, s.log || "(waiting for packets)")) : h("p", { class: "dim" }, "No listener running."));
    } catch (e) { note(lout, e.message, false); }
  };
  const listenForm = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" },
    select("Test type", "kind", [["conn", "Connection + speed test"], ["spoof", "Spoof test"]]), field("This server public IP", "host", ""), field("Port (1024-65533)", "port", "4500")));
  const lbtn = h("button", { class: "btn w", onclick: async () => {
    try { await api("/api/test/listen", "POST", { kind: val(listenForm, "kind"), host: val(listenForm, "host"), port: val(listenForm, "port") }); refresh(); } catch (e) { note(lout, e.message, false); }
  } }, "Start listener");
  const sbtn = h("button", { class: "btn", onclick: async () => { await api("/api/test/stop", "POST"); refresh(); } }, "Stop listener");
  try { listenForm.elements.host.value = (await api("/api/defaults")).ip; } catch (e) { /* ignore */ }
  const runForm = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" },
    select("Test type", "kind", [["conn", "Connection + speed test"], ["spoof", "Spoof test"]]), field("Link from the listener", "link"),
    select("Spoof mode", "mode", [["scan", "Range scan"], ["one", "One forged IP"]]), field("Forged IP (one IP mode)", "spoof_ip"), field("This server public IP (range scan)", "my_ip"), field("Extra ranges (optional)", "ranges", "", { placeholder: "5.22.0.0/16,185.10.0.0/16" })));
  const rbtn = h("button", { class: "btn w", onclick: async () => {
    rbtn.disabled = true;
    tout.replaceChildren(h("div", { class: "msg" }, "Running... up to 4 minutes."));
    const body = {};
    for (const el of runForm.elements) if (el.name) body[el.name] = el.value.trim();
    try { const r = await api("/api/test/run", "POST", body); tout.replaceChildren(h("pre", {}, r.text)); } catch (e) { note(tout, e.message, false); }
    rbtn.disabled = false;
  } }, "Run test");
  view.replaceChildren(
    h("div", { class: "th" }, h("h2", {}, "Connection test")),
    h("div", { class: "card" }, h("h3", {}, "1) Listener (run on the first server)"), listenForm, h("div", { class: "row" }, lbtn, sbtn), lout),
    h("div", { class: "card" }, h("h3", {}, "2) Tester (run on the second server)"), runForm, rbtn, tout));
  refresh();
}

async function render() {
  stopTimer();
  try { const s = await api("/api/session"); if (s.auth) { csrf = s.csrf; return shell(); } } catch (e) { /* login */ }
  renderLogin();
}
render();
