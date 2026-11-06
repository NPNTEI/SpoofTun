"use strict";
let csrf = "";
const app = document.getElementById("app");

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}

async function api(path, method = "GET", body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method !== "GET") { opts.headers["Content-Type"] = "application/json"; opts.headers["X-CSRF"] = csrf; opts.body = JSON.stringify(body || {}); }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* ignore */ }
  if (res.status === 401 && path !== "/api/login") { csrf = ""; render(); }
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

function field(label, name, value = "", extra = {}) {
  return h("label", {}, label, h("input", { name, value, autocomplete: "off", spellcheck: "false", ...extra }));
}
function select(label, name, options) {
  return h("label", {}, label, h("select", { name }, options.map(([v, t]) => h("option", { value: v }, t))));
}
function val(form, name) { const el = form.elements[name]; return el ? el.value.trim() : ""; }

function note(box, text, ok) {
  box.replaceChildren(h("div", { class: "msg " + (ok ? "ok" : "err") }, text));
}

async function login() {
  const pw = document.getElementById("pw").value;
  const box = document.getElementById("lmsg");
  try { const r = await api("/api/login", "POST", { password: pw }); csrf = r.csrf; render(); }
  catch (e) { note(box, e.message, false); }
}

function renderLogin() {
  app.replaceChildren(h("div", { class: "login" },
    h("div", { class: "card" },
      h("h3", {}, "UnUnknownTun Panel"),
      h("div", { id: "lmsg" }),
      h("label", {}, "Password", h("input", { id: "pw", type: "password", autocomplete: "current-password", onkeydown: (e) => { if (e.key === "Enter") login(); } })),
      h("div", { class: "row mt" }, h("button", { class: "btn red", onclick: login }, "Sign in")),
      h("p", { class: "dim" }, "The password was shown once during installation. Reset: ununknowntun panel-password"))));
}

let tab = "tunnels";
function renderShell() {
  const tabs = [["tunnels", "Tunnels"], ["create", "Create"], ["tests", "Tests"]];
  app.replaceChildren(
    h("header", {}, h("b", {}, "UNUNKNOWNTUN"), h("button", { class: "btn sm", onclick: async () => { await api("/api/logout", "POST"); csrf = ""; render(); } }, "Log out")),
    h("nav", {}, tabs.map(([id, t]) => h("button", { class: tab === id ? "on" : "", onclick: () => { tab = id; renderShell(); } }, t))),
    h("main", { id: "main" }));
  ({ tunnels: viewTunnels, create: viewCreate, tests: viewTests })[tab]();
}

async function viewTunnels() {
  const main = document.getElementById("main");
  const out = h("div", { id: "out" });
  const list = h("div", { class: "card" }, h("h3", {}, "Quick tunnels"));
  main.replaceChildren(list, out);
  let data;
  try { data = await api("/api/tunnels"); } catch (e) { list.append(h("div", { class: "msg err" }, e.message)); return; }
  if (!data.tunnels.length) list.append(h("p", { class: "dim" }, "No tunnels yet. Use the Create tab: foreign first, then Iran."));
  for (const t of data.tunnels) {
    const act = (name, label, extra = "") => h("button", { class: "btn sm " + extra, onclick: async () => {
      if (name === "remove" && !confirm("Remove tunnel " + t.name + " and its services?")) return;
      try { const r = await api("/api/tunnel/" + t.name + "/" + name, "POST"); note(out, r.text, true); } catch (e) { note(out, e.message, false); }
      if (["remove", "start", "stop", "restart"].includes(name)) setTimeout(viewTunnels, 800);
    } }, label);
    const view = (kind, label) => h("button", { class: "btn sm", onclick: async () => {
      try { const r = await api("/api/tunnel/" + t.name + "/" + kind); out.replaceChildren(h("pre", { class: kind === "link" ? "link" : "" }, r.text)); } catch (e) { note(out, e.message, false); }
    } }, label);
    list.append(h("div", { class: "t" },
      h("div", {}, h("span", { class: "dot " + (t.running ? "on" : "") }), h("b", {}, t.name), h("span", { class: "tag" }, t.role), h("span", { class: "tag" }, t.type), h("span", { class: "dim ml" }, t.detail)),
      h("div", { class: "row flush" }, act("start", "Start"), act("stop", "Stop"), act("restart", "Restart"), view("logs", "Logs"), t.has_link ? view("link", "Link") : null, act("remove", "Remove", "red"))));
  }
}

async function submitCreate(kind, form, out, button) {
  button.disabled = true;
  out.replaceChildren(h("div", { class: "msg" }, "Working... this can take up to a minute."));
  const body = {};
  for (const el of form.elements) if (el.name) body[el.name] = el.type === "checkbox" ? el.checked : el.value.trim();
  try {
    const r = await api("/api/create/" + kind, "POST", body);
    const kids = [h("div", { class: "msg " + (r.ok ? "ok" : "err") }, r.ok ? "Done." : "Failed. Read the output below.")];
    if (r.link) kids.push(h("p", {}, "Paste this link into the Iran server (Create tab):"), h("pre", { class: "link" }, r.link));
    kids.push(h("pre", {}, r.text));
    out.replaceChildren(...kids);
  } catch (e) { note(out, e.message, false); }
  button.disabled = false;
}

async function viewCreate() {
  const main = document.getElementById("main");
  let d = { ip: "", iface: "" };
  try { d = await api("/api/defaults"); } catch (e) { /* ignore */ }
  const card = (title, kind, fields, help) => {
    const out = h("div", {});
    const form = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" }, fields));
    const btn = h("button", { class: "btn red", onclick: () => submitCreate(kind, form, out, btn) }, "Create");
    return h("div", { class: "card" }, h("h3", {}, title), help ? h("p", { class: "dim" }, help) : null, form, btn, out);
  };
  main.replaceChildren(
    h("p", { class: "dim" }, "Order: 1) create on the FOREIGN server and copy the link, 2) paste it on the IRAN server."),
    card("Quick TLS tunnel: FOREIGN (creates a link)", "quick-foreign", [field("Name", "name", "tun1"), field("This server public IP", "ip", d.ip), field("Tunnel port", "port", "8443"), field("TLS name (SNI, optional)", "sni", "")],
      "Direct TLS 1.3, no domain. Iran connects to this port."),
    card("Quick TLS tunnel: IRAN (paste the link)", "quick-iran", [field("Link (uutun://...)", "link"), field("Ports to forward", "ports", "443", { placeholder: "443 or 8080=2083, 8443" }),
      select("Fingerprint", "fingerprint", [["1", "Chrome"], ["2", "Firefox"], ["3", "iOS"]]), field("Sessions (2-32)", "sessions", "8"),
      h("label", {}, "Options", h("span", {}, h("input", { type: "checkbox", name: "advanced" }), " use fingerprint/sessions above  ", h("input", { type: "checkbox", name: "fragment" }), " TLS fragment"))],
      "Ports: 443 maps Iran 443 to foreign 443. 8080=2083 maps Iran 8080 to foreign 2083."),
    card("Quick SPOOF tunnel: FOREIGN (creates a link)", "spoof-foreign", [field("Name", "name", "spoof1"), field("Iran server IP", "iran_ip"), field("This server real IP", "ip", d.ip), field("Interface", "iface", d.iface || "eth0"),
      select("Who forges the source", "forger", [["iran", "Iran forges (recommended)"], ["foreign", "Foreign forges"]]), field("Forged source IP", "spoof_ip", "", { placeholder: "inside a range that passed the Spoof test" }), field("Service port on this server", "target", "8443")],
      "Run the Spoof test first (Tests tab). Needs /dev/net/tun, GRE (protocol 47) open and a real IP on the interface."),
    card("Quick SPOOF tunnel: IRAN (paste the link)", "spoof-iran", [field("Link (uutspoof://...)", "link"), field("Interface", "iface", d.iface || "eth0"), field("Port users connect to (1024-65535)", "port", "8443")]));
}

async function viewTests() {
  const main = document.getElementById("main");
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
  const lbtn = h("button", { class: "btn red", onclick: async () => {
    try { await api("/api/test/listen", "POST", { kind: val(listenForm, "kind"), host: val(listenForm, "host"), port: val(listenForm, "port") }); refresh(); } catch (e) { note(lout, e.message, false); }
  } }, "Start listener");
  const sbtn = h("button", { class: "btn", onclick: async () => { await api("/api/test/stop", "POST"); refresh(); } }, "Stop listener");
  try { listenForm.elements.host.value = (await api("/api/defaults")).ip; } catch (e) { /* ignore */ }
  const runForm = h("form", { onsubmit: (e) => e.preventDefault() }, h("div", { class: "row" },
    select("Test type", "kind", [["conn", "Connection + speed test"], ["spoof", "Spoof test"]]), field("Link from the listener", "link"),
    select("Spoof mode", "mode", [["scan", "Range scan"], ["one", "One forged IP"]]), field("Forged IP (one IP mode)", "spoof_ip"), field("This server public IP (range scan)", "my_ip"), field("Extra ranges (optional)", "ranges", "", { placeholder: "5.22.0.0/16,185.10.0.0/16" })));
  const rbtn = h("button", { class: "btn red", onclick: async () => {
    rbtn.disabled = true;
    tout.replaceChildren(h("div", { class: "msg" }, "Running... up to 4 minutes."));
    const body = {};
    for (const el of runForm.elements) if (el.name) body[el.name] = el.value.trim();
    try { const r = await api("/api/test/run", "POST", body); tout.replaceChildren(h("pre", {}, r.text)); } catch (e) { note(tout, e.message, false); }
    rbtn.disabled = false;
  } }, "Run test");
  main.replaceChildren(
    h("div", { class: "card" }, h("h3", {}, "1) Listener (run on the first server)"), listenForm, h("div", { class: "row mt" }, lbtn, sbtn), lout),
    h("div", { class: "card" }, h("h3", {}, "2) Tester (run on the second server)"), runForm, rbtn, tout));
  refresh();
}

async function render() {
  try { const s = await api("/api/session"); if (s.auth) { csrf = s.csrf; return renderShell(); } } catch (e) { /* login */ }
  renderLogin();
}
render();
