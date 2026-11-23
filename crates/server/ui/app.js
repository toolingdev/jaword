// jaword web UI. No frameworks and no inline script. Every piece of server
// data reaches the page as a text node, never parsed as markup, so a stored
// value cannot turn into HTML or script. The access token lives in
// sessionStorage (gone when the tab closes).
"use strict";

const REVEAL_SECONDS = 30;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const STALE_DAYS = 90;          // red: overdue for a change
const AGING_DAYS = 30;          // amber: getting old
const state = { token: null, me: null, view: "secrets", secrets: [], folders: [], folder: "", selected: null, sort: "name", onlyStale: false };
const root = document.getElementById("app");

try { state.token = sessionStorage.getItem("jaword.token"); } catch (_) { /* storage blocked */ }

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

// Icons are drawn here as SVG elements (never parsed from strings).
const SVGNS = "http://www.w3.org/2000/svg";
const EYE = "M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12Z";
const ICONS = {
  eyeOpen: [["path", { d: EYE }], ["circle", { cx: 12, cy: 12, r: 3 }]],
  eyeClosed: [["path", { d: "M3 10c2.4 3.4 5.4 5 9 5s6.6-1.6 9-5" }], ["path", { d: "M12 15v3M7.6 14.2l-1.4 2.6M16.4 14.2l1.4 2.6M4.4 11.6 2.8 13.2M19.6 11.6l1.6 1.6" }]],
  copy: [["rect", { x: 9, y: 9, width: 11, height: 11, rx: 2 }], ["path", { d: "M5 15V6a2 2 0 0 1 2-2h9" }]],
  check: [["path", { d: "M5 12.5l4.5 4.5L19 7.5" }]],
  again: [["path", { d: "M20 12a8 8 0 1 1-2.6-5.9" }], ["path", { d: "M20 3.5V9h-5.5" }]],
};
function icon(name) {
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24"); svg.setAttribute("class", "icon"); svg.setAttribute("aria-hidden", "true");
  for (const [tag, attrs] of ICONS[name]) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.append(el);
  }
  return svg;
}
// A button that is only an icon still needs a name for screen readers and a tooltip.
function iconButton(name, label, onclick) {
  const b = h("button", { class: "iconbtn", type: "button", title: label, "aria-label": label, onclick }, icon(name));
  b.setIcon = (n, l) => { b.replaceChildren(icon(n)); if (l) { b.title = l; b.setAttribute("aria-label", l); } };
  return b;
}
// Copy with a brief check mark in place of the icon.
async function copyWith(button, getText, okMsg) {
  try {
    await navigator.clipboard.writeText(await getText());
    button.setIcon("check"); button.classList.add("done");
    setTimeout(() => { button.setIcon("copy"); button.classList.remove("done"); }, 1400);
    if (okMsg) toast(okMsg);
    return true;
  } catch (e) { if (e && e.status) throw e; toast("Copy failed, select it by hand", true); return false; }
}

let toastTimer;
function toast(msg, bad) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (bad ? " bad" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ""; }, bad ? 5000 : 2200);
}

async function api(method, path, body) {
  const headers = {};
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: "no-store", credentials: "omit", redirect: "error" });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) {
    const err = new Error((data && data.message) || "HTTP " + res.status);
    err.status = res.status;
    err.code = data && data.error;
    throw err;
  }
  return data;
}

const p2 = (n) => String(n).padStart(2, "0");
function fmt(ts) {
  if (!ts) return "never";
  const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function short(ts) { const d = new Date(ts * 1000); return `${MONTHS[d.getMonth()]} ${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`; }
const daysSince = (ts) => Math.max(0, Math.floor((Date.now() / 1000 - ts) / 86400));
const ageText = (days) => (days === 0 ? "today" : days === 1 ? "1 day" : days + " days");
const ageGrade = (days) => (days > STALE_DAYS ? "red" : days >= AGING_DAYS ? "amber" : "green");
// Only things that are meant to be changed regularly have an age worth showing.
const rotates = (s) => ["password", "api_key", "ssh_key"].includes(s.kind);
const lamp = (colour) => h("span", { class: "lamp " + (colour || ""), "aria-hidden": "true" });
const who = (actor) => (actor || "").split(":")[0] || "unknown";

// Folders are path prefixes. People see "Personal / Banks"; agents and access
// rules keep using the stable address personal/banks/chase.
const pretty = (seg) => { const t = seg.replace(/[-_]+/g, " "); return t.charAt(0).toUpperCase() + t.slice(1); };
const folderOf = (p) => { const i = p.lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i); };
const leafOf = (p) => p.slice(p.lastIndexOf("/") + 1);
const folderLabel = (p) => (p ? p.split("/").map(pretty).join(" / ") : "Vault");
const slug = (t) => t.toLowerCase().normalize("NFKD").replace(/[^a-z0-9._-]+/g, "-").replace(/\.{2,}/g, ".").replace(/^[^a-z0-9]+|[-.]+$/g, "").slice(0, 60);
const itemName = (s) => s.meta.title || pretty(leafOf(s.path));

function logout() {
  state.token = null; state.me = null; state.selected = null; state.secrets = [];
  try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ }
  boot();
}

let idleTimer;
function armIdle() {
  clearTimeout(idleTimer);
  if (state.token) idleTimer = setTimeout(() => { toast("Signed out after 10 minutes without activity"); logout(); }, IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((e) => document.addEventListener(e, armIdle, { passive: true }));

function dialog(cls, ...kids) {
  const dlg = h("dialog", { class: cls || null }, ...kids);
  document.body.append(dlg);
  dlg.addEventListener("close", () => dlg.remove());
  return dlg;
}

// ------------------------------------------------------------------ gates
// A ring of approach lights: red while sealed, blue when ready for a token,
// and they run green one after another when the vault opens.

function ring(mode) {
  const el = h("div", { class: "ring " + mode, "aria-hidden": "true" });
  for (let i = 0; i < 24; i++) {
    const dot = h("i", {});
    dot.style.transform = `rotate(${i * 15}deg) translateY(-62px)`;
    dot.style.transitionDelay = i * 22 + "ms";
    el.append(dot);
  }
  return el;
}

function gate(mode, title, text, ...body) {
  root.replaceChildren(h("div", { class: "gate" }, h("div", { class: "card" }, ring(mode), h("h1", {}, title), h("p", {}, text), ...body)));
}

function gateForm(label, placeholder, button, onSubmit) {
  const input = h("input", { type: "password", autocomplete: "off", spellcheck: "false", placeholder, required: true });
  const err = h("div", { class: "error" });
  const btn = h("button", { class: "btn primary", type: "submit" }, button);
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault();
    btn.disabled = true; err.textContent = "";
    try { await onSubmit(input.value); } catch (ex) { err.textContent = ex.message; btn.disabled = false; input.select(); }
  } }, h("label", {}, label), input, err, h("div", { class: "row" }, btn));
  setTimeout(() => input.focus(), 0);
  return form;
}

function runGreen(then) {
  const r = document.querySelector(".ring");
  if (r) r.className = "ring open";
  setTimeout(then, matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 760);
}

async function boot() {
  let st;
  try { st = await api("GET", "/v1/sys/status"); }
  catch (e) { return gate("sealed", "Vault unreachable", e.message, h("button", { class: "btn", onclick: boot }, "Try again")); }
  if (!st.initialized) {
    return gate("sealed", "Not set up yet", "Create the vault from a terminal on its host, so the recovery key never passes through a browser.",
      h("p", {}, h("code", {}, "jaword init")), h("button", { class: "btn", onclick: boot }, "Check again"));
  }
  if (st.sealed) {
    return gate("sealed", "Sealed", "Nothing can be read until the passphrase or recovery key is entered.",
      gateForm("Passphrase", "", "Unseal", async (v) => { await api("POST", "/v1/sys/unseal", { credential: v }); runGreen(boot); }));
  }
  if (state.token) {
    try { state.me = await api("GET", "/v1/whoami"); armIdle(); return shell(); }
    catch (e) { state.token = null; try { sessionStorage.removeItem("jaword.token"); } catch (_) { /* ignore */ } }
  }
  gate("ready", "jaword", "Paste your access token. It stays in this tab and is gone when you close it.",
    gateForm("Access token", "jw_…", "Open vault", async (v) => {
      state.token = v.trim();
      try { state.me = await api("GET", "/v1/whoami"); }
      catch (e) { state.token = null; throw e; }
      try { sessionStorage.setItem("jaword.token", state.token); } catch (_) { /* ignore */ }
      armIdle(); runGreen(shell);
    }));
}

// ------------------------------------------------------------------ shell

const isAdmin = () => state.me && state.me.role === "admin";
const MAC = /Mac|iPhone|iPad/.test(navigator.platform);

function shell() {
  const views = [["secrets", "Vault"]];
  if (isAdmin()) views.push(["tokens", "Tokens"], ["audit", "Audit log"], ["updates", "Updates"]);
  const main = h("main", { class: "main" });
  root.replaceChildren(
    h("header", { class: "bar" },
      h("div", { class: "brand" }, "jaword"),
      h("nav", { class: "tabs", "aria-label": "Sections" }, views.map(([id, label]) => h("button", { class: "tab" + (state.view === id ? " on" : ""), onclick: () => go(id) }, label))),
      h("button", { class: "cmd", onclick: palette, "aria-label": "Find an item or run a command" }, h("span", { class: "grow" }, "Find an item or run a command"), h("kbd", {}, MAC ? "⌘K" : "Ctrl K")),
      h("div", { class: "who" },
        h("span", { class: "state" }, lamp("green"), h("span", {}, "Unsealed")),
        h("span", { class: "name", title: state.me.role }, state.me.name),
        h("button", { class: "link", onclick: logout }, "Sign out"),
        isAdmin() && h("button", { class: "link danger", onclick: sealVault }, "Seal"))),
    main);
  ({ secrets: viewSecrets, tokens: viewTokens, audit: viewAudit, updates: viewUpdates })[state.view](main);
}
function go(view) { state.view = view; shell(); }

async function sealVault() {
  if (!confirm("Seal the vault? Nothing can be read or rotated until someone enters the passphrase again.")) return;
  try { await api("POST", "/v1/sys/seal", {}); logout(); } catch (e) { toast(e.message, true); }
}

function fail(e) {
  if (e.status === 401) { toast("Signed out", true); return logout(); }
  if (e.code === "sealed") return boot();
  toast(e.message, true);
}

// ---------------------------------------------------------- command palette

let vaultReload = null;   // set by the vault view so commands can refresh it

function palette() {
  if (!state.me || document.querySelector("dialog.palette")) return;
  const commands = [
    ["New item", () => secretDialog(null, vaultReload || (() => go("secrets")))],
    ["New payment card", () => cardDialog("card", null, vaultReload || (() => go("secrets")))],
    ["New gift card", () => cardDialog("gift_card", null, vaultReload || (() => go("secrets")))],
    ["New person or address", () => personDialog(null, vaultReload || (() => go("secrets")))],
    ["New folder", () => folderDialog(null, vaultReload || (() => go("secrets")))],
    ["Import from another password manager", () => importDialog(vaultReload || (() => go("secrets")))],
    ["Show passwords overdue for a change", () => { state.onlyStale = true; state.folder = ""; go("secrets"); }],
    ["Go to Vault", () => go("secrets")],
  ];
  if (isAdmin()) commands.push(["Go to Tokens", () => go("tokens")], ["Go to Audit log", () => go("audit")], ["Go to Updates", () => go("updates")], ["Seal the vault", sealVault]);
  commands.push(["Sign out", logout]);
  const input = h("input", { type: "text", placeholder: "Find an item or run a command", autocomplete: "off", spellcheck: "false", "aria-label": "Find an item or run a command" });
  const list = h("ul", { role: "listbox" });
  let rows = [], at = 0;
  const pick = (i) => { const r = rows[i]; if (!r) return; dlg.close(); r.run(); };
  function draw() {
    const q = input.value.trim().toLowerCase();
    const items = state.secrets.filter((s) => !q || itemName(s).toLowerCase().includes(q) || s.path.includes(q) || s.meta.url.toLowerCase().includes(q) || s.meta.username.toLowerCase().includes(q) || s.meta.tags.some((t) => t.toLowerCase().includes(q)))
      .slice(0, 8).map((s) => ({ label: itemName(s), side: [isPerson(s) ? personSummary(s) : isCardish(s) ? cardSummary(s) : s.meta.username, folderLabel(folderOf(s.path))].filter(Boolean).join("   "), run: () => { state.selected = s.path; state.folder = ""; state.onlyStale = false; go("secrets"); } }));
    const cmds = commands.filter(([l]) => !q || l.toLowerCase().includes(q)).map(([label, run]) => ({ label, run, cmd: true }));
    rows = q ? [...items, ...cmds] : [...cmds, ...items];
    at = Math.min(at, Math.max(0, rows.length - 1));
    if (!rows.length) return list.replaceChildren(h("li", { class: "none" }, "Nothing matches."));
    list.replaceChildren(...rows.map((r, i) => h("li", { class: (i === at ? "on " : "") + (r.cmd ? "cmdrow" : ""), role: "option", "aria-selected": i === at ? "true" : "false", onclick: () => pick(i), onpointermove: () => { if (at !== i) { at = i; draw(); } } },
      h("span", { class: "grow" }, r.label), r.side && h("small", {}, r.side))));
    const on = list.querySelector(".on"); if (on) on.scrollIntoView({ block: "nearest" });
  }
  input.addEventListener("input", () => { at = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); at = Math.min(rows.length - 1, at + 1); draw(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); at = Math.max(0, at - 1); draw(); }
    else if (e.key === "Enter") { e.preventDefault(); pick(at); }
  });
  const dlg = dialog("palette", input, list);
  dlg.addEventListener("click", (e) => { if (e.target === dlg) dlg.close(); });
  draw();
  dlg.showModal();
}
document.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette(); }
});

// ------------------------------------------------------------------ vault

// A folder dropdown that can also make a new folder on the spot. The top
// level is called the Vault; folders are created inside it.
const NEW_FOLDER = "\u0000new";
function folderPicker(selected, opts) {
  const o = opts || {};
  const list = (state.folders || []).filter((f) => !o.exclude || (f.path !== o.exclude && !f.path.startsWith(o.exclude + "/")));
  const sel = h("select", { "aria-label": o.label || "Folder" },
    (o.extra || []).map(([v, l]) => h("option", { value: v, selected: v === selected }, l)),
    !o.noRoot && h("option", { value: "", selected: selected === "" }, "Vault (no folder)"),
    list.map((f) => h("option", { value: f.path, selected: f.path === selected }, "  ".repeat(f.path.split("/").length - 1) + pretty(leafOf(f.path)))),
    h("option", { value: NEW_FOLDER }, "+ New folder…"),
    (o.tail || []).map(([v, l]) => h("option", { value: v }, l)));
  const name = h("input", { type: "text", placeholder: "Name of the new folder", autocomplete: "off", hidden: true, "aria-label": "Name of the new folder" });
  name.style.marginTop = "8px";
  sel.addEventListener("change", () => { name.hidden = sel.value !== NEW_FOLDER; if (!name.hidden) name.focus(); });
  return {
    el: h("div", {}, sel, name),
    raw: () => sel.value,
    isNew: () => sel.value === NEW_FOLDER,
    valid: () => sel.value !== NEW_FOLDER || !!slug(name.value),
    value: () => (sel.value === NEW_FOLDER ? slug(name.value) : sel.value),
    // Make sure a newly named folder exists, then return its path.
    async ensure() {
      if (sel.value !== NEW_FOLDER) return sel.value;
      const p = slug(name.value);
      if (!p) throw new Error("Give the new folder a name.");
      await api("POST", "/v1/folders/create", { path: p });
      return p;
    },
  };
}

function ageCell(s) {
  if (isCardish(s)) return gaugeCell(s);
  if (!rotates(s)) return h("span", { class: "hint" }, "—");
  const days = daysSince(s.changed_at);
  const lit = Math.max(1, Math.ceil((Math.min(days, STALE_DAYS) / STALE_DAYS) * 8));
  const grade = ageGrade(days);
  return h("div", { class: "age " + grade, title: "Last changed " + fmt(s.changed_at) },
    h("span", { class: "lights", "aria-hidden": "true" }, Array.from({ length: 8 }, (_, i) => h("i", { class: i < lit ? "lit" : null }))),
    h("span", {}, ageText(days)));
}

async function viewSecrets(main) {
  const noticeEl = h("div", {});
  const treeEl = h("nav", { class: "tree", "aria-label": "Folders" });
  const tableEl = h("div", {});
  const detailEl = h("div", {});
  main.replaceChildren(noticeEl,
    h("div", { class: "deck" },
      h("div", { class: "folders" }, h("div", { class: "cap" }, "Folders"), treeEl),
      h("div", {}, tableEl),
      detailEl));

  const pick = (f) => { state.folder = f; state.onlyStale = false; render(); };
  const stale = () => state.secrets.filter((s) => rotates(s) && daysSince(s.changed_at) > STALE_DAYS);

  function renderNotice() {
    const old = stale();
    if (!old.length) return noticeEl.replaceChildren();
    const auto = old.filter((s) => s.has_driver);
    const names = old.slice(0, 3).map(itemName).join(", ") + (old.length > 3 ? ` and ${old.length - 3} more` : "");
    noticeEl.replaceChildren(h("div", { class: "notice", role: "status" }, lamp("red"),
      h("span", {}, `${old.length} ${old.length === 1 ? "password has" : "passwords have"} not changed in over ${STALE_DAYS} days.`),
      h("span", { class: "names grow" }, names),
      h("button", { class: "btn small", onclick: () => { state.onlyStale = !state.onlyStale; state.folder = ""; render(); } }, state.onlyStale ? "Show everything" : old.length === 1 ? "Show it" : "Show them"),
      auto.length > 0 && h("button", { class: "btn small danger outline", onclick: () => rotateMany(auto) }, auto.length === old.length ? (auto.length === 1 ? "Rotate it" : auto.length === 2 ? "Rotate both" : `Rotate all ${auto.length}`) : `Rotate the ${auto.length} that can`)));
  }

  async function rotateMany(list) {
    if (!confirm(`Rotate ${list.length} ${list.length === 1 ? "password" : "passwords"} on ${list.length === 1 ? "its" : "their"} live ${list.length === 1 ? "system" : "systems"} now?\n\n${list.map(itemName).join("\n")}`)) return;
    let ok = 0; const bad = [];
    for (const s of list) {
      toast(`Rotating ${itemName(s)}…`);
      try { const r = await api("POST", "/v1/secrets/rotate", { path: s.path }); if (r.rotated) ok++; else bad.push(itemName(s)); }
      catch (e) { if (e.status === 401) return fail(e); bad.push(itemName(s)); }
    }
    toast(bad.length ? `Rotated ${ok}. Failed, old password kept: ${bad.join(", ")}` : `Rotated ${ok}`, bad.length > 0);
    reload();
  }

  function renderTree() {
    const all = h("div", { class: "foldrow" }, h("button", { class: "fold" + (!state.folder ? " on" : ""), onclick: () => pick("") }, h("span", { class: "grow" }, "All items"), h("span", { class: "cnt" }, state.secrets.length)));
    const rows = state.folders.map((f) => {
      const b = h("button", { class: "fold" + (state.folder === f.path ? " on" : ""), onclick: () => pick(f.path), title: f.path },
        h("span", { class: "grow" }, pretty(leafOf(f.path))), h("span", { class: "cnt" }, f.count));
      b.style.paddingLeft = 10 + (f.path.split("/").length - 1) * 14 + "px";
      return h("div", { class: "foldrow" }, b,
        h("button", { class: "more", title: "Rename, move or delete", "aria-label": "Options for folder " + folderLabel(f.path), onclick: () => folderDialog(f, reload) }, "⋯"));
    });
    treeEl.replaceChildren(all, ...rows, h("button", { class: "link", onclick: () => folderDialog(null, reload) }, "+  New folder"));
  }

  function renderTable() {
    let rows = state.secrets.filter((s) => (!state.folder || s.path.startsWith(state.folder + "/")) && (!state.onlyStale || (rotates(s) && daysSince(s.changed_at) > STALE_DAYS)));
    if (state.sort === "age") rows = [...rows].sort((a, b) => (rotates(b) ? daysSince(b.changed_at) : -1) - (rotates(a) ? daysSince(a.changed_at) : -1));
    else rows = [...rows].sort((a, b) => itemName(a).localeCompare(itemName(b)));
    const sorter = (key, label) => h("button", { class: state.sort === key ? "on" : null, title: "Sort by " + label.toLowerCase(), onclick: () => { state.sort = key; renderTable(); } }, label);
    const newBtn = h("button", { class: "btn primary small", onclick: () => secretDialog(null, reload) }, "New item");
    const title = h("div", { class: "tablehead" }, h("div", { class: "cap grow" }, state.onlyStale ? "Overdue for a change" : state.folder ? folderLabel(state.folder) : "All items"),
      h("button", { class: "btn small", onclick: () => importDialog(reload) }, "Import"), newBtn);
    title.style.marginBottom = "6px";
    if (!rows.length) {
      if (state.secrets.length) return tableEl.replaceChildren(title, h("div", { class: "empty" }, state.onlyStale ? "Nothing is overdue." : "This folder is empty."));
      const starter = (n) => h("button", { class: "btn small", onclick: async () => { try { await api("POST", "/v1/folders/create", { path: slug(n) }); reload(); } catch (e) { fail(e); } } }, n);
      const have = new Set(state.folders.map((f) => f.path));
      const ideas = ["Personal", "Work", "Family"].filter((n) => !have.has(slug(n)));
      return tableEl.replaceChildren(title, h("div", { class: "empty" },
        h("p", {}, "The vault is empty. Add an item, or use Import to bring everything over from another password manager."),
        ideas.length > 0 && h("div", { class: "row" }, h("span", {}, "Start with a folder:"), ideas.map(starter), h("button", { class: "link", onclick: () => folderDialog(null, reload) }, "or name your own"))));
    }
    tableEl.replaceChildren(title, h("table", { class: "grid" },
      h("thead", {}, h("tr", {}, h("th", {}, sorter("name", "Name")), h("th", { class: "us" }, "Account"), h("th", {}, sorter("age", "Last changed")), h("th", {}, "Rotation"), h("th", { class: "ver" }, "Ver"))),
      h("tbody", {}, rows.map((s) => h("tr", { class: state.selected === s.path ? "on" : null, tabindex: "0",
        onclick: () => { state.selected = s.path; renderTable(); renderDetail(); },
        onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); state.selected = s.path; renderTable(); renderDetail(); } } },
        h("td", { class: "nm" }, itemName(s), !state.folder && folderOf(s.path) && h("small", {}, folderLabel(folderOf(s.path)))),
        h("td", { class: "us" }, isPerson(s) ? personSummary(s) : isCardish(s) ? cardSummary(s) : s.meta.username),
        h("td", {}, ageCell(s)),
        h("td", { class: "rot" + (s.has_driver ? " auto" : "") }, s.pending_rotation ? "Pending" : s.has_driver ? (s.rotate_every_days ? every(s.rotate_every_days).replace(/^e/, "E") : "On request") : rotates(s) ? "By hand" : "—"),
        h("td", { class: "ver" }, s.current_version))))));
  }

  async function renderDetail() {
    if (!state.selected) return detailEl.replaceChildren(h("div", { class: "insp empty" }, "Select an item to see it."));
    let d;
    try { d = await api("GET", "/v1/secrets/get?path=" + encodeURIComponent(state.selected)); }
    catch (e) { state.selected = null; return fail(e); }
    detailEl.replaceChildren(isPerson(d) ? personPanel(d, reload) : isCardish(d) ? cardPanel(d, reload) : secretPanel(d, reload));
  }

  function render() { renderNotice(); renderTree(); renderTable(); }
  async function reload() {
    try { [state.secrets, state.folders] = await Promise.all([api("GET", "/v1/secrets"), api("GET", "/v1/folders")]); } catch (e) { return fail(e); }
    if (state.selected && !state.secrets.some((s) => s.path === state.selected)) state.selected = null;
    if (state.folder && !state.folders.some((f) => f.path === state.folder)) state.folder = "";
    render(); renderDetail();
  }
  vaultReload = reload;
  reload();
}

// Digits in amber, symbols in blue: easier to read back and to compare.
function paint(el, value) {
  el.replaceChildren(...[...value].map((c) => h("span", { class: /[0-9]/.test(c) ? "c-d" : /[A-Za-z]/.test(c) ? null : "c-s" }, c)));
}

function secretPanel(d, reload) {
  const MASK = "••••••••••••••••••••";
  const val = h("div", { class: "val" }, MASK);
  const note = h("div", { class: "hint under" });
  let shown = false, hideTimer, tick;
  const eye = iconButton("eyeClosed", "Show password", () => (shown ? hide() : reveal()));
  const copyBtn = iconButton("copy", "Copy password", copy);
  const plate = h("div", { class: "plate" }, val, h("div", { class: "tools" }, eye, copyBtn));
  function hide() { clearTimeout(hideTimer); clearInterval(tick); shown = false; val.textContent = MASK; plate.className = "plate"; note.textContent = ""; eye.setIcon("eyeClosed", "Show password"); }
  async function fetchValue(version) { return (await api("POST", "/v1/secrets/reveal", { path: d.path, version: version || null })).value; }
  async function reveal(version) {
    try {
      const v = await fetchValue(version);
      paint(val, v); shown = true; plate.className = "plate shown"; eye.setIcon("eyeOpen", "Hide password");
      let left = REVEAL_SECONDS;
      const label = version ? `v${version}, hides in ` : "Hides in ";
      note.textContent = `${label}${left}s`;
      clearTimeout(hideTimer); clearInterval(tick);
      tick = setInterval(() => { left -= 1; note.textContent = `${label}${left}s`; }, 1000);
      hideTimer = setTimeout(hide, REVEAL_SECONDS * 1000);
    } catch (e) { fail(e); }
  }
  async function copy() {
    try {
      let v;
      if (await copyWith(copyBtn, async () => (v = await fetchValue()), "Copied. Clipboard clears in 30 seconds")) {
        setTimeout(async () => { try { if (await navigator.clipboard.readText() === v) await navigator.clipboard.writeText(""); } catch (_) { /* tab not focused */ } }, 30000);
      }
    } catch (e) { fail(e); }
  }
  async function act(path, body, okMsg) {
    try {
      const r = await api("POST", path, body);
      if (r && r.rotated === false) toast("Rotation failed, old password kept: " + r.error, true); else toast(okMsg);
      reload();
    } catch (e) { fail(e); }
  }
  const m = d.meta;
  const days = daysSince(d.changed_at);
  const grade = rotates(d) ? ageGrade(days) : "green";
  const statusText = d.pending_rotation ? "Rotation pending" : grade === "red" ? "Overdue, v" + d.current_version : "Current, v" + d.current_version;
  const drv = d.driver ? rotationSummary(d.driver) : d.has_driver ? (d.rotate_every_days ? every(d.rotate_every_days).replace(/^e/, "E") : "On request") : "By hand";
  return h("div", { class: "insp" },
    h("div", { class: "top" },
      h("div", { class: "grow" }, h("h3", {}, m.title || pretty(leafOf(d.path))), h("div", { class: "where" }, folderLabel(folderOf(d.path)))),
      h("div", { class: "status" }, lamp(d.pending_rotation ? "amber" : grade), statusText)),
    plate, note,
    h("dl", { class: "kv" },
      m.username && h("dt", {}, "Username"), m.username && h("dd", {}, m.username),
      m.url && h("dt", {}, "Website"), m.url && h("dd", {}, /^https?:\/\//i.test(m.url) ? h("a", { href: m.url, target: "_blank", rel: "noopener noreferrer" }, m.url.replace(/^https?:\/\//i, "")) : m.url),
      m.tags.length > 0 && h("dt", {}, "Tags"), m.tags.length > 0 && h("dd", {}, m.tags.map((t) => h("span", { class: "chiplet" }, t))),
      m.notes && h("dt", {}, "Notes"), m.notes && h("dd", {}, m.notes),
      h("dt", {}, "Changed"), h("dd", {}, `${days === 0 ? "Today" : ageText(days) + " ago"}, by ${who(d.changed_by)}`),
      h("dt", {}, "Address"), h("dd", { class: "mono", title: "What agents and access rules use to refer to this item" }, d.path),
      rotates(d) && h("dt", {}, "Rotation"), rotates(d) && h("dd", {}, drv)),
    h("div", { class: "row" },
      d.has_driver && h("button", { class: "btn go", onclick: () => confirm(`Rotate ${itemName(d)} on the live system now?`) && act("/v1/secrets/rotate", { path: d.path }, "Rotated") }, "Rotate now"),
      h("button", { class: "btn" + (d.has_driver ? "" : " primary"), onclick: () => changeDialog(d, reload) }, rotates(d) && d.kind !== "ssh_key" ? "Change password" : "Replace"),
      h("button", { class: "btn", onclick: () => secretDialog(d, reload) }, "Edit"),
      h("button", { class: "btn", onclick: () => moveDialog(d, reload) }, "Move"),
      isAdmin() && rotates(d) && h("button", { class: "btn", onclick: () => rotationDialog(d, reload) }, d.has_driver ? "Rotation setup" : "Set up rotation"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Make the pending version the current one? Do this only if the live system already uses it.") && act("/v1/secrets/resolve", { path: d.path, promote: true }, "Pending version is now current") }, "Keep pending"),
      d.pending_rotation && isAdmin() && h("button", { class: "btn", onclick: () => confirm("Discard the pending version?") && act("/v1/secrets/resolve", { path: d.path, promote: false }, "Pending version discarded") }, "Discard pending")),
    h("div", { class: "cap sep" }, "History"),
    h("ul", { class: "timeline" }, d.versions.map((v) => h("li", { class: v.state, title: v.state },
      h("span", { class: "v" }, "v" + v.version), h("span", {}, short(v.created_at)), h("span", {}, who(v.created_by)),
      v.state !== "current" && h("span", { class: "acts" },
        h("button", { class: "link", onclick: () => reveal(v.version) }, "Show"),
        v.state !== "pending" && h("button", { class: "link", title: "Make this version the current one again", onclick: () => confirm(`Go back to version ${v.version}? It becomes the current password again; nothing is lost.`) && act("/v1/secrets/restore", { path: d.path, version: v.version }, `Version ${v.version} is current again`) }, "Use again"))))),
    h("div", { class: "row end" }, h("button", { class: "link danger", onclick: () => confirm(`Delete ${itemName(d)}?`) && act("/v1/secrets/delete", { path: d.path }, "Deleted") }, "Delete")));
}

// ---- cards and gift cards ------------------------------------------------
// The number, security code and PIN are the item's sealed value. Everything
// shown without revealing (brand, last four, expiry, balance) is metadata the
// vault worked out itself.
const isCard = (s) => s.kind === "card";
const isGift = (s) => s.kind === "gift_card";
const isCardish = (s) => isCard(s) || isGift(s);
const usd = (cents) => (cents < 0 ? "−" : "") + "$" + Math.floor(Math.abs(cents) / 100).toLocaleString("en-US") + "." + p2(Math.abs(cents) % 100);
function parseMoney(text) {
  const t = text.trim().replace(/^\$/, "").replace(/,/g, "");
  if (!/^\d{1,8}(\.\d{1,2})?$/.test(t)) return null;
  const [whole, frac = ""] = t.split(".");
  return Number(whole) * 100 + Number((frac + "00").slice(0, 2));
}
function parseExpiry(text) {
  const m = /^\s*(\d{1,2})\s*\/\s*(\d{2}|\d{4})\s*$/.exec(text);
  if (!m) return null;
  const month = Number(m[1]), year = Number(m[2]) < 100 ? 2000 + Number(m[2]) : Number(m[2]);
  return month >= 1 && month <= 12 ? { month, year } : null;
}
const expiryText = (c) => (c && c.exp_month && c.exp_year ? `${p2(c.exp_month)}/${p2(c.exp_year % 100)}` : "");
// Whole months of use left; negative once the card has expired.
function monthsLeft(c) {
  if (!c || !c.exp_month || !c.exp_year) return null;
  const now = new Date();
  return (c.exp_year - now.getFullYear()) * 12 + (c.exp_month - (now.getMonth() + 1));
}
const expiryGrade = (months) => (months < 0 ? "red" : months <= 2 ? "amber" : "green");
function cardSummary(s) {
  if (isCard(s)) { const c = s.meta.card || {}; return `${c.brand || "Card"} ending ${c.last4 || "····"}`; }
  const g = s.meta.gift || {};
  return [g.merchant, g.last4 && "ending " + g.last4].filter(Boolean).join(" ");
}
// Money ever put on a gift card: what it started with plus every top-up.
const giftLoaded = (g) => (g.initial_cents || 0) + (g.ledger || []).reduce((sum, e) => sum + Math.max(0, e.cents), 0);
const giftGrade = (left, loaded) => (left <= 0 ? "red" : loaded > 0 && left / loaded < 0.25 ? "amber" : "green");
function luhnOk(digits) {
  let sum = 0;
  [...digits].reverse().forEach((ch, i) => { let n = Number(ch); if (i % 2) { n *= 2; if (n > 9) n -= 9; } sum += n; });
  return sum % 10 === 0;
}
const groupDigits = (n) => (/^3[47]\d{13}$/.test(n) ? [n.slice(0, 4), n.slice(4, 10), n.slice(10)] : n.match(/.{1,4}/g) || []).join(" ");

// A fuel gauge: how much life or money is left, where passwords show age.
function gaugeCell(s) {
  const gauge = (grade, lit, text, title) => h("div", { class: "age " + grade, title },
    h("span", { class: "lights", "aria-hidden": "true" }, Array.from({ length: 8 }, (_, i) => h("i", { class: i < lit ? "lit" : null }))),
    h("span", {}, text));
  if (isCard(s)) {
    const months = monthsLeft(s.meta.card);
    if (months === null) return h("span", { class: "hint" }, "—");
    if (months < 0) return gauge("red", 8, "Expired " + expiryText(s.meta.card), "This card has expired");
    return gauge(expiryGrade(months), Math.max(1, Math.min(8, Math.ceil((months + 1) / 6))), "Expires " + expiryText(s.meta.card), months === 0 ? "Expires this month" : `${months} ${months === 1 ? "month" : "months"} left`);
  }
  const g = s.meta.gift || {}, left = s.balance_cents || 0, loaded = giftLoaded(g);
  const lit = left <= 0 ? 8 : Math.max(1, Math.min(8, Math.ceil((left / Math.max(loaded, left)) * 8)));
  return gauge(giftGrade(left, loaded), lit, left <= 0 ? "Empty" : usd(left) + " left", `${usd(left)} of ${usd(loaded)} left`);
}

function cardPanel(d, reload) {
  const gift = isGift(d), m = d.meta, info = (gift ? m.gift : m.card) || {};
  const codeName = gift ? "PIN" : "security code";
  const numMask = "•••• •••• " + (info.last4 || "••••");
  const num = h("div", { class: "val" }, numMask);
  const code = h("div", { class: "val" }, "•••");
  const note = h("div", { class: "hint under" });
  let shown = false, hideTimer, tick;
  async function fetchCard(version) {
    const raw = (await api("POST", "/v1/secrets/reveal", { path: d.path, version: version || null })).value;
    try { const v = JSON.parse(raw); return { number: String(v.number || ""), code: String(v.cvv || v.pin || "") }; } catch (_) { return { number: raw, code: "" }; }
  }
  const eye = iconButton("eyeClosed", "Show card number and " + codeName, () => (shown ? hide() : reveal()));
  const copyNum = iconButton("copy", "Copy card number", () => copy(copyNum, "number", "Card number copied. Clipboard clears in 30 seconds"));
  const copyCode = iconButton("copy", "Copy " + codeName, () => copy(copyCode, "code", `${gift ? "PIN" : "Security code"} copied. Clipboard clears in 30 seconds`));
  const numPlate = h("div", { class: "plate" }, num, h("div", { class: "tools" }, eye, copyNum));
  const codePlate = h("div", { class: "plate sub" }, h("span", { class: "lbl" }, gift ? "PIN" : "Security code"), code, h("div", { class: "tools" }, copyCode));
  function hide() {
    clearTimeout(hideTimer); clearInterval(tick); shown = false;
    num.textContent = numMask; code.textContent = "•••";
    numPlate.className = "plate"; codePlate.className = "plate sub"; note.textContent = ""; eye.setIcon("eyeClosed", "Show card number and " + codeName);
  }
  async function reveal(version) {
    try {
      const v = await fetchCard(version);
      paint(num, gift ? v.number : groupDigits(v.number));
      if (v.code) paint(code, v.code); else code.textContent = "none saved";
      shown = true; numPlate.className = "plate shown"; codePlate.className = "plate sub shown"; eye.setIcon("eyeOpen", "Hide card number and " + codeName);
      let left = REVEAL_SECONDS;
      const label = version ? `v${version}, hides in ` : "Hides in ";
      note.textContent = `${label}${left}s`;
      clearTimeout(hideTimer); clearInterval(tick);
      tick = setInterval(() => { left -= 1; note.textContent = `${label}${left}s`; }, 1000);
      hideTimer = setTimeout(hide, REVEAL_SECONDS * 1000);
    } catch (e) { fail(e); }
  }
  async function copy(button, field, okMsg) {
    try {
      let v;
      const got = await copyWith(button, async () => { v = (await fetchCard())[field]; if (!v) throw new Error("empty"); return v; }, okMsg);
      if (got) setTimeout(async () => { try { if (await navigator.clipboard.readText() === v) await navigator.clipboard.writeText(""); } catch (_) { /* tab not focused */ } }, 30000);
    } catch (e) { fail(e); }
  }
  async function act(path, body, okMsg) {
    try { await api("POST", path, body); toast(okMsg); reload(); } catch (e) { fail(e); }
  }
  const months = gift ? null : monthsLeft(info);
  const left = d.balance_cents || 0, loaded = gift ? giftLoaded(info) : 0;
  const grade = gift ? giftGrade(left, loaded) : months === null ? "green" : expiryGrade(months);
  const statusText = gift ? (left <= 0 ? "Empty" : usd(left) + " left")
    : months === null ? "No expiry saved" : months < 0 ? "Expired " + expiryText(info) : "Expires " + expiryText(info);
  const ledger = gift ? [...(info.ledger || [])].reverse() : [];
  const earlier = d.versions.filter((v) => v.state !== "current");
  return h("div", { class: "insp" },
    h("div", { class: "top" },
      h("div", { class: "grow" }, h("h3", {}, m.title || pretty(leafOf(d.path))), h("div", { class: "where" }, folderLabel(folderOf(d.path)))),
      h("div", { class: "status" }, lamp(grade), statusText)),
    numPlate, codePlate, note,
    h("dl", { class: "kv" },
      !gift && h("dt", {}, "Card"), !gift && h("dd", {}, cardSummary(d)),
      gift && info.merchant && h("dt", {}, "Store"), gift && info.merchant && h("dd", {}, info.merchant),
      gift && h("dt", {}, "Balance"), gift && h("dd", {}, `${usd(left)} of ${usd(loaded)}`),
      !gift && info.holder && h("dt", {}, "Name"), !gift && info.holder && h("dd", {}, info.holder),
      !gift && info.zip && h("dt", {}, "ZIP"), !gift && info.zip && h("dd", { class: "mono" }, info.zip),
      m.notes && h("dt", {}, "Notes"), m.notes && h("dd", {}, m.notes),
      h("dt", {}, "Address"), h("dd", { class: "mono", title: "What agents and access rules use to refer to this item" }, d.path)),
    h("div", { class: "row" },
      gift && h("button", { class: "btn primary", onclick: () => ledgerDialog(d, -1, reload) }, "Record spending"),
      gift && h("button", { class: "btn", onclick: () => ledgerDialog(d, 1, reload) }, "Add money"),
      h("button", { class: "btn", onclick: () => cardDialog(d.kind, d, reload, { replace: true }) }, gift ? "Replace number" : "Replace card"),
      h("button", { class: "btn", onclick: () => cardDialog(d.kind, d, reload) }, "Edit"),
      h("button", { class: "btn", onclick: () => moveDialog(d, reload) }, "Move")),
    gift && h("div", { class: "cap sep" }, "Spending"),
    gift && h("ul", { class: "timeline ledger" },
      ledger.map((e) => h("li", { class: e.cents > 0 ? "add" : "spend" },
        h("span", {}, short(e.at)), h("span", { class: "amt" }, (e.cents > 0 ? "+" : "") + usd(e.cents)),
        e.note && h("span", { class: "what" }, e.note), h("span", { class: "acts" }, who(e.by)))),
      h("li", { class: "start" }, h("span", {}, short(d.created_at)), h("span", { class: "amt" }, usd(info.initial_cents || 0)), h("span", { class: "what" }, "Starting balance"))),
    earlier.length > 0 && h("div", { class: "cap sep" }, gift ? "Earlier numbers" : "Earlier cards"),
    earlier.length > 0 && h("ul", { class: "timeline" }, earlier.map((v) => h("li", { class: v.state, title: v.state },
      h("span", { class: "v" }, "v" + v.version), h("span", {}, short(v.created_at)), h("span", {}, who(v.created_by)),
      h("span", { class: "acts" },
        h("button", { class: "link", onclick: () => reveal(v.version) }, "Show"),
        h("button", { class: "link", title: "Make this the current card again", onclick: () => confirm(`Go back to version ${v.version}? It becomes the current card again; nothing is lost.`) && act("/v1/secrets/restore", { path: d.path, version: v.version }, `Version ${v.version} is current again`) }, "Use again"))))),
    h("div", { class: "row end" }, h("button", { class: "link danger", onclick: () => confirm(`Delete ${itemName(d)}?`) && act("/v1/secrets/delete", { path: d.path }, "Deleted") }, "Delete")));
}

// One dialog, three jobs: add a card, edit its details, or put a new number
// on an existing item (the old number stays in its history).
function cardDialog(kind, existing, done, opts) {
  const o = opts || {};
  const gift = kind === "gift_card";
  const m = existing ? existing.meta : { title: o.title || "", username: "", url: "", notes: "", tags: [] };
  const info = (existing && (gift ? m.gift : m.card)) || {};
  const withNumber = !existing || o.replace, withDetails = !o.replace;
  const text = (attrs) => h("input", Object.assign({ type: "text", autocomplete: "off", spellcheck: "false" }, attrs));
  const f = {
    title: text({ class: "big", placeholder: gift ? "Name, like Bookshop gift card" : "Name, like Everyday Visa", value: m.title || "", maxlength: "200", required: !existing, autofocus: withDetails, "aria-label": "Name" }),
    number: text({ class: "mono", placeholder: gift ? "Gift card number" : "Card number", inputmode: gift ? "text" : "numeric", maxlength: "80", autofocus: !withDetails, "aria-label": gift ? "Gift card number" : "Card number" }),
    code: text({ class: "mono", placeholder: gift ? "PIN, if it has one" : "Security code", inputmode: gift ? "text" : "numeric", maxlength: gift ? "32" : "4", "aria-label": gift ? "PIN" : "Security code" }),
    exp: text({ class: "mono", placeholder: "Expires MM/YY", inputmode: "numeric", maxlength: "7", value: existing && !o.replace ? expiryText(info) : "", "aria-label": "Expiry date, month and year" }),
    holder: text({ placeholder: "Name on the card", value: info.holder || "", maxlength: "100", "aria-label": "Name on the card" }),
    zip: text({ placeholder: "Billing ZIP", value: info.zip || "", maxlength: "16", "aria-label": "Billing ZIP or postcode" }),
    merchant: text({ placeholder: "Store, like Target", value: info.merchant || "", maxlength: "100", "aria-label": "Store" }),
    balance: text({ class: "mono", placeholder: existing ? "Starting balance" : "Balance today, like 50.00", inputmode: "decimal", value: existing ? ((info.initial_cents || 0) / 100).toFixed(2) : "", "aria-label": existing ? "Starting balance" : "Balance today" }),
    notes: h("textarea", { placeholder: "Notes", "aria-label": "Notes" }, m.notes || ""),
  };
  const kindSel = h("select", { "aria-label": "Kind" }, [["card", "Payment card"], ["gift_card", "Gift card"], ["identity", "Person or address"], ["", "Something else…"]].map(([k, l]) => h("option", { value: k, selected: k === kind }, l)));
  const folder = folderPicker(o.folder !== undefined ? o.folder : state.folder || "");
  const err = h("div", { class: "error" });
  const warn = h("div", { class: "hint" });
  const where = h("span", { class: "hint" });
  const target = () => { const dir = folder.value(); return (dir ? dir + "/" : "") + (slug(f.title.value) || "card"); };
  const cleanNumber = () => (gift ? f.number.value.replace(/\s+/g, "") : f.number.value.replace(/[\s-]+/g, ""));
  const sync = () => {
    if (!existing) where.textContent = "Agents will know it as " + target() + ", never the number";
    const n = cleanNumber();
    warn.textContent = !gift && /^\d{12,19}$/.test(n) && !luhnOk(n) ? "That number does not add up the way card numbers do. Check it for a typo." : "";
  };
  [f.title, f.number, folder.el].forEach((el) => el.addEventListener("input", sync));
  folder.el.addEventListener("change", sync);
  kindSel.addEventListener("change", () => {
    dlg.close();
    newOfKind(kindSel.value, done, { title: f.title.value, folder: folder.isNew() ? "" : folder.raw() });
  });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const meta = Object.assign({}, m, { title: withDetails ? f.title.value.trim() : m.title, notes: withDetails ? f.notes.value : m.notes });
      delete meta.policy;
      if (gift) {
        const start = f.balance.value.trim() ? parseMoney(f.balance.value) : 0;
        if (withDetails && start === null) { err.textContent = "Write the balance like 50.00."; return; }
        meta.gift = Object.assign({}, info, withDetails ? { merchant: f.merchant.value.trim(), initial_cents: start } : {});
        delete meta.card;
      } else {
        const exp = f.exp.value.trim() ? parseExpiry(f.exp.value) : { month: 0, year: 0 };
        if (!exp) { err.textContent = "Write the expiry like 08/29."; return; }
        // Replacing with the expiry left blank keeps the one already saved.
        const keepExp = o.replace && !f.exp.value.trim();
        meta.card = Object.assign({}, info, keepExp ? {} : { exp_month: exp.month, exp_year: exp.year }, withDetails ? { holder: f.holder.value.trim(), zip: f.zip.value.trim() } : {});
        delete meta.gift;
      }
      const body = existing ? { path: existing.path, meta } : { path: target(), kind, meta };
      if (withNumber) {
        const n = cleanNumber(), c = f.code.value.trim();
        if (gift ? !/^[A-Za-z0-9-]{4,64}$/.test(n) : !/^\d{12,19}$/.test(n)) { err.textContent = gift ? "Enter the gift card number: letters, digits and dashes." : "Enter the card number: 12 to 19 digits."; return; }
        if (!gift && c && !/^\d{3,4}$/.test(c)) { err.textContent = "The security code is 3 or 4 digits."; return; }
        body.value = JSON.stringify(gift ? { number: n, pin: c } : { number: n, cvv: c });
      }
      try {
        if (!existing && !folder.valid()) { err.textContent = "Give the new folder a name."; return; }
        await api("POST", existing ? "/v1/secrets/update" : "/v1/secrets/create", body);
        if (!existing) state.selected = body.path;
        dlg.close();
        toast(o.replace ? "Saved. The old number is in this card's history" : existing ? "Saved" : "Added to the vault");
        done();
      } catch (ex) {
        if (ex.status === 401 || ex.code === "sealed") { dlg.close(); return fail(ex); }
        err.textContent = ex.status === 409 ? "This folder already has an item with that name."
          : ex.status === 403 ? "This access token may not save card numbers. Ask an admin for the write permission." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, o.replace ? (gift ? "New number for " : "New card for ") + itemName(existing) : existing ? "Edit " + (gift ? "gift card" : "card") : gift ? "New gift card" : "New card"), !existing && where),
      withDetails && f.title,
      withNumber && h("div", { class: "stack" }, f.number),
      withNumber && !gift && h("div", { class: "two gap" }, f.exp, f.code),
      withNumber && gift && h("div", { class: "two gap" }, f.code, withDetails ? f.balance : h("span", {})),
      !withNumber && !gift && h("div", { class: "two gap" }, f.exp, f.zip),
      !withNumber && gift && h("div", { class: "two gap" }, f.merchant, f.balance),
      withNumber && withDetails && !gift && h("div", { class: "two gap" }, f.holder, f.zip),
      withNumber && withDetails && gift && h("div", { class: "stack" }, f.merchant),
      !withNumber && !gift && h("div", { class: "stack" }, f.holder),
      !existing && h("div", { class: "two gap" }, h("div", {}, h("label", {}, "Folder"), folder.el), h("div", {}, h("label", {}, "Kind"), kindSel)),
      withDetails && h("div", { class: "stack" }, f.notes),
      warn,
      o.replace && h("p", { class: "hint" }, gift ? "The balance and spending history stay. The current number moves to this card's history." : "Leave the expiry blank to keep the one saved. The current number moves to this card's history."),
      err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, existing ? "Save changes" : "Add to vault"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  sync();
  dlg.showModal();
}

// Money out of, or onto, a gift card. This keeps the books; it moves no money.
function ledgerDialog(d, sign, done) {
  const left = d.balance_cents || 0;
  const amount = h("input", { class: "big mono", type: "text", inputmode: "decimal", placeholder: "0.00", autocomplete: "off", autofocus: true, required: true, "aria-label": sign < 0 ? "Amount spent" : "Amount added" });
  const noteIn = h("input", { type: "text", placeholder: sign < 0 ? "What was it for?" : "Where did it come from?", autocomplete: "off", maxlength: "200", "aria-label": "Note" });
  const err = h("div", { class: "error" });
  const after = h("p", { class: "hint" }, `${usd(left)} on the card now.`);
  amount.addEventListener("input", () => {
    const c = parseMoney(amount.value);
    after.textContent = c ? `${usd(left)} on the card now, ${usd(Math.max(0, left + sign * c))} after this.` : `${usd(left)} on the card now.`;
  });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const c = parseMoney(amount.value);
      if (!c) { err.textContent = "Write the amount like 12.34."; return; }
      if (sign < 0 && c > left) { err.textContent = `Only ${usd(left)} is left on this card.`; return; }
      try {
        const r = await api("POST", "/v1/secrets/ledger", { path: d.path, cents: sign * c, note: noteIn.value.trim() });
        dlg.close(); toast(`${usd(r.balance_cents || 0)} left on ${itemName(d)}`); done();
      } catch (ex) {
        if (ex.status === 401 || ex.code === "sealed") { dlg.close(); return fail(ex); }
        err.textContent = ex.status === 403 ? "This access token may not change this card's details." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, (sign < 0 ? "Spent from " : "Added to ") + itemName(d))),
      amount,
      h("div", { class: "stack" }, noteIn),
      after, err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, sign < 0 ? "Record spending" : "Add money"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  dlg.showModal();
}

// ---- people and addresses -------------------------------------------------
// Contact details and the address are plain details an agent may read and
// use. Identity numbers are the sealed value: only their labels show.
const isPerson = (s) => s.kind === "identity";
const PERSON_KINDS = { card: "Payment card", gift_card: "Gift card", identity: "Person or address" };
// Open the right "new" dialog for a kind, carrying over what was typed so far.
function newOfKind(kind, done, carry) {
  if (kind === "identity") personDialog(null, done, carry);
  else if (kind === "card" || kind === "gift_card") cardDialog(kind, null, done, carry);
  else secretDialog(null, done);
}
function addressLines(p) {
  const place = [p.city, [p.region, p.postal].filter(Boolean).join(" ")].filter(Boolean).join(", ");
  return [p.line1, p.line2, place, p.country].filter(Boolean);
}
function personSummary(s) {
  const p = s.meta.person || {};
  return [p.full_name, p.line1 || p.city].filter(Boolean).join(", ");
}
function birthdayText(iso) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || "");
  return m ? `${MONTHS[Number(m[2]) - 1]} ${Number(m[3])}, ${m[1]}` : iso || "";
}

function personPanel(d, reload) {
  const m = d.meta, p = m.person || {};
  const note = h("div", { class: "hint under" });
  let shown = false, hideTimer, tick;
  async function fetchSealed() {
    try { return JSON.parse((await api("POST", "/v1/secrets/reveal", { path: d.path })).value) || {}; } catch (e) { if (e && e.status) throw e; return {}; }
  }
  const sealed = (p.sealed || []).map((label) => {
    const val = h("div", { class: "val" }, "•••••••");
    const copyBtn = iconButton("copy", "Copy " + label, async () => {
      try {
        let v;
        const got = await copyWith(copyBtn, async () => { v = (await fetchSealed())[label]; if (!v) throw new Error("empty"); return v; }, label + " copied. Clipboard clears in 30 seconds");
        if (got) setTimeout(async () => { try { if (await navigator.clipboard.readText() === v) await navigator.clipboard.writeText(""); } catch (_) { /* tab not focused */ } }, 30000);
      } catch (e) { fail(e); }
    });
    const plate = h("div", { class: "plate sub" }, h("span", { class: "lbl" }, label), val, h("div", { class: "tools" }, copyBtn));
    return { label, val, plate };
  });
  const eye = iconButton("eyeClosed", "Show private numbers", () => (shown ? hide() : reveal()));
  function hide() {
    clearTimeout(hideTimer); clearInterval(tick); shown = false; note.textContent = "";
    sealed.forEach((s) => { s.val.textContent = "•••••••"; s.plate.className = "plate sub"; });
    eye.setIcon("eyeClosed", "Show private numbers");
  }
  async function reveal() {
    try {
      const all = await fetchSealed();
      sealed.forEach((s) => { paint(s.val, all[s.label] || ""); s.plate.className = "plate sub shown"; });
      shown = true; eye.setIcon("eyeOpen", "Hide private numbers");
      let left = REVEAL_SECONDS;
      note.textContent = `Hides in ${left}s`;
      clearTimeout(hideTimer); clearInterval(tick);
      tick = setInterval(() => { left -= 1; note.textContent = `Hides in ${left}s`; }, 1000);
      hideTimer = setTimeout(hide, REVEAL_SECONDS * 1000);
    } catch (e) { fail(e); }
  }
  async function act(path, body, okMsg) {
    try { await api("POST", path, body); toast(okMsg); reload(); } catch (e) { fail(e); }
  }
  // A detail row with its own copy button: these get pasted into forms a lot.
  const row = (label, text, shownAs) => {
    if (!text) return [];
    const b = iconButton("copy", "Copy " + label.toLowerCase(), () => copyWith(b, async () => text, label + " copied"));
    return [h("dt", {}, label), h("dd", { class: "copyable" }, h("span", { class: "grow" }, shownAs || text), b)];
  };
  const addr = addressLines(p);
  return h("div", { class: "insp" },
    h("div", { class: "top" },
      h("div", { class: "grow" }, h("h3", {}, m.title || p.full_name || pretty(leafOf(d.path))), h("div", { class: "where" }, folderLabel(folderOf(d.path))))),
    h("dl", { class: "kv first" },
      row("Name", p.full_name), row("Email", p.email), row("Phone", p.phone),
      row("Birthday", p.birthday, birthdayText(p.birthday)), row("Company", p.company),
      row("Address", addr.join("\n"), h("span", { class: "lines" }, addr.map((l) => h("span", {}, l)))),
      m.notes && h("dt", {}, "Notes"), m.notes && h("dd", {}, m.notes),
      h("dt", {}, "Known as"), h("dd", { class: "mono", title: "What agents and access rules use to refer to this item" }, d.path)),
    sealed.length > 0 && h("div", { class: "caprow" }, h("div", { class: "cap grow" }, "Private numbers, sealed"), eye),
    sealed.map((s) => s.plate), sealed.length > 0 && note,
    h("div", { class: "row" },
      h("button", { class: "btn primary", onclick: () => personDialog(d, reload) }, "Edit"),
      h("button", { class: "btn", onclick: () => sealedDialog(d, reload) }, sealed.length ? "Private numbers" : "Add a private number"),
      h("button", { class: "btn", onclick: () => moveDialog(d, reload) }, "Move")),
    h("p", { class: "hint" }, "Agents you connect can read the details above. They cannot read private numbers."),
    h("div", { class: "row end" }, h("button", { class: "link danger", onclick: () => confirm(`Delete ${itemName(d)}?`) && act("/v1/secrets/delete", { path: d.path }, "Deleted") }, "Delete")));
}

function personDialog(existing, done, opts) {
  const o = opts || {};
  const m = existing ? existing.meta : { title: o.title || "", username: "", url: "", notes: "", tags: [] };
  const p = (existing && m.person) || {};
  const text = (key, placeholder, extra) => h("input", Object.assign({ type: "text", autocomplete: "off", spellcheck: "false", maxlength: "200", placeholder, value: p[key] || "", "aria-label": placeholder }, extra || {}));
  const f = {
    title: h("input", { class: "big", type: "text", placeholder: "What to call it, like Me, home or Mom", value: m.title || "", autocomplete: "off", maxlength: "200", required: true, autofocus: true, "aria-label": "Name of this entry" }),
    full_name: text("full_name", "Full name"),
    email: text("email", "Email", { inputmode: "email" }),
    phone: text("phone", "Phone", { inputmode: "tel" }),
    birthday: text("birthday", "Birthday, YYYY-MM-DD", { class: "mono", inputmode: "numeric", maxlength: "10" }),
    company: text("company", "Company"),
    line1: text("line1", "Street address"),
    line2: text("line2", "Apartment, suite, unit"),
    city: text("city", "City"),
    region: text("region", "State"),
    postal: text("postal", "ZIP", { class: "mono", maxlength: "16" }),
    country: text("country", "Country"),
    notes: h("textarea", { placeholder: "Notes", "aria-label": "Notes" }, m.notes || ""),
  };
  const kindSel = h("select", { "aria-label": "Kind" }, [["identity", PERSON_KINDS.identity], ["card", PERSON_KINDS.card], ["gift_card", PERSON_KINDS.gift_card], ["", "Something else…"]].map(([k, l]) => h("option", { value: k, selected: k === "identity" }, l)));
  const folder = folderPicker(o.folder !== undefined ? o.folder : state.folder || "");
  const err = h("div", { class: "error" });
  const where = h("span", { class: "hint" });
  const target = () => { const dir = folder.value(); return (dir ? dir + "/" : "") + (slug(f.title.value) || "person"); };
  const sync = () => { if (!existing) where.textContent = "Agents will know it as " + target(); };
  [f.title, folder.el].forEach((el) => el.addEventListener("input", sync));
  folder.el.addEventListener("change", sync);
  kindSel.addEventListener("change", () => { dlg.close(); newOfKind(kindSel.value, done, { title: f.title.value, folder: folder.isNew() ? "" : folder.raw() }); });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const bday = f.birthday.value.trim();
      if (bday && !/^\d{4}-\d{2}-\d{2}$/.test(bday)) { err.textContent = "Write the birthday like 1990-04-23."; return; }
      const person = Object.assign({}, p);
      ["full_name", "email", "phone", "company", "line1", "line2", "city", "region", "postal", "country"].forEach((k) => { person[k] = f[k].value.trim(); });
      person.birthday = bday;
      const meta = Object.assign({}, m, { title: f.title.value.trim(), notes: f.notes.value, person });
      delete meta.policy;
      const body = existing ? { path: existing.path, meta } : { path: target(), kind: "identity", meta };
      try {
        if (!existing && !folder.valid()) { err.textContent = "Give the new folder a name."; return; }
        await api("POST", existing ? "/v1/secrets/update" : "/v1/secrets/create", body);
        if (!existing) state.selected = body.path;
        dlg.close(); toast(existing ? "Saved" : "Added to the vault"); done();
      } catch (ex) {
        if (ex.status === 401 || ex.code === "sealed") { dlg.close(); return fail(ex); }
        err.textContent = ex.status === 409 ? "This folder already has an item with that name." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, existing ? "Edit " + itemName(existing) : "New person or address"), !existing && where),
      f.title,
      h("div", { class: "two gap" }, f.full_name, f.company),
      h("div", { class: "two gap" }, f.email, f.phone),
      h("div", { class: "stack" }, f.line1, f.line2),
      h("div", { class: "three gap" }, f.city, f.region, f.postal),
      h("div", { class: "two gap" }, f.country, f.birthday),
      !existing && h("div", { class: "two gap" }, h("div", {}, h("label", {}, "Folder"), folder.el), h("div", {}, h("label", {}, "Kind"), kindSel)),
      h("div", { class: "stack" }, f.notes),
      h("p", { class: "hint" }, "Fill in only what you want kept. Passport, license and ID numbers go in Private numbers, where they stay sealed."),
      err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, existing ? "Save changes" : "Add to vault"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  sync();
  dlg.showModal();
}

// Passport, licence and ID numbers: the sealed part of a person.
async function sealedDialog(d, done) {
  let current = {};
  try { current = JSON.parse((await api("POST", "/v1/secrets/reveal", { path: d.path })).value) || {}; }
  catch (e) { if (e && e.status === 403) return toast("This access token may not see private numbers.", true); if (e && e.status) return fail(e); }
  const rowsEl = h("div", { class: "stack" });
  const err = h("div", { class: "error" });
  const hints = h("datalist", { id: "sealed-labels" }, ["Social Security number", "Passport", "Driver's license", "State ID", "Tax ID", "Known Traveler Number", "Insurance member ID"].map((l) => h("option", { value: l })));
  function addRow(label, number) {
    const l = h("input", { type: "text", placeholder: "What it is, like Passport", value: label || "", maxlength: "40", autocomplete: "off", list: "sealed-labels", "aria-label": "What this number is" });
    const n = h("input", { class: "mono", type: "text", placeholder: "Number", value: number || "", maxlength: "200", autocomplete: "off", spellcheck: "false", "aria-label": "Number" });
    const rm = h("button", { class: "link danger", type: "button", onclick: () => r.remove() }, "Remove");
    const r = h("div", { class: "sealedrow" }, l, n, rm);
    r.read = () => [l.value.trim(), n.value.trim()];
    rowsEl.append(r);
    return l;
  }
  Object.entries(current).forEach(([l, n]) => addRow(l, n));
  if (!rowsEl.children.length) addRow();
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const next = {};
      for (const r of rowsEl.children) {
        const [label, number] = r.read();
        if (!label && !number) continue;
        if (!label || !number) { err.textContent = "Each number needs both a name and a value."; return; }
        if (label in next) { err.textContent = `"${label}" is listed twice.`; return; }
        next[label] = number;
      }
      try {
        await api("POST", "/v1/secrets/update", { path: d.path, value: JSON.stringify(next) });
        dlg.close(); toast("Saved and sealed"); done();
      } catch (ex) {
        if (ex.status === 401 || ex.code === "sealed") { dlg.close(); return fail(ex); }
        err.textContent = ex.status === 403 ? "This access token may not save private numbers. Ask an admin for the write permission." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, "Private numbers for " + itemName(d))),
      hints, rowsEl,
      h("button", { class: "link", type: "button", onclick: () => addRow().focus() }, "+  Add another"),
      h("p", { class: "hint" }, "These are sealed like passwords. Agents can see that a passport number is on file, never the number."),
      err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Save"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  dlg.showModal();
}

// ---- password generator -------------------------------------------------
// Runs in the browser with the platform CSPRNG and rejection sampling (no
// modulo bias), mirroring the server's generator and its character sets.
const GEN = { lower: "abcdefghijklmnopqrstuvwxyz", upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits: "0123456789", symbols: "!@#%^*-_=+", alike: "Il1O0o" };
const LEN_MIN = 12, LEN_MAX = 64, LIGHTS = 27;

function randInt(n) {
  const zone = 4294967296 - (4294967296 % n);
  const b = new Uint32Array(1);
  for (;;) { crypto.getRandomValues(b); if (b[0] < zone) return b[0] % n; }
}

function poolFor(o) {
  return ["lower", "upper", "digits", "symbols"].filter((k) => o[k]).map((k) => [...GEN[k]].filter((c) => !(o.plain && GEN.alike.includes(c))));
}

function makePassword(o) {
  const sets = poolFor(o);
  if (!sets.length) return "";
  const all = sets.flat();
  const out = sets.map((set) => set[randInt(set.length)]);
  while (out.length < o.length) out.push(all[randInt(all.length)]);
  for (let i = out.length - 1; i > 0; i--) { const k = randInt(i + 1); [out[i], out[k]] = [out[k], out[i]]; }
  return out.join("");
}

// Word passwords use the EFF list (7,776 words), fetched once from the vault.
let WORDS = null;
async function loadWords() {
  if (!WORDS) WORDS = (await (await fetch("/wordlist.txt", { credentials: "omit" })).text()).split("\n").filter(Boolean);
  return WORDS;
}
const WORDS_MIN = 4, WORDS_MAX = 10;
const SEPARATORS = [["-", "dashes"], ["", "run together"], [".", "dots"], [" ", "spaces"]];

function makeWords(o) {
  const digitAt = o.number ? randInt(o.words) : -1;
  return Array.from({ length: o.words }, (_, i) => {
    let w = WORDS[randInt(WORDS.length)];
    if (o.capitalize) w = w[0].toUpperCase() + w.slice(1);
    return i === digitAt ? w + randInt(10) : w;
  }).join(o.separator);
}

function generator(policy) {
  const o = { mode: "random", length: 24, lower: true, upper: true, digits: true, symbols: true, plain: false, words: 5, separator: "-", capitalize: true, number: false };
  if (policy && policy.type === "password") Object.assign(o, { length: Math.max(LEN_MIN, Math.min(LEN_MAX, policy.length || 24)), lower: policy.lower !== false, upper: policy.upper !== false, digits: policy.digits !== false, symbols: policy.symbols !== "", plain: !!policy.exclude_ambiguous });
  if (policy && policy.type === "words") Object.assign(o, { mode: "words", words: Math.max(WORDS_MIN, Math.min(WORDS_MAX, policy.words || 5)), separator: policy.separator == null ? "-" : policy.separator, capitalize: policy.capitalize !== false, number: !!policy.number });
  let typed = false;
  const field = h("input", { class: "pw", type: "text", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Password. Type here to use your own" });
  const verdict = h("div", { class: "verdict" });
  const modes = h("div", { class: "segs" });
  const runway = h("div", { class: "runway" });
  const opts = h("div", { class: "opts" });
  let range, dots;
  const words = () => o.mode === "words";

  function meter() {
    const v = field.value;
    let bits;
    if (typed) {
      const pool = (/[a-z]/.test(v) ? 26 : 0) + (/[A-Z]/.test(v) ? 26 : 0) + (/[0-9]/.test(v) ? 10 : 0) + (/[^A-Za-z0-9]/.test(v) ? 20 : 0);
      bits = v.length * Math.log2(pool || 1);
    } else if (words()) bits = o.words * Math.log2(7776) + (o.number ? Math.log2(10 * o.words) : 0);
    else bits = o.length * Math.log2(poolFor(o).flat().length);
    const grade = bits < 50 ? "weak" : bits < 75 ? "fair" : "";
    const word = grade === "weak" ? "Weak" : grade === "fair" ? "Good" : "Strong";
    verdict.className = "verdict " + grade;
    verdict.textContent = typed
      ? `Typed by hand, ${v.length} characters. ${grade === "weak" ? "Too easy to guess." : grade === "fair" ? "Acceptable." : "Strong, if it is not reused or a phrase."}`
      : words() ? `${o.words} words, ${v.length} characters. ${word}, about ${Math.round(bits)} bits.`
      : `${o.length} characters. ${word}, about ${Math.round(bits)} bits.`;
    // Long word passwords shrink to stay readable on one line.
    field.style.fontSize = v.length > 46 ? "13px" : v.length > 36 ? "15px" : v.length > 27 ? "18px" : "";
    const [lo, hi, val] = words() ? [WORDS_MIN, WORDS_MAX, o.words] : [LEN_MIN, LEN_MAX, typed ? Math.max(LEN_MIN, Math.min(LEN_MAX, v.length)) : o.length];
    const lit = Math.round(((val - lo) / (hi - lo)) * (dots.length - 1));
    dots.forEach((dEl, i) => { dEl.className = i === lit ? "lit knob" : i < lit ? "lit" : ""; });
  }
  function roll() {
    typed = false;
    if (words() && !WORDS) { field.value = ""; field.placeholder = "Loading words…"; loadWords().then(roll, () => { field.placeholder = "Could not load the word list"; }); return; }
    field.value = words() ? makeWords(o) : makePassword(o);
    range.value = String(words() ? o.words : o.length);
    meter();
  }
  const toggle = (key, label, title, guard) => {
    const box = h("input", { type: "checkbox", checked: o[key], "aria-label": title });
    box.addEventListener("change", () => { o[key] = box.checked; if (guard && !guard()) { o[key] = true; box.checked = true; return; } roll(); });
    return h("label", { class: "chip", title }, box, h("span", {}, label));
  };
  // The slider is a runway: lights come on up to the chosen length.
  function build() {
    const [lo, hi, val, count] = words() ? [WORDS_MIN, WORDS_MAX, o.words, WORDS_MAX - WORDS_MIN + 1] : [LEN_MIN, LEN_MAX, o.length, LIGHTS];
    range = h("input", { type: "range", min: String(lo), max: String(hi), step: "1", value: String(val), "aria-label": words() ? "Number of words" : "Password length" });
    range.addEventListener("input", () => { if (words()) o.words = Number(range.value); else o.length = Number(range.value); roll(); });
    dots = Array.from({ length: count }, () => h("i", {}));
    runway.replaceChildren(h("span", {}, lo), h("div", { class: "strip" }, dots, range), h("span", {}, hi));
    modes.replaceChildren(...[["random", "Random characters"], ["words", "Words"]].map(([m, label]) =>
      h("button", { class: "seg" + (o.mode === m ? " on" : ""), type: "button", "aria-pressed": o.mode === m ? "true" : "false", onclick: () => { if (o.mode !== m) { o.mode = m; build(); roll(); } } }, label)));
    if (words()) {
      const seps = SEPARATORS.map(([v, label]) => {
        const radio = h("input", { type: "radio", name: "gen-sep", checked: o.separator === v, "aria-label": "Between words: " + label });
        radio.addEventListener("change", () => { o.separator = v; roll(); });
        return h("label", { class: "chip", title: "Between words: " + label }, radio, h("span", {}, label));
      });
      opts.replaceChildren(...seps, toggle("capitalize", "Capitals", "Start each word with a capital letter"), toggle("number", "a number", "Add one digit, for sites that insist on a number"));
    } else {
      const keepOne = () => poolFor(o).length > 0;
      opts.replaceChildren(toggle("lower", "a-z", "Lowercase letters", keepOne), toggle("upper", "A-Z", "Capital letters", keepOne), toggle("digits", "0-9", "Digits", keepOne), toggle("symbols", "!@#", "Symbols", keepOne), toggle("plain", "no l1O0", "Leave out characters that look alike", keepOne));
    }
  }
  field.addEventListener("input", () => { typed = true; meter(); });
  const genCopy = iconButton("copy", "Copy this password", () => copyWith(genCopy, () => field.value, "Copied"));
  const el = h("div", { class: "gen" },
    modes,
    h("div", { class: "pwrow" }, field, h("div", { class: "tools" }, iconButton("again", "Make a different one", roll), genCopy)),
    runway, verdict, opts,
    h("div", { class: "foot" }, h("span", { class: "hint" }, "Or type your own in the field")));
  build();
  roll();
  return {
    el,
    value: () => field.value,
    // Remembered so the next change starts from the same shape; null when typed by hand.
    policy: () => (typed ? null
      : words() ? { type: "words", words: o.words, separator: o.separator, capitalize: o.capitalize, number: o.number }
      : { type: "password", length: o.length, lower: o.lower, upper: o.upper, digits: o.digits, symbols: o.symbols ? null : "", exclude_ambiguous: o.plain }),
  };
}

// Cmd/Ctrl+Enter submits the dialog's form from any field.
function quickSave(dlg) {
  dlg.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); const f = dlg.querySelector("form"); if (f) f.requestSubmit(); }
  });
}
const SAVE_HINT = (MAC ? "⌘" : "Ctrl") + " Enter to save";

function secretDialog(existing, done) {
  const m = existing ? existing.meta : { title: "", username: "", url: "", notes: "", tags: [] };
  const kinds = [["password", "Login or password"], ["card", "Payment card"], ["gift_card", "Gift card"], ["identity", "Person or address"], ["api_key", "API key"], ["ssh_key", "SSH key"], ["config", "Configuration"], ["note", "Secure note"]];
  const f = {
    title: h("input", { class: "big", type: "text", placeholder: "Name, like GitHub or Proxmox root", value: m.title || "", autocomplete: "off", maxlength: "200", autofocus: true, required: !existing, "aria-label": "Name" }),
    kind: h("select", {}, kinds.map(([k, l]) => h("option", { value: k }, l))),
    username: h("input", { type: "text", value: m.username, autocomplete: "off", placeholder: "Username", "aria-label": "Username" }),
    url: h("input", { type: "text", value: m.url, placeholder: "Website", autocomplete: "off", "aria-label": "Website" }),
    tags: h("input", { type: "text", value: m.tags.join(", "), placeholder: "Tags, separated with commas", autocomplete: "off", "aria-label": "Tags" }),
    notes: h("textarea", { placeholder: "Notes", "aria-label": "Notes" }, m.notes),
    content: h("textarea", { class: "mono", spellcheck: "false", placeholder: "Paste the key or text to keep safe" }),
  };
  const gen = generator(existing && existing.meta.policy);
  const folder = folderPicker(state.folder || "");
  const err = h("div", { class: "error" });
  const where = h("span", { class: "hint" });
  const genRow = h("div", {}, gen.el);
  const contentRow = h("div", { hidden: true }, h("label", {}, "Content"), f.content);
  // Editing changes details only; the password has its own Change password dialog.
  const replacing = !existing;
  const generated = () => ["password", "api_key"].includes(existing ? existing.kind : f.kind.value);
  const target = () => {
    const dir = folder.value();
    return (dir ? dir + "/" : "") + (slug(f.title.value) || "item");
  };
  const sync = () => {
    genRow.hidden = !replacing || !generated();
    contentRow.hidden = !replacing || generated();
    if (!existing) where.textContent = "Agents will know it as " + target();
  };
  [f.title, folder.el].forEach((el) => el.addEventListener("input", sync));
  [folder.el, f.kind].forEach((el) => el.addEventListener("change", sync));
  // Cards have their own fields: hand over to the card dialog, keeping the name.
  f.kind.addEventListener("change", () => {
    if (!(f.kind.value in PERSON_KINDS)) return;
    dlg.close();
    newOfKind(f.kind.value, done, { title: f.title.value, folder: folder.isNew() ? "" : folder.raw() });
  });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const meta = { title: f.title.value.trim(), username: f.username.value, url: f.url.value, notes: f.notes.value, tags: f.tags.value.split(",").map((t) => t.trim()).filter(Boolean) };
      if (existing && existing.meta.policy) meta.policy = existing.meta.policy;
      const body = existing ? { path: existing.path, meta } : { path: target(), kind: f.kind.value, meta };
      if (replacing) {
        const value = generated() ? gen.value() : f.content.value;
        if (!value) { err.textContent = generated() ? "The password is empty." : "Add the content to keep."; return; }
        body.value = value;
        const pol = generated() ? gen.policy() : null;
        if (pol) { if (existing) meta.policy = pol; else body.policy = pol; }
      }
      try {
        if (!existing && !folder.valid()) { err.textContent = "Give the new folder a name."; return; }
        await api("POST", existing ? "/v1/secrets/update" : "/v1/secrets/create", body);
        if (!existing) state.selected = body.path;
        dlg.close(); toast(existing ? "Saved" : "Added to the vault"); done();
      } catch (ex) {
        err.textContent = ex.status === 409 ? "This folder already has an item with that name."
          : ex.status === 403 && replacing ? "This access token may not set passwords by hand. Ask an admin for the write permission." : ex.message;
      }
    } },
      h("div", { class: "title" }, h("h3", {}, existing ? "Edit item" : "New item"), !existing && where),
      f.title,
      genRow, contentRow,
      h("div", { class: "two gap" }, f.username, f.url),
      !existing && h("div", { class: "two" }, h("div", {}, h("label", {}, "Folder"), folder.el), h("div", {}, h("label", {}, "Kind"), f.kind)),
      h("div", { class: "stack" }, f.tags, f.notes),
      err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, existing ? "Save changes" : "Add to vault"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  sync();
  dlg.showModal();
}

// Make a new password, look at it, decide to keep it. The old one stays in
// History in case the real system did not accept the new one.
function changeDialog(d, done) {
  const made = ["password", "api_key"].includes(d.kind);
  const gen = made ? generator(d.meta.policy) : null;
  const content = h("textarea", { class: "mono", spellcheck: "false", placeholder: "Paste the new content", autofocus: true });
  const err = h("div", { class: "error" });
  async function keep(copy) {
    err.textContent = "";
    const value = made ? gen.value() : content.value;
    if (!value) { err.textContent = made ? "The password is empty." : "Add the new content."; return; }
    const body = { path: d.path, value };
    const pol = made ? gen.policy() : null;
    if (pol) body.meta = Object.assign({}, d.meta, { policy: pol });
    try {
      await api("POST", "/v1/secrets/update", body);
      let copied = false;
      if (copy) { try { await navigator.clipboard.writeText(value); copied = true; } catch (_) { /* clipboard blocked */ } }
      dlg.close();
      toast(copied ? "Kept and copied. The old one is in History if you need it back" : "Kept. The old one is in History if you need it back");
      done();
    } catch (ex) {
      if (ex.status === 401 || ex.code === "sealed") { dlg.close(); return fail(ex); }
      err.textContent = ex.status === 403 ? "This access token may not set passwords by hand. Ask an admin for the write permission." : ex.message;
    }
  }
  const dlg = dialog(null,
    h("form", { onsubmit: (e) => { e.preventDefault(); keep(true); } },
      h("div", { class: "title" }, h("h3", {}, made ? "New password for " + itemName(d) : "Replace " + itemName(d))),
      made ? gen.el : content,
      h("p", { class: "hint" }, made
        ? "Nothing changes until you keep it. Then set it on the site or device yourself; the current password stays in History in case the new one does not take."
        : "The current content stays in History."),
      d.has_driver && h("p", { class: "hint" }, "This item also has automatic rotation set up. Changing it here does not change it on the server; use Rotate now for that."),
      err,
      h("div", { class: "actions" },
        h("button", { class: "btn primary", type: "submit" }, made ? "Keep and copy" : "Keep"),
        made && h("button", { class: "btn", type: "button", onclick: () => keep(false) }, "Keep"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Discard"),
        h("span", { class: "hint" }, SAVE_HINT))));
  quickSave(dlg);
  dlg.showModal();
}

function moveDialog(d, done) {
  const picker = folderPicker(folderOf(d.path));
  const err = h("div", { class: "error" });
  const dlg = dialog(null,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      if (!picker.valid()) { err.textContent = "Give the new folder a name."; return; }
      const dir = picker.value();
      const np = (dir ? dir + "/" : "") + leafOf(d.path);
      if (np === d.path) return dlg.close();
      try { await api("POST", "/v1/secrets/move", { path: d.path, new_path: np }); state.selected = np; dlg.close(); toast("Moved to " + folderLabel(dir)); done(); }
      catch (ex) { err.textContent = ex.status === 409 ? "That folder already has an item with this name." : ex.message; }
    } },
      h("h3", {}, "Move " + (d.meta.title || pretty(leafOf(d.path)))),
      h("p", { class: "hint" }, "History and rotation setup move with it. Its address changes, so anything that refers to the old address must be updated."),
      h("label", {}, "Move to"), picker.el, err,
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Move"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"))));
  dlg.showModal();
}

// One job per screen: rename or move on the first, deleting on its own step.
// Whatever the screen, its actions sit together at the bottom.
function folderDialog(folder, done) {
  const body = h("div", {});
  const err = h("div", { class: "error" });
  let screen = "edit";
  const name = h("input", { type: "text", value: folder ? pretty(leafOf(folder.path)) : "", placeholder: "Personal, Work, Business…", autocomplete: "off", required: true, autofocus: true });
  const parent = folderPicker(folder ? folderOf(folder.path) : state.folder || "", { exclude: folder && folder.path, label: "Inside" });
  const n = folder ? folder.count : 0;
  const things = n === 1 ? "1 item" : `${n} items`;
  const where = folder ? folderPicker(folderOf(folder.path), { exclude: folder.path, label: "Move the items to" }) : null;
  const keep = h("input", { type: "radio", name: "what", checked: true });
  const drop = h("input", { type: "radio", name: "what" });
  const finish = (msg, sel) => { if (sel !== undefined) state.folder = sel; dlg.close(); toast(msg); done(); };
  const dest = () => { const leaf = slug(name.value); const dir = parent.value(); return leaf ? (dir ? dir + "/" : "") + leaf : ""; };

  // Tokens are limited to folders by address, and do not follow a rename.
  const warn = h("p", { class: "error", hidden: true });
  if (folder && isAdmin()) {
    api("GET", "/v1/tokens").then((tokens) => {
      const hit = tokens.filter((t) => !t.revoked_at && !(t.expires_at && t.expires_at * 1000 < Date.now()) && t.rules.some((r) => r.path === folder.path || r.path.startsWith(folder.path + "/")));
      if (!hit.length) return;
      warn.textContent = `${hit.length === 1 ? "The access token " + hit[0].name + " is" : "The access tokens " + hit.map((t) => t.name).join(", ") + " are"} limited to this folder. After a rename or move ${hit.length === 1 ? "it" : "they"} will no longer reach these items; create ${hit.length === 1 ? "a new token" : "new tokens"} for the new name.`;
      warn.hidden = false;
    }).catch(() => { /* the warning is a courtesy */ });
  }

  async function save(e) {
    e.preventDefault(); err.textContent = "";
    if (!parent.valid()) { err.textContent = "Give the new parent folder a name."; return; }
    const to = dest();
    if (!to) { err.textContent = "Use letters or numbers in the name."; return; }
    if (to === "sys" || to.startsWith("sys/")) { err.textContent = "That name is kept for the vault itself. Choose another."; return; }
    try {
      if (!folder) { await api("POST", "/v1/folders/create", { path: to }); return finish("Folder created", to); }
      if (to === folder.path) return dlg.close();
      await api("POST", "/v1/folders/move", { from: folder.path, to });
      finish("Folder updated", to);
    } catch (ex) { err.textContent = ex.status === 409 ? "Some items would collide with ones already there: " + ex.message : ex.message; }
  }
  async function remove(e) {
    e.preventDefault(); err.textContent = "";
    const wipe = n > 0 && drop.checked;
    if (wipe && !confirm(`Delete the folder ${folderLabel(folder.path)} and the ${things} in it?`)) return;
    if (!wipe && n > 0 && !where.valid()) { err.textContent = "Give the new folder a name."; return; }
    const body = { path: folder.path };
    if (!wipe) body.move_to = n === 0 ? folderOf(folder.path) : where.value();
    try { await api("POST", "/v1/folders/delete", body); finish(wipe ? "Folder and items deleted" : n ? `Folder deleted, ${things} moved` : "Folder deleted", ""); }
    catch (ex) { err.textContent = ex.status === 409 ? "The destination already has an item with the same name: " + ex.message : ex.message; }
  }
  const show = (which) => { screen = which; err.textContent = ""; render(); };

  function render() {
    if (screen === "delete") {
      const label = () => (n > 0 && drop.checked ? `Delete folder and ${things}` : "Delete folder");
      const go = h("button", { class: "btn danger outline", type: "submit" }, label());
      [keep, drop].forEach((r) => { r.onchange = () => { go.textContent = label(); where.el.hidden = drop.checked; }; });
      where.el.hidden = drop.checked;
      body.replaceChildren(h("form", { onsubmit: remove },
        h("h3", {}, "Delete " + folderLabel(folder.path) + "?"),
        n === 0 ? h("p", { class: "hint" }, "This folder is empty.")
          : h("div", {},
              h("p", {}, `It holds ${things}, counting any in sub-folders. What should happen to ${n === 1 ? "it" : "them"}?`),
              h("label", { class: "check" }, keep, `Keep ${n === 1 ? "it" : "them"}, moved to`), h("div", { class: "indent" }, where.el),
              h("label", { class: "check" }, drop, `Delete ${n === 1 ? "it" : "all " + n} too`)),
        err,
        h("div", { class: "actions" }, go, h("button", { class: "btn ghost", type: "button", onclick: () => show("edit") }, "Back"))));
      return;
    }
    body.replaceChildren(h("form", { onsubmit: save },
      h("h3", {}, folder ? "Folder " + folderLabel(folder.path) : "New folder"),
      h("div", { class: "two" }, h("div", {}, h("label", {}, "Name"), name), h("div", {}, h("label", {}, "Inside"), parent.el)),
      folder && n > 0 && h("p", { class: "hint" }, `Renaming or moving it changes the address of the ${things} inside.`),
      warn, err,
      h("div", { class: "actions" },
        h("button", { class: "btn primary", type: "submit" }, folder ? "Save" : "Create folder"),
        h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        folder && h("button", { class: "link danger aside-link", type: "button", onclick: () => show("delete") }, "Delete folder…"))));
  }
  const dlg = dialog(null, body);
  render();
  dlg.showModal();
}

// ---- rotation setup -----------------------------------------------------
// Four short steps instead of a JSON box. What gets saved is the same setup
// the CLI accepts; "Show technical details" displays it for the curious.

const every = (n) => (!n ? "only when asked" : n === 365 ? "every year" : `every ${n} days`);
function rotationSummary(setup) {
  if (!setup) return "";
  const when = setup.every_days ? every(setup.every_days).replace(/^e/, "E") : "On request";
  return setup.type === "ssh" ? `${when}, on ${setup.host}` : `${when}, by ${setup.argv[0].split("/").pop()}`;
}

function rotationDialog(d, done) {
  const cur = d.driver || null;
  const m0 = cur && cur.type === "ssh" ? /^([a-z_][a-z0-9_-]*):\{\{new\}\}/.exec(cur.stdin) : null;
  const account0 = m0 ? m0[1] : d.meta.username || "";
  const st = {
    step: 0,
    how: cur && cur.type === "exec" ? "script" : "server",
    host: cur && cur.type === "ssh" ? cur.host : "",
    port: cur && cur.type === "ssh" ? cur.port || 22 : 22,
    account: account0,
    program: cur && cur.type === "exec" ? cur.argv.join(" ") : "",
    every: cur ? cur.every_days || 0 : 90,
    prep: null, checks: null, details: false, busy: false,
  };
  const STEPS = ["How", "Where", "Check", "Schedule"];
  const body = h("div", {});
  const err = h("div", { class: "error" });
  const pattern = () => (d.meta.policy && d.meta.policy.type === "password" ? d.meta.policy.length : 24) + "-character";

  function setup() {
    const base = st.how === "server"
      ? { type: "ssh", host: st.host.trim(), port: Number(st.port) || 22, user: "root", command: "chpasswd", stdin: `${st.account.trim()}:{{new}}\n`, timeout_secs: 30 }
      : { type: "exec", argv: st.program.trim().split(/\s+/).filter(Boolean), stdin: "{{new}}", timeout_secs: 30 };
    if (st.every) base.every_days = st.every;
    return base;
  }
  const sentence = () => {
    const what = st.how === "server"
      ? `the vault signs in to ${st.host.trim()} and sets a new ${pattern()} password for ${st.account.trim()}`
      : `the vault runs ${st.program.trim().split(/\s+/)[0] || "your program"} and hands it a new ${pattern()} password`;
    return st.every ? `${every(st.every).replace(/^e/, "E")}, ${what}. It can also be rotated on request.` : `When someone asks, ${what}.`;
  };
  async function busy(fn) {
    if (st.busy) return;
    st.busy = true; err.textContent = ""; render();
    try { await fn(); } catch (e) { if (e.status === 401 || e.code === "sealed") { dlg.close(); return fail(e); } err.textContent = e.message; }
    st.busy = false; render();
  }
  const goto = (n) => { st.step = n; err.textContent = ""; render(); };

  async function prepare() {
    st.prep = await api("POST", "/v1/rotation/prepare", { host: st.host.trim(), port: Number(st.port) || 22, account: st.account.trim() });
    st.checks = null;
    st.step = 2;
  }
  async function next() {
    if (st.step === 0) return goto(1);
    if (st.step === 1) {
      if (st.how === "server") {
        if (!st.host.trim() || !st.account.trim()) { err.textContent = "Fill in the server and the account."; return; }
        return busy(prepare);
      }
      if (!st.program.trim().startsWith("/")) { err.textContent = "Give the full path of the program, starting with /."; return; }
      return goto(3);
    }
    if (st.step === 2) return goto(3);
  }
  async function save(rotateNow) {
    await busy(async () => {
      await api("POST", "/v1/secrets/driver", { path: d.path, driver: setup() });
      if (rotateNow) {
        const r = await api("POST", "/v1/secrets/rotate", { path: d.path });
        dlg.close(); done();
        return r.rotated ? toast("Rotation set up, and rotated just now") : toast("Saved, but the first rotation failed. Old password kept: " + r.error, true);
      }
      dlg.close(); toast("Rotation set up"); done();
    });
  }

  function stepHow() {
    const card = (id, title, text) => h("button", { class: "choice" + (st.how === id ? " on" : ""), type: "button", "aria-pressed": st.how === id ? "true" : "false", onclick: () => { st.how = id; render(); } },
      lamp(st.how === id ? "blue" : ""), h("span", {}, h("b", {}, title), h("small", {}, text)));
    return [h("div", { class: "q" }, "How does this password get changed?"),
      h("div", { class: "choices" },
        card("server", "A user on a server", "Change a Linux or Mac account's password over SSH."),
        card("script", "My own script", "A program on the vault host does the change, for anything else.")),
      h("p", { class: "hint" }, "Databases and web apps do not have their own option yet; use a script for those.")];
  }
  function stepWhere() {
    const bind = (key, attrs) => { const el = h("input", Object.assign({ type: "text", value: st[key], autocomplete: "off", spellcheck: "false" }, attrs)); el.addEventListener("input", () => { st[key] = el.value; }); return el; };
    if (st.how === "script") {
      return [h("div", { class: "q" }, "Which program?"),
        h("label", {}, "Program on the vault host, with any arguments"), bind("program", { placeholder: "/usr/local/bin/rotate-gitea admin", class: "mono", autofocus: true }),
        h("p", { class: "hint" }, "The new password is sent to the program's input, never on its command line. It should exit with 0 only when the change worked.")];
    }
    const port = bind("port", { inputmode: "numeric", "aria-label": "Port" });
    const portRow = h("div", { hidden: Number(st.port) === 22 }, h("label", {}, "Port"), port);
    return [h("div", { class: "q" }, "Where is it?"),
      h("div", { class: "two" },
        h("div", {}, h("label", {}, "Server"), bind("host", { placeholder: "name or address", autofocus: true })),
        h("div", {}, h("label", {}, "Account whose password changes"), bind("account", { placeholder: "username on that server" }))),
      Number(st.port) === 22 && h("p", { class: "hint" }, "Uses the standard port, 22. ", h("button", { class: "link", type: "button", onclick: (e) => { portRow.hidden = false; e.target.parentNode.hidden = true; } }, "Use another")),
      portRow,
      h("p", { class: "hint" }, "The vault signs in as root with its own key, limited on the server to changing this one account.")];
  }
  function stepCheck() {
    const p = st.prep, k = p.host_key, c = st.checks;
    const host = st.host.trim();
    let ident;
    if (!k) ident = h("div", { class: "fp" }, lamp("red"), h("span", { class: "grow" }, p.scan_error || "Could not reach the server."), h("button", { class: "link", type: "button", onclick: () => busy(prepare) }, "Try again"));
    else {
      const trustIt = (label, cls) => h("button", { class: cls, type: "button", onclick: () => busy(async () => { await api("POST", "/v1/rotation/trust", { host, port: Number(st.port) || 22, key_type: k.key_type, key: k.key }); k.status = "trusted"; st.checks = null; }) }, label);
      ident = h("div", { class: "fp" }, lamp(k.status === "trusted" ? "green" : k.status === "changed" ? "red" : "amber"),
        h("span", { class: "grow" }, h("small", {}, `${host} identifies itself as`), h("span", { class: "mono" }, k.fingerprint)),
        k.status === "trusted" ? h("b", { class: "ok" }, "Trusted") : k.status === "changed" ? trustIt("Trust the new identity", "btn small danger outline") : trustIt("Yes, trust it", "btn small primary"));
    }
    const line = (ok, text) => h("li", {}, lamp(c ? (ok ? "green" : "red") : ""), text);
    const passed = c && c.reached && c.identity && c.signed_in && c.allowed;
    return [
      h("div", { class: "q" }, "1.  Confirm this is the right server"), ident,
      k && k.status === "changed" && h("p", { class: "error" }, "This is not the identity trusted before. That happens after a reinstall, or when something is impersonating the server. Only continue if you know why."),
      k && k.status === "new" && h("p", { class: "hint" }, "To be sure, compare with the output of ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub on the server."),
      h("div", { class: "q" }, `2.  Allow the vault on ${host}, once`),
      h("p", { class: "hint" }, `Run this on the server as root. It lets the vault change ${st.account.trim()} and nothing else: no shell, no other accounts. Skip it if you have already done so for this account.`),
      h("div", { class: "scriptbox" }, h("pre", { tabindex: "0" }, p.script),
        h("button", { class: "btn small", type: "button", onclick: async () => { try { await navigator.clipboard.writeText(p.script); toast("Copied. Paste it into a root shell on " + host); } catch (_) { toast("Copy failed, select it by hand", true); } } }, "Copy")),
      h("div", { class: "q" }, "3.  Test"),
      h("div", { class: "testrow" },
        h("ul", { class: "checks" }, line(c && c.reached, `Reached ${host}`), line(c && c.identity, "Server identity matches"), line(c && c.signed_in, "Signed in with the vault's key"), line(c && c.allowed, `Allowed to change ${st.account.trim()}`)),
        h("div", { class: "aside" },
          h("b", {}, passed ? "Ready." : c ? "Not yet." : "Nothing gets changed."), h("small", {}, passed ? "The vault can rotate this password." : c ? c.message : "The test only checks access."),
          h("button", { class: "btn small" + (c ? "" : " primary"), type: "button", disabled: st.busy || !k || k.status !== "trusted", onclick: () => busy(async () => { st.checks = await api("POST", "/v1/rotation/test", { host, port: Number(st.port) || 22, account: st.account.trim() }); }) }, st.busy ? "Testing…" : c ? "Test again" : "Run the test")))];
  }
  function stepSchedule() {
    const opt = (n, label) => h("button", { class: "seg" + (st.every === n ? " on" : ""), type: "button", "aria-pressed": st.every === n ? "true" : "false", onclick: () => { st.every = n; render(); } }, st.every === n && lamp("green"), label);
    return [h("div", { class: "q" }, "How often should it change?"),
      h("div", { class: "segs" }, opt(0, "Only when asked"), opt(30, "Every 30 days"), opt(90, "Every 90 days"), opt(365, "Every year")),
      h("p", { class: "hint" }, "People and agents with the Rotate permission can still do it any time. Scheduled changes pause while the vault is sealed."),
      h("div", { class: "q" }, "If a rotation fails"),
      h("div", { class: "fp" }, lamp("green"), h("span", { class: "grow" }, "The old password stays in use. Nothing breaks.", h("small", {}, "The attempt is kept in the item's history, and a scheduled one is tried again the next day."))),
      h("div", { class: "sentence" }, sentence())];
  }

  function render() {
    const passed = st.checks && st.checks.reached && st.checks.identity && st.checks.signed_in && st.checks.allowed;
    const last = st.step === 3;
    // Through h() so that skipped (false) pieces are dropped, not printed.
    body.replaceChildren(h("div", {},
      h("h3", {}, "Set up rotation for " + itemName(d)),
      h("ol", { class: "steps" }, STEPS.map((n, i) => (st.how === "script" && i === 2 ? null : h("li", { class: i === st.step ? "now" : i < st.step ? "done" : "" }, lamp(i < st.step ? "green" : i === st.step ? "blue" : ""), n)))),
      ...[stepHow, stepWhere, stepCheck, stepSchedule][st.step](),
      st.details && h("pre", { class: "details" }, JSON.stringify(setup(), null, 2)),
      err,
      h("div", { class: "actions" },
        last ? h("button", { class: "btn go", type: "button", disabled: st.busy, onclick: () => save(true) }, st.busy ? "Working…" : "Save and rotate now")
             : h("button", { class: "btn primary", type: "button", disabled: st.busy || (st.step === 2 && !passed), onclick: next }, st.busy && st.step === 1 ? "Contacting the server…" : "Continue"),
        last && h("button", { class: "btn", type: "button", disabled: st.busy, onclick: () => save(false) }, "Save only"),
        st.step > 0 ? h("button", { class: "btn ghost", type: "button", onclick: () => goto(st.how === "script" && st.step === 3 ? 1 : st.step - 1) }, "Back") : h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel"),
        st.step === 0 && d.has_driver && h("button", { class: "btn danger ghost", type: "button", onclick: () => confirm("Remove rotation for this item? Its password will only change by hand.") && busy(async () => { await api("POST", "/v1/secrets/driver", { path: d.path, driver: null }); dlg.close(); toast("Rotation removed"); done(); }) }, "Remove rotation"),
        st.step > 0 && h("button", { class: "link aside-link", type: "button", onclick: () => { st.details = !st.details; render(); } }, st.details ? "Hide technical details" : "Show technical details"))));
    const first = body.querySelector("[autofocus]"); if (first && document.activeElement === document.body) first.focus();
  }
  const dlg = dialog("wide", body);
  render();
  dlg.showModal();
}

// ---- import from another password manager -------------------------------
// The export file is read here in the browser and each login is added
// through the normal API. The file itself is never uploaded or stored.

function parseCsv(text) {
  const rows = []; let row = [], field = "", quoted = false;
  text = text.replace(/^\uFEFF/, "");
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\r" && text[i + 1] === "\n") { /* handled by the newline */ }
    else if (c === "\n" || c === "\r") { row.push(field); field = ""; rows.push(row); row = []; }
    else field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((f) => f.trim() !== ""));
}

const IMPORT_COLUMNS = {
  title: ["title", "name", "account", "group/title"],
  url: ["url", "urls", "website", "login_uri", "web site", "origin"],
  username: ["username", "login_username", "user name", "login name", "user"],
  email: ["email", "e-mail"],
  password: ["password", "login_password"],
  notes: ["notes", "note", "extra", "notesplain", "comments"],
  tags: ["tags"],
  folder: ["folder", "grouping", "group"],
  otp: ["otpauth", "login_totp", "totp", "otp"],
};

// Turn an export into plain rows. Throws with a message a person can act on.
function readExport(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error("That file has no rows. Export as CSV from your password manager and choose that file.");
  const header = rows.shift().map((x) => x.trim().toLowerCase());
  const col = {};
  for (const [k, names] of Object.entries(IMPORT_COLUMNS)) col[k] = header.findIndex((x) => names.includes(x));
  if (col.password < 0) throw new Error("That file has no password column. It should be a CSV export with columns like name, url, username, password.");
  const from = header.includes("cardholdername") ? "NordPass" : header.includes("otpauth") || header.includes("archived") ? "1Password" : header.includes("login_uri") ? "Bitwarden" : header.includes("grouping") ? "LastPass" : header.includes("timepasswordchanged") ? "Firefox" : "your password manager";
  const get = (r, k) => (col[k] >= 0 && r[col[k]] != null ? r[col[k]].trim() : "");
  const out = { from, items: [], noPassword: 0, codes: 0, tooLong: 0, hasFolders: false };
  for (const r of rows) {
    const password = col.password >= 0 && r[col.password] != null ? r[col.password] : "";
    if (!password) { out.noPassword++; continue; }
    if (password.length > 16000) { out.tooLong++; continue; }
    if (get(r, "otp")) out.codes++;
    const folder = get(r, "folder");
    if (folder) out.hasFolders = true;
    out.items.push({
      title: get(r, "title").slice(0, 200), url: get(r, "url").split(/[,\n]/)[0].trim().slice(0, 2048), username: (get(r, "username") || get(r, "email")).slice(0, 256),
      password, notes: get(r, "notes").slice(0, 8000), folder,
      tags: get(r, "tags").split(/[,;]/).map((t) => t.trim().slice(0, 64)).filter(Boolean).slice(0, 32),
    });
  }
  return out;
}

const hostOf = (url) => (url.split("://")[1] || url).split(/[/?#:]/)[0];

// Add the rows to the vault. Items already there (same place, same username
// and site) are left alone; name clashes with different logins get a suffix.
async function runImport(items, dest, keepFolders, onProgress) {
  const known = new Map(state.secrets.map((x) => [x.path, x]));
  const res = { added: 0, already: 0, failed: [] };
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    onProgress(i, items.length);
    const sub = keepFolders && it.folder ? it.folder.split(/[/\\]/).map(slug).filter(Boolean) : [];
    const base = [dest, ...sub, slug(it.title || hostOf(it.url)) || "item"].filter(Boolean).join("/");
    const meta = { title: it.title, username: it.username, url: it.url, notes: it.notes, tags: it.tags };
    let done = false;
    for (let n = 1; n <= 30 && !done; n++) {
      const path = n === 1 ? base : `${base}-${n}`;
      const have = known.get(path);
      if (have) {
        if (have.meta.username === it.username && have.meta.url === it.url) { res.already++; done = true; }
        continue;
      }
      try {
        const made = await api("POST", "/v1/secrets/create", { path, kind: "password", meta, value: it.password });
        known.set(path, made); res.added++; done = true;
      } catch (e) {
        if (e.status === 409) { known.set(path, { meta: {} }); continue; }
        if (e.status === 401 || e.status === 403 || e.code === "sealed") { e.partial = res; throw e; }
        res.failed.push(`${it.title || path}: ${e.message}`); done = true;
      }
    }
    if (!done) res.failed.push(`${it.title || base}: no free name`);
  }
  onProgress(items.length, items.length);
  return res;
}

function importDialog(done) {
  const body = h("div", {});
  let data = null, busy = false;
  const dest = folderPicker(state.folder || "", { label: "Put them in" });
  const keepFolders = h("input", { type: "checkbox", checked: true });
  const file = h("input", { type: "file", accept: ".csv,text/csv", "aria-label": "Export file" });
  const err = h("div", { class: "error" });
  file.addEventListener("change", async () => {
    err.textContent = ""; data = null;
    const f = file.files && file.files[0];
    if (!f) return render();
    if (f.size > 20 * 1024 * 1024) { err.textContent = "That file is larger than 20 MB."; return render(); }
    try { data = readExport(await f.text()); } catch (e) { err.textContent = e.message; }
    render();
  });
  function render(result, progress) {
    const n = data ? data.items.length : 0;
    body.replaceChildren(h("div", {},
      h("h3", {}, "Import from another password manager"),
      result ? [
        h("p", {}, h("span", { class: "st" }, lamp(result.failed.length ? "amber" : "green"), `${result.added} added.`), result.already > 0 && ` ${result.already} were already in the vault and left alone.`),
        result.failed.length > 0 && h("pre", { class: "details" }, result.failed.slice(0, 50).join("\n")),
        h("p", { class: "error" }, "Now delete the export file from your computer and empty the trash. It holds every one of those passwords in plain text."),
        h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", onclick: () => dlg.close() }, "Done")),
      ] : [
        h("p", { class: "hint" }, "Export your logins as a CSV file from 1Password, NordPass, Bitwarden, LastPass, KeePassXC, Chrome, Edge or Firefox, then choose that file. It is read here in your browser and never uploaded as a file."),
        file,
        data && h("div", {},
          h("p", {}, h("span", { class: "st" }, lamp("green"), `${n} ${n === 1 ? "login" : "logins"} found, from ${data.from}.`)),
          (data.noPassword > 0 || data.codes > 0 || data.tooLong > 0) && h("p", { class: "hint" },
            [data.noPassword > 0 && `${data.noPassword} without a password (notes, cards, identities) will be skipped.`, data.codes > 0 && `${data.codes} have one-time codes; the logins are imported, the codes are not.`, data.tooLong > 0 && `${data.tooLong} are too large and will be skipped.`].filter(Boolean).join(" ")),
          h("label", {}, "Put them in"), dest.el,
          data.hasFolders && h("label", { class: "check" }, keepFolders, "Keep the folders from the file, inside that one")),
        progress && h("p", { class: "st" }, lamp("amber"), progress),
        err,
        h("div", { class: "actions" },
          h("button", { class: "btn primary", type: "button", disabled: !n || busy, onclick: go }, busy ? "Importing…" : n ? `Import ${n} ${n === 1 ? "login" : "logins"}` : "Import"),
          h("button", { class: "btn ghost", type: "button", disabled: busy, onclick: () => dlg.close() }, "Cancel")),
      ]));
  }
  async function go() {
    if (busy || !data) return;
    err.textContent = "";
    let where;
    try { where = await dest.ensure(); } catch (e) { err.textContent = e.message; return; }
    busy = true; render(null, "Starting…");
    try {
      const res = await runImport(data.items, where, keepFolders.checked, (i, n) => { const p = body.querySelector("p.st"); if (p) p.lastChild.textContent = `Importing ${Math.min(i + 1, n)} of ${n}…`; });
      busy = false; data = null; render(res); done();
    } catch (e) {
      busy = false;
      if (e.status === 401 || e.code === "sealed") { dlg.close(); return fail(e); }
      const part = e.partial ? ` ${e.partial.added} were added before it stopped.` : "";
      err.textContent = (e.status === 403 ? "This access token may not add passwords here. It needs Add items and Set passwords by hand on that folder." : e.message) + part;
      render(); done();
    }
  }
  const dlg = dialog(null, body);
  dlg.addEventListener("cancel", (e) => { if (busy) e.preventDefault(); });
  render();
  dlg.showModal();
}

// ----------------------------------------------------------------- tokens

const stateLamp = (s) => ({ active: "green", ok: "green", current: "green", pending: "amber", denied: "red", error: "red", failed: "red", revoked: "red", expired: "amber", rejected: "amber" })[s] || "";
const stateCell = (s) => h("span", { class: "st" }, lamp(stateLamp(s)), s);

async function viewTokens(main) {
  const body = h("tbody", {});
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", { class: "grow" }, "Access tokens"), h("button", { class: "btn primary", onclick: () => tokenDialog(load) }, "New token")),
    h("div", { class: "tablewrap" }, h("table", { class: "plain" },
      h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", {}, "Role"), h("th", {}, "Can do"), h("th", {}, "Last used"), h("th", {}, "Expires"), h("th", {}, "State"), h("th", {}))), body)));
  async function load() {
    let rows;
    try { rows = await api("GET", "/v1/tokens"); } catch (e) { return fail(e); }
    body.replaceChildren(...rows.map((t) => {
      const st = t.revoked_at ? "revoked" : t.expires_at && t.expires_at * 1000 < Date.now() ? "expired" : "active";
      return h("tr", {},
        h("td", {}, t.name, h("div", { class: "hint mono" }, t.id)),
        h("td", {}, t.role),
        h("td", {}, t.role === "admin" ? "Everything" : t.rules.length ? t.rules.map((r) => h("div", {}, h("b", {}, scopeLabel(r.path)), "  ", r.caps.map((c) => (CAPS[c] || [c])[0]).join(", "))) : "Nothing"),
        h("td", { class: "nw" }, fmt(t.last_used_at)), h("td", { class: "nw" }, t.expires_at ? fmt(t.expires_at) : "never"),
        h("td", {}, stateCell(st)),
        h("td", {}, st === "active" && t.id !== state.me.id && h("button", { class: "link danger", onclick: async () => {
          if (!confirm(`Revoke the token ${t.name}? Anything using it stops working immediately.`)) return;
          try { await api("POST", "/v1/tokens/revoke", { id: t.id }); toast("Revoked"); load(); } catch (e) { fail(e); }
        } }, "Revoke")));
    }));
  }
  load();
}

// Permissions in the words a person would use, with the technical name the
// CLI and access rules use.
const CAPS = {
  list: ["See items", "Names, sites, usernames and history. Never the passwords themselves."],
  create: ["Add items", "Create new items; the vault generates the password."],
  update: ["Edit details", "Change name, username, website, tags and notes."],
  generate: ["Generate", "Have the vault make a new password without showing it."],
  rotate: ["Rotate", "Change a password on the live system through its rotation setup."],
  delete: ["Delete and move", "Delete items, or move them to another folder."],
  write: ["Set passwords by hand", "Store a password of its own choosing, which it then knows. Needed for imports."],
  reveal: ["Read passwords", "See the actual passwords. Never available to agents."],
};
const scopeLabel = (p) => (p === "**" ? "Everything" : p === "sys/update" ? "Vault updates" : p.endsWith("/**") ? folderLabel(p.slice(0, -3)) : p);
const ALL = "\u0000all", CUSTOM = "\u0000custom";

function tokenDialog(done) {
  const name = h("input", { type: "text", placeholder: "claude-mac, backup-script…", required: true, pattern: "[A-Za-z0-9._\\-]{1,64}", title: "Letters, numbers, dots, dashes and underscores", autocomplete: "off", autofocus: true });
  const role = h("select", {}, [["agent", "An agent or script (can never read passwords)"], ["human", "A person"], ["admin", "An admin (everything)"]].map(([r, l]) => h("option", { value: r }, l)));
  const where = folderPicker(state.folder || ALL, { noRoot: true, label: "Where it applies", extra: [[ALL, "Everything in the vault"]], tail: [[CUSTOM, "A custom pattern…"]] });
  const pattern = h("input", { type: "text", class: "mono", placeholder: "work/*/prod/**", spellcheck: "false", autocomplete: "off", hidden: true, "aria-label": "Custom pattern" });
  pattern.style.marginTop = "8px";
  const ttl = h("input", { type: "number", min: "1", max: "3650", placeholder: "Never" });
  const boxes = Object.keys(CAPS).map((c) => [c, h("input", { type: "checkbox", checked: ["list", "create", "generate", "rotate"].includes(c) })]);
  const updates = h("input", { type: "checkbox" });
  const err = h("div", { class: "error" });
  const scope = h("div", {}, h("label", {}, "Where it applies"), where.el, pattern, h("label", {}, "What it may do"),
    h("div", { class: "opts row plain" }, boxes.map(([c, b]) => h("label", { class: "chip", title: CAPS[c][1] }, b, h("span", {}, CAPS[c][0])))),
    h("label", { class: "check", title: "Check for and install signed vault releases. Installing restarts the vault sealed." }, updates, "May install vault updates"));
  const sync = () => {
    scope.hidden = role.value === "admin";
    pattern.hidden = where.raw() !== CUSTOM;
    const rv = boxes.find(([c]) => c === "reveal");
    rv[1].disabled = role.value === "agent";
    if (role.value === "agent") rv[1].checked = false;
  };
  role.addEventListener("change", sync);
  where.el.addEventListener("change", sync);
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); err.textContent = "";
    const body = { name: name.value.trim(), role: role.value, rules: [], ttl_days: ttl.value ? Number(ttl.value) : null };
    try {
      if (role.value !== "admin") {
        let path;
        if (where.raw() === ALL) path = "**";
        else if (where.raw() === CUSTOM) { path = pattern.value.trim(); if (!path) { err.textContent = "Type the pattern, or pick a folder."; return; } }
        else path = (await where.ensure()) + "/**";
        const caps = boxes.filter(([, b]) => b.checked).map(([c]) => c);
        if (!caps.length && !updates.checked) { err.textContent = "Choose at least one thing it may do."; return; }
        if (caps.length) body.rules.push({ path, caps });
        if (updates.checked) body.rules.push({ path: "sys/update", caps: ["upgrade"] });
      }
      const r = await api("POST", "/v1/tokens/create", body);
      form.replaceChildren(h("h3", {}, "Token created"), h("p", { class: "hint" }, "Copy it now. It is shown once and cannot be recovered."),
        h("div", { class: "once" }, r.token),
        h("div", { class: "actions" },
          h("button", { class: "btn primary", type: "button", onclick: async (e) => { try { await navigator.clipboard.writeText(r.token); e.currentTarget.textContent = "Copied"; toast("Copied"); } catch (_) { toast("Copy failed, select it by hand", true); } } }, "Copy token"),
          h("button", { class: "btn ghost", type: "button", onclick: () => { dlg.close(); done(); } }, "Done")));
    } catch (ex) { err.textContent = ex.message; }
  } },
    h("h3", {}, "New access token"),
    h("div", { class: "two" }, h("div", {}, h("label", {}, "Name"), name), h("div", {}, h("label", {}, "Who it is for"), role)),
    scope, h("label", {}, "Expires after this many days"), ttl, err,
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Create token"),
      h("button", { class: "btn ghost", type: "button", onclick: () => dlg.close() }, "Cancel")));
  const dlg = dialog(null, form);
  sync();
  dlg.showModal();
}

// ------------------------------------------------------------------ audit

async function viewAudit(main) {
  const body = h("tbody", {});
  const chain = h("span", { class: "st" }, lamp(""), "Checking the log…");
  const more = h("button", { class: "btn", onclick: () => load(false) }, "Load older entries");
  more.style.marginTop = "14px";
  let oldest = null;
  main.replaceChildren(
    h("div", { class: "head" }, h("h2", {}, "Audit log"), chain, h("div", { class: "grow" }),
      h("button", { class: "btn", onclick: verify }, "Check for tampering"), h("button", { class: "btn", onclick: () => load(true) }, "Refresh")),
    h("div", { class: "tablewrap" }, h("table", { class: "plain" },
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, "Time"), h("th", {}, "Who"), h("th", {}, "Did"), h("th", {}, "Item"), h("th", {}, "Result"), h("th", {}, "Detail"))), body)),
    more);
  async function verify() {
    try {
      const r = await api("GET", "/v1/audit/verify");
      chain.replaceChildren(lamp(r.intact ? "green" : "red"), r.intact ? `Untampered, ${r.rows} entries` : `Tampered with at entry ${r.first_bad_seq}`);
    } catch (e) { fail(e); }
  }
  async function load(reset) {
    if (reset) { oldest = null; body.replaceChildren(); }
    let rows;
    try { rows = await api("GET", "/v1/audit?limit=100" + (oldest ? "&before=" + oldest : "")); } catch (e) { return fail(e); }
    more.hidden = rows.length < 100;
    if (rows.length) oldest = rows[rows.length - 1].seq;
    body.append(...rows.map((r) => h("tr", {},
      h("td", { class: "num" }, r.seq), h("td", { class: "nw mono" }, fmt(r.ts)), h("td", { class: "mono" }, who(r.actor)), h("td", { class: "mono" }, r.action),
      h("td", { class: "mono" }, r.path), h("td", {}, stateCell(r.outcome)), h("td", {}, r.detail))));
  }
  load(true); verify();
}

// ---------------------------------------------------------------- updates

async function viewUpdates(main) {
  const box = h("div", { class: "panel" });
  main.replaceChildren(h("div", { class: "head" }, h("h2", {}, "Updates")), box);
  let timer;
  const busy = (s) => ["checking", "downloading", "installing"].includes(s);
  async function send(body) {
    try { await api("POST", "/v1/sys/update", body); toast("Requested"); setTimeout(load, 1500); } catch (e) { fail(e); }
  }
  async function load() {
    clearTimeout(timer);
    if (state.view !== "updates" || !box.isConnected) return;
    let s;
    try { s = await api("GET", "/v1/sys/update"); }
    catch (e) { if (e.status) return fail(e); timer = setTimeout(load, 2000); return box.replaceChildren(h("p", { class: "hint" }, "The vault is restarting…")); }
    const hp = (s.enabled && s.helper) || {};
    const latest = hp.latest || "";
    const newer = latest && latest !== s.current;
    box.replaceChildren(
      h("dl", { class: "kv" },
        h("dt", {}, "Installed"), h("dd", { class: "mono" }, s.current),
        h("dt", {}, "Latest"), h("dd", { class: "mono" }, latest || "Not checked yet"),
        h("dt", {}, "Status"), h("dd", {}, hp.state ? h("span", { class: "st" }, lamp(hp.state === "failed" ? "red" : busy(hp.state) ? "amber" : "green"), hp.message || hp.state) : "—"),
        h("dt", {}, "Last run"), h("dd", {}, hp.ts ? fmt(hp.ts) : "—")),
      s.enabled
        ? h("div", { class: "row" },
            h("button", { class: "btn", disabled: busy(hp.state), onclick: () => send({ action: "check" }) }, "Check for updates"),
            newer && h("button", { class: "btn primary", disabled: busy(hp.state), onclick: () => confirm(`Install ${latest}? The vault will restart and stay sealed until you enter the passphrase.`) && send({ action: "apply", version: latest }) }, "Install " + latest))
        : h("p", {}, "Updates are switched off. They turn on once your release signing key is installed on the vault host, so that only releases you signed can ever be installed."),
      h("p", { class: "hint" }, "Only releases signed with your release key are accepted. The signature is checked by a separate root helper, not by the vault itself, and a version that fails to start is rolled back automatically."));
    if (busy(hp.state) || s.pending_request) timer = setTimeout(load, 1500);
  }
  load();
}

boot();
