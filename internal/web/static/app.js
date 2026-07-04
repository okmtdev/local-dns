"use strict";

const state = {
  status: null,
  devices: [],
  mappings: [],
};

const $ = (id) => document.getElementById(id);

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Rows animate in only on the very first render.
let firstRenderDone = false;

// ---- API ----

async function api(path, options = {}) {
  const opts = { headers: {}, ...options };
  if (opts.body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty body */
  }
  if (!res.ok) {
    throw new Error((data && data.error) || `エラー (HTTP ${res.status})`);
  }
  return data;
}

// ---- rendering helpers ----

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function animateRow(tr, index) {
  if (firstRenderDone || reducedMotion) return;
  tr.classList.add("row-in");
  tr.style.animationDelay = `${Math.min(index * 45, 500)}ms`;
}

function relativeTime(iso) {
  if (!iso) return "-";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "-";
  const sec = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (sec < 10) return "たった今";
  if (sec < 60) return `${sec}秒前`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}分前`;
  const hour = Math.round(min / 60);
  if (hour < 24) return `${hour}時間前`;
  return new Date(iso).toLocaleString("ja-JP");
}

let toastTimer = null;
function toast(message, isError = false) {
  const node = $("toast");
  node.textContent = (isError ? "[ERR] " : "[ OK ] ") + message;
  node.className = "toast" + (isError ? " error" : "");
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 4000);
}

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(
      () => toast(`コピーしました: ${text}`),
      () => toast("コピーに失敗しました", true)
    );
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    toast(`コピーしました: ${text}`);
  } catch {
    toast("コピーに失敗しました", true);
  }
  document.body.removeChild(ta);
}

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

// ---- devices table ----

function renderDevices() {
  const tbody = $("devicesBody");
  tbody.textContent = "";
  const online = state.devices.filter((d) => d.online).length;
  $("deviceSummary").textContent =
    `${state.devices.length} 台登録 / ${online} 台オンライン`;

  if (state.devices.length === 0) {
    const tr = el("tr");
    const td = el("td", "muted", "デバイスが見つかりません。スキャンをお待ちください…");
    td.colSpan = 8;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  state.devices.forEach((d, i) => {
    const tr = el("tr");
    animateRow(tr, i);

    const tdStatus = el("td");
    const dot = el("span", "dot" + (d.online ? " online" : ""));
    dot.title = d.online ? "オンライン" : "オフライン";
    tdStatus.appendChild(dot);
    tr.appendChild(tdStatus);

    const tdName = el("td");
    const nameDiv = el("div", "dev-name", d.display_name);
    if (d.self) {
      nameDiv.appendChild(el("span", "self-badge", "このサーバ"));
    }
    tdName.appendChild(nameDiv);
    if (d.label && d.hostname && d.label !== d.hostname) {
      tdName.appendChild(el("div", "dev-sub", d.hostname));
    }
    tr.appendChild(tdName);

    const tdIP = el("td");
    tdIP.appendChild(el("span", "mono", d.ip || "-"));
    tr.appendChild(tdIP);

    const tdMAC = el("td");
    const mac = el("span", "mono", d.mac);
    mac.style.cursor = "copy";
    mac.title = "クリックでコピー";
    mac.addEventListener("click", () => copyText(d.mac));
    tdMAC.appendChild(mac);
    tr.appendChild(tdMAC);

    tr.appendChild(el("td", "", d.vendor || "-"));
    tr.appendChild(el("td", "muted", relativeTime(d.last_seen)));

    const tdNames = el("td");
    if (d.names.length === 0) {
      tdNames.appendChild(el("span", "muted", "-"));
    }
    for (const n of d.names) {
      const chip = el("span", "chip", n.fqdn);
      chip.title = "クリックでコピー";
      chip.addEventListener("click", () => copyText(n.fqdn));
      tdNames.appendChild(chip);
    }
    tr.appendChild(tdNames);

    const tdActions = el("td");
    const actions = el("div", "actions");
    const assignBtn = el("button", "btn small", "＋ DNS名");
    assignBtn.type = "button";
    assignBtn.addEventListener("click", () => openAssignDialog(d));
    actions.appendChild(assignBtn);
    const labelBtn = el("button", "btn small", "ラベル");
    labelBtn.type = "button";
    labelBtn.addEventListener("click", () => openLabelDialog(d));
    actions.appendChild(labelBtn);
    const delBtn = el("button", "btn small danger", "削除");
    delBtn.type = "button";
    delBtn.addEventListener("click", () => deleteDevice(d));
    actions.appendChild(delBtn);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });
}

async function deleteDevice(d) {
  const name = d.display_name || d.mac;
  if (!confirm(`デバイス「${name}」を一覧から削除しますか?\n(ネットワーク上に存在すれば次回スキャンで再登録されます)`)) {
    return;
  }
  try {
    await api(`/api/devices/${encodeURIComponent(d.mac)}`, { method: "DELETE" });
    toast("デバイスを削除しました");
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---- mappings table ----

function renderMappings() {
  const tbody = $("mappingsBody");
  tbody.textContent = "";
  $("mappingSummary").textContent = `${state.mappings.length} 件`;

  if (state.mappings.length === 0) {
    const tr = el("tr");
    const td = el(
      "td",
      "muted",
      "マッピングがまだありません。上のフォームまたはデバイス一覧の「＋ DNS名」から追加できます。"
    );
    td.colSpan = 6;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  state.mappings.forEach((m, i) => {
    const tr = el("tr");
    animateRow(tr, i);

    const tdFqdn = el("td");
    const chip = el("span", "chip", m.fqdn);
    chip.title = "クリックでコピー";
    chip.addEventListener("click", () => copyText(m.fqdn));
    tdFqdn.appendChild(chip);
    tr.appendChild(tdFqdn);

    const tdTarget = el("td");
    if (m.static) {
      tdTarget.appendChild(el("span", "", "固定IP "));
      tdTarget.appendChild(el("span", "mono", m.ip));
    } else {
      const label = m.device_name ? `${m.device_name} ` : "";
      if (label) tdTarget.appendChild(el("span", "", label));
      tdTarget.appendChild(el("span", "mono dev-sub", m.mac));
    }
    tr.appendChild(tdTarget);

    const tdIP = el("td");
    tdIP.appendChild(el("span", "mono", m.current_ip || "未検出"));
    tr.appendChild(tdIP);

    const tdStatus = el("td");
    const dot = el("span", "dot" + (m.online ? " online" : ""));
    dot.title = m.online ? "解決可能" : "デバイス未検出";
    tdStatus.appendChild(dot);
    tr.appendChild(tdStatus);

    tr.appendChild(el("td", "muted", m.note || "-"));

    const tdActions = el("td");
    const actions = el("div", "actions");
    const editBtn = el("button", "btn small", "編集");
    editBtn.type = "button";
    editBtn.addEventListener("click", () => openEditDialog(m));
    actions.appendChild(editBtn);
    const delBtn = el("button", "btn small danger", "削除");
    delBtn.type = "button";
    delBtn.addEventListener("click", () => deleteMapping(m));
    actions.appendChild(delBtn);
    tdActions.appendChild(actions);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });
}

async function deleteMapping(m) {
  if (!confirm(`DNS名「${m.fqdn}」を削除しますか?`)) return;
  try {
    await api(`/api/mappings/${encodeURIComponent(m.hostname)}`, {
      method: "DELETE",
    });
    toast("マッピングを削除しました");
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---- mapping form ----

// fillTargetSelect populates a target <select> with the known devices
// plus a "static IP" entry. extraMAC keeps a mapping's current target
// selectable even when that device is not in the registry (anymore).
function fillTargetSelect(select, selected, extraMAC) {
  select.textContent = "";
  const known = new Set();
  for (const d of state.devices) {
    const opt = document.createElement("option");
    opt.value = `mac:${d.mac}`;
    known.add(d.mac);
    const ip = d.ip ? ` (${d.ip})` : "";
    opt.textContent = `${d.display_name}${ip}`;
    select.appendChild(opt);
  }
  if (extraMAC && !known.has(extraMAC)) {
    const opt = document.createElement("option");
    opt.value = `mac:${extraMAC}`;
    opt.textContent = `${extraMAC} (未検出のデバイス)`;
    select.appendChild(opt);
  }
  const staticOpt = document.createElement("option");
  staticOpt.value = "static";
  staticOpt.textContent = "固定IPを直接指定…";
  select.appendChild(staticOpt);
  if (selected && [...select.options].some((o) => o.value === selected)) {
    select.value = selected;
  }
}

function renderTargetSelect() {
  const select = $("mTarget");
  fillTargetSelect(select, select.value, null);
  $("staticIPField").hidden = select.value !== "static";
}

function validateHostname(raw) {
  const hostname = raw.trim().toLowerCase().replace(/\.+$/, "");
  if (!hostname || !HOSTNAME_RE.test(hostname)) {
    throw new Error(
      "ホスト名は英小文字・数字・ハイフンで入力してください (例: nas, living-tv)"
    );
  }
  return hostname;
}

async function submitMappingForm(event) {
  event.preventDefault();
  try {
    const hostname = validateHostname($("mHostname").value);
    const body = { hostname, note: $("mNote").value.trim() };
    const target = $("mTarget").value;
    if (!target) throw new Error("割り当て先のデバイスがありません");
    if (target === "static") {
      const ip = $("mStaticIP").value.trim();
      if (!ip) throw new Error("固定IPを入力してください");
      body.ip = ip;
    } else {
      body.mac = target.slice(4);
    }
    await api("/api/mappings", { method: "POST", body });
    toast(`${hostname}.${state.status.domain} を保存しました`);
    $("mHostname").value = "";
    $("mNote").value = "";
    $("mStaticIP").value = "";
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---- dialogs ----

let assignMAC = null;

function openAssignDialog(device) {
  assignMAC = device.mac;
  $("assignTarget").textContent =
    `${device.display_name} (${device.mac}${device.ip ? " / " + device.ip : ""})`;
  $("aHostname").value = "";
  $("aNote").value = "";
  $("assignDialog").showModal();
  $("aHostname").focus();
}

async function submitAssign(event) {
  event.preventDefault();
  try {
    const hostname = validateHostname($("aHostname").value);
    await api("/api/mappings", {
      method: "POST",
      body: { hostname, mac: assignMAC, note: $("aNote").value.trim() },
    });
    toast(`${hostname}.${state.status.domain} を割り当てました`);
    $("assignDialog").close();
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

let editOriginalHostname = null;

function openEditDialog(m) {
  editOriginalHostname = m.hostname;
  $("editOriginal").textContent = `${m.fqdn} の設定を変更します`;
  $("eHostname").value = m.hostname;
  fillTargetSelect(
    $("eTarget"),
    m.static ? "static" : `mac:${m.mac}`,
    m.static ? null : m.mac
  );
  $("eStaticIPField").hidden = !m.static;
  $("eStaticIP").value = m.static ? m.ip : "";
  $("eNote").value = m.note || "";
  $("editDialog").showModal();
  $("eHostname").focus();
}

async function submitEdit(event) {
  event.preventDefault();
  try {
    const hostname = validateHostname($("eHostname").value);
    const body = { hostname, note: $("eNote").value.trim() };
    const target = $("eTarget").value;
    if (!target) throw new Error("割り当て先を選択してください");
    if (target === "static") {
      const ip = $("eStaticIP").value.trim();
      if (!ip) throw new Error("固定IPを入力してください");
      body.ip = ip;
    } else {
      body.mac = target.slice(4);
    }
    await api(`/api/mappings/${encodeURIComponent(editOriginalHostname)}`, {
      method: "PUT",
      body,
    });
    toast(`${hostname}.${state.status.domain} を更新しました`);
    $("editDialog").close();
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

let labelMAC = null;

function openLabelDialog(device) {
  labelMAC = device.mac;
  $("labelTarget").textContent = `${device.mac}${device.ip ? " / " + device.ip : ""}`;
  $("lLabel").value = device.label || "";
  $("labelDialog").showModal();
  $("lLabel").focus();
}

async function submitLabel(event) {
  event.preventDefault();
  try {
    await api(`/api/devices/${encodeURIComponent(labelMAC)}`, {
      method: "PATCH",
      body: { label: $("lLabel").value.trim() },
    });
    toast("ラベルを保存しました");
    $("labelDialog").close();
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
}

// ---- refresh loop ----

async function refresh() {
  const [status, devices, mappings] = await Promise.all([
    api("/api/status"),
    api("/api/devices"),
    api("/api/mappings"),
  ]);
  state.status = status;
  state.devices = devices;
  state.mappings = mappings;

  $("domainBadge").textContent = status.domain;
  $("fqdnSuffix").textContent = `.${status.domain}`;
  document
    .querySelectorAll(".assign-suffix")
    .forEach((n) => (n.textContent = `.${status.domain}`));
  $("lastScan").textContent = status.last_scan
    ? relativeTime(status.last_scan)
    : "未実施";
  $("footerInfo").textContent =
    `[SYS] local-dns ${status.version} ・ DNS ${status.dns_listen} ・ ` +
    `スキャン間隔 ${status.scan_interval_sec}秒 ・ TTL ${status.ttl}秒 ・ ` +
    `上流 ${status.upstreams.join(", ")}`;

  renderDevices();
  renderTargetSelect();
  renderMappings();
  firstRenderDone = true;
}

async function triggerScan() {
  const btn = $("scanBtn");
  const radar = $("radar");
  btn.disabled = true;
  btn.classList.add("scanning");
  radar.classList.add("fast");
  const originalText = btn.textContent;
  btn.textContent = "SCANNING…";
  const restore = () => {
    btn.disabled = false;
    btn.classList.remove("scanning");
    radar.classList.remove("fast");
    btn.textContent = originalText;
  };
  try {
    await api("/api/scan", { method: "POST" });
    toast("スキャンを開始しました…");
    setTimeout(async () => {
      try {
        await refresh();
      } catch {
        /* keep old view */
      }
      restore();
    }, 3500);
  } catch (err) {
    toast(err.message, true);
    restore();
  }
}

// ---- matrix rain background ----

function initMatrix() {
  const canvas = $("matrixCanvas");
  if (!canvas) return;
  if (reducedMotion) {
    canvas.remove();
    return;
  }
  const ctx = canvas.getContext("2d");
  const CHARS =
    "アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789ABCDEF<>/:$#*+-";
  const FONT = 14;
  let width = 0;
  let height = 0;
  let drops = [];

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const cols = Math.ceil(width / FONT);
    // Start columns at random heights so the effect is alive immediately.
    drops = Array.from({ length: cols }, () =>
      Math.floor(Math.random() * (height / FONT))
    );
    ctx.fillStyle = "#020705";
    ctx.fillRect(0, 0, width, height);
  }
  window.addEventListener("resize", resize);
  resize();

  // No document.hidden check needed: browsers pause rAF in hidden tabs.
  let last = 0;
  function frame(now) {
    requestAnimationFrame(frame);
    if (now - last < 60) return; // ~16fps is plenty
    last = now;
    ctx.fillStyle = "rgba(2, 7, 5, 0.14)"; // fading trails
    ctx.fillRect(0, 0, width, height);
    ctx.font = `${FONT}px monospace`;
    for (let i = 0; i < drops.length; i++) {
      const y = drops[i] * FONT;
      if (y > 0) {
        const ch = CHARS[(Math.random() * CHARS.length) | 0];
        ctx.fillStyle = Math.random() < 0.06 ? "#b4ffe1" : "#00cc7a";
        ctx.fillText(ch, i * FONT, y);
      }
      if (y > height && Math.random() > 0.975) {
        drops[i] = Math.floor(Math.random() * -30);
      } else {
        drops[i]++;
      }
    }
  }
  requestAnimationFrame(frame);
}

// ---- boot sequence ----

async function bootSequence() {
  const boot = $("boot");
  if (!boot) return;
  if (reducedMotion || sessionStorage.getItem("ldns-boot")) {
    boot.remove();
    return;
  }
  sessionStorage.setItem("ldns-boot", "1");

  const lines = [
    () => "> ESTABLISHING UPLINK ................ OK",
    () => "> AUTHENTICATING OPERATOR ............ [ADMIN]",
    () =>
      `> LOADING DEVICE REGISTRY ............ ${
        state.devices.length > 0 ? state.devices.length + " NODES" : "SYNCING"
      }`,
    () => "> DNS CORE ........................... ONLINE",
    () => "> ACCESS GRANTED — ようこそ、管理者",
  ];
  const container = $("bootLines");
  const bar = $("bootProgress");
  let skipped = false;
  boot.addEventListener("click", () => {
    skipped = true;
  });
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  await sleep(250);
  for (let i = 0; i < lines.length; i++) {
    if (skipped) break;
    const last = i === lines.length - 1;
    const div = el("div", last ? "granted" : "ok", lines[i]());
    container.appendChild(div);
    bar.style.width = `${Math.round(((i + 1) / lines.length) * 100)}%`;
    await sleep(last ? 500 : 260 + Math.random() * 160);
  }
  boot.classList.add("done");
  setTimeout(() => boot.remove(), 600);
}

// ---- init ----

$("mappingForm").addEventListener("submit", submitMappingForm);
$("mTarget").addEventListener("change", () => {
  $("staticIPField").hidden = $("mTarget").value !== "static";
});
$("assignForm").addEventListener("submit", (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  submitAssign(e);
});
$("editForm").addEventListener("submit", (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  submitEdit(e);
});
$("eTarget").addEventListener("change", () => {
  $("eStaticIPField").hidden = $("eTarget").value !== "static";
});
$("labelForm").addEventListener("submit", (e) => {
  if (e.submitter && e.submitter.value === "cancel") return;
  submitLabel(e);
});
$("scanBtn").addEventListener("click", triggerScan);

initMatrix();
bootSequence();
refresh().catch((err) => toast(err.message, true));
setInterval(() => {
  refresh().catch(() => {
    /* transient errors: keep old view */
  });
}, 10000);
