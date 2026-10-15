/* RKMSIEM 담당자 관리 화면 — 로그인 · 담당자 추가/수정/비활성/삭제 · 검색 · 최근 변경 · 연동 상태. */
"use strict";

const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hue = s => [...s].reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 7);
const initials = p => (p.display_name || p.username).trim().slice(0, 2).toUpperCase();
const ago = ts => { const s = Math.max(0, Date.now() / 1000 - ts);
  return s < 60 ? "방금" : s < 3600 ? `${Math.floor(s / 60)}분 전` : s < 86400 ? `${Math.floor(s / 3600)}시간 전` : `${Math.floor(s / 86400)}일 전`; };
const pad = n => String(n).padStart(2, "0");
const fmtT = ts => { const d = new Date(ts * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const ACTION = { "person.add": "추가", "person.update": "수정", "person.active": "활성 변경", "person.delete": "삭제",
  "admin.add": "관리자 추가", "admin.password": "관리자 비밀번호", "auth.login": "로그인", "auth.login_failed": "로그인 실패" };
const FIELD = { display_name: "이름", team: "팀", email: "메일", phone: "연락처", notify_assign: "배정 알림", active: "활성" };

const S = { token: null, me: null, people: [], edit: null };
try { S.token = sessionStorage.getItem("staff_token"); } catch { /* 저장소를 못 쓰면 매번 로그인 */ }

async function api(path, opt = {}) {
  const r = await fetch(path, { method: opt.method || "GET", headers: Object.assign({ "Content-Type": "application/json" },
    S.token ? { Authorization: `Bearer ${S.token}` } : {}), body: opt.body ? JSON.stringify(opt.body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "/api/login") { setToken(null); show("login"); throw new Error("다시 로그인하세요"); }
  if (!r.ok) throw new Error(d.error === "rate_limited" ? "로그인 시도가 너무 많습니다. 잠시 후 다시 하세요" :
    d.error === "invalid_credentials" ? "아이디 또는 비밀번호가 맞지 않습니다" : d.error || `오류 ${r.status}`);
  return d;
}
function setToken(t) { S.token = t; try { t ? sessionStorage.setItem("staff_token", t) : sessionStorage.removeItem("staff_token"); } catch { /* 무시 */ } }
function toast(html, level = "info") {
  const t = document.createElement("div"); t.className = `toast ${level}`; t.innerHTML = html; $("#toasts").append(t);
  setTimeout(() => t.remove(), level === "critical" ? 7000 : 4000);
}
const fail = e => toast(`<span class="err">${esc(e.message)}</span>`, "critical");
function show(which) {
  $("#login").classList.toggle("hidden", which !== "login");
  $("#main").classList.toggle("hidden", which !== "main");
  ["#logout", "#console"].forEach(s => $(s).classList.toggle("hidden", which !== "main"));
  $("#who").textContent = which === "main" && S.me ? `관리자 ${S.me.username}` : "";
  if (which === "login") setTimeout(() => $('#loginForm [name="username"]').focus(), 0);
}

// ---------------------------------------------------------------- 로그인
$("#loginForm").addEventListener("submit", async e => {
  e.preventDefault();
  const f = e.target;
  try {
    const d = await api("/api/login", { method: "POST", body: { username: f.username.value.trim(), password: f.password.value } });
    f.password.value = ""; $("#loginMsg").textContent = ""; setToken(d.token); await boot();
  } catch (err) { $("#loginMsg").textContent = err.message; }
});
$("#logout").onclick = async () => { try { await api("/api/logout", { method: "POST" }); } catch { /* 이미 만료 */ } setToken(null); S.me = null; show("login"); };

async function boot() {
  if (!S.token) return show("login");
  try { S.me = await api("/api/me"); } catch { return; }
  const c = $("#console");
  c.href = S.me.console_url || `${location.protocol}//${location.hostname}:8088/`;
  show("main");
  await load();
}

// ---------------------------------------------------------------- 목록
async function load() {
  const [p, ch, me] = await Promise.all([api("/api/people"), api("/api/changes?limit=30"), api("/api/me")]);
  S.people = p.items; S.me = me;
  const teams = [...new Set(S.people.map(x => x.team).filter(Boolean))].sort();
  $("#teams").innerHTML = teams.map(t => `<option value="${esc(t)}">`).join("");
  const tf = $("#teamFilter"), cur = tf.value;
  tf.innerHTML = `<option value="">모든 팀</option>` + teams.map(t => `<option ${t === cur ? "selected" : ""}>${esc(t)}</option>`).join("");
  renderMeta(); renderGrid(); renderChanges(ch.items);
}
function renderMeta() {
  const act = S.people.filter(x => x.active), noMail = act.filter(x => !x.email).length, last = (S.me.sync_clients || [])[0];
  $("#meta").innerHTML = `<span>활성 담당자 <b>${act.length}</b>명${S.people.length > act.length ? ` · 비활성 ${S.people.length - act.length}명` : ""}</span>
    ${noMail ? `<span class="warn">메일 없는 담당자 ${noMail}명 — 배정 메일을 받지 못합니다</span>` : ""}
    <span>RKMSIEM 연동: ${!S.me.sync_key ? `<b class="err">연동 키 없음</b> <span class="faint">(STAFF_SYNC_KEYS)</span>`
      : last ? `마지막으로 명단을 가져감 <b title="${esc(fmtT(last.last_at))}">${esc(ago(last.last_at))}</b> <span class="faint">(${last.count}명)</span>`
      : `<span class="warn">아직 가져가지 않음</span>`}${S.me.notify ? ` · <span class="faint">변경 즉시 알림</span>` : ""}</span>`;
}
function visible() {
  const q = $("#q").value.trim().toLowerCase(), team = $("#teamFilter").value, off = $("#showOff").checked;
  return S.people.filter(p => (off || p.active) && (!team || p.team === team) &&
    (!q || [p.username, p.display_name, p.team].some(v => (v || "").toLowerCase().includes(q))));
}
function renderGrid() {
  const list = visible();
  $("#grid").innerHTML = list.map(card).join("") || `<div class="empty">${S.people.length ? "조건에 맞는 담당자가 없습니다." : "담당자가 없습니다. 위에서 추가하세요."}</div>`;
  bindCards();
}
function card(p) {
  const editing = S.edit === p.username;
  return `<div class="card ${p.active ? "" : "off"} ${editing ? "editing" : ""}" data-u="${esc(p.username)}">
    <div class="head"><span class="av" style="--h:${hue(p.username)}">${esc(initials(p))}</span>
      <div class="id"><b>${esc(p.display_name || p.username)}</b><span class="faint">@${esc(p.username)}</span></div>
      ${p.team ? `<span class="team">${esc(p.team)}</span>` : ""}</div>
    <div class="contact">${p.email ? `✉ ${esc(p.email)}` : `<span class="warn">메일 없음</span>`}${p.phone ? ` · ☎ ${esc(p.phone)}` : ""}
      ${p.email && !p.notify_assign ? ` · <span class="faint">배정 알림 끔</span>` : ""}${p.active ? "" : ` · <b class="err">비활성</b>`}</div>
    <div class="acts"><button class="btn" data-x="edit">${editing ? "닫기" : "편집"}</button>
      <button class="btn ${p.active ? "" : "primary"}" data-x="active">${p.active ? "비활성화" : "다시 활성화"}</button>
      ${p.active ? "" : `<button class="btn danger" data-x="delete">삭제</button>`}</div>
    ${editing ? editForm(p) : ""}</div>`;
}
function editForm(p) {
  return `<div class="form">
    <label>이름<input data-e="display_name" value="${esc(p.display_name || "")}"></label>
    <label>팀<input data-e="team" value="${esc(p.team || "")}" list="teams"></label>
    <label>메일<input data-e="email" value="${esc(p.email || "")}"></label>
    <label>연락처<input data-e="phone" value="${esc(p.phone || "")}"></label>
    <label class="chk"><input type="checkbox" data-e="notify_assign" ${p.notify_assign ? "checked" : ""}> 배정 메일 알림</label>
    <div class="row"><button class="btn primary" data-x="save">저장</button></div></div>`;
}
function bindCards() {
  $$(".card").forEach(cardEl => {
    const name = cardEl.dataset.u, p = S.people.find(x => x.username === name);
    $$("[data-x]", cardEl).forEach(b => b.onclick = async () => {
      try {
        const x = b.dataset.x;
        if (x === "edit") { S.edit = S.edit === name ? null : name; renderGrid(); const i = $('[data-e="display_name"]', $(`[data-u="${CSS.escape(name)}"]`)); if (i) i.focus(); return; }
        if (x === "save") {
          const g = k => $(`[data-e="${k}"]`, cardEl);
          await api(`/api/people/${encodeURIComponent(name)}`, { method: "PATCH", body: { display_name: g("display_name").value, team: g("team").value,
            email: g("email").value, phone: g("phone").value, notify_assign: g("notify_assign").checked } });
          S.edit = null; toast(`<b>${esc(name)}</b> 저장`);
        }
        if (x === "active") {
          if (p.active && !confirm(`${p.display_name || name} 을(를) 비활성화할까요? RKMSIEM 에서 새 사건을 배정받지 못합니다 (맡은 사건은 그대로).`)) return;
          await api(`/api/people/${encodeURIComponent(name)}/active`, { method: "POST", body: { active: !p.active } });
        }
        if (x === "delete") {
          if (!confirm(`${p.display_name || name} 을(를) 명단에서 삭제할까요? 지난 사건의 담당 기록(아이디)은 RKMSIEM 에 그대로 남습니다.`)) return;
          await api(`/api/people/${encodeURIComponent(name)}`, { method: "DELETE" }); toast(`<b>${esc(name)}</b> 삭제`);
        }
        await load();
      } catch (e) { fail(e); }
    });
  });
}
function renderChanges(items) {
  const det = d => d ? Object.entries(d).filter(([, v]) => v !== null && v !== "").map(([k, v]) => `${FIELD[k] || k}=${typeof v === "boolean" ? (v ? "예" : "아니요") : v ?? "-"}`).join(", ") : "";
  $("#changes").innerHTML = items.filter(c => c.action !== "auth.login").map(c => `<div><span>${esc(fmtT(c.ts))}</span><span>${esc(c.actor)}</span>
    <span>${esc(ACTION[c.action] || c.action)} ${c.target ? `<b>@${esc(c.target)}</b>` : ""} <span class="faint">${esc(det(c.detail))}</span></span></div>`).join("")
    || `<span class="faint">변경 기록이 없습니다.</span>`;
}

// ---------------------------------------------------------------- 추가
$("#create").onclick = async () => {
  const add = $("#add"), v = k => $(`[data-n="${k}"]`, add);
  const body = { username: v("username").value.trim(), display_name: v("display_name").value, team: v("team").value,
    email: v("email").value, phone: v("phone").value, notify_assign: v("notify_assign").checked };
  if (!body.username) { $("#addMsg").innerHTML = `<span class="err">아이디가 필요합니다</span>`; v("username").focus(); return; }
  try {
    await api("/api/people", { method: "POST", body });
    ["username", "display_name", "email", "phone"].forEach(k => { v(k).value = ""; });
    $("#addMsg").textContent = ""; toast(`담당자 <b>${esc(body.display_name || body.username)}</b> 추가 — RKMSIEM 배정 목록에 곧 나타납니다`);
    await load();
  } catch (e) { $("#addMsg").innerHTML = `<span class="err">${esc(e.message)}</span>`; }
};
["#q", "#teamFilter", "#showOff"].forEach(s => $(s).addEventListener("input", renderGrid));
setInterval(() => { if (S.me && !document.hidden && !S.edit) load().catch(() => {}); }, 30000);
boot();
