/* RKMSIEM 담당자 화면 — 담당자 명단(별도 '담당자 관리' 앱에서 가져옴) · 업무량(맡은 사건) · 연동 상태 · 로그인 계정.
   이름·팀·연락처는 담당자 관리 앱에서만 고친다. 여기서는 보기·동기화와, 관리자(users:write)의 로그인 계정(역할·비밀번호·활성) 관리만.
   app.js 보다 먼저 읽히며 app.js 의 공통 도구를 호출 시점에 사용한다. */
"use strict";

const TM = { el: null, roles: {} };
const tmHue = s => [...s].reduce((h, ch) => (h * 31 + ch.charCodeAt(0)) % 360, 7);
const tmInitials = u => (u.display_name || u.username).trim().slice(0, 2).toUpperCase();
const tmGenPw = () => { const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"; const r = crypto.getRandomValues(new Uint32Array(16));
  return [...r].map(x => a[x % a.length]).join(""); };
const tmAgo = ts => { const s = Math.max(0, Date.now() / 1000 - ts);
  return s < 60 ? "방금" : s < 3600 ? `${Math.floor(s / 60)}분 전` : s < 86400 ? `${Math.floor(s / 3600)}시간 전` : `${Math.floor(s / 86400)}일 전`; };
const tmStaffUrl = st => st.public_url || `${location.protocol}//${location.hostname}:8090/`;

async function renderTeam(el, live) {
  TM.el = el;
  const admin = can("users:write");
  const [a, inc, st, acc] = await Promise.all([api("/api/assignees"), api("/api/incidents?open=1&size=500"), api("/api/staff/status"),
    admin ? api("/api/users") : Promise.resolve(null)]);
  if (acc) TM.roles = acc.roles;
  const people = a.items, unassigned = inc.items.filter(i => !i.assignee);
  const sevBy = {}; inc.items.forEach(i => { if (i.assignee) (sevBy[i.assignee] ||= []).push(i.severity); });
  const maxLoad = Math.max(3, ...people.map(x => x.open_incidents || 0));
  el.innerHTML = `<div class="meta-line"><span>담당자 <b>${people.length}</b>명</span>
      <span>열린 사건 <b>${fmt(inc.total)}</b> · 미배정 <b class="${unassigned.length ? "c-high" : ""}">${unassigned.length}</b>
        ${unassigned.length ? ` <span class="link" data-cmd="dashboard incidents unassigned">미배정 사건 보기</span>` : ""}</span></div>
    ${tmSyncBar(st, admin)}
    <div class="tm-grid">${people.map(x => tmCard(x, sevBy[x.username] || [], maxLoad)).join("")
      || empty("담당자 명단이 비어 있습니다. 담당자 관리 앱에서 담당자를 추가하세요.")}</div>
    ${admin ? tmAccounts(acc.items) : ""}`;
  tmBind(el, admin, acc ? acc.items : []);
  if (A && !live) anime({ targets: $$(".tm-card", el), opacity: [0, 1], translateY: [14, 0], delay: anime.stagger(45), duration: 420, easing: "easeOutCubic" });
}
function tmSyncBar(st, admin) {
  const state = !st.configured ? `<span class="c-high">연동 안 됨</span> <span class="faint">— 마지막 명단을 그대로 사용</span>`
    : st.last_error ? `<span class="c-critical">가져오기 실패</span> <span class="faint">${esc(st.last_error)} — 마지막 명단으로 계속</span>`
    : st.last_ok ? `<span class="acc">정상</span> <span class="faint">· ${esc(tmAgo(st.last_ok))} 가져옴 · ${st.interval_sec}초마다</span>`
    : `<span class="faint">아직 가져오지 않음</span>`;
  return `<div class="tm-sync"><span>담당자 관리 앱 연동: ${state}</span><span class="grow"></span>
    ${admin && st.configured ? `<button class="btn" data-x="sync">지금 가져오기</button>` : ""}
    <a class="btn primary" href="${esc(tmStaffUrl(st))}" target="_blank" rel="noopener">담당자 관리 열기 ↗</a></div>
    <p class="tm-note faint">이름·팀·연락처·배정 알림은 담당자 관리 앱에서 고칩니다. 명단에 있는 사람이면 로그인 계정이 없어도 사건을 배정할 수 있고, 아이디가 같으면 로그인 계정과 연결됩니다.</p>`;
}
function tmCard(u, sevs, maxLoad) {
  const load = u.open_incidents || 0, top = ["critical", "high", "medium", "low", "info"].find(s => sevs.includes(s));
  return `<div class="tm-card" data-u="${esc(u.username)}">
    <div class="tm-head"><span class="tm-av" style="--h:${tmHue(u.username)}">${esc(tmInitials(u))}</span>
      <div class="tm-id"><b>${esc(u.display_name || u.username)}</b><span class="faint">@${esc(u.username)}${u.team ? ` · ${esc(u.team)}` : ""}</span></div>
      <span class="tm-role">${u.has_account ? esc(u.role_label || u.role) : "계정 없음"}</span></div>
    <div class="tm-load"><div class="tm-bar"><i style="width:${Math.min(100, load / maxLoad * 100)}%;background:${top ? SEVC[top] : "var(--accent)"}"></i></div>
      <span>${load ? `열린 사건 <b>${load}</b>${top ? ` · 최고 ${sev(top)}` : ""}` : `<span class="faint">맡은 열린 사건 없음</span>`}</span></div>
    ${u.has_email ? "" : `<div class="tm-meta"><span class="c-high">메일 없음</span> <span class="faint">— 배정 메일을 받지 못함</span></div>`}
    ${load ? `<div class="tm-acts"><button class="btn" data-cmd="dashboard incidents assignee=${esc(u.username)}">사건 보기</button></div>` : ""}</div>`;
}
function tmAccounts(items) {
  const roles = cur => Object.entries(TM.roles).map(([k, l]) => `<option value="${esc(k)}" ${k === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
  return `<h3 class="tm-h">로그인 계정 <span class="faint">· 콘솔에 로그인하는 계정 (역할·비밀번호·활성)</span></h3>
    <details class="tm-add"><summary><b>＋ 로그인 계정 추가</b> <span class="faint">· 사건을 배정받으려면 담당자 관리 앱에도 같은 아이디로 등록</span></summary>
      <div class="tm-form">
        <label>아이디<input data-n="username" placeholder="영문·숫자·._-" autocomplete="off"></label>
        <label>역할<select data-n="role">${roles("analyst")}</select></label>
        <label class="tm-pw">임시 비밀번호<span class="st-row"><input data-n="password" type="password" placeholder="12자 이상" autocomplete="new-password"><button class="btn" data-x="gen">생성</button></span></label>
        <div class="st-row"><button class="btn primary" data-x="create">추가</button><span class="tm-msg faint"></span></div>
      </div></details>
    <div class="tbl"><table class="tm-acct"><thead><tr><th>아이디</th><th>역할</th><th>담당자 명단</th><th>상태</th><th></th></tr></thead><tbody>
      ${items.map(u => `<tr data-a="${esc(u.username)}" class="${u.active ? "" : "off"}">
        <td><b>${esc(u.username)}</b>${u.username === S.me?.username ? ' <span class="acc">(나)</span>' : ""}</td>
        <td><select data-x="role" aria-label="${esc(u.username)} 역할">${roles(u.role)}</select></td>
        <td>${u.in_roster ? `<span class="acc">연결됨</span>` : `<span class="faint">없음 · 배정 불가</span>`}</td>
        <td>${u.active ? "활성" : `<b class="c-high">비활성</b>`}</td>
        <td class="tm-acts"><button class="btn" data-x="pw">비밀번호 재설정</button>
          <button class="btn ${u.active ? "danger" : ""}" data-x="active">${u.active ? "비활성화" : "다시 활성화"}</button></td></tr>`).join("")}
    </tbody></table></div>`;
}
function tmBind(el, admin, accounts) {
  const err = e => toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"), redo = () => renderTeam(el, true);
  const sync = $('[data-x="sync"]', el);
  if (sync) sync.onclick = async () => {
    sync.disabled = true;
    try { const r = await api("/api/staff/sync", { method: "POST" }); tmAssigneeCache = null;
      toast(r.changed ? `명단 갱신 — 추가 ${r.added.length} · 변경 ${r.updated.length} · 제외 ${r.removed.length}` : "명단 변경 없음"); }
    catch (e) { err(e); }
    await redo();
  };
  if (!admin) return;
  const add = $(".tm-add", el);
  $('[data-x="gen"]', add).onclick = e => { e.preventDefault(); const i = $('[data-n="password"]', add); i.value = tmGenPw(); i.type = "text"; i.select(); };
  $('[data-x="create"]', add).onclick = async () => {
    const v = k => $(`[data-n="${k}"]`, add), body = { username: v("username").value.trim(), password: v("password").value, role: v("role").value };
    if (!body.username || body.password.length < 12) { shake(add, 5); $(".tm-msg", add).textContent = "아이디와 12자 이상 임시 비밀번호가 필요합니다"; return; }
    try { await api("/api/users", { method: "POST", body });
      toast(`로그인 계정 <b>${esc(body.username)}</b> 추가 — 임시 비밀번호를 본인에게 전달하고 로그인 후 passwd 로 바꾸게 하세요`); await redo(); }
    catch (e) { err(e); }
  };
  $$("tr[data-a]", el).forEach(row => {
    const name = row.dataset.a, u = accounts.find(x => x.username === name);
    $('[data-x="role"]', row).onchange = async e => {
      try { await api(`/api/users/${encodeURIComponent(name)}`, { method: "PATCH", body: { role: e.target.value } });
        toast(`${esc(name)} 역할 변경 — 그 사람은 다시 로그인합니다`); } catch (x) { err(x); }
      await redo();
    };
    $('[data-x="pw"]', row).onclick = async () => {
      const pw = prompt(`${name} 의 임시 비밀번호 (12자 이상, 비우면 자동 생성)`, ""); if (pw === null) return;
      const val = pw.trim() || tmGenPw();
      try { await api(`/api/users/${encodeURIComponent(name)}/password`, { method: "POST", body: { password: val } });
        if (!pw.trim()) prompt("생성된 임시 비밀번호 — 지금 복사해 전달하세요 (다시 볼 수 없음)", val);
        toast(`${esc(name)} 비밀번호 재설정 — 그 사람의 모든 세션이 로그아웃됨`); } catch (e) { err(e); }
    };
    $('[data-x="active"]', row).onclick = async () => {
      if (u.active && !confirm(`${name} 의 로그인 계정을 비활성화할까요? 즉시 로그아웃됩니다. 담당자 명단(배정)은 담당자 관리 앱에서 따로 관리합니다.`)) return;
      try { await api(`/api/users/${encodeURIComponent(name)}/active`, { method: "POST", body: { active: !u.active } }); } catch (e) { err(e); }
      await redo();
    };
  });
}

// ---------------------------------------------------------------- 사건 배정 선택 상자 (사건 화면에서 사용)
let tmAssigneeCache = null;
async function assigneeOptions(current) {
  if (!tmAssigneeCache || Date.now() - tmAssigneeCache.t > 30000) tmAssigneeCache = { t: Date.now(), d: await api("/api/assignees") };
  const d = tmAssigneeCache.d, known = d.items.some(a => a.username === current);
  return { me: d.me, inRoster: d.items.some(a => a.username === d.me),
    html: `<option value="">(미지정)</option>` + (current && !known ? `<option value="${esc(current)}" selected>${esc(current)} (명단에 없음)</option>` : "")
      + d.items.map(a => `<option value="${esc(a.username)}" ${a.username === current ? "selected" : ""}>
    ${esc(a.display_name)} (@${esc(a.username)})${a.team ? ` · ${esc(a.team)}` : ""} · 열린 사건 ${a.open_incidents}</option>`).join("") };
}
