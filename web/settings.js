/* RKMSIEM 설정 화면 — 메일 서버 · 받는 사람(끌어다 놓기) · 보고서 일정 · 목록 · 평판(AbuseIPDB).
   저장은 /api/config/<kind> (검증 → 새 버전 → 감사 로그 → 바로 반영), 비밀번호·API 키는 /api/secrets (암호화 저장, 다시 읽기 불가).
   app.js 보다 먼저 읽히며 app.js 의 공통 도구($, api, esc, toast …)를 호출 시점에 사용한다. */
"use strict";

const ST_TABS = [["mail", "✉ 메일 서버"], ["people", "⇄ 받는 사람 · 알림"], ["reports", "◷ 보고서 일정"], ["lists", "☰ 목록"], ["rep", "⌕ 평판 (AbuseIPDB)"], ["data", "⌫ 데이터 초기화"]];
const ST_PRESETS = {
  gmail: { label: "Gmail", host: "smtp.gmail.com", port: 587, security: "starttls", note: "Google 계정 → 보안 → 2단계 인증 → '앱 비밀번호' 를 만들어 아래 비밀번호에 넣으세요." },
  naver: { label: "Naver", host: "smtp.naver.com", port: 587, security: "starttls", note: "네이버 메일 → 환경설정 → POP3/IMAP 설정에서 SMTP 사용을 켜세요. 2단계 인증이면 애플리케이션 비밀번호." },
  outlook: { label: "Outlook", host: "smtp.office365.com", port: 587, security: "starttls", note: "회사 계정이면 관리자가 SMTP AUTH 를 허용해야 합니다." },
  relay: { label: "사내 릴레이", host: "", port: 25, security: "none", note: "사내 메일 서버 주소를 넣고 로그인(계정)은 비워 두세요." },
};
const ST_LIST_KO = { internal_networks: ["사내망", "이 대역의 IP 는 위험도를 낮추고 지도에서 제외"], allowlist: ["허용 목록 (예외)", "이 IP 는 탐지·차단 대상에서 제외"],
  never_block: ["차단 금지", "관리자 접속 IP — 어떤 경우에도 차단하지 않음 (자기 차단 방지)"], protected_accounts: ["보호 계정", "자동 잠금하지 않는 계정 (root 등)"],
  privileged_users: ["권한 계정", "sudo 사용이 허용된 계정 — 그 밖의 권한 상승은 경보"] };
const ST_EVERY = [["day", "매일"], ["monday", "월요일"], ["tuesday", "화요일"], ["wednesday", "수요일"], ["thursday", "목요일"], ["friday", "금요일"], ["saturday", "토요일"], ["sunday", "일요일"]];
const ST_SEV = [["critical", "긴급만"], ["high", "높음 이상"], ["medium", "주의 이상"], ["low", "낮음 이상"]];
const ST_EMAIL = /^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/, ST_DOMAIN = /^@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const ST_KINDS = { mail: "mail", reports: "reports", rep: "reputation", lists: "lists" };

const SET = { el: null, tab: "mail", ro: true, saved: {}, draft: {}, ver: {}, secrets: null, pick: null };
const stClone = o => JSON.parse(JSON.stringify(o));
const stDirty = k => JSON.stringify(SET.draft[k]) !== JSON.stringify(SET.saved[k]);
addEventListener("beforeunload", e => { if (SET.el?.isConnected && Object.keys(ST_KINDS).some(stDirty)) { e.preventDefault(); e.returnValue = ""; } });

async function renderSettings(el, live, arg) {
  SET.el = el; SET.ro = !can("config:write");
  if (arg && ST_TABS.some(t => t[0] === arg.trim())) SET.tab = arg.trim();
  const [m, r, rp, l, sec] = await Promise.all(["mail", "reports", "reputation", "lists"].map(k => api(`/api/config/${k}`)).concat(api("/api/secrets")));
  for (const [k, x] of [["mail", m], ["reports", r], ["rep", rp], ["lists", l]]) { SET.saved[k] = x.content || {}; SET.ver[k] = x; }
  SET.draft = stClone(SET.saved); SET.secrets = sec;
  el.innerHTML = `<div class="meta-line"><span>저장하면 <b>재시작 없이 바로 적용</b> · 버전 기록 · 감사 로그</span>
      <span>비밀번호·API 키: <b>${sec.ready ? "암호화 저장" : "<span class='c-critical'>사용 불가</span>"}</b>${sec.key_source === "file" ? " <span class='c-medium'>(암호화 키가 DB 옆 파일 — 운영은 RKMSIEM_SECRET_KEY 권장)</span>" : ""}</span>
      ${SET.ro ? `<span class="c-high">읽기 전용 — config:write 권한 필요</span>` : ""}</div>
    <div class="st-tabs" role="tablist">${ST_TABS.map(([k, t]) => `<button class="st-tab" role="tab" data-tab="${k}">${t}<i class="st-dot"></i></button>`).join("")}</div>
    <div class="st-body"></div>
    <div class="st-bar"><span class="st-ver"></span><span class="grow"></span><span class="st-state"></span>
      ${SET.ro ? "" : `<input class="st-why" placeholder="변경 사유 (감사 로그)"><button class="btn" data-st="reset">되돌리기</button><button class="btn primary" data-st="save">저장</button>`}</div>`;
  $$(".st-tab", el).forEach(b => b.onclick = () => stTab(b.dataset.tab));
  $$("[data-st]", el).forEach(b => b.onclick = () => b.dataset.st === "save" ? stSave() : stReset());
  stTab(SET.tab, !live);
}
function stTab(k, anim = true) {
  SET.tab = k;
  $$(".st-tab", SET.el).forEach(b => b.setAttribute("aria-selected", b.dataset.tab === k));
  const body = $(".st-body", SET.el);
  stOnChange(body, null);
  ({ mail: stMail, people: stPeople, reports: stReports, lists: stLists, rep: stRep, data: stData })[k](body);
  $(".st-bar", SET.el).style.display = k === "data" ? "none" : "";          // 데이터 탭은 저장할 설정이 없음
  stMark();
  if (anim && M) M.animate(body, { opacity: [0, 1], y: [10, 0] }, { type: "spring", stiffness: 260, damping: 24 });
}
// 탭 ↔ 저장 대상 (받는 사람 탭은 mail + reports 를 함께 바꿈)
const stKindsOf = t => ({ mail: ["mail"], people: ["mail", "reports"], reports: ["reports"], lists: ["lists"], rep: ["rep"], data: [] })[t];
function stMark() {
  if (!SET.el) return;
  const tabDirty = t => stKindsOf(t).some(stDirty);
  $$(".st-tab", SET.el).forEach(b => b.classList.toggle("dirty", tabDirty(b.dataset.tab)));
  const ks = stKindsOf(SET.tab);
  $(".st-ver", SET.el).innerHTML = ks.map(k => { const x = SET.ver[k], last = (x.versions || [])[0];
    return `${esc(ST_KINDS[k])} <b>v${x.version ?? "-"}</b>${last ? ` <span class="faint">· ${esc(last.created_by)} ${fmtT(last.created_at)}</span>` : ""}`; }).join("  ");
  const st = $(".st-state", SET.el); if (st) st.innerHTML = tabDirty(SET.tab) ? `<span class="c-medium">● 저장 안 됨</span>` : `<span class="faint">저장됨</span>`;
}
// 탭 본문은 다시 그려도 같은 요소라 리스너가 쌓이지 않게 하나만 유지
function stOnChange(box, fn) { if (box._stc) box.removeEventListener("st-change", box._stc); box._stc = fn; if (fn) box.addEventListener("st-change", fn); }
function stTouch() { stMark(); }
function stReset() { for (const k of stKindsOf(SET.tab)) SET.draft[k] = stClone(SET.saved[k]); stTab(SET.tab, false); }
async function stSave() {
  const why = $(".st-why", SET.el).value.trim() || "콘솔 설정 화면에서 변경", btn = $('[data-st="save"]', SET.el);
  const ks = stKindsOf(SET.tab).filter(stDirty);
  if (!ks.length) { toast("바뀐 내용이 없습니다"); return; }
  btn.disabled = true;
  try {
    for (const k of ks) {
      const r = await api(`/api/config/${ST_KINDS[k]}?comment=${encodeURIComponent(why)}`, { method: "PUT", body: SET.draft[k] });
      SET.saved[k] = stClone(SET.draft[k]);
      SET.ver[k] = await api(`/api/config/${ST_KINDS[k]}`);
      toast(`${esc(ST_KINDS[k])} 설정 저장 → v${r.version} (바로 적용)`);
    }
    $(".st-why", SET.el).value = ""; stMark();
    if (A) anime({ targets: $(".st-body", SET.el), backgroundColor: ["rgba(74,222,128,.10)", "rgba(0,0,0,0)"], duration: 900, easing: "easeOutQuad" });
  } catch (e) {
    toast(`<span class="err">저장 실패 — ${esc(errMsg(e))}</span>`, "critical"); shake(btn.parentElement, 6);
  } finally { btn.disabled = false; }
}
// 입력칸 ↔ 초안 연결: data-p="mail.host" 처럼 경로
function stBind(box) {
  const dis = SET.ro;
  $$("[data-p]", box).forEach(i => {
    if (dis) i.disabled = true;
    const [k, ...path] = i.dataset.p.split("."), get = () => path.reduce((o, x) => o?.[x], SET.draft[k]);
    const v = get();
    if (i.type === "checkbox") i.checked = !!v; else if (v != null) i.value = v;
    i.addEventListener(i.type === "checkbox" || i.tagName === "SELECT" ? "change" : "input", () => {
      let o = SET.draft[k]; for (const x of path.slice(0, -1)) o = (o[x] ||= {});
      const last = path[path.length - 1];
      o[last] = i.type === "checkbox" ? i.checked : i.dataset.num ? (i.value === "" ? undefined : +i.value) : i.value;
      if (o[last] === undefined) delete o[last];
      stTouch(); i.dispatchEvent(new CustomEvent("st-change", { bubbles: true }));
    });
  });
}
const stSwitch = (p, label, sub = "") => `<label class="st-sw"><input type="checkbox" data-p="${p}"><i></i><span><b>${label}</b>${sub ? `<small>${sub}</small>` : ""}</span></label>`;

// ================================================================ 메일 서버
function stMail(box) {
  const d = SET.draft.mail, secret = SET.secrets.items.find(x => x.name === "smtp_password");
  box.innerHTML = `<div class="st-grid2"><div>
      ${stSwitch("mail.enabled", "메일 발송 켜기", "끄면 알림·보고서 메일을 보내지 않습니다")}
      <div class="st-h">메일 서비스</div>
      <div class="st-presets">${Object.entries(ST_PRESETS).map(([k, x]) => `<button class="st-pre" data-pre="${k}">${esc(x.label)}</button>`).join("")}</div>
      <div class="st-note"></div>
      <div class="st-f3"><label>SMTP 서버<input data-p="mail.host" placeholder="smtp.example.com"></label>
        <label>포트<input data-p="mail.port" data-num="1" inputmode="numeric"></label>
        <label>보안<select data-p="mail.security"><option value="starttls">STARTTLS (587)</option><option value="ssl">SSL/TLS (465)</option><option value="none">없음 (사내 25)</option></select></label></div>
      <label>로그인 계정 <span class="faint">(비우면 로그인 없이 — 사내 릴레이)</span><input data-p="mail.username" placeholder="soc@example.com" autocomplete="off"></label>
      <label>보낸 사람 <span class="faint">(Gmail·Naver 는 로그인 계정과 같아야 함)</span><div class="st-row"><input data-p="mail.from" placeholder="RKMSIEM &lt;soc@example.com&gt;"><button class="btn" data-x="same">계정과 같게</button></div></label>
      <div class="st-h">비밀번호 <span class="faint">· 암호화 저장, 다시 볼 수 없음</span></div>
      <div class="st-secret">${stSecretHtml(secret)}</div>
    </div><div>
      <div class="st-h">메일 내용</div>
      <div class="st-f2"><label>제목 머리말<input data-p="mail.subject_prefix"></label>
        <label>콘솔 주소 <span class="faint">(본문 링크)</span><div class="st-row"><input data-p="mail.console_url" placeholder="http://1.1.12.135:8088"><button class="btn" data-x="origin">지금 주소</button></div></label></div>
      <div class="st-h">안전장치</div>
      <div class="st-f3"><label>시간당 최대<input data-p="mail.max_per_hour" data-num="1" inputmode="numeric"></label>
        <label>재시도<input data-p="mail.retries" data-num="1" inputmode="numeric"></label>
        <label>시간 제한(초)<input data-p="mail.timeout_sec" data-num="1" inputmode="numeric"></label></div>
      <div class="st-h">저장 전 테스트 <span class="faint">· 지금 화면의 값으로 보내 봄 (저장 안 함)</span></div>
      <div class="st-row"><input class="st-tto" placeholder="받는 사람 (허용 목록·알림 받는 사람 중)"><button class="btn" data-x="test">테스트 보내기</button></div>
      <div class="st-result"></div>
    </div></div>`;
  stBind(box);
  const note = $(".st-note", box), showNote = () => { const pr = Object.values(ST_PRESETS).find(x => x.host && x.host === d.host); note.textContent = pr ? pr.note : ""; };
  showNote();
  $$("[data-pre]", box).forEach(b => b.onclick = () => { if (SET.ro) return; const x = ST_PRESETS[b.dataset.pre];
    Object.assign(SET.draft.mail, { host: x.host, port: x.port, security: x.security }); if (b.dataset.pre === "relay") SET.draft.mail.username = "";
    stMail(box); stTouch(); note.textContent = x.note; $(".st-note", box).textContent = x.note;
    if (M) $$("[data-p='mail.host'], [data-p='mail.port'], [data-p='mail.security']", box).forEach(i => M.animate(i, { scale: [1.04, 1] }, { type: "spring", stiffness: 500, damping: 18 })); });
  stOnChange(box, showNote);
  $('[data-x="same"]', box).onclick = () => { const u = SET.draft.mail.username; if (!u) return; const f = $('[data-p="mail.from"]', box); f.value = `RKMSIEM <${u}>`; f.dispatchEvent(new Event("input")); };
  $('[data-x="origin"]', box).onclick = () => { const f = $('[data-p="mail.console_url"]', box); f.value = location.origin; f.dispatchEvent(new Event("input")); };
  $('[data-x="test"]', box).onclick = async e => {
    const to = $(".st-tto", box).value.trim(), res = $(".st-result", box), b = e.target;
    if (!to) { shake($(".st-tto", box), 5); return; }
    b.disabled = true; res.innerHTML = `<span class="dim">보내는 중… (최대 ${esc(d.timeout_sec || 15)}초)</span>`;
    const pw = $(".st-pw", box)?.value;
    try { const r = await api("/api/mail/test", { method: "POST", body: { to, mail: SET.draft.mail, ...(pw ? { password: pw } : {}) } });
      res.innerHTML = r.status === "sent" ? `<span class="acc">✔ 보냄 → ${esc(r.recipients)} (시도 ${r.attempts}회) — 받은편지함·스팸함을 확인하세요</span>`
        : `<span class="c-critical">✘ 실패: ${esc(r.error || r.status)}</span>${stHint(r.error)}`; }
    catch (x) { res.innerHTML = `<span class="c-critical">✘ ${esc(errMsg(x))}</span>`; }
    finally { b.disabled = false; }
  };
  stBindSecret(box, "smtp_password");
}
function stHint(err) {
  const e = String(err || "");
  if (/535|로그인/.test(e)) return `<div class="dim" style="font-size:12px">→ Gmail·Naver 는 일반 비밀번호가 아니라 <b>앱 비밀번호</b>가 필요합니다.</div>`;
  if (/연결 실패|timed out|refused/i.test(e)) return `<div class="dim" style="font-size:12px">→ 서버에서 SMTP 포트로 나가는 길(방화벽·ufw·VMware NAT)과 서버 주소·포트·보안 방식을 확인하세요.</div>`;
  return "";
}
function stSecretHtml(s) {
  const src = { web: "웹에서 입력 (암호화 저장)", env: `서버 파일 (${esc(s.env_name)})` }[s.source];
  return `<div class="st-sec-st">${s.set ? `<span class="acc">● 설정됨</span> <span class="dim">— ${src}${s.hint ? ` · ${esc(s.hint)}` : ""}${s.updated_at ? ` · ${esc(s.updated_by)} ${fmtT(s.updated_at)}` : ""}</span>` : `<span class="c-high">● 없음</span>`}</div>
    ${SET.ro ? "" : `<div class="st-row"><input type="password" class="st-pw" autocomplete="new-password" placeholder="${s.set ? "새 값으로 바꾸기" : "입력"}">
      <button class="btn" data-sec="save">저장</button>${s.source === "web" ? `<button class="btn danger" data-sec="clear">삭제</button>` : ""}</div>`}`;
}
function stBindSecret(box, name) {
  const wrap = $(".st-secret", box);
  $$("[data-sec]", wrap).forEach(b => b.onclick = async () => {
    try {
      if (b.dataset.sec === "save") { const v = $(".st-pw", wrap).value; if (!v.trim()) { shake($(".st-pw", wrap), 5); return; }
        SET.secrets = await api(`/api/secrets/${name}`, { method: "PUT", body: { value: v } }); toast("암호화해 저장했습니다 (바로 적용)"); }
      else { if (!confirm("저장된 값을 삭제할까요?")) return; SET.secrets = await api(`/api/secrets/${name}`, { method: "DELETE" }); toast("삭제했습니다"); }
      wrap.innerHTML = stSecretHtml(SET.secrets.items.find(x => x.name === name)); stBindSecret(box, name);
      if (M) M.animate(wrap, { scale: [.97, 1] }, { type: "spring", stiffness: 400, damping: 20 });
    } catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
  });
}

// ================================================================ 받는 사람 · 알림 (끌어다 놓기)
function stCols() {
  const m = SET.draft.mail, r = SET.draft.reports;
  m.alerts ||= {}; r.incident_on_close ||= {};
  const cols = [
    { id: "allowed", title: "허용 목록", sub: "보낼 수는 있는 주소 — 플레이북 메일·수동 발송 (@도메인 가능)", get: () => (m.allowed_recipients ||= []), domain: true },
    { id: "alerts", title: "경보 · 승인 알림", sub: "실시간 알림 메일을 받음", get: () => (m.alerts.to ||= []) },
    { id: "close", title: "사건 종결 보고서", sub: r.incident_on_close.enabled ? "사건을 닫으면 PDF" : "꺼짐 — 보고서 일정 탭에서 켜기", get: () => (r.incident_on_close.to ||= []) },
  ];
  (r.schedule || []).forEach((s, i) => cols.push({ id: `sch${i}`, title: `${({ day: "매일", monday: "매주 월" })[s.every] || ST_EVERY.find(e => e[0] === s.every)?.[1] || s.every} ${s.at} 보고서`,
    sub: `${s.name} · 최근 ${s.period_hours || 24}시간${s.enabled ? "" : " · 꺼짐"}`, get: () => (s.to ||= []) }));
  return cols;
}
function stPeople(box) {
  const m = SET.draft.mail, cols = stCols();
  const all = [...new Set(cols.flatMap(c => c.get()))].sort();
  box.innerHTML = `<div class="st-h">알림 기준</div>
    <div class="st-alerts">${stSwitch("mail.alerts.enabled", "경보 알림 메일")}${stSwitch("mail.alerts.approvals", "승인 요청도 메일로")}
      <div class="st-seg" data-seg="min_severity">${ST_SEV.map(([v, l]) => `<button data-v="${v}">${l}</button>`).join("")}</div>
      <label class="st-inline">묶음<select data-p="mail.alerts.batch_sec" data-num="1"><option value="0">바로</option><option value="30">30초</option><option value="60">1분</option><option value="300">5분</option><option value="900">15분</option></select></label></div>
    <div class="st-h">받는 사람 <span class="faint">· 주소를 아래 칸으로 끌어다 놓기 (또는 주소를 누르고 칸의 ＋)</span></div>
    <div class="st-pool"><div class="st-chips" data-pool>${all.map(a => stChip(a, true)).join("") || `<span class="faint">아직 주소가 없습니다 — 오른쪽에 추가하세요</span>`}</div>
      ${SET.ro ? "" : `<div class="st-row st-add"><input class="st-newaddr" placeholder="새 주소 또는 @회사도메인"><button class="btn" data-x="add">추가</button></div>`}</div>
    <div class="st-cols">${cols.map(c => `<div class="st-col" data-col="${c.id}"><div class="st-ch"><b>${esc(c.title)}</b>${SET.ro ? "" : `<button class="st-plus" title="선택한 주소 넣기">＋</button>`}<small>${esc(c.sub)}</small></div>
      <div class="st-chips">${c.get().map(a => stChip(a, false)).join("") || `<span class="st-empty">여기에 놓기</span>`}</div></div>`).join("")}</div>
    <p class="hint" style="margin-top:10px">알림·보고서 칸에 넣은 주소는 자동으로 허용됩니다. 저장 전에는 적용되지 않습니다.</p>`;
  stBind(box);
  const seg = $("[data-seg]", box), cur = m.alerts.min_severity || "high";
  $$("button", seg).forEach(b => { b.classList.toggle("on", b.dataset.v === cur); b.disabled = SET.ro;
    b.onclick = () => { m.alerts.min_severity = b.dataset.v; $$("button", seg).forEach(x => x.classList.toggle("on", x === b)); stTouch(); }; });
  const addr = (a, col) => {
    a = a.trim().toLowerCase();
    const c = cols.find(x => x.id === col); if (!c) return false;
    if (ST_DOMAIN.test(a) && !c.domain) { toast("@도메인은 '허용 목록' 칸에만 넣을 수 있습니다", "high"); return false; }
    if (!ST_EMAIL.test(a) && !ST_DOMAIN.test(a)) { toast(`메일 주소 형식이 아닙니다: ${esc(a)}`, "high"); return false; }
    const l = c.get(); if (l.includes(a)) return false;
    l.push(a); stTouch(); return true;
  };
  const rerender = (col, a) => { stPeople(box); const ch = col && $(`[data-col="${col}"] .st-chip[data-a="${CSS.escape(a)}"]`, box);
    if (ch && A) anime({ targets: ch, scale: [.3, 1], opacity: [0, 1], duration: 600, easing: "spring(1, 140, 10, 0)" }); };
  if (SET.ro) return;
  // 끌기
  $$(".st-chip", box).forEach(ch => {
    ch.addEventListener("dragstart", e => { e.dataTransfer.setData("application/x-rkaddr", ch.dataset.a); e.dataTransfer.effectAllowed = "copy"; box.classList.add("st-dragging"); });
    ch.addEventListener("dragend", () => { box.classList.remove("st-dragging"); $$(".st-col.over", box).forEach(x => x.classList.remove("over")); });
    ch.addEventListener("click", e => { if (e.target.closest(".st-x")) return; SET.pick = SET.pick === ch.dataset.a ? null : ch.dataset.a;
      $$(".st-chip", box).forEach(x => x.classList.toggle("picked", x.dataset.a === SET.pick)); });
  });
  $$(".st-col", box).forEach(col => {
    col.addEventListener("dragover", e => { if (!e.dataTransfer.types.includes("application/x-rkaddr")) return; e.preventDefault(); col.classList.add("over"); });
    col.addEventListener("dragleave", e => { if (!col.contains(e.relatedTarget)) col.classList.remove("over"); });
    col.addEventListener("drop", e => { e.preventDefault(); col.classList.remove("over"); const a = e.dataTransfer.getData("application/x-rkaddr");
      if (a && addr(a, col.dataset.col)) rerender(col.dataset.col, a); else shake(col, 5); });
    $(".st-plus", col).onclick = () => { if (!SET.pick) { toast("먼저 위에서 주소를 누르세요"); return; } if (addr(SET.pick, col.dataset.col)) rerender(col.dataset.col, SET.pick); };
  });
  $$(".st-x", box).forEach(x => x.onclick = e => { e.stopPropagation(); const ch = x.closest(".st-chip"), col = ch.closest("[data-col]");
    const go = () => { if (col) { const l = cols.find(c => c.id === col.dataset.col).get(); l.splice(l.indexOf(ch.dataset.a), 1); }
      else cols.forEach(c => { const l = c.get(), i = l.indexOf(ch.dataset.a); if (i >= 0) l.splice(i, 1); });
      stTouch(); stPeople(box); };
    if (!col && !confirm(`${ch.dataset.a} 을(를) 모든 칸에서 뺄까요?`)) return;
    if (A) anime({ targets: ch, scale: 0, opacity: 0, duration: 220, easing: "easeInBack", complete: go }); else go(); });
  const inp = $(".st-newaddr", box), add = () => { const a = inp.value.trim().toLowerCase(); if (!a) return;
    if (!ST_EMAIL.test(a) && !ST_DOMAIN.test(a)) { shake(inp, 5); toast("메일 주소 또는 @도메인 형식으로 넣으세요", "high"); return; }
    if (addr(a, "allowed")) rerender("allowed", a); else inp.value = ""; };
  $('[data-x="add"]', box).onclick = add; inp.onkeydown = e => { if (e.key === "Enter") add(); };
}
const stChip = (a, pool) => `<span class="st-chip ${ST_DOMAIN.test(a) ? "dom" : ""} ${SET.pick === a ? "picked" : ""}" ${SET.ro ? "" : 'draggable="true"'} data-a="${esc(a)}" title="${pool ? "끌어서 칸에 놓기" : ""}">${esc(a)}${SET.ro ? "" : `<button class="st-x" title="${pool ? "모든 칸에서 빼기" : "빼기"}">✕</button>`}</span>`;

// ================================================================ 보고서 일정
function stNext(s) {
  const now = new Date(), [h, mi] = (s.at || "09:00").split(":").map(Number);
  for (let i = 0; i < 8; i++) { const d = new Date(now); d.setDate(now.getDate() + i); d.setHours(h, mi, 0, 0);
    const wd = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"][d.getDay()];
    if (d > now && (s.every === "day" || s.every === wd)) return d; }
  return null;
}
function stReports(box) {
  const r = SET.draft.reports; r.schedule ||= []; r.incident_on_close ||= {};
  const pick = (v, opts) => opts.map(([k, l]) => `<option value="${k}" ${String(v) === String(k) ? "selected" : ""}>${l}</option>`).join("");
  box.innerHTML = `${stSwitch("reports.incident_on_close.enabled", "사건을 닫으면 사건 보고서 PDF 를 메일로", `받는 사람 ${(r.incident_on_close.to || []).length}명 — '받는 사람' 탭에서 배정`)}
    <div class="st-h">정기 요약 보고서 <span class="faint">· 서버 시간대 기준 · 보고서 범위는 발송 시각 직전 N시간</span></div>
    <div class="st-sched">${r.schedule.map((s, i) => { const nx = stNext(s);
      return `<div class="st-srow ${s.enabled ? "" : "off"}" data-i="${i}">
        <label class="st-sw sm"><input type="checkbox" data-k="enabled" ${s.enabled ? "checked" : ""}><i></i></label>
        <input class="st-name" data-k="name" value="${esc(s.name)}" title="이름 (영문 소문자)">
        <select data-k="every">${pick(s.every, ST_EVERY)}</select>
        <input type="time" data-k="at" value="${esc(s.at)}">
        <select data-k="period_hours">${pick(s.period_hours || 24, [[24, "최근 24시간"], [168, "최근 7일"], [720, "최근 30일"]])}</select>
        <span class="dim st-meta">받는 사람 <b>${(s.to || []).length}</b>명 · ${s.enabled && nx ? `다음 ${nx.getMonth() + 1}/${nx.getDate()} ${s.at}` : "꺼짐"}</span>
        ${SET.ro ? "" : `<button class="au-x" data-del title="삭제">✕</button>`}</div>`; }).join("") || `<div class="faint">일정 없음</div>`}</div>
    ${SET.ro ? "" : `<button class="btn" data-x="addsch" style="margin-top:8px">＋ 일정 추가</button>`}
    <p class="hint" style="margin-top:12px">지금 바로 받아 보려면 <span class="link" data-cmd="dashboard mail">dashboard mail</span> 에서 'PDF 받기'·'메일로 보내기'.</p>`;
  stBind(box);
  if (SET.ro) { $$("input, select", box).forEach(i => i.disabled = true); return; }
  $$(".st-srow", box).forEach(row => {
    const s = r.schedule[+row.dataset.i];
    $$("[data-k]", row).forEach(i => i.addEventListener("change", () => {
      const k = i.dataset.k;
      if (k === "enabled") s.enabled = i.checked;
      else if (k === "period_hours") s.period_hours = +i.value;
      else if (k === "name") { const v = i.value.trim().toLowerCase(); if (!/^[a-z][a-z0-9_]{0,30}$/.test(v) || r.schedule.some((x, j) => x !== s && x.name === v)) { i.value = s.name; shake(i, 5); toast("이름: 영문 소문자로 시작, 중복 불가", "high"); return; } s.name = v; }
      else s[k] = i.value;
      stTouch(); stReports(box);
    }));
    $("[data-del]", row).onclick = () => { if ((s.to || []).length && !confirm(`${s.name} 일정을 삭제할까요?`)) return; r.schedule.splice(+row.dataset.i, 1); stTouch(); stReports(box); };
  });
  $('[data-x="addsch"]', box).onclick = () => { let n = 1, name = "report"; while (r.schedule.some(x => x.name === name)) name = `report${++n}`;
    r.schedule.push({ name, every: "friday", at: "18:00", period_hours: 168, to: [], enabled: false }); stTouch(); stReports(box);
    if (A) anime({ targets: $$(".st-srow", box).pop(), opacity: [0, 1], translateY: [-8, 0], duration: 350, easing: "easeOutCubic" }); };
}

// ================================================================ 목록 (차단 금지 · 사내망 · 보호 계정 …)
const stCidr = v => /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(v) || /^[0-9a-f:]+(\/\d{1,3})?$/i.test(v);
function stLists(box) {
  const L = SET.draft.lists, order = [...Object.keys(ST_LIST_KO).filter(k => L[k]), ...Object.keys(L).filter(k => !ST_LIST_KO[k]).sort()];
  box.innerHTML = `<p class="hint">탐지·대응이 참조하는 이름 있는 목록입니다. 저장하면 탐지 엔진이 바로 다시 구성됩니다.</p>
    <div class="st-lists">${order.map(k => { const l = L[k], [ko, desc] = ST_LIST_KO[k] || [k, l.description || ""];
      return `<div class="st-list ${k === "never_block" && !l.values.length ? "warn" : ""}" data-l="${esc(k)}"><div class="st-ch"><b>${esc(ko)}</b> <code>${esc(k)}</code> <span class="bdg">${l.kind === "cidr" ? "IP/CIDR" : "값"}</span>
        ${l.sample ? `<span class="sample-badge">SAMPLE</span>` : ""}<small>${esc(desc)}${k === "never_block" && !l.values.length ? " — <b class='c-high'>비어 있음: 관리자 IP 를 넣으세요</b>" : ""}</small></div>
        <div class="st-chips">${l.values.map((v, i) => `<span class="st-chip" data-i="${i}">${esc(v)}${SET.ro ? "" : `<button class="st-x" title="빼기">✕</button>`}</span>`).join("") || `<span class="st-empty">비어 있음</span>`}</div>
        ${SET.ro ? "" : `<div class="st-row"><input class="st-lv" placeholder="${l.kind === "cidr" ? "예: 203.0.113.7 또는 10.0.0.0/8" : "예: root"}"><button class="btn" data-x="ladd">추가</button></div>`}</div>`; }).join("")}</div>`;
  if (SET.ro) return;
  $$(".st-list", box).forEach(card => {
    const l = L[card.dataset.l], inp = $(".st-lv", card);
    const add = () => { const v = inp.value.trim(); if (!v) return;
      if (l.kind === "cidr" && !stCidr(v)) { shake(inp, 5); toast("IP 또는 CIDR 형식으로 넣으세요 (서버에서 다시 검사)", "high"); return; }
      if (l.values.includes(v)) { inp.value = ""; return; }
      l.values.push(v); stTouch(); stLists(box);
      const c = $(`[data-l="${CSS.escape(card.dataset.l)}"] .st-chip:last-of-type`, box); if (c && A) anime({ targets: c, scale: [.3, 1], duration: 500, easing: "spring(1, 140, 10, 0)" });
      $(`[data-l="${CSS.escape(card.dataset.l)}"] .st-lv`, box)?.focus(); };
    $('[data-x="ladd"]', card).onclick = add; inp.onkeydown = e => { if (e.key === "Enter") add(); };
    $$(".st-x", card).forEach(x => x.onclick = () => { const i = +x.closest(".st-chip").dataset.i;
      if (card.dataset.l === "never_block" && !confirm(`${l.values[i]} 를 차단 금지에서 빼면 이 IP 도 차단될 수 있습니다. 뺄까요?`)) return;
      l.values.splice(i, 1); stTouch(); stLists(box); });
  });
}

// ================================================================ 평판 (AbuseIPDB)
function stRep(box) {
  const a = (SET.draft.rep.abuseipdb ||= {}), secret = SET.secrets.items.find(x => x.name === "abuseipdb_key");
  const mal = a.malicious_score ?? 75, sus = a.suspicious_score ?? 25;
  box.innerHTML = `<div class="st-grid2"><div>
      ${stSwitch("rep.abuseipdb.enabled", "AbuseIPDB 조회", "키가 있을 때 플레이북 평판 조회에 사용 (실패하면 공개 피드로 계속)")}
      <div class="st-h">API 키 <span class="faint">· abuseipdb.com → Account → API</span></div>
      <div class="st-secret">${stSecretHtml(secret)}</div>
      <div class="st-row" style="margin-top:8px"><input class="st-ip" value="185.220.101.1" placeholder="IP"><button class="btn" data-x="look">조회해 보기</button></div>
      <div class="st-result"></div>
    </div><div>
      <div class="st-h">판정 기준 <span class="faint">· AbuseIPDB 신뢰도 점수 0~100</span></div>
      <div class="st-scale"><div class="st-zone u" style="width:${sus}%"><span>정보 없음</span></div><div class="st-zone s" style="width:${mal - sus}%"><span>의심</span></div><div class="st-zone m" style="width:${100 - mal}%"><span>악성</span></div></div>
      <label>의심 기준 <b class="st-sv">${sus}</b> 점 이상<input type="range" min="0" max="99" data-p="rep.abuseipdb.suspicious_score" data-num="1"></label>
      <label>악성 기준 <b class="st-mv">${mal}</b> 점 이상<input type="range" min="1" max="100" data-p="rep.abuseipdb.malicious_score" data-num="1"></label>
      <div class="st-f3"><label>신고 반영 기간<select data-p="rep.abuseipdb.max_age_days" data-num="1"><option value="30">30일</option><option value="90">90일</option><option value="180">180일</option><option value="365">365일</option></select></label>
        <label>같은 IP 재사용<select data-p="rep.abuseipdb.cache_ttl_sec" data-num="1"><option value="3600">1시간</option><option value="21600">6시간</option><option value="86400">24시간</option></select></label>
        <label>시간 제한(초)<input data-p="rep.abuseipdb.timeout_sec" data-num="1" inputmode="numeric"></label></div>
      <p class="hint">무료 키는 하루 1,000건 — 같은 IP 는 재사용 시간 동안 다시 묻지 않습니다. 사설 IP 는 외부로 보내지 않습니다.</p>
    </div></div>`;
  stBind(box);
  stOnChange(box, e => { if (e.target.type !== "range") return;
    const s = +SET.draft.rep.abuseipdb.suspicious_score, m = +SET.draft.rep.abuseipdb.malicious_score;
    $(".st-sv", box).textContent = s; $(".st-mv", box).textContent = m;
    const [u, sz, mz] = $$(".st-zone", box); u.style.width = `${Math.min(s, m)}%`; sz.style.width = `${Math.max(0, m - s)}%`; mz.style.width = `${100 - m}%`;
    $(".st-scale", box).classList.toggle("bad", s >= m); });
  $('[data-x="look"]', box).onclick = async () => {
    const res = $(".st-result", box);
    if (stDirty("rep")) res.innerHTML = `<span class="c-medium">저장 전 기준은 아직 적용되지 않았습니다 — 저장된 기준으로 조회합니다.</span>`;
    try { res.innerHTML += repHtml(await api(`/api/intel/lookup?ip=${encodeURIComponent($(".st-ip", box).value.trim())}`)); }
    catch (e) { res.innerHTML = `<span class="c-critical">${esc(errMsg(e))}</span>`; }
  };
  stBindSecret(box, "abuseipdb_key");
}

// ================================================================ 데이터 초기화
const ST_COUNT_KO = { events: "이벤트", alerts: "경보", incidents: "사건", runs: "플레이북 실행", blocklist: "차단", accounts: "계정 잠금 기록", incidents_kept: "남기는 사건" };
const stCounts = c => Object.entries(c).filter(([k, v]) => v || k === "events").map(([k, v]) => `${ST_COUNT_KO[k] || k} <b>${fmt(v)}</b>`).join(" · ");
async function stData(box) {
  const card = (scope, title, desc, danger) => `<div class="st-reset ${danger ? "danger" : ""}" data-scope="${scope}">
      <div class="st-ch"><b>${title}</b><small>${desc}</small></div>
      <div class="st-plan dim">지울 대상 계산 중…</div>
      ${SET.ro ? "" : `<div class="st-row">${danger ? `<label class="st-chk"><input type="checkbox" class="st-bl"> 차단 목록도 지우기 (서버 방화벽에서도 해제)</label>` : ""}</div>
      <div class="st-row">${danger ? `<input class="st-confirm" placeholder="확인: 초기화 라고 입력">` : ""}<input class="st-rwhy" placeholder="사유 (감사 로그)">
        <button class="btn ${danger ? "danger" : "primary"}" data-reset="${scope}" disabled>${danger ? "전체 초기화" : "테스트 기록 지우기"}</button></div>`}
    </div>`;
  box.innerHTML = `<p class="hint">설치 확인(스모크테스트)·샘플 기록 때문에 위협 수준이 '심각'으로 남아 있을 때 쓰세요.
      <b>설정·규칙·플레이북·사용자·감사 로그·메일 기록·비밀 값</b>은 지우지 않고, auth.log 를 처음부터 다시 읽지도 않습니다. 초기화도 감사 로그에 남습니다.</p>
    ${card("test", "테스트 기록만 지우기 (추천)", "문서용 IP 대역(192.0.2.x · 198.51.100.x · 203.0.113.x — 스모크테스트가 씀), 임시 계정 rkmsmoke*, 샘플 데이터와 그에 딸린 경보·사건·실행·차단", false)}
    ${card("all", "전체 초기화", "이벤트·경보·사건·플레이북 실행·알림을 모두 지웁니다 — 실제 공격 기록도 사라집니다", true)}
    <p class="hint" style="margin-top:12px">사건을 '오탐'으로 닫으면 그 경보는 지우지 않아도 위협 수준 계산에서 빠집니다.</p>`;
  for (const el of $$(".st-reset", box)) {
    const scope = el.dataset.scope, plan = $(".st-plan", el), btn = $("[data-reset]", el);
    const load = async () => { try { const r = await api("/api/system/reset", { method: "POST", body: { scope, dry_run: true, include_blocklist: !!$(".st-bl", el)?.checked } });
        const empty = !r.counts.events && !r.counts.alerts && !r.counts.incidents;
        plan.innerHTML = empty ? `<span class="acc">지울 기록이 없습니다.</span>` : `지울 대상: ${stCounts(r.counts)}`;
        if (btn) btn.dataset.empty = empty ? "1" : ""; check(); }
      catch (e) { plan.innerHTML = `<span class="c-critical">${esc(errMsg(e))}</span>`; } };
    const check = () => { if (!btn) return; btn.disabled = !!btn.dataset.empty || (scope === "all" && $(".st-confirm", el).value.trim() !== "초기화"); };
    $(".st-confirm", el)?.addEventListener("input", check);
    $(".st-bl", el)?.addEventListener("change", load);
    if (btn) btn.onclick = async () => {
      if (scope === "test" && !confirm("테스트 기록을 지울까요? 되돌릴 수 없습니다.")) return;
      btn.disabled = true; btn.textContent = "지우는 중…";
      try { const r = await api("/api/system/reset", { method: "POST", body: { scope, reason: $(".st-rwhy", el).value.trim() || undefined,
          ...(scope === "all" ? { confirm: $(".st-confirm", el).value.trim(), include_blocklist: !!$(".st-bl", el)?.checked } : {}) } });
        toast(`초기화 완료 — ${stCounts(r.counts)} 삭제`); await loadOverview(); stData(box);
        if (A) anime({ targets: box, backgroundColor: ["rgba(74,222,128,.10)", "rgba(0,0,0,0)"], duration: 900, easing: "easeOutQuad" }); }
      catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); btn.disabled = false; btn.textContent = scope === "all" ? "전체 초기화" : "테스트 기록 지우기"; }
    };
    load();
  }
}
