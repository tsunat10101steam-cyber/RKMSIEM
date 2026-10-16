/* RKMSIEM 콘솔 — 모든 수치는 백엔드 API 결과를 그대로 표시한다(탐지/정책 로직을 여기서 다시 구현하지 않음). */
"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = n => Number(n || 0).toLocaleString("ko-KR");
const pad = n => String(n).padStart(2, "0");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
const A = typeof anime !== "undefined" && !reduceMotion;
const M = window.Motion && !reduceMotion ? window.Motion : null;
let skipping = false;
const sleep = ms => new Promise(r => setTimeout(r, skipping ? 0 : ms));
const out = $("#out"), input = $("#cmd");
const SEVC = { critical: "var(--critical)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--faint)" };
const SEVX = { critical: "#ff5b5b", high: "#ff9f43", medium: "#fcd34d", low: "#8592a3", info: "#4f5b6b" };
const SEVK = { critical: ["CRIT", "긴급"], high: ["HIGH", "높음"], medium: ["WARN", "주의"], low: ["LOW", "낮음"], info: ["INFO", "정보"] };
const sev = l => `<span class="sev ${l === "info" ? "low" : l}">${SEVK[l][0]} <span class="ko">${SEVK[l][1]}</span></span>`;
const state = s => `<span class="state ${esc(s)}">${esc(STATE_KO[s] || s)}</span>`;
const STATE_KO = { new: "신규", investigating: "조사 중", responding: "대응 중", resolved: "해결", false_positive: "오탐", queued: "대기",
  running: "실행 중", waiting_approval: "승인 대기", waiting_task: "사람 할 일", succeeded: "성공", failed: "실패", cancelled: "취소", compensated: "보상 완료",
  skipped: "건너뜀", timed_out: "시간 초과", rejected: "거절", pending: "대기", approved: "승인", expired: "만료" };

// ================================================================ API
const S = { token: null, me: null, data: null, range: { label: "최근 데이터 24시간", from: null, to: null }, view: null, es: null };
try { S.token = sessionStorage.getItem("rk_token"); } catch (e) { /* 저장소 차단 환경 */ }
class ApiErr extends Error { constructor(status, body) { super(body?.error || `HTTP ${status}`); this.status = status; this.body = body; } }
async function api(path, opt = {}) {
  const h = { "Content-Type": "application/json" };
  if (S.token) h.Authorization = `Bearer ${S.token}`;
  const r = await fetch(path, { method: opt.method || "GET", headers: h, body: opt.body ? JSON.stringify(opt.body) : undefined });
  let j = null;
  try { j = await r.json(); } catch (e) { /* 본문 없음 */ }
  if (r.status === 401 && path !== "/api/auth/login" && path !== "/api/auth/mfa") { setToken(null); throw new ApiErr(401, { error: "로그인이 필요합니다 — login 을 입력하세요" }); }
  if (!r.ok) throw new ApiErr(r.status, j);
  return j;
}
// 파일 받기 (PDF 등) — 인증 헤더가 필요해 링크 대신 fetch → blob
async function download(path, fallbackName) {
  const r = await fetch(path, { headers: S.token ? { Authorization: `Bearer ${S.token}` } : {} });
  if (!r.ok) { let j = null; try { j = await r.json(); } catch (e) { /* 본문 없음 */ } throw new ApiErr(r.status, j); }
  const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/)?.[1] || fallbackName;
  const url = URL.createObjectURL(await r.blob()), a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return name;
}
function setToken(t) {
  S.token = t;
  try { t ? sessionStorage.setItem("rk_token", t) : sessionStorage.removeItem("rk_token"); } catch (e) { /* noop */ }
  if (!t) { S.me = null; closeStream(); $("#who").textContent = "로그인 전"; $("#ps").innerHTML = `guest@rkmsiem:<span class="path">~</span>$`; }
}
const can = p => !!S.me && S.me.permissions.includes(p);
function errMsg(e) {
  if (e instanceof ApiErr) {
    const d = e.body?.details; return `${e.message}${d ? " — " + (Array.isArray(d) ? d.join("; ") : d) : ""}${e.status === 403 && e.body?.required ? ` (필요 권한: ${e.body.required})` : ""}`;
  }
  return String(e?.message || e);
}

// ================================================================ 공통 UI
const tick = () => { const d = new Date(); $("#clock").textContent = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
tick(); setInterval(tick, 1000);
const tip = $("#tip");
function showTip(ev, html) {
  tip.innerHTML = html; tip.style.opacity = 1;
  const r = tip.getBoundingClientRect();
  let x = ev.clientX + 14, y = ev.clientY + 14;
  if (x + r.width > innerWidth - 8) x = ev.clientX - r.width - 14;
  if (y + r.height > innerHeight - 8) y = ev.clientY - r.height - 14;
  tip.style.left = x + "px"; tip.style.top = y + "px";
}
const hideTip = () => tip.style.opacity = 0;
const bindTip = (el, html) => { el.addEventListener("mousemove", e => showTip(e, html)); el.addEventListener("mouseleave", hideTip); };
addEventListener("scroll", hideTip, { passive: true });
const TZ = () => S.data?.meta?.timezone || "Asia/Seoul";
function fmtT(ts, withDate = true) {
  if (!ts) return "-";
  const o = { timeZone: TZ(), hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" };
  if (withDate) Object.assign(o, { month: "2-digit", day: "2-digit" });
  return new Intl.DateTimeFormat("ko-KR", o).format(new Date(ts * 1000));
}
function niceMax(v) {
  const raw = (v || 1) / 4, p = Math.pow(10, Math.floor(Math.log10(raw)));
  const step = [1, 2, 2.5, 5, 10].map(m => m * p).find(x => x >= raw && x >= 1 && Number.isInteger(x)) || Math.ceil(raw);
  return step * 4;
}
function countUp(els, start = 0, live = false) {
  els.forEach((el, i) => {
    const end = +el.dataset.count;
    if (!A || live) { el.textContent = fmt(end); return; }
    const o = { n: 0 };
    anime({ targets: o, n: end, round: 1, delay: start + i * 70, duration: 1000, easing: "easeOutExpo", update: () => el.textContent = fmt(o.n) });
  });
}
function shake(el, amt = 8) { if (A) anime({ targets: el, translateX: [0, -amt, amt, -amt * .6, amt * .6, -amt * .3, 0], duration: 500, easing: "easeInOutSine" }); }
function flicker(el, n = 3) {
  if (!A || !el) return;
  let k = 0;
  const iv = setInterval(() => { el.classList.toggle("flick"); if (++k >= n * 2) { clearInterval(iv); el.classList.remove("flick"); } }, 70);
}
const HANGUL = "가나다라마바사아자차카타파하심각경계주의관정상위협";
function decode(el, text, ms = 700) {
  if (!A) { el.textContent = text; return; }
  const t0 = performance.now();
  const iv = setInterval(() => {
    const p = Math.min(1, (performance.now() - t0) / ms);
    el.textContent = [...text].map((ch, i) => p * text.length > i + .5 ? ch : HANGUL[Math.random() * HANGUL.length | 0]).join("");
    if (p >= 1) { clearInterval(iv); el.textContent = text; }
  }, 40);
}
function toast(html, level = "info", onclick) {
  const t = document.createElement("div");
  t.className = `toast ${level}`;
  t.innerHTML = `<div class="t">${fmtT(Date.now() / 1000)}</div>${html}`;
  if (onclick) t.onclick = onclick;
  $("#toasts").prepend(t);
  if (M) M.animate(t, { opacity: [0, 1], x: [40, 0] }, { type: "spring", stiffness: 300, damping: 24 });
  setTimeout(() => t.remove(), 8000);
  while ($("#toasts").children.length > 4) $("#toasts").lastChild.remove();
}
function metaLine(extra = "") {
  const m = S.data?.meta;
  if (!m) return "";
  return `<div class="meta-line"><span>범위 <b>${fmtT(m.from)} ~ ${fmtT(m.to)}</b> (${esc(S.range.label)})</span><span>집계 <b>${esc(m.aggregation)}</b></span>
    <span>갱신 <b>${fmtT(m.generated_at)}</b></span>${m.has_sample ? `<span class="sample-badge">SAMPLE</span> <span>예제(가상) 데이터 포함</span>` : ""}${extra}</div>`;
}
const empty = msg => `<div class="empty-state">${esc(msg)}</div>`;

// ================================================================ 실시간 (SSE)
let refreshTimer = null;
function setConn(cls, text) { const c = $("#conn"); c.className = `conn ${cls}`; $("span", c).textContent = text; }
function closeStream() { if (S.es) { S.es.close(); S.es = null; } setConn("", "오프라인"); }
let retry = 0;
async function openStream() {
  closeStream();
  if (!S.token) return;
  try {
    const { ticket } = await api("/api/stream/ticket", { method: "POST" });
    const es = new EventSource(`/api/stream?ticket=${encodeURIComponent(ticket)}`);
    S.es = es;
    es.addEventListener("hello", () => { retry = 0; setConn("live", "LIVE"); });
    es.onerror = () => {                        // 티켓은 1회용 → 직접 새 티켓으로 재연결
      es.close(); S.es = null;
      setConn("retry", `재연결 중 (${++retry})`);
      setTimeout(openStream, Math.min(15000, 1000 * 2 ** Math.min(retry, 4)));
    };
    es.addEventListener("overflow", () => { es.close(); setConn("retry", "재연결 중"); setTimeout(openStream, 500); });
    for (const t of ["alert", "incident", "run", "ingest", "notification", "config", "metrics"]) es.addEventListener(t, e => onLive(t, JSON.parse(e.data)));
  } catch (e) {
    setConn("down", "연결 실패");
    if (S.token) setTimeout(openStream, 5000);
  }
}
function onLive(type, msg) {
  const d = msg.data || {};
  if (type === "metrics") { $("#ticker").textContent = `● 큐 ${fmt(d.queue_depth)} · 저장 이벤트 ${fmt(d.events_stored)} · 실시간 구독 ${d.subscribers}`; return; }
  if (type === "ingest") $("#ticker").textContent = `● ${fmtT(msg.ts)} 수집 ${fmt(d.stored)}건 ${Object.entries(d.by_source || {}).map(([k, v]) => `${k}:${v}`).join(" ")}${d.duplicates ? ` · 중복 ${d.duplicates}` : ""}`;
  if (type === "alert" && d.op === "new" && ["critical", "high"].includes(d.severity))
    toast(`${sev(d.severity)} <b>${esc(d.title)}</b><br><span class="dim">${esc(Object.values(d.group || {}).join(" · "))}</span>`, d.severity,
      () => d.incident_id && run(`incident ${d.incident_id}`));
  if (type === "run" && d.state === "waiting_task") toast(`<b>사람 할 일</b> — 플레이북 ${esc(d.playbook_id)} (실행 #${d.id})`, "medium", () => run(`run ${d.id}`));
  if (type === "run" && d.state === "waiting_approval") toast(`<b>승인 요청</b> — 플레이북 ${esc(d.playbook_id)} (실행 #${d.id})`, "high", () => run(`run ${d.id}`));
  if (type === "notification") toast(`<b>알림</b> ${esc(d.message)}`, "info");
  if (type === "incident" && d.id) {                                   // 나에게 새로 배정된 사건
    const prev = assignSeen[d.id]; assignSeen[d.id] = d.assignee || null;
    if (S.me && d.assignee === S.me.username && prev !== undefined && prev !== d.assignee) {
      toast(`<b>사건 #${d.id} 이(가) 나에게 배정됨</b><br><span class="dim">${esc(d.title || "")}</span>`, "high", () => run(`incident ${d.id}`));
      tmAssigneeCache = null;
    }
  }
  if (type === "staff") tmAssigneeCache = null;                      // 담당자 관리 앱의 명단이 바뀜
  if (["alert", "incident", "run", "ingest", "config", "staff"].includes(type)) scheduleRefresh();
}
const assignSeen = {};
function scheduleRefresh() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => {
    if (!S.token || !S.view || busy) return;
    try { await loadOverview(); await rerender(true); } catch (e) { /* 다음 이벤트에 재시도 */ }
  }, 1200);
}

// ================================================================ 데이터
function rangeQuery() {
  const q = new URLSearchParams();
  if (S.range.from != null) q.set("from", S.range.from);
  if (S.range.to != null) q.set("to", S.range.to);
  return q.toString();
}
async function loadOverview() {
  S.data = await api(`/api/overview?${rangeQuery()}`);
  const t = S.data.threat;
  $("#tbLevel").textContent = `위협 ${t.current.label}`;
  $("#tbLevel").style.background = THREAT_C[t.index] || "var(--faint)";
  setFavicon(t.index <= 1 ? THREAT_C[t.index] : null);
  return S.data;
}
// 탭 아이콘: 위협 수준이 '심각'·'경계'면 오른쪽 위에 색 점 (다른 탭을 보고 있어도 보이게)
function setFavicon(dot) {
  const f = $("#favicon"); if (!f) return;
  const key = dot || "";
  if (f.dataset.dot === key) return;
  f.dataset.dot = key;
  f.href = !dot ? "/static/favicon.svg" : "data:image/svg+xml," + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
    <rect x="2" y="2" width="60" height="60" rx="14" fill="#0a0d12" stroke="#1e2834" stroke-width="3"/>
    <polyline points="15,20 29,32 15,44" fill="none" stroke="#4ade80" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
    <rect x="33" y="39" width="18" height="7" rx="2.5" fill="#dbe2ea"/><circle cx="49" cy="15" r="11" fill="${dot}" stroke="#0a0d12" stroke-width="4"/></svg>`);
}
const THREAT_C = ["#ff5b5b", "#ff9f43", "#fcd34d", "#60a5fa", "#4ade80"];   // 설정 순서(위=가장 심각)대로

// ================================================================ 패널
const PANELS = {};
function panel(key, no, title, en, aliases, desc, span, render, opts = {}) { PANELS[key] = { key, no, title, en, aliases, desc, span, render, ...opts }; }

panel("threat", "01", "위협 수준", "THREAT LEVEL", ["threat", "t", "위협"], "사이버위기 경보 5단계 표기로 본 현재 위협", 5, (el, live) => {
  const t = S.data.threat, lv = t.levels, i = t.index, n = lv.length;
  const steps = [...lv].reverse();                                  // 표시: 정상 → 심각
  const cur = n - 1 - i, color = THREAT_C[i];
  const r = t.reasons, why = [];
  if (r.severe_ips) why.push(`침해 의심 IP <b class="c-critical">${r.severe_ips}개</b>`);
  if (r.account_alerts) why.push(`계정 단위 공격 <b class="c-high">${r.account_alerts}건</b>`);
  if (r.critical_alerts) why.push(`긴급 경보 <b>${r.critical_alerts}건</b>`);
  el.innerHTML = metaLine() + `<div class="threat">
      <div class="big" style="color:${color}"><span class="ring"></span><span class="ring"></span><span class="lvtxt">${esc(t.current.label)}</span><small>${esc(t.current.en)}</small></div>
      <div><div class="steps">${steps.map((s, k) => `<div data-on="${k <= cur}" style="${k <= cur ? `background:${THREAT_C[n - 1 - k]};box-shadow:none` : ""}"></div>`).join("")}</div>
        <div class="steps-lab">${steps.map((s, k) => `<span class="${k === cur ? "cur" : ""}">${esc(s.label)}</span>`).join("")}</div>
        <div class="why">${why.length ? why.join(" · ") + (i <= 1 ? " → <b>즉시 대응 필요</b>" : "") : "기준을 위반한 활동이 없습니다."}</div>
        <div class="hint" style="margin:6px 0 0">단계 판정 기준은 config/detection.yaml 의 threat_levels 에서 관리됩니다.</div></div></div>`;
  if (!A || live) return;
  decode($(".lvtxt", el), t.current.label, 800);
  anime({ targets: $(".big small", el), opacity: [0, 1], letterSpacing: ["1.2em", ".3em"], duration: 900, easing: "easeOutExpo" });
  anime({ targets: $$(".steps div", el).filter(d => d.dataset.on === "true"), scaleY: [0, 1], opacity: [0, 1], delay: anime.stagger(140, { start: 200 }), easing: "spring(1, 90, 11, 0)" });
  anime({ targets: $$(".ring", el), scale: [.3, 2.6], opacity: [.9, 0], delay: anime.stagger(450, { start: 800 }), duration: 1400, easing: "easeOutCubic", loop: 2 });
  if (i === 0) setTimeout(() => shake(el.closest(".panel"), 10), 950);
});

panel("kpi", "02", "핵심 지표", "KEY METRICS", ["kpi", "stats", "지표"], "이벤트·경보·사건·대응 요약", 7, (el, live) => {
  const t = S.data.totals, inc = S.data.incidents, pb = S.data.playbooks;
  const openInc = Object.entries(inc).filter(([k]) => !["resolved", "false_positive"].includes(k)).reduce((a, [, v]) => a + v, 0);
  const rate = t.events ? (t.fail / t.events * 100).toFixed(1) : "0.0";
  const k = [
    { k: "침해 의심 IP", v: t.severe_ips, s: t.severe_ips ? "즉시 확인 필요" : "없음", hot: t.severe_ips > 0 },
    { k: "미처리 경보", v: t.open_alerts, s: `범위 내 경보 ${fmt(t.alerts)}건` },
    { k: "열린 사건", v: openInc, s: Object.entries(inc).map(([s, n]) => `${STATE_KO[s] || s} ${n}`).join(" · ") || "없음" },
    { k: "승인 대기", v: pb.pending_approvals.length, s: pb.success_rate == null ? "완료된 대응 없음" : `대응 성공률 ${(pb.success_rate * 100).toFixed(0)}%`, hot: pb.pending_approvals.length > 0 },
    { k: "로그인 실패", v: t.fail, s: `전체 ${fmt(t.events)}건 중 ${rate}%` },
    { k: "실패 발생 IP", v: t.fail_ips, s: `전체 IP ${fmt(t.unique_ips)}개` },
  ];
  el.innerHTML = metaLine() + `<div class="kpis">${k.map(x => `<div class="kpi ${x.hot ? "hot" : ""}"><div class="k">${x.k}</div><div class="v" data-count="${x.v}">0</div><div class="s">${esc(x.s)}</div></div>`).join("")}</div>`;
  if (A && !live) anime({ targets: $$(".kpi", el), rotateX: [-95, 0], opacity: [0, 1], delay: anime.stagger(90), easing: "spring(1, 70, 10, 0)" });
  countUp($$(".v", el), 250, live);
});

let alertFilter = "medium";                                       // IDS 경보(보통 주의)도 기본으로 보이게
const ALERT_F = [["critical", "긴급만", ["critical"]], ["high", "높음 이상", ["critical", "high"]], ["medium", "주의 이상", ["critical", "high", "medium"]],
  ["all", "전체", ["critical", "high", "medium", "low", "info"]]];
panel("alerts", "03", "최근 경보", "ALERT STREAM", ["alerts", "alert", "경보"], "최근 경보와 연결된 사건 (심각도 필터 · IDS 경보 포함)", 12, async (el, live) => {
  const r = await api(`/api/alerts?sort=-created&size=50&${rangeQuery()}`);
  const f = ALERT_F.find(x => x[0] === alertFilter) || ALERT_F[1];
  const items = r.items.filter(a => f[2].includes(a.severity)).slice(0, 25);
  const hidden = r.items.length - r.items.filter(a => f[2].includes(a.severity)).length;
  const isIds = a => /^ids_/.test(a.rule_id);
  el.innerHTML = metaLine(`<span>표시 <b>${items.length}</b> / 범위 내 ${fmt(r.total)}건</span>`) +
    `<div class="filter">${ALERT_F.map(([k, l]) => `<button class="fkey" data-af="${k}" aria-pressed="${k === alertFilter}">${l}</button>`).join("")}
      ${hidden ? `<span class="faint" style="font:12px var(--ko)">· 필터로 ${hidden}건 숨김</span>` : ""}</div>` +
    (items.length ? `<ul class="stream">${items.map(a => `
    <li><span class="t">${fmtT(a.last_ts, false)}</span><span class="tag ${a.severity === "critical" ? "breach" : a.severity === "high" ? "ddos" : a.severity === "medium" ? "warn" : "low"}">${SEVK[a.severity][0]}</span><div>
      <div class="head">${isIds(a) ? `<span class="src-ids">IDS</span> ` : ""}${esc(a.title)} — <span class="ip">${esc(Object.values(a.group).join(" · "))}</span></div>
      <div class="body">${esc(a.detail)} · 위험 ${a.risk_score.toFixed(0)} · ${esc(a.rule_name || a.rule_id)} v${a.rule_version}${a.basis ? ` · 근거: ${esc(a.basis)}` : ""}</div>
      <div class="act">${a.incident_id ? `<span class="link" data-cmd="incident ${a.incident_id}">사건 #${a.incident_id} 열기</span>` : "사건 없음"} · 상태 ${state(a.status)}</div></div></li>`).join("")}</ul>`
      : empty(`범위 안에 '${f[1]}' 경보가 없습니다.${hidden ? " 필터를 '전체'로 바꿔 보세요." : ""}`));
  $$("[data-af]", el).forEach(b => b.onclick = () => { alertFilter = b.dataset.af; PANELS.alerts.render(el, false); });
  if (A && !live) {
    const lis = $$(".stream li", el);
    anime({ targets: lis, clipPath: ["inset(0% 100% 0% 0%)", "inset(0% 0% 0% 0%)"], opacity: [0, 1], delay: anime.stagger(120), duration: 650, easing: "easeOutExpo" });
    lis.forEach((li, i) => setTimeout(() => { flicker($(".tag", li), 3); }, 120 + i * 120));
  }
});

panel("hourly", "04", "시간대별 로그인", "TIMELINE", ["hourly", "time", "시간"], "로그인 실패·성공 추이와 급증 구간", 12, (el, live) => {
  const se = S.data.series, f = se.map(x => x.fail), max = niceMax(Math.max(1, ...f));
  const avg = f.reduce((a, b) => a + b, 0) / Math.max(1, f.length);
  const day = S.data.meta.bucket_sec >= 86400;
  if (!f.some(Boolean)) { el.innerHTML = metaLine() + empty("범위 안에 로그인 실패 이벤트가 없습니다."); return; }
  const lab = x => { const p = new Intl.DateTimeFormat("ko-KR", { timeZone: TZ(), hour12: false, ...(day ? { month: "2-digit", day: "2-digit" } : { hour: "2-digit" }) }).format(new Date(x.t * 1000)); return p; };
  const every = Math.max(1, Math.ceil(se.length / 12));
  el.innerHTML = metaLine() + `<p class="hint">평균의 2배 이상 몰린 구간은 <b class="c-critical">빨간색</b>. 막대에 마우스를 올리면 실패·성공 건수가 보입니다.</p>
    <div class="hourly"><div class="yaxis">${[0, 1, 2, 3, 4].map(i => `<span style="top:${100 - i * 25}%">${fmt(max / 4 * i)}</span>`).join("")}</div>
    <div class="cols" style="grid-template-columns:repeat(${se.length},1fr)">${[1, 2, 3, 4].map(i => `<div class="gl" style="bottom:${i * 25}%"></div>`).join("")}
      <div class="avg" style="bottom:${avg / max * 100}%"><span>평균 ${avg.toFixed(0)}</span></div>
      ${se.map((x, h) => { const sp = x.fail >= avg * 2 && x.fail > 0; return `<div class="col ${sp ? "spike" : ""}" data-h="${h}"><div class="bar" style="height:${x.fail / max * 100}%"></div>${sp ? `<div class="lab" style="bottom:calc(${x.fail / max * 100}% + 6px)">${fmt(x.fail)} ▲</div>` : ""}</div>`; }).join("")}
    </div></div>
    <div class="xaxis" style="grid-template-columns:repeat(${se.length},1fr)">${se.map((x, h) => `<span>${h % every === 0 ? esc(lab(x)) : ""}</span>`).join("")}</div>`;
  $$(".col", el).forEach(c => { const x = se[+c.dataset.h], sp = c.classList.contains("spike");
    bindTip(c, `<b>${fmtT(x.t)}</b><br>실패 ${fmt(x.fail)}건 · 성공 ${fmt(x.success)}건${x.other ? ` · 기타 ${fmt(x.other)}` : ""}${sp ? `<br><b class="c-critical">평균의 ${(x.fail / avg).toFixed(1)}배</b>` : ""}`); });
  if (!A || live) return;
  anime({ targets: $$(".col:not(.spike) .bar", el), scaleY: [0, 1], delay: anime.stagger(28), easing: "spring(1, 120, 9, 0)" });
  anime({ targets: $(".avg", el), scaleX: [0, 1], opacity: [0, 1], delay: 500, duration: 700, easing: "easeInOutQuart" });
  $$(".col.spike", el).forEach(col => {
    anime({ targets: $(".bar", col), scaleY: [{ value: 0, duration: 0 }, { value: 1.12, duration: 520, easing: "easeOutQuart" }, { value: 1, duration: 230, easing: "easeInOutSine" }], delay: 1050,
      complete: () => { const s = document.createElement("div"); s.className = "shock"; s.style.bottom = $(".bar", col).style.height; col.appendChild(s);
        anime({ targets: s, scale: [0, 5], opacity: [.95, 0], duration: 800, easing: "easeOutCubic", complete: () => s.remove() }); shake($(".cols", el), 6); } });
    anime({ targets: $(".lab", col), translateY: [-40, 0], opacity: [0, 1], delay: 1500, duration: 700, easing: "easeOutBounce" });
  });
});

panel("top", "05", "위험 IP 순위", "TOP OFFENDERS", ["top", "ip", "공격"], "경보 위험 점수 상위 12개 출발 IP", 7, (el, live) => {
  const list = S.data.offenders.slice(0, 12);
  if (!list.length) { el.innerHTML = metaLine() + empty("범위 안에 경보가 걸린 IP가 없습니다."); return; }
  el.innerHTML = metaLine() + `<p class="hint">막대 = <b>백엔드가 계산한 위험 점수(0~100)</b> — 심각도 기본 점수 + 근거 이벤트 수. 오른쪽은 가장 높은 탐지 규칙.</p>
    <div class="hlist">${list.map((o, i) => `<div class="hrow" data-i="${i}">
      <div class="name ${o.severe ? "c-critical" : ""}">${esc(o.ip)}</div>
      <div class="track"><div class="fill" style="width:${Math.max(o.risk, 1.5)}%;background:${SEVC[o.severity]}"></div></div>
      <div class="meta"><b class="${o.severe ? "c-critical" : ""}" data-count="${Math.round(o.risk)}">0</b>${esc(o.rules[0].title.split(" (")[0])}</div></div>`).join("")}</div>
    <div class="legend">${["critical", "high", "medium", "low"].map(l => `<span><i style="background:${SEVC[l]}"></i>${SEVK[l][1]}</span>`).join("")}<span>빨간 IP = 침해 의심 단계</span></div>`;
  $$(".hrow", el).forEach(r => { const o = list[+r.dataset.i];
    bindTip(r, `<b>${esc(o.ip)}</b> ${sev(o.severity)}<br>${o.rules.map(x => esc(x.title)).join("<br>")}<br>실패 ${fmt(o.fails)} · 성공 ${fmt(o.success)} · 계정 ${o.users.length}개<br>${fmtT(o.first_ts)} → ${fmtT(o.last_ts)}`);
    r.onclick = () => o.incident_id && run(`incident ${o.incident_id}`); });
  countUp($$(".meta b", el), 150, live);
  if (A && !live) {
    anime({ targets: $$(".fill", el), scaleX: [0, 1], delay: anime.stagger(60, { start: 150 }), easing: "spring(1, 80, 12, 0)" });
    anime({ targets: $$(".hrow", el), translateX: [-30, 0], opacity: [0, 1], delay: anime.stagger(40), duration: 450, easing: "easeOutCubic" });
    setTimeout(() => $$(".name.c-critical", el).forEach(n => flicker(n, 4)), 1000);
  }
});

panel("targets", "06", "표적 계정", "TARGETED ACCOUNTS", ["targets", "accounts", "계정"], "실패가 몰린 계정과 공격 IP 수", 5, (el, live) => {
  const list = S.data.targets;
  if (!list.length) { el.innerHTML = metaLine() + empty("범위 안에 실패한 로그인이 없습니다."); return; }
  const max = niceMax(list[0].fails);
  el.innerHTML = metaLine() + `<p class="hint">숫자 = 실패 횟수 / 그 계정을 공격한 IP 수. 주황색은 계정 단위 경보(분산 공격 등)가 걸린 계정.</p>
    <div class="hlist users">${list.map((u, i) => `<div class="hrow ${u.account_alert ? "botrow" : ""}" data-i="${i}">
      <div class="name ${u.account_alert ? "c-high" : ""}">${esc(u.user)}</div>
      <div class="track"><div class="fill" style="width:${u.fails / max * 100}%;background:${u.account_alert ? "var(--high)" : "var(--accent)"}"></div></div>
      <div class="meta"><b data-count="${u.fails}">0</b>/ ${fmt(u.ips)} IP</div></div>`).join("")}</div>`;
  $$(".hrow", el).forEach(r => { const u = list[+r.dataset.i]; bindTip(r, `<b>${esc(u.user)}</b><br>실패 ${fmt(u.fails)}회 · 공격 IP ${fmt(u.ips)}개`); });
  countUp($$(".meta b", el), 150, live);
  if (A && !live) {
    anime({ targets: $$(".fill", el), scaleX: [0, 1], delay: anime.stagger(60), easing: "spring(1, 80, 12, 0)" });
    setTimeout(() => $$(".botrow", el).forEach(r => { shake(r, 7); anime({ targets: r, backgroundColor: ["rgba(255,159,67,.35)", "rgba(255,159,67,0)"], duration: 1200, easing: "easeOutQuad" }); }), 900);
  }
});

panel("timeline", "07", "공격 타임라인", "TRACE", ["timeline", "trace", "타임라인"], "긴급·높음 IP의 공격 시간대", 12, (el, live) => {
  const { from, to } = S.data.meta, span = to - from;
  const list = S.data.offenders.filter(o => ["critical", "high"].includes(o.severity)).sort((a, b) => a.first_ts - b.first_ts).slice(0, 20);
  if (!list.length) { el.innerHTML = metaLine() + empty("범위 안에 긴급·높음 IP가 없습니다."); return; }
  const pos = t => Math.max(0, Math.min(100, (t - from) / span * 100));
  const ticks = [0, 1, 2, 3, 4, 5, 6, 7, 8].map(k => from + span * k / 8);
  el.innerHTML = metaLine() + `<p class="hint">짧은 조각 = 몰아친 공격, 긴 줄 = 오래 이어진 공격. 빨간 글씨 = 침해 의심 IP.</p>
    <div class="tl"><div class="tl-cursor"><span></span></div>${list.map((o, i) => { const l = pos(o.first_ts), w = Math.max(.3, pos(o.last_ts) - l);
      return `<div class="tl-row" data-i="${i}"><div class="name ${o.severe ? "c-critical" : ""}">${esc(o.ip)}</div>
        <div class="tl-track">${ticks.map((_, k) => `<div class="hr" style="left:${k / 8 * 100}%"></div>`).join("")}
          <div class="tl-seg" style="left:${l}%;width:${w}%;background:${SEVC[o.severity]}"></div>
          ${o.severe ? `<div class="tl-note" style="left:calc(${l + w}% + 6px)">◀ 침해 의심</div>` : ""}</div></div>`; }).join("")}</div>
    <div class="tl-axis"><i></i><div>${ticks.map((t, k) => `<span style="left:${k / 8 * 100}%">${esc(fmtT(t).slice(-8, -3))}</span>`).join("")}</div></div>`;
  $$(".tl-row", el).forEach(r => { const o = list[+r.dataset.i]; bindTip(r, `<b>${esc(o.ip)}</b> ${sev(o.severity)}<br>${fmtT(o.first_ts)} → ${fmtT(o.last_ts)}<br>${o.rules.map(x => esc(x.title)).join("<br>")}`);
    r.onclick = () => o.incident_id && run(`incident ${o.incident_id}`); });
  const cur = $(".tl-cursor", el);
  if (!A || live) { cur.remove(); return; }
  const SW = 2200, o = { p: 0 };
  $$(".tl-seg, .tl-note", el).forEach(s => s.style.opacity = 0);
  anime({ targets: o, p: [0, 1], duration: SW, easing: "easeInOutSine",
    update: () => { cur.style.setProperty("--p", o.p); $("span", cur).textContent = fmtT(from + span * o.p).slice(-8, -3); },
    complete: () => anime({ targets: cur, opacity: [1, 0], duration: 400, easing: "linear" }) });
  list.forEach((x, i) => { const row = $$(".tl-row", el)[i], at = pos(x.first_ts) / 100 * SW;
    anime({ targets: $(".tl-seg", row), scaleX: [0, 1], opacity: [0, 1], delay: at, duration: 500, easing: "easeOutExpo" });
    const note = $(".tl-note", row);
    if (note) anime({ targets: note, opacity: [0, 1], delay: pos(x.last_ts) / 100 * SW + 200, duration: 400, easing: "easeOutBack", complete: () => flicker(note, 2) }); });
});

// ---------------------------------------------------------------- 3D 지구본 (motion.dev)
const LIBS = { d3: "https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js", topo: "https://cdn.jsdelivr.net/npm/topojson-client@3.1.0/dist/topojson-client.min.js",
  world: "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json", world50: "https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-50m.json",
  simplify: "https://cdn.jsdelivr.net/npm/topojson-simplify@3.0.3/dist/topojson-simplify.min.js" };
let worldCache = null, worldDetail = null;
const loadScript = src => new Promise((ok, no) => { const s = document.createElement("script"); s.src = src; s.onload = ok; s.onerror = no; document.head.appendChild(s); });
async function loadWorld() {
  if (worldCache) return worldCache;
  if (!window.d3) await loadScript(LIBS.d3);
  if (!window.topojson) await loadScript(LIBS.topo);
  const topo = await (await fetch(LIBS.world)).json();
  return (worldCache = { land: topojson.feature(topo, topo.objects.countries), borders: topojson.mesh(topo, topo.objects.countries, (a, b) => a !== b) });
}
// 정밀 지도(1:5천만, 약 750KB)를 단순화 정도 q(남길 점 비율)로 만드는 함수 — 매 프레임 그려도 되는 수준으로 줄여 씀
async function loadWorldDetail() {
  if (worldDetail) return worldDetail;
  if (!topojson.presimplify) await loadScript(LIBS.simplify);
  const pre = topojson.presimplify(await (await fetch(LIBS.world50)).json()), made = {};
  return (worldDetail = q => made[q] ||= (() => { const t = topojson.simplify(pre, topojson.quantile(pre, q));
    return { land: topojson.feature(t, t.objects.countries), borders: topojson.mesh(t, t.objects.countries, (a, b) => a !== b) }; })());
}
// 태양 직하점 (경도·위도) — 낮/밤 경계용 (균시차 무시, 오차 수 도 이내)
function subsolar(date = new Date()) {
  const doy = (Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()) - Date.UTC(date.getUTCFullYear(), 0, 0)) / 864e5;
  const decl = 23.44 * Math.sin(2 * Math.PI * (284 + doy) / 365);
  const hrs = date.getUTCHours() + date.getUTCMinutes() / 60 + date.getUTCSeconds() / 3600;
  return [((-15 * (hrs - 12)) + 540) % 360 - 180, decl];
}
function tween(from, to, opts, onUpdate) { if (!M) { onUpdate(to); return { stop() {} }; } return M.animate(from, to, { ...opts, onUpdate }); }
panel("map", "08", "공격 출발지 3D 지구본", "GEO ATTACK GLOBE", ["map", "geo", "globe", "지도"], "공격 국가 → 서버 경로 (드래그·확대·클릭)", 12, async (el, live) => {
  const G = S.data.geo, list = G.countries, top = list.slice(0, 10), maxF = list.length ? list[0].fails : 1;
  const colorOf = c => c.level ? SEVX[c.level] : "#67e8f9";
  const quiet = G.source === "none" ? `<div class="geo-quiet c-high">위치 DB 없음 — 서버에서 <code>sudo /usr/local/lib/rkmsiem/geoip-update</code> 를 실행하면 공격 국가가 표시됩니다.</div>`
    : `<div class="geo-quiet"><b class="acc">● 공격 없음</b><br><span class="dim">범위(${esc(S.range.label)}) 안에 외부 IP 의 로그인 실패가 없습니다. 생기면 실시간으로 나타납니다 · <span class="link" data-cmd="range 7d">range 7d</span> 로 넓혀 보기</span></div>`;
  el.innerHTML = metaLine(G.source === "sample" ? `<span class="sample-badge">SAMPLE GEO</span> <span>위치는 데모용 추정</span>` : "") +
    `<p class="hint">솟은 기둥 = 그 나라에서 온 실패 횟수, 떠 있는 호 = 관제 서버로 향한 공격 경로. 색 = 그 나라 IP 중 가장 높은 경보 심각도, 하늘색 = 경보 없는 트래픽.</p>
    <div class="globe-wrap"><div class="globe-box">
      <div class="globe-ctrl"><button class="gbtn" data-act="home">◎ 서버</button><button class="gbtn" data-act="spin" aria-pressed="true">⟳ 자동 회전</button>
        <button class="gbtn" data-act="in" aria-label="확대">＋</button><button class="gbtn" data-act="out" aria-label="축소">－</button></div>
      <div class="globe-stage"><div class="dim" style="padding:40px 0">지구본 불러오는 중…</div></div>
      <div class="globe-help">드래그: 회전 · 휠: 확대/축소 · 국가 클릭: 이동 · 더블클릭: 처음 위치</div></div>
      <div class="map-side"><h4>국가별 실패 상위 10 <span class="faint" style="font-weight:400">· 클릭하면 이동</span></h4>
        ${top.map((c, i) => `<div class="crow" data-i="${i}"><span class="cc">${esc(c.cc)}</span><span>${esc(c.name)} ${c.level ? sev(c.level) : ""}</span><span class="n">${fmt(c.fails)}</span>
          <div class="bar"><i style="width:${c.fails / maxF * 100}%;background:${colorOf(c)}"></i></div></div>`).join("") || quiet}
        <div class="geo-note">${G.source === "none" ? "※ 위치 DB 없음." : G.source === "sample" ? "※ 위치는 데모용 샘플 GeoIP(IP 대역 추정)라 실제 위치가 아닙니다. data/GeoLite2-City.mmdb 와 geoip2 패키지가 있으면 실제 DB로 조회합니다." : (/dbip/i.test(G.db || "") ? `※ 위치: <a href="https://db-ip.com" target="_blank" rel="noopener" class="link">IP Geolocation by DB-IP</a> (${esc(G.db)}, CC BY 4.0)` : `※ 위치: ${esc(G.db || "MaxMind GeoLite2")}`)} 사내망 IP는 제외.</div></div></div>`;
  const rows = $$(".crow", el);
  rows.forEach(r => { const c = top[+r.dataset.i]; bindTip(r, `<b>${esc(c.cc)}</b> ${esc(c.name)}<br>실패 ${fmt(c.fails)}회 · IP ${fmt(c.ips)}개${c.alert_ips.length ? `<br>경보 IP: ${c.alert_ips.map(esc).join(", ")}` : ""}`); });
  if (M && !live) M.animate(rows, { opacity: [0, 1], x: [24, 0] }, { delay: M.stagger(0.05), type: "spring", stiffness: 200, damping: 20 });
  const stage = $(".globe-stage", el), box = $(".globe-box", el);
  let world;
  try { world = await loadWorld(); } catch (e) { stage.innerHTML = `<div class="c-high" style="padding:40px 0">지구본 데이터를 불러오지 못했습니다 (인터넷 연결 확인). 오른쪽 목록은 그대로 볼 수 있습니다.</div>`; return; }
  const W = stage.clientWidth || 700, H = Math.round(Math.min(W * 0.8, 620)), R = Math.min(W, H) / 2 / 1.42;
  const srv = G.server, byNum = new Map(list.map(c => [c.num, c]));
  const St = { lam: -srv.lon + 170, phi: -28, k: .45, grow: 0, spike: 0, auto: !reduceMotion, focus: null };
  const proj = d3.geoOrthographic().translate([W / 2, H / 2]).clipAngle(90).precision(.7), path = d3.geoPath(proj);
  const svg = d3.create("svg").attr("viewBox", `0 0 ${W} ${H}`).attr("class", "globe").attr("role", "img").attr("aria-label", "공격 출발지 3D 지구본");
  const defs = svg.append("defs");
  const g1 = defs.append("radialGradient").attr("id", "ocean").attr("cx", "35%").attr("cy", "30%").attr("r", "75%");
  g1.append("stop").attr("offset", "0%").attr("stop-color", "#1a2a3c"); g1.append("stop").attr("offset", "100%").attr("stop-color", "#070b11");
  const g2 = defs.append("radialGradient").attr("id", "atmo");
  [["86%", 0], ["93%", .35], ["100%", 0]].forEach(([o, a]) => g2.append("stop").attr("offset", o).attr("stop-color", "#67e8f9").attr("stop-opacity", a));
  const g3 = defs.append("radialGradient").attr("id", "shade").attr("cx", "30%").attr("cy", "28%").attr("r", "80%");
  g3.append("stop").attr("offset", "0%").attr("stop-color", "#fff").attr("stop-opacity", .10); g3.append("stop").attr("offset", "60%").attr("stop-color", "#000").attr("stop-opacity", 0);
  g3.append("stop").attr("offset", "100%").attr("stop-color", "#000").attr("stop-opacity", .45);
  const g4 = defs.append("radialGradient").attr("id", "rim");                  // 가장자리 대기광
  [["90%", 0], ["97%", .55], ["100%", .9]].forEach(([o, a]) => g4.append("stop").attr("offset", o).attr("stop-color", "#8be9ff").attr("stop-opacity", a));
  // 별 (지구본 회전에 따라 천천히 흘러감 — 원근감, 반짝임 없음)
  const stars = svg.append("g").attr("class", "gstars").attr("pointer-events", "none");
  const starData = Array.from({ length: 170 }, () => ({ x: Math.random() * W * 2, y: Math.random() * H, r: Math.random() < .08 ? 1.3 : .35 + Math.random() * .6,
    o: .25 + Math.random() * .6 }));
  const starEls = starData.map(d => stars.append("circle").attr("r", d.r).attr("fill", "#cfe8ff").node());
  const atmo = svg.append("circle").attr("cx", W / 2).attr("cy", H / 2).attr("fill", "url(#atmo)");
  const sphere = svg.append("circle").attr("cx", W / 2).attr("cy", H / 2).attr("fill", "url(#ocean)");
  const grat = svg.append("path").attr("class", "grat").datum(d3.geoGraticule10());
  const fillOf = c => c.level ? SEVX[c.level] : "#67e8f9", alphaOf = c => .22 + .55 * Math.sqrt(c.fails / maxF);
  // 지도는 한 벌만 (멈춤/움직임에 따라 바꾸지 않음 — 선명↔뭉개짐 반복 방지).
  // 처음엔 110m 로 그리고, 정밀 지도가 준비되면 이 PC 성능에 맞는 단순화 정도를 골라 한 번만 교체
  function layer(w, cls, before) {
    const g = before ? svg.insert("g", () => before).attr("class", cls) : svg.append("g").attr("class", cls);
    const feats = w.land.features.map(f => { const b = d3.geoBounds(f), c = d3.geoCentroid(f);
      return Object.assign(f, { _c: c, _r: Math.max(d3.geoDistance(c, b[0]), d3.geoDistance(c, b[1]), d3.geoDistance(c, [b[0][0], b[1][1]]), d3.geoDistance(c, [b[1][0], b[0][1]])) }); });
    const lands = g.selectAll("path").data(feats).join("path").attr("class", d => "land" + (byNum.has(String(d.id).padStart(3, "0")) ? " hit" : ""))
      .each(function (d) { const c = byNum.get(String(d.id).padStart(3, "0")); if (c) { this.style.fill = fillOf(c); this.style.fillOpacity = alphaOf(c); } });
    lands.on("mousemove", (e, d) => { const c = byNum.get(String(d.id).padStart(3, "0"));
      showTip(e, c ? `<b>${esc(c.cc)}</b> ${esc(c.name)}<br>실패 ${fmt(c.fails)}회 · IP ${fmt(c.ips)}개${c.level ? `<br>최고 심각도 ${sev(c.level)}` : ""}` : esc(d.properties.name)); })
      .on("mouseleave", hideTip).on("click", (e, d) => { const c = byNum.get(String(d.id).padStart(3, "0")); if (c) focus(c); });
    const border = g.append("path").attr("class", "border").attr("pointer-events", "none").datum(w.borders);
    const nodes = lands.nodes();
    const one = (el, center) => { const d = el.__data__; el.setAttribute("d", d3.geoDistance(d._c, center) - d._r > Math.PI / 2 + .02 ? "" : path(d) || ""); };
    return { g, draw(center) {                                         // 화면 뒤쪽(보이지 않는) 나라는 계산 생략
      nodes.forEach(el => one(el, center)); border.attr("d", path); },
      cost(center) { const t0 = performance.now(); nodes.forEach(el => { const d = el.__data__; if (d3.geoDistance(d._c, center) - d._r <= Math.PI / 2 + .02) path(d); });
        return performance.now() - t0; } };
  }
  let land = layer(world, "gland");
  const view = { key: "" };
  loadWorldDetail().then(make => {
    if (!svg.node().isConnected) return;
    const center = [-St.lam, -St.phi], base = land.cost(center);
    // 기존 지도 대비 1.8배 이내(또는 6ms 이내)인 가장 세밀한 단계 — 느린 PC 는 기존 지도 유지
    for (const q of [0.14, 0.1, 0.07]) {
      const w = make(q), cand = layer(w, "gland", land.g.node());
      cand.g.style("display", "none");
      if (cand.cost(center) <= Math.max(6, base * 1.8)) { cand.g.style("display", null); land.g.remove(); land = cand; view.key = ""; view.q = q; return; }
      cand.g.remove();
    }
  }).catch(() => { /* 기존 지도 유지 */ });
  // 밤 쪽 (태양 반대편 반구) + 박명 띠
  const night = svg.append("g").attr("class", "gnight").attr("pointer-events", "none");
  const nightPaths = [[90, .5], [96, .18], [102, .12]].map(([rad, op]) => ({ c: d3.geoCircle().radius(rad), el: night.append("path").attr("fill", "#02040a").attr("fill-opacity", op).node() }));
  const shade = svg.append("circle").attr("cx", W / 2).attr("cy", H / 2).attr("fill", "url(#shade)").attr("pointer-events", "none");
  const rim = svg.append("circle").attr("cx", W / 2).attr("cy", H / 2).attr("fill", "url(#rim)").attr("pointer-events", "none");
  const gArc = svg.append("g"), gSpk = svg.append("g"), gPkt = svg.append("g"),
    gLab = svg.append("g").attr("pointer-events", "none");

  const N = 44;
  const arcs = list.map((c, i) => {
    const ip = d3.geoInterpolate([c.lon, c.lat], [srv.lon, srv.lat]), dist = d3.geoDistance([c.lon, c.lat], [srv.lon, srv.lat]);
    const strong = c.level === "critical" || c.level === "high", col = colorOf(c);
    return { c, i, ip, alt: .06 + .32 * dist / Math.PI, strong, off: Math.random(),
      halo: gArc.append("path").attr("fill", "none").attr("stroke", col).attr("stroke-linecap", "round").attr("stroke-width", strong ? 7 : 3.5).node(),
      arc: gArc.append("path").attr("fill", "none").attr("stroke", col).attr("stroke-linecap", "round").attr("stroke-width", strong ? 2.2 : 1).node(),
      pkh: strong ? gPkt.append("circle").attr("r", 7).attr("fill", col).node() : null,
      pkt: strong ? gPkt.append("circle").attr("r", 3.2).attr("fill", "#fff").node() : null,
      tail: strong ? [1, 2, 3, 4].map(k => gPkt.append("circle").attr("r", 3 - k * .55).attr("fill", col).node()) : [],
      wave: strong ? gSpk.append("ellipse").attr("fill", "none").attr("stroke", col).attr("stroke-width", 1.6).node() : null,
      spk: gSpk.append("line").attr("stroke", col).attr("stroke-linecap", "round").attr("stroke-width", 2 + Math.sqrt(c.fails / maxF) * 4).node(),
      cap: gSpk.append("circle").attr("r", 3).attr("fill", col).style("cursor", "pointer").node(), h: .04 + .32 * Math.sqrt(c.fails / maxF),
      lab: i < 6 ? gLab.append("text").attr("class", "glabel").text(`${c.name} ${fmt(c.fails)}`).node() : null };
  });
  arcs.forEach(a => { bindTip(a.cap, `<b>${esc(a.c.cc)}</b> ${esc(a.c.name)}<br>실패 ${fmt(a.c.fails)}회 · IP ${fmt(a.c.ips)}개`); a.cap.addEventListener("click", () => focus(a.c)); });
  const beam = gSpk.append("line").attr("stroke", "var(--accent)").attr("stroke-width", 3).attr("stroke-linecap", "round").node();
  const ring = gSpk.append("ellipse").attr("fill", "none").attr("stroke", "var(--accent)").attr("stroke-width", 2).node();
  const core = gSpk.append("circle").attr("r", 5).attr("fill", "var(--accent)").node();
  const srvLab = gLab.append("text").attr("class", "glabel srv").text("◎ " + srv.name).node();
  stage.innerHTML = ""; stage.appendChild(svg.node());
  let rot;
  function P3(lon, lat, h = 0) {
    const [l, f] = rot([lon, lat]), L = l * Math.PI / 180, F = f * Math.PI / 180;
    const x = Math.cos(F) * Math.sin(L), y = Math.sin(F), z = Math.cos(F) * Math.cos(L), r = R * St.k * (1 + h);
    return { x: W / 2 + r * x, y: H / 2 - r * y, z, vis: z > 0 || (x * x + y * y) * (1 + h) * (1 + h) > 1 };
  }
  function draw(now) {
    const Rs = R * St.k;
    proj.scale(Rs).rotate([St.lam, St.phi]); rot = d3.geoRotation([St.lam, St.phi]);
    atmo.attr("r", Rs * 1.18); sphere.attr("r", Rs); shade.attr("r", Rs); rim.attr("r", Rs * 1.012); grat.attr("d", path);
    const key = `${St.lam},${St.phi},${St.k}`;
    if (key !== view.key) { land.draw([-St.lam, -St.phi]); view.key = key; }     // 움직이지 않으면 땅은 다시 계산하지 않음
    const [sx, sy] = subsolar(), anti = [sx + 180, -sy];
    nightPaths.forEach(n => n.el.setAttribute("d", path(n.c.center(anti)()) || ""));
    const drift = ((St.lam * 1.6) % (W * 2) + W * 2) % (W * 2), dphi = St.phi * .6;
    starData.forEach((s, i) => { let x = s.x - drift; if (x < 0) x += W * 2; const y = (s.y + dphi + H) % H, dx = x - W / 2, dy = y - H / 2;
      const el = starEls[i], d2 = Math.sqrt(dx * dx + dy * dy) / (Rs * 1.05), fade = Math.max(0, Math.min(1, (d2 - 1) * 4));
      el.setAttribute("cx", x); el.setAttribute("cy", y); el.setAttribute("opacity", x > W ? 0 : s.o * fade); });
    arcs.forEach(a => {
      const dim = St.focus && St.focus !== a.c.cc, g = Math.max(0, Math.min(1, St.grow * 1.8 - a.i * .05));
      let d = "", pen = false;
      for (let j = 0; j <= N * g; j++) { const t = j / N, [lo, la] = a.ip(t), p = P3(lo, la, Math.sin(Math.PI * t) * a.alt);
        if (p.vis) { d += (pen ? "L" : "M") + p.x.toFixed(1) + "," + p.y.toFixed(1); pen = true; } else pen = false; }
      a.arc.setAttribute("d", d); a.arc.setAttribute("opacity", dim ? .08 : a.strong ? .95 : .35);
      a.halo.setAttribute("d", d); a.halo.setAttribute("opacity", dim ? 0 : a.strong ? .18 : .07);
      if (a.pkt) { const t = ((now / 1700) + a.off) % 1, [lo, la] = a.ip(t), p = P3(lo, la, Math.sin(Math.PI * t) * a.alt);
        a.pkt.setAttribute("cx", p.x); a.pkt.setAttribute("cy", p.y); a.pkt.setAttribute("opacity", p.vis && t <= g && !dim ? 1 : 0);
        a.pkh.setAttribute("cx", p.x); a.pkh.setAttribute("cy", p.y); a.pkh.setAttribute("opacity", p.vis && t <= g && !dim ? .3 : 0);
        a.tail.forEach((el, k) => { const tk = t - (k + 1) * .018; if (tk < 0) { el.setAttribute("opacity", 0); return; }
          const [lo2, la2] = a.ip(tk), q = P3(lo2, la2, Math.sin(Math.PI * tk) * a.alt);
          el.setAttribute("cx", q.x); el.setAttribute("cy", q.y); el.setAttribute("opacity", q.vis && tk <= g && !dim ? .75 - k * .17 : 0); }); }
      const b = P3(a.c.lon, a.c.lat, 0), tp = P3(a.c.lon, a.c.lat, a.h * St.spike), show = b.z > 0;
      a.spk.setAttribute("x1", b.x); a.spk.setAttribute("y1", b.y); a.spk.setAttribute("x2", tp.x); a.spk.setAttribute("y2", tp.y);
      a.spk.setAttribute("opacity", show ? (dim ? .15 : .9) : 0); a.cap.setAttribute("cx", tp.x); a.cap.setAttribute("cy", tp.y); a.cap.setAttribute("opacity", show ? 1 : 0);
      if (a.wave) { const ph = ((now / 1600) + a.off) % 1, rr = (4 + ph * 18) * St.k;
        a.wave.setAttribute("cx", b.x); a.wave.setAttribute("cy", b.y); a.wave.setAttribute("rx", rr); a.wave.setAttribute("ry", rr * Math.max(.25, Math.abs(b.z)));
        a.wave.setAttribute("opacity", show && !dim ? (1 - ph) * .8 : 0); }
      if (a.lab) { a.lab.setAttribute("x", tp.x + 7); a.lab.setAttribute("y", tp.y - 4); a.lab.setAttribute("opacity", show && St.spike > .6 && !dim ? 1 : 0); }
    });
    const sb = P3(srv.lon, srv.lat, 0), st = P3(srv.lon, srv.lat, .22 * St.spike), pulse = (now / 1400) % 1;
    beam.setAttribute("x1", sb.x); beam.setAttribute("y1", sb.y); beam.setAttribute("x2", st.x); beam.setAttribute("y2", st.y);
    core.setAttribute("cx", sb.x); core.setAttribute("cy", sb.y); ring.setAttribute("cx", sb.x); ring.setAttribute("cy", sb.y);
    ring.setAttribute("rx", 6 + pulse * 26 * St.k); ring.setAttribute("ry", (6 + pulse * 26 * St.k) * Math.max(.25, Math.abs(sb.z))); ring.setAttribute("opacity", sb.z > 0 ? 1 - pulse : 0);
    [beam, core].forEach(n => n.setAttribute("opacity", sb.z > 0 ? 1 : 0));
    srvLab.setAttribute("x", st.x + 8); srvLab.setAttribute("y", st.y); srvLab.setAttribute("opacity", sb.z > 0 ? 1 : 0);
  }
  let last = performance.now(), dragging = false;
  (function frame(now) { if (!svg.node().isConnected) return; const dt = Math.min(50, now - last); last = now;
    if (St.auto && !dragging && !St.focus) St.lam += dt * .006; draw(now); requestAnimationFrame(frame); })(last);
  let rotAnims = [];
  const stopRot = () => { rotAnims.forEach(a => a.stop()); rotAnims = []; };
  if (M && !live) M.animate(stage, { opacity: [0, 1], scale: [.85, 1] }, { duration: .9, ease: [.2, .8, .2, 1] });
  tween(St.k, 1, { type: "spring", stiffness: 45, damping: 11 }, v => St.k = v);
  rotAnims.push(tween(St.lam, -srv.lon + 25, { type: "spring", stiffness: 18, damping: 9 }, v => St.lam = v));
  tween(0, 1, { duration: 2.6, ease: "easeInOut", delay: .5 }, v => St.grow = v);
  tween(0, 1, { type: "spring", stiffness: 70, damping: 7, delay: 1.1 }, v => St.spike = v);
  const sv = svg.node();
  let dr = null;
  sv.addEventListener("pointerdown", e => { stopRot(); dragging = true; St.auto = false; hideTip();
    dr = { x: e.clientX, y: e.clientY, lam: St.lam, phi: St.phi, lx: e.clientX, ly: e.clientY, lt: performance.now(), vx: 0, vy: 0 }; sv.setPointerCapture(e.pointerId); });
  sv.addEventListener("pointermove", e => { if (!dr) return; const sens = .32 / St.k, now = performance.now(), dt = Math.max(1, now - dr.lt);
    St.lam = dr.lam + (e.clientX - dr.x) * sens; St.phi = Math.max(-80, Math.min(80, dr.phi - (e.clientY - dr.y) * sens));
    dr.vx = (e.clientX - dr.lx) / dt * 1000 * sens; dr.vy = -(e.clientY - dr.ly) / dt * 1000 * sens; dr.lx = e.clientX; dr.ly = e.clientY; dr.lt = now; });
  const endDrag = () => { if (!dr) return; const cv = v => Math.max(-360, Math.min(360, v)), vx = cv(dr.vx), vy = cv(dr.vy); dr = null; dragging = false;
    rotAnims.push(tween(St.lam, St.lam + vx * .18, { type: "spring", velocity: vx, stiffness: 30, damping: 14 }, v => St.lam = v));
    rotAnims.push(tween(St.phi, Math.max(-80, Math.min(80, St.phi + vy * .18)), { type: "spring", velocity: vy, stiffness: 30, damping: 14 }, v => St.phi = Math.max(-80, Math.min(80, v))));
    clearTimeout(endDrag.t); endDrag.t = setTimeout(() => { if ($('[data-act="spin"]', el).getAttribute("aria-pressed") === "true" && !St.focus) St.auto = true; }, 3500); };
  sv.addEventListener("pointerup", endDrag); sv.addEventListener("pointercancel", endDrag);
  let kTarget = 1, kAnim = null;
  const zoomTo = k => { kTarget = Math.max(.7, Math.min(3.2, k)); kAnim && kAnim.stop(); kAnim = tween(St.k, kTarget, { type: "spring", stiffness: 160, damping: 22 }, v => St.k = v); };
  sv.addEventListener("wheel", e => { e.preventDefault(); zoomTo(kTarget * (e.deltaY < 0 ? 1.15 : 1 / 1.15)); }, { passive: false });
  function rotateTo(lon, lat, k) { stopRot(); St.auto = false; let tl = -lon; while (tl - St.lam > 180) tl -= 360; while (tl - St.lam < -180) tl += 360;
    rotAnims.push(tween(St.lam, tl, { type: "spring", stiffness: 40, damping: 13 }, v => St.lam = v));
    rotAnims.push(tween(St.phi, Math.max(-70, Math.min(70, -lat)), { type: "spring", stiffness: 40, damping: 13 }, v => St.phi = v)); if (k) zoomTo(k); }
  function focus(c) { if (St.focus === c.cc) return reset(); St.focus = c.cc; rows.forEach(r => r.classList.toggle("active", top[+r.dataset.i]?.cc === c.cc));
    const mid = d3.geoInterpolate([c.lon, c.lat], [srv.lon, srv.lat])(.5); rotateTo(mid[0], mid[1], 1.35); }
  function reset() { St.focus = null; rows.forEach(r => r.classList.remove("active")); rotateTo(srv.lon - 25, 28, 1);
    setTimeout(() => { if ($('[data-act="spin"]', el).getAttribute("aria-pressed") === "true") St.auto = true; }, 1600); }
  sv.addEventListener("dblclick", reset);
  rows.forEach(r => r.addEventListener("click", () => focus(top[+r.dataset.i])));
  $$(".gbtn", el).forEach(b => b.addEventListener("click", () => { const a = b.dataset.act;
    if (a === "home") reset();
    if (a === "spin") { const on = b.getAttribute("aria-pressed") !== "true"; b.setAttribute("aria-pressed", on); St.auto = on && !St.focus; }
    if (a === "in") zoomTo(kTarget * 1.3); if (a === "out") zoomTo(kTarget / 1.3);
    if (M) M.animate(b, { scale: [.85, 1] }, { type: "spring", stiffness: 500, damping: 15 }); }));
  if (M) { box.addEventListener("mousemove", e => { if (dr) return; const r = box.getBoundingClientRect(), px = (e.clientX - r.left) / r.width - .5, py = (e.clientY - r.top) / r.height - .5;
      M.animate(stage, { rotateY: px * 14, rotateX: -py * 10 }, { type: "spring", stiffness: 120, damping: 16 }); });
    box.addEventListener("mouseleave", () => M.animate(stage, { rotateY: 0, rotateX: 0 }, { type: "spring", stiffness: 120, damping: 16 })); }
}, { liveSkip: true });

panel("ips", "09", "탐지 IP 목록", "OFFENDER LIST", ["ips", "offenders", "목록"], "경보가 걸린 IP 전체와 규칙·근거 (검색·필터)", 12, (el, live) => {
  const all = S.data.offenders;
  el.innerHTML = metaLine() + `<div class="filter"><input type="search" class="q" placeholder="IP 또는 계정 검색" aria-label="검색">
    ${[["all", "전체", "F1"], ["critical", "긴급", "F2"], ["high", "높음", "F3"], ["medium", "주의", "F4"], ["low", "낮음", "F5"]].map(([f, ko, k]) =>
      `<button class="fkey" data-f="${f}" aria-pressed="${f === ipFilter}"><kbd>${k}</kbd>${ko}</button>`).join("")}</div>
    <div class="tbl"><table><thead><tr><th>심각도</th><th>IP</th><th>탐지 규칙 · 근거</th><th style="text-align:right">위험</th><th style="text-align:right">실패</th><th style="text-align:right">성공</th><th>계정</th><th>시간</th><th>사건</th></tr></thead><tbody></tbody></table></div>`;
  const tb = $("tbody", el), q = $(".q", el);
  const render = () => {
    const s = q.value.trim().toLowerCase();
    const rows = all.filter(o => (ipFilter === "all" || o.severity === ipFilter) && (!s || o.ip.includes(s) || o.users.some(u => u.toLowerCase().includes(s))));
    tb.innerHTML = rows.length ? rows.map(o => `<tr class="${o.severe ? "crit" : ""}"><td>${sev(o.severity)}</td>
      <td style="white-space:nowrap"><span class="${o.severe ? "c-critical" : ""}">${esc(o.ip)}</span>${o.internal ? '<span class="tag-in">보정됨</span>' : ""}</td>
      <td class="rules">${o.rules.map(r => `<span class="rule">${sev(r.severity)} <b>${esc(r.title)}</b><br>${esc(r.detail)} <span class="basis">· ${esc(r.basis)}${r.modifiers.length ? " · " + r.modifiers.map(m => esc(m.note)).join(", ") : ""}</span></span>`).join("")}</td>
      <td class="num">${o.risk.toFixed(0)}</td><td class="num">${fmt(o.fails)}</td><td class="num ${o.severe && o.success ? "c-critical" : ""}">${fmt(o.success)}</td>
      <td class="dim">${o.users.slice(0, 6).map(esc).join(", ")}${o.users.length > 6 ? ` +${o.users.length - 6}` : ""}</td>
      <td style="white-space:nowrap">${fmtT(o.first_ts)}<br><span class="dim">${fmtT(o.last_ts)}</span></td>
      <td>${o.incident_id ? `<span class="link" data-cmd="incident ${o.incident_id}">#${o.incident_id}</span>` : "-"}</td></tr>`).join("")
      : `<tr><td colspan="9" class="dim" style="text-align:center;padding:16px">일치하는 항목이 없습니다.</td></tr>`;
    if (A && !live) anime({ targets: $$("tr", tb), rotateX: [-80, 0], opacity: [0, 1], delay: anime.stagger(40), duration: 600, easing: "easeOutBack" });
  };
  const setF = f => { ipFilter = f; $$(".fkey", el).forEach(b => b.setAttribute("aria-pressed", b.dataset.f === f)); render(); };
  $$(".fkey", el).forEach(b => b.onclick = () => setF(b.dataset.f));
  q.addEventListener("input", render);
  fkeyHandler = setF;
  render();
});
let ipFilter = "all", fkeyHandler = null;

panel("incidents", "10", "사건", "INCIDENTS", ["incidents", "cases", "사건"], "사건 목록 (상태·담당자) — 내 사건 · 미배정 · 담당자별", 12, async (el, live, arg) => {
  // 인자: mine | unassigned | open | assignee=<아이디>
  const a = (arg || "").trim(), me = S.me?.username;
  const who = a === "mine" ? me : (a.match(/^assignee=(\S+)$/) || [])[1];
  const q = new URLSearchParams({ sort: "-severity", size: "100" });
  if (who) q.set("assignee", who);
  if (a === "unassigned") { q.set("unassigned", "1"); q.set("open", "1"); }
  if (a === "open") q.set("open", "1");
  const [r, as] = await Promise.all([api(`/api/incidents?${q}`), api("/api/assignees").catch(() => ({ items: [] }))]);
  const names = Object.fromEntries(as.items.map(x => [x.username, x.display_name]));
  const tabs = [["", "전체"], ["open", "열린 사건"], ["mine", "내 사건"], ["unassigned", "미배정"]];
  el.innerHTML = `<div class="meta-line"><span>${who ? `담당 <b>${esc(names[who] || who)}</b> · ` : ""}<b>${fmt(r.total)}</b>건 · 정렬: 심각도</span><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span></div>
    <div class="filter">${tabs.map(([k, l]) => `<button class="fkey" data-inc="${k}" aria-pressed="${(a || "") === k || (k === "mine" && who === me && a !== "")}">${l}</button>`).join("")}
      <select class="inc-who" aria-label="담당자별"><option value="">담당자별…</option>${as.items.map(x => `<option value="${esc(x.username)}" ${x.username === who ? "selected" : ""}>${esc(x.display_name)} · ${x.open_incidents}</option>`).join("")}</select></div>` +
    (r.items.length ? `<div class="tbl"><table>
    <thead><tr><th>#</th><th>심각도</th><th>상태</th><th>제목</th><th style="text-align:right">경보</th><th>담당</th><th>마지막 이벤트</th></tr></thead><tbody>${r.items.map(i => `
    <tr class="${i.severity === "critical" && !["resolved", "false_positive"].includes(i.state) ? "crit" : ""}" style="cursor:pointer" data-cmd="incident ${i.id}">
      <td class="num">${i.id}</td><td>${sev(i.severity)}</td><td>${state(i.state)}</td><td>${esc(i.title)}${i.sample ? ' <span class="sample-badge">SAMPLE</span>' : ""}</td>
      <td class="num">${i.alert_count}</td><td>${i.assignee ? `<span class="${i.assignee === me ? "acc" : ""}">${esc(names[i.assignee] || i.assignee)}</span>` : '<span class="c-high">미배정</span>'}</td>
      <td style="white-space:nowrap">${fmtT(i.last_event_ts)}</td></tr>`).join("")}</tbody></table></div>` : empty(a === "unassigned" ? "미배정 열린 사건이 없습니다." : "사건이 없습니다."));
  $$("[data-inc]", el).forEach(b => b.onclick = () => run(`dashboard incidents ${b.dataset.inc}`.trim()));
  $(".inc-who", el).onchange = e => e.target.value && run(`dashboard incidents assignee=${e.target.value}`);
  if (A && !live) anime({ targets: $$("tbody tr", el), translateX: [-20, 0], opacity: [0, 1], delay: anime.stagger(35), duration: 400, easing: "easeOutCubic" });
});

panel("runs", "11", "플레이북 실행 · 승인", "SOAR RUNS", ["runs", "playbooks", "대응"], "실행 상태와 승인 대기 — 바로 승인/거절", 12, async (el, live) => {
  const r = await api(`/api/runs?size=50`);
  const pend = S.data.playbooks.pending_approvals, tasks = S.data.playbooks.pending_tasks || [];
  el.innerHTML = `<div class="meta-line"><span>실행 모드 <b>${esc(S.me.mode)}</b>${S.me.mode === "simulate" ? " (외부 변경 없음)" : " — 승인된 조치가 실제 반영됨"}</span><span>성공률 <b>${S.data.playbooks.success_rate == null ? "-" : (S.data.playbooks.success_rate * 100).toFixed(0) + "%"}</b></span><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span></div>
    <h4 style="margin:0 0 8px;font:700 14px var(--ko)">승인 대기 ${pend.length}건</h4>
    ${pend.length ? pend.map(p => `<div class="step waiting_approval"><span class="ix">#${p.run_id}</span><div><b>${esc(p.playbook_id)}</b> · 단계 <b>${esc(p.step_id)}</b> (${esc(p.action)})
       · 사건 <span class="link" data-cmd="incident ${p.incident_id}">#${p.incident_id}</span><div class="out">${esc(JSON.stringify(p.input))}</div>
       <div class="dim" style="font-size:12px">요청 ${fmtT(p.requested_at)} · 만료 ${fmtT(p.expires_at)}</div>${approvalForm(p.run_id, p.step_id)}</div><span></span></div>`).join("") : empty("승인 대기 중인 조치가 없습니다.")}
    <h4 style="margin:18px 0 8px;font:700 14px var(--ko)">사람 할 일 ${tasks.length}건</h4>
    ${tasks.length ? tasks.map(t => `<div class="step waiting_task"><span class="ix">#${t.run_id}</span><div><b>${esc(t.title)}</b> <span class="dim">· ${esc(t.playbook_id)} · 확인 ${t.checklist.length}개</span>
       ${t.incident_id ? ` · 사건 <span class="link" data-cmd="incident ${t.incident_id}">#${t.incident_id}</span>` : ""} · <span class="link" data-cmd="run ${t.run_id}">열기</span>
       <div class="dim" style="font-size:12px">요청 ${fmtT(t.requested_at)}</div></div><span></span></div>`).join("") : empty("기다리는 할 일이 없습니다.")}
    <h4 style="margin:18px 0 8px;font:700 14px var(--ko)">최근 실행</h4>
    ${r.items.length ? `<div class="tbl"><table><thead><tr><th>#</th><th>플레이북</th><th>상태</th><th>모드</th><th>사건</th><th>요청</th><th>생성</th></tr></thead><tbody>${r.items.map(x => `
      <tr style="cursor:pointer" data-cmd="run ${x.id}"><td class="num">${x.id}</td><td>${esc(x.playbook_id)} v${x.playbook_version}</td><td>${state(x.state)}</td><td>${esc(x.mode)}</td>
      <td>${x.incident_id ? "#" + x.incident_id : "-"}</td><td>${esc(x.requested_by)}</td><td>${fmtT(x.created_at)}</td></tr>`).join("")}</tbody></table></div>` : empty("실행 기록이 없습니다.")}`;
  bindApprovalForms(el);
  if (A && !live) anime({ targets: $$(".step, tbody tr", el), opacity: [0, 1], translateY: [8, 0], delay: anime.stagger(30), duration: 350, easing: "easeOutCubic" });
});

panel("rules", "12", "탐지 규칙", "/etc/rkmsiem/rules", ["rules", "policy", "규칙", "기준"], "활성 규칙 · 단계 기준 · 실행 통계 (설정 기반)", 12, async (el, live) => {
  const r = await api("/api/rules");
  el.innerHTML = `<div class="meta-line"><span>규칙 <b>${r.items.length}</b>개 · 저장소: config_versions (변경 이력·롤백)</span><span>통계 = 이 서버 기동 이후</span></div>
    <pre class="conf">${r.items.map(x => `<span class="ln"><span class="k">${esc(x.id)}</span> <span class="c"># v${x.version} · ${esc(x.type)} · <span class="ko">${esc(x.name)}</span></span>
  enabled = <span class="v${x.enabled ? "" : " a"}">${x.enabled}</span>   levels = ${x.levels.map(l => `<span class="v">${esc(l.id)}≥${l.min}</span>(${l.severity})`).join(" ")}
  <span class="c"># 평가 ${fmt(x.stats.evaluated)} · 일치 ${fmt(x.stats.matched)} · 경보 ${fmt(x.alerts_total)} · 상향 ${fmt(x.stats.escalations)} · 오탐 처리 ${x.false_positives}${x.fp_rate != null ? ` (${(x.fp_rate * 100).toFixed(1)}%)` : ""} · 평가 ${(x.stats.ms || 0).toFixed(1)}ms</span>${can("rules:write") ? `  <span class="link" data-toggle="${esc(x.id)}" data-en="${x.enabled}">[${x.enabled ? "비활성화" : "활성화"}]</span>` : ""}</span>`).join("\n\n")}</pre>`;
  $$("[data-toggle]", el).forEach(b => b.onclick = async () => {
    try { await api(`/api/rules/${b.dataset.toggle}/enabled`, { method: "POST", body: { enabled: b.dataset.en !== "true", reason: "콘솔에서 변경" } }); toast(`규칙 ${esc(b.dataset.toggle)} 변경됨`); await PANELS.rules.render(el, true); }
    catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); } });
  if (A && !live) anime({ targets: $$(".ln", el), opacity: [0, 1], translateX: [-24, 0], delay: anime.stagger(60), duration: 450, easing: "easeOutCubic" });
}, { noOverview: true });

panel("collectors", "13", "수집기 · 파이프라인", "INGEST HEALTH", ["collectors", "ingest", "수집"], "수집기 상태 · 큐 · 지연 · 오류", 12, async (el, live) => {
  const r = await api("/api/collectors"), p = r.pipeline, lat = p.latency.all || {};
  el.innerHTML = `<div class="meta-line"><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span><span>마지막 배치 <b>${fmtT(p.last_batch_at)}</b></span></div>
    <div class="kpis">${[["큐", `${fmt(p.queue_depth)} / ${fmt(p.queue_size)}`, p.queue_depth > p.queue_size * .9], ["수신", fmt(p.received)], ["저장", fmt(p.stored)],
      ["중복 제거", fmt(p.duplicates)], ["파싱 실패(DLQ)", `${fmt(p.parse_errors)} · 대기 ${fmt(p.dlq_pending)}`, p.dlq_pending > 0], ["거부(429)", fmt(p.rejected), p.rejected > 0],
      ["수집 지연 평균", lat.avg_ms == null ? "-" : `${lat.avg_ms}ms`], ["p95 이하", lat.p95_le_ms == null ? "-" : `${lat.p95_le_ms}ms`], ["작업자", p.alive ? "정상" : "중지", !p.alive]]
      .map(([k, v, hot]) => `<div class="kpi ${hot ? "hot" : ""}"><div class="k">${k}</div><div class="v" style="font-size:24px">${v}</div></div>`).join("")}</div>
    <div class="tbl" style="margin-top:14px"><table><thead><tr><th>소스</th><th>유형</th><th>파서</th><th>상태</th><th style="text-align:right">수신</th><th>마지막 수신</th><th>오류</th></tr></thead><tbody>
    ${r.collectors.map(c => `<tr><td>${esc(c.id)} ${c.sample ? '<span class="sample-badge">SAMPLE</span>' : ""}${c.listen ? `<br><span class="dim">${esc(c.listen)}</span>` : ""}</td><td>${esc(c.type)}</td><td>${esc(c.parser)}</td>
      <td>${state(c.state === "running" || c.state === "passive" ? "succeeded" : c.state === "backpressure" || c.state === "waiting" ? "pending" : "failed").replace(/>[^<]+</, `>${esc(c.state)}<`)}</td>
      <td class="num">${fmt(c.received)}</td><td>${fmtT(c.last_event_at)}</td><td class="dim">${esc(c.last_error || "")}</td></tr>`).join("") || `<tr><td colspan="7">${empty("실행 중인 수집기가 없습니다.")}</td></tr>`}</tbody></table></div>`;
  if (A && !live) anime({ targets: $$(".kpi", el), rotateX: [-95, 0], opacity: [0, 1], delay: anime.stagger(50), easing: "spring(1, 70, 10, 0)" });
}, { noOverview: true });

panel("events", "14", "이벤트 검색", "EVENT SEARCH", ["events", "search", "검색"], "정규화된 이벤트 검색 (ip= user= outcome= source= 텍스트)", 12, async (el, live, arg) => {
  const params = new URLSearchParams(rangeQuery());
  const free = [];
  (arg || "").split(/\s+/).filter(Boolean).forEach(t => { const m = t.match(/^(ip|user|outcome|source|dataset|action|page)=(.+)$/); m ? params.set(m[1], m[2]) : free.push(t); });
  if (free.length) params.set("q", free.join(" "));
  params.set("size", "50");
  const r = await api(`/api/events?${params}`);
  const page = r.page, pages = Math.max(1, Math.ceil(r.total / r.size));
  el.innerHTML = metaLine(`<span>조건 <b>${esc(arg || "(없음)")}</b></span>`) + `<div class="inline-form"><input class="q" value="${esc(arg || "")}" placeholder="ip=1.2.3.4 user=admin outcome=failure 텍스트"><button class="btn primary">검색</button></div>
    <div class="tbl" style="margin-top:10px"><table><thead><tr><th>발생 시각</th><th>소스</th><th>결과</th><th>계정</th><th>IP</th><th>메시지</th></tr></thead><tbody>
    ${r.items.map(e => `<tr><td style="white-space:nowrap">${fmtT(e.ts)}</td><td>${esc(e.source_id)}${e.sample ? ' <span class="sample-badge">S</span>' : ""}</td><td>${state(e.outcome === "failure" ? "failed" : e.outcome === "success" ? "succeeded" : "skipped").replace(/>[^<]+</, `>${esc(e.outcome)}<`)}</td>
      <td>${esc(e.user_name || "")}</td><td>${e.source_ip ? `<span class="link" data-cmd="search ip=${esc(e.source_ip)}">${esc(e.source_ip)}</span>` : ""}</td><td class="dim">${esc((e.message || "").slice(0, 160))}</td></tr>`).join("") || `<tr><td colspan="6">${empty("검색 결과가 없습니다.")}</td></tr>`}</tbody></table></div>
    <div class="pager">${fmt(r.total)}건 · ${page}/${pages} 쪽 ${page > 1 ? `<button class="btn" data-pg="${page - 1}">이전</button>` : ""}${page < pages ? `<button class="btn" data-pg="${page + 1}">다음</button>` : ""}</div>`;
  const go = a => run(`search ${a}`);
  $(".btn.primary", el).onclick = () => go($(".q", el).value);
  $(".q", el).onkeydown = e => { if (e.key === "Enter") go(e.target.value); };
  $$("[data-pg]", el).forEach(b => b.onclick = () => go(`${(arg || "").replace(/\bpage=\d+/, "").trim()} page=${b.dataset.pg}`));
});

panel("audit", "15", "감사 로그", "AUDIT TRAIL", ["audit", "감사"], "모든 조작 기록 · 해시 체인 무결성", 12, async (el, live) => {
  const [r, v] = await Promise.all([api("/api/audit?size=100"), api("/api/audit/verify")]);
  el.innerHTML = `<div class="meta-line"><span>무결성 <b class="${v.ok ? "acc" : "c-critical"}">${v.ok ? `정상 (${fmt(v.checked)}건 검증)` : `훼손 감지 — #${v.broken_at}`}</b></span><span>최근 100건 · 수정/삭제 불가</span></div>
    <div class="tbl"><table><thead><tr><th>#</th><th>시각</th><th>주체</th><th>행위</th><th>대상</th><th>사유</th><th>내용</th></tr></thead><tbody>${r.items.map(a => `
    <tr><td class="num">${a.id}</td><td style="white-space:nowrap">${fmtT(a.ts)}</td><td>${esc(a.actor)}</td><td><b>${esc(a.action)}</b></td><td>${esc(a.target_type || "")} ${esc(a.target_id || "")}</td>
    <td>${esc(a.reason || "")}</td><td class="dim" style="font:11.5px var(--mono);word-break:break-all">${esc(JSON.stringify(a.detail || {})).slice(0, 220)}</td></tr>`).join("")}</tbody></table></div>`;
}, { noOverview: true, perm: "audit:read" });

const BL_VIEW = [["all", "전체"], ["soon", "1시간 안 만료"], ["forever", "무기한"], ["incident", "사건에서"], ["playbook", "플레이북"], ["manual", "수동"]];
const BL_ACT = { block: "차단", unblock: "해제", extend: "기간 변경", expire: "만료" };
const BL = { q: "", view: "all", sel: new Set(), hist: null };
const blLeft = s => s == null ? "무기한" : s < 3600 ? `${Math.max(1, Math.round(s / 60))}분 남음` : s < 86400 ? `${(s / 3600).toFixed(1)}시간 남음` : `${(s / 86400).toFixed(1)}일 남음`;
panel("blocklist", "16", "차단 목록", "BLOCKLIST", ["blocklist", "blocked", "차단"], "차단 중인 IP — 검색·만료·연장·해제·일괄 해제·기록", 12, async (el, live) => {
  const qs = new URLSearchParams({ q: BL.q, view: BL.view });
  const [r, h] = await Promise.all([api(`/api/blocklist?${qs}`), api(`/api/blocklist/history?limit=60${BL.hist ? `&ip=${encodeURIComponent(BL.hist)}` : ""}`)]);
  const st = r.stats, canB = can("runs:approve"), canU = can("runs:cancel"), sim = r.mode === "simulate";
  BL.sel = new Set([...BL.sel].filter(ip => r.items.some(x => x.ip === ip)));
  const src = b => b.source === "incident" ? `<span class="link" data-cmd="incident ${b.incident_id}">사건 #${b.incident_id}</span>` : b.source === "playbook" ? `<span class="link" data-cmd="run ${b.run_id}">실행 #${b.run_id}</span>` : "수동";
  el.innerHTML = `<div class="meta-line"><span>백엔드 <b>${esc(r.backend)}</b>${r.backend === "nftables" ? " (서버 방화벽에 실제 적용)" : " (플랫폼 기록만)"}</span><span>모드 <b class="${sim ? "" : "c-high"}">${esc(r.mode)}</b></span>
      <span>차단 중 <b>${st.total}</b> · 1시간 안 만료 <b>${st.soon}</b> · 무기한 <b>${st.forever}</b></span><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span></div>
    ${sim ? `<div class="hint">simulate 모드 — 차단·해제는 실제로 하지 않고 아래 '기록'에만 남습니다 (목록에는 안 들어감).</div>` : ""}
    ${canB ? `<div class="inline-form"><input class="bip" placeholder="차단할 IP"><input class="bwhy" placeholder="사유 (필수)" style="flex:1"><select class="bdur">${IX_DUR.map(([v, l]) => `<option value="${v}" ${v === 86400 ? "selected" : ""}>${l}</option>`).join("")}</select><button class="btn danger" data-act="block">차단</button></div>` : ""}
    <div class="inline-form" style="margin-top:8px"><input class="bq" placeholder="검색: IP · 사유 · 차단한 사람" value="${esc(BL.q)}" style="flex:1">
      ${BL_VIEW.map(([k, l]) => `<button class="btn${BL.view === k ? " primary" : ""}" data-view="${k}">${l}${k !== "all" && st[k] != null ? ` ${st[k]}` : ""}</button>`).join("")}</div>
    ${canU && BL.sel.size ? `<div class="inline-form bl-bulk"><b>${BL.sel.size}개 선택</b><input class="bbwhy" placeholder="해제 사유 (필수)" style="flex:1"><button class="btn danger" data-act="bulk">선택 해제</button><button class="btn" data-act="clearsel">선택 취소</button></div>` : ""}
    <div class="tbl" style="margin-top:8px"><table><thead><tr>${canU ? `<th><input type="checkbox" class="bl-all" aria-label="모두 선택" ${r.items.length && r.items.every(b => BL.sel.has(b.ip)) ? "checked" : ""}></th>` : ""}<th>IP</th><th>사유</th><th>출처</th><th>차단</th><th>만료</th><th></th></tr></thead><tbody>
    ${r.items.map(b => `<tr>${canU ? `<td><input type="checkbox" class="bl-one" data-ip="${esc(b.ip)}" ${BL.sel.has(b.ip) ? "checked" : ""}></td>` : ""}
      <td><b>${esc(b.ip)}</b></td><td>${esc(b.reason || "")}</td><td>${src(b)}</td><td>${fmtT(b.added_at)}${b.added_by ? ` <span class="dim">· ${esc(b.added_by)}</span>` : ""}</td>
      <td>${b.expires_at ? `${fmtT(b.expires_at)} <span class="${b.remaining_sec <= 3600 ? "c-medium" : "dim"}">(${blLeft(b.remaining_sec)})</span>` : `<span class="c-high">무기한</span>`}</td>
      <td class="ix-btns">${canB ? `<select class="bl-ext" data-ip="${esc(b.ip)}" aria-label="기간 변경"><option value="">기간 변경…</option>${IX_DUR.map(([v, l]) => `<option value="${v}">지금부터 ${l}</option>`).join("")}</select>` : ""}
        ${canU ? `<button class="btn" data-unblock="${esc(b.ip)}">해제</button>` : ""}<button class="btn" data-hist="${esc(b.ip)}">기록</button></td></tr>`).join("")
      || `<tr><td colspan="7">${empty(BL.q || BL.view !== "all" ? "조건에 맞는 차단이 없습니다." : "차단된 IP가 없습니다.")}</td></tr>`}</tbody></table></div>
    <h4 style="margin:16px 0 8px;font:700 14px var(--ko)">기록${BL.hist ? ` — ${esc(BL.hist)} <span class="link" data-act="histall">[전체 보기]</span>` : " (최근 60건)"}</h4>
    <div class="tbl"><table><thead><tr><th>시각</th><th>IP</th><th>동작</th><th>누가</th><th>사유</th><th>만료</th></tr></thead><tbody>${h.items.map(x => `<tr>
      <td style="white-space:nowrap">${fmtT(x.ts)}</td><td><span class="link" data-hist="${esc(x.ip)}">${esc(x.ip)}</span></td>
      <td>${esc(BL_ACT[x.action] || x.action)}${x.simulated ? ` <span class="faint">(simulate)</span>` : ""}</td><td>${esc(x.actor || "")}${x.incident_id ? ` <span class="link" data-cmd="incident ${x.incident_id}">#${x.incident_id}</span>` : ""}</td>
      <td>${esc(x.reason || "")}</td><td>${x.action === "block" || x.action === "extend" ? (x.expires_at ? fmtT(x.expires_at) : "무기한") : ""}</td></tr>`).join("") || `<tr><td colspan="6">${empty("기록이 없습니다.")}</td></tr>`}</tbody></table></div>`;
  const redo = () => PANELS.blocklist.render(el, true), err = e => toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical");
  const bq = $(".bq", el); let tq;
  bq.oninput = () => { clearTimeout(tq); tq = setTimeout(() => { BL.q = bq.value.trim(); redo().then(() => { const n = $(".bq", el); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }); }, 300); };
  $$("[data-view]", el).forEach(b => b.onclick = () => { BL.view = b.dataset.view; redo(); });
  $$("[data-hist]", el).forEach(b => b.onclick = () => { BL.hist = b.dataset.hist; redo(); });
  const ha = $('[data-act="histall"]', el); if (ha) ha.onclick = () => { BL.hist = null; redo(); };
  $$(".bl-one", el).forEach(c => c.onchange = () => { c.checked ? BL.sel.add(c.dataset.ip) : BL.sel.delete(c.dataset.ip); redo(); });
  const all = $(".bl-all", el); if (all) all.onchange = () => { r.items.forEach(b => all.checked ? BL.sel.add(b.ip) : BL.sel.delete(b.ip)); redo(); };
  const cs = $('[data-act="clearsel"]', el); if (cs) cs.onclick = () => { BL.sel.clear(); redo(); };
  const bk = $('[data-act="bulk"]', el);
  if (bk) bk.onclick = async () => {
    const why = $(".bbwhy", el).value.trim();
    if (!why) { shake($(".bbwhy", el), 5); return; }
    if (!confirm(`${BL.sel.size}개 IP 의 차단을 해제할까요?`)) return;
    bk.disabled = true;
    try { const o = await api("/api/blocklist/unblock", { method: "POST", body: { ips: [...BL.sel], reason: why } });
      toast(`해제 ${o.ok}개${o.failed ? ` · <span class="err">실패 ${o.failed}개: ${esc(o.items.filter(x => !x.ok).map(x => `${x.ip} ${x.error}`).join(", "))}</span>` : ""}`, o.failed ? "high" : "info"); BL.sel.clear(); redo(); }
    catch (e) { err(e); bk.disabled = false; }
  };
  $$("[data-unblock]", el).forEach(b => b.onclick = async () => {
    const why = prompt(`${b.dataset.unblock} 차단 해제 사유`, "");
    if (!why || !why.trim()) return;
    try { await api(`/api/blocklist/${encodeURIComponent(b.dataset.unblock)}?reason=${encodeURIComponent(why.trim())}`, { method: "DELETE" }); toast(`${esc(b.dataset.unblock)} 차단 해제`); redo(); }
    catch (e) { err(e); } });
  $$(".bl-ext", el).forEach(sel => sel.onchange = async () => {
    if (sel.value === "") return;
    const dur = +sel.value, label = IX_DUR.find(d => d[0] === dur)[1], why = prompt(`${sel.dataset.ip} — 지금부터 ${label} 로 바꿉니다. 사유:`, "");
    if (!why || !why.trim()) { sel.value = ""; return; }
    try { const o = await api(`/api/blocklist/${encodeURIComponent(sel.dataset.ip)}/extend`, { method: "POST", body: { reason: why.trim(), duration_sec: dur || null } });
      toast(o.simulated ? `simulate — ${esc(o.would)}` : `${esc(sel.dataset.ip)} 차단 → ${o.expires_at ? fmtT(o.expires_at) + " 까지" : "무기한"}`); redo(); }
    catch (e) { err(e); sel.value = ""; } });
  const bb = $('[data-act="block"]', el);
  if (bb) bb.onclick = async () => {
    const ip = $(".bip", el).value.trim(), why = $(".bwhy", el).value.trim(), dur = +$(".bdur", el).value;
    if (!ip || !why) { shake(bb.parentElement, 5); return; }
    try { const o = await api("/api/blocklist", { method: "POST", body: { ip, reason: why, ...(dur ? { duration_sec: dur } : {}) } });
      toast(o.simulated ? `시뮬레이션 모드 — ${esc(ip)} 는 실제로 차단되지 않았습니다 (${esc(o.would)})` : `${esc(ip)} 차단됨 (${esc(o.backend)})`, o.simulated ? "info" : "high"); redo(); }
    catch (e) { err(e); }
  };
}, { noOverview: true, liveSkip: true });

panel("doctor", "17", "시스템 자가 점검", "DOCTOR", ["doctor", "health", "점검"], "수집 권한·방화벽·계정 헬퍼·인텔·모드 점검 (서비스 권한으로)", 12, async (el, live) => {
  const r = await api("/api/system/doctor");
  const ic = { ok: "✔", warn: "!", fail: "✘" }, cl = { ok: "acc", warn: "c-medium", fail: "c-critical" };
  el.innerHTML = `<div class="meta-line"><span>결과 <b class="${r.ok ? "acc" : "c-critical"}">${r.ok ? "치명적 문제 없음" : "실패 항목 있음"}</b></span><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span>
    ${can("config:write") ? `<span class="link" data-act="feeds">[위협 인텔 피드 지금 갱신]</span>` : ""}</div>
    <div class="tbl"><table><thead><tr><th></th><th>항목</th><th>내용</th></tr></thead><tbody>${r.checks.map(c => `<tr><td class="${cl[c.status]}"><b>${ic[c.status]}</b></td><td><b>${esc(c.check)}</b></td><td>${esc(c.detail)}</td></tr>`).join("")}</tbody></table></div>`;
  const f = $('[data-act="feeds"]', el);
  if (f) f.onclick = async () => { f.textContent = "[갱신 중…]"; try { const x = await api("/api/system/feeds/refresh", { method: "POST" }); toast(`피드: ${esc(JSON.stringify(x.counts))}`); PANELS.doctor.render(el, true); } catch (e) { toast(esc(errMsg(e)), "critical"); } };
  if (A && !live) anime({ targets: $$("tbody tr", el), opacity: [0, 1], translateX: [-12, 0], delay: anime.stagger(40), duration: 300, easing: "easeOutCubic" });
}, { noOverview: true, perm: "config:read" });

panel("automation", "18", "자동화 편집기", "SOAR PLAYBOOK BUILDER", ["automation", "auto", "flow", "자동화"], "플레이북을 끌어다 놓아 만들기 — 트리거·단계·조건·승인·보상 (web/automation.js)", 12,
  (el, live, arg) => renderAutomation(el, live, arg), { liveSkip: true, noOverview: true, perm: "playbooks:read" });

const MAIL_KIND = { alert: "경보 알림", approval: "승인 요청", "report:incident": "사건 보고서", "report:manual": "요약 보고서", "report:daily": "일간 보고서",
  "report:weekly": "주간 보고서", playbook: "플레이북", test: "테스트", manual: "수동" };
panel("mail", "19", "메일 · 보고서", "MAIL & REPORTS", ["mail", "reports", "메일", "보고서"], "메일 설정 상태 · 테스트 발송 · 요약 보고서 PDF 받기/보내기 · 발송 기록", 12, async (el, live) => {
  const r = await api("/api/mail?size=50"), st = r.status, al = st.alerts || {}, rep = st.reports || {};
  const ok = st.configured, list = v => (v || []).length ? (v || []).map(esc).join(", ") : `<span class="faint">없음</span>`;
  el.innerHTML = `<div class="meta-line"><span>메일 <b class="${ok ? "acc" : "c-high"}">${ok ? "켜짐" : "꺼짐"}</b>${ok ? ` · ${esc(st.host)}:${esc(st.port)} (${esc(st.security)})` : ` — <span class="link" data-cmd="dashboard settings mail">settings</span> 에서 켜기`}</span>
      <span>PDF 한글 폰트 <b class="${r.pdf_font.ok ? "acc" : "c-high"}">${r.pdf_font.ok ? "정상" : "없음"}</b></span><span>갱신 <b>${fmtT(Date.now() / 1000)}</b></span></div>
    ${!r.pdf_font.ok ? `<div class="msg c-high">${esc(r.pdf_font.detail)}</div>` : ""}
    <div class="detail-grid"><div>
      <dl class="kv"><dt>보낸 사람</dt><dd>${esc(st.from || "-")}</dd><dt>로그인</dt><dd>${st.username ? `${esc(st.username)} · 비밀번호 ${st.password_set ? "설정됨" : "<b class='c-high'>없음 — settings 에서 입력</b>"}` : "없음 (릴레이)"}</dd>
        <dt>허용 수신자</dt><dd>${list(st.allowed_recipients)}</dd><dt>시간당 한도</dt><dd>${esc(st.max_per_hour)}통 · 대기열 ${st.queue}</dd>
        <dt>경보 알림</dt><dd>${al.enabled !== false && (al.to || []).length ? `${esc(al.min_severity || "high")} 이상 · ${esc(al.batch_sec || 60)}초 묶음${al.approvals !== false ? " · 승인 요청 포함" : ""} → ${list(al.to)}` : "<span class='faint'>꺼짐</span>"}</dd>
        <dt>사건 종결 시</dt><dd>${rep.incident_on_close?.enabled ? `사건 보고서 → ${list(rep.incident_on_close.to)}` : "<span class='faint'>꺼짐</span>"}</dd>
        <dt>정기 보고서</dt><dd>${(rep.schedule || []).map(s => `${esc(s.name)}: ${s.enabled && (s.to || []).length ? `${s.every === "day" ? "매일" : esc(s.every)} ${esc(s.at)} · 최근 ${esc(s.period_hours)}시간 → ${list(s.to)}` : "<span class='faint'>꺼짐</span>"}`).join("<br>") || "-"}</dd>
        ${st.last_error ? `<dt>마지막 오류</dt><dd class="c-critical">${esc(st.last_error)}</dd>` : ""}</dl>
      <div class="hint" style="margin-top:8px">설정 변경: <span class="link" data-cmd="dashboard settings mail">dashboard settings</span> (저장하면 바로 적용)</div>
    </div><div>
      <h4 style="margin:0 0 8px;font:700 14px var(--ko)">요약 보고서 (현재 range: ${esc(S.range.label)})</h4>
      <div class="inline-form"><button class="btn" data-m="dl">⇩ PDF 받기</button>
        ${can("incidents:write") ? `<input class="mto" placeholder="받는 사람 (비우면 경보 알림 수신자)"><button class="btn primary" data-m="send" ${ok ? "" : "disabled"}>✉ 메일로 보내기</button>` : ""}</div>
      ${can("config:write") ? `<h4 style="margin:16px 0 8px;font:700 14px var(--ko)">테스트 메일</h4><div class="inline-form"><input class="tto" placeholder="받는 사람 (허용 목록 안)"><button class="btn" data-m="test" ${ok ? "" : "disabled"}>보내기</button></div>` : ""}
    </div></div>
    <h4 style="margin:18px 0 8px;font:700 14px var(--ko)">발송 기록</h4>
    <div class="tbl"><table><thead><tr><th>#</th><th>시각</th><th>종류</th><th>받는 사람</th><th>제목</th><th>상태</th><th>요청</th></tr></thead><tbody>${r.log.map(m => `<tr>
      <td class="num">${m.id}</td><td style="white-space:nowrap">${fmtT(m.ts)}</td><td>${esc(MAIL_KIND[m.kind] || m.kind)}</td><td>${esc(m.recipients)}</td><td>${esc(m.subject)}</td>
      <td>${state(m.status === "sent" ? "succeeded" : m.status === "failed" ? "failed" : m.status === "queued" ? "queued" : "skipped").replace(/>[^<]+</, `>${esc({ sent: "보냄", failed: "실패", queued: "대기", simulated: "시뮬레이션" }[m.status] || m.status)}<`)}
        ${m.error ? `<br><span class="err" style="font-size:12px">${esc(m.error)}</span>` : ""}</td><td>${esc(m.actor || "")}</td></tr>`).join("") || `<tr><td colspan="7">${empty("보낸 메일이 없습니다.")}</td></tr>`}</tbody></table></div>`;
  const redo = () => PANELS.mail.render(el, true), err = e => toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical");
  const res = (x, what) => toast(x.status === "sent" ? `${what} → ${esc(x.recipients)}` : `<span class="err">${what} 실패: ${esc(x.error || x.status)}</span>`, x.status === "sent" ? "info" : "critical");
  $$("[data-m]", el).forEach(b => b.onclick = async () => {
    b.disabled = true;
    try {
      if (b.dataset.m === "dl") toast(`${esc(await download(`/api/reports/summary.pdf?${rangeQuery()}`, "rkmsiem-summary.pdf"))} 저장`);
      if (b.dataset.m === "send") { const to = $(".mto", el).value.trim(); res(await api("/api/reports/summary/email", { method: "POST", body: { ...(to ? { to } : {}), ...(S.range.from != null ? { from: S.range.from, to_ts: S.range.to } : {}) } }), "요약 보고서"); await redo(); }
      if (b.dataset.m === "test") { const to = $(".tto", el).value.trim(); if (!to) { shake($(".tto", el), 5); return; } res(await api("/api/mail/test", { method: "POST", body: { to } }), "테스트 메일"); await redo(); }
    } catch (e) { err(e); } finally { b.disabled = false; }
  });
  if (A && !live) anime({ targets: $$("dl.kv dt, dl.kv dd, tbody tr", el), opacity: [0, 1], translateX: [-10, 0], delay: anime.stagger(20), duration: 300, easing: "easeOutCubic" });
}, { noOverview: true, perm: "config:read" });

panel("settings", "20", "설정", "SETTINGS", ["settings", "config", "설정"], "메일 서버 · 받는 사람(끌어다 놓기) · 보고서 일정 · 목록 · AbuseIPDB — 저장하면 바로 적용 (web/settings.js)", 12,
  (el, live, arg) => renderSettings(el, live, arg), { liveSkip: true, noOverview: true, perm: "config:read" });

panel("team", "21", "담당자", "TEAM", ["team", "users", "담당자"], "담당자 명단(담당자 관리 앱에서 가져옴) · 업무량(맡은 사건) · 연동 상태 · 로그인 계정 (web/team.js)", 12,
  (el, live) => renderTeam(el, live), { liveSkip: true, noOverview: true });
panel("topology", "22", "네트워크 토폴로지", "TOPOLOGY", ["topology", "topo", "network", "토폴로지", "네트워크"], "감지한 기기를 끌어다 놓고 와이어로 연결 · 경보·차단 상태 겹쳐 보기 (web/topology.js)", 12,
  (el, live) => renderTopology(el, live), { liveSkip: true, noOverview: true });
// ---------------------------------------------------------------- 원격 조치 에이전트 (대상 서버의 rkmsiem-agent · rkmsiem/agents.py)
const AG_ACT = { container_stop: "중지", container_restart: "재시작", process_kill: "종료", service_restart: "재시작" };
const AG = { timer: null };
const agAgo = t => t ? `${Math.max(0, Math.round(Date.now() / 1000 - t))}초 전` : "-";
const agBytes = kb => kb == null ? "-" : kb > 1048576 ? `${(kb / 1048576).toFixed(1)}GB` : `${Math.round(kb / 1024)}MB`;
panel("agents", "24", "원격 조치", "AGENTS", ["agents", "agent", "원격", "에이전트"], "대상 서버의 에이전트 — 컨테이너 중지·재시작 · 프로세스 종료 · 서비스 재시작 (dashboard agents <이름>)", 12, async (el, live, arg) => {
  clearTimeout(AG.timer);
  const want = String(arg || "").trim();
  if (want) return agentDetail(el, want, live);
  const r = await api("/api/agents");
  const card = a => `<div class="cx-card" style="border:1px solid var(--line, #333);border-radius:6px;padding:10px 12px;min-width:240px;flex:1 1 240px">
      <div><b>${esc(a.name)}</b> ${a.online ? `<span class="acc">● 연결됨</span>` : `<span class="c-high">● 끊김</span>`} <span class="faint">${esc(a.hostname || "")}</span></div>
      <div class="dim" style="font-size:12px;margin:4px 0">${a.summary.ips.map(esc).join(" · ") || "-"} · 마지막 ${agAgo(a.last_seen)}${a.summary.load ? ` · 부하 ${a.summary.load.map(x => x.toFixed(2)).join(" ")}` : ""}</div>
      <div class="dim" style="font-size:12px">${a.summary.docker ? `컨테이너 ${a.summary.containers}` : "docker 없음"} · 실패한 서비스 ${a.summary.failed_services ? `<span class="c-high">${a.summary.failed_services}</span>` : 0}
        · 허용: ${a.allow.length ? a.allow.map(x => esc(r.actions[x] || x)).join(", ") : "<span class='c-medium'>없음(보고만)</span>"}</div>
      <div style="margin-top:6px"><span class="link" data-cmd="dashboard agents ${esc(a.name)}">▣ 열기</span></div></div>`;
  el.innerHTML = `<div class="meta-line"><span>모드 <b class="${r.mode === "live" ? "c-high" : ""}">${esc(r.mode)}</b>${r.mode === "simulate" ? " (조치는 기록만 · 에이전트에 보내지 않음)" : " — 조치가 실제로 실행됨"}</span><span>에이전트 <b>${r.items.length}</b></span></div>
    <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px">${r.items.map(card).join("") || `<div class="empty-state" style="flex:1">등록한 에이전트가 없습니다.</div>`}</div>
    ${can("config:write") ? `<h4 style="margin:16px 0 8px;font:700 14px var(--ko)">에이전트 추가</h4>
      <div class="inline-form"><input class="ag-name" placeholder="이름 (예: ids-server)" maxlength="32"><input class="ag-siem" value="${esc(r.install.origin)}" title="에이전트가 접속할 SIEM 주소" style="flex:1"><button class="btn primary" data-act="enroll">등록 코드 만들기</button></div>
      <div class="ag-cmd"></div>
      <p class="hint">에이전트는 대상 서버에서 SIEM 으로 <b>나가서</b> 할 일을 받아 갑니다 (대상 서버에 들어오는 포트 없음). 무엇을 허용할지는 대상 서버의 <code>/etc/rkmsiem-agent/agent.env</code> (ALLOW · PROTECT_*) 가 정합니다.
        SIEM 방화벽에서 대상 서버 IP 를 8443 에 허용해야 합니다.</p>` : ""}`;
  const eb = $('[data-act="enroll"]', el);
  if (eb) eb.onclick = async () => {
    const name = $(".ag-name", el).value.trim(), siem = $(".ag-siem", el).value.trim().replace(/\/+$/, "");
    if (!name) { shake($(".ag-name", el), 5); return; }
    eb.disabled = true;
    try {
      const e = await api("/api/agents", { method: "POST", body: { name } });
      const fp = r.install.fingerprint, https = siem.startsWith("https://");
      const cmd = `curl -fsS${https ? "k" : ""} ${siem}/agent/rkmsiem-agent.tgz -o /tmp/rkmsiem-agent.tgz && echo "${r.install.sha256}  /tmp/rkmsiem-agent.tgz" | sha256sum -c - && tar xzf /tmp/rkmsiem-agent.tgz -C /tmp && sudo /tmp/rkmsiem-agent/install-agent.sh --siem ${siem}${fp ? ` --fingerprint ${fp}` : ""} --code ${e.code}`;
      $(".ag-cmd", el).innerHTML = `<div class="msg acc" style="margin-top:8px">'${esc(e.name)}' 등록 코드 — ${fmtT(e.expires_at)} 까지 · 1회용. 대상 서버에서 실행:</div>
        <pre class="pl-pre" style="white-space:pre-wrap;user-select:all">${esc(cmd)}</pre>
        ${https && !fp ? `<div class="msg c-high">SIEM 인증서 지문을 아직 모릅니다 — SIEM 서버에서 <code>sudo rkmsiem-update</code> 후 다시 만들거나, <code>sudo /usr/share/rkmsiem/deploy/tls.sh --show</code> 의 지문을 --fingerprint 로 넣으세요.</div>` : ""}
        <div class="hint">꾸러미는 SIEM 에서 받고, 위 해시(sha256)가 맞을 때만 설치합니다. 설치되면 몇 초 안에 위 목록에 '연결됨'으로 나타납니다.</div>`;
      clearTimeout(AG.timer);                                         // 설치되면 목록을 저절로 새로 고침
      AG.timer = setTimeout(function poll() { if (!el.isConnected) return; api("/api/agents").then(x => { if (x.items.some(a => a.name === e.name)) toast(`에이전트 '${esc(e.name)}' 연결됨`); else AG.timer = setTimeout(poll, 4000); }).catch(() => {}); }, 4000);
    } catch (x) { toast(`<span class="err">${esc(errMsg(x))}</span>`, "critical"); }
    finally { eb.disabled = false; }
  };
}, { liveSkip: true, noOverview: true, perm: "runs:read" });

async function agentDetail(el, name, live) {
  const a = await api(`/api/agents/${encodeURIComponent(name)}`), i = a.info || {}, ok = x => a.allow.includes(x) && can("runs:approve");
  const keep = $(".ag-why", el)?.value || "";
  const btn = (act, attrs, prot) => ok(act) && !prot ? `<button class="btn danger" data-ag="${act}" ${attrs}>${AG_ACT[act]}</button>` : "";
  el.innerHTML = `<div class="meta-line"><span><b>${esc(a.name)}</b> ${a.online ? `<span class="acc">● 연결됨</span>` : `<span class="c-high">● 끊김 (${agAgo(a.last_seen)})</span>`}</span>
      <span>${esc(a.hostname || "")} · ${esc(i.os || "")}</span><span>${(i.ips || []).map(esc).join(" · ")}</span>
      <span>CPU ${i.cpus || "-"}개 · 부하 ${(i.load || []).map(x => x.toFixed(2)).join(" ")} · 메모리 ${agBytes(i.mem?.available)} / ${agBytes(i.mem?.total)} 남음</span>
      <span>허용: ${a.allow.map(x => esc(x)).join(", ") || "없음"}</span><span class="link" data-cmd="dashboard agents">← 목록</span></div>
    ${can("runs:approve") ? `<div class="inline-form"><input class="ag-why" placeholder="사유 (모든 원격 조치에 필수 — 감사 로그에 남음)" style="flex:1" value="${esc(keep)}"></div>` : ""}
    <h4 style="margin:12px 0 6px;font:700 14px var(--ko)">컨테이너</h4>
    ${i.docker ? `<div class="tbl"><table><thead><tr><th>이름</th><th>이미지</th><th>상태</th><th>CPU</th><th>메모리</th><th></th></tr></thead><tbody>${(i.containers || []).map(c => `<tr>
      <td><b>${esc(c.name)}</b>${c.protected ? ` <span class="faint">보호</span>` : ""}</td><td class="dim">${esc(c.image || "")}</td><td>${c.state === "running" ? `<span class="acc">${esc(c.status)}</span>` : esc(c.status || c.state)}</td>
      <td class="num ${c.cpu > 80 ? "c-critical" : ""}">${c.cpu == null ? "-" : c.cpu.toFixed(1) + "%"}</td><td class="dim">${esc(c.mem || "-")}</td>
      <td class="ix-btns">${c.state === "running" ? btn("container_stop", `data-container="${esc(c.name)}"`, c.protected) : ""}${btn("container_restart", `data-container="${esc(c.name)}"`, c.protected)}</td></tr>`).join("") || `<tr><td colspan="6">${empty("컨테이너 없음")}</td></tr>`}</tbody></table></div>`
      : `<div class="dim">이 서버에 docker 가 없습니다.</div>`}
    <h4 style="margin:12px 0 6px;font:700 14px var(--ko)">프로세스 <span class="faint" style="font-weight:400">(CPU 상위 · 약 25초마다 갱신)</span></h4>
    <div class="tbl"><table><thead><tr><th>PID</th><th>사용자</th><th>CPU</th><th>메모리</th><th>명령</th><th></th></tr></thead><tbody>${(i.processes || []).map(x => `<tr>
      <td class="num">${x.pid}</td><td>${esc(x.user)}</td><td class="num ${x.cpu > 80 ? "c-critical" : ""}">${x.cpu.toFixed(1)}%</td><td class="num">${x.mem.toFixed(1)}%</td>
      <td style="max-width:520px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.cmd)}"><b>${esc(x.comm)}</b> <span class="dim">${esc(x.cmd)}</span>${x.protected ? ` <span class="faint">보호</span>` : ""}</td>
      <td class="ix-btns">${btn("process_kill", `data-pid="${x.pid}" data-start="${x.start}" data-expect="${esc(x.comm)}"`, x.protected)}</td></tr>`).join("") || `<tr><td colspan="6">${empty("보고 없음")}</td></tr>`}</tbody></table></div>
    <h4 style="margin:12px 0 6px;font:700 14px var(--ko)">서비스</h4>
    <div class="dim" style="margin-bottom:6px">실패한 서비스: ${(i.failed_services || []).map(sv => `<code>${esc(sv)}</code> ${btn("service_restart", `data-service="${esc(sv)}"`)}`).join(" ") || "없음"}</div>
    ${ok("service_restart") ? `<div class="inline-form"><input class="ag-svc" placeholder="서비스 이름 (예: nginx)"><button class="btn danger" data-ag="service_restart" data-service-input="1">재시작</button>
      <span class="faint">보호: ${(i.protect?.services || []).map(esc).join(", ")}</span></div>` : ""}
    <h4 style="margin:12px 0 6px;font:700 14px var(--ko)">작업 기록</h4>
    <div class="tbl"><table><thead><tr><th>#</th><th>시각</th><th>조치</th><th>대상</th><th>상태</th><th>누가 · 사유</th><th>결과</th></tr></thead><tbody>${a.jobs.map(j => `<tr>
      <td class="num">${j.id}</td><td style="white-space:nowrap">${fmtT(j.created_at)}</td><td>${esc(j.action)}</td><td>${esc(j.params.container || j.params.service || (j.params.pid ? `PID ${j.params.pid} ${j.params.expect || ""}` : ""))}</td>
      <td>${state(j.state === "sent" ? "running" : j.state === "expired" ? "failed" : j.state)}</td><td>${esc(j.requested_by || "")}${j.incident_id ? ` <span class="link" data-cmd="incident ${j.incident_id}">#${j.incident_id}</span>` : ""} <span class="dim">${esc(j.reason || "")}</span></td>
      <td class="${j.error ? "err" : "dim"}" style="font-size:12px">${esc(j.error || (j.result ? JSON.stringify(j.result).slice(0, 120) : ""))}</td></tr>`).join("") || `<tr><td colspan="7">${empty("작업 없음")}</td></tr>`}</tbody></table></div>
    ${can("config:write") ? `<div class="inline-form" style="margin-top:12px"><button class="btn danger" data-act="revoke">에이전트 해제</button><span class="faint">토큰을 무효로 — 대상 서버에서는 sudo /tmp/rkmsiem-agent/install-agent.sh --uninstall</span></div>` : ""}`;
  const why = () => ($(".ag-why", el)?.value || "").trim();
  $$("[data-ag]", el).forEach(b => b.onclick = async () => {
    const act = b.dataset.ag, d = b.dataset;
    const body = { action: act, reason: why() };
    if (d.container) body.container = d.container;
    if (d.pid) Object.assign(body, { pid: +d.pid, start: +d.start, expect: d.expect });
    if (d.service) body.service = d.service;
    if (d.serviceInput) body.service = $(".ag-svc", el).value.trim();
    if (!body.reason) { const w = $(".ag-why", el); w.focus(); shake(w, 5); toast("사유를 적어 주세요", "high"); return; }
    if (act === "service_restart" && !body.service) { shake($(".ag-svc", el), 5); return; }
    const what = body.container || body.service || `PID ${body.pid} (${body.expect})`;
    if (!confirm(`${a.name}: ${what} ${AG_ACT[act]}\n계속할까요?`)) return;
    b.disabled = true; b.textContent = "실행 중…";
    try { const o = await api(`/api/agents/${encodeURIComponent(name)}/actions`, { method: "POST", body });
      toast(o.output?.simulated ? `simulate — ${esc(o.output.would)} (기록만)` : `${esc(what)} ${AG_ACT[act]} 완료`); }
    catch (x) { toast(`<span class="err">${esc(errMsg(x))}</span>`, "critical"); }
    agentDetail(el, name, true);
  });
  const rv = $('[data-act="revoke"]', el);
  if (rv) rv.onclick = async () => { if (!confirm(`'${name}' 에이전트를 해제할까요? 토큰이 무효가 되어 더는 연결되지 않습니다.`)) return;
    try { await api(`/api/agents/${encodeURIComponent(name)}`, { method: "DELETE" }); toast(`${esc(name)} 해제`); run("dashboard agents"); } catch (x) { toast(`<span class="err">${esc(errMsg(x))}</span>`, "critical"); } };
  clearTimeout(AG.timer);
  AG.timer = setTimeout(() => { if (el.isConnected && document.activeElement?.tagName !== "INPUT" && !$("button[disabled]", el)) agentDetail(el, name, true).catch(() => {}); }, 15000);
}

// ---------------------------------------------------------------- 연동 (connect) — 당겨오기 소스와 그 화면(view)
// 화면은 콘솔과 다른 출처(https://<서버>:8445)에서 열림 — 연동 제품 페이지가 콘솔 로그인 토큰에 닿지 못하게 (rkmsiem/connect.py)
let cxExp = 0;
async function cxSession(force) {                                   // /connect/ 전용 쿠키 — 만료 10분 전이면 새로
  if (!force && Date.now() / 1000 < cxExp - 600) return;
  const r = await api("/api/connect/session", { method: "POST" });
  cxExp = Date.now() / 1000 + r.expires_in;
}
async function loadCx() {
  S.cx = null;
  if (!can("metrics:read")) return;
  try { S.cx = await api("/api/connect"); } catch (e) { /* 권한·구버전 */ }
}
const cxUrl = (id, path) => `${S.cx.origin}/connect/${encodeURIComponent(id)}/${String(path || "/").replace(/^\//, "")}`;
function cxRange(path) {
  const R = S.range, f = R.from == null ? "now-24h" : Math.round(R.from * 1000), t = R.from == null ? "now" : Math.round(R.to * 1000);
  return String(path).replaceAll("{from}", f).replaceAll("{to}", t);
}
const cxFrame = (src, title, h) => `<iframe class="cx-frame" src="${esc(src)}" title="${esc(title)}" loading="lazy" referrerpolicy="same-origin"
  style="width:100%;height:${h};border:1px solid var(--line, #333);border-radius:6px;background:#111217"></iframe>`;
panel("connect", "23", "연동", "CONNECT", ["connect", "연동", "cx"], "연동한 외부 서비스(당겨오기)와 그 대시보드 — connect <연동> [대시보드] 로 화면 열기", 12, async (el, live, arg) => {
  S.cx = await api("/api/connect");
  const items = S.cx.items, [want, dash] = String(arg || "").trim().split(/\s+/);
  if (!items.length) {
    el.innerHTML = `<div class="empty-state">연동한 서비스가 없습니다.</div>
      <div class="hint">${can("config:write") ? `<span class="link" data-cmd="dashboard settings pull">settings → 당겨오기</span> 에서 추가하세요 (프리셋: Prometheus · Grafana · Kubernetes · JSON API). 화면(대시보드)이 있는 제품은 '화면' 칸을 채우면 여기서 열립니다.`
        : "관리자가 settings → 당겨오기 에서 추가하면 여기에 나타납니다."}</div>`;
    return;
  }
  const pick = items.find(x => x.id === want) || (!want ? items.find(x => x.view) : null);
  if (want && !pick) { el.innerHTML = `<div class="msg c-high">연동 '${esc(want)}' 이 없습니다.</div>`; }
  const st = x => { const s = x.status || {};
    if (x.enabled === false) return `<span class="faint">수집 꺼짐</span>`;
    if (s.last_error) return `<span class="c-critical" title="${esc(s.last_error)}">오류</span>`;
    return s.alive || s.state === "running" ? `<span class="acc">● 연결됨</span>` : `<span class="c-medium">${esc(s.state || "대기")}</span>`; };
  const card = x => `<div class="cx-card${x === pick ? " on" : ""}" style="border:1px solid var(--line, #333);border-radius:6px;padding:10px 12px;min-width:220px;flex:1 1 220px;${x === pick ? "border-color:var(--acc, #3f6)" : ""}">
      <div><b>${esc(x.title)}</b> <span class="faint">${esc(x.kind || x.type)}</span> ${st(x)}</div>
      <div class="dim" style="font-size:12px;margin:4px 0">${x.type === "http_pull" ? `받은 이벤트 ${x.status?.received ?? 0}건${x.status?.last_poll_at ? ` · 마지막 조회 ${fmtT(x.status.last_poll_at)}` : ""}` : esc(x.dataset || "")}</div>
      <div>${x.view ? `<span class="link" data-cmd="connect ${esc(x.id)}">▣ 화면</span>${x.view.dashboards.map(d => ` · <span class="link" data-cmd="connect ${esc(x.id)} ${esc(d.name)}">${esc(d.title || d.name)}</span>`).join("")}`
        : `<span class="faint">화면 없음 (데이터만)</span>`} · <span class="link" data-cmd="search source=${esc(x.id)}">이벤트</span>
        ${can("config:write") ? ` · <span class="link" data-cmd="dashboard settings pull">설정</span>` : ""}</div></div>`;
  el.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px">${items.map(card).join("")}</div><div class="cx-view"></div>`;
  if (!pick?.view) { if (pick) $(".cx-view", el).innerHTML = `<div class="hint">'${esc(pick.title)}' 은 데이터만 연동되어 있습니다 — 화면을 보려면 당겨오기 설정의 '화면' 칸을 채우세요.</div>`; return; }
  const d = pick.view.dashboards.find(x => x.name === dash), path = d ? d.path : pick.view.home;
  await cxSession(true);
  const src = cxUrl(pick.id, cxRange(path));
  $(".cx-view", el).innerHTML = `<div class="meta-line"><span><b>${esc(pick.title)}</b> ${esc(d?.title || d?.name || "")}</span>
      <span><a class="link" href="${esc(src)}" target="_blank" rel="noopener">↗ 새 창으로</a></span>
      ${pick.view.sso ? `<span class="dim">RKMSIEM 로그인으로 들어감</span>` : `<span class="dim">제품 자체 로그인</span>`}</div>
    ${cxFrame(src, pick.title, "calc(100vh - 340px);min-height:420px")}`;
}, { liveSkip: true, noOverview: true, perm: "metrics:read" });

// 대시보드 칸에 연동 화면 끼우기 (settings → 당겨오기 → 대시보드 칸) — 설정 embeds
const cxOver = (key, mode) => (S.cx?.slots || []).map((o, i) => ({ ...o, i })).filter(o => o.slot === key && (o.mode || "replace") === mode && S.cx.items.some(x => x.id === o.source && x.view));
const cxShell = (o, key) => ({ no: o.mode === "after" ? "↗" : PANELS[key].no, title: o.title || o.source, en: "CONNECT", span: o.span || PANELS[key].span });
panel("embed", "↗", "연동 화면", "CONNECT", ["embed"], "대시보드 칸에 끼운 연동 화면", 6, async (el, live, arg) => {
  const o = S.cx?.slots?.[arg ?? el.closest(".panel")?.dataset.cx];
  if (!o) { el.innerHTML = `<div class="dim">칸 설정이 바뀌었습니다 — 다시 여세요.</div>`; return; }
  const src = cxUrl(o.source, cxRange(o.path)), fr = $("iframe", el);
  if (fr && fr.getAttribute("src") === src) { if (Date.now() / 1000 > cxExp - 600) await cxSession(); return; }   // 그대로 (제품이 스스로 새로 고침)
  await cxSession();
  const solo = !!el.closest(".panel.solo");
  el.innerHTML = cxFrame(src, o.title || o.source, solo ? `max(${o.height || 300}px, calc(100vh - 300px))` : `${o.height || 300}px`).replace("border:1px solid var(--line, #333)", "border:0") +
    `<div class="faint" style="font-size:11px;margin-top:4px">연동 <span class="link" data-cmd="connect ${esc(o.source)}">${esc(o.source)}</span>${o.mode !== "after" ? ` · <span class="link" data-cmd="dashboard ${esc(PANELS[o.slot].aliases[0])} raw">원래 패널</span>` : ""}</div>`;
}, { noOverview: true, perm: "metrics:read" });

// ---------------------------------------------------------------- 승인 폼
function approvalForm(runId, stepId) {
  if (!can("runs:approve")) return `<div class="dim" style="font-size:12px;margin-top:4px">승인 권한이 없습니다 (대응 담당자/관리자).</div>`;
  return `<div class="inline-form approval-box" data-run="${runId}" data-step="${esc(stepId)}"><input class="reason" placeholder="승인/거절 사유 (필수)">
    <button class="btn primary" data-ok="1">승인</button><button class="btn danger" data-ok="0">거절</button></div>`;
}
// 플레이북의 사람 할 일 (manual_task) — 확인 목록을 모두 체크해야 '완료', 건너뜀·문제는 메모 필수
function taskForm(runId, t) {
  const canDo = can("incidents:write");
  return `<div class="task-box" data-run="${runId}" data-step="${esc(t.step_id)}" style="border:1px dashed var(--line, #444);border-radius:6px;padding:8px 10px;margin-top:6px">
    <b>${esc(t.title)}</b>${t.instructions ? `<div class="dim" style="white-space:pre-wrap;margin:4px 0">${esc(t.instructions)}</div>` : ""}
    ${t.checklist.map((c, i) => `<label style="display:block;margin:3px 0"><input type="checkbox" class="tk-chk" value="${i}" ${canDo ? "" : "disabled"}> ${esc(c)}</label>`).join("")}
    ${canDo ? `<div class="inline-form" style="margin-top:6px"><input class="tk-note" placeholder="메모 (건너뜀·문제는 필수)" style="flex:1">
      <button class="btn primary" data-tk="done" ${t.checklist.length ? "disabled" : ""}>완료</button><button class="btn" data-tk="skipped">건너뜀</button><button class="btn danger" data-tk="failed">문제 있음</button></div>`
      : `<div class="dim">처리 권한이 없습니다 (incidents:write).</div>`}</div>`;
}
function taskDone(t) {
  const o = { done: "완료", skipped: "건너뜀", failed: "문제 있음" }[t.state] || t.state;
  return `<div class="out">${esc(t.title)} — <b>${esc(o)}</b> · ${esc(t.done_by || "")} ${t.done_at ? fmtT(t.done_at) : ""}${t.checklist.length ? ` · 확인 ${t.checked.length}/${t.checklist.length}` : ""}${t.note ? `<br>${esc(t.note)}` : ""}</div>`;
}
function bindTaskForms(root) {
  $$(".task-box", root).forEach(f => {
    const chks = $$(".tk-chk", f), done = $('[data-tk="done"]', f);
    chks.forEach(c => c.onchange = () => { if (done) done.disabled = !chks.every(x => x.checked); });
    $$("[data-tk]", f).forEach(b => b.onclick = async () => {
      const outcome = b.dataset.tk, note = $(".tk-note", f).value.trim();
      if (outcome !== "done" && !note) { $(".tk-note", f).focus(); shake($(".tk-note", f), 5); toast("메모(사유)를 적어 주세요", "high"); return; }
      b.disabled = true;
      try { await api(`/api/runs/${f.dataset.run}/steps/${encodeURIComponent(f.dataset.step)}/task`, { method: "POST", body: { outcome, note: note || undefined, checked: chks.filter(c => c.checked).map(c => +c.value) } });
        toast(`할 일 '${esc($("b", f).textContent)}' ${{ done: "완료", skipped: "건너뜀", failed: "문제 표시" }[outcome]}`); await loadOverview(); await rerender(true); }
      catch (e) { b.disabled = false; toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
    });
  });
}
function bindApprovalForms(root) {
  bindTaskForms(root);
  $$(".approval-box", root).forEach(f => $$("button", f).forEach(b => b.onclick = async () => {
    const reason = $(".reason", f).value.trim();
    if (!reason) { $(".reason", f).focus(); shake($(".reason", f), 5); return; }
    b.disabled = true;
    try { await api(`/api/runs/${f.dataset.run}/steps/${f.dataset.step}/decision`, { method: "POST", body: { approve: b.dataset.ok === "1", reason } });
      toast(`실행 #${f.dataset.run} · ${esc(f.dataset.step)} ${b.dataset.ok === "1" ? "승인" : "거절"}됨`, "info"); await loadOverview(); await rerender(true); }
    catch (e) { b.disabled = false; toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
  }));
}

// ---------------------------------------------------------------- 사건 상세
async function showIncident(id, live) {
  const d = await api(`/api/incidents/${id}`);
  const sec = live && $(".panel.solo[data-incident]") || panelShell({ no: "#" + d.id, title: `사건 상세`, en: "INCIDENT" }, !live);
  sec.dataset.incident = id;
  const body = $(".panel-body", sec);
  body.innerHTML = `<div class="meta-line"><span>생성 <b>${fmtT(d.created_at)}</b></span><span>갱신 <b>${fmtT(d.updated_at)}</b></span><span>상관 키 <b>${esc(d.correlation_key)}</b></span>${d.sample ? '<span class="sample-badge">SAMPLE</span>' : ""}</div>
    <h3 style="margin:0 0 10px;font:800 18px var(--ko)">${sev(d.severity)} ${esc(d.title)}</h3>
    <div class="detail-grid"><div>
      <dl class="kv"><dt>상태</dt><dd>${state(d.state)}</dd><dt>담당자</dt><dd>${d.assignee ? `${esc(d.assignee)}${d.assignee === S.me?.username ? ' <span class="acc">(나)</span>' : ""}` : '<span class="c-high">미지정</span>'}</dd><dt>위험 점수</dt><dd>${(d.risk_score || 0).toFixed(0)}</dd><dt>경보</dt><dd>${d.alerts.length}건</dd></dl>
      ${can("incidents:write") && d.allowed_transitions.length ? `<div class="inline-form"><select class="to">${d.allowed_transitions.map(t => `<option value="${esc(t)}">${esc(STATE_KO[t] || t)}</option>`).join("")}</select>
        <input class="reason" placeholder="사유 (재오픈 등은 필수)"><button class="btn primary" data-act="transition">상태 변경</button></div>` : ""}
      ${can("incidents:assign") ? `<div class="inline-form"><select class="assignee" aria-label="담당자"><option>불러오는 중…</option></select><button class="btn" data-act="assign">배정</button>
        ${d.assignee !== S.me?.username ? `<button class="btn" data-act="assignme">나에게</button>` : ""}</div>` : ""}
      ${can("incidents:write") ? `<div class="inline-form"><input class="comment" placeholder="메모"><button class="btn" data-act="comment">기록</button></div>` : ""}
      <div class="inline-form"><button class="btn" data-act="pdf">⇩ 사건 보고서 PDF</button>${can("incidents:write") ? `<input class="mailto" placeholder="받는 사람 (비우면 기본 수신자)"><button class="btn" data-act="mailpdf">✉ 보고서 메일로</button>` : ""}</div>
      <div class="ix-act"></div>
      <h4 style="margin:16px 0 8px;font:700 14px var(--ko)">탐지 근거 경보</h4>
      ${d.alerts.map(a => `<div class="step"><span class="ix">${SEVK[a.severity][0]}</span><div><b>${esc(a.title)}</b>${Object.entries(a.group).filter(([k]) => k !== "source.ip").map(([, v]) => ` <span class="grp">${esc(v)}</span>`).join("")} <span class="dim">· ${esc(a.rule_id)} v${a.rule_version}</span>
        <div class="out">${esc(a.detail)} · 위험 ${a.risk_score.toFixed(0)} = 기본 ${a.risk_basis.severity_base} + ${a.risk_basis.event_count}×${a.risk_basis.per_event}${a.risk_basis.modifiers.length ? " · 보정 " + a.risk_basis.modifiers.map(m => `${m.delta} (${esc(m.note)})`).join(", ") : ""}</div>
        <div class="dim" style="font-size:12px">${fmtT(a.first_ts)} → ${fmtT(a.last_ts)} · 근거 이벤트 ${a.evidence.length}건 <span class="link" data-cmd="search alert=${a.id}" data-alert="${a.id}">보기</span></div></div><span></span></div>`).join("")}
      <h4 style="margin:16px 0 8px;font:700 14px var(--ko)">플레이북 실행</h4>
      ${d.runs.length ? d.runs.map(runBlock).join("") : empty("실행 없음")}
    </div><div>
      <h4 style="margin:0 0 8px;font:700 14px var(--ko)">타임라인</h4>
      <ul class="tl-list">${d.timeline.map(t => `<li class="k-${esc(t.kind)}"><span class="when">${fmtT(t.ts)}</span><b>${esc(TL_KO[t.kind] || t.kind)}</b> <span class="dim">· ${esc(t.actor)}</span><br><span class="dim">${esc(tlText(t))}</span></li>`).join("")}</ul>
      ${d.audit ? `<h4 style="margin:16px 0 8px;font:700 14px var(--ko)">감사 기록</h4><ul class="tl-list">${d.audit.slice(0, 40).map(a => `<li><span class="when">${fmtT(a.ts)}</span><b>${esc(a.action)}</b> · ${esc(a.actor)}${a.reason ? ` · ${esc(a.reason)}` : ""}</li>`).join("")}</ul>` : ""}
    </div></div>`;
  bindApprovalForms(body);
  const asel = $("select.assignee", body);
  if (asel) assigneeOptions(d.assignee).then(o => { asel.innerHTML = o.html; const me = $('[data-act="assignme"]', body); if (me && !o.inRoster) me.remove(); }).catch(() => { asel.innerHTML = `<option value="${esc(d.assignee || "")}">${esc(d.assignee || "(미지정)")}</option>`; });
  $$("[data-alert]", body).forEach(l => l.onclick = e => { e.stopPropagation(); showEvidence(+l.dataset.alert); });
  const act = async (fn, msg) => { try { await fn(); toast(msg); await loadOverview(); await showIncident(id, true); } catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); } };
  $$("[data-act]", body).forEach(b => b.onclick = () => {
    const f = b.closest(".inline-form");
    if (b.dataset.act === "transition") act(() => api(`/api/incidents/${id}/transition`, { method: "POST", body: { to: $(".to", f).value, reason: $(".reason", f).value || undefined } }), "상태 변경됨");
    if (b.dataset.act === "assign") act(() => api(`/api/incidents/${id}/assign`, { method: "POST", body: { assignee: $(".assignee", f).value || null } }), "담당자 배정됨");
    if (b.dataset.act === "assignme") act(() => api(`/api/incidents/${id}/assign`, { method: "POST", body: { assignee: S.me.username } }), "나에게 배정됨");
    if (b.dataset.act === "comment" && $(".comment", f).value.trim()) act(() => api(`/api/incidents/${id}/comment`, { method: "POST", body: { text: $(".comment", f).value } }), "메모 기록됨");
    if (b.dataset.act === "pdf") { b.disabled = true; download(`/api/reports/incident/${id}.pdf`, `rkmsiem-incident-${id}.pdf`).then(n => toast(`${esc(n)} 저장`)).catch(e => toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical")).finally(() => b.disabled = false); }
    if (b.dataset.act === "mailpdf") { b.disabled = true; api(`/api/reports/incident/${id}/email`, { method: "POST", body: $(".mailto", f).value.trim() ? { to: $(".mailto", f).value.trim() } : {} })
      .then(r => toast(r.status === "sent" ? `보고서 메일 발송 → ${esc(r.recipients)}` : `<span class="err">발송 실패: ${esc(r.error || r.status)}</span>`, r.status === "sent" ? "info" : "critical"))
      .catch(e => toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical")).finally(() => b.disabled = false); }
  });
  incidentActions($(".ix-act", body), id, live);
  if (A && !live) anime({ targets: $$(".step, .tl-list li", body), opacity: [0, 1], translateX: [-12, 0], delay: anime.stagger(30), duration: 350, easing: "easeOutCubic" });
}
// 사건 화면의 즉시 조치 — 플레이북 없이 사람이 바로 (차단·잠금은 승인 권한, 사유 필수). 사건 타임라인·감사 로그에 남음
const IX_DUR = [[3600, "1시간"], [86400, "1일"], [604800, "7일"], [0, "무기한"]];
const IX_NAME = { ip_reputation: "평판 조회", asset_lookup: "계정 조회", block_ip: "IP 차단", unblock_ip: "차단 해제", disable_account: "계정 잠금", enable_account: "잠금 해제" };
async function incidentActions(box, id, live) {
  if (!box) return;
  let t;
  try { t = await api(`/api/incidents/${id}/targets`); } catch (e) { box.innerHTML = ""; return; }
  const A_ = t.actions, any = Object.values(A_).some(Boolean) || t.playbooks.length;
  if (!any) { box.innerHTML = ""; return; }
  const ipRow = x => `<tr><td><code>${esc(x.value)}</code></td><td class="num">${x.events}</td>
    <td>${x.blocked ? `<span class="c-high">차단 중</span>${x.expires_at ? ` <span class="faint">~${fmtT(x.expires_at)}</span>` : ` <span class="faint">무기한</span>`}` : x.guard ? `<span class="faint">${esc(x.guard)}</span>` : `<span class="dim">-</span>`}</td>
    <td class="ix-btns">${A_.ip_reputation ? `<button class="btn" data-ix="ip_reputation" data-v="${esc(x.value)}">평판</button>` : ""}
      ${x.blocked ? (A_.unblock_ip ? `<button class="btn" data-ix="unblock_ip" data-v="${esc(x.value)}">차단 해제</button>` : "")
        : A_.block_ip && !x.guard ? `<select class="ix-dur" aria-label="차단 기간">${IX_DUR.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select><button class="btn danger" data-ix="block_ip" data-v="${esc(x.value)}">차단</button>` : ""}</td></tr>`;
  const acRow = x => `<tr><td><code>${esc(x.value)}</code></td><td class="num">${x.events}</td>
    <td>${x.locked ? `<span class="c-high">잠김</span>` : x.guard ? `<span class="faint">${esc(x.guard)}</span>` : `<span class="dim">-</span>`}</td>
    <td class="ix-btns">${A_.asset_lookup ? `<button class="btn" data-ix="asset_lookup" data-v="${esc(x.value)}">조회</button>` : ""}
      ${x.locked ? (A_.enable_account ? `<button class="btn" data-ix="enable_account" data-v="${esc(x.value)}">잠금 해제</button>` : "")
        : A_.disable_account && !x.guard ? `<button class="btn danger" data-ix="disable_account" data-v="${esc(x.value)}">잠금</button>` : ""}</td></tr>`;
  const sim = t.mode === "simulate";
  box.innerHTML = `<h4 style="margin:16px 0 8px;font:700 14px var(--ko)">즉시 조치 <span class="faint" style="font:400 12px var(--mono, monospace)">${sim ? "simulate — 실제로 바꾸지 않고 기록만" : "<span class='c-high'>live — 실제 방화벽·계정에 반영</span>"}</span></h4>
    ${A_.block_ip || A_.disable_account || A_.unblock_ip ? `<div class="inline-form"><input class="ix-why" placeholder="사유 (차단·잠금·해제에 필수 — 타임라인·감사 로그에 남음)" style="flex:1"></div>` : ""}
    ${t.ips.length ? `<div class="tbl"><table><thead><tr><th>IP</th><th>이벤트</th><th>상태</th><th></th></tr></thead><tbody>${t.ips.map(ipRow).join("")}</tbody></table></div>` : ""}
    ${t.accounts.length ? `<div class="tbl" style="margin-top:6px"><table><thead><tr><th>계정</th><th>이벤트</th><th>상태</th><th></th></tr></thead><tbody>${t.accounts.map(acRow).join("")}</tbody></table></div>` : ""}
    ${!t.ips.length && !t.accounts.length ? `<div class="dim">이 사건에서 나온 IP·계정이 없습니다.</div>` : ""}
    ${t.hosts.length ? `<div class="dim" style="font-size:12px;margin-top:6px">관련 호스트: ${t.hosts.map(h => `<code>${esc(h.value)}</code>`).join(" ")}</div>` : ""}
    ${(t.agents || []).length ? `<div style="margin-top:6px">원격 조치: ${t.agents.map(n => `<span class="link" data-cmd="dashboard agents ${esc(n)}">▣ ${esc(n)}</span>`).join(" · ")} <span class="faint">(컨테이너·프로세스·서비스)</span></div>` : ""}
    ${t.playbooks.length ? `<div class="inline-form" style="margin-top:8px"><select class="ix-pb" aria-label="플레이북">${t.playbooks.map(pb => `<option value="${esc(pb.id)}" title="${esc(pb.description)}">${esc(pb.name)} (${esc(pb.id)})</option>`).join("")}</select><button class="btn" data-ix="playbook">플레이북 실행</button></div>` : ""}
    <div class="ix-out"></div>`;
  const out = $(".ix-out", box), why = () => ($(".ix-why", box)?.value || "").trim();
  const show = (title, o) => { out.innerHTML = `<div class="msg" style="margin-top:8px"><b>${esc(title)}</b><pre class="pl-pre" style="max-height:220px;overflow:auto">${esc(JSON.stringify(o, null, 2))}</pre></div>`; };
  $$("[data-ix]", box).forEach(b => b.onclick = async () => {
    const a = b.dataset.ix, v = b.dataset.v;
    if (a === "playbook") {
      b.disabled = true;
      try { const r = await api(`/api/playbooks/${encodeURIComponent($(".ix-pb", box).value)}/run`, { method: "POST", body: { incident_id: id } });
        toast(`플레이북 실행 #${r.run_id ?? ""} 요청됨`); await loadOverview(); await showIncident(id, true); }
      catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); b.disabled = false; }
      return;
    }
    const destructive = ["block_ip", "unblock_ip", "disable_account", "enable_account"].includes(a);
    if (destructive && !why()) { const w = $(".ix-why", box); w?.focus(); if (w) shake(w, 5); toast("사유를 적어 주세요", "high"); return; }
    const dur = a === "block_ip" ? +b.parentElement.querySelector(".ix-dur").value : null;
    if (["block_ip", "disable_account"].includes(a) && !confirm(`${IX_NAME[a]}: ${v}${a === "block_ip" ? ` (${IX_DUR.find(d => d[0] === dur)[1]})` : ""}\n${sim ? "simulate 모드 — 실제로 바꾸지 않고 기록만 합니다." : "live 모드 — 실제로 반영됩니다."}\n계속할까요?`)) return;
    b.disabled = true;
    try {
      const r = await api(`/api/incidents/${id}/actions`, { method: "POST", body: { action: a, target: v, ...(why() ? { reason: why() } : {}), ...(a === "block_ip" ? { duration_sec: dur || null } : {}) } });
      if (destructive) { toast(`${esc(IX_NAME[a])} ${esc(v)} ${r.output?.simulated ? "(simulate — 기록만)" : "완료"}`); await loadOverview(); await showIncident(id, true); }
      else { show(`${IX_NAME[a]} — ${v}`, r.output); b.disabled = false; }
    } catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); b.disabled = false; }
  });
}
const TL_KO = { created: "사건 생성", alert_linked: "경보 연결", alert_escalated: "경보 상향", severity_changed: "심각도 변경", state_changed: "상태 변경", assigned: "담당자 배정",
  comment: "메모", manual_action: "즉시 조치", task_requested: "할 일 요청", task_done: "할 일 처리", approval_requested: "승인 요청", approval_approved: "승인", approval_rejected: "거절", playbook_result: "대응 결과", playbook_finished: "플레이북 종료" };
function tlText(t) {
  const d = t.detail || {};
  if (t.kind === "task_done") return `${d.title} — ${{ done: "완료", skipped: "건너뜀", failed: "문제 있음" }[d.outcome] || d.outcome}${d.text ? `: ${d.text}` : ""}`;
  if (t.kind === "manual_action") return `${IX_NAME[d.action] || d.action} ${d.input?.ip || d.input?.account || ""}${d.input?.duration_sec ? ` (${IX_DUR.find(x => x[0] === d.input.duration_sec)?.[1] || d.input.duration_sec + "초"})` : ""}${d.reason ? ` — ${d.reason}` : ""}${d.mode === "simulate" ? " (simulate)" : ""}${d.ok === false ? ` ✘ ${d.error}` : ""}`;
  return d.title || d.summary || d.text || (d.from ? `${STATE_KO[d.from] || d.from} → ${STATE_KO[d.to] || d.to}${d.reason ? ` (${d.reason})` : ""}` : "") ||
    (d.to ? `→ ${d.to}${d.reason ? ` (${d.reason})` : ""}` : "") || (d.assignee !== undefined ? `→ ${d.assignee || "미지정"}` : "") ||
    (d.action ? `${d.action} ${JSON.stringify(d.input || {})}` : "") || (d.state ? `${d.playbook || ""} ${STATE_KO[d.state] || d.state}${d.error ? " — " + d.error : ""}` : "") || JSON.stringify(d);
}
function runBlock(r) {
  return `<div style="margin-bottom:10px"><div><b>#${r.id} ${esc(r.playbook_id)}</b> v${r.playbook_version} ${state(r.state)} <span class="dim">· ${esc(r.mode)} · 요청 ${esc(r.requested_by)}${r.error ? ` · ${esc(r.error)}` : ""}</span>
    ${can("runs:cancel") && !["succeeded", "failed", "cancelled", "compensated"].includes(r.state) ? `<span class="link" data-cancel="${r.id}">[취소+보상]</span>` : ""}</div>
    <div class="step-list" style="margin-top:6px">${r.steps.map((s, i) => `<div class="step ${esc(s.state)}"><span class="ix">${i + 1}</span><div><b>${esc(s.step_id)}</b> <span class="dim">(${esc(s.action)}${s.attempts > 1 ? ` · 시도 ${s.attempts}` : ""})</span>
      ${s.output && !s.task ? `<div class="out">${esc(JSON.stringify(s.output)).slice(0, 300)}</div>` : ""}${s.error ? `<div class="err" style="font-size:12px">${esc(s.error)}</div>` : ""}
      ${s.state === "waiting_approval" ? approvalForm(r.id, s.step_id) : ""}${s.task ? (s.task.state === "pending" ? taskForm(r.id, s.task) : taskDone(s.task)) : ""}</div><span>${state(s.state)}</span></div>`).join("")}</div></div>`;
}
async function showEvidence(alertId) {
  try { const a = await api(`/api/alerts/${alertId}`);
    toast(`<b>근거 이벤트 ${a.evidence_events.length}건</b><br>${a.evidence_events.slice(-6).map(e => `${fmtT(e.ts, false)} ${esc(e.outcome)} ${esc(e.user_name || "")}@${esc(e.source_ip || "")}`).join("<br>")}`, a.severity); }
  catch (e) { toast(esc(errMsg(e)), "critical"); }
}
async function showRun(id, live) {
  const r = await api(`/api/runs/${id}`);
  const sec = live && $(".panel.solo[data-run]") || panelShell({ no: "#" + r.id, title: "플레이북 실행", en: "RUN" }, !live);
  sec.dataset.run = id;
  $(".panel-body", sec).innerHTML = `<div class="meta-line"><span>생성 <b>${fmtT(r.created_at)}</b></span><span>시작 <b>${fmtT(r.started_at)}</b></span><span>종료 <b>${fmtT(r.finished_at)}</b></span>
    ${r.incident_id ? `<span class="link" data-cmd="incident ${r.incident_id}">사건 #${r.incident_id}</span>` : ""}</div>${runBlock(r)}`;
  bindApprovalForms(sec);
  $$("[data-cancel]", sec).forEach(b => b.onclick = async () => { const why = prompt("취소 사유"); if (!why) return;
    try { await api(`/api/runs/${b.dataset.cancel}/cancel`, { method: "POST", body: { reason: why, compensate: true } }); await showRun(id, true); } catch (e) { toast(esc(errMsg(e)), "critical"); } });
}
out.addEventListener("click", e => {
  const c = e.target.closest("[data-cancel]");
  if (c && !c.onclick) return;
  const t = e.target.closest("[data-cmd]");
  if (t && !e.target.closest("[data-alert]")) run(t.dataset.cmd);
});

// ================================================================ 화면 틀
function panelShell(p, animate = true, host = out, solo = true) {
  const sec = document.createElement("section");
  sec.className = `panel ${solo ? "solo" : `span-${p.span || 12}`}`;
  sec.innerHTML = (solo ? `<i class="cm tl"></i><i class="cm tr"></i><i class="cm bl"></i><i class="cm br"></i>` : "") +
    `<div class="panel-head"><span class="no">${esc(p.no)}</span><span class="title">${esc(p.title)}</span><span class="en">${esc(p.en)}</span><span class="rule"></span></div><div class="panel-body"></div>`;
  host.appendChild(sec);
  if (animate && solo && M) {
    M.animate(sec, { clipPath: ["inset(48% 0% 48% 0%)", "inset(0% 0% 0% 0%)"] }, { duration: .55, ease: [.7, 0, .2, 1] });
    const far = { tl: [-60, -40], tr: [60, -40], bl: [-60, 40], br: [60, 40] };
    $$(".cm", sec).forEach(c => { const [x, y] = far[c.classList[1]]; M.animate(c, { x: [x, 0], y: [y, 0], opacity: [0, 1] }, { type: "spring", stiffness: 260, damping: 18 }); });
    M.animate($(".panel-head", sec), { opacity: [0, 1], x: [-20, 0] }, { delay: .2, type: "spring", stiffness: 300, damping: 24 });
  }
  return sec;
}
async function renderPanel(key, body, live, arg) {
  const p = PANELS[key];
  try { await p.render(body, live, arg); }
  catch (e) { body.innerHTML = `<div class="err">불러오기 실패: ${esc(errMsg(e))}</div>`; if (e.status === 401) promptLogin(); }
}
// 실시간 갱신에서 빼는 패널(지구본·편집기)이라도, 비어 있던 지구본에 첫 공격이 들어오면 다시 그림
const skipLive = (key, body) => PANELS[key].liveSkip && !(key === "map" && $(".geo-quiet", body) && S.data?.geo?.countries?.length);
async function rerender(live) {
  const v = S.view;
  if (!v) return;
  if (v.kind === "panel") { const b = $(".panel.solo .panel-body"); if (b && !(live && skipLive(v.key, b))) await renderPanel(v.key, b, live && v.key !== "map", v.arg); }
  if (v.kind === "all") for (const sec of $$(".dash-grid .panel[data-key]:not(.lazy)")) { const bd = $(".panel-body", sec); if (!(live && skipLive(sec.dataset.key, bd))) await renderPanel(sec.dataset.key, bd, sec.dataset.key !== "map"); }
  if (v.kind === "incident") await showIncident(v.arg, true);
  if (v.kind === "run") await showRun(v.arg, true);
}
async function showPanel(key, arg) {
  const g = arg !== "raw" && cxOver(key, "replace")[0];            // 이 칸을 연동 화면으로 바꿔 둔 경우
  if (g) {
    out.insertAdjacentHTML("beforeend", `<div class="crumb">✂ dashboard all › <b>${PANELS[key].no} ${esc(g.title || g.source)}</b> (연동 ${esc(g.source)}) 만 잘라서 표시</div>`);
    const sec = panelShell(cxShell(g, key), true); sec.dataset.cx = g.i;
    if (M) await sleep(250);
    S.view = { kind: "panel", key: "embed", arg: g.i };
    await renderPanel("embed", $(".panel-body", sec), false, g.i);
    return;
  }
  if (arg === "raw") arg = "";
  const p = PANELS[key];
  out.insertAdjacentHTML("beforeend", `<div class="crumb">✂ dashboard all › <b>${p.no} ${esc(p.title)}</b> 만 잘라서 표시</div>`);
  const sec = panelShell(p, true);
  if (M) await sleep(250);
  S.view = { kind: "panel", key, arg };
  await renderPanel(key, $(".panel-body", sec), false, arg);
}
function showAll() {
  out.insertAdjacentHTML("beforeend", `<div class="dash-title"><b>RKMSIEM 대시보드</b> · 전체 보기 <span class="faint">— 스크롤하면 지표마다 애니메이션 · 새 데이터는 실시간 반영</span></div>`);
  const grid = document.createElement("div"); grid.className = "dash-grid"; out.appendChild(grid);
  S.view = { kind: "all" };
  const items = [];
  ALL.forEach(k => {
    const g = cxOver(k, "replace")[0];
    if (g) items.push([g, k]); else if (!PANELS[k].perm || can(PANELS[k].perm)) items.push([null, k]);
    cxOver(k, "after").forEach(a => items.push([a, k]));
  });
  items.forEach(([g, slot]) => {
    const k = g ? "embed" : slot, p = g ? cxShell(g, slot) : PANELS[k];
    const sec = panelShell(p, false, grid, false); sec.classList.add("lazy"); sec.dataset.key = k;
    if (g) sec.dataset.cx = g.i;
    let done = false;
    const go = () => { if (done) return; done = true; sec.classList.remove("lazy");
      if (M) M.animate(sec, { opacity: [0, 1], y: [40, 0] }, { type: "spring", stiffness: 120, damping: 18 }); renderPanel(k, $(".panel-body", sec), false); };
    if (M && M.inView) M.inView(sec, go, { amount: .15 }); else go();
  });
}

// ================================================================ 명령
const ORDER = ["threat", "kpi", "alerts", "hourly", "top", "targets", "timeline", "map", "ips", "incidents", "runs", "rules", "collectors", "events", "audit", "blocklist", "doctor", "automation", "mail", "settings", "team", "topology", "connect", "agents"];
const ALL = ["threat", "kpi", "alerts", "hourly", "top", "targets", "map", "timeline", "incidents", "runs", "ips", "collectors"];
const ALIAS = {};
ORDER.forEach(k => PANELS[k].aliases.forEach(a => ALIAS[a] = k));
["all", "전체", "a"].forEach(a => ALIAS[a] = "all");
function helpHtml() {
  return `<div class="help"><div class="h">사용법: dashboard [option] — dashboard all(전체 화면)에서 해당 지표만 잘라 보여줍니다</div>
    ${ORDER.map(k => `<code>dashboard ${PANELS[k].aliases[0]}</code><span>${PANELS[k].no} ${esc(PANELS[k].title)} — ${esc(PANELS[k].desc)} <span class="faint">(같은 뜻: ${PANELS[k].aliases.slice(1).join(", ")})</span></span>`).join("")}
    <code>dashboard all</code><span>전체 대시보드</span>
    <div class="h">조사 · 대응</div>
    <code>incident &lt;번호&gt;</code><span>사건 상세 — 근거 경보·타임라인·플레이북·상태 변경·배정</span>
    <code>run &lt;번호&gt;</code><span>플레이북 실행 상세</span>
    <code>approve &lt;실행&gt; &lt;단계&gt; &lt;사유&gt;</code><span>파괴적 조치 승인 (reject 는 거절)</span>
    <code>search ip=… user=… outcome=… 텍스트</code><span>이벤트 검색</span>
    <code>report incident &lt;번호&gt;</code><span>사건 보고서 PDF 받기 (사건 화면에서 메일 발송)</span>
    <code>report [6h|24h|7d|30d|all]</code><span>기간 요약 보고서 PDF 받기 (생략하면 현재 range)</span>
    <code>mfa · mfa setup · mfa off</code><span>2단계 인증(OTP 앱) 상태 / 켜기 (QR 코드) / 끄기</span>
    <code>ssh [계정@]IP</code><span>웹 터미널 — 토폴로지에서 SIEM 과 와이어로 이어진 기기에 SSH 접속 (권한 terminal:use). ssh 만 치면 접속 가능한 기기 목록</span>
    <code>connect [연동] [대시보드]</code><span>연동한 외부 서비스 목록 · 화면 열기 (예: connect grafana) — 추가는 settings → 당겨오기</span>
    <code>rep &lt;IP&gt;</code><span>IP 평판 조회 — AbuseIPDB 점수·신고 수 + 공개 차단 목록 피드</span>
    <code>range 6h|24h|7d|30d|all|data</code><span>집계 시간 범위 (data = 최신 데이터 기준 24시간, 기본)</span>
    <div class="h">계정 · 기타</div>
    <code>login · logout · whoami · passwd</code><span>로그인 / 로그아웃 / 내 권한 / 비밀번호 변경</span>
    <code>clear · theme [green|amber|cyan|pink]</code><span>화면 지우기 / 강조 색</span>
    <code>↑ / ↓ · Tab</code><span>이전 명령 · 자동 완성</span></div>`;
}
const echo = (cmd, meta = "") => `<div class="cmd-echo"><span class="ps">${esc(S.me?.username || "guest")}@rkmsiem:~$</span> <span class="typed">${esc(cmd)}</span>${meta ? `<span class="meta">${meta}</span>` : ""}</div>`;
let busy = false;
const hist = []; let hi = 0;
let loginStep = null;
async function run(raw) {
  const cmd = String(raw).trim();
  if (loginStep) return loginInput(cmd);
  if (!cmd || busy) return;
  hist.push(cmd); hi = hist.length;
  const [c0, ...rest] = cmd.split(/\s+/);
  const c = c0.toLowerCase(), arg = rest.join(" ");
  const opt = (rest[0] || "").replace(/^-+/, "").toLowerCase();
  hideTip(); fkeyHandler = null;
  if (c === "clear" || c === "cls") { S.view = null; await intro(true); return; }
  if (c === "login") return promptLogin();
  if (c === "passwd") { if (!S.token) return promptLogin(); return promptPasswd(); }
  if (c === "logout") { try { await api("/api/auth/logout", { method: "POST" }); } catch (e) { /* 이미 만료 */ } setToken(null); out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg">로그아웃했습니다.</div>`); return; }
  if (c === "theme") { const t = ["green", "amber", "cyan", "pink"].includes(opt) ? opt : null; if (t) document.documentElement.dataset.accent = t === "green" ? "" : t;
    out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg">${t ? `강조 색 ${t}` : "theme green | amber | cyan | pink"}</div>`); return; }
  if (c === "help" || c === "?" || (c === "dashboard" && (!opt || opt === "help"))) { S.view = null; out.innerHTML = echo(cmd) + helpHtml(); scrollTo(0, 0); return; }
  if (!S.token) { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg c-high">먼저 <span class="acc">login</span> 하세요.</div>`); scrollTo(0, document.body.scrollHeight); return; }
  if (c === "whoami") { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg">${esc(S.me.username)} (${esc(S.me.role)}) · 실행 모드 ${esc(S.me.mode)}<br><span class="dim">${S.me.permissions.map(esc).join(" · ")}</span></div>`); return; }
  if (c === "range") {
    const R = { "6h": 6, "24h": 24, "7d": 168, "30d": 720 }, now = Date.now() / 1000;
    if (R[opt]) S.range = { label: `현재 기준 최근 ${opt}`, from: now - R[opt] * 3600, to: now };
    else if (opt === "all") S.range = { label: "전체 기간", from: 0, to: now };
    else S.range = { label: "최근 데이터 24시간", from: null, to: null };
    out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg">집계 범위: ${esc(S.range.label)}</div>`);
    await loadOverview().catch(() => {}); if (S.view) await rerender(true); return;
  }
  if (c === "approve" || c === "reject") {
    const [rid, sid, ...why] = rest;
    try { await api(`/api/runs/${+rid}/steps/${encodeURIComponent(sid || "")}/decision`, { method: "POST", body: { approve: c === "approve", reason: why.join(" ") } });
      out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg acc">실행 #${esc(rid)} · ${esc(sid)} ${c === "approve" ? "승인" : "거절"} 완료</div>`); }
    catch (e) { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg c-high">${esc(errMsg(e))}</div>`); }
    scrollTo(0, document.body.scrollHeight); return;
  }
  if (c === "report" || c === "보고서") {                             // report incident 17 | report [6h|24h|7d|30d|all]
    const R = { "6h": 6, "24h": 24, "7d": 168, "30d": 720 }, now = Date.now() / 1000;
    let path, name;
    if (opt === "incident" && +rest[1]) { path = `/api/reports/incident/${+rest[1]}.pdf`; name = `rkmsiem-incident-${+rest[1]}.pdf`; }
    else { const q = new URLSearchParams(R[opt] ? { from: now - R[opt] * 3600, to: now } : opt === "all" ? { from: 0, to: now } : rangeQuery());
      path = `/api/reports/summary.pdf?${q}`; name = "rkmsiem-summary.pdf"; }
    out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg dim">PDF 만드는 중…</div>`);
    try { const n = await download(path, name); out.lastElementChild.outerHTML = `<div class="msg acc">⇩ ${esc(n)} 저장됨 <span class="dim">(메일 발송은 dashboard mail · 사건 화면)</span></div>`; }
    catch (e) { out.lastElementChild.outerHTML = `<div class="msg c-high">${esc(errMsg(e))}</div>`; }
    scrollTo(0, document.body.scrollHeight); return;
  }
  if (c === "mfa" || c === "2fa") { await mfaCommand(opt, cmd); return; }
  if (c === "ssh" || c === "터미널") {                               // 웹 터미널 (토폴로지에서 SIEM 과 와이어로 이어진 기기)
    try { out.insertAdjacentHTML("beforeend", echo(cmd) + await terminalCommand(arg)); }
    catch (e) { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg c-high">${esc(errMsg(e))}</div>`); }
    scrollTo(0, document.body.scrollHeight); return;
  }
  if (c === "rep" || c === "평판") {                                 // IP 평판 직접 조회 (AbuseIPDB + 피드)
    try { out.insertAdjacentHTML("beforeend", echo(cmd) + repHtml(await api(`/api/intel/lookup?ip=${encodeURIComponent(rest[0] || "")}`))); }
    catch (e) { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg c-high">${esc(errMsg(e))}</div>`); }
    scrollTo(0, document.body.scrollHeight); return;
  }
  busy = true;
  const t0 = performance.now();
  try {
    if (!S.data) await loadOverview();
    if (c === "incident" && +rest[0]) { out.innerHTML = echo(cmd); S.view = { kind: "incident", arg: +rest[0] }; await showIncident(+rest[0]); }
    else if (c === "run" && +rest[0]) { out.innerHTML = echo(cmd); S.view = { kind: "run", arg: +rest[0] }; await showRun(+rest[0]); }
    else if (c === "search") { out.innerHTML = echo(cmd); await showPanel("events", arg.replace(/\balert=(\d+)/, "")); if (/alert=(\d+)/.test(arg)) showEvidence(+arg.match(/alert=(\d+)/)[1]); }
    else {
      const key = c === "dashboard" ? ALIAS[opt] : ALIAS[c.replace(/^-+/, "")];
      if (!key) { out.insertAdjacentHTML("beforeend", echo(cmd) + `<div class="msg c-high">${c === "dashboard" ? `알 수 없는 옵션: ${esc(opt)}` : `명령을 찾을 수 없습니다: ${esc(c0)}`} — <span class="acc">help</span></div>`); scrollTo(0, document.body.scrollHeight); return; }
      out.innerHTML = echo(cmd); scrollTo(0, 0);
      if (key === "all") showAll(); else await showPanel(key, c === "dashboard" ? rest.slice(1).join(" ") : arg);
    }
    $(".cmd-echo", out)?.insertAdjacentHTML("beforeend", `<span class="meta">rendered in ${((performance.now() - t0) / 1000).toFixed(2)}s</span>`);
  } catch (e) {
    out.insertAdjacentHTML("beforeend", `<div class="msg c-high">${esc(errMsg(e))}</div>`);
    if (e.status === 401) promptLogin();
  } finally { busy = false; }
}
addEventListener("keydown", e => {
  const m = { F1: "all", F2: "critical", F3: "high", F4: "medium", F5: "low" }[e.key];
  if (m && fkeyHandler && !e.target.closest?.(".tw")) { e.preventDefault(); fkeyHandler(m); }
});

const VERDICT_KO = { malicious: ["c-critical", "악성"], suspicious: ["c-high", "의심"], clean: ["acc", "정상(허용 목록)"], unknown: ["dim", "정보 없음"], internal: ["dim", "내부/예약 대역"] };
function repHtml(r) {
  const [cl, ko] = VERDICT_KO[r.verdict] || ["dim", r.verdict], a = r.abuseipdb, st = r.abuseipdb_status || {};
  return `<div class="msg"><b>${esc(r.ip)}</b> → <b class="${cl}">${esc(ko)}</b> <span class="dim">(${esc(r.verdict)} · 신뢰도 ${r.confidence} · 출처 ${esc(r.source || "-")})</span>
    ${r.note ? `<br><span class="dim">${esc(r.note)}</span>` : ""}
    ${a && !a.error ? `<br>AbuseIPDB 점수 <b class="${a.score >= 75 ? "c-critical" : a.score >= 25 ? "c-high" : "acc"}">${a.score}</b> · 신고 ${fmt(a.total_reports)}건 (신고자 ${fmt(a.distinct_users)}) · ${esc(a.country || "?")} · ${esc(a.isp || "")} ${a.usage_type ? `· ${esc(a.usage_type)}` : ""}${a.is_tor ? " · <b class='c-high'>Tor</b>" : ""}
      <span class="dim">· 마지막 신고 ${esc(a.last_reported_at || "-")}${a.cached ? " · 캐시" : ""}</span>` : ""}
    ${a?.error ? `<br><span class="c-high">AbuseIPDB: ${esc(a.error)}</span> <span class="dim">— 공개 피드 결과로 판정</span>` : ""}
    ${!a && !st.enabled ? `<br><span class="dim">AbuseIPDB 키 없음 — 공개 피드·로컬 항목만 사용</span>` : ""}
    ${st.remaining != null ? `<br><span class="faint">오늘 남은 AbuseIPDB 조회 ${fmt(st.remaining)}/${fmt(st.limit)}</span>` : ""}</div>`;
}

// ---------------------------------------------------------------- 로그인 (터미널 안에서)
function promptLogin() {
  loginStep = { step: "user" };
  input.type = "text"; input.value = ""; input.placeholder = "사용자 이름";
  $("#ps").innerHTML = `login:<span class="path"> username</span>`;
  out.insertAdjacentHTML("beforeend", `<div class="msg acc">로그인 — 사용자 이름을 입력하세요 (Esc 취소)</div>`);
  scrollTo(0, document.body.scrollHeight); input.focus();
}
// 비밀번호 변경 (입력은 화면에 남기지 않음)
function promptPasswd() {
  loginStep = { step: "pw_cur", passwd: true };
  input.type = "password"; input.value = ""; input.placeholder = "현재 비밀번호";
  $("#ps").innerHTML = `passwd:<span class="path"> current</span>`;
  out.insertAdjacentHTML("beforeend", `<div class="msg acc">비밀번호 변경 — 현재 비밀번호, 새 비밀번호(12자 이상)를 차례로 입력 (Esc 취소)</div>`);
  input.focus();
}
async function passwdInput(v) {
  if (loginStep.step === "pw_cur") { loginStep = { step: "pw_new", passwd: true, cur: v }; input.value = ""; input.placeholder = "새 비밀번호 (12자 이상)"; $("#ps").innerHTML = `passwd:<span class="path"> new</span>`; return; }
  if (loginStep.step === "pw_new") { loginStep = { step: "pw_again", passwd: true, cur: loginStep.cur, nw: v }; input.value = ""; input.placeholder = "새 비밀번호 확인"; $("#ps").innerHTML = `passwd:<span class="path"> again</span>`; return; }
  const { cur, nw } = loginStep;
  loginStep = null; input.type = "text"; input.placeholder = "dashboard [option] 입력 · help 로 전체 명령 보기";
  if (nw !== v) { out.insertAdjacentHTML("beforeend", `<div class="msg c-high">새 비밀번호가 서로 다릅니다.</div>`); $("#ps").innerHTML = `${esc(S.me.username)}@rkmsiem:<span class="path">~</span>$`; return; }
  try { await api("/api/me/password", { method: "POST", body: { current: cur, new: nw } });
    setToken(null); out.insertAdjacentHTML("beforeend", `<div class="msg acc">비밀번호를 바꿨습니다. 모든 세션이 로그아웃되었으니 다시 로그인하세요.</div>`); promptLogin(); }
  catch (e) { out.insertAdjacentHTML("beforeend", `<div class="msg c-high">변경 실패: ${esc(e.status === 401 ? "현재 비밀번호가 틀립니다" : errMsg(e))}</div>`); $("#ps").innerHTML = `${esc(S.me.username)}@rkmsiem:<span class="path">~</span>$`; }
}
async function loginInput(v) {
  if (loginStep.passwd) return passwdInput(v);
  if (loginStep.mfaCmd) return mfaInput(v);
  if (loginStep.step === "user") {
    if (!v) return;
    loginStep = { step: "pass", user: v };
    input.type = "password"; input.placeholder = "비밀번호"; $("#ps").innerHTML = `login:<span class="path"> password</span>`;
    return;
  }
  if (loginStep.step === "mfa") {                                    // 2단계 인증 코드
    const { ticket } = loginStep;
    loginStep = null; input.type = "text"; input.removeAttribute("inputmode"); input.placeholder = "dashboard [option] 입력 · help 로 전체 명령 보기";
    try { await loginDone(await api("/api/auth/mfa", { method: "POST", body: { ticket, code: v } })); }
    catch (e) {
      const again = e.body?.error === "invalid_code";
      out.insertAdjacentHTML("beforeend", `<div class="msg c-high">${again ? "코드가 맞지 않습니다 (방금 쓴 코드는 다시 못 씀) — 앱에 새로 나온 6자리를 입력하세요" : e.status === 429 ? "시도가 너무 많습니다. 잠시 후 다시" : "인증 시간이 지났습니다 — 처음부터 다시 로그인하세요"}</div>`);
      if (again) promptMfa(ticket); else promptLogin();
    }
    return;
  }
  const user = loginStep.user;
  loginStep = null; input.type = "text"; input.placeholder = "dashboard [option] 입력 · help 로 전체 명령 보기";
  try {
    const r = await api("/api/auth/login", { method: "POST", body: { username: user, password: v } });
    if (r.mfa_required) return promptMfa(r.mfa_ticket);
    await loginDone(r);
  } catch (e) {
    out.insertAdjacentHTML("beforeend", `<div class="msg c-high">로그인 실패: ${esc(e.status === 429 ? "시도가 너무 많습니다. 잠시 후 다시" : "사용자 이름 또는 비밀번호가 올바르지 않습니다")}</div>`);
    $("#ps").innerHTML = `guest@rkmsiem:<span class="path">~</span>$`;
  }
}
function promptMfa(ticket) {
  loginStep = { step: "mfa", ticket };
  input.type = "text"; input.value = ""; input.setAttribute("inputmode", "numeric"); input.autocomplete = "one-time-code"; input.placeholder = "OTP 앱의 6자리 코드";
  $("#ps").innerHTML = `login:<span class="path"> code</span>`;
  out.insertAdjacentHTML("beforeend", `<div class="msg acc">2단계 인증 — OTP 앱(Google Authenticator 등)에 보이는 6자리 코드를 입력하세요</div>`);
  scrollTo(0, document.body.scrollHeight); input.focus();
}
async function loginDone(r) {
  setToken(r.token);
  if (r.must_change_password) return forcePasswd();
  await afterLogin(true);
}
async function forcePasswd() {                                       // 첫 로그인·임시 비밀번호: 바꾸기 전에는 다른 기능이 막힘
  S.me = await api("/api/me");
  $("#who").textContent = `${S.me.username} (${S.me.role})`;
  out.insertAdjacentHTML("beforeend", `<div class="msg c-high">처음 받은(또는 관리자가 재설정한) 비밀번호입니다. 새 비밀번호를 정해야 콘솔을 쓸 수 있습니다.</div>`);
  promptPasswd();
}
async function afterLogin(announce) {
  S.me = await api("/api/me");
  if (S.me.must_change_password) return forcePasswd();
  $("#who").textContent = `${S.me.username} (${S.me.role})`;
  $("#ps").innerHTML = `${esc(S.me.username)}@rkmsiem:<span class="path">~</span>$`;
  const md = $("#mode"); md.textContent = S.me.mode.toUpperCase(); md.className = `mode ${S.me.mode === "live" ? "live" : ""}`;
  await Promise.all([loadOverview(), loadCx()]);
  openStream();
  if (announce) out.insertAdjacentHTML("beforeend", `<div class="msg acc">${esc(S.me.username)} 님 로그인 (${esc(S.me.role)}). <span class="dim">dashboard all 또는 아래 버튼으로 시작하세요.</span></div>`);
  if (announce && !S.me.mfa_enabled && can("terminal:use")) out.insertAdjacentHTML("beforeend", `<div class="msg c-medium">2단계 인증이 꺼져 있습니다 — <span class="link" data-cmd="mfa setup">mfa setup</span> 으로 켜세요 (웹 터미널은 2단계 인증 계정만 사용 가능)</div>`);
  scrollTo(0, document.body.scrollHeight);
}

// ---------------------------------------------------------------- 2단계 인증 (mfa)
let qrLib = null;
function loadQr() {
  return qrLib ||= new Promise((ok, bad) => { const sc = document.createElement("script"); sc.src = "/static/vendor/qrcode/qrcode.js";
    sc.onload = ok; sc.onerror = () => { qrLib = null; bad(new Error("QR 모듈을 불러오지 못했습니다")); }; document.head.appendChild(sc); });
}
function mfaPrompt(step, ph, ps, pw) {
  loginStep = { mfaCmd: true, ...step };
  input.type = pw ? "password" : "text"; input.value = ""; input.placeholder = ph;
  if (!pw) input.setAttribute("inputmode", "numeric"); else input.removeAttribute("inputmode");
  $("#ps").innerHTML = `mfa:<span class="path"> ${ps}</span>`; input.focus();
}
function mfaEnd() { loginStep = null; input.type = "text"; input.removeAttribute("inputmode"); input.placeholder = "dashboard [option] 입력 · help 로 전체 명령 보기";
  $("#ps").innerHTML = `${esc(S.me.username)}@rkmsiem:<span class="path">~</span>$`; }
async function mfaCommand(opt, cmd) {
  const msg = h => { out.insertAdjacentHTML("beforeend", h); scrollTo(0, document.body.scrollHeight); };
  try {
    const st = await api("/api/me/mfa");
    if (!opt) return msg(echo(cmd) + `<div class="msg">2단계 인증: ${st.enabled ? `<b class="acc">켜짐</b>` : `<b class="c-high">꺼짐</b>`}
      ${st.required_for_terminal ? `<span class="dim">· 웹 터미널은 2단계 인증 계정만 사용 가능</span>` : ""}<br><span class="dim">${st.enabled ? "끄기: mfa off" : "켜기: mfa setup"}</span></div>`);
    if (opt === "setup") {
      if (st.enabled) return msg(echo(cmd) + `<div class="msg c-high">이미 켜져 있습니다. 휴대폰을 바꿨다면 mfa off 후 다시 setup 하세요.</div>`);
      const [r] = await Promise.all([api("/api/me/mfa/setup", { method: "POST" }), loadQr()]);
      const qr = qrcode(0, "M"); qr.addData(r.uri); qr.make();
      msg(echo(cmd) + `<div class="msg mfa-box"><div class="mfa-qr">${qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true, title: "2단계 인증 QR 코드" })}</div>
        <div><b>1.</b> 휴대폰 OTP 앱(Google Authenticator · Microsoft Authenticator 등)에서 <b>QR 코드 스캔</b><br>
        <span class="dim">스캔이 안 되면 '설정 키 입력' 으로:</span> <code class="mfa-key">${esc(r.secret.match(/.{1,4}/g).join(" "))}</code><br>
        <b>2.</b> 앱에 나온 <b>6자리 코드</b>를 아래에 입력하면 켜집니다 <span class="dim">(Esc 취소 — 코드를 넣기 전에는 켜지지 않음)</span><br>
        <span class="faint">이 화면은 지금 한 번만 보입니다. 다른 사람이 보지 않게 하세요.</span></div></div>`);
      return mfaPrompt({ step: "enable" }, "앱의 6자리 코드", "code");
    }
    if (opt === "off") {
      if (!st.enabled) return msg(echo(cmd) + `<div class="msg">이미 꺼져 있습니다.</div>`);
      msg(echo(cmd) + `<div class="msg acc">2단계 인증 끄기 — 비밀번호와 지금 코드를 차례로 입력 (Esc 취소)</div>`);
      return mfaPrompt({ step: "off_pw" }, "비밀번호", "password", true);
    }
    msg(echo(cmd) + `<div class="msg">사용법: mfa · mfa setup · mfa off</div>`);
  } catch (e) { msg(echo(cmd) + `<div class="msg c-high">${esc(errMsg(e))}</div>`); }
}
async function mfaInput(v) {
  const msg = h => { out.insertAdjacentHTML("beforeend", h); scrollTo(0, document.body.scrollHeight); };
  const s = loginStep;
  if (s.step === "off_pw") return mfaPrompt({ step: "off_code", pw: v }, "앱의 6자리 코드", "code");
  try {
    if (s.step === "enable") { await api("/api/me/mfa/enable", { method: "POST", body: { code: v } }); S.me.mfa_enabled = true;
      mfaEnd(); $$(".mfa-qr").forEach(q => q.closest(".mfa-box").innerHTML = `<span class="dim">(QR 코드 숨김)</span>`);
      return msg(`<div class="msg acc">2단계 인증을 켰습니다. 다음 로그인부터 비밀번호 다음에 앱의 코드를 묻습니다.</div>`); }
    if (s.step === "off_code") { await api("/api/me/mfa/disable", { method: "POST", body: { password: s.pw, code: v } }); S.me.mfa_enabled = false;
      mfaEnd(); return msg(`<div class="msg acc">2단계 인증을 껐습니다.</div>`); }
  } catch (e) {
    if (s.step === "enable") { msg(`<div class="msg c-high">${esc(e.body?.details || errMsg(e))} — 다시 입력하세요 (Esc 취소)</div>`); return mfaPrompt({ step: "enable" }, "앱의 6자리 코드", "code"); }
    mfaEnd(); msg(`<div class="msg c-high">${esc(e.body?.details || errMsg(e))}</div>`);
  }
}

// ---------------------------------------------------------------- 입력창
const COMPLETE = ["help", "clear", "login", "logout", "whoami", "passwd", "range ", "search ", "incident ", "run ", "rep ", "ssh ", "mfa", "mfa setup", "mfa off", "report ", "report incident ", "approve ", "reject ", "theme ", "dashboard all"].concat(ORDER.map(k => "dashboard " + PANELS[k].aliases[0]));
input.addEventListener("keydown", e => {
  if (e.key === "Escape" && loginStep) { loginStep = null; input.type = "text"; input.value = ""; input.removeAttribute("inputmode"); $("#ps").innerHTML = `${esc(S.me?.username || "guest")}@rkmsiem:<span class="path">~</span>$`; return; }
  if (e.key === "Enter") { const v = input.value; input.value = ""; run(v); }
  else if (loginStep) return;
  else if (e.key === "ArrowUp") { if (hi > 0) input.value = hist[--hi]; e.preventDefault(); }
  else if (e.key === "ArrowDown") { if (hi < hist.length - 1) input.value = hist[++hi]; else { hi = hist.length; input.value = ""; } e.preventDefault(); }
  else if (e.key === "Tab") { e.preventDefault(); const v = input.value.toLowerCase(), m = COMPLETE.filter(x => x.startsWith(v) && x !== v);
    if (m.length === 1) input.value = m[0]; else if (m.length > 1) out.insertAdjacentHTML("beforeend", `<div class="msg dim">${m.map(esc).join("    ")}</div>`); }
});
$("#term").addEventListener("click", e => { if (booted && !e.target.closest("input,button,a,select,table,.crow,.hrow,.col,.tl-row,svg,.globe-box,.link,[data-cmd],.au-grid,.au-bar,.au-tool") && !getSelection().toString()) input.focus(); });
$("#chips").innerHTML = ["all", "threat", "incidents", "runs", "map", "alerts", "hourly", "top", "ips", "collectors", "rules", "events", "automation", "mail", "settings", "team", "topology", "connect", "agents"].map(k => k === "all"
  ? `<button class="chip" data-cmd="dashboard all">all<span class="ko">전체</span></button>` : `<button class="chip" data-cmd="dashboard ${PANELS[k].aliases[0]}">${PANELS[k].aliases[0]}<span class="ko">${esc(PANELS[k].title)}</span></button>`).join("") +
  `<button class="chip" data-cmd="help">help</button>`;
$$(".chip").forEach(b => b.onclick = async () => { if (busy || loginStep) return; const cmd = b.dataset.cmd; input.value = ""; input.focus();
  if (A) { for (const ch of cmd) { input.value += ch; await sleep(18); } await sleep(100); } input.value = ""; run(cmd); });

// ================================================================ 부팅 → 로고 → 로그인
const FONT = { R: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"], K: ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
  M: ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"], S: ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
  I: ["██╗", "██║", "██║", "██║", "██║", "╚═╝"], E: ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"] };
const NOISE = "█▓▒░╳╬#%@$&?";
const logoHtml = (p = 1) => [0, 1, 2, 3, 4, 5].map(r => [..."RKMSIEM"].map((ch, i) => {
  const th = Math.min(1, Math.max(0, p * 1.7 - (i / 6) * 0.7)); let t = "";
  for (const x of FONT[ch][r]) t += x !== " " && Math.random() > th ? NOISE[Math.random() * NOISE.length | 0] : x;
  return `<span class="ch ${i < 3 ? "rkm" : "siem"}" data-i="${i}">${t}</span>`; }).join(" ")).join("\n");
const rnd = (a, b) => a + Math.random() * (b - a);
function jitter(g, amt) {
  const [base, r, c] = [$(".base", g), $(".layer.r", g), $(".layer.c", g)];
  [r, c].forEach((l, k) => { const top = rnd(0, 85), h = rnd(6, 40); l.style.opacity = .9;
    l.style.transform = `translate(${(k ? -1 : 1) * rnd(2, 12) * amt}px, ${rnd(-2, 2) * amt}px)`;
    l.style.clipPath = Math.random() < .35 ? "none" : `inset(${top}% 0 ${Math.max(0, 100 - top - h)}% 0)`; });
  base.style.transform = Math.random() < .35 ? `translateX(${rnd(-4, 4) * amt}px) skewX(${rnd(-8, 8) * amt}deg)` : "none";
  base.style.clipPath = Math.random() < .2 ? `inset(${rnd(0, 60)}% 0 ${rnd(0, 30)}% 0)` : "none";
}
function settle(g) { $$(".layer", g).forEach(l => { l.style.opacity = 0; l.style.transform = "none"; l.style.clipPath = "none"; }); const b = $(".base", g); b.style.transform = "none"; b.style.clipPath = "none"; }
async function screenGlitch(frames) {
  const root = document.documentElement, fl = $("#flash"), term = $("#term");
  for (const [inv, bands, ms] of frames) {
    root.classList.toggle("invert", inv);
    fl.innerHTML = Array.from({ length: bands }, () => `<i style="top:${rnd(0, 92)}%;height:${rnd(1.5, 14)}%;transform:translateX(${rnd(-30, 30)}px)"></i>`).join("");
    term.style.transform = bands ? `translateX(${rnd(-10, 10)}px)` : "none";
    await new Promise(r => setTimeout(r, ms));
  }
  root.classList.remove("invert"); fl.innerHTML = ""; term.style.transform = "none";
}
async function glitchIn(g) {
  const set = html => $$("pre", g).forEach(x => x.innerHTML = html);
  if (!A || skipping) { set(logoHtml(1)); return; }
  const T = 1200, t0 = performance.now();
  await new Promise(done => { const iv = setInterval(() => { const p = Math.min(1, (performance.now() - t0) / T); set(logoHtml(p)); jitter(g, 1 - p * 0.6);
    if (p >= 1 || skipping) { clearInterval(iv); done(); } }, 45); });
  set(logoHtml(1)); jitter(g, 1.3);
  await screenGlitch([[true, 0, 70], [false, 3, 45], [true, 2, 35], [false, 4, 55], [true, 0, 25], [false, 1, 40]]);
  settle(g);
}
function idleGlitch(g) {
  if (!A) return;
  setTimeout(async () => { if (!g.isConnected) return; const n = 2 + (Math.random() * 4 | 0);
    for (let k = 0; k < n; k++) { jitter(g, rnd(.4, 1)); await sleep(rnd(35, 70)); } settle(g);
    if (Math.random() < .35) await screenGlitch([[true, 0, 40], [false, 2, 50]]); idleGlitch(g); }, rnd(2200, 5200));
}
let booted = false;
async function intro(again) {
  out.innerHTML = "";
  if (!again) {
    const pre = document.createElement("pre"); pre.className = "boot"; out.appendChild(pre);
    const hint = document.createElement("div"); hint.className = "skip"; hint.textContent = "아무 키나 누르면 건너뜁니다"; out.appendChild(hint);
    let lines = [];
    try {                                                   // 부팅 로그 = 실제 서버 상태(/readyz)
      const r = await fetch("/readyz"); const j = await r.json(); const ck = j.checks;
      lines = [["RKMSIEM 콘솔 기동", true], ["데이터베이스 연결", ck.database], ["수집 파이프라인 작업자", ck.pipeline_worker], ["플레이북 작업자", ck.soar_worker],
        ["수집 큐 여유", ck.queue_ok], ["수집기 상태", ck.collectors_ok], [`준비 상태 → ${j.ready ? "READY" : "NOT READY"}`, j.ready]];
    } catch (e) { lines = [["서버에 연결할 수 없습니다", false]]; }
    let text = "";
    for (let i = 0; i < lines.length; i++) {
      const [msg, ok] = lines[i], t = `[${(i * 0.137).toFixed(3).padStart(7)}] ${msg}`;
      if (A && !skipping) { const t0 = performance.now(); for (let j = 0; j < t.length && !skipping; j = Math.round((performance.now() - t0) / 200 * t.length)) { pre.innerHTML = text + esc(t.slice(0, j)) + "▌"; await sleep(16); } }
      text += esc(t) + ` <span class="faint">${".".repeat(Math.max(3, 60 - t.length))}</span> ` + (ok ? `<span class="ok">[ OK ]</span>` : `<span class="warn">[ !! ]</span>`) + "\n";
      pre.innerHTML = text; await sleep(A ? 80 : 0);
    }
    await sleep(A ? 400 : 0);
    if (A && !skipping) await anime({ targets: out, opacity: [1, 0], duration: 300, easing: "easeInCubic" }).finished;
    out.style.opacity = 1; out.innerHTML = "";
  }
  const wrap = document.createElement("div"); wrap.className = "logo-wrap";
  wrap.innerHTML = `<div class="glitch" aria-label="RKMSIEM" role="img"><pre class="logo base"></pre><pre class="logo layer r" aria-hidden="true"></pre><pre class="logo layer c" aria-hidden="true"></pre></div>
    <div class="tagline"><b>RKMSIEM</b> · Security Information &amp; Event Management + SOAR · 실시간 보안 관제 콘솔<br><br>
    ${S.token ? `<span class="acc">dashboard [option]</span> 을 입력하면 해당 지표가 나타납니다. 예) <span class="acc">dashboard all</span> · <span class="acc">dashboard incidents</span> · <span class="acc">help</span>`
      : `먼저 <span class="acc">login</span> 하세요. 계정은 관리자가 발급합니다 (README 참고).`}</div>`;
  out.appendChild(wrap);
  const g = $(".glitch", wrap), tag = $(".tagline", wrap);
  if (A && !skipping) tag.style.opacity = 0;
  await glitchIn(g);
  if (A && !skipping) anime({ targets: tag, opacity: [0, 1], translateY: [8, 0], duration: 500, easing: "easeOutCubic" }); else tag.style.opacity = 1;
  idleGlitch(g);
  const pa = $("#promptArea");
  if (pa.classList.contains("hidden")) { pa.classList.remove("hidden"); if (A && !skipping) anime({ targets: pa, opacity: [0, 1], translateY: [14, 0], duration: 450, easing: "easeOutCubic" }); }
  booted = true; skipping = false; input.focus();
  if (!again) {
    if (S.token) { try { await afterLogin(false); } catch (e) { setToken(null); promptLogin(); } }
    else promptLogin();
  }
}
const skip = () => { if (!booted) skipping = true; };
addEventListener("keydown", skip); addEventListener("pointerdown", skip);
intro(false);
