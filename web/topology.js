/* RKMSIEM 네트워크 토폴로지 — 감지한 기기를 끌어다 놓고 와이어로 연결, 실시간 경보·차단 상태를 겹쳐 보여 준다.
   배치는 설정 'topology' (버전·감사 기록), 상태는 /api/topology, 감지는 /api/topology/discover.
   app.js 보다 먼저 읽히며 app.js 의 공통 도구를 호출 시점에 사용한다. */
"use strict";

const TP_TYPES = {
  siem: ["SIEM", "M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z M9 12l2 2 4-4"],
  server: ["서버", "M4 3h16v7H4z M4 14h16v7H4z M8 6.5h.01 M8 17.5h.01"],
  router: ["라우터", "M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18 M7 12h10 M14 9l3 3-3 3 M12 7v10"],
  switch: ["스위치", "M3 7h18v10H3z M7 10.5h10 M14 8.5l3 2-3 2 M17 13.5H7 M10 11.5l-3 2 3 2"],
  firewall: ["방화벽", "M3 5h18v14H3z M3 10h18 M3 15h18 M9 5v5 M15 10v5 M9 15v4"],
  ids: ["IDS", "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z M12 9a3 3 0 1 0 0 6a3 3 0 1 0 0-6"],
  pc: ["PC", "M3 4h18v12H3z M8 20h8 M12 16v4"],
  attacker: ["공격자", "M12 2v4 M12 18v4 M2 12h4 M18 12h4 M12 6a6 6 0 1 0 0 12a6 6 0 1 0 0-12 M12 10.5a1.5 1.5 0 1 0 0 3a1.5 1.5 0 1 0 0-3"],
  cloud: ["인터넷", "M7 18h10a4 4 0 0 0 .5-8 6 6 0 0 0-11.5 1.5A3.5 3.5 0 0 0 7 18z"],
  other: ["기타", "M12 4a8 8 0 1 0 0 16a8 8 0 1 0 0-16"],
};
const TP_TIER = { cloud: 0, router: 1, firewall: 1, switch: 2, siem: 3, server: 3, ids: 3, pc: 4, attacker: 4, other: 4 };
const TP_SEV = { critical: "#ff5b5b", high: "#ff9f43", medium: "#fcd34d", low: "#8592a3", info: "#4f5b6b" };
const NS = "http://www.w3.org/2000/svg";
const TP = { el: null, layout: null, saved: "", status: {}, disc: [], sel: null, view: { x: 0, y: 0, k: 1 }, editable: false, wire: null, timer: null };
const tpId = p => p + Math.random().toString(36).slice(2, 9);
const tpDirty = () => JSON.stringify(TP.layout) !== TP.saved;
addEventListener("beforeunload", e => { if (TP.el?.isConnected && TP.editable && tpDirty()) { e.preventDefault(); e.returnValue = ""; } });

async function renderTopology(el, live) {
  TP.el = el;
  const r = await api("/api/topology");
  TP.layout = r.layout; TP.saved = JSON.stringify(r.layout); TP.status = r.status || {}; TP.editable = r.can_edit; TP.sel = null; TP.ver = r.version;
  el.innerHTML = `<div class="meta-line"><span>기기 <b class="tp-nn">0</b> · 연결 <b class="tp-ln">0</b></span><span>배치 <b>v${r.version ?? "-"}</b></span>
      <span>상태 갱신 <b class="tp-upd">${fmtT(Date.now() / 1000)}</b></span>${TP.editable ? "" : `<span class="c-high">보기 전용 — 배치 변경은 관리자</span>`}</div>
    <p class="hint">${TP.editable ? `왼쪽 <b>기기 종류</b>나 <b>감지된 기기</b>를 캔버스로 끌어다 놓으세요. 기기 오른쪽 <b>●</b>을 끌어 다른 기기에 놓으면 <b>와이어</b>가 이어집니다.
      빈 곳 드래그 = 이동, 휠 = 확대, Delete = 선택 삭제.` : ""} 테두리 색 = 그 IP 의 열린 경보 최고 심각도, ⊘ = 차단됨, 흐르는 와이어 = 경보가 있는 기기와 이어진 경로.</p>
    <div class="tp-wrap">
      ${TP.editable ? `<aside class="tp-side"><h5>기기 종류</h5><div class="tp-pal">${Object.entries(TP_TYPES).map(([k, [l, d]]) =>
        `<div class="tp-pi" draggable="true" data-type="${k}" title="끌어다 놓기"><svg viewBox="0 0 24 24"><path d="${d}"/></svg><span>${l}</span></div>`).join("")}</div>
        <h5 style="margin-top:14px">감지된 기기 <button class="btn tp-scan" data-t="scan">감지</button></h5>
        <input class="tp-q" placeholder="IP 검색"><div class="tp-disc"><div class="faint">‘감지’를 누르면 서버가 아는 기기를 찾습니다</div></div></aside>` : ""}
      <div class="tp-main"><div class="tp-tools">
          ${TP.editable ? `<button class="btn" data-t="auto">자동 배치</button>` : ""}<button class="btn" data-t="fit">화면 맞춤</button>
          <span class="grow"></span><span class="tp-state"></span>
          ${TP.editable ? `<button class="btn" data-t="revert">되돌리기</button><button class="btn primary" data-t="save">저장</button>` : ""}</div>
        <div class="tp-canvas"><svg class="tp-svg" tabindex="0" aria-label="네트워크 토폴로지"><defs>
            <pattern id="tpgrid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="var(--line)" stroke-width=".6"/></pattern></defs>
            <rect class="tp-bg" width="100%" height="100%" fill="url(#tpgrid)"/><g class="tp-world"><g class="tp-links"></g><g class="tp-nodes"></g><path class="tp-temp"/></g></svg>
          <div class="tp-empty">${TP.editable ? "아직 배치된 기기가 없습니다 — 왼쪽에서 끌어다 놓거나 ‘감지’ 후 ‘감지된 기기 모두 놓기’" : "아직 배치된 토폴로지가 없습니다"}</div></div></div>
      <aside class="tp-insp"></aside></div>`;
  tpBind(); tpDraw(true); tpInsp();
  if (TP.editable) tpScan(true);
  if (TP.layout.nodes.length) setTimeout(tpFit, 0);
  clearInterval(TP.timer);
  TP.timer = setInterval(async () => {                               // 상태만 주기적으로 (배치는 그대로)
    if (!el.isConnected) return clearInterval(TP.timer);
    try { const ips = TP.layout.nodes.map(n => n.ip).filter(Boolean).slice(0, 400).join(",");
      TP.status = (await api(`/api/topology?ips=${encodeURIComponent(ips)}`)).status || {}; $(".tp-upd", el).textContent = fmtT(Date.now() / 1000); tpDraw(); tpInsp(); } catch (e) { /* 다음에 */ }
  }, 10000);
}

// ---------------------------------------------------------------- 그리기
function tpNode(id) { return TP.layout.nodes.find(n => n.id === id); }
function tpHot(n) { const s = n && n.ip && TP.status[n.ip]; return s && (s.severity === "critical" || s.severity === "high"); }
function tpDraw(anim) {
  const el = TP.el, gl = $(".tp-links", el), gn = $(".tp-nodes", el), L = TP.layout;
  $(".tp-nn", el).textContent = L.nodes.length; $(".tp-ln", el).textContent = L.links.length;
  $(".tp-empty", el).style.display = L.nodes.length ? "none" : "";
  gl.innerHTML = L.links.map(l => { const a = tpNode(l.from), b = tpNode(l.to); if (!a || !b) return "";
    const hot = tpHot(a) || tpHot(b), s = hot ? (TP.status[(tpHot(a) ? a : b).ip] || {}).severity : null;
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    return `<g class="tp-link ${TP.sel?.link === l.id ? "sel" : ""} ${hot ? "hot" : ""}" data-l="${esc(l.id)}">
      <line class="hit" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>
      <line class="wire" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" ${s ? `style="stroke:${TP_SEV[s]}"` : ""}/>
      ${l.label ? `<text class="tp-ll" x="${mx}" y="${my - 6}">${esc(l.label)}</text>` : ""}</g>`; }).join("");
  gn.innerHTML = L.nodes.map(n => { const st = (n.ip && TP.status[n.ip]) || {}, [lab, d] = TP_TYPES[n.type] || TP_TYPES.other;
    const ring = st.severity ? TP_SEV[st.severity] : null;
    return `<g class="tp-node t-${n.type} ${TP.sel?.node === n.id ? "sel" : ""} ${tpHot(n) ? "hot" : ""}" data-n="${esc(n.id)}" transform="translate(${n.x},${n.y})">
      ${ring ? `<rect class="pulse" x="-34" y="-34" width="68" height="68" rx="18" style="stroke:${ring}"/>` : ""}
      <rect class="tile" x="-28" y="-28" width="56" height="56" rx="14" ${ring ? `style="stroke:${ring}"` : ""}/>
      <svg x="-14" y="-14" width="28" height="28" viewBox="0 0 24 24"><path class="ico" d="${d}"/></svg>
      <text class="lab" y="46">${esc(n.label || lab)}</text>${n.ip ? `<text class="ip" y="61">${esc(n.ip)}</text>` : ""}
      ${st.open_alerts ? `<g class="badge" transform="translate(26,-26)"><circle r="10" style="fill:${ring || "var(--high)"}"/><text y="4">${st.open_alerts > 99 ? "99+" : st.open_alerts}</text></g>` : ""}
      ${st.blocked ? `<g class="blk" transform="translate(-26,-26)"><circle r="10"/><text y="4">⊘</text></g>` : ""}
      ${TP.editable ? `<circle class="port" cx="34" cy="0" r="6"><title>끌어서 와이어 연결</title></circle>` : ""}</g>`; }).join("");
  tpApplyView();
  const st = $(".tp-state", el); if (st) st.innerHTML = TP.editable ? (tpDirty() ? `<span class="c-medium">● 저장 안 됨</span>` : `<span class="faint">저장됨</span>`) : "";
  if (anim && A) anime({ targets: $$(".tp-node", gn), opacity: [0, 1], scale: [.6, 1], delay: anime.stagger(30), duration: 500, easing: "spring(1, 120, 12, 0)" });
}
function tpApplyView() { const v = TP.view; $(".tp-world", TP.el).setAttribute("transform", `translate(${v.x},${v.y}) scale(${v.k})`); }
function tpToWorld(e) { const r = $(".tp-svg", TP.el).getBoundingClientRect(), v = TP.view; return { x: (e.clientX - r.left - v.x) / v.k, y: (e.clientY - r.top - v.y) / v.k }; }
function tpFit() {
  const L = TP.layout.nodes, svg = $(".tp-svg", TP.el); if (!L.length || !svg) return;
  const r = svg.getBoundingClientRect(), xs = L.map(n => n.x), ys = L.map(n => n.y);
  const x0 = Math.min(...xs) - 70, x1 = Math.max(...xs) + 70, y0 = Math.min(...ys) - 60, y1 = Math.max(...ys) + 80;
  const k = Math.max(.35, Math.min(1.6, Math.min(r.width / (x1 - x0), r.height / (y1 - y0))));
  const to = { k, x: (r.width - (x1 - x0) * k) / 2 - x0 * k, y: (r.height - (y1 - y0) * k) / 2 - y0 * k };
  if (M) { const from = { ...TP.view }; M.animate(0, 1, { duration: .45, ease: [.2, .8, .2, 1], onUpdate: t => { for (const key of ["x", "y", "k"]) TP.view[key] = from[key] + (to[key] - from[key]) * t; tpApplyView(); } }); }
  else { Object.assign(TP.view, to); tpApplyView(); }
}

// ---------------------------------------------------------------- 편집
function tpChange(redraw = true) { if (redraw) tpDraw(); tpInsp(); }
function tpAddNode(n) {
  if (n.ip) { const ex = TP.layout.nodes.find(x => x.ip === n.ip); if (ex) { TP.sel = { node: ex.id }; tpChange(); tpFlash(ex.id); toast(`${esc(n.ip)} 는 이미 배치돼 있습니다`); return ex; } }
  const node = { id: tpId("n"), type: n.type || "other", label: n.label || "", x: Math.round(n.x / 12) * 12, y: Math.round(n.y / 12) * 12, ...(n.ip ? { ip: n.ip } : {}) };
  TP.layout.nodes.push(node); TP.sel = { node: node.id }; tpChange(); tpFlash(node.id);
  return node;
}
function tpFlash(id) { const g = $(`.tp-node[data-n="${CSS.escape(id)}"]`, TP.el); if (g && A) anime({ targets: g.querySelector(".tile"), strokeWidth: [6, 1.5], duration: 700, easing: "easeOutQuad" }); }
function tpLink(a, b) {
  if (a === b) return;
  if (TP.layout.links.some(l => (l.from === a && l.to === b) || (l.from === b && l.to === a))) { toast("이미 이어져 있습니다"); return; }
  const l = { id: tpId("l"), from: a, to: b }; TP.layout.links.push(l); TP.sel = { link: l.id }; tpChange();
  const w = $(`.tp-link[data-l="${CSS.escape(l.id)}"] .wire`, TP.el);
  if (w && A) { const len = Math.hypot(w.x2.baseVal.value - w.x1.baseVal.value, w.y2.baseVal.value - w.y1.baseVal.value);
    anime({ targets: w, strokeDashoffset: [len, 0], strokeDasharray: [len, len], duration: 450, easing: "easeOutCubic", complete: () => { w.style.strokeDasharray = ""; } }); }
}
function tpDelete() {
  const s = TP.sel; if (!s || !TP.editable) return;
  if (s.node) { TP.layout.links = TP.layout.links.filter(l => l.from !== s.node && l.to !== s.node); TP.layout.nodes = TP.layout.nodes.filter(n => n.id !== s.node); }
  if (s.link) TP.layout.links = TP.layout.links.filter(l => l.id !== s.link);
  TP.sel = null; tpChange();
}
function tpAuto() {
  const tiers = {}; TP.layout.nodes.forEach(n => (tiers[TP_TIER[n.type] ?? 4] ||= []).push(n));
  Object.entries(tiers).forEach(([t, ns]) => { ns.sort((a, b) => (a.ip || a.label || "").localeCompare(b.ip || b.label || ""));
    ns.forEach((n, i) => { n.x = Math.round((i - (ns.length - 1) / 2) * 150); n.y = +t * 140; }); });
  if (A) { tpDraw(); anime({ targets: $$(".tp-node", TP.el), opacity: [.3, 1], duration: 400, easing: "easeOutQuad" }); } else tpDraw();
  tpInsp(); setTimeout(tpFit, 0);
}
async function tpSave() {
  const btn = $('[data-t="save"]', TP.el); btn.disabled = true;
  try { const r = await api("/api/config/topology?comment=" + encodeURIComponent("토폴로지 화면에서 저장"), { method: "PUT", body: TP.layout });
    TP.saved = JSON.stringify(TP.layout); toast(`토폴로지 저장 → v${r.version}`); tpDraw(); tpInsp(); }
  catch (e) { toast(`<span class="err">저장 실패 — ${esc(errMsg(e))}</span>`, "critical"); }
  finally { btn.disabled = false; }
}

// ---------------------------------------------------------------- 감지
async function tpScan(quiet) {
  const box = $(".tp-disc", TP.el); if (!box) return;
  if (!quiet) box.innerHTML = `<div class="dim">감지 중…</div>`;
  try { TP.disc = (await api("/api/topology/discover")).items; tpDisc(); }
  catch (e) { box.innerHTML = `<div class="c-high">${esc(errMsg(e))}</div>`; }
}
const TP_SEEN = { self: "이 서버", gateway: "게이트웨이", neighbor: "같은 망", ids: "IDS", logs: "로그" };
function tpDisc() {
  const box = $(".tp-disc", TP.el), q = ($(".tp-q", TP.el)?.value || "").trim(), placed = new Set(TP.layout.nodes.map(n => n.ip));
  const items = TP.disc.filter(c => !q || c.ip.includes(q) || (c.label || "").includes(q));
  box.innerHTML = (items.length ? `<button class="btn tp-all" data-t="placeall">감지된 기기 모두 놓기 (${items.filter(c => !placed.has(c.ip)).length})</button>` : "") +
    (items.slice(0, 120).map(c => { const s = c.status || {}, [lab, d] = TP_TYPES[c.suggest] || TP_TYPES.other;
      return `<div class="tp-di ${placed.has(c.ip) ? "placed" : ""}" draggable="${!placed.has(c.ip)}" data-ip="${esc(c.ip)}" title="${esc(c.seen_by.map(k => TP_SEEN[k]).join(" · "))}">
        <svg viewBox="0 0 24 24"><path d="${d}"/></svg><div><b>${esc(c.ip)}</b>${c.label ? ` <span class="dim">${esc(c.label)}</span>` : ""}
        <small>${esc(c.seen_by.map(k => TP_SEEN[k]).join(" · "))}${c.events ? ` · 이벤트 ${fmt(c.events)}` : ""}${c.mac ? ` · ${esc(c.mac)}` : ""}</small></div>
        ${s.severity ? `<i class="dot" style="background:${TP_SEV[s.severity]}"></i>` : ""}${s.blocked ? `<i class="blkm">⊘</i>` : ""}${placed.has(c.ip) ? `<span class="faint">배치됨</span>` : ""}</div>`; }).join("")
      || `<div class="faint">감지된 기기가 없습니다</div>`);
  $$(".tp-di[draggable=true]", box).forEach(d => d.addEventListener("dragstart", e => { e.dataTransfer.setData("application/x-rktopo", JSON.stringify({ ip: d.dataset.ip })); e.dataTransfer.effectAllowed = "copy"; }));
  $$(".tp-di:not(.placed)", box).forEach(d => d.addEventListener("dblclick", () => { const c = TP.disc.find(x => x.ip === d.dataset.ip); tpPlaceDisc([c]); }));
  const all = $('[data-t="placeall"]', box); if (all) all.onclick = () => tpPlaceDisc(items.filter(c => !placed.has(c.ip)).slice(0, 60));
}
function tpPlaceDisc(list) {
  const base = TP.layout.nodes.length;
  list.forEach((c, i) => tpAddNode({ ip: c.ip, label: c.label || "", type: c.suggest, x: (base + i) % 6 * 150 - 375, y: Math.floor((base + i) / 6) * 140 }));
  if (list.length > 1) tpAuto(); tpDisc();
}

// ---------------------------------------------------------------- 오른쪽: 선택한 기기·와이어
function tpInsp() {
  const box = $(".tp-insp", TP.el), s = TP.sel, dis = TP.editable ? "" : "disabled";
  if (!s) { box.innerHTML = `<div class="faint" style="font:12.5px var(--ko)">기기나 와이어를 누르면 여기서 설정합니다.</div>
      <div class="tp-legend"><b>상태 표시</b>${Object.entries(TP_SEV).slice(0, 3).map(([k, c]) => `<span><i style="background:${c}"></i>${SEVK[k][1]} 경보</span>`).join("")}<span><i class="b">⊘</i>차단됨</span></div>`; return; }
  if (s.link) { const l = TP.layout.links.find(x => x.id === s.link); if (!l) { TP.sel = null; return tpInsp(); }
    const a = tpNode(l.from), b = tpNode(l.to);
    box.innerHTML = `<div class="tp-ih"><b>와이어</b><span class="dim">${esc(a?.label || a?.ip || "?")} ↔ ${esc(b?.label || b?.ip || "?")}</span></div>
      <label>이름 <span class="faint">(예: Gi0/1, 업링크)</span><input data-l="label" value="${esc(l.label || "")}" ${dis}></label>
      ${TP.editable ? `<button class="btn danger" data-t="del">와이어 삭제</button>` : ""}`;
  } else { const n = tpNode(s.node); if (!n) { TP.sel = null; return tpInsp(); }
    const st = (n.ip && TP.status[n.ip]) || {}, links = TP.layout.links.filter(l => l.from === n.id || l.to === n.id).length;
    box.innerHTML = `<div class="tp-ih"><svg viewBox="0 0 24 24"><path d="${(TP_TYPES[n.type] || TP_TYPES.other)[1]}"/></svg><b>${esc(n.label || TP_TYPES[n.type]?.[0] || "기기")}</b></div>
      <label>이름<input data-f="label" value="${esc(n.label || "")}" ${dis}></label>
      <label>종류<select data-f="type" ${dis}>${Object.entries(TP_TYPES).map(([k, [l]]) => `<option value="${k}" ${k === n.type ? "selected" : ""}>${l}</option>`).join("")}</select></label>
      <label>IP <span class="faint">(상태 연동)</span><input data-f="ip" value="${esc(n.ip || "")}" ${dis}></label>
      <label>메모<input data-f="note" value="${esc(n.note || "")}" ${dis}></label>
      <div class="tp-st">${n.ip ? `${st.severity ? `열린 경보 <b>${st.open_alerts}</b>건 · 최고 ${sev(st.severity)}<br><span class="dim">${(st.titles || []).map(esc).join(" · ")}</span>` : `<span class="acc">열린 경보 없음</span>`}
        ${st.blocked ? `<br><b class="c-critical">⊘ 방화벽에서 차단됨</b>` : ""}${st.events_24h ? `<br><span class="dim">최근 24시간 이벤트 ${fmt(st.events_24h)}건 · 마지막 ${fmtT(st.last_seen)}</span>` : ""}` : `<span class="faint">IP 를 넣으면 경보·차단 상태가 표시됩니다</span>`}</div>
      ${tpTermBtn(n)}
      <div class="st-row" style="flex-wrap:wrap">${n.ip ? `<button class="btn" data-cmd="search ip=${esc(n.ip)}">이벤트 검색</button>` : ""}${st.incident_id ? `<button class="btn" data-cmd="incident ${st.incident_id}">사건 #${st.incident_id}</button>` : ""}
        ${TP.editable ? `<button class="btn danger" data-t="del">기기 삭제${links ? ` (와이어 ${links}개 포함)` : ""}</button>` : ""}</div>`;
  }
  const tb = $('[data-t="term"]', box); if (tb) tb.onclick = () => openTerminal({ ip: tb.dataset.ip, label: tb.dataset.label });
  if (!TP.editable) return;
  $$("[data-f], [data-l]", box).forEach(i => i.addEventListener(i.tagName === "SELECT" ? "change" : "input", () => {
    if (i.dataset.l) { const l = TP.layout.links.find(x => x.id === TP.sel.link); i.value ? l.label = i.value : delete l.label; }
    else { const n = tpNode(TP.sel.node), k = i.dataset.f, v = i.value.trim(); v ? n[k] = v : (k === "type" ? null : delete n[k]); if (k === "type") n.type = v; }
    tpDraw();
  }));
  const del = $('[data-t="del"]', box); if (del) del.onclick = tpDelete;
}

// 웹 터미널 버튼: 저장된 배치에서 SIEM 과 와이어로 이어진 기기만 (최종 판단은 백엔드)
function tpTermBtn(n) {
  if (!n.ip || n.type === "siem" || !can("terminal:use")) return "";
  const ok = twWired(JSON.parse(TP.saved), n.ip), unsaved = !ok && twWired(TP.layout, n.ip);
  return `<div class="tp-term"><button class="btn ${ok ? "primary" : ""}" data-t="term" data-ip="${esc(n.ip)}" data-label="${esc(n.label || "")}" ${ok ? "" : "disabled"}>▸_ 터미널 (SSH)</button>
    <span class="faint">${ok ? "SIEM 과 와이어로 연결됨" : unsaved ? "와이어 연결을 저장해야 접속할 수 있습니다" : "SIEM 과 와이어로 연결해야 접속할 수 있습니다"}</span></div>`;
}

// ---------------------------------------------------------------- 마우스·키보드
function tpBind() {
  const el = TP.el, svg = $(".tp-svg", el);
  $$("[data-t]", el).forEach(b => b.onclick = () => ({ save: tpSave, auto: tpAuto, fit: tpFit, scan: () => tpScan(false),
    revert: () => { if (tpDirty() && !confirm("저장하지 않은 변경을 버릴까요?")) return; TP.layout = JSON.parse(TP.saved); TP.sel = null; tpChange(); } })[b.dataset.t]?.());
  $(".tp-q", el)?.addEventListener("input", tpDisc);
  // 팔레트·감지 목록 → 캔버스
  $$(".tp-pi", el).forEach(p => p.addEventListener("dragstart", e => { e.dataTransfer.setData("application/x-rktopo", JSON.stringify({ type: p.dataset.type })); e.dataTransfer.effectAllowed = "copy"; }));
  svg.addEventListener("dragover", e => { if (TP.editable && e.dataTransfer.types.includes("application/x-rktopo")) { e.preventDefault(); svg.classList.add("over"); } });
  svg.addEventListener("dragleave", () => svg.classList.remove("over"));
  svg.addEventListener("drop", e => { svg.classList.remove("over"); const raw = e.dataTransfer.getData("application/x-rktopo"); if (!raw) return; e.preventDefault();
    const d = JSON.parse(raw), w = tpToWorld(e);
    if (d.ip) { const c = TP.disc.find(x => x.ip === d.ip) || { ip: d.ip }; tpAddNode({ ip: c.ip, label: c.label || "", type: c.suggest || "pc", x: w.x, y: w.y }); tpDisc(); }
    else tpAddNode({ type: d.type, x: w.x, y: w.y }); });
  // 끌기: 기기 이동 · 와이어 · 화면 이동
  let drag = null;
  svg.addEventListener("pointerdown", e => {
    svg.focus(); hideTip();
    const port = e.target.closest(".port"), node = e.target.closest(".tp-node"), link = e.target.closest(".tp-link"), w = tpToWorld(e);
    if (port && TP.editable) { drag = { kind: "wire", from: node.dataset.n }; svg.setPointerCapture(e.pointerId); e.stopPropagation(); return; }
    if (node) { TP.sel = { node: node.dataset.n }; const n = tpNode(node.dataset.n); drag = { kind: "node", n, dx: w.x - n.x, dy: w.y - n.y, moved: false };
      svg.setPointerCapture(e.pointerId); tpDraw(); tpInsp(); return; }
    if (link) { TP.sel = { link: link.dataset.l }; tpDraw(); tpInsp(); return; }
    TP.sel = null; tpDraw(); tpInsp();
    drag = { kind: "pan", x: e.clientX, y: e.clientY, vx: TP.view.x, vy: TP.view.y }; svg.setPointerCapture(e.pointerId);
  });
  svg.addEventListener("pointermove", e => {
    if (!drag) { const n = e.target.closest(".tp-node"); if (n) { const node = tpNode(n.dataset.n), st = node?.ip && TP.status[node.ip];
        showTip(e, `<b>${esc(node.label || TP_TYPES[node.type]?.[0])}</b>${node.ip ? ` ${esc(node.ip)}` : ""}${st?.severity ? `<br>${sev(st.severity)} 열린 경보 ${st.open_alerts}건` : ""}${st?.blocked ? "<br>⊘ 차단됨" : ""}`); } else hideTip(); return; }
    const w = tpToWorld(e);
    if (drag.kind === "pan") { TP.view.x = drag.vx + e.clientX - drag.x; TP.view.y = drag.vy + e.clientY - drag.y; tpApplyView(); }
    if (drag.kind === "node" && TP.editable) { drag.n.x = Math.round((w.x - drag.dx) / 12) * 12; drag.n.y = Math.round((w.y - drag.dy) / 12) * 12; drag.moved = true; tpDraw(); }
    if (drag.kind === "wire") { const a = tpNode(drag.from), t = $(".tp-temp", el); t.setAttribute("d", `M${a.x + 34},${a.y} L${w.x},${w.y}`);
      $$(".tp-node", el).forEach(g => g.classList.toggle("target", g.dataset.n !== drag.from && g.contains(document.elementFromPoint(e.clientX, e.clientY)))); }
  });
  const end = e => {
    if (drag?.kind === "wire") { $(".tp-temp", el).setAttribute("d", ""); const tgt = document.elementFromPoint(e.clientX, e.clientY)?.closest(".tp-node");
      $$(".tp-node.target", el).forEach(g => g.classList.remove("target")); if (tgt) tpLink(drag.from, tgt.dataset.n); }
    if (drag?.kind === "node" && drag.moved) tpInsp();
    drag = null;
  };
  svg.addEventListener("pointerup", end); svg.addEventListener("pointercancel", end);
  svg.addEventListener("wheel", e => { e.preventDefault(); const r = svg.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top, v = TP.view;
    const k = Math.max(.3, Math.min(2.5, v.k * (e.deltaY < 0 ? 1.12 : 1 / 1.12))); v.x = mx - (mx - v.x) * k / v.k; v.y = my - (my - v.y) * k / v.k; v.k = k; tpApplyView(); }, { passive: false });
  svg.addEventListener("keydown", e => { if ((e.key === "Delete" || e.key === "Backspace") && TP.sel) { e.preventDefault(); tpDelete(); } if (e.key === "Escape") { TP.sel = null; tpDraw(); tpInsp(); } });
  svg.addEventListener("dblclick", e => { if (!e.target.closest(".tp-node")) tpFit(); });
}
