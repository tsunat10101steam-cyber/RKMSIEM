/* RKMSIEM 자동화 편집기 — 플레이북(SOAR)을 끌어다 놓아 만든다.
   편집 결과는 config/playbooks/*.yaml 과 같은 형식의 플레이북이고, 검증·저장·버전·롤백·실행은 모두 백엔드 API 가 한다.
   app.js 보다 먼저 읽히며, 여기의 함수는 app.js 의 공통 도구($, api, esc, toast …)를 호출 시점에 사용한다. */
"use strict";

// 액션별 화면 정보 (등록돼 있지만 여기 없는 플러그인 액션은 '기타'로 표시하고 JSON 으로 편집)
const AU_META = {
  ip_reputation: { ko: "IP 평판 조회", ic: "⌕", group: "lookup", inputs: [{ k: "ip", label: "IP", def: "{{alert.group.source.ip}}" }],
    outputs: [["verdict", "판정 (malicious·suspicious·clean·unknown)"], ["confidence", "신뢰도"], ["source", "출처"], ["abuseipdb.score", "AbuseIPDB 점수"],
      ["abuseipdb.total_reports", "AbuseIPDB 신고 수"], ["abuseipdb.country", "국가"], ["abuseipdb.is_tor", "Tor 여부"]] },
  asset_lookup: { ko: "계정 · 자산 조회", ic: "◎", group: "lookup", inputs: [{ k: "account", label: "계정", def: "{{alert.group.user.name}}" }],
    outputs: [["found", "존재 여부"], ["privileged", "권한 계정 여부"], ["owner", "소유자"], ["criticality", "중요도"], ["disabled", "잠김 여부"]] },
  notify: { ko: "알림 보내기", ic: "✉", group: "record", inputs: [{ k: "channel", label: "채널", def: "soc" },
    { k: "message", label: "메시지", type: "area", def: "[{{alert.severity}}] {{alert.title}} — {{alert.group.source.ip}} (사건 #{{incident.id}})" },
    { k: "webhook_url", label: "웹훅 URL (선택 · 승인 정책의 허용 목록에 있는 https 만)", opt: true }], outputs: [["delivered", "전달 방식"]] },
  record_result: { ko: "결과 기록", ic: "✎", group: "record", inputs: [{ k: "summary", label: "사건 타임라인에 남길 요약", type: "area", def: "자동화 완료" }],
    outputs: [["recorded", "기록 여부"]] },
  send_email: { ko: "메일 보내기", ic: "✉", group: "record",
    inputs: [{ k: "to", label: "받는 사람 (쉼표 · settings.yaml mail.allowed_recipients 안에서만)", def: "" },
      { k: "subject", label: "제목", def: "[{{alert.severity}}] {{alert.title}} — 사건 #{{incident.id}}" },
      { k: "body", label: "본문", type: "area", def: "공격 IP: {{alert.group.source.ip}}\n계정: {{alert.group.user.name}}\n경보: {{alert.title}}\n사건: #{{incident.id}}" },
      { k: "attach_report", label: "사건 보고서 PDF 첨부", type: "select", options: ["false", "true"], def: "true" }],
    outputs: [["status", "발송 상태"], ["to", "받는 사람"]] },
  set_incident_severity: { ko: "사건 심각도 변경", ic: "▲", group: "record",
    inputs: [{ k: "severity", label: "심각도", type: "select", options: ["info", "low", "medium", "high", "critical"], def: "high" }, { k: "reason", label: "사유", def: "", opt: true }],
    outputs: [["severity", "바뀐 심각도"]] },
  block_ip: { ko: "IP 차단", ic: "⊘", group: "respond", comp: "unblock_ip",
    inputs: [{ k: "ip", label: "IP", def: "{{alert.group.source.ip}}" }, { k: "duration_sec", label: "차단 시간(초) · 비우면 무기한", type: "num", def: 3600, opt: true },
      { k: "reason", label: "사유", def: "자동화 차단 — 사건 #{{incident.id}}" }],
    outputs: [["blocked", "차단 여부"], ["already_blocked", "이미 차단돼 있었음"], ["backend", "적용 위치"]] },
  disable_account: { ko: "계정 잠금", ic: "⊠", group: "respond", comp: "enable_account",
    inputs: [{ k: "account", label: "계정", def: "{{alert.group.user.name}}" }, { k: "reason", label: "사유", def: "자동화 잠금 — 사건 #{{incident.id}}" }],
    outputs: [["disabled", "잠김 여부"], ["backend", "적용 위치"]] },
  unblock_ip: { ko: "IP 차단 해제", ic: "↺", group: "undo", inputs: [{ k: "ip", label: "IP", def: "{{alert.group.source.ip}}" }], outputs: [["unblocked", "해제 여부"]] },
  enable_account: { ko: "계정 잠금 해제", ic: "↻", group: "undo", inputs: [{ k: "account", label: "계정", def: "{{alert.group.user.name}}" }], outputs: [["disabled", "잠김 여부"]] },
};
const AU_GROUPS = [["lookup", "조회 · 보강"], ["record", "기록 · 알림"], ["respond", "대응 조치 (승인 필요)"], ["undo", "되돌리기"], ["other", "기타 (플러그인)"]];
const AU_VARS = [["alert.group.source.ip", "공격 IP"], ["alert.group.user.name", "계정"], ["alert.title", "경보 제목"], ["alert.severity", "경보 심각도"],
  ["alert.level_id", "경보 단계"], ["alert.rule_id", "탐지 규칙"], ["alert.risk_score", "위험 점수"], ["incident.id", "사건 번호"], ["incident.title", "사건 제목"],
  ["incident.severity", "사건 심각도"]];
const AU_OPS = [["eq", "="], ["ne", "≠"], ["in", "중 하나"], ["not_in", "중 아님"], ["contains", "포함"], ["regex", "정규식"], ["gt", ">"], ["gte", "≥"], ["lt", "<"], ["lte", "≤"],
  ["exists", "값 있음"], ["not_exists", "값 없음"], ["in_list", "목록에 있음"], ["not_in_list", "목록에 없음"]];
const AU_TRIG = { alert: ["경보가 생길 때마다", "탐지 규칙이 경보를 만들거나 단계를 올릴 때"], incident: ["새 사건이 만들어질 때", "사건당 처음 한 번"],
  manual: ["사람이 직접 실행", "사건 화면에서 분석가가 실행"] };
const AU_FALLBACK_LISTS = ["internal_networks", "allowlist", "protected_accounts", "privileged_users", "never_block"];
const AU_ID = /^[a-z][a-z0-9_]*$/;

const AU = { el: null, list: [], actions: {}, mode: null, lists: [], levels: [], cur: null, isNew: false, sel: "trigger", dirty: false, ro: true, drag: null, lastFocus: null };
const auClone = o => JSON.parse(JSON.stringify(o));
const auMeta = a => AU_META[a] || { ko: a, ic: "◇", group: "other", inputs: [], outputs: [] };
const auDestr = a => !!AU.actions[a]?.destructive;
addEventListener("beforeunload", e => { if (AU.dirty && AU.el?.isConnected) { e.preventDefault(); e.returnValue = ""; } });

// ================================================================ 진입
async function renderAutomation(el, live, arg) {
  AU.el = el; AU.ro = !can("playbooks:write");
  const [pb, lists, rules] = await Promise.all([api("/api/playbooks"),
    can("config:read") ? api("/api/config/lists").catch(() => null) : null, can("rules:read") ? api("/api/rules").catch(() => null) : null]);
  AU.list = pb.items; AU.actions = pb.actions; AU.mode = pb.mode;
  AU.lists = lists ? Object.keys(lists.content || {}) : AU_FALLBACK_LISTS;
  AU.levels = rules ? [...new Set(rules.items.flatMap(r => r.levels.map(l => l.id)))] : [];
  el.innerHTML = `<div class="meta-line"><span>실행 모드 <b class="${AU.mode === "live" ? "c-high" : "acc"}">${esc(AU.mode)}</b>
      ${AU.mode === "live" ? " — 승인된 차단·잠금은 서버에 실제로 반영됩니다" : " — 대응 조치는 기록만 하고 실제로 바꾸지 않습니다"}</span>
      <span>저장소 <b>config_versions</b> (버전 · 롤백 · 감사 로그)</span>${AU.ro ? `<span class="c-high">읽기 전용 — playbooks:write 권한 필요</span>` : ""}</div>
    <p class="hint">왼쪽 <b>도구</b>를 가운데 흐름에 <b>끌어다 놓으면</b> 단계가 추가됩니다 (클릭하면 선택한 단계 뒤에 추가). 단계는 끌어서 순서를 바꾸고, 클릭하면 오른쪽에서 설정합니다.
      <b>변수</b>는 입력칸에 끌어다 놓거나, 입력칸을 누른 뒤 클릭하면 들어갑니다.</p>
    <div class="au-bar"><div class="au-pbs"></div>${AU.ro ? "" : `<button class="btn" data-a="new">＋ 새 플레이북</button>`}</div>
    <div class="au-tool"><span class="au-name"></span><span class="au-dirty"></span><span class="grow"></span>
      <button class="btn" data-a="check">검증 · 미리보기</button><button class="btn" data-a="yaml">YAML</button><button class="btn" data-a="hist">이력</button>
      ${can("playbooks:run") ? `<button class="btn" data-a="run">사건에 실행</button>` : ""}
      ${AU.ro ? "" : `<button class="btn" data-a="dup">복제</button><input class="au-why" placeholder="변경 사유 (감사 로그)"><button class="btn primary" data-a="save">저장</button>`}</div>
    <div class="au-grid"><aside class="au-pal"></aside>
      <div class="au-canvas"><div class="au-lint"></div><div class="au-flow"></div><div class="au-result"></div></div>
      <aside class="au-insp"></aside></div><datalist id="au-fields"></datalist>`;
  $$(".au-tool [data-a], .au-bar [data-a]", el).forEach(b => b.onclick = () => auCmd(b.dataset.a));
  auBindFlow(); auBindInsp();
  const want = (arg && AU.list.find(p => p.id === arg.trim())) || (AU.cur && !AU.isNew && AU.list.find(p => p.id === AU.cur.id)) || AU.list[0];
  if (AU.cur && AU.isNew && AU.dirty) auShow(AU.cur, true, true);       // 저장 안 한 새 플레이북은 유지
  else if (want) auShow(want, false); else auShow(auBlank(), true);
  if (A && !live) {
    anime({ targets: $$(".au-tool-item, .au-var", el), opacity: [0, 1], translateX: [-14, 0], delay: anime.stagger(25), duration: 380, easing: "easeOutCubic" });
    if (M) M.animate($(".au-insp", el), { opacity: [0, 1], x: [30, 0] }, { type: "spring", stiffness: 200, damping: 22 });
  }
}

function auShow(pb, isNew, keep) {
  if (!keep) { AU.cur = auClone(pb); delete AU.cur._version; AU.dirty = !!isNew; }
  AU.isNew = !!isNew; AU.sel = "trigger";
  $(".au-result", AU.el).innerHTML = "";
  auChips(); auPalette(); auRender(true);
}
function auBlank() {
  let id = "new_playbook", n = 2;
  while (AU.list.some(p => p.id === id)) id = `new_playbook_${n++}`;
  return { id, name: "새 플레이북", description: "", enabled: false,
    trigger: { on: "alert", where: [{ field: "alert.severity", op: "in", value: ["critical", "high"] }] }, steps: [auNewStep("notify", [])] };
}
function auConfirmDiscard() { return !AU.dirty || confirm("저장하지 않은 변경이 있습니다. 버리고 계속할까요?"); }

// ================================================================ 상단: 플레이북 목록 · 도구 모음
function auChips() {
  const box = $(".au-pbs", AU.el);
  const items = AU.list.map(p => ({ id: p.id, name: p.name, on: p.trigger.on, en: p.enabled !== false, v: p._version }));
  if (AU.isNew) items.push({ id: AU.cur.id, name: AU.cur.name, on: AU.cur.trigger.on, en: AU.cur.enabled !== false, isNew: true });
  box.innerHTML = items.map(p => `<button class="au-pb ${p.id === AU.cur.id ? "on" : ""} ${p.en ? "" : "off"}" data-pb="${esc(p.id)}" title="${esc(p.id)}">
    <i></i>${esc(p.name)}<small>${p.isNew ? "새로 만듦" : `v${p.v} · ${esc(AU_TRIG[p.on][0])}`}</small></button>`).join("");
  $$("[data-pb]", box).forEach(b => b.onclick = () => {
    if (b.dataset.pb === AU.cur.id || !auConfirmDiscard()) return;
    const p = AU.list.find(x => x.id === b.dataset.pb); if (p) auShow(p, false);
  });
  $(".au-name", AU.el).innerHTML = `<b>${esc(AU.cur.name)}</b> <code>${esc(AU.cur.id)}</code>${AU.cur.enabled === false ? ` <span class="state cancelled">비활성</span>` : ` <span class="state succeeded">활성</span>`}`;
  auMarkDirty(AU.dirty);
}
function auMarkDirty(d) {
  AU.dirty = d;
  const t = $(".au-dirty", AU.el); if (t) t.innerHTML = d ? `<span class="c-medium">● 저장 안 됨</span>` : `<span class="faint">저장됨</span>`;
}
async function auCmd(a) {
  const res = $(".au-result", AU.el);
  try {
    if (a === "new") { if (!auConfirmDiscard()) return; auShow(auBlank(), true); return; }
    if (a === "dup") {
      const c = auClone(AU.cur); let id = `${c.id}_copy`, n = 2; while (AU.list.some(p => p.id === id)) id = `${c.id}_copy${n++}`;
      Object.assign(c, { id, name: `${c.name} (복사본)`, enabled: false }); auShow(c, true); toast("복사본을 만들었습니다 — 비활성 상태로 저장됩니다"); return;
    }
    if (a === "check") return auCheck(true);
    if (a === "save") return auSave();
    if (a === "yaml") {
      const v = await api("/api/playbooks/validate", { method: "POST", body: { playbook: auClean() } });
      res.innerHTML = v.ok ? `<div class="au-box"><div class="au-bh">YAML <span class="dim">· config/playbooks/${esc(AU.cur.id)}.yaml 과 같은 형식</span></div><pre class="conf au-yaml">${esc(v.yaml)}</pre></div>`
        : auErrs(v.errors);
      return;
    }
    if (a === "hist") {
      if (AU.isNew) { res.innerHTML = `<div class="au-box dim">아직 저장하지 않은 플레이북이라 이력이 없습니다.</div>`; return; }
      const d = await api(`/api/playbooks/${encodeURIComponent(AU.cur.id)}`);
      res.innerHTML = `<div class="au-box"><div class="au-bh">변경 이력 <span class="dim">· 롤백하면 그 내용이 새 버전으로 다시 활성화됩니다</span></div>
        <div class="tbl"><table><thead><tr><th>버전</th><th>시각</th><th>변경자</th><th>사유</th><th></th></tr></thead><tbody>${d.versions.map(v => `<tr>
          <td class="num">v${v.version} ${v.active ? `<span class="state succeeded">현재</span>` : ""}</td><td>${fmtT(v.created_at)}</td><td>${esc(v.created_by)}</td><td>${esc(v.comment || "")}</td>
          <td>${!v.active && !AU.ro ? `<button class="btn" data-rb="${v.version}">이 버전으로 롤백</button>` : ""}</td></tr>`).join("")}</tbody></table></div></div>`;
      $$("[data-rb]", res).forEach(b => b.onclick = async () => {
        if (!auConfirmDiscard()) return;
        try { const r = await api(`/api/playbooks/${encodeURIComponent(AU.cur.id)}/rollback`, { method: "POST", body: { version: +b.dataset.rb, reason: "자동화 편집기에서 롤백" } });
          toast(`v${b.dataset.rb} 내용으로 롤백 → v${r.version}`); AU.dirty = false; await auReload(AU.cur.id); }
        catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
      });
      return;
    }
    if (a === "run") {
      if (AU.isNew) { res.innerHTML = `<div class="au-box c-high">먼저 저장해야 실행할 수 있습니다.</div>`; return; }
      res.innerHTML = `<div class="au-box"><div class="au-bh">사건에 수동 실행 <span class="dim">· 저장된 v${AU.list.find(p => p.id === AU.cur.id)?._version} 이 실행됩니다${AU.dirty ? " (편집 중인 내용 아님)" : ""}</span></div>
        <div class="inline-form"><input class="au-inc" inputmode="numeric" placeholder="사건 번호"><button class="btn primary" data-go>실행</button></div>
        <div class="dim" style="font-size:12px;margin-top:6px">사건의 가장 심각한 경보가 변수(alert.*)로 들어갑니다. 대응 조치 단계는 승인 정책에 따라 승인 대기로 멈춥니다.</div></div>`;
      $("[data-go]", res).onclick = async () => {
        const id = +$(".au-inc", res).value; if (!id) { shake($(".au-inc", res), 5); return; }
        try { const r = await api(`/api/playbooks/${encodeURIComponent(AU.cur.id)}/run`, { method: "POST", body: { incident_id: id } });
          res.innerHTML = `<div class="au-box acc">실행 #${r.run_id} 을 만들었습니다 — <span class="link" data-cmd="run ${r.run_id}">실행 상세 보기</span></div>`; }
        catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
      };
    }
  } catch (e) { toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
}
async function auReload(selectId) {
  const pb = await api("/api/playbooks");
  AU.list = pb.items;
  const p = AU.list.find(x => x.id === selectId);
  if (p) auShow(p, false);
}

// 저장 형식으로 정리 (빈 조건·undefined 제거)
function auClean() {
  const pb = auClone(AU.cur);
  if (!pb.description) delete pb.description;
  if (!pb.trigger.where?.length) delete pb.trigger.where;
  if (pb.trigger.on === "manual") delete pb.trigger.once_per;
  pb.steps.forEach(s => { if (!s.when?.length) delete s.when; if (s.input && !Object.keys(s.input).length) delete s.input; });
  return pb;
}
const auErrs = errs => `<div class="au-box bad"><div class="au-bh c-critical">✘ 검증 실패 — 저장되지 않습니다</div><ul class="au-errs">${errs.map(e => `<li>${esc(e)}</li>`).join("")}</ul></div>`;

async function auCheck(show) {
  const res = $(".au-result", AU.el);
  const v = await api("/api/playbooks/validate", { method: "POST", body: { playbook: auClean() } });
  if (!v.ok) { res.innerHTML = auErrs(v.errors); shake(res.firstChild, 6); return false; }
  if (!show) return true;
  const pv = v.preview;
  res.innerHTML = `<div class="au-box ok"><div class="au-bh acc">✔ 검증 통과</div>${pv.trigger === "manual" ? `<div class="dim">수동 실행 플레이북이라 자동 실행 미리보기는 없습니다.</div>` : `
    <div class="au-pv"><b class="au-big" data-count="${pv.matched}">0</b><div>최근 경보 <b>${fmt(pv.checked)}</b>건에 이 트리거를 대입하면 <b>${fmt(pv.matched)}</b>건에서 실행됐을 것입니다
      <div class="dim" style="font-size:12px">${pv.matched / Math.max(1, pv.checked) > .5 ? "<span class='c-high'>절반 넘는 경보에서 실행됩니다 — 조건이 너무 넓지 않은지 확인하세요.</span>" : "실행 횟수 제한(once_per)은 실제 실행 때 적용됩니다."}</div></div></div>
    ${pv.samples.map(s => `<details class="au-sample"><summary>${sev(s.severity)} ${esc(s.title)} <span class="dim">· 경보 #${s.alert_id}${s.incident_id ? ` · 사건 #${s.incident_id}` : ""} · ${fmtT(s.ts)}</span></summary>
      ${AU.cur.steps.map(st => `<div class="au-si"><code>${esc(st.id)}</code> ${esc(auMeta(st.action).ko)} → <span class="dim">${esc(JSON.stringify(s.inputs[st.id] || {}))}</span></div>`).join("")}</details>`).join("")}`}</div>`;
  countUp($$("[data-count]", res), 0, false);
  if (M) M.animate(res.firstChild, { opacity: [0, 1], y: [12, 0] }, { type: "spring", stiffness: 260, damping: 22 });
  return true;
}
async function auSave() {
  const pb = auClean();
  if (!AU_ID.test(pb.id)) { toast("플레이북 id 는 영문 소문자로 시작하고 소문자·숫자·_ 만 쓸 수 있습니다", "critical"); AU.sel = "trigger"; auRender(); return; }
  if (AU.isNew && AU.list.some(p => p.id === pb.id)) { toast(`id '${esc(pb.id)}' 는 이미 있습니다 — 다른 id 를 쓰세요`, "critical"); return; }
  const btn = $('[data-a="save"]', AU.el); btn.disabled = true;
  try {
    if (!(await auCheck(false))) return;
    if (pb.enabled !== false && pb.steps.some(s => auDestr(s.action) && s.approval === "none") && AU.mode === "live"
        && !confirm("승인 없이 실제 차단·잠금을 실행하는 단계가 있습니다 (live 모드). 그대로 저장할까요?")) return;
    const why = $(".au-why", AU.el).value.trim() || "자동화 편집기에서 저장";
    const r = await api(`/api/playbooks/${encodeURIComponent(pb.id)}?comment=${encodeURIComponent(why)}`, { method: "PUT", body: pb });
    $(".au-why", AU.el).value = "";
    AU.dirty = false; toast(`<b>${esc(pb.name)}</b> 저장됨 → v${r.version} (즉시 적용)`);
    await auReload(pb.id);
    if (A) anime({ targets: $$(".au-node", AU.el), backgroundColor: ["rgba(74,222,128,.22)", "rgba(0,0,0,0)"], delay: anime.stagger(50), duration: 900, easing: "easeOutQuad" });
  } catch (e) { $(".au-result", AU.el).innerHTML = e.body?.details ? auErrs([].concat(e.body.details)) : ""; toast(`<span class="err">${esc(errMsg(e))}</span>`, "critical"); }
  finally { btn.disabled = false; }
}

// ================================================================ 왼쪽: 도구 · 변수
function auPalette() {
  const pal = $(".au-pal", AU.el), groups = {};
  Object.keys(AU.actions).forEach(a => (groups[auMeta(a).group] ||= []).push(a));
  pal.innerHTML = `<h5>도구 <span class="faint">· 끌어다 놓기</span></h5>` + AU_GROUPS.filter(([g]) => groups[g]).map(([g, label]) => `<div class="au-grp">${esc(label)}</div>` +
    groups[g].map(a => { const m = auMeta(a); return `<div class="au-tool-item ${auDestr(a) ? "danger" : ""}" ${AU.ro ? "" : 'draggable="true"'} data-add="${esc(a)}" title="${esc(AU.actions[a].description)}">
      <span class="ic">${m.ic}</span><span>${esc(m.ko)}<small>${esc(a)}</small></span></div>`; }).join("")).join("") + `<h5 style="margin-top:16px">변수</h5><div class="au-vars"></div>`;
  $$("[data-add]", pal).forEach(it => {
    it.addEventListener("dragstart", e => { AU.drag = { add: it.dataset.add }; e.dataTransfer.effectAllowed = "copy"; e.dataTransfer.setData("application/x-rkau", it.dataset.add); auDragging(true); });
    it.addEventListener("dragend", () => auDragging(false));
    it.addEventListener("click", () => { if (AU.ro) return; const at = typeof AU.sel === "number" ? AU.sel + 1 : AU.cur.steps.length; auInsert(it.dataset.add, at); });
  });
  auVars();
}
// 변수: 기본 + 선택한 단계보다 앞에 있는 단계의 결과
function auVarList(uptoIdx) {
  const vars = AU_VARS.map(([p, l]) => [p, l]);
  AU.cur.steps.slice(0, uptoIdx).forEach(s => auMeta(s.action).outputs.forEach(([o, l]) => vars.push([`steps.${s.id}.output.${o}`, `${s.id} → ${l.split(" (")[0]}`])));
  return vars;
}
function auVars() {
  const upto = typeof AU.sel === "number" ? AU.sel : AU.sel === "trigger" ? 0 : AU.cur.steps.length;
  const vars = auVarList(upto), box = $(".au-vars", AU.el);
  box.innerHTML = vars.map(([p, l]) => `<span class="au-var ${p.startsWith("steps.") ? "st" : ""}" draggable="true" data-var="${esc(p)}" title="{{${esc(p)}}}">${esc(l)}</span>`).join("") +
    (AU.sel === "trigger" ? `<div class="faint" style="font-size:11.5px;margin-top:6px">트리거 조건에서는 단계 결과를 쓸 수 없습니다.</div>` : "");
  $("#au-fields").innerHTML = auVarList(AU.cur.steps.length).map(([p, l]) => `<option value="${esc(p)}">${esc(l)}</option>`).join("");
  $$(".au-var", box).forEach(v => {
    v.addEventListener("dragstart", e => { AU.drag = { v: v.dataset.var }; e.dataTransfer.effectAllowed = "copy"; e.dataTransfer.setData("text/plain", `{{${v.dataset.var}}}`); });
    v.addEventListener("dragend", () => { AU.drag = null; });
    v.addEventListener("click", () => auInsertVar(v.dataset.var));
  });
}
function auInsertVar(p) {
  const f = AU.lastFocus;
  if (!f || !f.isConnected || AU.ro) { toast("먼저 오른쪽 설정에서 값을 넣을 입력칸을 누르세요"); return; }
  const isField = f.dataset.c === "field", txt = isField ? p : `{{${p}}}`;
  if (isField) f.value = txt;
  else {
    let s = f.selectionStart ?? f.value.length, e = f.selectionEnd ?? s;
    const open = f.value.lastIndexOf("{{", s - 1), end = open >= 0 ? f.value.indexOf("}}", open) : -1;
    if (s === e && end >= 0 && open < s && s < end + 2) s = e = end + 2;     // 다른 변수 안쪽이면 그 뒤에
    f.value = f.value.slice(0, s) + txt + f.value.slice(e); f.selectionStart = f.selectionEnd = s + txt.length; }
  f.dispatchEvent(new Event("input", { bubbles: true })); f.dispatchEvent(new Event("change", { bubbles: true })); f.focus();
  if (M) M.animate(f, { scale: [1.03, 1] }, { type: "spring", stiffness: 500, damping: 18 });
}

// ================================================================ 가운데: 흐름
function auRender(enter) { auFlow(enter ? "all" : null); auInsp(); auVars(); auLint(); auChipsName(); }
function auChipsName() {
  const n = $(".au-name", AU.el);
  if (n) n.innerHTML = `<b>${esc(AU.cur.name)}</b> <code>${esc(AU.cur.id)}</code>${AU.cur.enabled === false ? ` <span class="state cancelled">비활성</span>` : ` <span class="state succeeded">활성</span>`}`;
}
function auCondText(c) {
  const lab = (AU_VARS.find(v => v[0] === c.field) || [])[1] || c.field.replace(/^steps\.([^.]+)\.output\./, "$1 → ");
  const op = (AU_OPS.find(o => o[0] === c.op) || [, c.op])[1];
  return `${esc(lab)} <b>${esc(op)}</b> ${["exists", "not_exists"].includes(c.op) ? "" : esc(Array.isArray(c.value) ? c.value.join(", ") : String(c.value ?? ""))}`;
}
function auFlow(anim) {
  const pb = AU.cur, flow = $(".au-flow", AU.el), t = pb.trigger;
  const dz = i => AU.ro ? `<div class="au-wire"></div>` : `<div class="au-dz" data-dz="${i}"><span>여기에 놓기</span></div>`;
  flow.innerHTML = `<div class="au-node trig ${AU.sel === "trigger" ? "sel" : ""}" data-sel="trigger">
      <div class="hd"><span class="ic">⚡</span><b>트리거</b><span class="dim">${esc(AU_TRIG[t.on][0])}</span><span class="grow"></span>
        ${t.on !== "manual" ? `<span class="bdg">${t.once_per === "incident" || (!t.once_per && t.on === "incident") ? "사건당 1회" : "경보마다"}</span>` : ""}</div>
      <div class="bd">${t.on === "manual" ? "사건 화면 · 이 편집기의 [사건에 실행] 으로 시작" : (t.where?.length ? t.where.map(c => `<div>${auCondText(c)}</div>`).join("") : `<span class="c-high">조건 없음 — 모든 ${t.on === "alert" ? "경보" : "사건"}에서 실행</span>`)}</div></div>` +
    pb.steps.map((s, i) => dz(i) + auStepNode(s, i)).join("") + dz(pb.steps.length) +
    `<div class="au-node end"><span class="ic">■</span> 끝 <span class="dim">· 결과는 사건 타임라인·실행 기록·감사 로그에 남습니다</span></div>`;
  if (!A) return;
  if (anim === "all") anime({ targets: $$(".au-node", flow), opacity: [0, 1], translateY: [16, 0], delay: anime.stagger(60), duration: 450, easing: "easeOutCubic" });
  else if (typeof anim === "number") {
    const n = $(`.au-node[data-i="${anim}"]`, flow);
    if (n) anime({ targets: n, scale: [.85, 1], opacity: [0, 1], duration: 650, easing: "spring(1, 120, 11, 0)" });
  }
}
function auStepNode(s, i) {
  const m = auMeta(s.action), d = auDestr(s.action), b = [];
  if (s.when?.length) b.push(`<span class="bdg cond" title="${s.when.map(c => auCondText(c).replace(/<[^>]+>/g, "")).join(" 그리고 ")}">조건 ${s.when.length}</span>`);
  const ap = s.approval || "policy";
  if (ap === "required" || (ap === "policy" && d)) b.push(`<span class="bdg appr">승인 필요</span>`);
  if (ap === "none" && d) b.push(`<span class="bdg warn">승인 없이 실행</span>`);
  if (s.retries) b.push(`<span class="bdg">재시도 ${s.retries}</span>`);
  if (s.timeout_sec) b.push(`<span class="bdg">${s.timeout_sec}s 제한</span>`);
  b.push(`<span class="bdg">${{ abort: "실패 시 중단", continue: "실패해도 계속", compensate: "실패 시 되돌리고 중단" }[s.on_failure || "abort"]}</span>`);
  if (s.compensate) b.push(`<span class="bdg comp">↺ ${esc(auMeta(s.compensate.action).ko)}</span>`);
  const inp = Object.entries(s.input || {}).map(([k, v]) => `<span class="k">${esc(k)}</span> ${esc(String(typeof v === "object" ? JSON.stringify(v) : v)).replace(/\{\{([^}]+)\}\}/g, '<span class="tpl">$1</span>')}`).join("<br>");
  return `<div class="au-node stp ${d ? "danger" : ""} ${AU.sel === i ? "sel" : ""}" data-sel="${i}" data-i="${i}" ${AU.ro ? "" : 'draggable="true"'}>
    <div class="hd"><span class="no">${i + 1}</span><span class="ic">${m.ic}</span><b>${esc(m.ko)}</b><code>${esc(s.id)}</code><span class="grow"></span>
      ${AU.ro ? "" : `<span class="au-ops"><button data-op="up" ${i ? "" : "disabled"} title="위로">↑</button><button data-op="down" ${i < AU.cur.steps.length - 1 ? "" : "disabled"} title="아래로">↓</button>
        <button data-op="dup" title="복제">⧉</button><button data-op="del" title="삭제" class="x">✕</button></span>`}</div>
    ${inp ? `<div class="bd">${inp}</div>` : ""}<div class="bdgs">${b.join("")}</div></div>`;
}
function auDragging(on) {
  const f = $(".au-flow", AU.el); if (!f) return;
  f.classList.toggle("dragging", on);
  if (!on) { AU.drag = null; $$(".over", f).forEach(x => x.classList.remove("over")); $$(".lift", f).forEach(x => x.classList.remove("lift")); }
}
function auBindFlow() {
  const flow = $(".au-flow", AU.el);
  flow.addEventListener("click", e => {
    const op = e.target.closest("[data-op]");
    if (op) { e.stopPropagation(); const i = +op.closest(".au-node").dataset.i; auStepOp(op.dataset.op, i); return; }
    const n = e.target.closest("[data-sel]"); if (!n) return;
    AU.sel = n.dataset.sel === "trigger" ? "trigger" : +n.dataset.sel;
    $$(".au-node", flow).forEach(x => x.classList.toggle("sel", x === n));
    auInsp(); auVars();
  });
  flow.addEventListener("dragstart", e => {
    const n = e.target.closest(".au-node.stp"); if (!n || AU.ro) return;
    AU.drag = { move: +n.dataset.i }; e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("application/x-rkau", n.dataset.i);
    setTimeout(() => { auDragging(true); n.classList.add("lift"); }, 0);
  });
  flow.addEventListener("dragend", () => auDragging(false));
  flow.addEventListener("dragover", e => {
    if (!AU.drag || AU.drag.v) return;
    const z = e.target.closest(".au-dz") || auNearestDz(e.clientY); if (!z) return;
    e.preventDefault(); e.dataTransfer.dropEffect = AU.drag.add ? "copy" : "move";
    $$(".au-dz.over", flow).forEach(x => x !== z && x.classList.remove("over")); z.classList.add("over");
  });
  flow.addEventListener("dragleave", e => { if (!flow.contains(e.relatedTarget)) $$(".au-dz.over", flow).forEach(x => x.classList.remove("over")); });
  flow.addEventListener("drop", e => {
    const z = $(".au-dz.over", flow); if (!z || !AU.drag) return;
    e.preventDefault();
    const at = +z.dataset.dz, d = AU.drag; auDragging(false);
    if (d.add) auInsert(d.add, at);
    else if (d.move != null) auMove(d.move, at);
  });
}
// 노드 위에 놓아도 가장 가까운 놓기 칸으로
function auNearestDz(y) {
  let best = null, bd = Infinity;
  $$(".au-dz", AU.el).forEach(z => { const r = z.getBoundingClientRect(), d = Math.abs(r.top + r.height / 2 - y); if (d < bd) { bd = d; best = z; } });
  return bd < 140 ? best : null;
}
function auNewStep(a, steps) {
  const m = auMeta(a), input = {};
  let id = a, n = 2; while (steps.some(s => s.id === id)) id = `${a}_${n++}`;
  m.inputs.forEach(f => { if (f.def !== "" && f.def != null) input[f.k] = f.def; });
  const s = { id, action: a, input };
  if (AU.actions[a]?.destructive) { s.approval = "policy"; s.on_failure = "continue"; }
  if (m.comp) s.compensate = { action: m.comp, input: auCompInput(m.comp, input) };
  return s;
}
function auCompInput(comp, input) {
  const o = {}; auMeta(comp).inputs.forEach(f => { if (input[f.k] != null) o[f.k] = input[f.k]; else if (f.def) o[f.k] = f.def; }); return o;
}
function auInsert(a, at) {
  AU.cur.steps.splice(at, 0, auNewStep(a, AU.cur.steps));
  AU.sel = at; auMarkDirty(true); auFlow(at); auInsp(); auVars(); auLint();
  if (AU.actions[a]?.destructive) toast(`<b>${esc(auMeta(a).ko)}</b> 단계는 대응 조치라 승인 정책을 거치도록 넣었습니다`, "info");
}
function auMove(from, to) {
  if (to === from || to === from + 1) return;
  const [s] = AU.cur.steps.splice(from, 1), at = to > from ? to - 1 : to;
  AU.cur.steps.splice(at, 0, s); AU.sel = at; auMarkDirty(true); auFlow(at); auInsp(); auVars(); auLint();
}
function auStepOp(op, i) {
  const st = AU.cur.steps;
  if (op === "up" && i > 0) return auMove(i, i - 1);
  if (op === "down" && i < st.length - 1) return auMove(i, i + 2);
  if (op === "dup") { const c = auClone(st[i]); let id = `${c.id}_2`, n = 3; while (st.some(s => s.id === id)) id = `${c.id}_${n++}`; c.id = id;
    st.splice(i + 1, 0, c); AU.sel = i + 1; auMarkDirty(true); auFlow(i + 1); auInsp(); auVars(); auLint(); return; }
  if (op === "del") {
    if (st.length === 1) { toast("플레이북에는 단계가 하나 이상 있어야 합니다", "high"); return; }
    const n = $(`.au-node[data-i="${i}"]`, AU.el);
    const done = () => { st.splice(i, 1); AU.sel = "trigger"; auMarkDirty(true); auFlow(); auInsp(); auVars(); auLint(); };
    if (A && n) anime({ targets: n, opacity: 0, translateX: 60, duration: 260, easing: "easeInCubic", complete: done }); else done();
  }
}

// 저장 전 빠른 점검 (서버 검증과 별개로 사람이 놓치기 쉬운 것)
function auLint() {
  const w = [], pb = AU.cur, ids = pb.steps.map(s => s.id);
  if (pb.trigger.on !== "manual" && !pb.trigger.where?.length) w.push(["warn", `트리거 조건이 없어 모든 ${pb.trigger.on === "alert" ? "경보" : "사건"}마다 실행됩니다.`]);
  pb.steps.forEach((s, i) => {
    const txt = JSON.stringify([s.input, s.when, s.compensate]);
    for (const m of txt.matchAll(/steps\.([a-z0-9_]+)\./g)) {
      const j = ids.indexOf(m[1]);
      if (j < 0) w.push(["bad", `${s.id}: 없는 단계 '${m[1]}' 의 결과를 참조합니다.`]);
      else if (j >= i) w.push(["bad", `${s.id}: 뒤에 실행되는 '${m[1]}' 의 결과를 참조합니다 — 순서를 바꾸세요.`]);
    }
    if (auDestr(s.action) && s.approval === "none") w.push(["warn", `${s.id}: 승인 없이 ${auMeta(s.action).ko}을(를) 실행합니다${AU.mode === "live" ? " (live 모드 — 실제 반영)" : ""}.`]);
    if (!AU.actions[s.action]) w.push(["bad", `${s.id}: 서버에 등록되지 않은 액션 '${s.action}'`]);
  });
  new Set(ids).size !== ids.length && w.push(["bad", "단계 id 가 중복됩니다."]);
  const l = $(".au-lint", AU.el);
  l.innerHTML = [...new Map(w.map(x => [x[1], x])).values()].map(([k, t]) => `<div class="au-l ${k}">${k === "bad" ? "✘" : "!"} ${esc(t)}</div>`).join("");
}

// ================================================================ 오른쪽: 설정
const auValStr = v => Array.isArray(v) ? v.join(", ") : v == null ? "" : String(v);
const auAuto = s => /^-?\d+(\.\d+)?$/.test(s) ? Number(s) : s === "true" ? true : s === "false" ? false : s;
function auParseVal(op, s) {
  if (["in", "not_in"].includes(op)) return s.split(",").map(x => x.trim()).filter(Boolean).map(auAuto);
  if (["gt", "gte", "lt", "lte"].includes(op)) return isNaN(+s) || s === "" ? s : +s;
  if (["contains", "regex"].includes(op)) return s;
  return auAuto(s.trim());
}
function auConds(list, scope) {
  const dis = AU.ro ? "disabled" : "";
  return `<div class="au-conds" data-scope="${scope}">${(list || []).map((c, k) => `<div class="au-cond" data-k="${k}">
      <input list="au-fields" data-c="field" value="${esc(c.field)}" placeholder="필드 (변수)" ${dis}>
      <select data-c="op" ${dis}>${AU_OPS.map(([o, l]) => `<option value="${o}" ${o === c.op ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>
      ${["exists", "not_exists"].includes(c.op) ? `<span class="faint">—</span>` : ["in_list", "not_in_list"].includes(c.op)
        ? `<select data-c="value" ${dis}>${[...new Set([...AU.lists, c.value].filter(Boolean))].map(n => `<option ${n === c.value ? "selected" : ""}>${esc(n)}</option>`).join("")}</select>`
        : `<input data-c="value" value="${esc(auValStr(c.value))}" placeholder="${["in", "not_in"].includes(c.op) ? "값, 값, … (쉼표)" : "값"}" ${dis}>`}
      ${AU.ro ? "" : `<button class="au-x" data-cdel title="조건 삭제">✕</button>`}</div>`).join("") || `<div class="faint" style="font-size:12px">조건 없음</div>`}
    ${AU.ro ? "" : `<button class="btn au-addc">＋ 조건</button>`}</div>`;
}
function auField(f, val, path) {
  const v = val ?? "", dis = AU.ro ? "disabled" : "";
  if (f.type === "select") return `<label>${esc(f.label)}<select data-f="${path}" ${dis}>${f.options.map(o => `<option ${o === v ? "selected" : ""}>${esc(o)}</option>`).join("")}</select></label>`;
  if (f.type === "area") return `<label>${esc(f.label)}<textarea data-f="${path}" rows="3" ${dis}>${esc(v)}</textarea></label>`;
  return `<label>${esc(f.label)}<input data-f="${path}" ${f.type === "num" ? 'data-num="1"' : ""} value="${esc(typeof v === "object" ? JSON.stringify(v) : v)}" ${dis}></label>`;
}
function auFieldsFor(action, input, prefix) {
  const m = auMeta(action), known = m.inputs.map(f => f.k);
  const extra = Object.keys(input || {}).filter(k => !known.includes(k)).map(k => ({ k, label: k, opt: true }));
  if (!AU_META[action]) return `<label>입력 (JSON)<textarea data-f="${prefix}json" rows="4" ${AU.ro ? "disabled" : ""}>${esc(JSON.stringify(input || {}, null, 1))}</textarea></label>`;
  return [...m.inputs, ...extra].map(f => auField(f, (input || {})[f.k], `${prefix}in.${f.k}`)).join("");
}
function auInsp() {
  const box = $(".au-insp", AU.el), pb = AU.cur, dis = AU.ro ? "disabled" : "";
  if (AU.sel === "trigger") {
    const t = pb.trigger;
    box.innerHTML = `<div class="au-ih"><span class="ic">⚡</span><div><b>플레이북 · 트리거</b><div class="dim">언제, 어떤 경보에 실행할지</div></div></div>
      <label>이름<input data-t="name" value="${esc(pb.name)}" ${dis}></label>
      <label>설명<textarea data-t="description" rows="2" ${dis}>${esc(pb.description || "")}</textarea></label>
      <label>id ${AU.isNew ? `<input data-t="id" value="${esc(pb.id)}" ${dis}>` : `<code class="au-ro">${esc(pb.id)}</code>`}</label>
      <label class="au-chk"><input type="checkbox" data-t="enabled" ${pb.enabled !== false ? "checked" : ""} ${dis}> 활성 <span class="dim">— 끄면 자동으로 실행되지 않음</span></label>
      <fieldset><legend>언제 시작?</legend><div class="au-radio">${Object.entries(AU_TRIG).map(([k, [a, b]]) => `<label class="${t.on === k ? "on" : ""}">
        <input type="radio" name="au-on" value="${k}" data-t="on" ${t.on === k ? "checked" : ""} ${dis}><b>${esc(a)}</b><span class="dim">${esc(b)}</span></label>`).join("")}</div>
        ${t.on !== "manual" ? `<label>실행 횟수<select data-t="once_per" ${dis}><option value="alert" ${(t.once_per || (t.on === "alert" ? "alert" : "incident")) === "alert" ? "selected" : ""}>경보(단계)마다 한 번</option>
          <option value="incident" ${(t.once_per || (t.on === "alert" ? "alert" : "incident")) === "incident" ? "selected" : ""}>사건당 한 번</option></select></label>` : ""}</fieldset>
      ${t.on !== "manual" ? `<fieldset><legend>시작 조건 <span class="dim">· 모두 만족해야 실행</span></legend>
        ${AU.levels.length ? `<div class="au-sub">경보 단계 빠른 선택</div><div class="au-lv">${AU.levels.map(l => `<button class="au-lvb ${auLevelOn(l) ? "on" : ""}" data-lv="${esc(l)}" ${dis}>${esc(l)}</button>`).join("")}</div>` : ""}
        ${auConds(t.where, "trig")}</fieldset>` : ""}`;
  } else {
    const i = AU.sel, s = pb.steps[i];
    if (!s) { AU.sel = "trigger"; return auInsp(); }
    const m = auMeta(s.action), act = AU.actions[s.action] || {}, d = auDestr(s.action);
    box.innerHTML = `<div class="au-ih"><span class="ic ${d ? "c-critical" : ""}">${m.ic}</span><div><b>${i + 1}. ${esc(m.ko)}</b> <code>${esc(s.action)}</code><div class="dim">${esc(act.description || "")}</div></div></div>
      ${d ? `<div class="au-warn">대응 조치 — ${AU.mode === "live" ? "<b>live 모드</b>: 실행되면 서버에 실제로 반영됩니다." : "simulate 모드: 기록만 하고 실제로 바꾸지 않습니다."} 사내망·허용 목록·차단 금지 목록·보호 계정은 서버가 항상 거부합니다.</div>` : ""}
      <label>단계 id <span class="faint">(다른 단계가 결과를 참조할 때 쓰는 이름)</span><input data-f="id" value="${esc(s.id)}" ${dis}></label>
      <fieldset><legend>입력값 <span class="dim">· 변수를 끌어다 놓기</span></legend>${auFieldsFor(s.action, s.input, "")}</fieldset>
      <fieldset><legend>실행 조건 <span class="dim">· 모두 만족할 때만 (비우면 항상)</span></legend>${auConds(s.when, "when")}</fieldset>
      <fieldset><legend>실행 정책</legend>
        <label>승인<select data-f="approval" ${dis}>${[["policy", "승인 정책 따름 (대응 조치만 승인)"], ["required", "항상 사람이 승인"], ["none", "승인 없이 바로 실행"]].map(([v, l]) => `<option value="${v}" ${(s.approval || "policy") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <label>실패하면<select data-f="on_failure" ${dis}>${[["abort", "여기서 중단"], ["continue", "다음 단계로 계속"], ["compensate", "앞서 한 조치 되돌리고 중단"]].map(([v, l]) => `<option value="${v}" ${(s.on_failure || "abort") === v ? "selected" : ""}>${l}</option>`).join("")}</select></label>
        <div class="au-2"><label>재시도<input data-f="retries" data-num="1" value="${esc(s.retries ?? "")}" placeholder="0" ${dis}></label>
          <label>시간 제한(초)<input data-f="timeout_sec" data-num="1" value="${esc(s.timeout_sec ?? "")}" placeholder="기본" ${dis}></label></div></fieldset>
      <fieldset><legend>보상 작업 <span class="dim">· 취소·실패 때 되돌리기</span></legend>
        <label>되돌리는 액션<select data-f="comp.action" ${dis}><option value="">(없음)</option>${Object.keys(AU.actions).map(a => `<option value="${esc(a)}" ${s.compensate?.action === a ? "selected" : ""}>${esc(auMeta(a).ko)} (${esc(a)})</option>`).join("")}</select></label>
        ${s.compensate ? auFieldsFor(s.compensate.action, s.compensate.input, "comp.") : ""}</fieldset>`;
  }
  if (M) M.animate(box, { opacity: [.4, 1] }, { duration: .2 });
}
const auLevelCond = () => (AU.cur.trigger.where || []).find(c => c.field === "alert.level_id" && ["eq", "in"].includes(c.op));
const auLevelOn = l => { const c = auLevelCond(); return !!c && [].concat(c.value).includes(l); };

function auBindInsp() {
  const box = $(".au-insp", AU.el);
  box.addEventListener("focusin", e => { if (e.target.matches("input:not([type=checkbox]):not([type=radio]), textarea")) AU.lastFocus = e.target; });
  const apply = (e, commit) => {
    const el = e.target, pb = AU.cur;
    if (AU.ro) return;
    if (el.dataset.t) {                                                  // 트리거 · 플레이북
      const k = el.dataset.t;
      if (k === "enabled") pb.enabled = el.checked;
      else if (k === "on") { pb.trigger.on = el.value; if (el.value === "manual") delete pb.trigger.once_per; auInsp(); }
      else if (k === "once_per") pb.trigger.once_per = el.value;
      else if (k === "id") { if (!commit) return; const v = el.value.trim(); if (!AU_ID.test(v) || AU.list.some(p => p.id === v)) { el.classList.add("bad"); shake(el, 5); return; } el.classList.remove("bad"); pb.id = v; auChips(); }
      else pb[k] = el.value;
      if (k === "name" || k === "enabled") auChipsName();
    } else if (el.dataset.c) {                                           // 조건
      const row = el.closest(".au-cond"), scope = el.closest(".au-conds").dataset.scope, list = scope === "trig" ? pb.trigger.where : pb.steps[AU.sel].when, c = list[+row.dataset.k];
      if (el.dataset.c === "field") {                                   // 변수를 끌어다 놓으면 {{ }} 가 붙어 들어옴 → 경로만
        const v = el.value.trim().replace(/^\{\{\s*([^}]+?)\s*\}\}$/, "$1");
        if (v !== el.value.trim()) el.value = v;
        c.field = v;
      }
      if (el.dataset.c === "op") {
        c.op = el.value;
        if (["exists", "not_exists"].includes(c.op)) delete c.value;
        else if (["in_list", "not_in_list"].includes(c.op)) c.value = AU.lists.includes(c.value) ? c.value : AU.lists[0];
        else c.value = auParseVal(c.op, auValStr(c.value === undefined || AU.lists.includes(c.value) ? "" : c.value));
        auInsp();
      }
      if (el.dataset.c === "value") c.value = el.tagName === "SELECT" ? el.value : auParseVal(c.op, el.value);
    } else if (el.dataset.f) {                                           // 단계
      const s = pb.steps[AU.sel], f = el.dataset.f, num = el.dataset.num && /^\d+(\.\d+)?$/.test(el.value.trim());
      const val = num ? +el.value.trim() : el.value;
      if (f === "id") {
        if (!commit) return;
        const v = el.value.trim();
        if (!AU_ID.test(v) || pb.steps.some((x, j) => j !== AU.sel && x.id === v)) { el.classList.add("bad"); shake(el, 5); toast("단계 id: 영문 소문자로 시작, 소문자·숫자·_ 만, 중복 불가", "high"); return; }
        el.classList.remove("bad");
        if (v !== s.id) {                                                // 다른 단계의 참조도 같이 바꾼다
          const re = new RegExp(`steps\\.${s.id}\\.`, "g");
          pb.steps = JSON.parse(JSON.stringify(pb.steps).replace(re, `steps.${v}.`)); pb.steps[AU.sel].id = v;
        }
      } else if (f.startsWith("in.") || f.startsWith("comp.in.")) {
        const tgt = f.startsWith("comp.") ? (s.compensate.input ||= {}) : (s.input ||= {}), k = f.replace(/^(comp\.)?in\./, "");
        const def = auMeta(f.startsWith("comp.") ? s.compensate.action : s.action).inputs.find(x => x.k === k);
        if (el.value === "" && (!def || def.opt)) delete tgt[k]; else tgt[k] = val;
      } else if (f === "json" || f === "comp.json") {
        try { const o = JSON.parse(el.value || "{}"); f === "json" ? (s.input = o) : (s.compensate.input = o); el.classList.remove("bad"); } catch (_) { el.classList.add("bad"); return; }
      } else if (f === "comp.action") {
        if (!el.value) delete s.compensate; else s.compensate = { action: el.value, input: auCompInput(el.value, s.input || {}) };
        auInsp();
      } else if (f === "approval") { el.value === "policy" ? delete s.approval : (s.approval = el.value); }
      else if (f === "on_failure") { el.value === "abort" ? delete s.on_failure : (s.on_failure = el.value); }
      else if (f === "retries" || f === "timeout_sec") { el.value.trim() === "" ? delete s[f] : (s[f] = num ? val : el.value); }
    } else return;
    auMarkDirty(true); auFlow(); auLint(); if (el.dataset.f === "id") auVars();
  };
  box.addEventListener("input", e => { if (e.target.tagName !== "SELECT" && e.target.type !== "checkbox" && e.target.type !== "radio") apply(e, false); });
  box.addEventListener("change", e => apply(e, true));
  box.addEventListener("click", e => {
    if (AU.ro) return;
    const pb = AU.cur;
    const add = e.target.closest(".au-addc"), del = e.target.closest("[data-cdel]"), lv = e.target.closest("[data-lv]");
    if (!add && !del && !lv) return;
    e.preventDefault();
    if (lv) {                                                            // 경보 단계 빠른 선택 → alert.level_id in [...]
      const t = pb.trigger; t.where ||= [];
      let c = auLevelCond(); const l = lv.dataset.lv;
      if (!c) { c = { field: "alert.level_id", op: "in", value: [] }; t.where.push(c); }
      const vals = new Set([].concat(c.value)); vals.has(l) ? vals.delete(l) : vals.add(l);
      c.op = "in"; c.value = [...vals];
      if (!c.value.length) t.where.splice(t.where.indexOf(c), 1);
    } else {
      const scope = e.target.closest(".au-conds").dataset.scope;
      const holder = scope === "trig" ? pb.trigger : pb.steps[AU.sel], key = scope === "trig" ? "where" : "when";
      if (add) (holder[key] ||= []).push({ field: scope === "trig" ? "alert.severity" : "alert.group.user.name", op: scope === "trig" ? "eq" : "exists", ...(scope === "trig" ? { value: "critical" } : {}) });
      else { holder[key].splice(+del.closest(".au-cond").dataset.k, 1); if (!holder[key].length) delete holder[key]; }
    }
    auMarkDirty(true); auInsp(); auFlow(); auLint();
    if (add && A) anime({ targets: $$(".au-cond", box).pop(), opacity: [0, 1], translateY: [-8, 0], duration: 300, easing: "easeOutCubic" });
  });
}
