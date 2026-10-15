/* RKMSIEM 웹 터미널 — 토폴로지에서 SIEM 과 와이어로 이어진 기기에 SSH 로 접속해 브라우저에서 입력한다.
   허용 여부(권한 terminal:use · 와이어 연결)는 백엔드가 판단한다. 여기서는 창·입출력만 다룬다.
   출력: GET /api/terminal/<id>?since=N (롱 폴링) · 입력: POST …/input · 크기: POST …/resize
   xterm.js 는 web/vendor/xterm 에 함께 들어 있다 (서버가 인터넷에 못 나가도 동작). app.js 보다 먼저 읽힌다. */
"use strict";

const TW = { lib: null, wins: [], z: 60, ports: [22, 2222] };

function twLoadLib() {
  if (TW.lib) return TW.lib;
  TW.lib = new Promise((ok, bad) => {
    const css = document.createElement("link"); css.rel = "stylesheet"; css.href = "/static/vendor/xterm/xterm.css"; document.head.appendChild(css);
    let left = 2; const done = () => { if (--left === 0) ok(); };
    for (const src of ["/static/vendor/xterm/xterm.js", "/static/vendor/xterm/addon-fit.js"]) {
      const s = document.createElement("script"); s.src = src; s.onload = done; s.onerror = () => { TW.lib = null; bad(new Error("터미널 화면 모듈을 불러오지 못했습니다")); };
      document.head.appendChild(s);
    }
  });
  return TW.lib;
}

const twWait = ms => new Promise(r => setTimeout(r, ms));
function twB64(s) { const b = atob(s), u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }

// 토폴로지 화면에서 쓰는 조건 미리보기 (저장된 배치 기준, 최종 판단은 백엔드)
function twWired(layout, ip) {
  const nodes = new Map((layout?.nodes || []).map(n => [n.id, n])), adj = new Map([...nodes.keys()].map(k => [k, []]));
  for (const l of layout?.links || []) if (adj.has(l.from) && adj.has(l.to)) { adj.get(l.from).push(l.to); adj.get(l.to).push(l.from); }
  const seen = new Set([...nodes.values()].filter(n => n.type === "siem").map(n => n.id)), q = [...seen];
  while (q.length) { const cur = q.shift(), n = nodes.get(cur);
    if ([n.ip, ...(n.interfaces || []).map(i => i.ip)].includes(ip) && n.type !== "siem") return true;
    for (const x of adj.get(cur)) if (!seen.has(x)) { seen.add(x); q.push(x); } }
  return false;
}

/** 접속 창 열기: 계정·포트를 묻고 → 연결. node = {ip, label} */
function openTerminal(node, preset = {}) {
  const ex = TW.wins.find(w => w.ip === node.ip && !w.dead && !w.id && w.el.isConnected);
  if (ex) { twFront(ex); $(".tw-login", ex.el)?.focus(); return; }
  const w = { ip: node.ip, label: node.label || "", id: null, next: 0, dead: false, term: null, fit: null, q: Promise.resolve(), el: document.createElement("section") };
  w.el.className = "tw"; w.el.setAttribute("role", "dialog"); w.el.setAttribute("aria-label", `터미널 ${node.ip}`);
  const off = TW.wins.filter(x => x.el.isConnected).length * 28;
  w.el.style.cssText = `left:${Math.max(8, innerWidth / 2 - 380 + off)}px;top:${Math.max(8, 70 + off)}px`;
  w.el.innerHTML = `<header class="tw-h"><span class="tw-dot"></span><b class="tw-t">${esc(node.label || node.ip)}</b><span class="tw-s dim">${esc(node.ip)}</span>
      <span class="grow"></span><button class="tw-b" data-a="max" title="크게/작게">▢</button><button class="tw-b" data-a="close" title="닫기 (연결 종료)">✕</button></header>
    <form class="tw-form"><p class="dim">SSH 로 <b>${esc(node.ip)}</b> 에 접속합니다. 비밀번호와 호스트 키 확인은 다음 화면의 터미널에서 직접 입력하세요.</p>
      <div class="st-row"><label>계정<input class="tw-login" required maxlength="32" pattern="[A-Za-z_][A-Za-z0-9_.\\-]{0,31}" value="${esc(preset.login || twLastLogin(node.ip))}" autocomplete="username"></label>
      <label>포트<select class="tw-port">${TW.ports.map(p => `<option ${p === (preset.port || 22) ? "selected" : ""}>${p}</option>`).join("")}</select></label></div>
      <label class="tw-chk"><input type="checkbox" class="tw-legacy" ${(preset.legacy ?? twPref(node.ip, "legacy")) ? "checked" : ""}> 구형 장비 호환
        <span class="faint">— 오래된 스위치·라우터처럼 옛 암호 방식만 아는 장비 (예: diffie-hellman-group1-sha1)</span></label>
      <div class="st-row"><button class="btn primary" type="submit">접속</button><span class="tw-err c-high"></span></div>
      <p class="faint">접속·종료는 감사 로그에, 화면 출력은 서버의 터미널 기록에 남습니다. 토폴로지에서 와이어를 끊으면 연결도 끊깁니다.</p></form>
    <div class="tw-body" hidden></div><div class="tw-foot dim" hidden></div>`;
  document.body.appendChild(w.el); TW.wins.push(w); twFront(w); twDrag(w);
  w.el.addEventListener("pointerdown", () => twFront(w));
  $$(".tw-b", w.el).forEach(b => b.onclick = () => b.dataset.a === "close" ? twClose(w) : twMax(w));
  $(".tw-form", w.el).onsubmit = e => { e.preventDefault(); twConnect(w, $(".tw-login", w.el).value.trim(), +$(".tw-port", w.el).value, $(".tw-legacy", w.el).checked); };
  if (preset.login) twConnect(w, preset.login, preset.port || 22, preset.legacy ?? twPref(node.ip, "legacy")); else setTimeout(() => $(".tw-login", w.el).select(), 0);
  if (A) anime({ targets: w.el, opacity: [0, 1], translateY: [12, 0], duration: 260, easing: "easeOutCubic" });
  return w;
}
function twLastLogin(ip) { try { return localStorage.getItem("rk_ssh_" + ip) || ""; } catch (e) { return ""; } }
function twPref(ip, k) { try { return localStorage.getItem(`rk_ssh_${k}_${ip}`) === "1"; } catch (e) { return false; } }
function twSetPref(ip, k, on) { try { on ? localStorage.setItem(`rk_ssh_${k}_${ip}`, "1") : localStorage.removeItem(`rk_ssh_${k}_${ip}`); } catch (e) { /* 저장소 차단 */ } }
// ssh 가 암호 방식 협상에 실패했다는 뜻 (상대 장비가 옛 방식만 앎) → 구형 장비 호환으로 다시 접속을 권한다
const TW_NEGOTIATE = /Unable to negotiate|no matching (key exchange|host key type|cipher|MAC)/i;

async function twConnect(w, login, port, legacy = false) {
  const err = $(".tw-err", w.el), btn = $(".tw-form button", w.el); err.textContent = ""; btn.disabled = true;
  try {
    await twLoadLib();
    const body = $(".tw-body", w.el); $(".tw-form", w.el).hidden = true; body.hidden = false;
    const css = getComputedStyle(document.documentElement), v = k => css.getPropertyValue(k).trim();
    w.term = new (window.Terminal.Terminal || window.Terminal)({ cursorBlink: true, fontSize: innerWidth < 640 ? 12 : 13, scrollback: 5000, convertEol: false,
      fontFamily: "'JetBrains Mono', 'Nanum Gothic Coding', monospace",
      theme: { background: v("--bg") || "#0a0d12", foreground: v("--text") || "#dbe2ea", cursor: v("--accent") || "#4ade80", selectionBackground: "#2a3644" } });
    w.fit = new window.FitAddon.FitAddon(); w.term.loadAddon(w.fit); w.term.open(body); w.fit.fit();
    const r = await api("/api/terminal", { method: "POST", body: { ip: w.ip, login, port, legacy, cols: w.term.cols, rows: w.term.rows } });
    w.id = r.id; w.login = login; w.port = port; w.legacy = legacy; w.tail = "";
    try { localStorage.setItem("rk_ssh_" + w.ip, login); } catch (e) { /* 저장소 차단 */ }
    twSetPref(w.ip, "legacy", legacy);
    $(".tw-s", w.el).textContent = `${login}@${w.ip}${port !== 22 ? ":" + port : ""}${legacy ? " · 구형 호환" : ""}`; w.el.classList.add("on");
    w.term.onData(d => twSend(w, d));
    w.term.onResize(({ cols, rows }) => { clearTimeout(w.rt); w.rt = setTimeout(() => !w.dead && api(`/api/terminal/${w.id}/resize`, { method: "POST", body: { cols, rows } }).catch(() => {}), 150); });
    w.ro = new ResizeObserver(() => { try { w.fit.fit(); } catch (e) { /* 숨김 상태 */ } }); w.ro.observe(body);
    w.term.focus(); twLoop(w);
  } catch (e) {
    if (w.term) { w.term.dispose(); w.term = null; }
    $(".tw-body", w.el).hidden = true; $(".tw-body", w.el).innerHTML = ""; $(".tw-form", w.el).hidden = false;
    err.textContent = errMsg(e); btn.disabled = false;
  }
}
function twSend(w, d) {               // 입력 순서를 지키도록 한 줄로 이어서 보낸다
  if (w.dead || !w.id) return;
  w.q = w.q.then(() => api(`/api/terminal/${w.id}/input`, { method: "POST", body: { data: d } })).catch(e => { if (e.status === 410 || e.status === 404) twEnded(w, "연결이 종료됐습니다"); });
}
async function twLoop(w) {
  let fails = 0;
  while (!w.dead && w.el.isConnected) {
    try {
      const r = await api(`/api/terminal/${w.id}?since=${w.next}&wait=20`);
      fails = 0;
      if (r.truncated) w.term.write("\r\n\x1b[33m[이전 출력 일부 생략]\x1b[0m\r\n");
      if (r.data) { const u = twB64(r.data); w.term.write(u); w.tail = (w.tail + new TextDecoder().decode(u)).slice(-2000); }
      w.next = r.next;
      if (r.closed) return twEnded(w, r.reason || "연결 종료");
    } catch (e) {
      if (e.status === 404 || e.status === 401 || e.status === 403) return twEnded(w, errMsg(e));
      if (++fails > 20) return twEnded(w, "서버와 연결이 끊겼습니다");
      await twWait(Math.min(5000, 500 * fails));
    }
  }
}
function twEnded(w, why) {
  if (w.dead) return; w.dead = true; w.el.classList.remove("on"); w.el.classList.add("end");
  w.term?.write(`\r\n\x1b[90m── ${why} ──\x1b[0m\r\n`);
  const f = $(".tw-foot", w.el); f.hidden = false;
  const nego = !w.legacy && TW_NEGOTIATE.test(w.tail || "");
  f.innerHTML = `<span>${nego ? "이 장비는 옛 암호 방식만 지원합니다" : esc(why)}</span><span class="st-row">
    ${nego ? `<button class="btn primary" data-a="legacy">구형 장비 호환으로 다시 접속</button>` : ""}<button class="btn" data-a="again">다시 접속</button></span>`;
  const again = legacy => { const n = { ip: w.ip, label: w.label }, pre = { login: w.login, port: w.port, legacy }; twClose(w); openTerminal(n, pre); };
  $("[data-a=again]", f).onclick = () => again(w.legacy);
  const lg = $("[data-a=legacy]", f); if (lg) lg.onclick = () => { twSetPref(w.ip, "legacy", true); again(true); };
  if (nego) w.term?.write(`\x1b[33m이 장비는 옛 암호 방식만 지원합니다 → 아래 '구형 장비 호환으로 다시 접속'\x1b[0m\r\n`);
}
function twClose(w) {
  if (w.id && !w.dead) api(`/api/terminal/${w.id}`, { method: "DELETE" }).catch(() => {});
  w.dead = true; w.ro?.disconnect(); w.term?.dispose(); w.el.remove(); TW.wins = TW.wins.filter(x => x !== w);
}
function twFront(w) { w.el.style.zIndex = ++TW.z; }
function twMax(w) { w.el.classList.toggle("max"); setTimeout(() => { try { w.fit?.fit(); } catch (e) { /* noop */ } w.term?.focus(); }, 30); }
function twDrag(w) {
  const h = $(".tw-h", w.el); let d = null;
  h.addEventListener("pointerdown", e => { if (e.target.closest("button") || w.el.classList.contains("max")) return; const r = w.el.getBoundingClientRect();
    d = { x: e.clientX - r.left, y: e.clientY - r.top }; h.setPointerCapture(e.pointerId); });
  h.addEventListener("pointermove", e => { if (!d) return;
    w.el.style.left = Math.max(0, Math.min(innerWidth - 120, e.clientX - d.x)) + "px"; w.el.style.top = Math.max(0, Math.min(innerHeight - 40, e.clientY - d.y)) + "px"; });
  h.addEventListener("pointerup", () => { d = null; });
}
addEventListener("pagehide", () => TW.wins.forEach(w => w.id && !w.dead && fetch(`/api/terminal/${w.id}`,   // 페이지를 떠나면 연결도 닫는다
  { method: "DELETE", keepalive: true, headers: S.token ? { Authorization: `Bearer ${S.token}` } : {} }).catch(() => {})));

/** 콘솔 명령: ssh  |  ssh [계정@]IP [포트] */
async function terminalCommand(arg) {
  const r = await api("/api/terminal"); TW.ports = r.ports;
  const m = (arg || "").trim().match(/^(?:([^@\s]+)@)?(\S+)(?:\s+(\d+))?$/);
  if (!m) {
    return `<div class="msg"><b>접속할 수 있는 기기</b> <span class="dim">(토폴로지에서 SIEM 과 와이어로 이어진 기기)</span>${r.targets.length ? r.targets.map(t =>
      `<br>${(t.ips || [t.ip]).map(ip => `<span class="link" data-cmd="ssh ${esc(ip)}">${esc(ip)}</span>`).join(" ")} ${esc(t.label)} <span class="dim">· ${esc(t.path.join(" → "))}</span>`).join("")
      : `<br><span class="c-high">없음 — dashboard topology 에서 기기를 SIEM 과 와이어로 잇고 저장하세요</span>`}
      <br><span class="dim">사용법: ssh 계정@IP [포트]</span></div>`;
  }
  const t0 = r.targets.find(x => (x.ips || [x.ip]).includes(m[2])), t = t0 && { ...t0, ip: m[2] };
  if (!t) return `<div class="msg c-high">${esc(m[2])} 는 토폴로지에서 SIEM 과 와이어로 연결돼 있지 않습니다 — <span class="link" data-cmd="dashboard topology">dashboard topology</span></div>`;
  openTerminal(t, m[1] ? { login: m[1], port: +m[3] || 22 } : {});
  return `<div class="msg acc">터미널 창을 열었습니다 → ${esc(t.label || t.ip)} (${esc(t.path.join(" → "))})</div>`;
}
