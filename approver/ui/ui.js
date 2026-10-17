// agent-ssh 控制台（v2 骨架，T-21a）：多视图导航 + 审批视图迁移。
//
// K8-③ 红线延续：全部 DOM 经 createElement/createTextNode 构建，
// 零 innerHTML/insertAdjacentHTML/eval——命令全文永不进入 HTML 解析器。
// 视图路由：nav 按钮 ↔ section 切换（hash 不用——CSP/文件协议下无收益）。
// 未实施视图（history/audit/connections/settings）显示占位说明，随 T-21b~e 落地。

const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

// ─── 视图路由 ────────────────────────────────────────────────────────────────

const navItems = Array.from(document.querySelectorAll('.nav-item'));

function showView(name) {
  for (const section of document.querySelectorAll('.view')) {
    section.classList.toggle('hidden', section.id !== `view-${name}`);
  }
  for (const btn of navItems) {
    btn.classList.toggle('active', btn.dataset.view === name);
  }
  // 首次进入视图拉取（T-21b/c/d；load* 声明在文件后部，调用时已定义）。
  if (name === 'history' && typeof loadHistory === 'function' && !historyState.loaded) loadHistory();
  if (name === 'audit' && !auditState.loaded) { auditState.loaded = true; loadAudit(true); }
  if (name === 'connections') loadConnections();
}

for (const btn of navItems) {
  btn.addEventListener('click', () => showView(btn.dataset.view));
}

// ─── Host 状态（T-20：ping 探测，导航底部常显） ─────────────────────────────

const hostStatusEl = document.getElementById('host-status');
async function refreshHostStatus() {
  let text;
  if (!invoke) {
    text = 'Host 状态：桥不可用';
  } else {
    try {
      await invoke('ping');
      text = 'Host 状态：在线';
    } catch {
      text = 'Host 状态：离线/未连接';
    }
  }
  hostStatusEl.textContent = '';
  hostStatusEl.appendChild(document.createTextNode(text));
}
setInterval(refreshHostStatus, 10_000);

// ─── 审批视图（自 v1 迁移，逻辑零回归） ─────────────────────────────────────

const queue = document.getElementById('queue');
const cards = new Map(); // id → { card, countdownTimer }
const approvalsDot = document.getElementById('nav-approvals-dot');

function textNode(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.appendChild(document.createTextNode(text));
  return el;
}

function renderCard(payload) {
  const card = document.createElement('section');
  card.className = 'card';

  card.appendChild(textNode('p', 'meta', `profile: ${payload.profile ?? ''}`));
  card.appendChild(textNode('p', 'meta', `类别: ${payload.commandClass ?? ''}`));

  const cmd = document.createElement('pre');
  cmd.className = 'command';
  cmd.appendChild(document.createTextNode(payload.command ?? ''));
  card.appendChild(cmd);

  if (payload.challenge) {
    const row = document.createElement('div');
    row.className = 'challenge-row';
    const label = document.createElement('label');
    label.appendChild(document.createTextNode('校验码: '));
    const input = document.createElement('input');
    input.inputMode = 'numeric';
    input.maxLength = 4;
    input.autocomplete = 'off';
    row.appendChild(label);
    row.appendChild(input);
    card.appendChild(row);
    card.dataset.challenge = payload.challenge;
    card.__challengeInput = input;
  } else {
    card.appendChild(textNode('p', 'meta', '（此请求无需校验码）'));
  }

  const countdown = document.createElement('p');
  countdown.className = 'countdown';
  card.appendChild(countdown);
  card.__countdown = countdown;

  const row = document.createElement('div');
  row.className = 'row';
  const reject = document.createElement('button');
  reject.className = 'reject';
  reject.appendChild(document.createTextNode('拒绝'));
  const approve = document.createElement('button');
  approve.className = 'approve';
  approve.appendChild(document.createTextNode('批准'));
  reject.addEventListener('click', () => decide(card, payload, false));
  approve.addEventListener('click', () => decide(card, payload, true));
  row.appendChild(reject);
  row.appendChild(approve);
  card.appendChild(row);

  return card;
}

function startCountdown(card, payload) {
  const expiresAt = Date.parse(payload.expiresAt ?? '');
  if (Number.isNaN(expiresAt)) return;
  const tick = () => {
    const left = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
    card.__countdown.textContent = `过期剩余 ${left}s`;
  };
  tick();
  card.__countdownTimer = setInterval(tick, 1000);
}

function decide(card, payload, approved) {
  if (!invoke) {
    card.appendChild(textNode('p', 'meta', '桥未就绪，无法提交决定'));
    return;
  }
  const challenge = card.__challengeInput ? card.__challengeInput.value : undefined;
  invoke('decide', {
    id: payload.id ?? '',
    decision: approved ? 'approved' : 'rejected',
    face: 'desktop',
    challenge: challenge ?? undefined,
  })
    .then(() => removeCard(payload.id))
    .catch((err) => {
      const msg = typeof err === 'string' ? err : (err?.message ?? String(err));
      card.appendChild(textNode('p', 'meta', `决定失败: ${msg}`));
    });
}

function removeCard(id) {
  const entry = cards.get(id);
  if (entry) {
    clearInterval(entry.card.__countdownTimer);
    entry.card.remove();
    cards.delete(id);
  }
  if (cards.size === 0) showEmptyHint();
  refreshApprovalsDot();
}

function showEmptyHint() {
  const hint = document.createElement('p');
  hint.id = 'empty-hint';
  hint.appendChild(document.createTextNode('等待审批请求…（未连接或队列为空）'));
  queue.appendChild(hint);
}

function hideEmptyHint() {
  document.getElementById('empty-hint')?.remove();
}

function refreshApprovalsDot() {
  approvalsDot.classList.toggle('hidden', cards.size === 0);
}

function onPending(payload) {
  hideEmptyHint();
  if (cards.has(payload.id)) return; // 多请求堆叠去重
  const card = renderCard(payload);
  queue.appendChild(card);
  cards.set(payload.id, { card });
  startCountdown(card, payload);
  refreshApprovalsDot();
  // 新请求到达：即使不在审批视图也可见（导航红点 + toast 由 Rust 侧发）。
  showView('approvals');
}

function onSettled(payload) {
  removeCard(payload.id);
}

// ─── 锁屏/解锁（T-17.5d 验收 3）：locked 事件或初始态显示口令表单 ───
function showLockForm(reason) {
  const old = document.getElementById('lock-form');
  if (old) old.remove();
  const form = document.createElement('section');
  form.className = 'card';
  form.id = 'lock-form';
  form.appendChild(textNode('p', 'meta', reason || '输入 operator 口令解锁审批面'));
  const row = document.createElement('div');
  row.className = 'challenge-row';
  const input = document.createElement('input');
  input.type = 'password';
  input.autocomplete = 'off';
  row.appendChild(input);
  const btn = document.createElement('button');
  btn.className = 'approve';
  btn.appendChild(document.createTextNode('解锁'));
  btn.addEventListener('click', async () => {
    try {
      await invoke('unlock', { password: input.value });
      form.remove();
    } catch (err) {
      const msg = typeof err === 'string' ? err : (err?.message ?? String(err));
      form.appendChild(textNode('p', 'meta', `解锁失败: ${msg}`));
    }
  });
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') btn.click(); });
  row.appendChild(btn);
  form.appendChild(row);
  queue.insertBefore(form, queue.firstChild);
  input.focus();
}

async function main() {
  showView('approvals');
  refreshHostStatus();
  if (!invoke || !listen) {
    queue.appendChild(textNode('p', 'meta', 'Tauri 桥不可用（纯浏览模式，无审批功能）'));
    return;
  }
  await listen('approval.pending', (event) => onPending(event.payload));
  await listen('approval.settled', (event) => onSettled(event.payload));
  await listen('locked', (event) => showLockForm(`会话已回锁：${event.payload?.reason ?? ''}`));
  showLockForm('输入 operator 口令解锁审批面');
}

main();


// ─── 历史审批视图（T-21b）：operator 解锁后可拉取；过滤 + 分页 ───────────────

const historyState = { items: [], filter: 'all', loaded: false };

function historyRow(p) {
  const card = document.createElement('section');
  card.className = 'card';
  const statusText = { approved: '已批准', rejected: '已拒绝', expired: '已过期' }[p.status] ?? p.status;
  card.appendChild(textNode('p', 'meta', `${statusText} · ${p.commandClass ?? ''} · ${p.profile ?? ''}`));
  const cmd = document.createElement('pre');
  cmd.className = 'command';
  cmd.appendChild(document.createTextNode(p.command ?? ''));
  card.appendChild(cmd);
  const decidedAt = p.decidedAt ?? p.createdAt ?? '';
  card.appendChild(textNode('p', 'meta', `时间: ${decidedAt}`));
  if (p.decidedBy) card.appendChild(textNode('p', 'meta', `决定人: ${p.decidedBy}`));
  return card;
}

function renderHistory() {
  const list = document.getElementById('history-list');
  list.textContent = '';
  const shown = historyState.items.filter((p) => historyState.filter === 'all' || p.status === historyState.filter);
  if (shown.length === 0) {
    list.appendChild(textNode('p', 'meta', '暂无记录（operator 解锁后自动拉取）'));
    return;
  }
  for (const p of shown) list.appendChild(historyRow(p));
}

async function loadHistory() {
  if (!invoke) return;
  try {
    const res = await invoke('history', { offset: historyState.items.length, limit: 50 });
    const items = Array.isArray(res?.items) ? res.items : [];
    historyState.items.push(...items);
    historyState.loaded = true;
    renderHistory();
    const more = document.getElementById('history-more');
    more.classList.toggle('hidden', historyState.items.length >= (res?.total ?? 0));
  } catch (err) {
    const msg = typeof err === 'string' ? err : (err?.message ?? String(err));
    const list = document.getElementById('history-list');
    list.textContent = '';
    list.appendChild(textNode('p', 'meta', `加载失败: ${msg}`));
  }
}

for (const btn of document.querySelectorAll('#history-filters .filter')) {
  btn.addEventListener('click', () => {
    for (const b of document.querySelectorAll('#history-filters .filter')) b.classList.remove('active');
    btn.classList.add('active');
    historyState.filter = btn.dataset.f;
    renderHistory();
  });
}
document.getElementById('history-more').addEventListener('click', () => loadHistory());



// ─── 无边框窗控（T-21：自定义最小化/最大化/关闭=隐藏到托盘） ──────────────────

const win = window.__TAURI__?.window?.getCurrentWindow?.();
document.getElementById('win-min')?.addEventListener('click', () => win?.minimize());
document.getElementById('win-max')?.addEventListener('click', () => win?.toggleMaximize());
// 关闭=隐藏到托盘（托盘常驻语义；真正退出走托盘「退出（停 Host）」）。
document.getElementById('win-close')?.addEventListener('click', () => win?.hide());

// ─── 审计视图（T-21c） ───────────────────────────────────────────────────────

const auditState = { offsetTail: 0, loaded: false };
const auditList = document.getElementById('audit-list');
const auditMore = document.getElementById('audit-more');
const auditStatsEl = document.getElementById('audit-stats');

function auditRow(rec) {
  const row = document.createElement('div');
  row.className = 'audit-row';
  const cls = rec.decision === 'deny' ? 'denied' : rec.decision === 'allow' ? 'allowed' : 'pending-c';
  row.appendChild(textNode('p', 't', `${rec.timestamp ?? ''} · ${rec.profile ?? ''} · ${rec.decision ?? ''} · ${rec.ruleId ?? ''}`));
  const cmd = document.createElement('div');
  cmd.className = `cmd ${cls}`;
  cmd.appendChild(document.createTextNode(rec.command ?? ''));
  row.appendChild(cmd);
  row.appendChild(textNode('p', 't', `approver: ${rec.approver ?? '-'} · exit: ${rec.exitCode ?? '-'} · ${rec.durationMs ?? '-'}ms`));
  return row;
}

async function loadAudit(reset = false) {
  if (!invoke) return;
  if (reset) { auditState.offsetTail = 0; auditList.textContent = ''; }
  try {
    const res = await invoke('audit_query', {
      offsetTail: auditState.offsetTail,
      limit: 50,
      profile: document.getElementById('audit-profile').value || null,
      keyword: document.getElementById('audit-keyword').value || null,
      decision: document.getElementById('audit-decision').value || null,
      commandClass: null,
      ruleId: null,
    });
    const items = Array.isArray(res?.items) ? res.items : [];
    for (const rec of items) auditList.appendChild(auditRow(rec));
    auditState.offsetTail += items.length;
    auditMore.classList.toggle('hidden', items.length < 50);
    try {
      const st = await invoke('audit_stats');
      auditStatsEl.textContent = '';
      auditStatsEl.appendChild(document.createTextNode(`今日 ${st.today} 条 · 拒绝 ${st.denied} · 审批决定 ${st.approvalsDecided}`));
    } catch {}
  } catch (err) {
    const msg = typeof err === 'string' ? err : (err?.message ?? String(err));
    auditList.textContent = '';
    auditList.appendChild(textNode('p', 'meta', `加载失败: ${msg}`));
  }
}

document.getElementById('audit-apply')?.addEventListener('click', () => loadAudit(true));
auditMore?.addEventListener('click', () => loadAudit(false));

// ─── 连接与配额视图（T-21d） ────────────────────────────────────────────────

async function loadConnections() {
  if (!invoke) return;
  const connList = document.getElementById('conn-list');
  const quotaList = document.getElementById('quota-list');
  try {
    const conns = await invoke('connections');
    connList.textContent = '';
    for (const c of conns?.connections ?? []) {
      const card = document.createElement('section');
      card.className = 'card';
      card.appendChild(textNode('p', 'meta', `${c.profile} → ${c.user ?? ''}@${c.host ?? ''}:${c.port ?? ''}`));
      card.appendChild(textNode('p', 'meta', `状态: ${c.status ?? '?'} · 会话 ${c.sessions ?? 0} · PTY ${c.ptySessions ?? 0}`));
      connList.appendChild(card);
    }
    if ((conns?.connections ?? []).length === 0) connList.appendChild(textNode('p', 'meta', '无连接记录'));
  } catch (err) {
    connList.textContent = '';
    connList.appendChild(textNode('p', 'meta', `加载失败: ${typeof err === 'string' ? err : err?.message}`));
  }
  try {
    const qs = await invoke('quota_snapshot');
    quotaList.textContent = '';
    for (const q of qs?.quotas ?? []) {
      const row = document.createElement('p');
      row.className = 'meta';
      row.appendChild(document.createTextNode(`${q.profile}: ${q.used}${q.limit ? ` / ${q.limit}` : '（不限）'} 条`));
      quotaList.appendChild(row);
    }
  } catch {}
}
