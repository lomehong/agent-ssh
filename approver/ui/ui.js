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
  currentView = name;
  for (const section of document.querySelectorAll('.view')) {
    section.classList.toggle('hidden', section.id !== `view-${name}`);
  }
  for (const btn of navItems) {
    btn.classList.toggle('active', btn.dataset.view === name);
  }
  // 视图数据拉取（T-21b/c/d）：operator 面数据须解锁后拉取——未解锁时
  // 显示引导而非报错（截图事故：四页齐刷 not unlocked）。
  if (!unlocked) return;
  if (name === 'history' && typeof loadHistory === 'function' && !historyState.loaded) loadHistory();
  if (name === 'audit') { auditState.loaded = true; loadAudit(true); }
  if (name === 'connections') loadConnections();
  if (name === 'settings') { loadSettings(); renderAgents(); }
}

let currentView = 'approvals';
function refreshCurrentView(force = false) {
  if (force) {
    historyState.loaded = false;
    auditState.loaded = false;
  }
  showView(currentView);
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

// ─── 锁屏/解锁（T-17.5d 验收 3 + T-21 截图修正）：解锁是**控制台级门**——
// 全屏覆盖层（历史/审计/连接/设置都是 operator 面，未解锁时整窗只有锁屏），
// 而非审批视图的局部表单（截图事故：其余四页齐刷 "not unlocked"）。
let unlocked = false;

function showLockForm(reason) {
  unlocked = false;
  const overlay = document.getElementById('lock-overlay');
  overlay.classList.remove('hidden');
  document.getElementById('lock-title').textContent = '';
  document.getElementById('lock-title').appendChild(
    document.createTextNode(reason || '输入 operator 口令解锁控制台'),
  );
  const input = document.getElementById('lock-password');
  const msg = document.getElementById('lock-msg');
  msg.textContent = '';
  input.value = '';
  input.focus();
}

function wireLockForm() {
  const input = document.getElementById('lock-password');
  const btn = document.getElementById('lock-btn');
  const msg = document.getElementById('lock-msg');
  const submit = async () => {
    try {
      await invoke('unlock', { password: input.value });
      unlocked = true;
      document.getElementById('lock-overlay').classList.add('hidden');
      // 解锁后刷新当前视图数据（各视图首拉在解锁前被跳过）。
      refreshCurrentView(true);
    } catch (err) {
      msg.textContent = '';
      const m = typeof err === 'string' ? err : (err?.message ?? String(err));
      msg.appendChild(document.createTextNode(`解锁失败: ${m}`));
    }
  };
  btn.addEventListener('click', submit);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
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
  wireLockForm();
  showLockForm('输入 operator 口令解锁控制台');
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


// ─── 设置页（T-21e/g） ───────────────────────────────────────────────────────

const pwResult = document.getElementById('pw-result');

document.getElementById('set-autostart')?.addEventListener('change', async (e) => {
  const box = e.target;
  try {
    const res = await invoke('autostart_set', { enable: box.checked });
    box.checked = res.enabled === true;
  } catch (err) {
    box.checked = !box.checked;
    pwResult.textContent = '';
    pwResult.appendChild(document.createTextNode(`自启设置失败: ${typeof err === 'string' ? err : err?.message}`));
  }
});

document.getElementById('pw-change')?.addEventListener('click', async () => {
  const oldPw = document.getElementById('pw-old').value;
  const newPw = document.getElementById('pw-new').value;
  pwResult.textContent = '';
  if (newPw.length < 8) { pwResult.appendChild(document.createTextNode('新口令至少 8 字符')); return; }
  try {
    await invoke('change_password', { oldPassword: oldPw, newPassword: newPw });
    pwResult.appendChild(document.createTextNode('口令已更换——所有会话已失效，请用新口令重新解锁。'));
    // 本窗口会话已失效：回锁。
    showLockForm('口令已更换，请用新口令解锁');
  } catch (err) {
    pwResult.appendChild(document.createTextNode(`更换失败: ${typeof err === 'string' ? err : err?.message}`));
  }
});

async function loadSurfaces() {
  const el = document.getElementById('surfaces-list');
  try {
    const st = await invoke('host_status');
    el.textContent = '';
    for (const s of st?.surfaces ?? []) {
      const row = document.createElement('p');
      row.className = 'meta';
      row.appendChild(document.createTextNode(`${s.surface}: ${s.online ? '在线' : '离线/未用'}`));
      el.appendChild(row);
    }
    el.appendChild(textNode('p', 'meta', `版本: ${st.version ?? '?'} · 端口: ${st.port ?? '?'} · 队列: ${st.queueDir ?? ''}`));
  } catch (err) {
    el.textContent = '';
    el.appendChild(textNode('p', 'meta', `加载失败（需解锁）: ${typeof err === 'string' ? err : err?.message}`));
  }
}

async function loadSettings() {
  try {
    const res = await invoke('autostart_status');
    document.getElementById('set-autostart').checked = res.enabled === true;
  } catch {}
  loadSurfaces();
}

async function renderAgents() {
  const list = document.getElementById('agents-list');
  list.textContent = '';
  let hosts;
  try {
    hosts = (await invoke('agents_scan'))?.hosts ?? [];
  } catch (err) {
    list.appendChild(textNode('p', 'meta', `扫描失败（需解锁）: ${typeof err === 'string' ? err : err?.message}`));
    return;
  }
  for (const h of hosts) {
    const card = document.createElement('section');
    card.className = 'card';
    card.appendChild(textNode('p', 'meta', `${h.detected ? h.name : `${h.name}（未检测到安装）`} · ${h.configPath}`));
    if (h.note) card.appendChild(textNode('p', 'meta', h.note));
    const row = document.createElement('div');
    row.className = 'row';
    if (!h.supported) {
      row.appendChild(textNode('span', 'meta', '不支持自动接入——按上述路径手工配置'));
    } else if (h.configured) {
      card.appendChild(textNode('p', 'meta', '✓ 已接入'));
      const remove = document.createElement('button');
      remove.className = 'reject';
      remove.appendChild(document.createTextNode('移除条目'));
      remove.addEventListener('click', async () => {
        try {
          await invoke('agents_remove', { id: h.id });
          remove.replaceWith(textNode('span', 'meta', '已移除'));
        } catch (err) {
          card.appendChild(textNode('p', 'meta', `移除失败: ${typeof err === 'string' ? err : err?.message}`));
        }
      });
      row.appendChild(remove);
    } else {
      const btn = document.createElement('button');
      btn.className = 'approve';
      btn.appendChild(document.createTextNode(h.detected ? '一键接入' : '仍要写入'));
      btn.addEventListener('click', async () => {
        try {
          const res = await invoke('agents_configure', { id: h.id });
          btn.replaceWith(textNode('span', 'meta', `✓ 已写入（备份: ${res.backupPath ?? '无（新建文件）'}）——重启该宿主后生效`));
        } catch (err) {
          card.appendChild(textNode('p', 'meta', `写入失败: ${typeof err === 'string' ? err : err?.message}`));
        }
      });
      row.appendChild(btn);
    }
    card.appendChild(row);
    list.appendChild(card);
  }
}

document.getElementById('host-restart')?.addEventListener('click', async () => {
  await invoke('restart_host');
  setTimeout(refreshHostStatus, 4000);
});
document.getElementById('host-openlog')?.addEventListener('click', () => invoke('open_host_log'));

