// agent-ssh 控制台（v2 骨架，T-21a）：多视图导航 + 审批视图迁移。
//
// K8-③ 红线延续：全部 DOM 经 createElement/createTextNode 构建，
// 零 innerHTML/insertAdjacentHTML/eval——命令全文永不进入 HTML 解析器。
// 视图路由：nav 按钮 ↔ section 切换（hash 不用——CSP/文件协议下无收益）。
// 未实施视图（history/audit/connections/settings）显示占位说明，随 T-21b~e 落地。

const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

// 全局错误可见化：Webview console 不可见，未捕获错误必须让用户/运维看到。
window.addEventListener('error', (e) => showFatal(`脚本错误: ${e.message}`));
window.addEventListener('unhandledrejection', (e) => showFatal(`未处理的异步错误: ${e.reason?.message ?? e.reason}`));
function showFatal(text) {
  let bar = document.getElementById('fatal-bar');
  if (bar === null) {
    bar = document.createElement('div');
    bar.id = 'fatal-bar';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:999;background:#6e2f27;color:#fbeae7;font:12px monospace;padding:6px 12px;';
    (document.body ?? document.documentElement).appendChild(bar);
  }
  bar.textContent = '';
  bar.appendChild(document.createTextNode(text));
}

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
  // 视图数据拉取（T-21b/c/d）：operator 面数据须解锁后拉取。未解锁时
  // 渲染解锁引导空态 + 唤起锁屏（截图事故修正：静默空白比报错更糟）。
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
  hideEmptyHint(); // 幂等（孤儿 settled 连续到达时不叠加空态框——主人截图定性）
  const box = document.createElement('div');
  box.className = 'empty-state';
  box.id = 'empty-hint';
  const glyph = textNode('div', 'glyph', '~');
  const headline = textNode('p', 'headline', '队列干净');
  const sub = textNode('p', 'sub', '新的审批请求到达时会推送到这里，并在托盘提示。');
  box.append(glyph, headline, sub);
  queue.appendChild(box);
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

function handleNotUnlocked(err) {
  // 单令牌模型下不应出现 not unlocked（矩阵已放行 agent 面）——出现即异常，
  // 显示提示并保持数据面安静（防御性）。
  const m = typeof err === 'string' ? err : (err?.message ?? String(err));
  return m.includes('not unlocked');
}

function renderUnlockHint(name) {
  const titles = { history: 'history-list', audit: 'audit-list', connections: 'conn-list' };
  const target = document.getElementById(titles[name] ?? 'content');
  if (target === null) return;
  target.textContent = '';
  const box = document.createElement('div');
  box.className = 'empty-state';
  box.appendChild(textNode('div', 'glyph', '···'));
  box.appendChild(textNode('p', 'headline', '数据不可用'));
  box.appendChild(textNode('p', 'sub', '与 Host 的连接异常，请检查 Host 守护是否在线。'));
  target.appendChild(box);
}

async function main() {
  showView('approvals');
  refreshHostStatus();
  if (!invoke || !listen) {
    queue.appendChild(textNode('p', 'meta', 'Tauri 桥不可用（纯浏览模式，无审批功能）'));
    return;
  }
  try {
    await listen('approval-pending', (event) => onPending(event.payload));
    await listen('approval-settled', (event) => onSettled(event.payload));
    await listen('locked', () => showFatal('会话已回锁（单令牌模型下不应发生）'));
  } catch (err) {
    showFatal(`事件订阅失败: ${err?.message ?? err}`);
  }

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
    const box = document.createElement('div');
    box.className = 'empty-state';
    box.appendChild(textNode('div', 'glyph', '≈'));
    box.appendChild(textNode('p', 'headline', '暂无审批记录'));
    box.appendChild(textNode('p', 'sub', '批准、拒绝或过期的请求会留在这里备查。'));
    list.appendChild(box);
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
  const edge = rec.decision === 'deny' ? 'denied' : rec.decision === 'allow' ? 'allowed' : 'pending-c';
  row.classList.add(edge);
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
    if (handleNotUnlocked(err)) return;
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
    if ((conns?.connections ?? []).length === 0) {
      const box = document.createElement('div');
      box.className = 'empty-state';
      box.appendChild(textNode('div', 'glyph', '→'));
      box.appendChild(textNode('p', 'headline', '还没有 SSH 连接'));
      box.appendChild(textNode('p', 'sub', 'Agent 第一次对某台主机执行命令时会在这里建立连接。'));
      connList.appendChild(box);
    }
  } catch (err) {
    if (handleNotUnlocked(err)) return;
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
    if (handleNotUnlocked(err)) return;
    el.textContent = '';
    el.appendChild(textNode('p', 'meta', `加载失败: ${typeof err === 'string' ? err : err?.message}`));
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
    if (handleNotUnlocked(err)) return;
    list.appendChild(textNode('p', 'meta', `扫描失败: ${typeof err === 'string' ? err : err?.message}`));
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



// ─── 主机管理（主人指令：配置远程 SSH 服务器的 ip/端口/用户/密码/密钥） ──────

const hostForm = {
  editing: null, // 正在编辑的 profile 名（null=新建）
};

function renderHosts(profiles) {
  const list = document.getElementById('hosts-list');
  list.textContent = '';
  if ((profiles ?? []).length === 0) {
    const box = document.createElement('div');
    box.className = 'empty-state';
    box.appendChild(textNode('div', 'glyph', '⌘'));
    box.appendChild(textNode('p', 'headline', '还没有配置主机'));
    box.appendChild(textNode('p', 'sub', '点「添加主机」配置第一台远程 SSH 服务器（IP/端口/用户/密码或密钥）。'));
    list.appendChild(box);
    return;
  }
  for (const p of profiles) {
    const row = document.createElement('div');
    row.className = 'hosts-row';
    const info = document.createElement('div');
    info.className = 'info';
    info.appendChild(textNode('div', 'name', p.name));
    const authText = p.auth === 'keychain' ? '密码（凭据管理器）' : p.auth === 'key' ? `密钥 ${p.keyRef ?? ''}` : p.auth;
    info.appendChild(textNode('div', 'detail', `${p.user}@${p.host}:${p.port ?? 22} · ${authText}`));
    row.appendChild(info);
    const edit = document.createElement('button');
    edit.appendChild(document.createTextNode('编辑'));
    edit.addEventListener('click', () => openHostForm(p));
    row.appendChild(edit);
    const remove = document.createElement('button');
    remove.className = 'reject';
    remove.appendChild(document.createTextNode('删除'));
    remove.addEventListener('click', async () => {
      if (!confirm(`删除主机 \"${p.name}\"？配置文件会自动备份。`)) return;
      try {
        await invoke('profiles_remove', { name: p.name });
        await loadHosts();
        loadConnections();
      } catch (err) {
        alert(`删除失败: ${typeof err === 'string' ? err : err?.message}`);
      }
    });
    row.appendChild(remove);
    list.appendChild(row);
  }
}

async function loadHosts() {
  if (!invoke) return;
  const list = document.getElementById('hosts-list');
  try {
    const res = await invoke('profiles_list');
    renderHosts(res?.profiles ?? []);
  } catch (err) {
    if (handleNotUnlocked(err)) return;
    list.textContent = '';
    list.appendChild(textNode('p', 'meta', `加载失败: ${typeof err === 'string' ? err : err?.message}`));
  }
}

function openHostForm(p) {
  hostForm.editing = p ? p.name : null;
  document.getElementById('host-form-title').textContent = '';
  document.getElementById('host-form-title').appendChild(
    document.createTextNode(p ? `编辑主机: ${p.name}` : '添加主机'),
  );
  document.getElementById('hf-name').value = p?.name ?? '';
  document.getElementById('hf-name').disabled = Boolean(p); // 名称是主键，编辑时锁定
  document.getElementById('hf-host').value = p?.host ?? '';
  document.getElementById('hf-port').value = String(p?.port ?? 22);
  document.getElementById('hf-user').value = p?.user ?? '';
  document.getElementById('hf-auth').value = p?.auth === 'key' ? 'key' : 'password';
  document.getElementById('hf-secret').value = '';
  document.getElementById('hf-secret-label').childNodes[0]?.remove?.();
  document.getElementById('hf-secret-label').textContent = '';
  document.getElementById('hf-secret-label').appendChild(document.createTextNode(p?.auth === 'key' ? '私钥路径（留空=不变）' : '密码（留空=不变）'));
  document.getElementById('hf-group').value = p?.group ?? '';
  document.getElementById('hf-result').textContent = '';
  document.getElementById('host-form-card').classList.remove('hidden');
  document.getElementById('host-form-card').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

document.getElementById('host-add')?.addEventListener('click', () => openHostForm(null));
document.getElementById('hosts-refresh')?.addEventListener('click', () => loadHosts());
document.getElementById('hf-cancel')?.addEventListener('click', () => document.getElementById('host-form-card').classList.add('hidden'));
document.getElementById('hf-auth')?.addEventListener('change', (e) => {
  const isKey = e.target.value === 'key';
  const label = document.getElementById('hf-secret-label');
  label.textContent = '';
  label.appendChild(document.createTextNode(isKey ? '私钥路径' : '密码'));
  const secret = document.getElementById('hf-secret');
  secret.type = isKey ? 'text' : 'password';
  secret.value = '';
});

document.getElementById('hf-save')?.addEventListener('click', async () => {
  const result = document.getElementById('hf-result');
  result.textContent = '';
  const name = document.getElementById('hf-name').value.trim();
  const payload = {
    name,
    host: document.getElementById('hf-host').value.trim(),
    port: Number.parseInt(document.getElementById('hf-port').value, 10) || 22,
    user: document.getElementById('hf-user').value.trim(),
    auth: document.getElementById('hf-auth').value,
    group: document.getElementById('hf-group').value.trim(),
  };
  const secret = document.getElementById('hf-secret').value;
  if (payload.auth === 'password') payload.password = secret;
  if (payload.auth === 'key') payload.keyRef = secret;
  try {
    const res = await invoke('profiles_upsert', { profile: payload });
    result.appendChild(document.createTextNode(`已写入（备份: ${res.backupPath ?? '无'}）。重启 Host 后生效——是否立即重启？`));
    const btn = document.createElement('button');
    btn.className = 'approve small';
    btn.appendChild(document.createTextNode('立即重启 Host'));
    btn.addEventListener('click', async () => {
      await invoke('restart_host');
      result.textContent = '';
      result.appendChild(document.createTextNode('Host 重启中，几秒后配置生效。'));
    });
    result.appendChild(document.createTextNode(' '));
    result.appendChild(btn);
    await loadHosts();
  } catch (err) {
    result.appendChild(document.createTextNode(`保存失败: ${typeof err === 'string' ? err : err?.message}`));
  }
});

// 主机清单并入连接视图刷新链。
const origLoadConnections = loadConnections;
loadConnections = async function () {
  await origLoadConnections();
  await loadHosts();
};
