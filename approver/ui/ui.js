// agent-ssh 控制台（v2 骨架，T-21a）：多视图导航 + 审批视图迁移。
//
// K8-③ 红线延续：全部 DOM 经 createElement/createTextNode 构建，
// 零 innerHTML/insertAdjacentHTML/eval——命令全文永不进入 HTML 解析器。
// 视图路由：nav 按钮 ↔ section 切换（hash 不用——CSP/文件协议下无收益）。
// 未实施视图（history/audit/connections/settings）显示占位说明，随 T-21b~e 落地。

const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

// 独立审批弹窗（T-23 澄清）：**每条审批请求一个独立窗口**（飞书单卡体验）——
// label=approval-<请求id>，窗口内只渲染该请求的单卡；决定或过期自动关窗。
const winLabel = window.__TAURI__?.window?.getCurrentWindow?.()?.label ?? '';
const isPopup = winLabel.startsWith('approval-');
const popupId = isPopup ? winLabel.slice('approval-'.length) : null;

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
// 左侧菜单收起/展开：折叠=窄条只显图标。
document.getElementById('nav-toggle')?.addEventListener('click', () => {
  document.body.classList.toggle('nav-collapsed');
});

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

async function renderSingleCard(id) {
  try {
    const res = await invoke('list_pending');
    const p = (res?.pending ?? []).find((x) => x.id === id && x.status === 'pending');
    if (p === undefined) {
      document.getElementById('queue')?.appendChild(textNode('p', 'meta', '该请求已决定或过期——本窗口即将关闭。'));
      setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(), 2500);
      return;
    }
    const card = renderCard(p);
    document.getElementById('queue')?.appendChild(card);
    // 过期自动关窗：倒计时终点后 1 秒关（该请求已不可能再批）。
    const expiresAt = Date.parse(p.expiresAt ?? '');
    if (!Number.isNaN(expiresAt)) {
      setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(),
        Math.max(0, expiresAt - Date.now() + 1000));
    }
  } catch (err) {
    document.getElementById('queue')?.appendChild(textNode('p', 'meta', `拉取失败: ${typeof err === 'string' ? err : err?.message}`));
  }
}

// ─── 审批列表（主人 2026-10-17 交互重构：待决+已决+过期统一列表，
//      待决行点击弹独立审批窗；实时推送到达时 Rust 自动弹窗） ─────────────────

const historyList = document.getElementById('history-list');
let approvalsLoaded = false;

async function loadApprovalsList() {
  if (!invoke) return;
  historyList.textContent = '';
  let pendingItems = [];
  let decidedItems = [];
  try {
    const [p, d] = await Promise.all([
      invoke('list_pending'),
      invoke('approval.history', { limit: 200 }),
    ]);
    pendingItems = p?.pending ?? [];
    decidedItems = d?.items ?? [];
  } catch (err) {
    if (handleNotUnlocked(err)) return;
    historyList.appendChild(textNode('p', 'meta', `加载失败: ${typeof err === 'string' ? err : err?.message}`));
    return;
  }
  // 合并倒序：pending 最前（待办优先），已决按 decidedAt 倒序。
  const rows = [
    ...pendingItems.map((p) => ({ ...p, _state: 'pending' })),
    ...decidedItems.map((p) => ({ ...p, _state: p.status })),
  ];
  if (rows.length === 0) {
    const box = document.createElement('div');
    box.className = 'empty-state';
    box.appendChild(textNode('div', 'glyph', '~'));
    box.appendChild(textNode('p', 'headline', '暂无审批记录'));
    box.appendChild(textNode('p', 'sub', 'Agent 触发需要人工批准的命令时会出现在这里。'));
    historyList.appendChild(box);
    return;
  }
  for (const p of rows) historyList.appendChild(approvalRow(p));
}

function approvalRow(p) {
  const stateText = { pending: '待审批', approved: '已批准', rejected: '已拒绝', expired: '已过期' }[p._state ?? p.status] ?? (p.status ?? '');
  const stateClass = { pending: 'pending-c', approved: 'allowed', rejected: 'denied', expired: '' }[p._state ?? p.status] ?? '';
  const row = document.createElement('div');
  row.className = 'audit-row';
  if ((p._state ?? p.status) === 'pending') row.classList.add('pending-c');
  row.appendChild(textNode('p', 't', `${stateText} · ${p.commandClass ?? ''} · ${p.profile ?? ''}`));
  const cmd = document.createElement('div');
  cmd.className = 'cmd';
  cmd.appendChild(document.createTextNode(p.command ?? ''));
  row.appendChild(cmd);
  const who = p._state === 'pending' ? '等待人工决定' : `决定人: ${p.decidedBy ?? '-'}`;
  row.appendChild(textNode('p', 't', `${p.decidedAt ?? p.createdAt ?? ''} · ${who}`));
  if ((p._state ?? p.status) === 'pending') {
    row.style.cursor = 'pointer';
    row.title = '点击打开独立审批窗';
    row.addEventListener('click', async () => {
      try {
        await invoke('open_approval_window', { id: p.id });
      } catch (err) {
        showFatal(`打开审批窗失败: ${typeof err === 'string' ? err : err?.message}`);
      }
    });
  }
  return row;
}

/** 推送事件统一入口：刷新列表 + 红点（弹窗由 Rust 侧自动建/显）。 */
async function onApprovalEvent(payload) {
  approvalsLoaded = false;
  const pendingNow = payload && payload.id && payload._state !== 'settled' && payload.status === 'pending';
  approvalsDot.classList.toggle('hidden', !pendingNow);
  if (currentView === 'approvals') await loadApprovalsList();
}

async function main() {
  showView('approvals');
  refreshHostStatus();
  if (isPopup) {
    document.body.classList.add('popup-mode');
    await renderSingleCard(popupId);
    return;
  }
  if (!invoke || !listen) {
    showFatal('Tauri 桥不可用（纯浏览模式，无审批功能）');
    return;
  }
  try {
    await listen('approval-pending', (event) => onApprovalEvent(event.payload));
    await listen('approval-settled', (event) => onApprovalEvent(event.payload));
  } catch (err) {
    showFatal(`事件订阅失败: ${err?.message ?? err}`);
  }
  await loadApprovalsList();
}

main();
