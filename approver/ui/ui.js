// agent-ssh 控制台（主窗，label=main）。独立审批卡窗由 approval.html+approval.js
// 全权渲染（每请求一窗，label=approval-<请求id>），本文件不负责弹窗。
//
// K8-③ 红线延续：全部 DOM 经 createElement/createTextNode 构建，
// 零 innerHTML/insertAdjacentHTML/eval——命令全文永不进入 HTML 解析器。
// 视图：审批列表 / 审计查看器 / 连接（主机管理+会话配额）/ 设置。
// 纪律：每个视图的数据拉取失败就地显示错误文本（静默空白比报错更糟）；
// 切入视图即重载（控制台先于 Host 就绪打开时，点回视图即恢复）。

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

function textNode(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.appendChild(document.createTextNode(text));
  return el;
}

function errText(err) {
  return typeof err === 'string' ? err : (err?.message ?? String(err));
}

// ─── 视图路由 ────────────────────────────────────────────────────────────────

const navItems = Array.from(document.querySelectorAll('.nav-item'));
const approvalsDot = document.getElementById('nav-approvals-dot');

let currentView = 'approvals';

function showView(name) {
  currentView = name;
  for (const section of document.querySelectorAll('.view')) {
    section.classList.toggle('hidden', section.id !== `view-${name}`);
  }
  for (const btn of navItems) {
    btn.classList.toggle('active', btn.dataset.view === name);
  }
  // 切入视图即取最新；失败由各视图就地显示。
  if (name === 'approvals') loadApprovalsList();
  if (name === 'audit') loadAudit(true);
  if (name === 'connections') loadConnectionsView();
  if (name === 'settings') loadSettingsView();
}

for (const btn of navItems) {
  btn.addEventListener('click', () => showView(btn.dataset.view));
}
// 左侧菜单收起/展开：折叠=窄条只显图标。
document.getElementById('nav-toggle')?.addEventListener('click', () => {
  document.body.classList.toggle('nav-collapsed');
});

// ─── Host 状态（ping 探测，导航底部常显） ────────────────────────────────────

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

// ─── 审批视图：待决+已决统一列表，待决行点击弹独立审批窗 ─────────────────────

const historyList = document.getElementById('history-list');
let approvalFilter = 'all';

async function loadApprovalsList() {
  if (!invoke) return;
  historyList.textContent = '';
  let pendingItems = [];
  let decidedItems = [];
  try {
    const [p, d] = await Promise.all([
      invoke('list_pending'),
      invoke('history', { offset: 0, limit: 200 }),
    ]);
    pendingItems = p?.pending ?? [];
    decidedItems = d?.items ?? [];
  } catch (err) {
    historyList.appendChild(textNode('p', 'meta', `加载失败: ${errText(err)}`));
    return;
  }
  const rows = [
    ...pendingItems.map((x) => ({ ...x, _state: 'pending' })),
    ...decidedItems.map((x) => ({ ...x, _state: x.status })),
  ];
  const shown = approvalFilter === 'all' ? rows : rows.filter((x) => x._state === approvalFilter);
  if (shown.length === 0) {
    const box = document.createElement('div');
    box.className = 'empty-state';
    box.appendChild(textNode('div', 'glyph', '~'));
    box.appendChild(textNode('p', 'headline', '暂无审批记录'));
    box.appendChild(textNode('p', 'sub', 'Agent 触发需要人工批准的命令时会出现在这里。'));
    historyList.appendChild(box);
    return;
  }
  for (const x of shown) historyList.appendChild(approvalRow(x));
}

function approvalRow(p) {
  const state = p._state ?? p.status;
  const stateText = { pending: '待审批', approved: '已批准', rejected: '已拒绝', expired: '已过期' }[state] ?? (p.status ?? '');
  const stateClass = { pending: 'pending-c', approved: 'allowed', rejected: 'denied', expired: '' }[state] ?? '';
  const row = document.createElement('div');
  row.className = 'audit-row';
  if (state === 'pending') row.classList.add('pending-c');
  row.appendChild(textNode('p', 't', `${stateText} · ${p.commandClass ?? ''} · ${p.profile ?? ''}`));
  const cmd = document.createElement('div');
  cmd.className = 'cmd';
  cmd.appendChild(document.createTextNode(p.command ?? ''));
  row.appendChild(cmd);
  const who = state === 'pending' ? '等待人工决定' : `决定人: ${p.decidedBy ?? '-'}`;
  row.appendChild(textNode('p', 't', `${p.decidedAt ?? p.createdAt ?? ''} · ${who}`));
  if (state === 'pending') {
    row.style.cursor = 'pointer';
    row.title = '点击打开独立审批窗';
    row.addEventListener('click', async () => {
      try {
        await invoke('open_approval_window', { id: p.id });
      } catch (err) {
        showFatal(`打开审批窗失败: ${errText(err)}`);
      }
    });
  }
  return row;
}

for (const btn of document.querySelectorAll('#history-filters .filter')) {
  btn.addEventListener('click', () => {
    approvalFilter = btn.dataset.f ?? 'all';
    for (const b of document.querySelectorAll('#history-filters .filter')) {
      b.classList.toggle('active', b === btn);
    }
    loadApprovalsList();
  });
}

/** 推送事件统一入口：刷新列表 + 红点（弹窗由 Rust 侧自动建/显）。 */
async function onApprovalEvent(payload) {
  const pendingNow = payload && payload.id && payload._state !== 'settled' && payload.status === 'pending';
  approvalsDot.classList.toggle('hidden', !pendingNow);
  if (currentView === 'approvals') await loadApprovalsList();
}

// ─── 审计视图：过滤查询 + 统计行 + 加载更多 ─────────────────────────────────

const auditList = document.getElementById('audit-list');
const auditStatsEl = document.getElementById('audit-stats');
const auditMoreBtn = document.getElementById('audit-more');
const AUDIT_PAGE = 50;
let auditOffsetTail = 0;

async function loadAudit(reset) {
  if (!invoke) return;
  if (reset) {
    auditOffsetTail = 0;
    auditList.textContent = '';
    auditStatsEl.textContent = '';
  }
  try {
    const profile = document.getElementById('audit-profile')?.value.trim() ?? '';
    const keyword = document.getElementById('audit-keyword')?.value.trim() ?? '';
    const decision = document.getElementById('audit-decision')?.value ?? '';
    const [page, stats] = await Promise.all([
      invoke('audit_query', {
        offsetTail: auditOffsetTail,
        limit: AUDIT_PAGE,
        profile: profile || null,
        keyword: keyword || null,
        decision: decision || null,
      }),
      reset ? invoke('audit_stats') : Promise.resolve(null),
    ]);
    if (stats !== null) {
      auditStatsEl.textContent = '';
      auditStatsEl.appendChild(document.createTextNode(
        `今日 ${stats.today ?? 0} 条 · 拒绝 ${stats.denied ?? 0} · 审批决定 ${stats.approvalsDecided ?? 0}`,
      ));
    }
    const items = page?.items ?? [];
    for (const rec of items) auditList.appendChild(auditRow(rec));
    auditOffsetTail += items.length;
    const hasMore = auditOffsetTail < (page?.total ?? 0);
    auditMoreBtn.classList.toggle('hidden', !hasMore);
  } catch (err) {
    auditList.appendChild(textNode('p', 'meta', `加载失败: ${errText(err)}`));
  }
}

function auditRow(rec) {
  const row = document.createElement('div');
  row.className = 'audit-row';
  if (rec.decision === 'deny') row.classList.add('denied');
  row.appendChild(textNode('p', 't', `${rec.timestamp ?? ''} · ${rec.profile ?? ''} · ${rec.commandClass ?? ''} · ${rec.decision ?? ''}${rec.approver ? ` · ${rec.approver}` : ''}`));
  const cmd = document.createElement('div');
  cmd.className = 'cmd';
  cmd.appendChild(document.createTextNode(rec.command ?? ''));
  row.appendChild(cmd);
  if (rec.error) row.appendChild(textNode('p', 't', `error: ${rec.error}`));
  return row;
}

document.getElementById('audit-apply')?.addEventListener('click', () => loadAudit(true));
auditMoreBtn?.addEventListener('click', () => loadAudit(false));

// ─── 连接视图：主机管理（T-22）+ 会话/配额 ──────────────────────────────────

const hostsList = document.getElementById('hosts-list');
const hostFormCard = document.getElementById('host-form-card');
const hfResult = document.getElementById('hf-result');
let editingName = null; // 编辑中的主机名（null=新增模式；名称是主键，编辑时锁定）

function hostFormValue(id) {
  return document.getElementById(id)?.value ?? '';
}

function openHostForm(profile) {
  editingName = profile?.name ?? null;
  document.getElementById('host-form-title').textContent = editingName ? `编辑主机：${editingName}` : '添加主机';
  (document.getElementById('hf-name')).value = profile?.name ?? '';
  (document.getElementById('hf-name')).disabled = editingName !== null; // 名称是主键
  (document.getElementById('hf-host')).value = profile?.host ?? '';
  (document.getElementById('hf-port')).value = String(profile?.port ?? 22);
  (document.getElementById('hf-user')).value = profile?.user ?? '';
  (document.getElementById('hf-auth')).value = profile?.auth === 'key' ? 'key' : 'password';
  (document.getElementById('hf-secret')).value = '';
  (document.getElementById('hf-secret-label')).textContent = '';
  (document.getElementById('hf-secret-label')).appendChild(document.createTextNode('密码（留空=不变）'));
  (document.getElementById('hf-group')).value = profile?.group ?? '';
  hfResult.textContent = '';
  hostFormCard.classList.remove('hidden');
}

async function loadConnectionsView() {
  await loadHosts();
  await loadConnSessions();
  await loadQuotas();
}

async function loadHosts() {
  if (!invoke) return;
  hostsList.textContent = '';
  try {
    const res = await invoke('profiles_list');
    const profiles = res?.profiles ?? [];
    if (profiles.length === 0) {
      hostsList.appendChild(textNode('p', 'meta', '暂无主机——点「添加主机」配置第一台。'));
      return;
    }
    for (const p of profiles) {
      const row = document.createElement('div');
      row.className = 'hosts-row';
      const info = document.createElement('div');
      info.className = 'info';
      info.appendChild(textNode('div', 'name', p.name ?? ''));
      info.appendChild(textNode('div', 'detail', `${p.user ?? ''}@${p.host ?? ''}:${p.port ?? 22} · ${p.auth === 'key' ? `密钥 ${p.keyRef ?? ''}` : '密码(凭据管理器)'}${p.group ? ` · ${p.group}` : ''}`));
      row.appendChild(info);
      const edit = document.createElement('button');
      edit.className = 'ghost small';
      edit.appendChild(document.createTextNode('编辑'));
      edit.addEventListener('click', () => openHostForm(p));
      const del = document.createElement('button');
      del.className = 'ghost small';
      del.appendChild(document.createTextNode('删除'));
      del.addEventListener('click', async () => {
        if (!window.confirm(`删除主机 ${p.name}？（配置文件自动备份）`)) return;
        try {
          await invoke('profiles_remove', { name: p.name });
          await loadHosts();
        } catch (err) {
          showFatal(`删除失败: ${errText(err)}`);
        }
      });
      row.appendChild(edit);
      row.appendChild(del);
      hostsList.appendChild(row);
    }
  } catch (err) {
    hostsList.appendChild(textNode('p', 'meta', `主机清单加载失败: ${errText(err)}`));
  }
}

async function saveHostForm() {
  const name = hostFormValue('hf-name').trim();
  if (name === '') {
    hfResult.textContent = '';
    hfResult.appendChild(document.createTextNode('名称必填（字母/数字/-/_）。'));
    return;
  }
  const auth = hostFormValue('hf-auth');
  const payload = {
    name,
    host: hostFormValue('hf-host').trim(),
    port: Number.parseInt(hostFormValue('hf-port'), 10) || 22,
    user: hostFormValue('hf-user').trim(),
    auth,
    ...(auth === 'password' && hostFormValue('hf-secret') !== '' ? { password: hostFormValue('hf-secret') } : {}),
    ...(hostFormValue('hf-group').trim() !== '' ? { group: hostFormValue('hf-group').trim() } : {}),
  };
  try {
    const res = await invoke('profiles_upsert', { profile: payload });
    hfResult.textContent = '';
    hfResult.appendChild(document.createTextNode(res?.note ?? '已保存。'));
    hostFormCard.classList.add('hidden');
    await loadHosts();
  } catch (err) {
    hfResult.textContent = '';
    hfResult.appendChild(document.createTextNode(`保存失败: ${errText(err)}`));
  }
}

document.getElementById('host-add')?.addEventListener('click', () => openHostForm(null));
document.getElementById('hosts-refresh')?.addEventListener('click', () => loadHosts());
document.getElementById('hf-cancel')?.addEventListener('click', () => hostFormCard.classList.add('hidden'));
document.getElementById('hf-save')?.addEventListener('click', () => saveHostForm());

async function loadConnSessions() {
  const list = document.getElementById('conn-list');
  if (!invoke || list === null) return;
  list.textContent = '';
  try {
    const res = await invoke('connections');
    const conns = res?.connections ?? [];
    if (conns.length === 0) {
      list.appendChild(textNode('p', 'meta', '暂无活动连接——Agent 首次使用某主机时在此出现。'));
      return;
    }
    for (const c of conns) {
      const row = document.createElement('div');
      row.className = 'hosts-row';
      const info = document.createElement('div');
      info.className = 'info';
      info.appendChild(textNode('div', 'name', c.profile ?? ''));
      info.appendChild(textNode('div', 'detail', `${c.connected ? '已连接' : '未连接'} · 会话 ${c.sessions ?? 0} · PTY ${c.ptySessions ?? 0}`));
      row.appendChild(info);
      list.appendChild(row);
    }
  } catch (err) {
    list.appendChild(textNode('p', 'meta', `连接加载失败: ${errText(err)}`));
  }
}

async function loadQuotas() {
  const list = document.getElementById('quota-list');
  if (!invoke || list === null) return;
  list.textContent = '';
  try {
    const res = await invoke('quota_snapshot');
    const quotas = res?.quotas ?? [];
    if (quotas.length === 0) {
      list.appendChild(textNode('p', 'meta', '（无配额数据）'));
      return;
    }
    for (const q of quotas) {
      const row = document.createElement('div');
      row.className = 'hosts-row';
      const info = document.createElement('div');
      info.className = 'info';
      info.appendChild(textNode('div', 'name', q.profile ?? ''));
      info.appendChild(textNode('div', 'detail', `滚动 24h：${q.used ?? 0} / ${q.limit ?? '∞'} 条`));
      row.appendChild(info);
      list.appendChild(row);
    }
  } catch (err) {
    list.appendChild(textNode('p', 'meta', `配额加载失败: ${errText(err)}`));
  }
}

// ─── 设置视图：自启/Host 管理/审批面/宿主接入 ───────────────────────────────

async function loadSettingsView() {
  if (!invoke) return;
  // 开机自启
  try {
    const res = await invoke('autostart_status');
    (document.getElementById('set-autostart')).checked = res?.enabled === true;
  } catch (err) {
    showFatal(`自启状态读取失败: ${errText(err)}`);
  }
  // Host 信息 + 审批面
  const info = document.getElementById('set-host-info');
  const surfaces = document.getElementById('surfaces-list');
  info.textContent = '';
  surfaces.textContent = '';
  try {
    const st = await invoke('host_status');
    info.appendChild(document.createTextNode(
      `Host v${st?.version ?? '?'} @ 127.0.0.1:${st?.port ?? '?'} · 队列 ${st?.queueDir ?? '?'}`,
    ));
    const portEl = document.getElementById('mcp-http-port');
    if (portEl !== null) portEl.textContent = String(st?.mcpHttpPort ?? '未启用');
    for (const s of st?.surfaces ?? []) {
      const row = document.createElement('p');
      row.className = 'meta';
      row.appendChild(textNode('span', s.online ? 'allowed' : 'denied', s.online ? '● ' : '○ '));
      row.appendChild(document.createTextNode(`${s.surface}（${s.online ? '在线' : '离线'}）`));
      surfaces.appendChild(row);
    }
  } catch (err) {
    info.appendChild(document.createTextNode(`Host 状态读取失败: ${errText(err)}`));
  }
  renderAgents();
}

document.getElementById('set-autostart')?.addEventListener('change', async (e) => {
  try {
    await invoke('autostart_set', { enable: e.target.checked });
  } catch (err) {
    showFatal(`自启设置失败: ${errText(err)}`);
    e.target.checked = !e.target.checked;
  }
});
document.getElementById('host-restart')?.addEventListener('click', async () => {
  try {
    await invoke('restart_host');
    const info = document.getElementById('set-host-info');
    info.textContent = '';
    info.appendChild(document.createTextNode('Host 重启中——几秒后自动恢复。'));
    setTimeout(refreshHostStatus, 4000);
  } catch (err) {
    showFatal(`重启失败: ${errText(err)}`);
  }
});
document.getElementById('host-openlog')?.addEventListener('click', async () => {
  try {
    await invoke('open_host_log');
  } catch (err) {
    showFatal(`打开日志失败: ${errText(err)}`);
  }
});

async function renderAgents() {
  const list = document.getElementById('agents-list');
  if (list === null) return;
  list.textContent = '';
  try {
    const res = await invoke('agents_scan');
    const hosts = res?.hosts ?? [];
    if (hosts.length === 0) {
      list.appendChild(textNode('p', 'meta', '未识别到已知宿主。'));
      return;
    }
    for (const h of hosts) {
      const row = document.createElement('div');
      row.className = 'hosts-row';
      const info = document.createElement('div');
      info.className = 'info';
      const stateText = h.configured ? '已接入' : (h.detected ? '未接入' : '未安装');
      info.appendChild(textNode('div', 'name', `${h.name ?? h.id} · ${stateText}`));
      info.appendChild(textNode('div', 'detail', `${h.configPath ?? ''}${h.note ? ` · ${h.note}` : ''}`));
      row.appendChild(info);
      if (h.detected && h.supported) {
        const btn = document.createElement('button');
        btn.className = h.configured ? 'ghost small' : 'approve small';
        btn.appendChild(document.createTextNode(h.configured ? '重新写入' : '一键接入'));
        btn.addEventListener('click', async () => {
          btn.disabled = true;
          try {
            await invoke('agents_configure', { id: h.id });
            await renderAgents();
          } catch (err) {
            showFatal(`接入失败: ${errText(err)}`);
            btn.disabled = false;
          }
        });
        row.appendChild(btn);
        if (h.configured) {
          const rm = document.createElement('button');
          rm.className = 'ghost small';
          rm.appendChild(document.createTextNode('移除'));
          rm.addEventListener('click', async () => {
            if (!window.confirm(`从 ${h.name ?? h.id} 移除 agent-ssh 条目？`)) return;
            try {
              await invoke('agents_remove', { id: h.id });
              await renderAgents();
            } catch (err) {
              showFatal(`移除失败: ${errText(err)}`);
            }
          });
          row.appendChild(rm);
        }
      }
      list.appendChild(row);
    }
  } catch (err) {
    list.appendChild(textNode('p', 'meta', `宿主扫描失败: ${errText(err)}`));
  }
}

document.getElementById('agents-scan')?.addEventListener('click', () => renderAgents());

// ─── 远程 MCP 接入：一键复制配置（T-24） ────────────────────────────────────

const copyResultEl = document.getElementById('mcp-copy-result');

function noteCopyResult(text) {
  copyResultEl.textContent = '';
  copyResultEl.appendChild(document.createTextNode(text));
}

async function copyMcpConfig(kind, btn) {
  const original = btn.textContent;
  try {
    // 端口以 Host 实际上报为准（[http] 节可改；离线/未启用则无值）。
    const st = await invoke('host_status');
    const port = st?.mcpHttpPort;
    if (!port) {
      noteCopyResult('HTTP 面未启用或 Host 未连接——无法生成配置。');
      return;
    }
    const cfg = await invoke('mcp_http_token');
    const token = cfg?.token ?? '';
    const url = `http://127.0.0.1:${port}/mcp`;
    const text = kind === 'claude'
      ? `claude mcp add --transport http agent-ssh ${url} --header "Authorization: Bearer ${token}"`
      : JSON.stringify(
          { mcp: { 'agent-ssh': { type: 'remote', url, headers: { Authorization: `Bearer ${token}` }, enabled: true } } },
          null,
          2,
        );
    await navigator.clipboard.writeText(text);
    noteCopyResult(`已复制——粘贴到宿主配置后重启该宿主生效（URL: ${url}）。`);
    btn.textContent = '已复制 ✓';
    setTimeout(() => { btn.textContent = original; }, 2000);
  } catch (err) {
    noteCopyResult(`复制失败: ${errText(err)}`);
  }
}

document.getElementById('copy-mcp-json')?.addEventListener('click', (e) => copyMcpConfig('json', e.currentTarget));
document.getElementById('copy-mcp-cli')?.addEventListener('click', (e) => copyMcpConfig('claude', e.currentTarget));

// ─── 启动 ───────────────────────────────────────────────────────────────────

async function main() {
  showView('approvals');
  refreshHostStatus();
  if (!invoke || !listen) {
    showFatal('Tauri 桥不可用（纯浏览模式，无审批功能）');
    return;
  }
  try {
    await listen('approval-pending', (event) => onApprovalEvent(event.payload));
    await listen('approval-settled', (event) => onApprovalEvent(event.payload));
  } catch (err) {
    showFatal(`事件订阅失败: ${errText(err)}`);
  }
}

main();
