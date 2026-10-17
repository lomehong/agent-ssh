// 独立审批卡窗（T-23，主人 2026-10-17 定稿）：窗口内容=一张审批卡本身，
// 组织形式学 coucou 审批卡（主人指定参考）：
//   who 行（色点+粗体主体+状态短语）→ 命令块（视觉中心）
//   → 操作行（拒绝=次要 / 批准=主要，N/Y 键盘快捷键）→ 底边 2px 倒计时条。
// 无校验码（主人裁决：弹窗就在操作者自己屏幕上，码=「验证我是我」伪需求；
// Host 侧验码仅对 im 面生效——码在手机上，那才是它的价值）。
// 交互纪律同 coucou：600ms 防误击（弹窗落在光标下，穿透点击不得落在批准上）、
// 按钮只建一次（mousedown/mouseup 之间重建会吞点击）、× =暂不处理（请求留队列）。
// 每条审批请求一个窗口（URL query 携请求 id），决定/过期后自动关窗。
// K8-③：全部 textNode 渲染，零 innerHTML/eval。
import { invoke } from './tauri-shim.js';

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id') ?? '';

const cardRoot = document.getElementById('approval-card');
const countdownBar = document.getElementById('approval-countdown');

/** coucou CLICK_GUARD_MS：新卡出现的最初 600ms 忽略按钮点击。 */
const CLICK_GUARD_MS = 600;
let shownAt = performance.now();

function textNode(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.appendChild(document.createTextNode(text));
  return el;
}

function guarded(fn) {
  return () => {
    if (performance.now() - shownAt < CLICK_GUARD_MS) return;
    fn();
  };
}

function closeSoon(delay) {
  setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(), delay);
}

function renderExpired() {
  cardRoot.textContent = '';
  cardRoot.appendChild(textNode('p', 'meta', '该请求已决定或过期。'));
  closeSoon(2200);
}

/** ISO→本地时分秒（原始 ISO 串是给机器看的，不上卡面）。 */
function localTime(iso) {
  const t = Date.parse(iso ?? '');
  return Number.isNaN(t) ? (iso ?? '—') : new Date(t).toLocaleTimeString('zh-CN', { hour12: false });
}

/** 卡片高度贴合内容（飞书卡体验）：渲染后按实测内容高度 setSize，夹在 260–560。
 *  命令块过长时内部滚动（.command max-height），窗体不再留大片空档。 */
function fitWindowToContent() {
  const w = window.__TAURI__?.window?.getCurrentWindow?.();
  const LogicalSize = window.__TAURI__?.window?.LogicalSize;
  if (!w || !LogicalSize) return;
  requestAnimationFrame(() => {
    const head = document.getElementById('approval-head');
    const last = cardRoot.lastElementChild;
    if (!head || !last) return;
    const top = head.getBoundingClientRect().top;
    const bottom = last.getBoundingClientRect().bottom;
    const natural = Math.ceil(bottom - top) + 14 + 10 + 2; // 卡体底距+body 下边距+倒计时条
    const h = Math.min(560, Math.max(260, natural));
    w.setSize(new LogicalSize(420, h)).catch(() => {});
  });
}

/** coucou 形倒计时：底边 2px 进度条从满宽线性收到 0；归零后关窗（已不可能再批）。 */
function startCountdown(expiresAtMs) {
  const remain = expiresAtMs - Date.now();
  if (!Number.isFinite(remain) || remain <= 0) {
    renderExpired();
    return;
  }
  requestAnimationFrame(() => {
    countdownBar.style.transition = `width ${remain}ms linear`;
    countdownBar.style.width = '0%';
  });
  setTimeout(() => closeSoon(0), remain + 800);
}

function renderCard(entry) {
  cardRoot.textContent = '';
  const cls = entry.commandClass ?? '';
  const isDanger = cls === 'destructive' || cls === 'privileged';

  // who 行：色点（按类别取三态色）+ 粗体主体 + 状态短语。
  const who = document.createElement('p');
  who.className = 'who-row';
  const dot = textNode('i', `who-dot${cls ? ` ${cls}` : ''}`, '');
  who.appendChild(dot);
  who.appendChild(textNode('span', 'n', entry.profile ?? ''));
  who.appendChild(document.createTextNode(isDanger ? ' 请求执行高危命令，需要你的批准' : ' 请求执行命令，需要你的批准'));
  cardRoot.appendChild(who);

  // 单行弱化元信息：类别 + 过期时间（信息不丢，但不与命令块争夺视觉）。
  cardRoot.appendChild(textNode('p', 'card-meta', `${cls || '—'} · ${localTime(entry.expiresAt)} 过期`));

  // 命令块=视觉中心（coucou：批准的意义就在这一行，而非请求方的名字）。
  const cmd = document.createElement('pre');
  cmd.className = 'command';
  cmd.appendChild(document.createTextNode(entry.command ?? ''));
  cardRoot.appendChild(cmd);

  // 操作行：拒绝（次要）+ 批准（主要），kbd 提示 N/Y；按钮只建一次。
  const row = document.createElement('div');
  row.className = 'actions';
  const reject = document.createElement('button');
  reject.className = 'btn ghost';
  reject.appendChild(document.createTextNode('拒绝'));
  reject.appendChild(textNode('span', 'kbd', 'N'));
  const approve = document.createElement('button');
  approve.className = 'btn approve';
  approve.appendChild(document.createTextNode('批准'));
  approve.appendChild(textNode('span', 'kbd', 'Y'));
  row.appendChild(reject);
  row.appendChild(approve);
  cardRoot.appendChild(row);

  const feedback = textNode('p', 'feedback', '');
  cardRoot.appendChild(feedback);

  const decide = (approved) => {
    for (const b of [approve, reject]) b.disabled = true;
    invoke('decide', {
      id: entry.id ?? requestId,
      decision: approved ? 'approved' : 'rejected',
      face: 'desktop',
    })
      .then((res) => {
        const ok = res?.decided !== false;
        feedback.textContent = '';
        feedback.appendChild(document.createTextNode(ok ? `已${approved ? '批准' : '拒绝'}——窗口即将关闭` : (res?.message ?? '已处理（先到先得）')));
        countdownBar.style.width = '0%';
        closeSoon(1400);
      })
      .catch((err) => {
        const m = typeof err === 'string' ? err : (err?.message ?? String(err));
        for (const b of [approve, reject]) b.disabled = false;
        feedback.textContent = '';
        feedback.appendChild(document.createTextNode(`失败: ${m}`));
      });
  };
  approve.addEventListener('click', guarded(() => decide(true)));
  reject.addEventListener('click', guarded(() => decide(false)));

  // 键盘：N=拒绝，Y=批准，Esc=暂不处理。
  window.addEventListener('keydown', (e) => {
    if (e.key === 'n' || e.key === 'N') reject.click();
    else if (e.key === 'y' || e.key === 'Y') approve.click();
    else if (e.key === 'Escape') closeSoon(0);
  });

  startCountdown(Date.parse(entry.expiresAt ?? ''));
  fitWindowToContent();
}

async function main() {
  document.getElementById('approval-close')?.addEventListener('click', () => closeSoon(0));
  if (!requestId) {
    renderExpired();
    return;
  }
  let entry;
  try {
    const res = await invoke('list_pending');
    entry = (res?.pending ?? []).find((x) => x.id === requestId);
  } catch (err) {
    const m = typeof err === 'string' ? err : (err?.message ?? String(err));
    cardRoot.textContent = '';
    cardRoot.appendChild(textNode('p', 'meta', `拉取失败: ${m}`));
    closeSoon(2500);
    return;
  }
  if (entry === undefined) {
    renderExpired();
    return;
  }
  renderCard(entry);
}

main();
