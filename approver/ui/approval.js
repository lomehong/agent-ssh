// 独立审批卡窗（T-23，主人 2026-10-17 澄清）：窗口内容=一张审批卡片本身。
// 每条审批请求一个窗口（URL query 携带请求 id），决定/过期后自动关窗。
// K8-③：全部 textNode 渲染，零 innerHTML/eval。
import { invoke } from './tauri-shim.js';

const params = new URLSearchParams(window.location.search);
const requestId = params.get('id') ?? '';

const cardRoot = document.getElementById('approval-card');

function textNode(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.appendChild(document.createTextNode(text));
  return el;
}

function fieldRow(label, value) {
  const wrap = document.createElement('p');
  wrap.className = 'meta';
  wrap.appendChild(document.createTextNode(`${label}：`));
  wrap.appendChild(textNode('span', 'field-value', value));
  return wrap;
}

function renderExpired() {
  cardRoot.textContent = '';
  cardRoot.appendChild(textNode('p', 'meta', '该请求已决定或过期。'));
  setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(), 2200);
}

function renderCard(entry) {
  cardRoot.textContent = '';

  const head = textNode('p', 'approval-head', `agent-ssh 审批（${entry.commandClass ?? ''}）`);
  cardRoot.appendChild(head);

  cardRoot.appendChild(fieldRow('Profile', entry.profile ?? ''));
  cardRoot.appendChild(fieldRow('类别', entry.commandClass ?? ''));
  cardRoot.appendChild(fieldRow('过期', entry.expiresAt ?? ''));

  const cmd = document.createElement('pre');
  cmd.className = 'command';
  cmd.appendChild(document.createTextNode(entry.command ?? ''));
  cardRoot.appendChild(cmd);

  const needsChallenge = entry.commandClass === 'destructive' || entry.commandClass === 'privileged';
  let challengeInput;
  if (needsChallenge) {
    const note = textNode('p', 'meta', '破坏性命令：请输入推送中的 4 位校验码（单次有效）');
    cardRoot.appendChild(note);
    const row = document.createElement('div');
    row.className = 'challenge-row';
    const input = document.createElement('input');
    input.inputMode = 'numeric';
    input.maxLength = 4;
    input.autocomplete = 'off';
    row.appendChild(input);
    cardRoot.appendChild(row);
    challengeInput = input;
  }

  const row = document.createElement('div');
  row.className = 'row';
  const reject = document.createElement('button');
  reject.className = 'reject';
  reject.appendChild(document.createTextNode('拒绝'));
  const approve = document.createElement('button');
  approve.className = 'approve';
  approve.appendChild(document.createTextNode('批准'));
  row.appendChild(reject);
  row.appendChild(approve);
  cardRoot.appendChild(row);

  const feedback = textNode('p', 'meta', '');
  cardRoot.appendChild(feedback);

  const decide = (approved) => {
    for (const b of [approve, reject]) b.disabled = true;
    invoke('decide', {
      id: entry.id ?? requestId,
      decision: approved ? 'approved' : 'rejected',
      face: 'desktop',
      challenge: challengeInput?.value || undefined,
    })
      .then((res) => {
        const ok = res?.decided !== false;
        feedback.textContent = '';
        feedback.appendChild(document.createTextNode(ok ? `已${approved ? '批准' : '拒绝'}——窗口即将关闭` : (res?.message ?? '已处理（先到先得）')));
        setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(), 1400);
      })
      .catch((err) => {
        const m = typeof err === 'string' ? err : (err?.message ?? String(err));
        for (const b of [approve, reject]) b.disabled = false;
        feedback.textContent = '';
        feedback.appendChild(document.createTextNode(`失败: ${m}`));
      });
  };
  approve.addEventListener('click', () => decide(true));
  reject.addEventListener('click', () => decide(false));
}

async function main() {
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
    setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(), 2500);
    return;
  }
  if (entry === undefined) {
    renderExpired();
    return;
  }
  renderCard(entry);
  // 过期自动关窗。
  const expiresAt = Date.parse(entry.expiresAt ?? '');
  if (!Number.isNaN(expiresAt)) {
    setTimeout(() => window.__TAURI__?.window?.getCurrentWindow?.()?.close?.(),
      Math.max(0, expiresAt - Date.now() + 1000));
  }
}

main();
