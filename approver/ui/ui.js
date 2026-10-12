// 审批窗渲染（K8-③）：全部 DOM 经 createElement/createTextNode 构建，
// 零 innerHTML/insertAdjacentHTML/eval——命令全文永不进入 HTML 解析器。
// 数据来源：Tauri event `approval.pending`；决定经 invoke('decide', …)。

const invoke = window.__TAURI__?.core?.invoke;
const listen = window.__TAURI__?.event?.listen;

const queue = document.getElementById('queue');
const cards = new Map(); // id → { card, countdownTimer }

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

function onPending(payload) {
  hideEmptyHint();
  if (cards.has(payload.id)) return; // 多请求堆叠去重
  const card = renderCard(payload);
  queue.appendChild(card);
  cards.set(payload.id, { card });
  startCountdown(card, payload);
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
