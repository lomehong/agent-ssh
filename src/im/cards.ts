/**
 * 飞书审批卡片构建（T-17.6，纯函数——SDK 与网络均在 port.ts 适配层）。
 *
 * 两形态（§4.2）：
 * - 普通类（read-only/safe）：直接 [批准]/[拒绝] 按钮，value 携单次决策令牌；
 * - 破坏性/特权类：form + 4 位校验码输入框（D10 的 IM 侧形态——码由 Host
 *   生成，仅随卡片下发即"窗口可见"的等价物；decide 面走 face='im' 强制携码）。
 *
 * 命令展示（§4.2 明示代价）：full=全文（裁决依据完整性优先，默认）；
 * truncated=截断+类别。截断档必须叠加 redactor（截断≠脱敏，命令常含内嵌
 * 凭证——二轮评审小残留），full 档不脱敏（人要审的就是原文）。
 */
import { redactText } from '../guard/redactor.js';

export interface PendingCardInput {
  id: string;
  profile: string;
  command: string;
  commandClass: string;
  expiresAt: string;
  /** 单次决策令牌（decision-tokens 签发，≥128bit）。 */
  decisionToken: string;
  /** 破坏性/特权类随推送下发的 4 位校验码（ChallengeStore 生成）。 */
  challenge?: string;
  commandDetail?: 'full' | 'truncated';
}

export interface CardButtonValue {
  k: 'decide';
  id: string;
  t: string;
  d: 'approved' | 'rejected';
}

const TRUNCATE_AT = 400;

function commandBlock(command: string, mode: 'full' | 'truncated'): object {
  if (mode === 'truncated') {
    const redacted = redactText(command);
    const cut = redacted.length > TRUNCATE_AT ? `${redacted.slice(0, TRUNCATE_AT)}…（已截断，全文见 Host 队列/桌面端）` : redacted;
    return { tag: 'div', text: { tag: 'lark_md', content: `**命令（截断+脱敏档）**\n\`\`\`\n${cut}\n\`\`\`` } };
  }
  return { tag: 'div', text: { tag: 'lark_md', content: `**命令（全文）**\n\`\`\`\n${command}\n\`\`\`` } };
}

/** 2.0 架构的命令块（markdown 组件）。 */
function commandBlockV2(command: string, mode: 'full' | 'truncated'): object {
  if (mode === 'truncated') {
    const redacted = redactText(command);
    const cut = redacted.length > TRUNCATE_AT ? `${redacted.slice(0, TRUNCATE_AT)}…（已截断，全文见 Host 队列/桌面端）` : redacted;
    return { tag: 'markdown', content: `**命令（截断+脱敏档）**\n\`\`\`\n${cut}\n\`\`\`` };
  }
  return { tag: 'markdown', content: `**命令（全文）**\n\`\`\`\n${command}\n\`\`\`` };
}

function button(label: string, style: 'primary' | 'danger', value: CardButtonValue): object {
  return {
    tag: 'button',
    text: { tag: 'plain_text', content: label },
    type: style,
    value: value as unknown as Record<string, unknown>,
  };
}

/** 待决卡片。破坏性/特权类带校验码输入（form 提交合并进回调 value.challenge）。 */
export function buildPendingCard(input: PendingCardInput): Record<string, unknown> {
  const detail = input.commandDetail ?? 'full';
  const fields = [
    { is_short: true, text: { tag: 'lark_md', content: `**Profile**\n${input.profile}` } },
    { is_short: true, text: { tag: 'lark_md', content: `**类别**\n${input.commandClass}` } },
    { is_short: true, text: { tag: 'lark_md', content: `**过期**\n${input.expiresAt}` } },
    { is_short: true, text: { tag: 'lark_md', content: `**请求**\n\`${input.id}\`` } },
  ];
  const value = (d: 'approved' | 'rejected'): CardButtonValue => ({ k: 'decide', id: input.id, t: input.decisionToken, d });
  const needsChallenge = input.commandClass === 'destructive' || input.commandClass === 'privileged';

  if (needsChallenge) {
    // 破坏性/特权类走卡片 JSON 2.0：input/form 组件是 2.0 独有（legacy 架构
    // 混入 form/input 会被 400 拒收——T-17.6 真实 E2E 实测）。提交按钮
    // behaviors=form_submit，表单值经回调 action.form_value 回传（port 合并进
    // value）。settled patch 必须同架构（见 buildSettledCard）。
    return {
      schema: '2.0',
      config: { update_multi: true },
      header: { title: { tag: 'plain_text', content: `⚠️ agent-ssh 审批（${input.commandClass}）` }, template: 'red' },
      body: {
        direction: 'vertical',
        padding: '12px 12px 12px 12px',
        elements: [
          {
            tag: 'markdown',
            content:
              `**Profile**：${input.profile}\n**类别**：${input.commandClass}\n` +
              `**过期**：${input.expiresAt}\n**请求**：\`${input.id}\``,
          },
          commandBlockV2(input.command, detail),
          {
            tag: 'form',
            name: `f-${input.id}`,
            elements: [
              {
                tag: 'input',
                name: 'challenge',
                placeholder: { tag: 'plain_text', content: `输入校验码：${input.challenge ?? '（Host 未下发——经桌面端/CLI 决定）'}` },
                max_length: 8,
              },
              {
                tag: 'column_set',
                flex_mode: 'bisect',
                background_style: 'default',
                columns: [
                  {
                    tag: 'column',
                    width: 'weighted',
                    weight: 1,
                    vertical_align: 'top',
                    elements: [{
                      tag: 'button',
                      text: { tag: 'plain_text', content: '拒绝' },
                      type: 'danger',
                      size: 'medium',
                      behaviors: [{ type: 'callback', value: value('rejected') as unknown as Record<string, unknown> }],
                      form_action_type: 'submit',
                      name: `reject-${input.id}`,
                    }],
                  },
                  {
                    tag: 'column',
                    width: 'weighted',
                    weight: 1,
                    vertical_align: 'top',
                    elements: [{
                      tag: 'button',
                      text: { tag: 'plain_text', content: '批准（需校验码）' },
                      type: 'primary',
                      size: 'medium',
                      behaviors: [{ type: 'callback', value: value('approved') as unknown as Record<string, unknown> }],
                      form_action_type: 'submit',
                      name: `approve-${input.id}`,
                    }],
                  },
                ],
              },
            ],
          },
        ],
      },
    };
  }

  return {
    config: { wide_screen_mode: true },
    header: { title: { tag: 'plain_text', content: `agent-ssh 审批（${input.commandClass}）` }, template: 'orange' },
    elements: [
      { tag: 'div', fields },
      commandBlock(input.command, detail),
      {
        tag: 'action',
        actions: [
          button('批准', 'primary', value('approved')),
          button('拒绝', 'danger', value('rejected')),
        ],
      },
      { tag: 'note', elements: [{ tag: 'plain_text', content: '先到先得：桌面端/CLI 同时在线时，任一面决定后其余面失效。' }] },
    ],
  };
}

/** 已决卡片（patch 原消息——D11「已在桌面端批准」跨面仲裁可见）。
 * patch 内容必须与原卡片同架构（legacy ↔ 2.0 混 patch 会被拒），按待决
 * 输入是否挑战类分流。 */
export function buildSettledCard(
  pending: PendingCardInput,
  settledBy: { decision: 'approved' | 'rejected'; by: string },
): Record<string, unknown> {
  const approved = settledBy.decision === 'approved';
  const needsChallenge = pending.commandClass === 'destructive' || pending.commandClass === 'privileged';
  if (needsChallenge) {
    return {
      schema: '2.0',
      config: { update_multi: true },
      header: {
        title: { tag: 'plain_text', content: `${approved ? '✅ 已批准' : '⛔ 已拒绝'}（${settledBy.by}）` },
        template: approved ? 'green' : 'grey',
      },
      body: {
        direction: 'vertical',
        padding: '12px 12px 12px 12px',
        elements: [
          {
            tag: 'markdown',
            content: `**Profile**：${pending.profile}\n**类别**：${pending.commandClass}`,
          },
          commandBlockV2(pending.command, pending.commandDetail ?? 'full'),
          { tag: 'markdown', content: `决定人：${settledBy.by} · 本卡片按钮已失效。` },
        ],
      },
    };
  }
  return {
    config: { wide_screen_mode: true },
    header: {
      title: { tag: 'plain_text', content: `${approved ? '✅ 已批准' : '⛔ 已拒绝'}（${settledBy.by}）` },
      template: approved ? 'green' : 'grey',
    },
    elements: [
      {
        tag: 'div',
        fields: [
          { is_short: true, text: { tag: 'lark_md', content: `**Profile**\n${pending.profile}` } },
          { is_short: true, text: { tag: 'lark_md', content: `**类别**\n${pending.commandClass}` } },
        ],
      },
      commandBlock(pending.command, pending.commandDetail ?? 'full'),
      { tag: 'note', elements: [{ tag: 'plain_text', content: `决定人：${settledBy.by} · 本卡片按钮已失效。` }] },
    ],
  };
}
