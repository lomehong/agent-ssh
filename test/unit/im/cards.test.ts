import { describe, it, expect } from 'vitest';
import { buildPendingCard, buildSettledCard, type PendingCardInput } from '../../../src/im/cards.js';

// 卡片构建（T-17.6 §4.2）：full/truncated 两档、破坏性类校验码表单、
// settled 收尾形态。JSON 可序列化是底线（SDK content 字段要求）。

const base: PendingCardInput = {
  id: 'req-1',
  profile: 'prod',
  command: 'systemctl restart nginx',
  commandClass: 'safe',
  expiresAt: '2026-10-17T12:00:00.000Z',
  decisionToken: 'tok-abc',
};

describe('im 卡片构建', () => {
  it('普通类：按钮携决策令牌，命令全文展示', () => {
    const card = buildPendingCard(base);
    const json = JSON.stringify(card);
    expect(json).toContain('tok-abc');
    expect(json).toContain('systemctl restart nginx');
    expect(json).not.toContain('"input"'); // 无校验码输入
    const actions = JSON.parse(json);
    expect(JSON.stringify(actions)).toContain('批准');
  });

  it('破坏性类：2.0 架构 form+校验码输入框，form_action_type=submit（官方文法，400 修复回归）', () => {
    const card = buildPendingCard({ ...base, commandClass: 'destructive', challenge: '4321' });
    const json = JSON.stringify(card);
    expect(json).toContain('"input"');
    expect(json).toContain('challenge');
    expect(json).toContain('4321');
    expect(json).toContain('"schema":"2.0"');
    expect(json).toContain('form_action_type');
    // placeholder 必须是对象形态（字符串形态被飞书 400 拒收——实测）
    expect(json).toContain('\"placeholder\":{');
    expect(json).toContain('"form"');
  });

  it('truncated 档：命令经 redactor（截断≠脱敏，两道都做）', () => {
    const card = buildPendingCard({
      ...base,
      command: 'run AKIAABCDEFGHIJKLMNOP fallback',
      commandDetail: 'truncated',
    });
    const json = JSON.stringify(card);
    expect(json).toContain('[REDACTED:aws-access-key');
    expect(json).not.toContain('AKIAABCDEFGHIJKLMNOP');
  });

  it('full 档：命令原文保留（人审的就是原文，不脱敏）', () => {
    const card = buildPendingCard({ ...base, command: 'run AKIAABCDEFGHIJKLMNOP', commandDetail: 'full' });
    expect(JSON.stringify(card)).toContain('AKIAABCDEFGHIJKLMNOP');
  });

  it('settled 卡片：决定人入标题，按钮语义已被 patch 替换', () => {
    const card = buildSettledCard(base, { decision: 'approved', by: 'desktop:lome' });
    const json = JSON.stringify(card);
    expect(json).toContain('已批准');
    expect(json).toContain('desktop:lome');
    expect(json).toContain('本卡片按钮已失效');
  });
});
