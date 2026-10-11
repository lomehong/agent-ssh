import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDirectCli, DIRECT_VERBS } from '../../src/cli-direct.js';

// run/info 直连面的纯逻辑面：动词表、无命令用法、禁止名单对人工同样拦截。
//
// 历史更正（T-13，审计 High-1）：早期报告与旧版本测试注释声称
// 「rm -rf /etc/passwd 被禁止名单拦下 exit 1」——不实。该路径不匹配
// FORBIDDEN_PATTERNS（模式要求 `rm -rf /` 后接空白/行尾），当时观察到的
// exit 1 是远端非 root 权限拒绝。T-13 已在 cli-direct 补上
// findForbiddenMatch 拦截，并由下方 forbidden 用例以本地行为证实（不触网）。

afterEach(() => {
  vi.restoreAllMocks();
});

describe('cli-direct', () => {
  it('动词表恰为 run 与 info', () => {
    expect(DIRECT_VERBS).toEqual(['run', 'info']);
  });

  it('run 无命令 → 用法说明 + 退出码 1', async () => {
    const errors: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((m) => errors.push(String(m)));
    const code = await runDirectCli('run', []);
    errSpy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join('\n')).toContain('Usage: agent-ssh run');
  });

  it('forbidden 命中：配置加载前本地拒绝 + exit 1（不触网、不写审计）', async () => {
    const errors: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((m) => errors.push(String(m)));
    // rm -rf / 命中 FORBIDDEN_PATTERNS；不提供 --config——拒绝发生在配置加载之前，
    // 若实现错误地走到连接阶段，用例会因缺凭证/不可达而以别的方式失败。
    const code = await runDirectCli('run', ['rm -rf /']);
    errSpy.mockRestore();
    expect(code).toBe(1);
    expect(errors.join('\n')).toContain('命中禁止名单');
  }, 15000);
});
