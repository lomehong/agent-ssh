import { describe, it, expect, vi, afterEach } from 'vitest';
import { runDirectCli, DIRECT_VERBS } from '../../src/cli-direct.js';

// run/info 直连面的纯逻辑面：动词表、无命令用法、配置缺失传播。
// 真实 SSH 行为（连接/执行/退出码透传/禁止名单拦截）由 T-07 实机抽验覆盖
// （192.168.2.131 手测：exit 7 透传、rm -rf /etc/passwd 被禁止名单拦下 exit 1）。

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
});
