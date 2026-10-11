import { describe, it, expect, afterEach } from 'vitest';
import { createHarness, type Harness } from './harness.js';
import { detectPtyAlerts } from '../../../src/tools/pty-tools.js';

// P2 内容级告警（主人裁决不接受挂起，2026-10-11）：裸 PTY 输入不做策略门，
// 但审计日志要看它——destructive/privileged 行落 ptyAlert 字段 + stderr 告警。

let h: Harness;

afterEach(async () => { await h?.close(); });

describe('detectPtyAlerts', () => {
  it('命中 destructive 与 privileged 行', () => {
    const alert = detectPtyAlerts('rm -rf /tmp/build\nsudo systemctl restart nginx\necho hi\n');
    expect(alert).toContain('destructive');
    expect(alert).toContain('sudo systemctl restart nginx');
    expect(alert).not.toContain('echo hi');
  });

  it('无害输入无告警', () => {
    expect(detectPtyAlerts('display version\nterminal length 0\n')).toBeUndefined();
  });

  it('空行与纯空白跳过', () => {
    expect(detectPtyAlerts('\n  \n')).toBeUndefined();
  });
});

describe('pty-write 审计与告警接线', () => {
  it('写入送达且危险行落入审计 ptyAlert 字段', async () => {
    h = await createHarness();
    const res = await h.client.callTool({
      name: 'pty-write',
      arguments: { name: 's1', input: 'rm -rf /tmp/build\n' },
    }) as any;
    expect(res.isError).toBeFalsy();
    expect(h.ptyWrites).toEqual([{ name: 's1', input: 'rm -rf /tmp/build\n' }]);
    const record = h.auditRecords.at(-1);
    expect(record.command).toContain('pty:write s1');
    expect(record.ptyAlert).toContain('destructive');
    expect(record.ptyAlert).toContain('rm -rf /tmp/build');
  });

  it('无害写入不产生 ptyAlert 字段', async () => {
    h = await createHarness();
    const res = await h.client.callTool({
      name: 'pty-write',
      arguments: { name: 's1', input: 'display version\n' },
    }) as any;
    expect(res.isError).toBeFalsy();
    const record = h.auditRecords.at(-1);
    expect(record.ptyAlert).toBeUndefined();
  });
});
