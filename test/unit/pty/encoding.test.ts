import { describe, it, expect, vi } from 'vitest';
import { EventEmitter } from 'node:events';
import { PtySession } from '../../../src/pty/pty-session.js';

// ptyEncoding（agent-ssh T-10）：老华为/华三设备 GB2312/GBK 输出经 Node 内置
// TextDecoder（full-ICU）解码，零新增依赖；跨 chunk 的多字节序列用流式解码保持完整。

class FakeChannel extends EventEmitter {
  writes: string[] = [];
  stderr = new EventEmitter();
  write(input: string) { this.writes.push(input); }
  setWindow() {}
  close() { this.destroy(); }
}

function makeSession(encoding?: 'utf8' | 'gbk') {
  const channel = new FakeChannel() as never as InstanceType<typeof FakeChannel> & import('ssh2').ClientChannel;
  const session = new PtySession('s1', 'dev', channel, { maxBufferBytes: 65536, encoding });
  return { session, channel };
}

describe('ptyEncoding', () => {
  it('gbk: GB2312 字节流解码为中文（你好 = C4E3 BAC3）', async () => {
    const { session, channel } = makeSession('gbk');
    channel.emit('data', Buffer.from([0xc4, 0xe3, 0xba, 0xc3]));
    const read = session.readSince(0, 1000);
    expect(read.output).toBe('你好');
  });

  it('gbk: 跨 chunk 断开的多字节序列流式解码不错乱', async () => {
    const { session, channel } = makeSession('gbk');
    const bytes = Buffer.from([0xc4, 0xe3, 0xba, 0xc3]);
    channel.emit('data', bytes.subarray(0, 1)); // 拆在双字节中间
    channel.emit('data', bytes.subarray(1));
    expect(session.readSince(0, 1000).output).toBe('你好');
  });

  it('默认 utf8 不变', () => {
    const { session, channel } = makeSession(undefined);
    channel.emit('data', Buffer.from('hello', 'utf8'));
    expect(session.readSince(0, 1000).output).toBe('hello');
  });

  it('utf8 显式声明与默认一致', () => {
    const { session, channel } = makeSession('utf8');
    channel.emit('data', Buffer.from('你好', 'utf8'));
    expect(session.readSince(0, 1000).output).toBe('你好');
  });
});
