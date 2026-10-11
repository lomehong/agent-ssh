import { describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { FrameReader } from '../../../src/rpc/frame.js';
import { RPC_PROTOCOL_VERSION } from '../../../src/rpc/protocol.js';
import { buildGoldenFixture, type GoldenFixture } from '../../../src/rpc/golden.js';

const FIXTURE = join(process.cwd(), 'test', 'fixtures', 'rpc', 'protocol-golden.json');

/** K6 生成动作：TS 单测写盘，Rust 只消费（src/rpc/golden.ts 保持零 fs 纯构建器）。 */
function generate(): GoldenFixture {
  const fixture = buildGoldenFixture();
  mkdirSync(dirname(FIXTURE), { recursive: true });
  writeFileSync(FIXTURE, JSON.stringify(fixture, null, 2) + '\n', 'utf8');
  return fixture;
}

describe('契约夹具 golden.json（K6：TS 协议类型单测生成，Rust 只消费）', () => {
  it('生成 test/fixtures/rpc/protocol-golden.json 并含全套样本', () => {
    generate();
    expect(existsSync(FIXTURE)).toBe(true);
    const parsed = JSON.parse(readFileSync(FIXTURE, 'utf8')) as GoldenFixture;
    expect(parsed.protocolVersion).toBe(RPC_PROTOCOL_VERSION);
    const names = parsed.samples.map((s) => s.name);
    expect(names).toEqual([
      'hello.request',
      'hello.result',
      'tool.call.request',
      'tool.call.result',
      'error.forbidden',
      'approval.pending.push',
    ]);
  });

  it('每个样本 wire 都是合法单帧且可往返解码', () => {
    const parsed = JSON.parse(readFileSync(FIXTURE, 'utf8')) as GoldenFixture;
    for (const sample of parsed.samples) {
      expect(sample.wire.endsWith('\n'), sample.name).toBe(true);
      const reader = new FrameReader();
      const events = reader.push(sample.wire);
      expect(events, sample.name).toHaveLength(1);
      expect(events[0].kind, sample.name).toBe('frame');
      expect(reader.isDead(), sample.name).toBe(false);
    }
  });

  it('生成是确定性的：两次生成字节一致（Rust 对拍的前提）', () => {
    const first = JSON.stringify(buildGoldenFixture());
    const second = JSON.stringify(buildGoldenFixture());
    expect(first).toBe(second);
  });

  it('hello.result 样本回显证书指纹字段（§3.1 带外核对）', () => {
    const parsed = JSON.parse(readFileSync(FIXTURE, 'utf8')) as GoldenFixture;
    const hello = parsed.samples.find((s) => s.name === 'hello.result');
    expect(hello).toBeDefined();
    const value = JSON.parse((hello as { wire: string }).wire) as {
      result: { protocolVersion: string; certFingerprint: string };
    };
    expect(value.result.protocolVersion).toBe(RPC_PROTOCOL_VERSION);
    expect(value.result.certFingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});
