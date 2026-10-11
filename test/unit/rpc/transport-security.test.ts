import { describe, expect, it } from 'vitest';
import {
  BindPolicyError,
  PinMismatchError,
  assertBindAllowed,
  assertClientConnectAllowed,
  isLoopbackBindAddress,
  verifyPin,
} from '../../../src/rpc/transport-security.js';

describe('环回绑定判定（复用 http.ts:277-357 实现，含 IPv6 文法）', () => {
  it.each([
    ['127.0.0.1', true],
    ['127.5.5.5', true], // 127/8 前缀
    ['::1', true],
    ['[::1]', true], // 括号文法
    ['::ffff:127.0.0.1', true], // 映射地址归一
    ['localhost', true], // 主机名（A/AAAA 均为环回）
    ['192.168.1.1', false],
    ['0.0.0.0', false], // 所有接口 ≠ 环回，非环回纪律适用
    ['::', false],
    ['example.com', false],
  ])('isLoopbackBindAddress(%s) → %j', (host, expected) => {
    expect(isLoopbackBindAddress(host)).toBe(expected);
  });
});

describe('Host 绑定纪律（§3.1：非环回强制 TLS，否则启动即拒）', () => {
  it('非环回 + 无 TLS → BindPolicyError', () => {
    expect(() => assertBindAllowed('192.168.1.1', false)).toThrow(BindPolicyError);
    expect(() => assertBindAllowed('0.0.0.0', false)).toThrow(BindPolicyError);
  });

  it('环回明文与非环回 TLS 均放行', () => {
    expect(() => assertBindAllowed('127.0.0.1', false)).not.toThrow();
    expect(() => assertBindAllowed('::1', false)).not.toThrow();
    expect(() => assertBindAllowed('192.168.1.1', true)).not.toThrow();
  });
});

describe('客户端连接纪律（K8-① fail-closed + A7 pin 一票否决）', () => {
  it('非环回目标 + 无 TLS → 拒连', () => {
    expect(() => assertClientConnectAllowed({ host: '10.1.2.3', tls: false })).toThrow(BindPolicyError);
  });

  it('TLS 但无 pin → fail-closed 拒连（K8-①：stub 行为必须有定义）', () => {
    expect(() => assertClientConnectAllowed({ host: '10.1.2.3', tls: true, pin: undefined })).toThrow(
      BindPolicyError,
    );
  });

  it('环回明文放行；环回明文但设了 pin → 拒（明文无从校验 pin）', () => {
    expect(() => assertClientConnectAllowed({ host: '127.0.0.1', tls: false, pin: undefined })).not.toThrow();
    expect(() => assertClientConnectAllowed({ host: '127.0.0.1', tls: false, pin: 'aabb' })).toThrow(
      BindPolicyError,
    );
  });

  it('pin 一票否决：指纹不匹配即拒，任何模式不可覆盖', () => {
    expect(() => verifyPin('a'.repeat(64), 'a'.repeat(64))).not.toThrow();
    expect(() => verifyPin('a'.repeat(64), 'b'.repeat(64))).toThrow(PinMismatchError);
    // pin 大小写不敏感（指纹 hex 惯例差异），但内容必须一致
    expect(() => verifyPin('A'.repeat(64), 'a'.repeat(64))).not.toThrow();
  });
});
