import { describe, expect, it } from 'vitest';
import { RPC_PROTOCOL_VERSION, negotiateHello } from '../../../src/rpc/protocol.js';

describe('host.hello 版本握手（§3.6：protocolVersion 语义化，不匹配显式拒绝）', () => {
  it('同版本协商通过', () => {
    expect(negotiateHello(RPC_PROTOCOL_VERSION, RPC_PROTOCOL_VERSION)).toEqual({ ok: true });
  });

  it('patch 位差异容忍（0.2.0 ↔ 0.2.9）', () => {
    expect(negotiateHello('0.2.0', '0.2.9')).toEqual({ ok: true });
  });

  it('minor 位差异拒绝并附双方版本（0.x 期 minor 即破坏性）', () => {
    const result = negotiateHello('0.2.0', '0.3.0');
    expect(result).toEqual({ ok: false, clientVersion: '0.2.0', serverVersion: '0.3.0' });
  });

  it('major 位差异拒绝', () => {
    expect(negotiateHello('1.0.0', RPC_PROTOCOL_VERSION).ok).toBe(false);
  });
});
