import { describe, expect, it, vi } from 'vitest';
import { RpcClient } from '../../src/rpc/client.js';
import { RPC_TEST_TIMEOUT_MS, SkipError, spawnDevHost, tlsFixture } from './harness.js';

// K9-⑤：双进程用例显式超时预算（vitest 默认 5s 不够——构建/拉起/重连都在预算内）
vi.setConfig({ testTimeout: RPC_TEST_TIMEOUT_MS });

describe('T-14.5 双进程垂直切片（独立 Host 子进程 + RPC 客户端）', () => {
  it('echo 工具经独立 Host 进程真链路返回（认证→矩阵→handler）', async () => {
    const host = await spawnDevHost();
    const client = new RpcClient({ host: '127.0.0.1', port: host.port, token: host.token });
    try {
      await client.connect();
      const result = await client.call<{ echoed: { v: number }; host: string }>('tool.call', { v: 1 });
      expect(result.host).toBe('dev');
      expect(result.echoed).toEqual({ v: 1 });
    } finally {
      await client.close();
      await host.stop();
    }
  });

  it('未持令牌的进程间调用被矩阵拒绝（hello 即 -32001）', async () => {
    const host = await spawnDevHost();
    const client = new RpcClient({ host: '127.0.0.1', port: host.port, token: '' });
    try {
      await expect(client.connect()).rejects.toMatchObject({ code: -32001 });
    } finally {
      await client.close();
      await host.stop();
    }
  });

  it('TLS + pin（openssl 可用时）：相符连通、不符拒连（K8-①/A7）', async () => {
    let fixture: ReturnType<typeof tlsFixture>;
    try {
      fixture = tlsFixture();
    } catch (err) {
      if (err instanceof SkipError) return; // 本机无 openssl：条件跳过，不算失败
      throw err;
    }
    const host = await spawnDevHost({ tlsCertPath: fixture.certPath, tlsKeyPath: fixture.keyPath });
    try {
      // 相符：连通且 ping 可用
      const good = new RpcClient({
        host: '127.0.0.1',
        port: host.port,
        token: host.token,
        tls: { pin: fixture.pin },
      });
      await good.connect();
      expect(await good.call('host.ping')).toMatchObject({ pong: true });
      await good.close();
      // 不符：拒连，措辞对齐 HOST_PIN_MISMATCH 纪律
      const bad = new RpcClient({
        host: '127.0.0.1',
        port: host.port,
        token: host.token,
        tls: { pin: 'f'.repeat(64) },
      });
      await expect(bad.connect()).rejects.toThrow(/HOST_PIN_MISMATCH/);
    } finally {
      await host.stop();
    }
  });
});
