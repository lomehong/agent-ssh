import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, connect } from 'node:net';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { allServersUp, checkAllServers, setupEnv, createAppConfig } from './fixtures.js';
import type { AppConfig } from '../../src/types.js';

// Port-forwarding end to end against the real ssh-admin container:
// - local: a loopback connection here crosses the tunnel and reads the
//   container's own SSH banner from 127.0.0.1:2222 (inside the container);
// - dynamic: the same banner through the hand-rolled SOCKS5 path;
// - remote: the container dials its own bound port with bash /dev/tcp and the
//   bytes land on a local echo server through the manager's accept() path.

let env: ReturnType<typeof setupEnv>;
let registry: ConnectionRegistry | undefined;

const AUTO_CONFIG: AppConfig = (() => {
  const base = createAppConfig();
  const p = { ...base.profiles.find((x) => x.name === 'admin')!, approvalPolicy: 'auto' as const };
  return { ...base, profiles: [p] };
})();

function readUntil(socket: import('node:net').Socket, needle: string, timeoutMs = 3000): Promise<string> {
  return new Promise((resolve, reject) => {
    let seen = '';
    const timer = setTimeout(() => reject(new Error(`timeout; seen: ${JSON.stringify(seen)}`)), timeoutMs);
    socket.on('data', (b: Buffer) => {
      seen += b.toString('utf8');
      if (seen.includes(needle)) {
        clearTimeout(timer);
        resolve(seen);
      }
    });
    socket.on('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

beforeAll(async () => {
  if (!allServersUp(await checkAllServers())) return;
  env = setupEnv();
  process.env.SSH_MCP_ADMIN_PASSWORD = 'secret';
});

afterAll(async () => {
  await registry?.closeAll();
  env?.restore();
});

describe.skipIf(!allServersUp(await checkAllServers()))('port forwarding (agent-ssh)', () => {
  // All three modes need a forwarding-enabled sshd: the stock linuxserver
  // fixture ships AllowTcpForwarding no (and its init hooks cannot win the
  // config-generation race — see docker/bastion-sshd/Dockerfile).
  it('local forward: loopback here reaches the container through the tunnel', async () => {
    process.env.SSH_MCP_FWD_PASSWORD = 'bastionpass';
    const base = createAppConfig();
    const p = {
      ...base.profiles.find((x) => x.name === 'admin')!,
      approvalPolicy: 'auto' as const,
      name: 'fwd', host: '127.0.0.1', port: 2229, user: 'bastion',
    };
    const cfg = { ...base, defaults: { ...base.defaults, allowDynamicForwarding: true }, profiles: [p] };
    const r = new ConnectionRegistry(cfg, 'insecure');
    const conn = await r.getOrCreate('fwd');

    const info = await conn.openForward({ mode: 'local', listenPort: 0, targetHost: '127.0.0.1', targetPort: 2222 });
    const port = Number(info.listen.split(':')[1]);

    const socket = connect(port, '127.0.0.1');
    const seen = await readUntil(socket, 'SSH-2.0');
    expect(seen).toContain('SSH-2.0');
    socket.destroy();

    const closed = await conn.closeForward(info.id);
    expect(closed.outcome).toBe('closed');
    await r.closeAll();
  }, 30000);

  it('dynamic forward: SOCKS5 CONNECT reaches the container sshd banner', async () => {
    // The forwarding-enabled fixture (ssh-forward, port 2229) — dynamic is also
    // the opt-in switch proof: the stock AUTO_CONFIG has it off.
    const enabled = createAppConfig();
    const p = {
      ...enabled.profiles.find((x) => x.name === 'admin')!,
      approvalPolicy: 'auto' as const,
      name: 'fwd', host: '127.0.0.1', port: 2229, user: 'bastion',
    };
    const cfg = { ...enabled, defaults: { ...enabled.defaults, allowDynamicForwarding: true }, profiles: [p] };
    process.env.SSH_MCP_FWD_PASSWORD = 'bastionpass';
    const r = new ConnectionRegistry(cfg, 'insecure');
    const conn = await r.getOrCreate('fwd');

    await expect(
      new ConnectionRegistry(AUTO_CONFIG, 'insecure').getOrCreate('admin').then((c) => c.openForward({ mode: 'dynamic', listenPort: 0 })),
    ).rejects.toThrow(/disabled/);

    const info = await conn.openForward({ mode: 'dynamic', listenPort: 0 });
    const port = Number(info.listen.split(':')[1]);

    const sock = connect(port, '127.0.0.1');
    sock.write(Buffer.from([0x05, 0x01, 0x00]));
    await new Promise<void>((resolve) => sock.once('data', () => resolve()));
    // CONNECT 127.0.0.1:2222 — resolved from the CONTAINER (its own sshd).
    sock.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x08, 0xae]));
    const seen = await readUntil(sock, 'SSH-2.0');
    expect(seen).toContain('SSH-2.0');
    sock.destroy();
    await conn.closeForward(info.id);
    await r.closeAll();
  }, 30000);

  it('remote forward: a container-side dial lands on the local echo server', async () => {
    const echo = createServer((s) => s.end('REMOTE-E2E\n'));
    await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
    const echoPort = (echo.address() as { port: number }).port;

    // sshd refuses a bind to port 0 on a remote forward, so bind a fixed port
    // on the forwarding-enabled fixture and dial it from inside that container.
    process.env.SSH_MCP_FWD2_PASSWORD = 'bastionpass';
    const enabled = createAppConfig();
    const p2 = {
      ...enabled.profiles.find((x) => x.name === 'admin')!,
      approvalPolicy: 'auto' as const,
      name: 'fwd2', host: '127.0.0.1', port: 2229, user: 'bastion',
    };
    const r2 = new ConnectionRegistry({ ...enabled, profiles: [p2] }, 'insecure');
    const conn2 = await r2.getOrCreate('fwd2');

    const info = await conn2.openForward({ mode: 'remote', listenPort: 23457, targetHost: '127.0.0.1', targetPort: echoPort });
    expect(Number(info.listen.split(':')[1])).toBe(23457);

    // The container dials its own bound port; bash /dev/tcp + head pulls the
    // bytes that must have crossed: container sshd → channel → accept() → echo.
    const result = await conn2.exec(
      `timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/23457 && head -c 10 <&3'`,
      { timeoutMs: 8000 },
    );
    expect(result.stdout).toContain('REMOTE-E2E');

    await conn2.closeForward(info.id);
    await r2.closeAll();
    await new Promise<void>((r) => echo.close(() => r()));
  }, 30000);
});
