import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ConnectionRegistry } from '../../src/ssh/connection-registry.js';
import { setupEnv, createAppConfig } from './fixtures.js';
import { DeviceSimulator, DIALECTS } from './device-simulator.js';
import type { AppConfig, DeviceType, Profile } from '../../src/types.js';

// T-05: the four vendor archives, end to end — a REAL SSH server (ssh2 server
// mode) speaking each vendor's CLI dialect, driven through the raw-PTY tools'
// underlying connection path: open → auto paging-off (sent by the manager) →
// prompt detected → query command answered → quit closes the session.

let env: ReturnType<typeof setupEnv>;

const VENDORS: Array<{ deviceType: DeviceType }> = [
  { deviceType: 'huawei' },
  { deviceType: 'h3c' },
  { deviceType: 'cisco' },
  { deviceType: 'ruijie' },
];

const simulators: DeviceSimulator[] = [];

beforeAll(async () => {
  env = setupEnv();
  for (const v of VENDORS) {
    process.env[`SSH_MCP_SIM_${v.deviceType.toUpperCase()}_PASSWORD`] = 'simpass';
    simulators.push(await DeviceSimulator.start(v.deviceType));
  }
});

afterAll(async () => {
  for (const sim of simulators) await sim.stop();
  env?.restore();
});

function configFor(deviceType: DeviceType, port: number): AppConfig {
  const base = createAppConfig();
  const profile: Profile = {
    ...base.profiles.find((x) => x.name === 'admin')!,
    approvalPolicy: 'auto',
    name: `sim-${deviceType}`,
    host: '127.0.0.1',
    port,
    user: 'operator',
    deviceType,
  };
  return { ...base, profiles: [profile] };
}

describe('device archives (huawei/h3c/cisco/ruijie)', () => {
  for (const { deviceType } of VENDORS) {
    it(`${deviceType}: paging-off is sent automatically, prompt is detected, query round-trips`, async () => {
      const dialect = DIALECTS[deviceType];
      const sim = simulators[VENDORS.findIndex((v) => v.deviceType === deviceType)];
      const registry = new ConnectionRegistry(configFor(deviceType, sim.port), 'insecure');
      const conn = await registry.getOrCreate(`sim-${deviceType}`);

      const info = await conn.openPtySession({ name: `${deviceType}-s1` });
      expect(info.closed).toBe(false);

      // The manager sends the archive's paging-off command through the same
      // write path user input takes; the simulator's ack plus the prompt come
      // back through the buffer.
      let cursor = 0;
      let seen = '';
      let promptDetected = false;
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 100));
        const read = conn.readPtySession(`${deviceType}-s1`, cursor, 32768);
        seen += read.output;
        cursor = read.cursor;
        promptDetected = (read as { promptDetected?: boolean }).promptDetected ?? false;
        if (seen.includes(dialect.disablePagingAck) && promptDetected) break;
      }
      expect(seen).toContain(dialect.disablePaging);
      expect(seen).toContain(dialect.disablePagingAck);
      expect(promptDetected).toBe(true);

      const written = conn.writePtySession(`${deviceType}-s1`, `${dialect.queryCommand}\n`);
      expect(written.delivered).toBe(true);

      seen = '';
      for (let i = 0; i < 40 && !seen.includes('Version'); i++) {
        await new Promise((r) => setTimeout(r, 100));
        const read = conn.readPtySession(`${deviceType}-s1`, cursor, 32768);
        seen += read.output;
        cursor = read.cursor;
      }
      expect(seen).toContain(dialect.queryOutput);

      // quit tears the session down remotely.
      conn.writePtySession(`${deviceType}-s1`, 'quit\n');
      await new Promise((r) => setTimeout(r, 300));
      const listed = conn.listPtySessions();
      const mine = listed.find((s) => s.name === `${deviceType}-s1`);
      expect(mine?.closed).toBe(true);
      expect(mine?.closeReason).toBe('remote');

      await registry.closeAll();
    }, 30000);
  }
});
