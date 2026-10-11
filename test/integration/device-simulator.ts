import { createHash } from 'node:crypto';
import { Server, utils, type Connection } from 'ssh2';

/**
 * An in-process network-device CLI simulator built on ssh2's SERVER mode.
 *
 * One instance speaks one vendor dialect: it greets with a banner, shows the
 * vendor prompt, honours that vendor's paging-off command, answers one canned
 * query command, and closes the session on quit/exit. It is a fixture, not an
 * emulator — enough CLI behaviour to prove the archive wiring (auto paging-off,
 * prompt detection, round-trip read/write) against a REAL SSH server speaking
 * PTY, and nothing more.
 */

export interface DeviceDialect {
  banner: string;
  prompt: string;
  disablePaging: string;
  disablePagingAck: string;
  queryCommand: string;
  queryOutput: string;
}

export const DIALECTS: Record<string, DeviceDialect> = {
  huawei: {
    banner: '\r\nInfo: The max number of VTY users is 8 (8 used).\r\n',
    prompt: '<sim-huawei>',
    disablePaging: 'screen-length 0 temporary',
    disablePagingAck: 'Info: Succeeded in setting the screen length to 0.\r\n',
    queryCommand: 'display version',
    queryOutput: 'Huawei Versatile Routing Platform Software\r\nVRP (R) software, Version 8.210\r\n',
  },
  h3c: {
    banner: '\r\n<sim-h3c>Comware Software\r\n',
    prompt: '<sim-h3c>',
    disablePaging: 'screen-length disable',
    disablePagingAck: 'The current configuration is as follows.\r\n',
    queryCommand: 'display version',
    queryOutput: 'H3C Comware Platform Software, Version 7.1.070\r\n',
  },
  cisco: {
    banner: '\r\nsim-cisco line is available.\r\n',
    prompt: 'sim-cisco>',
    disablePaging: 'terminal length 0',
    disablePagingAck: '',
    queryCommand: 'show version',
    queryOutput: 'Cisco IOS Software, Version 15.2\r\n',
  },
  ruijie: {
    banner: '\r\nRuijie Full 10G Routing Switch\r\n',
    prompt: 'sim-ruijie>',
    disablePaging: 'terminal length 0',
    disablePagingAck: '',
    queryCommand: 'show version',
    queryOutput: 'Ruijie RGOS 11.x firmware\r\n',
  },
}

export class DeviceSimulator {
  readonly port: number;
  private readonly server: Server;
  private readonly hostKey: Buffer;

  private constructor(port: number, server: Server, hostKey: Buffer) {
    this.port = port;
    this.server = server;
    this.hostKey = hostKey;
  }

  fingerprint(): string {
    return 'SHA256:' + createHash('sha256').update(this.hostKey).digest('base64');
  }

  static start(device: keyof typeof DIALECTS, password = 'simpass'): Promise<DeviceSimulator> {
    const dialect = DIALECTS[device];
    const { private: hostKey } = utils.generateKeyPairSync('ed25519');

    return new Promise((resolve, reject) => {
      const server = new Server({ hostKeys: [hostKey] }, (conn: Connection) => {
        conn.on('authentication', (ctx) => {
          if (ctx.method === 'password' && ctx.username === 'operator' && ctx.password === password) return ctx.accept();
          ctx.reject();
        });
        conn.on('ready', () => {
          conn.on('session', (accept) => {
            const session = accept();
            // The client asks for the PTY before the shell; no handler here
            // means ssh2 rejects the request and the client sees
            // "Unable to request a pseudo-terminal".
            session.once('pty', (acceptPty) => acceptPty());
            session.once('shell', (acceptShell) => {
              const stream = acceptShell();
              let line = '';
              let paging = false;
              const write = (text: string) => stream.write(text);
              write(dialect.banner + dialect.prompt);
              stream.on('data', (chunk: Buffer) => {
                line += chunk.toString('utf8');
                if (!line.endsWith('\r') && !line.endsWith('\n')) return;
                const command = line.replace(/[\r\n]+$/, '').trim();
                line = '';
                // A real PTY echoes typed input — the archive tests assert on
                // that echo, and its absence would hide a broken write path.
                write(command.length > 0 ? command + '\r\n' : '');
                if (command.length === 0) {
                  write(dialect.prompt);
                } else if (command === dialect.disablePaging) {
                  paging = true;
                  write(dialect.disablePagingAck + dialect.prompt);
                } else if (command === dialect.queryCommand) {
                  write(dialect.queryOutput + dialect.prompt);
                } else if (command === 'quit' || command === 'exit') {
                  write('Bye.\r\n');
                  stream.end();
                  return;
                } else {
                  write(`% Invalid input at '^' marker.\r\n` + dialect.prompt);
                }
                void paging;
              });
            });
          });
        });
      });

      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        const port = addr && typeof addr === 'object' ? addr.port : 0;
        resolve(new DeviceSimulator(port, server, hostKey));
      });
      server.once('error', reject);
    });
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }
}
