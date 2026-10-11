/**
 * 最小可运行 Host 进程（T-14.5 双进程切片专用入口；T-15 正式装配前的接缝）。
 *
 * 用法（构建后）：node build/rpc/dev-host.js --port 0 --token <agent 令牌>
 *   [--tls-cert <pem>] [--tls-key <pem>]
 * 就绪探测：stderr 打印 `rpc-host-ready port=<实际端口>`（端口 0 时为 OS 分配值）。
 * 内建 echo 工具（tool.call 原样回显，标注 host=dev）——真链路验证用，非真实管线（T-15）。
 * SIGTERM/SIGINT → 关停监听并退出（harness 进程树清理的配合面）。
 */
import { readFileSync } from 'node:fs';
import { generateAgentToken, hashPassword, tokenDigest, OperatorSessionStore } from './auth.js';
import { RpcHostServer } from './server.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const argOf = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`);
    return i === -1 || i + 1 >= args.length ? undefined : args[i + 1];
  };

  const port = Number(argOf('port') ?? '0');
  if (!Number.isInteger(port) || port < 0) {
    console.error('rpc-host-error invalid --port');
    process.exit(1);
  }
  const token = argOf('token') ?? generateAgentToken();
  const tlsCert = argOf('tls-cert');
  const tlsKey = argOf('tls-key');

  const server = new RpcHostServer({
    tables: {
      agentTokens: new Set([tokenDigest(token)]),
      // 切片不验 operator 口令（哈希仅占位）；会话语义测试在进程内用例覆盖
      sessions: new OperatorSessionStore({ storedHash: hashPassword('dev-host-no-operator') }),
      imDecisionTokens: new Set(),
    },
    handlers: {
      'tool.call': (params) => ({ echoed: params, host: 'dev' }),
    },
    audit: (event) => console.error(`rpc-audit kind=${event.kind} method=${event.method ?? ''}`),
  });

  const actual = await server.listen({
    port,
    host: '127.0.0.1',
    tls:
      tlsCert !== undefined && tlsKey !== undefined
        ? { cert: readFileSync(tlsCert, 'utf8'), key: readFileSync(tlsKey, 'utf8') }
        : undefined,
  });
  console.error(`rpc-host-ready port=${actual}`);

  let closing = false;
  const shutdown = (): void => {
    if (closing) return;
    closing = true;
    void server.close().then(() => process.exit(0));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

void main();
