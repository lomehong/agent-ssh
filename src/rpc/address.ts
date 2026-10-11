/**
 * 客户端地址键控与环回判定（T-13.5 预重构：自 src/transport/http.ts 原样迁入，零行为变化）。
 *
 * 覆盖 IPv6 ::1/[::1] 文法、::ffff: 映射拼写与 127.0.0.0/8 前缀的判定原语
 * 全在本模块（canonicalAddress/isTrustedPeer/keyOf）。RPC 层（T-14）的
 * 「非环回绑定强制 TLS」环回判定复用此处实现（方案 §3.1），届时按需扩导出；
 * 本票保持纯机械迁移，不新增导出面。
 */
import { isIP } from 'net';
import type { IncomingMessage } from 'http';

/**
 * 一次尝试计费到哪个客户端：chargedAddress 解析出的地址，
 * 由 keyOf 分组成键。只在此分组一次，使 header 逻辑的
 * 任何路径都无法交回未分组的地址——信任在内部决定，
 * 基于确切对端，在任何分组发生之前。
 */
export function clientKey(
  req: IncomingMessage,
  trustProxy: boolean,
  trustedProxies?: string[],
): { key: string; forwardedIgnored: boolean } {
  const { address, forwardedIgnored } = chargedAddress(req, trustProxy, trustedProxies);
  return { key: keyOf(address), forwardedIgnored };
}

/**
 * 一次尝试计费到的确切地址。
 *
 * 套接字的远程地址，直连时即真实客户端——本服务器的
 * 正常运行方式。X-Forwarded-For 仅在代理被显式信任时读取：
 * 无条件采信会让任何客户端伪造自己的键，
 * 从而完全绕开限制。
 *
 * 读取时取**最右**条目而非最左。代理追加它看到的地址，
 * 最右条目是最近受信代理观察到的，左侧全部来自客户端。
 * 读最左比没有限制更糟：发 X-Forwarded-For: 10.0.0.1 的客户端
 * 每次请求铸造新预算——实测九个错误令牌零 429——发受害者
 * 地址则烧*他们的*预算，锁死正确令牌。
 *
 *
 * 假定恰好一个受信代理在前，即 --trustProxy 的含义。两个的链
 * 需要倒数第二个，此处不猜深度。非 IP 地址一律丢弃
 * 而非用作映射键。
 */
function chargedAddress(
  req: IncomingMessage,
  trustProxy: boolean,
  trustedProxies?: string[],
): { address: string; forwardedIgnored: boolean } {
  const peer = canonicalAddress(req.socket.remoteAddress ?? 'unknown');
  const forwarded = req.headers['x-forwarded-for'];
  if (!trustProxy || forwarded === undefined) return { address: peer, forwardedIgnored: false };

  // 最右条目是代理写的仅当代理确实追加了。头部本身
  // 不说明是否如此，所以*对端*必须是代理——否则
  // 直达监听器的客户端发送一条伪造条目，该条目即最右，
  // 它自选键。此键控修复要阻止的两个攻击恰在该配置下复活。
  //
  if (!isTrustedPeer(peer, trustedProxies)) {
    return { address: peer, forwardedIgnored: true };
  }

  const raw = Array.isArray(forwarded) ? forwarded.join(',') : forwarded;
  const entries = raw.split(',').map((e) => e.trim()).filter(Boolean);
  const nearest = entries[entries.length - 1];
  const address = nearest === undefined ? undefined : forwardedAddress(nearest);
  if (address === undefined) return { address: peer, forwardedIgnored: true };
  return { address, forwardedIgnored: false };
}

/**
 * 地址计费到的键：IPv4 按自身，IPv6 按 /64。
 *
 * 用户通常至少分配一个 /64，/64 即客户端。提供商将多个客户
 * 放在同一 /64 时共享预算，如 IPv4 NAT 后的主机。
 *
 * 三个 IPv6 范围不是客户端自己的 /64 而是携带 IPv4 地址的方式，
 * 按那个地址键控：IPv4 映射 ::ffff:0:0/96 各种拼写、NAT64
 * 知名前缀 64:ff9b::/96 下转换部署看到的每个 IPv4 客户端、
 * 以及 IPv4 兼容 ::/96。按 /64 分组则每个都会把所有 IPv4
 * 客户端放到一个键上。使用自有前缀的转换器不被识别，
 * 其 IPv4 客户端共享该前缀的 /64。回环保持 ::1，无论拼写。
 */
function keyOf(address: string): string {
  if (isIP(address) !== 6) return address;
  const g = ipv6Groups(address);
  if (g.slice(0, 7).every((n) => n === 0) && g[7] === 1) return '::1';
  const lowZero = g[2] === 0 && g[3] === 0 && g[4] === 0;
  const carriesIpv4 = lowZero && (
    (g[0] === 0 && g[1] === 0 && (g[5] === 0 || g[5] === 0xffff)) ||
    (g[0] === 0x64 && g[1] === 0xff9b && g[5] === 0)
  );
  if (carriesIpv4) return `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
  return `${g.slice(0, 4).map((n) => n.toString(16)).join(':')}::/64`;
}

/**
 * IPv6 地址为其八个 16 位组，不论拼写：区域丢弃、::
 * 展开、点分 IPv4 尾读作最后两组、大小写和前导零由
 * 按数值读每组消除。期望 net.isIP 已接受的地址。
 */
function ipv6Groups(address: string): number[] {
  const [head, tail] = address.split('%')[0].split('::');
  const parse = (part: string | undefined): number[] =>
    part === undefined || part === ''
      ? []
      : part.split(':').flatMap((group) => {
        if (!group.includes('.')) return [parseInt(group, 16)];
        const [a, b, c, d] = group.split('.').map(Number);
        return [(a << 8) | b, (c << 8) | d];
      });
  const headGroups = parse(head);
  const tailGroups = parse(tail);
  if (tail === undefined) return headGroups;
  return [...headGroups, ...Array(8 - headGroups.length - tailGroups.length).fill(0), ...tailGroups];
}

/**
 * 对端是否可以代表其他客户端说话。
 *
 * 裸 --trustProxy 意味着回环对端，即 README 要求的部署：
 * 服务器绑 127.0.0.1，同主机代理终结 TLS。别处的代理
 * 必须具名，因为「信任连接者」正是让头部可伪造的假设。
 *
 */
function isTrustedPeer(peer: string, trustedProxies?: string[]): boolean {
  if (trustedProxies !== undefined && trustedProxies.length > 0) {
    return trustedProxies.includes(peer);
  }
  return peer === '127.0.0.1' || peer === '::1' || peer.startsWith('127.');
}

/**
 * 一条 X-Forwarded-For 条目作为地址，非地址则为 undefined。
 *
 * net.isIP 拒绝带括号和端口后缀的拼写，IPv6 在此头部
 * 通常是那样出现的——拒绝静默把所有客户端折叠到代理的键上，
 * 比不键控还糟。
 */
function forwardedAddress(entry: string): string | undefined {
  let candidate = entry;
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);
  if (bracketed) candidate = bracketed[1];
  // 尾随 :port 仅当剩余部分不是 IPv6 字面量：::1 自有冒号，
  // 不得截断。
  else if (isIP(candidate) === 0 && /^[^:]+:\d+$/.test(candidate)) {
    candidate = candidate.slice(0, candidate.lastIndexOf(':'));
  }
  candidate = canonicalAddress(candidate);
  return isIP(candidate) === 0 ? undefined : candidate;
}

/**
 * ::ffff:127.0.0.1 和 127.0.0.1 是同一客户端；键控相同。
 *
 * 仅该拼写且后续为 IPv4 时：::ffff:c000:280 剥离为
 * c000:280 就不是地址了，请求回落到代理的键。映射地址
 * 其余拼写经 keyOf 按值到达 IPv4 键。
 * 大小写保留原样，因为这也是信任检查对照 --trustedProxies
 * 的对端——%WAN 这样的区域必须按写法匹配。
 */
function canonicalAddress(address: string): string {
  return address.startsWith('::ffff:') && isIP(address.slice(7)) === 4 ? address.slice(7) : address;
}

// T-14 扩导出：环回绑定判定（./transport-security）复用本归一实现（方案 §3.1）。
export { canonicalAddress };
