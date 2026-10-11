import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { clientKey } from '../../../src/rpc/address.js';
import {
  AuthFailureLimiter,
  ClientRateLimiter,
  DEFAULT_AUTH_FAILURE_LIMIT,
  MAX_TRACKED_CLIENTS,
} from '../../../src/rpc/limiters.js';

/**
 * T-15 自 test/unit/transport/http.test.ts 原样迁入（该文件随 transport/http.ts
 * 删除而消亡）：限流器与地址键控的纯单测是 src/rpc/ 迁入件的资产，跟着代码走。
 * 语义零改动——仅把动态导入自 http.js 改指 rpc 模块、行为级的 HTTP 服务器用例
 * （default-limit 十次 401→429、/64 双预算端到端）随服务器删除，登记于票面。
 */

describe('clientKey', () => {
  // `clientKey` also reports whether a forwarded entry was ignored, which the handler
  // uses to warn. These cases are about the key.
  const clientKeyOf = (req: any, trustProxy: boolean, trusted?: string[]) =>
    clientKey(req, trustProxy, trusted).key;
  const ignoredFor = (req: any, trustProxy: boolean) => clientKey(req, trustProxy).forwardedIgnored;
  const fake = (remoteAddress: string | undefined, forwarded?: string | string[]) => ({
    socket: { remoteAddress },
    headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
  }) as any;

  it('uses the socket address, which is the real client on a direct connection', async () => {
    expect(clientKeyOf(fake('203.0.113.7'), false)).toBe('203.0.113.7');
  });

  it('treats the IPv6-mapped form as the same client', async () => {
    expect(clientKeyOf(fake('::ffff:127.0.0.1'), false)).toBe('127.0.0.1');
    expect(clientKeyOf(fake('127.0.0.1'), false)).toBe('127.0.0.1');
  });

  it('ignores X-Forwarded-For unless a proxy is trusted', async () => {
    // Otherwise a client picks its own key and opts out of the limit.
    expect(clientKeyOf(fake('203.0.113.7', '9.9.9.9'), false)).toBe('203.0.113.7');
    // A loopback peer is the proxy in the deployment the README describes.
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9'), true)).toBe('9.9.9.9');
  });

  it('reads the rightmost forwarded entry, which is the hop the proxy itself added', async () => {
    // Not the leftmost. A proxy appends the address it saw, so everything to the left of
    // the last entry came from the client — reading the leftmost let a client mint a fresh
    // budget per request, and let it burn a victim's budget by naming their address.
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9, 10.0.0.5, 10.0.0.9'), true)).toBe('10.0.0.9');
    expect(clientKeyOf(fake('127.0.0.1', ['8.8.8.8', '7.7.7.7']), true)).toBe('7.7.7.7');
  });

  it('discards a forwarded value that is not an address', async () => {
    // Otherwise arbitrary client text becomes a map key.
    expect(clientKeyOf(fake('127.0.0.1', 'not-an-ip'), true)).toBe('127.0.0.1');
    expect(clientKeyOf(fake('127.0.0.1', '9.9.9.9, garbage'), true)).toBe('127.0.0.1');
  });

  it('normalises the forwarded value the same way as the socket address', async () => {
    expect(clientKeyOf(fake('127.0.0.1', '::ffff:203.0.113.9'), true)).toBe('203.0.113.9');
  });

  it('will not let a client that is not the proxy speak for others', () => {
    // The rightmost entry is proxy-authored only if a proxy appended one. On a direct
    // connection the client's single forged entry *is* the rightmost, so both attacks
    // this keying was written to stop came back alive until the peer was checked.
    expect(clientKeyOf(fake('203.0.113.50', '10.0.0.1'), true)).toBe('203.0.113.50');
    expect(ignoredFor(fake('203.0.113.50', '10.0.0.1'), true)).toBe(true);
    // Naming the proxy makes it trusted again.
    expect(clientKeyOf(fake('10.9.9.9', '198.51.100.42'), true, ['10.9.9.9']))
      .toBe('198.51.100.42');
  });

  it.each([
    ['[2001:db8::1]:443', '2001:db8:0:0::/64'],
    ['[2001:db8::1]', '2001:db8:0:0::/64'],
    ['198.51.100.5:51234', '198.51.100.5'],
    ['::1', '::1'],
  ])('reads %s as %s', (forwarded, expected) => {
    // `net.isIP` rejects the bracketed and port-suffixed spellings, which is how IPv6
    // usually appears here — and rejecting silently collapsed every client onto the
    // proxy's key, which is worse than not keying at all.
    expect(clientKeyOf(fake('127.0.0.1', forwarded), true)).toBe(expected);
  });

  it('says when a forwarded entry was ignored, so the handler can warn', () => {
    expect(ignoredFor(fake('127.0.0.1', 'garbage'), true)).toBe(true);
    expect(ignoredFor(fake('127.0.0.1', '9.9.9.9'), true)).toBe(false);
    expect(ignoredFor(fake('127.0.0.1'), true)).toBe(false);
  });

  it('falls back rather than throwing when there is no address', async () => {
    expect(clientKeyOf(fake(undefined), false)).toBe('unknown');
    // A trusted proxy that sent nothing useful must not produce an empty key.
    expect(clientKeyOf(fake('127.0.0.1', '   '), true)).toBe('127.0.0.1');
  });

  it('keys an IPv6 client by its /64, not its full address', () => {
    // A subscriber is handed a whole /64, so the /64 is the client.
    const a = clientKeyOf(fake('2001:db8:1:2::a'), false);
    expect(a).toBe('2001:db8:1:2::/64');
    expect(clientKeyOf(fake('2001:db8:1:2:ffff:ffff:ffff:fffe'), false)).toBe(a);
    // A neighbouring /64 is a different client.
    expect(clientKeyOf(fake('2001:db8:1:3::a'), false)).toBe('2001:db8:1:3::/64');
    // The same through a trusted proxy.
    expect(clientKeyOf(fake('127.0.0.1', '2001:db8:1:2::b'), true)).toBe(a);
  });

  it.each([
    ['2001:DB8:1:2::A', '2001:db8:1:2::/64'],
    ['2001:0db8:0001:0002:0:0:0:a', '2001:db8:1:2::/64'],
    ['2001:db8:1:2::203.0.113.9', '2001:db8:1:2::/64'],
    // A dotted tail stands for two groups; miscounting it shifts where `::` expands.
    ['2001::1:2:3:4:203.0.113.9', '2001:0:1:2::/64'],
    ['fe80::1%en0', 'fe80:0:0:0::/64'],
    // A zone name may itself contain a dot (a VLAN interface) and must not count as one.
    ['2001:db8::1:2:3:4:5%eth0.1', '2001:db8:0:1::/64'],
    // An address that carries an IPv4 address is keyed by that address, in any spelling.
    ['::FFFF:203.0.113.9', '203.0.113.9'],
    ['0:0:0:0:0:ffff:203.0.113.9', '203.0.113.9'],
    ['::ffff:cb00:7109', '203.0.113.9'],
    ['::FFFF:CB00:7109', '203.0.113.9'],
    ['64:ff9b::203.0.113.9', '203.0.113.9'],
    ['::203.0.113.9', '203.0.113.9'],
  ])('normalises %s to %s', (address, expected) => {
    // Every spelling of one address must reach one key.
    expect(clientKeyOf(fake(address), false)).toBe(expected);
    expect(clientKeyOf(fake('127.0.0.1', address), true)).toBe(expected);
  });

  it('keeps clients that arrive as IPv4-in-IPv6 apart', () => {
    // Grouped by /64, every one of these would share `64:ff9b:0:0::/64` or `0:0:0:0::/64`.
    expect(clientKeyOf(fake('64:ff9b::1.2.3.4'), false)).toBe('1.2.3.4');
    expect(clientKeyOf(fake('64:ff9b::5.6.7.8'), false)).toBe('5.6.7.8');
    // Outside those ranges a low address is an ordinary /64.
    expect(clientKeyOf(fake('64:ff9b:1::1.2.3.4'), false)).toBe('64:ff9b:1:0::/64');
  });

  it('keeps loopback as itself, however it is written', () => {
    expect(clientKeyOf(fake('::1'), false)).toBe('::1');
    // Not the IPv4-compatible `0.0.0.1` it would otherwise read as.
    expect(clientKeyOf(fake('0:0:0:0:0:0:0:1'), false)).toBe('::1');
    expect(clientKeyOf(fake('::1%lo0'), false)).toBe('::1');
  });

  it('still recognises a named IPv6 proxy by its full address', () => {
    // The prefix is the *key*. Trust is decided on the exact peer, or every host in the
    // proxy's /64 would be allowed to speak for other clients.
    expect(clientKeyOf(fake('2001:db8:9::10', '198.51.100.42'), true, ['2001:db8:9::10']))
      .toBe('198.51.100.42');
    // A neighbour in the proxy's /64 is not the proxy: its header is ignored, and it is
    // charged as itself.
    expect(clientKey(fake('2001:db8:9::11', '198.51.100.42'), true, ['2001:db8:9::10']))
      .toEqual({ key: '2001:db8:9:0::/64', forwardedIgnored: true });
    // The proxy itself, with a header it cannot read, is charged by its /64 too.
    expect(clientKey(fake('2001:db8:9::10', 'garbage'), true, ['2001:db8:9::10']))
      .toEqual({ key: '2001:db8:9:0::/64', forwardedIgnored: true });
  });

  it('matches a named proxy as Node reports it, zone case included', () => {
    // The trust check compares the peer as written. Folding its case lost a match on a
    // link-local proxy whose interface name has capitals.
    expect(clientKeyOf(fake('fe80::1%WAN', '198.51.100.42'), true, ['fe80::1%WAN']))
      .toBe('198.51.100.42');
  });
});

describe('the documented default limit', () => {
  it('agrees with the README value', () => {
    // 行为级「十次 401→429」用例随 HTTP 服务器删除（T-15）；字面量对照 README
    // 的常量一致性断言随迁移保留。
    expect(DEFAULT_AUTH_FAILURE_LIMIT).toBe(10);
  });
});

describe('AuthFailureLimiter', () => {
  it('keeps the tracked-client map bounded', () => {
    const limiter = new AuthFailureLimiter(5) as any;
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 50; i++) limiter.recordFailure(`10.0.${i >> 8}.${i & 255}`);
    // The only bound on this map, and the key is attacker-chosen under --trustProxy.
    expect(limiter.buckets.size).toBeLessThanOrEqual(MAX_TRACKED_CLIENTS);
  });

  it('gives an arriving client one attempt while every bucket is spent', () => {
    const limiter = new AuthFailureLimiter(10);
    // Saturate the table with exhausted buckets, which is remotely reachable.
    for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) {
      for (let n = 0; n < 10; n++) limiter.recordFailure(`atk-${i}`);
    }
    // `peek` allows a key it has never seen, so the first attempt is free; the bucket is
    // created by the failure and starts spent, so the second is refused. On an unsaturated
    // table the same client would have the full budget — that collapse is the cost of not
    // refunding, and it is asserted here so it cannot change unnoticed.
    expect(limiter.peek('arriving').allowed).toBe(true);
    limiter.recordFailure('arriving');
    expect(limiter.peek('arriving').allowed).toBe(false);

    const unsaturated = new AuthFailureLimiter(10);
    unsaturated.recordFailure('arriving');
    expect(unsaturated.peek('arriving').allowed).toBe(true);
  });

  it('does not refund a spent budget when the map is recycled', () => {
    const limiter = new AuthFailureLimiter(2);
    for (let i = 0; i < 2; i++) limiter.recordFailure('victim');
    expect(limiter.peek('victim').allowed).toBe(false);

    // Evicting by age discarded the *blocked* bucket first — its lastRefill is frozen,
    // because peek does not mutate — and then handed the key a fresh full budget, so
    // cycling keys cleared a lockout.
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 10; i++) limiter.recordFailure(`filler-${i}`);
    expect(limiter.peek('victim').allowed).toBe(false);
  });

  it('reports the wait until the next attempt, not a whole interval', () => {
    const T0 = 1_800_000_000_000;
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new AuthFailureLimiter(3); // one attempt back every 20s
      for (let n = 0; n < 3; n++) limiter.recordFailure('a');
      vi.setSystemTime(T0 + 7_500);
      expect(limiter.peek('a')).toEqual({ allowed: false, retryAfterMs: 12_500 });
    } finally {
      vi.useRealTimers();
    }
  });

  it('recovers once a saturated table has refilled', () => {
    const T0 = 1_800_000_000_000;
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
    try {
      const limiter = new AuthFailureLimiter(10);
      for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) {
        for (let n = 0; n < 10; n++) limiter.recordFailure(`atk-${i}`);
      }
      // An hour later every one of those buckets is full again. The scan used to read the
      // stored count, which never changes for a key that stops sending, so the table
      // stayed "saturated" for good: every new client started empty, and one typo made
      // its correct token wait. Measured on 09ecbad.
      vi.setSystemTime(T0 + 3_600_000);
      // The whole budget, not merely a second attempt: nine failures still leave room,
      // and the tenth spends it — the same as on a table that was never saturated.
      for (let n = 0; n < 9; n++) limiter.recordFailure('arriving');
      expect(limiter.peek('arriving').allowed).toBe(true);
      limiter.recordFailure('arriving');
      expect(limiter.peek('arriving').allowed).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('ClientRateLimiter', () => {
  const T0 = 1_800_000_000_000;

  // Every test here runs on a frozen clock, including those that never move it: a slow
  // run must not refill a bucket between two calls and turn an expected refusal into an
  // admission.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'], now: T0 });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('gives each client its own budget', () => {
    const limiter = new ClientRateLimiter(2);
    expect(limiter.tryConsume('a').allowed).toBe(true);
    expect(limiter.tryConsume('a').allowed).toBe(true);
    expect(limiter.tryConsume('a').allowed).toBe(false);
    // The point of #187: one client spending its budget leaves another's whole.
    expect(limiter.tryConsume('b').allowed).toBe(true);
    expect(limiter.tryConsume('b').allowed).toBe(true);
  });

  it('keeps the tracked-client map bounded', () => {
    const limiter = new ClientRateLimiter(5) as any;
    for (let i = 0; i < MAX_TRACKED_CLIENTS + 50; i++) limiter.tryConsume(`10.0.${i >> 8}.${i & 255}`);
    expect(limiter.buckets.size).toBe(MAX_TRACKED_CLIENTS);
  });

  it('evicts the fullest bucket, not the oldest', () => {
    const limiter = new ClientRateLimiter(3) as any;
    // The oldest entry is the spent one. Evicting by age would hand it a fresh budget.
    for (let n = 0; n < 3; n++) limiter.tryConsume('spent');
    for (let i = 0; i < MAX_TRACKED_CLIENTS - 2; i++) {
      limiter.tryConsume(`filler-${i}`);
      limiter.tryConsume(`filler-${i}`);
    }
    limiter.tryConsume('idle'); // 2 of 3 left: the fullest in the table
    expect(limiter.buckets.size).toBe(MAX_TRACKED_CLIENTS);

    limiter.tryConsume('arriving');
    expect(limiter.buckets.has('idle')).toBe(false);
    expect(limiter.buckets.has('spent')).toBe(true);
    expect(limiter.tryConsume('spent').allowed).toBe(false);
  });

  it('serves an arriving client even when every tracked bucket is spent', () => {
    const limiter = new ClientRateLimiter(1);
    for (let i = 0; i < MAX_TRACKED_CLIENTS; i++) limiter.tryConsume(`holder-${i}`);
    // Unlike the failure budget: a request bucket exists only past the token check, so a
    // saturated table is 1024 token holders, and refusing a newcomer's first request
    // would punish it for their traffic.
    expect(limiter.tryConsume('arriving').allowed).toBe(true);
  });

  it('refills on the clock and re-arms afterwards', () => {
    const limiter = new ClientRateLimiter(2);
    limiter.tryConsume('a');
    limiter.tryConsume('a');
    expect(limiter.tryConsume('a').allowed).toBe(false);
    vi.setSystemTime(T0 + 60_000 / 2); // one token's interval
    expect(limiter.tryConsume('a').allowed).toBe(true);
    expect(limiter.tryConsume('a').allowed).toBe(false);
  });

  it('reports the wait until this client\'s next token, not a whole interval', () => {
    const limiter = new ClientRateLimiter(3); // one token per 20s
    for (let n = 0; n < 3; n++) limiter.tryConsume('a');
    vi.setSystemTime(T0 + 7_500);
    expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 12_500 });
  });

  it('never reports a wait under a second', () => {
    const limiter = new ClientRateLimiter(120); // one token per 500ms
    for (let n = 0; n < 120; n++) limiter.tryConsume('a');
    vi.setSystemTime(T0 + 499);
    // 1ms remains. Retry-After is whole seconds, and 0 would read as "retry now".
    expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 1_000 });
  });

  it('caps the wait at one token\'s interval when the clock steps back', () => {
    const limiter = new ClientRateLimiter(3);
    for (let n = 0; n < 3; n++) limiter.tryConsume('a');
    vi.setSystemTime(T0 - 3_600_000);
    // lastRefill is now an hour in the future; the raw difference would say 3620s.
    expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 20_000 });
  });

  it('reports whole milliseconds when the limit does not divide a minute', () => {
    const limiter = new ClientRateLimiter(7); // one token per 8571.43ms
    for (let n = 0; n < 7; n++) limiter.tryConsume('a');
    // Rounded up, never down: a client told 8571 that comes back then is refused again.
    expect(limiter.tryConsume('a')).toEqual({ allowed: false, retryAfterMs: 8_572 });
  });
});
