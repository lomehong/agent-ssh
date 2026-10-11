import { createHash } from 'crypto';
import { OperatorError } from '../errors.js';

export type HostKeyMode = 'tofu' | 'strict' | 'insecure';

/**
 * 以字面量共享，而不是经消息构造器：下面三条拒绝的建议各不相同，
 * message-quality.test.ts 对各自的措辞分别断言。只有命令是共同的，
 * 也只有它应该是。
 */
const CONFIRM_OUT_OF_BAND =
  '`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server';

export function fingerprintPublicKey(key: Buffer): string {
  const hash = createHash('sha256').update(key).digest('base64');
  // 用 `={0,2}` 而非 `=+`：base64 填充从不超过两个字符，
  // 有界形式不可能回溯。此处不可达——输入永远是 44 字符摘要——
  // 但无界的尾部量词正是别处不该照抄的形状。
  //
  return `SHA256:${hash.replace(/={0,2}$/, '')}`;
}

/**
 * 决定是否接受主机刚出示的密钥。
 *
 * `knownHosts` 是所有 profile 共享的一个 Map（connection-registry.ts），
 * 这正是固定（pin）从不*读*它的原因：为已固定主机查询它，会让
 * 为同一 host:port 固定了不同密钥的两个 profile，在主机向各自出示
 * 密钥时以假的 HOST_KEY_MISMATCH 相撞。
 *
 * `--hostKeyMode=strict` 为何在 2.8.0 前拒绝一切主机，写在
 * .changeset/lucky-keys-pinned.md 与 SECURITY.md；这里的分支顺序
 * 就是那段历史留下的东西。
 *
 * @param pinnedFingerprint profile 的 `trustedHostKey`。假值即无固定。
 *   有值则在一切模式（含 `insecure`）下决定结果。它从不与
 *   `knownHosts` 比较，但匹配会在 `tofu` 下把记录写进去——
 *   为何两者不同，见 pin 分支。
 */
export function verifyHostKey(
  host: string,
  port: number,
  fingerprint: string,
  knownHosts: Map<string, string>,
  mode: HostKeyMode,
  pinnedFingerprint: string | undefined,
): boolean {
  const key = `${host}:${port}`;

  // 放在 `insecure` 之前而非之后：被它替代的那道门位于
  // connection.ts 的 verifyHostKey 之前，与固定矛盾的密钥因此在
  // 一切模式（含 `insecure`）下被拒。host-key.test.ts 固定了它：
  // "refuses a key that contradicts the pin, in every mode including insecure"。
  //
  // 用真值而非 `!== undefined`：`trustedHostKey = ""` 在 2.7.0 上无效，
  // 因为那道门测的是真值；改成 `!== undefined` 会让同样的配置变成
  // 「拒绝一切主机」。schema 已拒绝空固定，这里是纵深防御
  // 而非主守卫。
  if (pinnedFingerprint) {
    if (pinnedFingerprint !== fingerprint) {
      // 与下面两条拒绝不同，这里没有「或者把检查关掉」的出口。
      // 没有任何东西能覆盖固定——tofu 不能，insecure 也不能——
      // 给出一个模式等于描述一条不存在的出路。
      throw new OperatorError(
        `HOST_KEY_PIN_MISMATCH: the key presented by ${host}:${port} is not the pinned key.\n` +
        `  pinned   ${pinnedFingerprint}\n` +
        `  received ${fingerprint}\n` +
        'trustedHostKey on this profile is what decided, and no host key mode overrides it. ' +
        'Either the pin is stale — the server was rebuilt or its address reused, in which case ' +
        `confirm the new fingerprint out of band (${CONFIRM_OUT_OF_BAND}) ` +
        'and update trustedHostKey — or something is intercepting this connection, ' +
        'which is what pinning exists to catch.',
      );
    }
    // 匹配。写入受两条约束，都无法从代码本身推出：
    //
    // 仅 `tofu`——在 `strict` 下存储是未固定 profile 获准的唯一途径，
    // 在那里播种会让一个 profile 的固定授权另一个。只填空——
    // 无条件 set 会让条目顺序影响未固定的兄弟 profile，而 2.7.0 的写入
    // 只有在存储未命中时可达，所以本写入恰在它本会写的时机写。
    //
    // 且它在匹配之内、throw 之下：在拒绝路径上记录，
    // 会把拦截者的指纹写进共享存储——
    // 这正是该写入要防止的失败。
    //
    if (mode === 'tofu' && !knownHosts.has(key)) knownHosts.set(key, fingerprint);
    return true;
  }

  if (mode === 'insecure') return true;

  const stored = knownHosts.get(key);

  if (stored) {
    if (stored !== fingerprint) {
      // 两种截然不同的情形都会走到这里，消息必须让读者分得清——
      // 否则下意识的动作就是 --insecureHostKey，
      // 那会把检查对所有主机关掉，而不只这一台。
      throw new OperatorError(
        `HOST_KEY_MISMATCH: the key presented by ${host}:${port} is not the one seen before.\n` +
        `  expected ${stored}\n` +
        `  received ${fingerprint}\n` +
        'Either the server was rebuilt, reinstalled or had its address reused — in which case the new key is ' +
        'genuine — or something is intercepting this connection, which is what this check exists to catch. ' +
        'Nothing here can tell those apart; confirm the fingerprint out of band, from the host itself ' +
        `(${CONFIRM_OUT_OF_BAND}) or from whoever rebuilt it.\n` +
        'If it matches, pin it with trustedHostKey on the profile. Do not reach for --insecureHostKey to get ' +
        'past this: it disables verification for every host and every future connection, including the case ' +
        'this message is warning you about.',
      );
    }
    return true;
  }

  if (mode === 'strict') {
    throw new OperatorError(
      `HOST_KEY_UNKNOWN: No known key for ${host}:${port} and --hostKeyMode=strict is set. ` +
      'Pin the key with trustedHostKey in the profile, or use --hostKeyMode=tofu to trust on first use.',
    );
  }

  knownHosts.set(key, fingerprint);
  return true;
}
