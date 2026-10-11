export const FROZEN_ALGORITHMS = {
  kex: [
    'curve25519-sha256',
    'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256',
    'ecdh-sha2-nistp384',
    'ecdh-sha2-nistp521',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group14-sha256',
  ],
  cipher: [
    'chacha20-poly1305@openssh.com',
    'aes256-gcm@openssh.com',
    'aes128-gcm@openssh.com',
    'aes256-ctr',
    'aes192-ctr',
    'aes128-ctr',
  ],
  serverHostKey: [
    'ssh-ed25519',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
    'rsa-sha2-512',
    'rsa-sha2-256',
  ],
  hmac: [
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha2-256',
    'hmac-sha2-512',
  ],
};

// ─── Profile 覆盖（网络设备兼容轴）──────────────────────────
//
// 上面的冻结清单是安全下限。profile 可以只为「只会说老式 SSH 的主机」放宽它
// （老旧网络设备的出厂默认还是 ssh-rsa / CBC / DH-group1 年代的产物），
// 而这种放宽刻意在这里解析，而不是把 `{ append, prepend, remove }`
// 直接交给 ssh2：
//
// ssh2 把调整对象应用于*它自己的*默认值，
// 而不是 FROZEN_ALGORITHMS——因此原样透传会悄悄放回
// 冻结清单本要拒绝的每一套算法，而且就在运维以为
// 自己限定住的类别里。在这里对照冻结基线解析，让白名单保持
// 唯一的记录基准：覆盖只声明它改了什么，
// 而每条连接拿到的仍是完整解析后的精确清单。

export type AlgorithmCategory = 'kex' | 'cipher' | 'serverHostKey' | 'hmac';

/** 相对冻结清单为一个类别增删名称。 */
export interface AlgorithmListAdjustment {
  append?: string[];
  prepend?: string[];
  remove?: string[];
}

/** 精确清单直接替换冻结类别；调整形式则在其上修改。 */
export type AlgorithmOverride = Partial<
  Record<AlgorithmCategory, string[] | AlgorithmListAdjustment>
>;

export interface ResolvedAlgorithms {
  kex: string[];
  cipher: string[];
  serverHostKey: string[];
  hmac: string[];
}

function dedupe(list: string[]): string[] {
  return [...new Set(list)];
}

/**
 * 相对冻结白名单解析某个 profile 的算法覆盖。
 *
 * 拒绝优先语义：拼装清单（冻结 + prepend + append）
 * 最后才按 `remove` 过滤，因此同一覆盖里 append
 * 复活不了显式的 remove，被 remove 的 prepend 名称也保持移除。
 * 移除是安全相关操作，所以它赢。去重按拼装顺序保留首次出现，
 * 这让 prepend（最高优先）具有确定性。
 *
 *
 * 每次调用都返回新数组——冻结清单从不被修改，
 * 一个 profile 的覆盖因此不会泄入另一个 profile 或模块状态。
 */
export function resolveAlgorithms(override?: AlgorithmOverride): ResolvedAlgorithms {
  const resolved: ResolvedAlgorithms = {
    kex: [...FROZEN_ALGORITHMS.kex],
    cipher: [...FROZEN_ALGORITHMS.cipher],
    serverHostKey: [...FROZEN_ALGORITHMS.serverHostKey],
    hmac: [...FROZEN_ALGORITHMS.hmac],
  };
  if (!override) return resolved;

  for (const category of Object.keys(override) as AlgorithmCategory[]) {
    const value = override[category];
    if (!value) continue;
    if (Array.isArray(value)) {
      resolved[category] = dedupe(value);
      continue;
    }
    let list = resolved[category];
    if (value.append?.length) list = [...list, ...value.append];
    if (value.prepend?.length) list = [...value.prepend, ...list];
    if (value.remove?.length) {
      const remove = new Set(value.remove);
      list = list.filter((name) => !remove.has(name));
    }
    resolved[category] = dedupe(list);
  }
  return resolved;
}

