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

// ─── Profile overrides (network-device compatibility axis) ──────────────────
//
// The frozen list above is the security floor. A profile may widen it for hosts
// that only speak legacy SSH (older network gear ships ssh-rsa / CBC / DH-group1
// era defaults), and that widening is deliberately resolved HERE rather than
// handed to ssh2 as `{ append, prepend, remove }`:
//
// ssh2 applies an adjustment object against *its own* defaults, not against
// FROZEN_ALGORITHMS — so a passthrough would silently re-admit every algorithm
// the frozen list exists to refuse, in the same category the operator thought
// they were scoping. Resolving against the frozen base here keeps the allowlist
// the single base of record: an override can only name what it changes, and
// every connection still receives a fully-resolved exact list.

export type AlgorithmCategory = 'kex' | 'cipher' | 'serverHostKey' | 'hmac';

/** Add or drop names relative to the frozen list for one category. */
export interface AlgorithmListAdjustment {
  append?: string[];
  prepend?: string[];
  remove?: string[];
}

/** Exact list replaces the frozen category; adjustment form modifies it. */
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
 * Resolve a profile's algorithm override against the frozen allowlist.
 *
 * Deny-wins semantics: the assembled list (frozen + prepend + append) is
 * filtered by `remove` LAST, so an explicit remove cannot be resurrected by an
 * append in the same override, and a prepended name that is also removed stays
 * removed. Removal is the security-relevant operation, so it wins. Deduplication
 * keeps first occurrence on the assembled order, which makes prepend (highest
 * preference) deterministic.
 *
 * Returns fresh arrays every call — the frozen list is never mutated, so one
 * profile's override cannot leak into another profile or into module state.
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

