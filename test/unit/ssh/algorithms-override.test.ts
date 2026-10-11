import { describe, it, expect } from 'vitest';
import { FROZEN_ALGORITHMS, resolveAlgorithms } from '../../../src/ssh/algorithms.js';

// The override resolver is the security boundary of the network-device
// compatibility axis: it must never mutate the frozen base, never let an
// adjustment form leak through to ssh2 (whose adjustments apply against ssh2's
// own much wider defaults), and compose adjustments deterministically.

describe('resolveAlgorithms', () => {
  it('returns a deep copy of the frozen list when there is no override', () => {
    const a = resolveAlgorithms();
    const b = resolveAlgorithms(undefined);
    expect(a).toEqual(FROZEN_ALGORITHMS);
    expect(b).toEqual(FROZEN_ALGORITHMS);
    expect(a).not.toBe(FROZEN_ALGORITHMS);
    expect(a.kex).not.toBe(FROZEN_ALGORITHMS.kex);
  });

  it('does not mutate the frozen list across calls', () => {
    const before = JSON.stringify(FROZEN_ALGORITHMS);
    resolveAlgorithms({ kex: { remove: FROZEN_ALGORITHMS.kex } });
    resolveAlgorithms({ cipher: ['3des-cbc'] });
    expect(JSON.stringify(FROZEN_ALGORITHMS)).toBe(before);
  });

  it('replaces exactly the category an exact list names, and nothing else', () => {
    const resolved = resolveAlgorithms({ kex: ['diffie-hellman-group1-sha1'] });
    expect(resolved.kex).toEqual(['diffie-hellman-group1-sha1']);
    expect(resolved.cipher).toEqual(FROZEN_ALGORITHMS.cipher);
    expect(resolved.serverHostKey).toEqual(FROZEN_ALGORITHMS.serverHostKey);
    expect(resolved.hmac).toEqual(FROZEN_ALGORITHMS.hmac);
  });

  it('applies adjustment form against the frozen base, not ssh2 defaults', () => {
    const resolved = resolveAlgorithms({
      kex: { append: ['diffie-hellman-group1-sha1'] },
    });
    // Modern entries survive — this is append-to-frozen, not "ssh2 defaults plus one".
    expect(resolved.kex).toContain('curve25519-sha256');
    expect(resolved.kex).toContain('diffie-hellman-group1-sha1');
  });

  it('applies remove before append before prepend', () => {
    const resolved = resolveAlgorithms({
      kex: {
        remove: ['curve25519-sha256'],
        append: ['curve25519-sha256'], // must NOT resurrect the removed name
        prepend: ['diffie-hellman-group1-sha1'],
      },
    });
    expect(resolved.kex[0]).toBe('diffie-hellman-group1-sha1');
    const count = resolved.kex.filter((k) => k === 'curve25519-sha256').length;
    expect(count).toBe(0);
  });

  it('deduplicates, keeping the first occurrence so prepend wins preference', () => {
    const resolved = resolveAlgorithms({
      kex: { prepend: ['diffie-hellman-group14-sha256'] },
    });
    expect(resolved.kex.filter((k) => k === 'diffie-hellman-group14-sha256')).toHaveLength(1);
    expect(resolved.kex[0]).toBe('diffie-hellman-group14-sha256');
  });

  it('handles an adjustment object with no arrays as a no-op', () => {
    const resolved = resolveAlgorithms({ hmac: {} });
    expect(resolved.hmac).toEqual(FROZEN_ALGORITHMS.hmac);
  });
});
