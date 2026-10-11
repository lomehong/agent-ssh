import { describe, it, expect } from 'vitest';
import { profileSchema } from '../../../src/config/schema.js';
import { algorithmsOverrideWarning } from '../../../src/config/loader.js';
import type { Profile } from '../../../src/types.js';

// T-02: the network-device compatibility fields must validate at load time —
// an unknown algorithm category or a typo'd deviceType would otherwise parse
// cleanly and then silently do nothing, which is the exact shape this schema
// file's `.strict()` discipline exists to prevent.

function baseProfile(overrides: Record<string, unknown> = {}) {
  return {
    name: 'dev',
    host: '10.0.0.5',
    user: 'operator',
    tty: false,
    keyboardInteractive: false,
    role: 'operator',
    readOnly: false,
    cert: false,
    announceAgent: true,
    ...overrides,
  };
}

describe('profileSchema: algorithms override', () => {
  it('accepts an exact-list override', () => {
    const r = profileSchema.safeParse(
      baseProfile({ algorithms: { kex: ['diffie-hellman-group1-sha1'] } }),
    );
    expect(r.success).toBe(true);
  });

  it('accepts the adjustment form (append/prepend/remove)', () => {
    const r = profileSchema.safeParse(
      baseProfile({
        algorithms: {
          cipher: { append: ['aes128-cbc'], remove: ['aes192-ctr'] },
          kex: { prepend: ['diffie-hellman-group14-sha1'] },
        },
      }),
    );
    expect(r.success).toBe(true);
  });

  it('rejects an unknown algorithm category', () => {
    const r = profileSchema.safeParse(
      baseProfile({ algorithms: { compression: ['zlib'] } }),
    );
    expect(r.success).toBe(false);
  });

  it('rejects an exact list with an empty algorithm name', () => {
    const r = profileSchema.safeParse(
      baseProfile({ algorithms: { kex: ['  '] } }),
    );
    expect(r.success).toBe(false);
  });

  it('rejects an exact empty list (no way to negotiate is always a mistake)', () => {
    const r = profileSchema.safeParse(baseProfile({ algorithms: { kex: [] } }));
    expect(r.success).toBe(false);
  });

  it('rejects unknown keys inside the adjustment form', () => {
    const r = profileSchema.safeParse(
      baseProfile({ algorithms: { kex: { appendx: ['x'] } } }),
    );
    expect(r.success).toBe(false);
  });

  it('leaves the field absent when the profile does not set it', () => {
    const r = profileSchema.safeParse(baseProfile());
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.algorithms).toBeUndefined();
  });
});

describe('profileSchema: deviceType', () => {
  it('accepts each supported vendor personality', () => {
    for (const deviceType of ['generic', 'huawei', 'h3c', 'cisco', 'ruijie']) {
      const r = profileSchema.safeParse(baseProfile({ deviceType }));
      expect(r.success, deviceType).toBe(true);
    }
  });

  it('rejects an unknown vendor', () => {
    const r = profileSchema.safeParse(baseProfile({ deviceType: 'juniper' }));
    expect(r.success).toBe(false);
  });
});

describe('profileSchema: keyboardInteractive', () => {
  it('defaults to false', () => {
    const raw = baseProfile() as Record<string, unknown>;
    delete raw.keyboardInteractive;
    const r = profileSchema.safeParse(raw);
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.keyboardInteractive).toBe(false);
  });

  it('accepts true', () => {
    const r = profileSchema.safeParse(baseProfile({ keyboardInteractive: true }));
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.keyboardInteractive).toBe(true);
  });
});

describe('algorithmsOverrideWarning', () => {
  const base = profileSchema.parse(baseProfile()) as unknown as Profile;

  it('returns null when no profile overrides algorithms', () => {
    expect(algorithmsOverrideWarning([base])).toBeNull();
  });

  it('names the profiles and the categories they widen', () => {
    const widened = {
      ...base,
      name: 'legacy-switch',
      algorithms: { kex: ['diffie-hellman-group1-sha1'], cipher: ['3des-cbc'] },
    } as Profile;
    const message = algorithmsOverrideWarning([base, widened]);
    expect(message).toContain('1 profile(s)');
    expect(message).toContain('legacy-switch');
    expect(message).toContain('kex, cipher');
    expect(message).toContain('algorithmsOverride=true');
  });
});
