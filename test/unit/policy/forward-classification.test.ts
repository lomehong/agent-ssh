import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';
import { PolicyEngine, type PolicyRules } from '../../../src/policy/engine.js';
import type { Profile } from '../../../src/types.js';

// forward:open embeds the full listen→target pair in its synthetic command, so
// the denylist, the role matrix and the approval gate all see exactly what the
// tunnel would open — these tests pin that each layer actually does.

const profile: Profile = {
  name: 'dev', host: 'h', port: 22, user: 'u', auth: 'password',
  tty: false, keyboardInteractive: false, timeout: 15000, maxChars: 5000,
  maxOutputBytes: 1048576, role: 'admin', readOnly: false,
  approvalPolicy: 'ask-destructive', cert: false, announceAgent: true,
  sessionMaxPerConnection: 5, sessionIdleTimeoutMs: 60000,
  sessionBackgroundMaxMs: 3600000, commandQuotaPerDay: 0,
  transferMaxBytes: 268435456, transferTimeoutMs: 300000, group: 'dev',
};

describe('synthetic floors for the forwarding tools', () => {
  it('forward:open is destructive — role matrix + approval gate apply', () => {
    const parsed = classifyCommand('forward:open local 127.0.0.1:8080 -> db.internal:5432');
    expect(parsed.class).toBe('destructive');
    expect(parsed.binary).toBe('forward:open');
  });

  it('forward:list lowers to read-only', () => {
    expect(classifyCommand('forward:list').class).toBe('read-only');
  });
});

describe('denylist sees the tunnel target', () => {
  const rules: PolicyRules = {
    roleBindings: { admin: { dev: ['read-only', 'safe', 'destructive', 'privileged'] } },
    denylist: ['internal-db:5432'],
  };
  const engine = new PolicyEngine(rules);

  it('refuses a tunnel whose target matches a denylist rule', () => {
    const decision = engine.evaluate(
      'forward:open local 127.0.0.1:8080 -> internal-db:5432',
      { ...profile, role: 'admin' },
    );
    expect(decision.decision).toBe('deny');
    expect(decision.ruleId).toBe('denylist');
  });

  it('allows a tunnel to a target no rule names', () => {
    const decision = engine.evaluate(
      'forward:open local 127.0.0.1:8080 -> 127.0.0.1:2222',
      { ...profile, role: 'admin' },
    );
    // destructive under ask-destructive → require-approval, not deny.
    expect(decision.decision).toBe('require-approval');
  });
});

describe('viewer role refuses tunnels outright', () => {
  const engine = new PolicyEngine();

  it('viewer holds no destructive class, so forward:open denies', () => {
    const viewer: Profile = { ...profile, role: 'viewer' };
    const decision = engine.evaluate('forward:open local 127.0.0.1:8080 -> 10.0.0.9:80', viewer);
    expect(decision.decision).toBe('deny');
  });
});
