import { describe, it, expect } from 'vitest';
import { classifyCommand } from '../../../src/policy/classifier.js';

// The PTY safety plan's layer ① lives here: pty-open must classify destructive
// (the approval gate), the read/list pair must stay readable on readOnly
// profiles, and the write verb must NOT pretend to be classifiable (it is
// audited, not gated — the tools layer owns that constant).

describe('synthetic floors for the raw-PTY tools', () => {
  it('pty:open is destructive — the approval gate at open', () => {
    expect(classifyCommand('pty:open switch-1').class).toBe('destructive');
    expect(classifyCommand('pty:open switch-1').binary).toBe('pty:open');
  });

  it('pty:read and pty:list lower to read-only', () => {
    expect(classifyCommand('pty:read switch-1').class).toBe('read-only');
    expect(classifyCommand('pty:list').class).toBe('read-only');
  });

  it('carriers can only raise a pty:open, never lower it', () => {
    // Same authority argument as session:open: a composed string must not let
    // the outer verb hide what it carries.
    const parsed = classifyCommand('pty:open s1 && rm -rf /tmp/x');
    expect(parsed.class).toBe('destructive');
  });

  it('pty:write stays outside the classifier on purpose (audited, not gated)', () => {
    // No synthetic entry for pty:write: the default would be `safe`, and the
    // tools layer deliberately bypasses classification for raw input. If this
    // ever classifies destructive here, someone added a floor — check the plan
    // before letting a byte-stream verb into the approval machinery.
    expect(classifyCommand('pty:write s1 show version').binary).toBe('pty:write');
  });
});
