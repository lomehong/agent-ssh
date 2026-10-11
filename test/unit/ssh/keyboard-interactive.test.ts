import { describe, it, expect } from 'vitest';
import { answerKeyboardInteractive } from '../../../src/ssh/connection.js';

// Exported for exactly this: the handler fires mid-handshake inside connect(),
// which otherwise needs a live keyboard-interactive server to exercise. Network
// devices commonly offer password auth only through this method, so the
// answers must reach `finish` verbatim, one per prompt.

const handler = answerKeyboardInteractive('devpass');

function run(prompts: { prompt: string; echo: boolean }[]): string[] {
  let answers: string[] = [];
  handler('device-login', 'Authentication', 'en-US', prompts, (a) => {
    answers = a;
  });
  return answers;
}

describe('answerKeyboardInteractive', () => {
  it('answers every prompt with the password', () => {
    const answers = run([
      { prompt: 'Password:', echo: false },
      { prompt: 'Password: ', echo: false },
    ]);
    expect(answers).toEqual(['devpass', 'devpass']);
  });

  it('answers a single prompt with a single answer (no spurious entries)', () => {
    expect(run([{ prompt: 'Password:', echo: false }])).toEqual(['devpass']);
  });

  it('answers with empty strings when no password credential exists', () => {
    const none = answerKeyboardInteractive(undefined);
    let answers: string[] = [];
    none('x', 'y', 'z', [{ prompt: 'Password:', echo: false }], (a) => {
      answers = a;
    });
    // The server fails the auth with its own message; we do not invent a
    // different error client-side.
    expect(answers).toEqual(['']);
  });

  it('ignores name/instructions/lang and never echoes into the answers', () => {
    const answers = run([{ prompt: 'Verification code', echo: true }]);
    expect(answers).toEqual(['devpass']);
  });
});
