import { describe, it, expect } from 'vitest';
import { PtyOutputBuffer } from '../../../src/pty/output-buffer.js';

describe('PtyOutputBuffer', () => {
  it('returns appended output from cursor 0 and advances the cursor', () => {
    const b = new PtyOutputBuffer(1000);
    b.append('login:\n');
    const r1 = b.readSince(0, 100);
    expect(r1.output).toBe('login:\n');
    expect(r1.cursor).toBe(7);
    const r2 = b.readSince(r1.cursor, 100);
    expect(r2.output).toBe('');
  });

  it('serves incremental reads as new data arrives', () => {
    const b = new PtyOutputBuffer(1000);
    b.append('a');
    const r1 = b.readSince(0, 100);
    b.append('bc');
    const r2 = b.readSince(r1.cursor, 100);
    expect(r2.output).toBe('bc');
    expect(r2.cursor).toBe(3);
  });

  it('caps a single read at maxChunk and resumes from the returned cursor', () => {
    const b = new PtyOutputBuffer(1000);
    b.append('0123456789');
    const r1 = b.readSince(0, 4);
    expect(r1.output).toBe('0123');
    const r2 = b.readSince(r1.cursor, 4);
    expect(r2.output).toBe('4567');
    const r3 = b.readSince(r2.cursor, 4);
    expect(r3.output).toBe('89');
  });

  it('evicts the head when the cap is exceeded and reports droppedBytes', () => {
    const b = new PtyOutputBuffer(10);
    b.append('0123456789');
    b.append('ABCDE');
    const r = b.readSince(0, 100);
    // The head was evicted: a cursor-0 read cannot see it.
    expect(r.skippedBytes).toBe(5);
    expect(r.output).toBe('56789ABCDE');
    expect(r.droppedBytes).toBe(5);
    expect(r.totalBytes).toBe(15);
  });

  it('reports skippedBytes separately when the cursor lags behind eviction', () => {
    const b = new PtyOutputBuffer(10);
    b.append('0123456789'); // cursor 0 valid
    b.append('ABCDE');      // evicts 01234
    b.readSince(0, 100);     // reader skipped 5 evicted bytes
    b.append('FGHIJ');      // evicts 5 more
    const r = b.readSince(15, 100); // cursor 15 = exactly at base after second eviction
    expect(r.skippedBytes).toBe(0);
    expect(r.output).toBe('FGHIJ');
  });

  it('clamps a negative cursor to the stream start', () => {
    const b = new PtyOutputBuffer(100);
    b.append('xyz');
    const r = b.readSince(-5, 100);
    expect(r.output).toBe('xyz');
    expect(r.cursor).toBe(3);
  });

  it('rejects non-positive maxBytes and maxChunk', () => {
    expect(() => new PtyOutputBuffer(0)).toThrow();
    const b = new PtyOutputBuffer(10);
    expect(() => b.readSince(0, 0)).toThrow();
  });
});
