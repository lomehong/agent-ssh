import type { DeviceType } from '../types.js';

/**
 * Device archives (agent-ssh T-05): the vendor personality a raw PTY session
 * needs to drive a network-device CLI — the paging-off command, the prompt
 * shapes, and the output encoding.
 *
 * Grounded in vendor CLI reality, kept deliberately small:
 * - Huawei VRP: user view `<HOSTNAME>`, system view `[~HOSTNAME]`; paging is
 *   per-session via `screen-length 0 temporary` (the `temporary` form needs no
 *   `save` and no configuration-mode trip).
 * - H3C Comware: `<HOSTNAME>` / `[HOSTNAME]`; `screen-length disable`.
 * - Cisco IOS: `HOSTNAME>` / `HOSTNAME#`; `terminal length 0`.
 * - Ruijie RGOS: Cisco-flavoured (`terminal length 0`, `HOSTNAME>`).
 *
 * Encoding is recorded per archive but the transport decodes UTF-8 today:
 * legacy GB2312/GBK device output (common on older Huawei/H3C builds) would
 * need a decode step that is deliberately out of scope until a real device
 * proves it necessary — recorded here so the gap is visible, not latent.
 */

export interface DeviceArchive {
  deviceType: Exclude<DeviceType, 'generic'>;
  /** Sent automatically after the PTY opens; null = no paging to disable. */
  disablePaging: string | null;
  /** A line matching any of these is a ready prompt. */
  promptPatterns: RegExp[];
  encoding: 'utf8';
  /** Visible gap note — what this archive does NOT handle yet. */
  encodingNote?: string;
}

const ARCHIVES: Record<Exclude<DeviceType, 'generic'>, DeviceArchive> = {
  huawei: {
    deviceType: 'huawei',
    disablePaging: 'screen-length 0 temporary',
    promptPatterns: [/<[\w.-]+>/, /\[[~]?[\w.-]+\]/],
    encoding: 'utf8',
    encodingNote: 'older VRP builds may emit GB2312; add a decode step when a real device proves it',
  },
  h3c: {
    deviceType: 'h3c',
    disablePaging: 'screen-length disable',
    promptPatterns: [/<[\w.-]+>/, /\[[\w.-]+\]/],
    encoding: 'utf8',
    encodingNote: 'same GB2312 caveat as huawei',
  },
  cisco: {
    deviceType: 'cisco',
    disablePaging: 'terminal length 0',
    promptPatterns: [/[\w.-]+>/, /[\w.-]+#/],
    encoding: 'utf8',
  },
  ruijie: {
    deviceType: 'ruijie',
    disablePaging: 'terminal length 0',
    promptPatterns: [/[\w.-]+>/, /[\w.-]+#/],
    encoding: 'utf8',
  },
};

export function getDeviceArchive(deviceType: DeviceType | undefined): DeviceArchive | null {
  if (!deviceType || deviceType === 'generic') return null;
  return ARCHIVES[deviceType];
}

/**
 * Whether any line of `output`'s tail looks like a ready prompt.
 *
 * Checks the last non-empty line only: a paging banner from several screens
 * ago must not read as "the device is ready for the next command".
 */
export function outputEndsWithPrompt(output: string, patterns: RegExp[]): boolean {
  if (patterns.length === 0) return false;
  const lines = output.split(/\r?\n/).reverse();
  for (const line of lines) {
    const trimmed = line.replace(/\r/g, '').trimEnd();
    if (trimmed.length === 0) continue;
    return patterns.some((p) => p.test(trimmed));
  }
  return false;
}
