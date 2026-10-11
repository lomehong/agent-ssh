import type { DeviceType } from '../types.js';

/**
 * 设备档案（agent-ssh T-05）：裸 PTY 会话驱动网络设备 CLI
 * 所需的厂商特性——关分页命令、提示符形态
 * 与输出编码。
 *
 * 以厂商 CLI 的真实情况为据，刻意保持精简：
 * - 华为 VRP：用户视图 `<HOSTNAME>`、系统视图 `[~HOSTNAME]`；分页按
 *   会话用 `screen-length 0 temporary` 关闭（`temporary` 形式
 *   无需 `save`，不必进配置模式）。
 * - H3C Comware：`<HOSTNAME>` / `[HOSTNAME]`；`screen-length disable`。
 * - 思科 IOS：`HOSTNAME>` / `HOSTNAME#`；`terminal length 0`。
 * - 锐捷 RGOS：类思科风格（`terminal length 0`、`HOSTNAME>`）。
 *
 * 编码默认 UTF-8；profile 可用 `ptyEncoding: "gbk"` 覆盖
 * （Node full-ICU TextDecoder 流式解码，agent-ssh T-10 已实现——
 * 老华为/华三固件的 GB2312/GBK 输出不再是登记缺口）。
 * 档案的 `encoding` 字段即管理器在 profile 未指定时的回退默认。
 */

export interface DeviceArchive {
  deviceType: Exclude<DeviceType, 'generic'>;
  /** PTY 打开后自动发送；null = 无分页可关。 */
  disablePaging: string | null;
  /** 匹配其中任一形态的行即为就绪提示符。 */
  promptPatterns: RegExp[];
  encoding: 'utf8';
  /** 显式缺口备注——本档案尚未处理什么。 */
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
 * `output` 的尾部是否有任何一行像就绪提示符。
 *
 * 只查最后一行非空行：几屏之前的分页横幅不能被读成
 * 「设备已准备好接收下一条命令」。
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
