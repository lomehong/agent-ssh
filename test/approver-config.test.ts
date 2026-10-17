import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

// 桌面控制台构建配置断言（T-21a）：防 withGlobalTauri 回归——缺席时 Webview
// 桥不可用，窗口退化为纯浏览模式（2026-10-17 主人截图定性的事故）。
// 同时钉死 ui/ 红线：K8-③ 零 innerHTML/eval（命令全文永不进 HTML 解析器）。

const REPO = resolve(import.meta.dirname, '..');
const confPath = join(REPO, 'approver', 'tauri.conf.json');
const uiDir = join(REPO, 'approver', 'ui');

describe('桌面控制台构建配置（T-21a）', () => {
  it('withGlobalTauri 必须开启（Webview 桥注入）', () => {
    const conf = JSON.parse(readFileSync(confPath, 'utf8'));
    expect(conf.app.withGlobalTauri).toBe(true);
  });

  it('frontendDist 指向存在的 ui/ 目录，三件套在场', () => {
    const conf = JSON.parse(readFileSync(confPath, 'utf8'));
    const dist = join(REPO, 'approver', conf.build.frontendDist.replace('./', ''));
    expect(existsSync(join(dist, 'index.html'))).toBe(true);
    expect(existsSync(join(dist, 'ui.js'))).toBe(true);
    expect(existsSync(join(dist, 'ui.css'))).toBe(true);
  });

  it('ui.js 红线：零 innerHTML/outerHTML/insertAdjacentHTML/document.write/eval', () => {
    // 剥行注释后再扫——本文件头注本身会提及禁词（说明性文字非代码语义）。
    const lines = readFileSync(join(uiDir, 'ui.js'), 'utf8').split('\n');
    const js = lines.filter((l) => !l.trim().startsWith('//')).join('\n');
    for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(']) {
      expect(js).not.toContain(banned);
    }
  });

  it('四视图骨架在场（审批列表实装；历史并入审批——主人 2026-10-17 交互重构）', () => {
    const html = readFileSync(join(uiDir, 'index.html'), 'utf8');
    for (const view of ['approvals', 'audit', 'connections', 'settings']) {
      expect(html).toContain(`view-${view}`);
    }
    expect(html).not.toContain('view-history');
  });
});
