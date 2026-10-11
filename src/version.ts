import { createRequire } from 'module';

const require = createRequire(import.meta.url);

/**
 * MCP（`initialize`）与 `GET /status` 上所报告版本的唯一事实来源。
 * 运行时从 package.json 读取，因此 changesets 发布提升版本后，
 * 不会残留与已安装包不一致的硬编码字面量。
 * 从 `src/` 与 `build/` 均可解析到仓库根目录。
 */
export const SERVER_VERSION: string = (require('../package.json') as { version: string }).version;
