#!/usr/bin/env node
/**
 * 把 package.json 的版本复制进 server.json（MCP registry 登记条目）。
 *
 * 版本在那里出现两次，两者都必须与到达 npm 的版本一致：
 * reaches npm:
 *
 *   version            登记条目自身的版本。registry 拒绝重复发布
 *                      已有服务器的同版本，所以这里的过期值
 *                      会让发布直接失败。
 *   packages[].version 登记条目指向的 npm 版本。registry 拿它去
 *                      `registry.npmjs.org/<identifier>/<version>` 解析，
 *                      并从那份确切的清单里读 `mcpName`——因此过期值
 *                      要么 404，要么更糟：列出的不是刚发布的那一版。
 *
 *
 * 接在 `version` npm script 上——changesets/action 打开或更新
 * "Version Packages" PR 时运行的就是它。它提交 version 命令
 * 留在工作树里的一切，所以重写结果随 package.json 提升与
 * CHANGELOG 条目一起进入那个 PR——发布任务从 main 发布时，
 * main 已经是对的。
 *
 * 仓库里再无别处携带版本：src/version.ts 运行时从
 * package.json 读取。
 *
 * `--check` 报告过期而不修复，供发布任务在发布登记前运行。
 * `git diff --exit-code server.json` 是它的第一个形态，也是个陷阱：
 * git diff 对未跟踪文件只字不提，于是检查恰好在
 * server.json 没进索引的那台机器上通过。
 *
 *
 * 本脚本*不做*的是把 server.json 对着 schema 校验。
 * 更早的版本把 100 字符的 `title`/`description` 上限重新实现成字面量，
 * 理由是以为 mcp-publisher 只在发布时报告它们。并非如此：
 * `mcp-publisher validate` 无需发布即可对整个 schema 校验，
 * 走的是免凭据的端点，发布工作流也运行它。
 * 把 schema 的两条规则抄成本文件常量，固定的 schema URL 一动就会过期，
 * 而 name 模式、必填字段与其余规则仍然漏掉。
 * 对人工编辑的值真正要紧的上限，由
 * test/unit/sync-server-json.test.ts 在真实文件上断言，
 * 写它们的那个 PR 就会红，
 * 而不是两次合并之后的发布才红。
 */
import { readFileSync, writeFileSync } from 'node:fs';

const checkOnly = process.argv.slice(2).includes('--check');

const root = new URL('..', import.meta.url);
const registryFile = new URL('server.json', root);

const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const registry = JSON.parse(readFileSync(registryFile, 'utf8'));

/**
 * 此处失配就是 registry 的 "ownership validation failed. Expected
 * mcpName '<a>', got '<b>'"——发现时 npm 已经发布，正卡在发布流程里
 * 唯一无法靠重跑挽回的一步。在版本提升还是 PR 的时候
 * 花一次比较就能抓住它。
 */
if (pkg.mcpName !== registry.name) {
  console.error(
    `sync-server-json: package.json mcpName (${pkg.mcpName ?? 'unset'}) does not match ` +
    `server.json name (${registry.name}). The registry validates one against the other.`,
  );
  process.exit(1);
}

const npmPackage = registry.packages?.find((p) => p.registryType === 'npm');
// 拒绝而不是猜：静默跳过会把一个指向旧版本的
// server.json 交给发布任务。
if (!npmPackage) {
  console.error('sync-server-json: server.json has no npm package entry to update');
  process.exit(1);
}

/**
 * identifier 是同一所有权检查的另一半。
 *
 * 上面的 `mcpName` 证明我们拥有登记条目所声称的包；这里是
 * 它实际解析到的包——registry 去
 * `registry.npmjs.org/<identifier>/<version>` 取回并从*那份*
 * 清单里读 `mcpName`。这里的改名或笔误以同样方式、同样迟地失败，
 * 所以它得到同样的守卫，而不是唯一一个抄了却无人
 * 验证的字段。
 */
if (npmPackage.identifier !== pkg.name) {
  console.error(
    `sync-server-json: server.json packages[].identifier (${npmPackage.identifier}) does not ` +
    `match the npm package name (${pkg.name}).`,
  );
  process.exit(1);
}

const stale =
  registry.version !== pkg.version || npmPackage.version !== pkg.version;

if (!stale) {
  console.log(`sync-server-json: server.json already at ${pkg.version}`);
  process.exit(0);
}

if (checkOnly) {
  console.error(
    `sync-server-json: server.json is stale — listing ${registry.version} / npm ` +
    `${npmPackage.version}, but package.json is at ${pkg.version}. ` +
    'Run `node scripts/sync-server-json.mjs` and commit the result.',
  );
  process.exit(1);
}

registry.version = pkg.version;
npmPackage.version = pkg.version;
writeFileSync(registryFile, `${JSON.stringify(registry, null, 2)}\n`);
console.log(`sync-server-json: server.json -> ${pkg.version}`);
