import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { getAuditLogPath } from '../audit/store.js';
import type { ForbiddenDir } from './local-path.js';

/**
 * 除大门自己已派生的两个目录（安装目录与配置目录）之外，
 * 传输根目录不得与之重叠的目录清单。
 *
 * 单独成一个模块，而不是 index.ts 调用点里的字面量，因为
 * 那份清单原本放在 `main()` 函数体内，任何测试都够不到——
 * 它不被导出，不启动服务器就不会被求值。于是这份清单成了
 * 传输根大门唯一无人验证的输入，而大门本身对递给它的东西
 * 反而测得很彻底。（测试下 index.ts 不运行 `main()`：该调用由
 * SSH_MCP_DISABLE_MAIN 把关，每个测试脚本都会设置它。
 * 是不可达，不是不可导入。）大门把清单作为参数接收，正是为了让
 * 「审计日志去了哪里」成为别人的职责——
 * 本模块就是那个别人。
 * 两个条目按惯例都是 0700 且属主自有，因此大门施加的每项隐私检查
 * 都会接受它们。它们必须按名字排除：
 *
 * - 根目录里含审计日志时，一次下载就能替换记录这次传输本身的
 *   防篡改记录；
 *
 * - 形如 `~/.ssh` 的根目录会把同样的两个工具变成「读私钥」与
 *   「向 authorized_keys 追加」。
 */
export function transferForbiddenDirs(): ForbiddenDir[] {
  return [
    { path: dirname(getAuditLogPath()), reason: 'the audit log directory' },
    { path: join(homedir(), '.ssh'), reason: 'the SSH client directory (~/.ssh)' },
  ];
}
