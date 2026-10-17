import { existsSync, readFileSync } from 'node:fs';

/**
 * 审计查询（T-21c）：桌面控制台审计视图的服务端读面。
 *
 * 数据=审计 JSONL 主文件 + 轮转序列（rotateIfNeeded 的 `.N` 后缀，序号越大
 * 越旧）。倒序语义（最新在前）自尾部起算；分页 cursor 采用「自尾部偏移」
 * ——个人量级下每次重扫行数可接受，换取实现免维护文件序号状态
 * （评审建议的 (文件序号,行号) 在轮转边界抖动，尾部偏移对轮转天然稳定：
 * 新文件只会把旧行往尾部推）。
 *
 * 过滤：profile 精确 / commandClass / decision / ruleId / 关键词（command
 * 子串，大小写不敏感）。行解析失败的跳过（防半行撕裂）；返回前不过二次
 * 脱敏——审计写入侧已脱敏（store.record），此处按存储原样出。
 */

export interface AuditFilter {
  profile?: string;
  commandClass?: string;
  decision?: string;
  ruleId?: string;
  keyword?: string;
  /** ISO 时间下限/上限（评审 B3：时间范围过滤，按记录 time 字段字典序比较）。 */
  timeFrom?: string;
  timeTo?: string;
}

export interface AuditQueryOpts {
  auditPath: string;
  filter?: AuditFilter;
  /** 自最新一条起的偏移（0=最新）。 */
  offsetTail?: number;
  limit?: number;
}

export interface AuditQueryResult {
  /** 过滤后的总条数（分页前的全量）。 */
  total: number;
  /** 自尾部 offsetTail 起的条目（最新在前）。 */
  items: Record<string, unknown>[];
}

function rotationFiles(auditPath: string): string[] {
  // 旧→新：.10 … .1，主文件最后（MAX_FILES=10 与 store 一致）。
  const files: string[] = [];
  for (let i = 10; i >= 1; i--) {
    const p = `${auditPath}.${i}`;
    if (existsSync(p)) files.push(p);
  }
  if (existsSync(auditPath)) files.push(auditPath);
  return files;
}

function parseLine(line: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(line) as unknown;
    return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : null;
  } catch {
    return null; // 半行撕裂/空行：跳过
  }
}

function matches(rec: Record<string, unknown>, f: AuditFilter | undefined): boolean {
  if (!f) return true;
  if (f.profile !== undefined && rec.profile !== f.profile) return false;
  if (f.commandClass !== undefined && rec.commandClass !== f.commandClass) return false;
  if (f.decision !== undefined && rec.decision !== f.decision) return false;
  if (f.ruleId !== undefined && rec.ruleId !== f.ruleId) return false;
  if (f.keyword !== undefined && f.keyword !== '') {
    const cmd = typeof rec.command === 'string' ? rec.command.toLowerCase() : '';
    if (!cmd.includes(f.keyword.toLowerCase())) return false;
  }
  if (f.timeFrom !== undefined && f.timeFrom !== '') {
    const t = typeof rec.time === 'string' ? rec.time : '';
    if (t < f.timeFrom) return false;
  }
  if (f.timeTo !== undefined && f.timeTo !== '') {
    const t = typeof rec.time === 'string' ? rec.time : '';
    if (t > f.timeTo) return false;
  }
  return true;
}

export function queryAudit(opts: AuditQueryOpts): AuditQueryResult {
  const records: Record<string, unknown>[] = [];
  for (const file of rotationFiles(opts.auditPath)) {
    const body = readFileSync(file, 'utf8');
    for (const line of body.split('\n')) {
      if (line.trim() === '') continue;
      const rec = parseLine(line);
      if (rec !== null && matches(rec, opts.filter)) records.push(rec);
    }
  }
  // 文件序已旧→新；倒序=最新在前。
  records.reverse();
  const offsetTail = Math.max(0, opts.offsetTail ?? 0);
  const limit = Math.min(200, Math.max(1, opts.limit ?? 50));
  return {
    total: records.length,
    items: records.slice(offsetTail, offsetTail + limit),
  };
}

/** 聚合（audit.stats）：主文件的今日条数/拒绝数/审批决定数。 */
export function auditStats(auditPath: string): {
  today: number;
  denied: number;
  approvalsDecided: number;
} {
  const todayPrefix = new Date().toISOString().slice(0, 10);
  let today = 0;
  let denied = 0;
  let approvalsDecided = 0;
  const files: string[] = [];
  for (let i = 10; i >= 1; i--) {
    const p = `${auditPath}.${i}`;
    if (existsSync(p)) files.push(p);
  }
  if (existsSync(auditPath)) files.push(auditPath);
  for (const file of files) {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      if (line.trim() === '') continue;
      const rec = parseLine(line);
      if (rec === null) continue;
      const ts = typeof rec.timestamp === 'string' ? rec.timestamp : '';
      if (ts.startsWith(todayPrefix)) {
        today++;
        if (rec.decision === 'deny') denied++;
        if (typeof rec.ruleId === 'string' && rec.ruleId.startsWith('challenge')) approvalsDecided++;
        if (typeof rec.command === 'string' && rec.command.startsWith('approval.decide')) approvalsDecided++;
      }
    }
  }
  return { today, denied, approvalsDecided };
}

