#!/usr/bin/env node
// 构建差分语料：策略测试套件中的每个带引号字面量
// （无论当初为什么写，都是有效的分类探针），加上每个的
// 确定性反斜杠改写，让运行覆盖套件从没刻意写过的输入。
// 输出排序去重，让同一份语料
// 能被树的两个修订版各自分类。
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const dir = new URL('../test/unit/policy/', import.meta.url);
const entries = new Set();

for (const file of readdirSync(dir)) {
  if (!file.endsWith('.test.ts')) continue;
  const text = readFileSync(join(dir.pathname, file), 'utf8');
  for (const m of text.matchAll(/'((?:[^'\\\n]|\\.)*)'/g)) entries.add(m[1]);
  for (const m of text.matchAll(/"((?:[^"\\\n]|\\.)*)"/g)) entries.add(m[1]);
}

const probes = new Set();
for (const literal of entries) {
  probes.add(literal);
  if (literal.length === 0 || literal.length > 100) continue;
  if (/['"\\\n]/.test(literal)) continue;   // variants stay single-token-simple
  probes.add(literal.replaceAll('/', '\\'));
  const firstSpace = literal.indexOf(' ');
  const first = firstSpace === -1 ? literal : literal.slice(0, firstSpace);
  const rest = firstSpace === -1 ? '' : literal.slice(firstSpace);
  if (!first.includes('/')) {
    const exe = first.includes('.') ? first : `${first}.exe`;
    probes.add(`C:\\Windows\\System32\\${exe}${rest}`);
    probes.add(`"${first}"${rest}`);
    if (first.length > 1) probes.add(`${first.slice(0, 1)}\\${first.slice(1)}${rest}`);
  }
}

const corpus = [...probes].sort();
writeFileSync(new URL('../test/differential/corpus.json', import.meta.url), `${JSON.stringify(corpus, null, 1)}\n`);
console.log(`corpus: ${corpus.length} probes from ${entries.size} literals`);
