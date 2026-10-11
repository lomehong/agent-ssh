#!/usr/bin/env node
// 比较两次差分运行。本装置在语料上度量的不变量：一条命令的
// 类别要么不变、要么上升——绝不下降
// （更严格的读法可能多要一次批准；
// 但绝不会多拒绝一条）。
import { readFileSync } from 'node:fs';

const RANK = { 'read-only': 0, safe: 1, destructive: 2, privileged: 3 };
const [baseFile, headFile] = process.argv.slice(2);
if (!baseFile || !headFile) {
  console.error('usage: differential-compare.mjs <base.json> <head.json>');
  process.exit(2);
}
const base = JSON.parse(readFileSync(baseFile, 'utf8'));
const head = JSON.parse(readFileSync(headFile, 'utf8'));

let same = 0;
const rises = [];
const drops = [];
for (const command of Object.keys(base)) {
  const before = base[command];
  const after = head[command];
  if (after === undefined) { drops.push([command, before, '(absent)']); continue; }
  if (RANK[after] === RANK[before]) { same++; continue; }
  (RANK[after] > RANK[before] ? rises : drops).push([command, before, after]);
}

for (const [command, before, after] of rises) console.log(`RISE  ${before} -> ${after}  ${command}`);
for (const [command, before, after] of drops) console.log(`DROP  ${before} -> ${after}  ${command}`);
console.log(`\n${same} unchanged, ${rises.length} risen, ${drops.length} dropped`);
process.exit(drops.length === 0 ? 0 : 1);
