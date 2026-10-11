#!/usr/bin/env bash
# 差分分类运行：分支基线 vs 工作树。
# 用法：scripts/differential-run.sh [base-ref]   （默认 1ccee48）
set -euo pipefail
BASE_REF="${1:-1ccee48}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ssh-mcp-diff.XXXXXX")"
git -C "$ROOT" worktree add --detach "$WORK/base" "$BASE_REF"
trap 'git -C "$ROOT" worktree remove --force "$WORK/base" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

# 基线树用它自己的源码加本树的依赖，给同一份语料分类：
# 同一运行器、同一语料、一个符号链接。
mkdir -p "$WORK/base/test/differential"
cp "$ROOT/test/differential/corpus.json" "$WORK/base/test/differential/"
cp "$ROOT/test/differential/runner.test.ts" "$WORK/base/test/differential/"
ln -s "$ROOT/node_modules" "$WORK/base/node_modules"

(cd "$ROOT" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-head.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)
(cd "$WORK/base" && SSH_MCP_DISABLE_MAIN=1 SSH_MCP_DIFFERENTIAL_OUT="$WORK/out-base.json" \
  npx vitest --run test/differential/runner.test.ts >/dev/null)

node "$ROOT/scripts/differential-compare.mjs" "$WORK/out-base.json" "$WORK/out-head.json"
