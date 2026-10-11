import { isAbsolute, relative, sep } from 'node:path';

/**
 * 具备路径段意识的包含判断；与前缀检查不同，兄弟目录永不匹配。
 *
 * `..` 的各种情形是显式写出的，而不是用 `rel.startsWith('..')`——
 * 后者会把 `..cache` 这样正当命名的兄弟目录也一并拒绝。
 */
export function isWithinRoot(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/** 双向包含（含相等）时为真。 */
export function pathsOverlap(left: string, right: string): boolean {
  return isWithinRoot(left, right) || isWithinRoot(right, left);
}
