/**
 * 传输安全纪律（T-14，方案 §3.1 + A7 + K8-①）：
 * - Host 侧：非环回绑定强制 TLS，否则启动即拒（fail-fast，不留半开配置）；
 * - stub/审批端侧：非环回目标必须 TLS；TLS 无 pin → fail-closed 拒连
 *   （pin 是唯一身份锚，缺失即拒，不做任何默认放行）；
 * - pin 一票否决（A7）：AGENT_SSH_HOST_PIN 一旦设置，任何模式不可覆盖，
 *   证书指纹不匹配即拒，错误对齐 HOST_KEY_PIN_MISMATCH 措辞纪律。
 *
 * 环回判定复用 http.ts 的地址归一实现（canonicalAddress，T-13.5 迁入 ./address）。
 */
import { timingSafeEqual } from 'crypto';
import { isIP } from 'net';
import { canonicalAddress } from './address.js';

export class BindPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BindPolicyError';
  }
}

export class PinMismatchError extends Error {
  constructor() {
    // 措辞对齐 HOST_KEY_PIN_MISMATCH 纪律（A7）
    super('HOST_PIN_MISMATCH: host certificate fingerprint does not match AGENT_SSH_HOST_PIN');
    this.name = 'PinMismatchError';
  }
}

/** 绑定地址是否环回：127/8、::1（含 [::1] 文法）、::ffff: 映射的 IPv4 环回、localhost。 */
export function isLoopbackBindAddress(host: string): boolean {
  let candidate = host.trim().toLowerCase();
  if (candidate === 'localhost') return true;
  if (candidate.startsWith('[') && candidate.endsWith(']')) candidate = candidate.slice(1, -1);
  candidate = canonicalAddress(candidate);
  if (isIP(candidate) === 0) return false;
  return candidate === '127.0.0.1' || candidate === '::1' || candidate.startsWith('127.');
}

/** Host 启动自检：非环回绑定未开 TLS 直接拒启（§3.1）。 */
export function assertBindAllowed(host: string, tls: boolean): void {
  if (!isLoopbackBindAddress(host) && !tls) {
    throw new BindPolicyError(
      `Binding ${host} requires TLS: non-loopback binds refuse plaintext (fail-fast at startup)`,
    );
  }
}

export interface ClientConnectPolicy {
  host: string;
  tls: boolean;
  /** AGENT_SSH_HOST_PIN（部署时分发，一票否决）。 */
  pin?: string;
}

/** 客户端连接自检：stub/审批端连 Host 前调用，违规即拒连（绝不降级重试明文）。 */
export function assertClientConnectAllowed(policy: ClientConnectPolicy): void {
  const loopback = isLoopbackBindAddress(policy.host);
  if (!policy.tls) {
    if (policy.pin !== undefined && policy.pin !== '') {
      throw new BindPolicyError(
        'AGENT_SSH_HOST_PIN is set but the connection is plaintext: pin cannot be verified, refusing (fail-closed)',
      );
    }
    if (!loopback) {
      throw new BindPolicyError(`Refusing plaintext connection to non-loopback host ${policy.host}`);
    }
    return;
  }
  if (policy.pin === undefined || policy.pin === '') {
    // K8-①：TLS+无 pin 行为必须有定义——fail-closed 拒连
    throw new BindPolicyError(
      'TLS connection without AGENT_SSH_HOST_PIN refuses to connect (fail-closed; the pin is the only identity anchor)',
    );
  }
}

/** 证书指纹核对（sha256 hex，大小写与冒号分隔差异归一后常时比较）。 */
export function verifyPin(certFingerprintHex: string, pin: string): void {
  const normalize = (s: string): string => s.replace(/:/g, '').toLowerCase();
  const actual = Buffer.from(normalize(certFingerprintHex), 'hex');
  const expected = Buffer.from(normalize(pin), 'hex');
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new PinMismatchError();
  }
}
