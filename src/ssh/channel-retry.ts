/**
 * 放弃之前，把「打开 SSH 通道」重试几次。
 *
 * 不是每台服务器都能在第一次请求时可靠地分配通道。Dropbear 尤其如此——
 * 在上一个通道刚释放后它会间歇性失败。用原生 ssh2 即可复现，
 * 与我们的代码无关：
 *
 *   cycle #1: ok
 *   cycle #2: FAIL - Unable to request a pseudo-terminal
 *   cycle #3: ok
 *
 * SFTP 子系统同理。不重试的话，在整类主机上（嵌入式设备、
 * 路由器、极简镜像）开会话或传文件就是掷硬币——
 * 而且失败只会以一句干巴巴的
 * 「failed to open interactive session」呈现给用户。
 *
 * 重试*打开*是安全的：失败的打开没有创建任何东西。预算刻意
 * 很小，因此真正坏掉的主机仍会快速失败，
 * 而不是卡在重试后面。
 */
export interface RetryOptions {
  attempts?: number;
  delayMs?: number;
}

export async function openWithRetry<T>(
  open: () => Promise<T>,
  { attempts = 3, delayMs = 150 }: RetryOptions = {},
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await open();
    } catch (err) {
      lastError = err;
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, delayMs * attempt));
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
