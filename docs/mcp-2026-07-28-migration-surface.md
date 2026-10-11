# MCP 2026-07-28：它将让我们付出什么，以及在那天之前该做什么

> 撰写于 2026-08-24，依据规范修订版 [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
> 及截至 2026-08-22 的 [路线图](https://modelcontextprotocol.io/development/roadmap)。
> 本文今天没有任何可落地为代码的内容——见[为什么现在无东西可升级](#为什么现在无东西可升级)。
> 它的目的是：等 SDK 追上来的那一天，我们不必重新发现这份清单。

## 为什么现在无东西可升级

| | |
|---|---|
| 当前规范修订版 | **2026-07-28** |
| 已安装 SDK | `@modelcontextprotocol/sdk@1.30.0` |
| 最新发布 SDK | **1.30.0** —— 唯一的 dist-tag，无预发布版 |
| 该 SDK 支持的最新协议 | `LATEST_PROTOCOL_VERSION = '2025-11-25'`（默认协商：`2025-03-26`） |

TypeScript SDK 发布于 **2026-07-27**，比规范修订早一天，至今没有跟上。我们已经在最新版本上；差距在上游。

差距有多大，以 `node_modules/@modelcontextprotocol/sdk/dist/esm/` 为准实测：

| 符号 | 命中文件数 |
|---|---|
| `tasks/get` | 7 |
| `input_required` | 5 |
| `resultType` | 0 |
| `server/discover` | 0 |
| `inputRequests` | 0 |
| `subscriptions/listen` | 0 |
| `cacheScope` | 0 |
| `Mcp-Method` | 0 |

`tasks/*` 与 `input_required` 的命中来自 **2025-11-25** 的实验性 Tasks 特性——2026-07-28 已把它*移出*核心、放进 `io.modelcontextprotocol/tasks` 扩展并重新设计。2026-07-28 的核心内容一行都还没开始。信任这张表之前请重跑一遍：

```bash
for s in resultType server/discover input_required inputRequests subscriptions/listen cacheScope Mcp-Method tasks/get; do
  printf '%-22s %s\n' "$s" "$(grep -rl "$s" node_modules/@modelcontextprotocol/sdk/dist/esm/ 2>/dev/null | wc -l)"
done
```

## 会落到我们头上的

按「多少是我们的代码而非 SDK 的代码」排序。

### 1. Elicitation 变为 Multi Round-Trip Requests——最大的一件

**规范：** MRTR（[SEP-2322](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2322)）
取代服务器发起的请求，含 `elicitation/create`。服务器返回携带 `inputRequests` 的
`InputRequiredResult`（`resultType: "input_required"`）；客户端以携带 `inputResponses` 的方式
**重试原始请求**来作答。

**我们的现状：** `src/guard/elicitation.ts` 与 `src/tools/pipeline.ts` 中的 `checkPolicyAndApprove`
在单次工具调用*内部*阻塞等待 `server.elicitInput()`。MRTR 把这个模型倒转：调用先返回，
答案由之后的一次调用带来。

在动这块之前值得知道的后果：

- `approvalGrantTtlMs` 不再只是便利项，而成为让重试变便宜的机制——授权正是让第二次尝试不必再次询问就能通过的东西。
- 规范移除了 `notifications/elicitation/complete` 与 `elicitationId`，并说需要跨重试关联 elicitation 的服务器应「把自己的标识符编码进 `requestState`」。我们今天两者都没用，没有需要回退的东西。
- 一个早已收回回报的决定：`elicitation.ts` 刻意使用 SDK 的类型化 `elicitInput()`，而不是手工构造信封，为的就是「协议变更时坏掉的是构建而不是运行时」。这就是它为之而写的那次协议变更。

### 2. 协议层会话被移除

**规范：** [SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567) 从
Streamable HTTP 中移除 sessions 与 `Mcp-Session-Id` 头；list 端点不再随连接而不同。需要跨调用
状态的服务器改用「显式的、由服务器铸造的、作为普通工具参数传递的句柄」。

**我们的现状：** `src/transport/http.ts` 维护以 `mcp-session-id` 为键的
`Map<string, StreamableHTTPServerTransport>`，带 `MAX_SESSIONS`、DELETE 路径和 `-32000`/`-32001`
会话错误。这些全部变成死重。

**设计本身存活。** `open-session name=…` 本来就*是*一个作为工具参数传递的服务器铸造句柄——
正是新规范要求的东西。要走的只是传输层的管道。

### 3. HTTP GET 端点被 `subscriptions/listen` 取代

GET 端点与 `resources/subscribe`/`unsubscribe` 消失，由单一的长连接 POST 响应流取代。
`src/transport/http.ts` 在限流器与健康探针中对 `/` 匹配 `req.method === 'GET'`；前者需要重审，
后者是我们自己的，不受影响。

注意规范明确：请求作用域的通知——我们从 `pipeline.ts` 发出的 `notifications/progress`——
**继续流经其自身请求的响应流**，而非订阅流。我们的进度路径不受影响。

### 4. `ttlMs` 与 `cacheScope` 成为 list 与 read 结果的必填项

[SEP-2549](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2549) 要求
`tools/list`、`prompts/list`、`resources/list`、`resources/read` 与 `resources/templates/list`
同时携带两者。

**不要与我们在 `src/types.ts` 里自己的 `ttlMs` 混淆**——那是会话空闲 TTL，与
`CacheableResult` 毫无关系。

我们的 resources（`ssh://connections`、`ssh://connections/{profile}`、
`ssh://sessions/{profile}/{session}`）返回的是实时的、随调用方而异的状态。诚实的答案是
`cacheScope: "private"` 配一个较短的 `ttlMs`，而且这值得深思熟虑地选择，而不是接受 SDK 的
随便什么默认值——一个共享中间层缓存连接列表是信息泄露，不是小划伤。

### 5. 必填请求头

`Mcp-Method` 与 `Mcp-Name` 成为 Streamable HTTP POST 的必填头
（[SEP-2243](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2243)），触及
`src/transport/http.ts` 中的认证与限流中间件。

### 那是 SDK 的问题，不是我们的

无状态化与 `initialize` 握手的移除；`server/discover`（对服务器是 **MUST**）；每个结果上的
`resultType`；错误码重编号。

## 我们白拿到的

不是运气——其中大半是我们出于别的原因早已采取的立场。

- **Sampling、Roots 与 Logging 全部被弃用，而我们一个都没用。** Logging 的建议迁移路径是
  「记录到 `stderr`（stdio）或使用 OpenTelemetry」——两条我们都在做。
- **HTTP+SSE 被正式标记为 Deprecated**；我们已在 Streamable HTTP 上。
- **我们的自定义 JSON-RPC 码被 grandfathered。** 新的分配政策把 `-32000`–`-32019` 保留为
  实现自定义区；我们的 `-32000`/`-32001` 正在其中。（规范出于同样理由把它自己的
  `HeaderMismatch` 从 `-32001` 改到 `-32020`。）
- **我们不返回 `structuredContent`**，因此路线图上 `tools/call` 的结果形态重设计伤不到我们。
  如果哪天想要结构化输出，那就是采纳的时机——不必更早。
- `elicitationId` 与 `notifications/elicitation/complete` 我们都没用，而两者都被移除了。

## 路线图上正对着我们的条目

- **Agent Identity（优先级 3）。** 路线图原话：现有服务器「依赖粘贴的 API key 与长期
  refresh token」。那说的就是我们的 HTTP bearer 令牌。方向是 DPoP、Workload Identity Federation
  （[SEP-1933](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/1933)）、
  ID-JAG 与 RFC 8693 令牌交换。今天没有一样可实现——但足以成为不再为现有认证路径继续投入的理由。
- **Tasks（优先级 1，[SEP-2663](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663)）。**
  后台会话 + 进度 + 取消，就是这个扩展的手工版。重设计经 `tasks/get` 轮询、经 `tasks/update`
  接收客户端输入。长期看它可能取代 `open-session type="background"`。
- **HTTP over stdio（优先级 2）。** Streamable HTTP 成为唯一绑定，跑在 stdin/stdout 上。
  会把我们的两种传输合而为一。现在无事可做，但它是一条「在此期间别再写更多传输专属代码」的理由。
- **渐进式发现（优先级 4）。** 面向工具目录庞大的服务器。我们只有 14 个工具；暂时与我们无关。
- **一致性测试套件（优先级 5）。** 出现之后值得对我们自己跑一遍。

## 该做什么，不该做什么

**现在：**

1. 让本文保持最新。这正是写它的全部意义。
2. **不要再基于 elicitation 或会话作用域的传输状态构建任何新东西。** 两者都在被移除。
   这是今天就能做、且真正能为以后省力的唯一动作。

**一个决策，而非代码：** 是否为 HTTP 传输的 bearer 令牌跟进 DPoP。它决定我们还愿意在现有
认证路径上投入多少。

**明确不做：** 在一个尚不支持 2026-07-28 的 SDK 上实现 2026-07-28。我们的 HTTP 传输构建在
`StreamableHTTPServerTransport` 之上；fork 或 shim 它会打开一大片高风险表面，换来的规范的
SDK 支持还没有开始。等 SDK 发布时，上文第 1–5 节的大部分会变成「一次 SDK 升级 + 对
`src/transport/http.ts` 与审批路径的一次聚焦修改」。

## 如何复核本文

```bash
npm view @modelcontextprotocol/sdk dist-tags --json          # 是否有更新的发布或预发布？
grep -n "LATEST_PROTOCOL_VERSION\|SUPPORTED_PROTOCOL_VERSIONS" \
  node_modules/@modelcontextprotocol/sdk/dist/esm/types.js   # 它实际说的是哪个协议？
```

当 `LATEST_PROTOCOL_VERSION` 读出 `2026-07-28` 的那一天，这份清单就不再是理论。

