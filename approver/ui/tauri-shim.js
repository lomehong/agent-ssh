// approval.js 的 invoke 桥（独立窗口无 index.html 的全局注入依赖）：
// 与 ui.js 相同来源——window.__TAURI__（withGlobalTauri 注入）。
const invoke = window.__TAURI__?.core?.invoke;

export { invoke };
