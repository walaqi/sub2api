# Anthropic OAuth 请求与响应逐字简繁转换计划

> 状态：已确认方案，尚未实施。只有在明确收到“开始实施”指令后才进入编码阶段。

## 目标

仅对 `PlatformAnthropic + AccountTypeOAuth` 的转发执行以下处理：

| 阶段 | 转换方式 |
| --- | --- |
| 发往上游的请求 | 对最终请求 body 一次性执行简体到繁体的逐字转换 |
| 返回客户端的非流式响应 | 对最终响应 body 一次性执行繁体到简体的逐字转换 |
| 返回客户端的流式响应 | 对每个已完整组装的下游 SSE block 执行繁体到简体的逐字转换 |

## 范围与边界

请求侧不按 `role`、消息类型或 JSON 路径筛选。完整 body 中的 `system`、全部历史消息、工具定义、工具参数、工具结果、metadata，以及中文键名和字符串值都参与转换。转换必须同时识别直接 UTF-8 中文和 JSON `\uXXXX` 转义形式。

HTTP headers、URL 和 body 之外的数据不处理。API Key、SetupToken、Service Account、Bedrock 及其他平台账号必须保持现有行为和原始字节不变。本功能不增加配置开关，严格由账号平台和类型判定。

## 转换语义

- 只做一对一 Unicode 字符映射，不做词组转换、上下文判断或台湾/香港地区用语转换。
- 多义字采用固定字符表中的确定性首选映射；未命中的字符保持不变。
- 字符表从固定版本的 OpenCC `STCharacters`、`TSCharacters` 字符字典生成，不加载 phrase 字典。
- 提交字符数据时记录上游版本、生成方式和 Apache-2.0 许可证归属。
- 转换后必须保持 JSON/SSE 语法有效、字段顺序稳定，并保留所有不相关字节。

## 模块设计

新增独立包 `backend/internal/pkg/zhcharconv`，负责字符表和完整载荷转换；新增 `backend/internal/service/anthropic_oauth_chinese_rewriter.go`，负责账号判定及网关接入。核心接口接收完整 `[]byte`，返回转换后的 body、是否发生变化及错误，不暴露字段级业务规则。

实现采用单次线性扫描。无匹配字符时直接返回原 slice；首次命中后才分配输出缓冲区。不得通过完整 `json.Unmarshal`/`json.Marshal` 重建对象树，以免改变字段顺序并放大内存占用。流式路径为每条连接复用 scratch buffer，避免每个 block 产生多轮小对象分配。

## 请求接入

1. 在 `buildUpstreamRequest` 完成 OAuth metadata、billing、beta 能力净化等现有 body 改写后，且在创建 `http.Request` 之前执行一次完整 body 简转繁。
2. `buildCountTokensRequest` 在同等的最终 wire-body 阶段执行相同转换，保证计数请求与真实请求一致。
3. 原生 Messages、Chat Completions 和 Responses 兼容路径通过最终上游请求构建器复用同一逻辑，不在各入口重复转换。
4. 每次上游尝试只转换一次。重试必须从未转换的逻辑 body 派生，转换后的 wire body 不得泄漏到后续非 OAuth failover 尝试。

## 响应接入

1. 原生非流式响应在模型名恢复、工具名恢复和其他现有改写完成后，紧邻 `c.Data` 之前整体繁转简。
2. Chat Completions 和 Responses 的非流式兼容响应在最终协议对象 marshal 且工具名恢复后整体转换。
3. 原生流式响应在一个 SSE block 完整组装、协议字段处理和工具名恢复后，紧邻写入与 flush 之前转换该 block。
4. 两条兼容协议的流式响应同样只转换最终下游协议 block，不提前转换上游碎片，也不跨 block 缓存。
5. usage 解析、计费、终止事件识别和运维日志继续使用现有结构化数据，不依赖转换后的显示文本。

## 错误处理

请求转换失败时停止本次上游发送，避免传出部分转换的 body。非流式响应在写出前转换失败时沿用现有网关错误响应。流式转换以完整 block 为原子单位；当前 block 转换失败时不得写出半个 block，并沿用现有 SSE 错误处理机制。

## 性能约束

转换复杂度为 `O(n)`，只增加内存扫描和必要的输出缓冲区，不增加网络 I/O、锁或 goroutine。按现有流量特征，约 100 KB 已属于大请求，超过 1 MB 的请求占比约千分之一；更大载荷视为边界条件，不为此功能增加专项 benchmark 或压测。

仍需保留 ASCII 快速路径、延迟分配和流式缓冲区复用，以控制常规请求的 CPU 与 GC 开销。

## 实施与验证顺序

1. 实现字符转换模块和请求/响应接入，不提前编写测试代码。
2. 使用本地录制上游和可控 SSE 样例确认最终 wire body、非流式完整响应及多 block 流式输出均符合预期。
3. 功能确认正确后补充必要的回归测试：完整载荷转换、UTF-8 与 Unicode 转义、非目标账号旁路、重试/failover 隔离、非流式响应和逐 block 流式响应。
4. 运行 `gofmt`、定向 Go 测试、`go test ./...` 和 `golangci-lint run ./...`。

不增加性能 benchmark。

## 验收标准

- 目标 OAuth 账号的最终上游请求 body 中，所有可映射简体字符均已逐字转换为繁体。
- 非流式最终响应 body 中，所有可映射繁体字符均已逐字转换为简体。
- 流式响应的每个完整下游 SSE block 在 flush 前完成转换，且不增加跨 block 等待。
- Unicode 转义、中文键名、工具内容和历史消息均符合完整载荷规则。
- 非目标账号、HTTP headers、URL、usage、计费和 failover 行为不发生回归。
- 输出保持有效 JSON/SSE，未出现部分转换或重复转换。
