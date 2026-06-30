## 列出deduction\_mode所支持的所有内容

`deduction_mode` 字段只有两个合法取值，由数据库 CHECK 约束 + Go 端常量双重锁定：

| 取值 | 语义 | 必填字段 | 算法阶段 |
| --- | --- | --- | --- |
| `priority` | 优先扣除：先于充值池消耗，与充值池独立 | `ratio_recharge` 必须 NULL | Stage 1 |
| `ratio` | 比例扣除：每扣 1 单位充值池同步扣 `ratio_recharge` 单位赠金；充值池触底时联动作废 | `ratio_recharge` 必须 > 0 | Stage 2 |

**事实出处**：

*   DB 约束 [backend/migrations/142\_user\_gifts.sql:11-22](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/migrations/142_user_gifts.sql#L11-L22)：
    
    ```sql
    deduction_mode VARCHAR(16) NOT NULL CHECK (deduction_mode IN ('priority','ratio')),
    CONSTRAINT user_gifts_mode_ratio_check CHECK (
        (deduction_mode = 'ratio' AND ratio_recharge IS NOT NULL AND ratio_recharge > 0)
        OR (deduction_mode = 'priority' AND ratio_recharge IS NULL)
    )
    ```
    
*   Go 常量 [backend/internal/gift/types.go:10-17](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/gift/types.go#L10-L17)：
    
    ```go
    const (
        DeductionModePriority DeductionMode = "priority"
        DeductionModeRatio    DeductionMode = "ratio"
    )
    ```
    
*   引擎入口校验 [backend/internal/gift/engine.go validateGrantInput](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/gift/engine.go)：拒绝其他值、拒绝 priority 带 ratio\_recharge、拒绝 ratio 缺 ratio\_recharge 或 ≤ 0

**status 字段**（与 deduction\_mode 不同，但常一起被记错）也列出来供参考：

| status | 触发 |
| --- | --- |
| `active` | 默认；可参与扣费 |
| `exhausted` | remaining 自然耗尽（扣到 0） |
| `expired` | 过期清理 ticker 把 expires\_at 过期的赠金作废 |
| `revoked` | ratio 联动作废：充值池触底时所有仍 active 的 ratio 赠金一并作废 |

`source` 字段目前实际写入 3 个值：`keybind`、`oauth_first_bind`、`promo_code`（[gift/types.go:25-29](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/gift/types.go#L25-L29)），其他 source（如 `manual`、`redeem`）按用户决策本次不写入。


---

