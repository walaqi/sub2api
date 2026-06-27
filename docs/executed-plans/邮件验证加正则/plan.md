调研全部完成。两个设计点已锁定:**分隔符 `#`(按第一个 `#` 拆分,正则在左、展示信息在右)**,**强制 `^…$` 锚定**。下面是完整的可行方案与改动清单。

## 条目格式

```
re:<正则>#<展示信息>
```

例:`re:^\d+@qq\.com$#仅限纯数字QQ邮箱`

*   `re:` 前缀标记;无前缀的条目保持旧语义(`@domain` / `*.domain`),完全向后兼容。
*   按**第一个** `#` 拆分:`#` 在 RE2/JS 正则中都是字面量,正则部分不会用到它;展示信息里可自由使用 `|`、空格等。
*   强制:正则必须以 `^` 开头、`$` 结尾;`#` 后展示信息必须非空;`regexp.Compile` 必须通过。任一不满足 → 保存时报错(满足你"必须写全否则校验不通过")。

## 后端改动 [registration\_email\_policy.go](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/service/registration_email_policy.go)

1.  `normalizeRegistrationEmailSuffix`(:100):**最前面**加 `re:` 分支(在 `ToLower` 之前分流,避免把 `\D \W` 翻转)。校验锚定、`#`、`Compile`,原样保留大小写返回。
2.  `IsRegistrationEmailSuffixAllowed`(:25):加 `re:` 分支,取 `#` 前的正则对**整封邮箱**跑 `MatchString`。
3.  新增已编译正则的 `sync.Map` 缓存(RE2 线性安全,缓存仅省 CPU)。
4.  `buildEmailSuffixNotAllowedError` 在 [auth\_service.go:1044](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/service/auth_service.go#L1044):`re:` 条目对终端用户只展示 `#` 后的文案,不泄露 raw 正则。

## 前端改动 [registrationEmailPolicy.ts](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/frontend/src/utils/registrationEmailPolicy.ts)

1.  `isRegistrationEmailSuffixAllowed`:`re:` 用 `new RegExp` 匹配整封邮箱。
2.  归一化/canonical/format 三个函数对 `re:` 走专门分支,**不**经过 `EMAIL_SUFFIX_INVALID_CHAR_RE` 和 `ToLower`。
3.  `format...ForMessage`:`re:` 条目显示 `#` 后文案。

## 前端输入框 [SettingsView.vue](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/frontend/src/views/admin/SettingsView.vue)

放开你关心的字符拦截,三个 handler:

1.  `handleRegistrationEmailSuffixWhitelistDraftInput`(:7353):draft 以 `re:` 开头 → 跳过逐字符归一化(放行 `: ^ \ + $ # | @`)。
2.  `commitRegistrationEmailSuffixWhitelistDraft` / `addRegistrationEmailSuffixWhitelistTag`(:7329):`re:` 用正则校验代替 domain 校验。
3.  分隔键集合(:7314)+ `payload` 映射(:8011 `suffix.startsWith("*.") ? ... : @${suffix}`):`re:` draft 期间只允许 Enter 提交,且 payload 映射不给 `re:` 加 `@` 前缀。
4.  `handleRegistrationEmailSuffixWhitelistPaste`:`re:` 行不走 `[\s,，]+` 切分(否则切碎正则)。

## i18n + 测试

*   文案补 `re:` 用法说明:[zh.ts:5536](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/frontend/src/i18n/locales/zh.ts#L5536) / [en.ts:5374](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/frontend/src/i18n/locales/en.ts#L5374)。
*   后端 [registration\_email\_policy\_test.go](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/service/registration_email_policy_test.go) \+ 前端 [registrationEmailPolicy.spec.ts](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/frontend/src/utils/__tests__/registrationEmailPolicy.spec.ts) 补 `re:` 用例(锚定校验、`#` 拆分、纯数字 QQ 匹配、缺段报错)。

## 不用动

DB(仍 JSON 数组,无迁移)、审计 diff([setting\_handler.go:2108](vscode-webview://02o6oaihn1evl1rnsgsvd6sggap7dcl2ecrpvbkpb2m8s8vmtt5k/backend/internal/handler/admin/setting_handler.go#L2108) 字符串比较天然兼容)。

* * *

方案到此明确,要我开始实现吗?我会按"后端 policy + 缓存 → 后端测试 → 前端 util → 前端输入框 → i18n → 前端测试",每步跑对应的 `go test` / `vitest` 验证。