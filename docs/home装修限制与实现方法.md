# 首页 (home_content) 装修限制与实现方法

> 本文档总结了通过后台「系统设置 → 首页内容 (`home_content`)」对站点首页做自定义装修时,**渲染机制、CSP 限制、以及当前可用的占位符语法**。新增功能时优先参考这里。

---

## 1. 渲染机制

源码位置: [frontend/src/views/HomeView.vue](../frontend/src/views/HomeView.vue)

```vue
<div v-if="homeContent" class="min-h-screen">
  <!-- URL 模式 -->
  <iframe v-if="isHomeContentUrl" :src="homeContent.trim()" ...></iframe>
  <!-- HTML 模式 -->
  <div v-else v-html="homeContent"></div>
</div>
```

后台 `home_content` 字段:
- 以 `http://` / `https://` 开头 → 走 **iframe 模式**(整页嵌入外部 URL)
- 否则 → 走 **HTML 模式**(`v-html` 直接 innerHTML 注入)

设置走 `appStore.cachedPublicSettings.home_content`,后端通过 [vite.config.ts:24](../frontend/vite.config.ts#L24) 在 `index.html` 顶部注入 `window.__APP_CONFIG__ = {...PublicSettings...}`(字段类型见 [frontend/src/types/index.ts:188](../frontend/src/types/index.ts#L188))。

---

## 2. 关键限制

### 2.1 CSP 严格拦截 inline 事件处理器

站点 CSP 形如:
```
script-src 'self' 'nonce-<random>' https://challenges.cloudflare.com ...
```

不含 `unsafe-inline` / `unsafe-hashes`。后果:
- `onload="..."` / `onerror="..."` / `onclick="..."` 等内联事件处理器 **全部被拦**,控制台报 `Executing inline event handler violates the following CSP directive`。
- 内联 `<script>...</script>` 也无 nonce → 同样被拦。

### 2.2 `v-html` 不执行 `<script>`

Vue 的 `v-html` 用 `el.innerHTML = value`。按 HTML 规范,**通过 innerHTML 写入的 `<script>` 标签不会执行**(无论是否带 nonce)。

### 2.3 推论:home_content 内**无法运行任何 JS**

CSP 拦内联 handler + innerHTML 不跑 script,两条路都堵死。所以:
- 拿不到 `window.__APP_CONFIG__`
- 拿不到登录态、用户信息
- 不能调用 fetch / `addEventListener`

**任何"动态显示"必须在 Vue 层先把数据替换好再 v-html 出去**,这就是下面的模板替换方案。

### 2.4 其它限制

- `home_content` 的 XSS 风险被显式接受(注释见 [HomeView.vue:11](../frontend/src/views/HomeView.vue#L11)),因为该字段只有 admin 能改。
- 自定义 CSS 必须使用 **唯一前缀**(如 `.or-`)避免污染主应用的 Tailwind 类。
- 暗色主题:用 `:where(.dark) .or-root { ... }` 跟随主站 `.dark` class 自动切换(主站通过 `<html>` 上 `.dark` 触发)。

---

## 3. 模板替换机制 (Pre-render Substitution)

为了在 CSP 限制下仍能"按后台设置动态显示",在 [HomeView.vue](../frontend/src/views/HomeView.vue#L424) 的 `homeContent` computed 中,**v-html 注入前做字符串替换**:

```ts
const homeContent = computed(() => {
  const raw = appStore.cachedPublicSettings?.home_content || ''
  if (!raw) return ''
  const s = appStore.cachedPublicSettings || ({} as Record<string, any>)
  const authed = authStore.isAuthenticated
  const dashPath = authStore.isAdmin ? '/admin/dashboard' : '/dashboard'
  const ctaHref = authed ? dashPath : '/login'
  const ctaText = authed ? '控制台' : '免费注册'
  const conditional = (input: string) =>
    input.replace(/\{\{#if\s+auth\s*\}\}([\s\S]*?)\{\{else\}\}([\s\S]*?)\{\{\/if\}\}/g,
      (_m, a, b) => (authed ? a : b))
  return conditional(raw)
    .replace(/\{\{\s*site_name\s*\}\}/g, s.site_name || '')
    .replace(/\{\{\s*site_logo\s*\}\}/g, s.site_logo || '')
    .replace(/\{\{\s*site_subtitle\s*\}\}/g, s.site_subtitle || '')
    .replace(/\{\{\s*doc_url\s*\}\}/g, s.doc_url || '')
    .replace(/\{\{\s*cta_href\s*\}\}/g, ctaHref)
    .replace(/\{\{\s*cta_text\s*\}\}/g, ctaText)
})
```

### 3.1 当前支持的占位符

| 占位符 | 来源 | 说明 |
|---|---|---|
| `{{ site_name }}` | `PublicSettings.site_name` | 站点名称 |
| `{{ site_logo }}` | `PublicSettings.site_logo` | 站点 logo(后台返回的可能是 `data:image/png;base64,...`,直接塞 `<img src>` 即可) |
| `{{ site_subtitle }}` | `PublicSettings.site_subtitle` | 站点副标题 |
| `{{ doc_url }}` | `PublicSettings.doc_url` | 文档地址 |
| `{{ cta_href }}` | 派生 | 已登录 → `/dashboard` 或 `/admin/dashboard`;未登录 → `/login` |
| `{{ cta_text }}` | 派生 | 已登录 → `控制台`;未登录 → `免费注册` |

### 3.2 条件块语法

```
{{#if auth}}已登录看到的 HTML{{else}}未登录看到的 HTML{{/if}}
```

- 仅支持 `auth` 一个条件(对应 `authStore.isAuthenticated`)
- **不支持嵌套**(正则非贪婪,内层 `{{#if auth}}` 会被外层吞掉)
- 块内可以是任意 HTML、含其它 `{{ ... }}` 变量占位符(因为替换发生在条件块替换**之后**)

---

## 4. 新增占位符 / 条件的扩展方法

### 4.1 加一个简单变量

例: 加 `{{ user_email }}`。

1. 确保数据在 `appStore.cachedPublicSettings` 或 `authStore` 里能拿到。
2. 在 `homeContent` computed 末尾追加 `.replace(/\{\{\s*user_email\s*\}\}/g, authStore.user?.email || '')`。
3. 文档表格里补一行,粘贴到 home_content 的 HTML 里使用 `{{ user_email }}`。

### 4.2 加一个派生值(如 CTA 跳转)

参考现有 `cta_href` / `cta_text`,在 computed 顶部计算好,再用 `.replace` 注入。

### 4.3 加一个新条件块

例: `{{#if admin}}...{{else}}...{{/if}}`。

复制 `conditional` 函数,把正则里的 `auth` 改成 `admin`,判断条件改成 `authStore.isAdmin`。要点:**多个条件块的替换顺序很重要**,内层先替换、外层后替换;或者干脆约定 home_content 里不嵌套条件块。

### 4.4 为何不直接做"通用模板引擎"

- 当前需求轻量,正则替换够用,**显式列举占位符** 比 sandbox 一个 eval 更安全。
- 防 XSS 也容易审查:每个 `.replace` 都明确知道值的来源(都是 admin 自己设置或后端派生的可信值)。
- 如果将来需求复杂,再考虑接 [Mustache](https://github.com/janl/mustache.js) 或 [Handlebars](https://handlebarsjs.com/) 单独打包到 HomeView。

---

## 5. CSS 约定

- 所有自定义类用统一前缀(如 OpenRouter 风格那套用 `or-`),避免和主应用 Tailwind 冲突。
- 把 `<style>` 标签直接写进 home_content,作用域仅限当前页面(因为离开首页后该 DOM 被卸载,样式也跟着 GC)。
- 暗色模式靠 `:where(.dark) .or-root { --or-bg: ...; }` 切 CSS 变量,而**不要**在 home_content 里挂 `document.addEventListener` 监听主题。
- 避免使用 `<img onload>` 等内联事件做"图片预加载/动画" → CSP 拦。改用 CSS `@keyframes` 实现纯 CSS 动画。

---

## 6. 可执行 JS 的逃生通道:iframe 模式

如果某天确实需要在自定义首页里跑 JS(图表、表单提交联动、第三方组件等),用 **iframe 模式**:

1. 把要展示的页面自己托管(可以是同源静态目录,也可以是外站)
2. 后台 `home_content` 填该页面的完整 URL(http/https 开头)
3. Vue 端会自动走 iframe 分支 ([HomeView.vue:6-10](../frontend/src/views/HomeView.vue#L6-L10)),iframe 内部脱离主站 CSP 控制

代价:登录态需要 iframe 自己用 cookie / `postMessage` 通信。

---

## 7. 关键文件索引

| 文件 | 作用 |
|---|---|
| [frontend/src/views/HomeView.vue](../frontend/src/views/HomeView.vue) | 渲染入口 + 占位符替换 computed |
| [frontend/src/stores/app.ts](../frontend/src/stores/app.ts) | `cachedPublicSettings` 来源 |
| [frontend/src/types/index.ts](../frontend/src/types/index.ts) | `PublicSettings` 接口定义 |
| [frontend/vite.config.ts](../frontend/vite.config.ts) | 把 `__APP_CONFIG__` 注入到 index.html |
| [home-openrouter-style.html](../home-openrouter-style.html) | 当前线上 OpenRouter 风格首页 HTML (粘到后台 home_content) |

---

## 8. 历史教训(避免重复踩坑)

1. ❌ **不要再尝试**用 `<img onerror>` / `<img onload>` / `<svg onload>` 做 hydration。CSP 拦。
2. ❌ **不要再尝试**用 `<script>` 标签注入数据。innerHTML 不执行。
3. ❌ **不要**在 home_content 里直接写 `{{ vue 表达式 }}` 期待 Vue 编译 —— v-html 不编译模板,只 innerHTML。当前 `{{ ... }}` 是我们**自己用正则做的字符串替换**,不是 Vue 模板语法。
4. ✅ 需要动态值 → 加占位符 + Vue 层 `.replace`。
5. ✅ 需要交互 JS → 走 iframe 模式。
