# keypool 批次发 key 功能实现计划

## Context

`keypool@atai8.cc` 是 sub2api 后端配置的 "pool 用户"——它名下 active 且剩余配额 > 50% 的 API key 可以被普通用户通过 `POST /api/v1/bind-key/{reserve,commit}` 领走（`api_keys.user_id` 从 pool → 真实用户、`group_id` 被清空，见 [keybind/service.go:185-244](../../projects/sub2api/backend/internal/keybind/service.go#L185-L244)）。

目前 sub2api-ops 工具不能给 pool 账户量产 key——这次就是要补上：

1. 在 ops 工具里新建一个「Key 池补货」批次：批次名、单 key 余额、生成数量、key 所属分组（可选）→ 一键调 `keypool@atai8.cc` 的用户态 `POST /api/v1/keys` 接口生成 N 个 key；
2. 生成的 key 在批次详情页明文展示，方便复制分发；
3. 批次详情页实时显示 **被使用余额**`(used/total quota)` 和 **被领取数量**`(claimed/total)`。

## 决策与约束

- **不改 sub2api 后端**（用户决定）。靠 ops 工具用 `keypool@atai8.cc` 的邮箱+密码登录拿 JWT，再调用用户态 `POST /api/v1/keys` 创建 key。后端只有用户态创建接口 ([api_key_handler.go:143-184](../../projects/sub2api/backend/internal/handler/api_key_handler.go#L143-L184))。
- **整批共享一套参数**（用户决定）：批次内每个 key 都用同一份 `{quota, group_id, expires_in_days}`，名字按 `{batch_name} #{n}` 自动生成。
- **明文 key 落本机 SQLite**（用户决定）：和 `config.yaml`（已有 admin 密钥）一个保密级别（`chmod 600`），不加密。批次详情页一键复制。
- **领取统计实时查询**（用户决定）：进入批次详情页时调一次 sub2api，不缓存。
- **被领取判定**（用户最新决定）：只看 `owner != keypool 用户 id`，不需要拿到具体新 owner。一次 `GET /api/v1/admin/users/{keypool_user_id}/api-keys?page_size=1000` 拿到当前仍在 pool 的 key id 集合，与本批次记录的 key id 做差集即得已领取列表。
- **配置存储**：keypool 邮箱/密码新增到 `config.yaml`，`config.py` 加对应 dataclass。
- **Turnstile**：`AuthService.VerifyTurnstile` 在 `Server.Mode != "release"` 或 `Turnstile.Required = false` 时直接返回 nil ([auth_service.go:378-400](../../projects/sub2api/backend/internal/service/auth_service.go#L378-L400))。ops 工具传空 `turnstile_token`；如果对方部署强制 Turnstile，登录会失败并明确报错——届时再补 Cloudflare bypass。

## 改动文件清单

### sub2api-ops（主改动）

| 文件 | 改动 | 说明 |
|---|---|---|
| `config.example.yaml` | + `keypool:` 段 | 新增 `email`/`password`/`pool_user_id`（启动时若为 0 则懒查询） |
| `config.yaml` | + `keypool:` 段 | 同上（线下手填）|
| `config.py` | + `KeypoolConfig` dataclass | 串到 `AppConfig.keypool` |
| `sub2api_client/client.py` | + 4 个方法 | 见下面【client 改动】 |
| `ops/store.py` | + 2 张表、+ DAO 方法 | 见下面【SQLite schema】 |
| `ops/keypool_batch.py` | **新增** | 批次提交 + 后台生成 + 拉取 stats |
| `views/keypool.py` | **新增** | Blueprint `/keypool` |
| `app.py` | 注册新 blueprint | 一行 |
| `templates/base.html` | 导航加「Key 池」 | 一行 |
| `templates/keypool/list.html` | **新增** | 批次列表 |
| `templates/keypool/new.html` | **新增** | 新建批次表单 |
| `templates/keypool/detail.html` | **新增** | 批次详情（key 明文 + 复制 + stats） |

### sub2api 后端

**不动**。

## 详细设计

### 1. SQLite schema（追加到 [ops/store.py:18-64](../../projects/sub2api-ops/ops/store.py#L18-L64) `_SCHEMA`）

```sql
CREATE TABLE IF NOT EXISTS keypool_batches (
  id INTEGER PRIMARY KEY,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,                -- 批次名，例如 "2026-05 内测群发-A"
  pool_user_id INTEGER NOT NULL,     -- 创建时的 keypool 用户 id 快照
  group_id INTEGER,                  -- 每个 key 绑定到的分组（NULL = 不绑）
  per_key_quota REAL NOT NULL,       -- 每个 key 的 quota（USD），0 = 无限
  expires_in_days INTEGER,           -- 每个 key 的有效期（NULL = 永久）
  total INTEGER NOT NULL,            -- 计划生成数量
  status TEXT NOT NULL,              -- pending / generating / done / failed / partial
  notes TEXT
);

CREATE TABLE IF NOT EXISTS keypool_batch_keys (
  id INTEGER PRIMARY KEY,
  batch_id INTEGER NOT NULL REFERENCES keypool_batches(id),
  seq INTEGER NOT NULL,              -- 批内序号 1..N（用来做名字）
  api_key_id INTEGER,                -- 创建成功后的 sub2api id（失败为 NULL）
  api_key_plain TEXT,                -- 明文 key（成功后填，失败为 NULL）
  status TEXT NOT NULL,              -- pending / created / failed
  error TEXT,
  created_at TEXT,                   -- sub2api 那边的 created_at
  UNIQUE(batch_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_keypool_batch_keys_batch ON keypool_batch_keys(batch_id);
CREATE INDEX IF NOT EXISTS idx_keypool_batch_keys_api ON keypool_batch_keys(api_key_id);
```

**新增 DAO 方法**（`Store` class 末尾追加，命名风格参照 `create_batch`/`list_batches`）：

```python
def create_keypool_batch(*, name, pool_user_id, group_id, per_key_quota,
                         expires_in_days, total, notes="") -> int
def insert_keypool_batch_key(*, batch_id, seq, status="pending") -> int
def update_keypool_batch_key_success(*, batch_id, seq, api_key_id,
                                     api_key_plain, created_at) -> None
def update_keypool_batch_key_failure(*, batch_id, seq, error) -> None
def update_keypool_batch_status(batch_id: int, status: str) -> None
def list_keypool_batches(limit: int = 50) -> list[Row]
def get_keypool_batch(batch_id: int) -> Row | None
def list_keypool_batch_keys(batch_id: int) -> list[Row]
```

### 2. sub2api_client/client.py 新增方法

复用现有 `_request`/`_unwrap`/重试机制（[client.py:44-91](../../projects/sub2api-ops/sub2api_client/client.py#L44-L91)）。

```python
# ---- auth (special: not via x-api-key, returns JWT) ------------------
def login_user_password(self, *, email: str, password: str,
                        turnstile_token: str = "") -> dict[str, Any]:
    """POST /api/v1/auth/login. 返回 {access_token, refresh_token, expires_in, user}."""
    body = {"email": email, "password": password,
            "turnstile_token": turnstile_token}
    # 注意：登录不能带 admin x-api-key header；要新建一次性 httpx 调用或临时改 header。
    resp = httpx.post(f"{self._base}/api/v1/auth/login",
                      json=body, timeout=self._client.timeout)
    resp.raise_for_status()
    return self._unwrap(resp.json())

# ---- user-side keys (impersonating keypool@atai8.cc) ----------------
def create_user_api_key(self, *, jwt: str, name: str,
                        group_id: int | None = None,
                        quota: float = 0,
                        expires_in_days: int | None = None) -> dict[str, Any]:
    """POST /api/v1/keys with Bearer JWT. 返回完整 APIKey DTO（含明文 key）。"""
    body = {"name": name, "quota": quota}
    if group_id is not None:
        body["group_id"] = group_id
    if expires_in_days is not None:
        body["expires_in_days"] = expires_in_days
    headers = {"Authorization": f"Bearer {jwt}",
               "Accept": "application/json"}
    return self._unwrap(self._request("POST", "/api/v1/keys",
                                      json=body, headers=headers))

# ---- admin: list keys still owned by pool user -----------------------
def list_user_api_keys(self, user_id: int, *, page: int = 1,
                       page_size: int = 200) -> dict[str, Any]:
    """GET /api/v1/admin/users/{id}/api-keys. 返回 {items, pagination}."""
    return self._unwrap(self._request("GET",
        f"/api/v1/admin/users/{user_id}/api-keys",
        params={"page": page, "page_size": page_size}))

# ---- admin: batch usage stats by key ids -----------------------------
def batch_api_keys_usage(self, api_key_ids: list[int]) -> dict[str, Any]:
    """POST /api/v1/admin/dashboard/api-keys-usage.
    返回 {stats: {key_id_str: usage_payload}}.（不依赖 owner）"""
    return self._unwrap(self._request("POST",
        "/api/v1/admin/dashboard/api-keys-usage",
        json={"api_key_ids": list(api_key_ids)}))
```

**关键点**：`_request` 当前只在构造函数里设置了 `x-api-key` header（[client.py:29-33](../../projects/sub2api-ops/sub2api_client/client.py#L29-L33)）。`create_user_api_key` 走 Bearer 时需要让 `headers` 参数覆盖；`_request` 已经把 `**kwargs` 透传给 `httpx`，httpx 的 `headers` 是合并而非覆盖，但 Bearer 跟 x-api-key 共存不影响（后端 admin middleware 优先看 x-api-key，但 `/api/v1/keys` 用的是 JWT middleware，看 Authorization header）。**保险起见在 `_request` 里加一个 `_strip_admin_auth` 开关，调登录和用户态接口时不附带 x-api-key。**

### 3. ops/keypool_batch.py（新增，参照 [ops/batch_provision.py](../../projects/sub2api-ops/ops/batch_provision.py) 的三段式）

```python
def submit_keypool_batch(client, store, cfg, *, name, group_id,
                         per_key_quota, expires_in_days, total) -> int:
    """落 SQLite，返回 batch_id。不做后端调用。"""
    pool_user_id = _resolve_pool_user_id(client, cfg)   # 启动时缓存
    batch_id = store.create_keypool_batch(
        name=name, pool_user_id=pool_user_id, group_id=group_id,
        per_key_quota=per_key_quota, expires_in_days=expires_in_days,
        total=total, notes="")
    for seq in range(1, total + 1):
        store.insert_keypool_batch_key(batch_id=batch_id, seq=seq)
    store.log(action="keypool.create",
              payload={"batch_id": batch_id, "total": total})
    return batch_id


def process_keypool_batch(batch_id, *, client, store, cfg) -> None:
    """后台线程：登录 keypool，逐条创建 N 个 key，写回 plaintext。"""
    batch = store.get_keypool_batch(batch_id)
    store.update_keypool_batch_status(batch_id, "generating")

    try:
        login = client.login_user_password(
            email=cfg.keypool.email, password=cfg.keypool.password)
        jwt = login["access_token"]
    except Exception as e:
        store.update_keypool_batch_status(batch_id, "failed")
        store.log(action="keypool.login", result=str(e))
        # 把所有 pending 行标 failed
        for row in store.list_keypool_batch_keys(batch_id):
            if row["status"] == "pending":
                store.update_keypool_batch_key_failure(
                    batch_id=batch_id, seq=row["seq"],
                    error=f"login failed: {e}")
        return

    succeeded = failed = 0
    for row in store.list_keypool_batch_keys(batch_id):
        if row["status"] != "pending":
            continue
        key_name = f"{batch['name']} #{row['seq']:04d}"
        try:
            payload = client.create_user_api_key(
                jwt=jwt, name=key_name,
                group_id=batch["group_id"],
                quota=float(batch["per_key_quota"]),
                expires_in_days=batch["expires_in_days"],
            )
            store.update_keypool_batch_key_success(
                batch_id=batch_id, seq=row["seq"],
                api_key_id=int(payload["id"]),
                api_key_plain=payload["key"],
                created_at=str(payload.get("created_at") or ""))
            succeeded += 1
        except Exception as e:
            store.update_keypool_batch_key_failure(
                batch_id=batch_id, seq=row["seq"], error=str(e))
            failed += 1

    final = "done" if failed == 0 else ("failed" if succeeded == 0 else "partial")
    store.update_keypool_batch_status(batch_id, final)
    store.log(action="keypool.done",
              payload={"batch_id": batch_id, "ok": succeeded, "fail": failed})


def fetch_batch_stats(client, store, batch_id) -> dict:
    """详情页实时查询：返回 {claimed, total, total_quota, used_quota}."""
    rows = store.list_keypool_batch_keys(batch_id)
    batch = store.get_keypool_batch(batch_id)
    created_ids = [int(r["api_key_id"]) for r in rows
                   if r["status"] == "created" and r["api_key_id"]]
    if not created_ids:
        return {"claimed": 0, "total": batch["total"],
                "total_quota": 0.0, "used_quota": 0.0}

    # 还在 pool 名下的 id 集合
    in_pool: set[int] = set()
    page = 1
    while True:
        data = client.list_user_api_keys(
            int(batch["pool_user_id"]), page=page, page_size=200)
        items = data.get("items") or []
        in_pool.update(int(k["id"]) for k in items)
        total = int(data.get("total") or
                    data.get("pagination", {}).get("total") or 0)
        if page * 200 >= total or not items:
            break
        page += 1

    claimed = sum(1 for kid in created_ids if kid not in in_pool)

    # 用量汇总（不区分 owner，使用 api-keys-usage 端点）
    usage = client.batch_api_keys_usage(created_ids)
    stats = usage.get("stats") or {}
    total_quota = float(batch["per_key_quota"]) * len(created_ids)
    used_quota = sum(float(v.get("total_cost") or v.get("quota_used") or 0)
                     for v in stats.values())
    return {"claimed": claimed, "total": batch["total"],
            "total_quota": total_quota, "used_quota": used_quota}
```

> ⚠ `batch_api_keys_usage` 返回的字段名要在第一次跑通时确认（`total_cost` vs `quota_used` vs `usage`）。如果该端点拿不到 `quota_used`，改成对每个 id 单查 `GET /api/v1/admin/users/.../api-keys` 拼一下；当前 plan 先按主路径写。**实施时第一件事：手测一个真实 key 看 `POST /admin/dashboard/api-keys-usage` 的响应字段。**

### 4. views/keypool.py（新增 blueprint）

```python
bp = Blueprint("keypool", __name__, url_prefix="/keypool")

@bp.route("/")                                    # 列表页
@bp.route("/new", methods=["GET", "POST"])        # 表单：name/total/quota/group/expires
@bp.route("/<int:batch_id>")                      # 详情：keys + 实时 stats
```

POST `/keypool/new` 校验后调 `submit_keypool_batch`，再 `run_in_background(process_keypool_batch, ...)`，flash + 重定向到详情。重用 [batches.py:60-66](../../projects/sub2api-ops/views/batches.py#L60-L66) 的 `run_in_background` 模式。

### 5. 模板设计

**templates/keypool/new.html**（参考 [batches/new.html](../../projects/sub2api-ops/templates/batches/new.html)）：

```
[ 批次名     ] (例如 "2026-05 群发-A")
[ 数量       ] (1-200)
[ 单 key 余额 ] USD  (0 = 无限)
[ 所属分组    ] dropdown ← GET /admin/groups 拉，可选「不绑」
[ 有效期      ] 天数（留空 = 永久）
[ 提交 ]
```

**templates/keypool/detail.html**（核心）：

```
顶部卡片 4 列：
  批次名 | 状态(badge) | 已生成/计划 | 创建时间
中部 stats 卡（动态加载或服务端渲染都可，先服务端）：
  「被领取」 X / N 进度条
  「已用余额」 $used / $total 进度条

工具栏：
  [全部复制为 txt] [仅复制成功的 key（一行一个）] [刷新 stats]

key 列表（表格）：
  seq | 名字 | 状态 | api_key_id | 明文 key + [复制] | 错误
```

复制实现：用 `navigator.clipboard.writeText(...)`，包一个小 JS：
```html
<button class="btn btn-sm btn-outline-secondary"
        onclick="navigator.clipboard.writeText(this.dataset.k)
                 .then(()=>this.textContent='已复制')"
        data-k="{{ row.api_key_plain }}">复制</button>
```

「全部复制」：把所有成功 key 拼成 `\n` 分隔字符串，用同样的 API。

### 6. 配置（config.yaml 新增段）

```yaml
keypool:
  email: keypool@atai8.cc
  password: <REDACTED>          # 用户私下填
  pool_user_id: 0               # 0 = 启动时按 email 懒查；非 0 = 直接用
```

`config.py` 增 `@dataclass class KeypoolConfig`，串到 `AppConfig`。`config.example.yaml` 同步占位。

### 7. 安全注意

- `config.yaml` 已要求 `chmod 600`（README 已写）。
- ops/keypool 表里 `api_key_plain` 是明文但仅本机访问；`/keypool/<batch_id>` 走 `@login_required`。
- 日志里**绝不**打印明文 key。`ops.store.log()` 调用处只传 `batch_id`/计数，不传 key 字符串。
- `password` 在 `op_log` payload 里也不能出现：`process_keypool_batch` 登录失败时 `result=str(e)` 可能漏密码？httpx 异常一般不带 body；但保险点把 `client.login_user_password` 包一层，自己捕异常并改写 message。

## 验证步骤

1. **client 单测先行**（手测）：
   ```bash
   uv run python -c "
   from config import load_config
   from sub2api_client import Sub2ApiClient
   cfg = load_config()
   c = Sub2ApiClient(cfg.sub2api.base_url, cfg.sub2api.admin_api_key)
   tok = c.login_user_password(email='keypool@atai8.cc', password='...')
   print('access_token len:', len(tok['access_token']))
   k = c.create_user_api_key(jwt=tok['access_token'], name='test', quota=1.0)
   print('key:', k['key'][:8] + '...', 'id:', k['id'])
   print(c.batch_api_keys_usage([k['id']]))
   "
   ```
   确认 `batch_api_keys_usage` 的字段名后再回填 `fetch_batch_stats`。

2. **跑应用**：`uv run python app.py` → 浏览器打开 → 登录 → 导航看到「Key 池」。

3. **端到端**：新建一个 `total=3, per_key_quota=1.0` 的批次，确认：
   - 详情页 3 个 key 都成功生成、明文可复制；
   - 「被领取 0/3」、「已用余额 $0/$3」；
   - 在 sub2api 前端用领取页拿走 1 个 key，回 ops 详情页刷新，「被领取」变 1/3；
   - 让那个被领走的 key 跑一点真实请求消耗配额，刷新页面「已用余额」非 0。

4. **失败路径**：把 `keypool.password` 故意改错，新建批次后所有行 `failed`；改回正确后**不**重试（当前 plan 不做重试，先观察够不够用）。

5. **数据落库检查**：`sqlite3 data/ops.db 'SELECT * FROM keypool_batches; SELECT seq, status, length(api_key_plain) FROM keypool_batch_keys;'`

## 不做的事

- 不做单 key 重试 / 失败重生（一批要么过要么留下 failed 行手动处理；够用再说）。
- 不做 key 撤销 / 删除按钮（后端 `DELETE /api/v1/api-keys/:id` 是用户态，要 JWT；以后再说）。
- 不在 ops 端缓存 stats（每次进详情页都拉 sub2api，按用户决定）。
- 不改 sub2api 后端代码。
- 不做 Turnstile bypass（如果遇到强制 Turnstile 部署，再补一次性人工 token 输入框）。
