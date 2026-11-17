# 越权检测平台 (IDOR Detector)

多租户系统上线前的自动化越权检测:用高权限账号把业务操作录一遍,平台自动用
**低权限账号**和**其他租户账号**重放每个请求,并把请求里的对象编号换成受害方的再试,
通过响应比对判断是否存在越权(IDOR / 水平越权 / 垂直越权)。

```
idor-target/    靶场 (Quarkus, :8081) —— 故意埋了 4 处越权的多租户 Demo
idor-detector/  检测平台 (Quarkus, :8082) —— 录制 / 重放 / 比对 / 报告 + Web UI
```

## 快速开始

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21   # 任意 JDK 21+
export PATH=$HOME/tools/apache-maven-3.9.11/bin:$PATH

# 构建并启动(两个终端,或用 ./run.sh 一把起)
cd idor-target   && mvn package -DskipTests && java -jar target/quarkus-app/quarkus-run.jar &
cd idor-detector && mvn package -DskipTests && java -jar target/quarkus-app/quarkus-run.jar &
```

打开 http://localhost:8082 → 「扫描与报告」→ **一键灌入演示数据** → **开始扫描**。

演示数据 = 指向靶场的 3 个账号 + 用高权限账号录制的 12 条业务请求。
扫描结果应检出靶场全部 4 处埋点,安全接口零误报(仅 1 条需人工复核的疑似)。

## 检测原理

```
                 ┌────────────────────────────────────────────┐
                 │  录制:高权限账号的业务请求 (POST/HAR 导入)   │
                 └──────────────────┬─────────────────────────┘
                                    ▼
   第 1 步  归属池收集:三个账号分别重放所有 GET,
            从响应里收集各自"可见的对象编号/标识"(对象ID、tenantId、邮箱…)
            · 全量池 —— 所有 GET 的响应(用于认识全部对象编号)
            · 自身池 —— 仅"请求里不含对象编号"的 GET(列表/自查接口),
              避免越权端点把别人的数据污染进"自己的"池
                                    ▼
   第 2 步  对每条录制请求做三类测试:
            a) 垂直重放   —— 同租户低权限账号原样重放
            b) 跨租户重放 —— 其他租户账号原样重放
            c) ID 替换    —— 把路径/query/body 里的对象编号换成
                            受害方池里同类型(同前缀)的编号再重放;
                            同时用高权限账号打一条"替换后基线"作参照
                                    ▼
   第 3 步  逐条判定(见下),按接口(METHOD + 路径模板)归组出报告
```

### 判定规则

| 条件 | 判定 |
|---|---|
| 401 / 403 / 404 | `SAFE_DENIED` 访问被拒 |
| 2xx 但响应为空(`[]`/`{}`) | `SAFE_EMPTY` 只返回了空数据 |
| 响应含受害方标识(别的池里的对象编号/租户标识),或 ID 替换后仍返回该编号的数据 | **`VULNERABLE`** |
| 与基线相似度 ≥ 阈值,但响应标识全部落在该账号自身可见范围 | `SAFE_DIFFERENT` 是ta自己的数据 |
| 与基线相似度 ≥ 阈值 且无法归因(垂直重放) | `SUSPICIOUS` 需人工确认权限矩阵 |
| 与基线相似度 ≥ 阈值 且无法归因(跨租户/ID替换) | **`VULNERABLE`** |
| 相似度 0.5 ~ 阈值 | `SUSPICIOUS` |
| 相似度 < 0.5 | `SAFE_DIFFERENT` |

### 相似度阈值怎么定的(默认 0.8)

- 比对前先做**归一化**:JSON 键排序、剔除易变字段(时间戳、请求ID 等);
- 相似度 = 归一化后 **JSON 叶子「键=值」对** 的 Dice 系数
  (只比数据内容,不比 JSON 结构 —— 否则"同结构的各人自己的数据"会虚高);
- **≥ 0.8** 视为"拿到了与基线实质相同的数据"。实测:同一对象被越权读出时
  相似度是 1.0,各看各的数据时通常 < 0.4,0.8 留了充足余量;
- **0.5 ~ 0.8** 灰色地带一律转人工,不自动放行;
- 阈值可在扫描时按接口现场调整(`similarityThreshold` 参数 / UI 输入框)。

## 靶场埋点清单(idor-target)

| # | 接口 | 问题 |
|---|---|---|
| 1 | `GET /api/orders/{id}` | 未校验订单归属,任意登录用户可读任意租户订单 |
| 2 | `PUT /api/orders/{id}/status` | 写操作 IDOR,可改其他租户订单状态 |
| 3 | `GET /api/invoices?ownerId=` | ownerId 未校验,可遍历任意用户发票 |
| 4 | `GET /api/users/{id}` | 泄露任意租户用户资料(含手机/邮箱) |
| — | `GET /api/orders`、`/api/documents/{id}`、`/api/invoices/{id}`、`/api/profile` | 正确鉴权(对照组) |
| — | `GET /api/audit-logs?userId=` | 静默过滤型:永远只返回自己的日志 |
| — | `GET /api/invoices/{id}/payments` | 静默空数据型:跨租户返回 `[]` |

靶场账号:`token-admin-a`(租户A管理员)/ `token-user-a`(租户A普通)/ `token-user-b`(租户B)。

## 平台 API(idor-detector)

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET/POST/DELETE` | `/api/accounts` | 测试账号管理(凭证放请求头) |
| `GET/POST/DELETE` | `/api/recordings` | 录制请求管理 |
| `POST` | `/api/recordings/har` | 导入浏览器/抓包工具导出的 HAR |
| `POST` | `/api/scan` | 发起扫描 `{baselineAccount, lowPrivAccount, crossTenantAccount, similarityThreshold}` |
| `GET` | `/api/scans`、`/api/scans/{id}` | 历史扫描 |
| `GET` | `/api/report/latest` | 最近一次扫描按接口归组的报告 |
| `POST` | `/api/demo/seed` | 一键灌入指向本地靶场的演示数据 |

## 接入真实系统

1. `POST /api/accounts` 注册三个账号:高权限、同租户低权限、其他租户账号
   (凭证放在 `headers` 里,如 `{"Authorization": "Bearer ..."}`);
2. 用高权限账号正常点一遍业务,把请求录进来:
   浏览器/抓包工具导出 HAR 后 `POST /api/recordings/har`,
   或逐条 `POST /api/recordings`(认证头会被自动忽略,重放时按账号替换);
3. `POST /api/scan`,然后打开 UI 看按接口归组的报告。

## 已知边界

- 垂直越权(低权限能不能看本租户数据)没有权限矩阵就无法纯自动判定,
  平台把它归为 `SUSPICIOUS` 交人工,而不是武断报越权;
- 写操作会真实重放(这正是目的),请在测试环境跑;
- 归属池靠录制的 GET 请求收集,录制覆盖越全,受害方标识库越准;
- 状态目前存内存,重启即清空。
