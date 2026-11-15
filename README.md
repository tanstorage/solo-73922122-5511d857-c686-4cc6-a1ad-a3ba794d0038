# 签章检验报告入仓 API

数仓侧接收合作实验室提交的 **enveloped XML 数字签名检验报告**，仅在验签通过后把
**可信测值**原子写入 SQLite，并支持实验室授权的永久撤销。

- 技术栈：FastAPI + signxml 5（XML-DSig）+ lxml + SQLite（WAL）
- 签名约束：仅接受 **enveloped、RSA-SHA256、SHA256 摘要** 的 `ds:Signature`
- 信任锚：只使用本地 `certs/<实验室号>.pem` 证书验签，**绝不信任文件自带证书**
- 单件上限：**256 KiB**（按实际字节累计，不信赖 `Content-Length`）
- 部署：Docker Compose 起两个对等实例 `api-a` / `api-b`，共享同一 SQLite 数据库文件

---

## 1. 目录结构

```
app/
  config.py     运行期配置（环境变量可覆盖）
  db.py         SQLite 持久层：WAL、BEGIN IMMEDIATE、原子事务
  security.py   硬化 XML 解析 + 结构白名单 + RSA-SHA256 验签 + 数据提取
  trust.py      本地信任库：certs/*.pem 启动登记
  main.py       FastAPI 端点、256KiB 限长中间件、事务编排
certs/          本地信任锚（每个实验室一个 <lab_id>.pem；不含私钥）
examples/
  generate_certs.py  生成演示用 RSA 密钥/自签证书
  sign_report.py     构造并签署合法报告
  tamper_report.py   构造 6 类篡改/攻击样例
  demo_client.py     双实例端到端演示
tests/          28 个 pytest 用例（含真实双 uvicorn 实例并发测试）
docker-compose.yml / Dockerfile
```

## 2. 报告 XML 格式

```xml
<?xml version="1.0" encoding="UTF-8"?>
<lr:Report xmlns:lr="https://lab.example.com/report/1" Id="report-RPT-1">
  <lr:ReportNo>RPT-1</lr:ReportNo>
  <lr:LabId>LAB-001</lr:LabId>
  <lr:SampleNo>SAMPLE-77</lr:SampleNo>
  <lr:Measurement><lr:Analyte>Pb</lr:Analyte><lr:Value>0.12</lr:Value></lr:Measurement>
  <lr:Measurement><lr:Analyte>Cd</lr:Analyte><lr:Value>0.03</lr:Value></lr:Measurement>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"> … </ds:Signature>
</lr:Report>
```

## 3. 快速开始（Docker Compose）

```bash
# 1) 生成本地信任证书（同时生成 examples/keys 下的演示私钥）
python3 -m pip install -r requirements-dev.txt   # 或先 python3 -m venv .venv
python examples/generate_certs.py

# 2) 起两个实例（8001 / 8002），共享命名卷中的 SQLite
docker compose up --build -d

# 3) 生成并签署合法报告
python examples/sign_report.py LAB-001 RPT-2026-0001 SAMPLE-77 \
    "Pb=0.12" "Cd=0.03" --out examples/out/report-valid.xml

# 4) 入仓（X-Lab-ID 指定用哪个本地证书验签）
curl -s -X POST http://127.0.0.1:8001/v1/ingest \
    -H "X-Lab-ID: LAB-001" --data-binary @examples/out/report-valid.xml

# 5) 交互式文档
open http://127.0.0.1:8001/docs
```

无 Docker 时的本地等价运行（与 compose 同构，两个进程共享 DB 文件）：

```bash
DB_PATH=$PWD/data/warehouse.db CERT_DIR=$PWD/certs ADMIN_TOKEN=dev-admin-token \
    .venv/bin/python -m uvicorn app.main:app --port 8001 &
DB_PATH=$PWD/data/warehouse.db CERT_DIR=$PWD/certs ADMIN_TOKEN=dev-admin-token \
    .venv/bin/python -m uvicorn app.main:app --port 8002 &
python examples/demo_client.py            # 默认连 8001/8002
```

## 4. API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/ingest` | 验签并原子入仓；请求头 `X-Lab-ID` 选择本地信任证书 |
| GET  | `/v1/reports/{report_no}` | 查询报告、测值与接收记录（撤销后仍可查） |
| GET  | `/v1/reports` | 报告列表 |
| POST | `/v1/admin/labs/{lab_id}/revoke` | 永久撤销授权（头 `X-Admin-Token`） |
| GET  | `/v1/labs` | 实验室授权状态与证书指纹 |
| GET  | `/healthz` | 存活探针；`/docs` 为 Swagger UI |

入仓语义：

- 同报告号 + **同原文**（SHA-256 相等）重试：返回 `200` 且 `reused=true`，复用既有接收结果，不重复落库。
- 同报告号 + **异原文**：返回 `409 REPORT_CONFLICT`，事务回滚，旧数据原样保留。
- 任何验签/结构失败：返回 4xx，**不留半份报告、不写残留记录**。

## 5. 安全设计（拒收清单）

| 攻击/违规 | 处理 | 错误码 |
| --- | --- | --- |
| 篡改已签内容（测值、报告号等） | 摘要校验失败拒收 | `DIGEST_MISMATCH` |
| 签名后追加未签同名元素 | 根元素摘要失配拒收；且数据只取自验签重建子树 | `DIGEST_MISMATCH` |
| 用非本地信任的证书/私钥重签 | 本地证书公钥验签失败 | `BAD_SIGNATURE` |
| 非 RSA-SHA256 算法（如 rsa-sha1、HMAC、ECDSA） | 算法白名单拒收 | `ALGORITHM_FORBIDDEN` |
| 外部 `http(s):` 引用、XPointer | 仅允许同文档 `#id`，并注入拒绝型 uri_resolver 兜底 | `EXTERNAL_REFERENCE` |
| 重复 XML Id | 全文档 Id 唯一性预检 + signxml 歧义检测 | `DUPLICATE_ID` |
| 多份报告 / 多个签名 / 非 enveloped | 结构预检拒收 | `MULTIPLE_REPORTS` / `SIGNATURE_COUNT` / `NOT_ENVELOPED` |
| XSLT/XPath 等可执行 Transform | Transform 白名单（仅 enveloped + 标准 C14N） | `TRANSFORM_FORBIDDEN` |
| DOCTYPE / 实体 / 注释 | 禁用 DTD、关闭实体解析与网络 | `DOCTYPE_FORBIDDEN` / `COMMENT_FORBIDDEN` |
| 超大报文 | 流式累计超 256 KiB 立即 413 | `PAYLOAD_TOO_LARGE` |

数据提取只遍历 signxml 返回的 `signed_xml`——它由**通过摘要比对的规范化负载**重建，
文档树中任何未签名节点都不可能混入结果。

## 6. 撤销与并发一致性

- 撤销为**永久单向**：`labs.revoked` 置位后，刷新/重挂证书不会恢复授权；撤销操作幂等。
- **在途拦截**：入仓写事务内复检撤销状态（`BEGIN IMMEDIATE` 取写锁后），
  即使验签期间另一实例完成撤销，该报告也无法提交；已入仓报告的查询不受影响。
- **原子生效**：报告原文、测值、接收结果在同一事务提交，失败整体回滚。
- **双实例共享**：SQLite WAL + `busy_timeout` + 写事务重试，跨连接立即可见已提交状态。

## 7. 自测

```bash
python3 -m pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 28 passed：正常入仓/幂等/冲突、13 项安全拒收、撤销 5 项、真实双实例并发 3 项
```

攻击样例的手工验证：

```bash
python examples/tamper_report.py examples/out/report-valid.xml
for f in examples/out/attacks/*.xml; do
  curl -s -o /dev/null -w "$f -> %{http_code}\n" \
    -X POST http://127.0.0.1:8001/v1/ingest \
    -H "X-Lab-ID: LAB-001" --data-binary @"$f"
done
```

## 8. 配置项（环境变量）

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `MAX_BODY_BYTES` | `262144` | 单件 XML 字节上限 |
| `CERT_DIR` | `./certs` | 本地信任证书目录 |
| `DB_PATH` | `./data/warehouse.db` | SQLite 文件路径（两实例必须相同） |
| `ADMIN_TOKEN` | 空 | 撤销接口令牌；**为空时管理接口 fail-closed 一律 401**，compose 默认下发 `dev-admin-token` |
| `BUSY_TIMEOUT_MS` / `WRITE_RETRIES` | `10000` / `20` | 写锁等待与重试 |
