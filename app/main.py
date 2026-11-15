"""签章 XML 入仓 API（FastAPI）。

端点：
  POST /v1/ingest                     验签并原子入仓（X-Lab-ID 指定本地信任证书）
  GET  /v1/reports/{report_no}        查询已入仓报告及测值（撤销后仍可查）
  GET  /v1/reports                    报告列表
  POST /v1/admin/labs/{lab_id}/revoke 永久撤销实验室授权
  GET  /v1/labs                       实验室授权状态
  GET  /healthz                       存活探针
  GET  /docs                          Swagger UI

并发模型：业务端点为同步函数，FastAPI 在线程池中执行；每个工作线程持有独立的
SQLite 连接（线程局部），写事务使用 BEGIN IMMEDIATE，双实例共享同一 WAL 数据库文件。
"""
from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from . import config, db, security, trust
from .security import RejectError


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    registered = trust.sync_labs()
    app.state.registered_labs = registered
    yield


app = FastAPI(
    title="签章检验报告入仓 API",
    version="1.0.0",
    description="仅接受 enveloped RSA-SHA256 签名的检验报告 XML，本地证书验签后原子入仓。",
    lifespan=lifespan,
)


# ---------------- 中间件：256 KiB 硬限制（按实际字节累计，不信赖 Content-Length） ----------------
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        total = 0
        chunks: list[bytes] = []
        async for chunk in request.stream():
            total += len(chunk)
            if total > config.MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": f"请求体超过 {config.MAX_BODY_BYTES} 字节上限",
                            "limit_bytes": config.MAX_BODY_BYTES,
                            "received_bytes": total,
                        }
                    },
                )
            chunks.append(chunk)
        body = b"".join(chunks)
        # 预填 Starlette 请求体缓存，下游 request.body() 直接复用，不再触碰 receive
        request._body = body
    return await call_next(request)


async def read_body(request: Request) -> bytes:
    """异步依赖：中间件已完成限长，这里取出完整请求体交给同步端点。"""
    return await request.body()


@app.exception_handler(RejectError)
async def reject_handler(_: Request, exc: RejectError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


# ---------------- 业务端点（同步，运行于线程池，支持同进程真实并发） ----------------
@app.post("/v1/ingest")
def ingest(request: Request, raw: bytes = Depends(read_body),
           x_lab_id: str | None = Header(default=None)):
    if not x_lab_id or not x_lab_id.strip():
        raise RejectError(400, "LAB_ID_REQUIRED", "必须通过 X-Lab-ID 头指定实验室号")
    lab_hint = x_lab_id.strip()

    if not raw:
        raise RejectError(400, "EMPTY_BODY", "请求体为空")
    if len(raw) > config.MAX_BODY_BYTES:  # 中间件已拦截，纵深防御
        raise RejectError(413, "PAYLOAD_TOO_LARGE", "请求体超过 256 KiB 上限")

    # 结构检查与验签（无数据库写操作，耗时最长的在途阶段）
    report = security.verify_report(raw, _require_cert(lab_hint))

    # 头里的实验室号只用于选择本地证书；身份以已签报告中的 LabId 为准
    if report.lab_id != lab_hint:
        raise RejectError(
            403,
            "LAB_ID_MISMATCH",
            "X-Lab-ID 与已签报告中的 LabId 不一致",
        )

    digest = security.sha256_hex(raw)
    return _commit_ingest(report, raw, digest)


def _require_cert(lab_hint: str) -> str:
    """取本地配置证书；实验室未知或已撤销立即拒收。"""
    conn = db.get_conn()
    row = db.get_lab_cert(conn, lab_hint)
    if row is None:
        raise RejectError(404, "UNKNOWN_LAB", f"未登记的实验室: {lab_hint}")
    if bool(row["revoked"]):
        raise RejectError(403, "LAB_REVOKED", f"实验室授权已撤销: {lab_hint}")
    return row["cert_pem"]


def _commit_ingest(report: security.SignedReport, raw: bytes, digest: str) -> JSONResponse:
    """单事务：撤销复检 + 幂等判定 + 报告/测值/接收结果一起生效。"""
    attempts = config.WRITE_RETRIES
    for attempt in range(attempts):
        try:
            with db.write_tx() as tx:
                # 事务内复检撤销：即使验签期间另一实例撤销了授权，也无法入仓
                if db.is_revoked(tx, report.lab_id):
                    raise RejectError(
                        403, "LAB_REVOKED", f"实验室授权已撤销: {report.lab_id}"
                    )

                existing = db.find_report(tx, report.report_no)
                if existing is not None:
                    if existing["sha256"] == digest:
                        # 同报告号同原文：复用既有接收结果，不重复写入
                        return JSONResponse(
                            status_code=200,
                            content=_receipt(
                                report.report_no, report.lab_id,
                                report.sample_no, len(report.measurements),
                                reused=True,
                            ),
                        )
                    # 同报告号异原文：拒绝，事务回滚，不留半份报告
                    raise RejectError(
                        409,
                        "REPORT_CONFLICT",
                        f"报告号 {report.report_no} 已存在且原文不同，拒绝入仓",
                    )

                db.insert_report(
                    tx,
                    report_no=report.report_no,
                    lab_id=report.lab_id,
                    sample_no=report.sample_no,
                    raw_xml=raw,
                    sha256=digest,
                    measurements=report.measurements,
                    outcome="ACCEPTED",
                    detail="验签通过并入仓",
                )
                return JSONResponse(
                    status_code=201,
                    content=_receipt(
                        report.report_no, report.lab_id,
                        report.sample_no, len(report.measurements),
                        reused=False,
                    ),
                )
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() and attempt < attempts - 1:
                continue  # 写锁竞争：重试整个事务
            raise RejectError(503, "BUSY", "数据库写锁竞争超时，请重试") from exc
    raise RejectError(503, "BUSY", "数据库写锁竞争超时，请重试")


def _receipt(report_no: str, lab_id: str, sample_no: str, n: int, *, reused: bool) -> dict:
    return {
        "report_no": report_no,
        "lab_id": lab_id,
        "sample_no": sample_no,
        "measurement_count": n,
        "outcome": "ACCEPTED",
        "reused": reused,
        "message": "同报告号同原文重试，复用既有接收结果" if reused else "验签通过并入仓",
    }


@app.get("/v1/reports/{report_no}")
def get_report(report_no: str):
    conn = db.get_conn()
    row = db.find_report(conn, report_no)
    if row is None:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": "NOT_FOUND", "message": f"报告不存在: {report_no}"}},
        )
    measurements = [
        {"analyte": r["analyte"], "value": r["value"]}
        for r in conn.execute(
            "SELECT analyte, value FROM measurements WHERE report_no=? ORDER BY id",
            (report_no,),
        )
    ]
    receipt = conn.execute(
        "SELECT outcome, detail, recorded_at FROM receipts WHERE report_no=?",
        (report_no,),
    ).fetchone()
    return {
        "report_no": row["report_no"],
        "lab_id": row["lab_id"],
        "sample_no": row["sample_no"],
        "sha256": row["sha256"],
        "received_at": row["received_at"],
        "measurements": measurements,
        "receipt": dict(receipt) if receipt else None,
    }


@app.get("/v1/reports")
def list_reports(limit: int = 100, offset: int = 0):
    conn = db.get_conn()
    limit = max(1, min(limit, 500))
    rows = conn.execute(
        "SELECT report_no, lab_id, sample_no, received_at FROM reports "
        "ORDER BY received_at LIMIT ? OFFSET ?",
        (limit, max(0, offset)),
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) AS c FROM reports").fetchone()["c"]
    return {"total": total, "items": [dict(r) for r in rows]}


@app.post("/v1/admin/labs/{lab_id}/revoke")
def revoke(lab_id: str, x_admin_token: str | None = Header(default=None)):
    _check_admin(x_admin_token)
    try:
        with db.write_tx() as tx:
            ok = db.revoke_lab(tx, lab_id)
    except sqlite3.OperationalError as exc:
        raise RejectError(503, "BUSY", "数据库写锁竞争超时，请重试") from exc
    if not ok:
        raise RejectError(404, "UNKNOWN_LAB", f"未登记的实验室: {lab_id}")
    return {"lab_id": lab_id, "revoked": True, "message": "授权已永久撤销"}


@app.get("/v1/labs")
def list_labs():
    conn = db.get_conn()
    rows = conn.execute(
        "SELECT lab_id, fingerprint, revoked, revoked_at FROM labs ORDER BY lab_id"
    ).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


def _check_admin(token: str | None) -> None:
    # 未配置管理令牌时管理接口关闭（fail-closed），避免裸奔
    if not config.ADMIN_TOKEN or token != config.ADMIN_TOKEN:
        raise RejectError(401, "UNAUTHORIZED", "管理令牌缺失或错误")
