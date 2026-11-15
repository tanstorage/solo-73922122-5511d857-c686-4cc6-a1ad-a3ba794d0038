"""撤销授权：永久生效、在途拦截、历史可查、跨连接可见。"""
from __future__ import annotations

import threading

import pytest


async def _post(env, raw, lab="LAB-001"):
    return await env["client"].post(
        "/v1/ingest", content=raw, headers={"X-Lab-ID": lab}
    )


async def test_revoke_blocks_new_ingest_but_keeps_history(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    assert (await _post(env, raw)).status_code == 201

    r = await env["client"].post(
        "/v1/admin/labs/LAB-001/revoke",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert r.status_code == 200 and r.json()["revoked"] is True

    r2 = await _post(env, raw)
    assert r2.status_code == 403
    assert r2.json()["error"]["code"] == "LAB_REVOKED"

    q = await env["client"].get("/v1/reports/RPT-1")
    assert q.status_code == 200
    assert q.json()["report_no"] == "RPT-1"

    r3 = await env["client"].post(
        "/v1/admin/labs/LAB-001/revoke",
        headers={"X-Admin-Token": "test-admin-token"},
    )
    assert r3.status_code == 200
    assert (await _post(env, raw)).status_code == 403


async def test_revoke_requires_admin_token(app_env):
    env = app_env
    r = await env["client"].post("/v1/admin/labs/LAB-001/revoke")
    assert r.status_code == 401
    r = await env["client"].post(
        "/v1/admin/labs/LAB-001/revoke", headers={"X-Admin-Token": "wrong"}
    )
    assert r.status_code == 401


async def test_revoke_unknown_lab_404(app_env):
    env = app_env
    r = await env["client"].post(
        "/v1/admin/labs/NOPE/revoke", headers={"X-Admin-Token": "test-admin-token"}
    )
    assert r.status_code == 404


async def test_revoke_fail_closed_when_token_unset(app_env, monkeypatch):
    env = app_env
    cfg = env["modules"]["config"]
    monkeypatch.setattr(cfg, "ADMIN_TOKEN", "")
    # 未配置令牌：即使不带或随便带令牌也必须拒绝
    r = await env["client"].post("/v1/admin/labs/LAB-001/revoke")
    assert r.status_code == 401
    r = await env["client"].post(
        "/v1/admin/labs/LAB-001/revoke", headers={"X-Admin-Token": "anything"}
    )
    assert r.status_code == 401
    # 授权状态未被改变
    labs = (await env["client"].get("/v1/labs")).json()["items"]
    assert all(x["revoked"] == 0 for x in labs)


async def test_inflight_revocation_blocks_commit(app_env, monkeypatch):
    """验签已通过、尚未提交时另一线程撤销授权：提交事务内复检必须拦截。"""
    env = app_env
    main = env["modules"]["main"]
    security = env["modules"]["security"]
    db = env["modules"]["db"]
    RejectError = security.RejectError

    raw = env["sign"](env["build"]())
    cert_pem = db.get_lab_cert(db.get_conn(), "LAB-001")["cert_pem"]
    report = security.verify_report(raw, cert_pem)  # 先完成验签

    release = threading.Event()

    def revoke_during_ingest():
        release.wait(timeout=5)
        with db.write_tx() as tx:
            assert db.revoke_lab(tx, "LAB-001") is True

    t = threading.Thread(target=revoke_during_ingest)
    t.start()

    real_commit = main._commit_ingest

    def patched(rep, rw, digest):
        release.set()
        import time
        time.sleep(0.2)  # 让撤销线程先拿到写锁并提交
        return real_commit(rep, rw, digest)

    monkeypatch.setattr(main, "_commit_ingest", patched)
    # 事务内复检到撤销 -> 回滚并抛出 RejectError（HTTP 层由异常处理器转为 403）
    with pytest.raises(RejectError) as exc_info:
        main._commit_ingest(report, raw, security.sha256_hex(raw))
    t.join()
    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "LAB_REVOKED"

    conn = db.get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 0
    assert conn.execute("SELECT COUNT(*) c FROM measurements").fetchone()["c"] == 0
    assert conn.execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"] == 0


async def test_revocation_visible_across_connections(app_env):
    """模拟双实例：另一个全新连接也必须立刻看到撤销状态（WAL + 即时事务）。"""
    env = app_env
    import sqlite3
    db = env["modules"]["db"]
    cfg = env["modules"]["config"]
    other = sqlite3.connect(str(cfg.DB_PATH), isolation_level=None)
    other.execute("PRAGMA busy_timeout=10000")
    assert other.execute(
        "SELECT revoked FROM labs WHERE lab_id='LAB-001'"
    ).fetchone()[0] == 0

    assert (await env["client"].post(
        "/v1/admin/labs/LAB-001/revoke",
        headers={"X-Admin-Token": "test-admin-token"},
    )).status_code == 200

    assert other.execute(
        "SELECT revoked FROM labs WHERE lab_id='LAB-001'"
    ).fetchone()[0] == 1
    other.close()
