"""正常入仓、幂等复用、查询与原子性测试。"""
from __future__ import annotations


async def _post(env, raw, lab="LAB-001"):
    return await env["client"].post(
        "/v1/ingest", content=raw,
        headers={"X-Lab-ID": lab, "Content-Type": "application/xml"},
    )


async def test_happy_path_ingest_and_query(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    r = await _post(env, raw)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["report_no"] == "RPT-1"
    assert body["lab_id"] == "LAB-001"
    assert body["measurement_count"] == 2
    assert body["reused"] is False

    q = await env["client"].get("/v1/reports/RPT-1")
    assert q.status_code == 200
    qb = q.json()
    assert qb["sample_no"] == "S-1"
    assert {m["analyte"]: m["value"] for m in qb["measurements"]} == {
        "Pb": "0.12", "Cd": "0.03",
    }
    assert qb["receipt"]["outcome"] == "ACCEPTED"
    assert len(qb["sha256"]) == 64

    lst = (await env["client"].get("/v1/reports")).json()
    assert lst["total"] == 1
    labs = (await env["client"].get("/v1/labs")).json()["items"]
    assert {x["lab_id"] for x in labs} == {"LAB-001", "LAB-002"}
    assert all(x["revoked"] == 0 for x in labs)


async def test_retry_same_bytes_is_idempotent(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    assert (await _post(env, raw)).status_code == 201
    r2 = await _post(env, raw)
    assert r2.status_code == 200
    assert r2.json()["reused"] is True
    conn = env["modules"]["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 1
    assert conn.execute("SELECT COUNT(*) c FROM measurements").fetchone()["c"] == 2
    assert conn.execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"] == 1


async def test_same_report_no_different_content_rejected_and_no_half_report(app_env):
    env = app_env
    raw1 = env["sign"](env["build"](measurements=(("Pb", "0.12"),)))
    assert (await _post(env, raw1)).status_code == 201

    raw2 = env["sign"](env["build"](measurements=(("Pb", "9.99"),)))
    r = await _post(env, raw2)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "REPORT_CONFLICT"

    conn = env["modules"]["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 1
    row = conn.execute("SELECT sha256 FROM reports").fetchone()
    assert row["sha256"] == env["modules"]["security"].sha256_hex(raw1)
    values = [r["value"] for r in conn.execute("SELECT value FROM measurements")]
    assert values == ["0.12"]


async def test_lab_id_header_mismatch_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"](lab_id="LAB-001"), lab_id="LAB-001")
    r = await _post(env, raw, lab="LAB-002")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "BAD_SIGNATURE"


async def test_signed_labid_differs_from_header_rejected(app_env):
    env = app_env
    # 用 LAB-001 私钥合法签名，但报告体内 LabId 写成别的实验室
    raw = env["sign"](env["build"](lab_id="LAB-FORGE"), lab_id="LAB-001")
    r = await _post(env, raw, lab="LAB-001")  # 验签能过，但身份对不上
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "LAB_ID_MISMATCH"
    conn = env["modules"]["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 0


async def test_unknown_and_missing_lab_header(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    r = await env["client"].post("/v1/ingest", content=raw)
    assert r.status_code == 400 and r.json()["error"]["code"] == "LAB_ID_REQUIRED"
    r = await _post(env, raw, lab="LAB-404")
    assert r.status_code == 404 and r.json()["error"]["code"] == "UNKNOWN_LAB"


async def test_size_limit_256kib(app_env):
    env = app_env
    many = [(f"A{i:04d}", "1.0") for i in range(4000)]
    raw = env["sign"](env["build"](measurements=many))
    assert len(raw) > 256 * 1024
    r = await _post(env, raw)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"
    conn = env["modules"]["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 0


async def test_garbage_body_rejected_cleanly(app_env):
    env = app_env
    r = await _post(env, b"this is not xml at all")
    assert r.status_code == 400 and r.json()["error"]["code"] == "NOT_XML"
    r = await _post(env, b"")
    assert r.status_code == 400
    conn = env["modules"]["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 0
    assert conn.execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"] == 0
