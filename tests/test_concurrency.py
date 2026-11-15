"""并发测试：启动两个真实 uvicorn 实例（api-a/api-b），共享同一 SQLite 文件。

覆盖：
- 同报告号并发接收：恰好一份 201，其余全部复用，无 5xx/409
- 不同报告号并发接收：全部完整落库
- 接收与撤销并发：每条报告要么完整存在（含测值与接收记录），要么整体拒收
"""
from __future__ import annotations

import importlib
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import SignatureConstructionMethod, XMLSigner

NS = "https://lab.example.com/report/1"
DS = "http://www.w3.org/2000/09/xmldsig#"
ADMIN_TOKEN = "test-admin-token"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def cluster(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cluster")
    import os
    os.environ["APP_BASE_DIR"] = str(tmp)
    os.environ["DB_PATH"] = str(tmp / "data" / "warehouse.db")
    os.environ["CERT_DIR"] = str(tmp / "certs")
    os.environ["ADMIN_TOKEN"] = ADMIN_TOKEN

    import app.config
    import app.db as db_mod
    importlib.reload(app.config)
    importlib.reload(db_mod)
    import app.trust
    importlib.reload(app.trust)
    import app.security
    importlib.reload(app.security)
    import app.main
    importlib.reload(app.main)

    cert_dir = tmp / "certs"
    cert_dir.mkdir()
    key_dir = tmp / "keys"
    key_dir.mkdir()
    keys = {}
    for lab_id in ("LAB-001", "LAB-002"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, lab_id)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        (key_dir / f"{lab_id}.key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        (cert_dir / f"{lab_id}.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        keys[lab_id] = (key, cert)

    db_mod.init_db()
    app.trust.sync_labs()

    def build(lab_id="LAB-001", report_no="RPT-1", sample_no="S-1",
              measurements=(("Pb", "0.12"), ("Cd", "0.03"))):
        root = etree.Element(f"{{{NS}}}Report", Id=f"report-{report_no}",
                             nsmap={"lr": NS})
        for tag, text in (("ReportNo", report_no), ("LabId", lab_id),
                          ("SampleNo", sample_no)):
            el = etree.SubElement(root, f"{{{NS}}}{tag}")
            el.text = text
        for analyte, value in measurements:
            m = etree.SubElement(root, f"{{{NS}}}Measurement")
            etree.SubElement(m, f"{{{NS}}}Analyte").text = analyte
            etree.SubElement(m, f"{{{NS}}}Value").text = value
        return root

    def sign(root, lab_id="LAB-001"):
        key, cert = keys[lab_id]
        signed = XMLSigner(method=SignatureConstructionMethod.enveloped).sign(
            root, key=key,
            cert=cert.public_bytes(serialization.Encoding.PEM).decode(),
        )
        return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")

    # 启动两个独立 uvicorn 实例（独立线程、独立端口、共享 DB 文件）
    servers = []
    ports = []
    for _ in range(2):
        port = _free_port()
        cfg = uvicorn.Config(app.main.app, host="127.0.0.1", port=port,
                             log_level="warning", workers=1)
        server = uvicorn.Server(cfg)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        servers.append(server)
        ports.append(port)

    base_urls = [f"http://127.0.0.1:{p}" for p in ports]
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            if all(httpx.get(f"{u}/healthz", timeout=1).status_code == 200
                   for u in base_urls):
                break
        except httpx.HTTPError:
            time.sleep(0.1)
    else:
        raise RuntimeError("测试实例启动超时")

    yield {
        "base_urls": base_urls,
        "build": build,
        "sign": sign,
        "db": db_mod,
        "headers": {"X-Lab-ID": "LAB-001"},
        "admin_headers": {"X-Admin-Token": ADMIN_TOKEN},
    }

    for server in servers:
        server.should_exit = True


def test_concurrent_same_report_exactly_one_insert(cluster):
    urls = cluster["base_urls"]
    raw = cluster["sign"](cluster["build"]())
    barrier = threading.Barrier(8)

    def send(i):
        barrier.wait()  # 尽量同时发出，制造真实竞争
        with httpx.Client(timeout=30) as c:
            return c.post(f"{urls[i % 2]}/v1/ingest", content=raw,
                          headers=cluster["headers"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(send, range(8)))

    statuses = sorted(r.status_code for r in responses)
    assert statuses.count(201) == 1, statuses
    assert statuses.count(200) == 7, statuses

    conn = cluster["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 1
    assert conn.execute("SELECT COUNT(*) c FROM measurements").fetchone()["c"] == 2
    assert conn.execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"] == 1


def test_concurrent_different_reports_all_persist(cluster):
    urls = cluster["base_urls"]
    raws = {
        f"RPT-{i}": cluster["sign"](cluster["build"](report_no=f"RPT-{i}"))
        for i in range(10)
    }

    def send(item):
        report_no, raw = item
        i = int(report_no.split("-")[1])
        with httpx.Client(timeout=30) as c:
            return c.post(f"{urls[i % 2]}/v1/ingest", content=raw,
                          headers=cluster["headers"])

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(send, raws.items()))
    assert all(r.status_code == 201 for r in responses), [r.text for r in responses]

    conn = cluster["db"].get_conn()
    assert conn.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"] == 10
    assert conn.execute("SELECT COUNT(*) c FROM measurements").fetchone()["c"] == 20


def test_concurrent_revoke_and_ingest_no_inconsistent_state(cluster):
    urls = cluster["base_urls"]

    def ingest(i):
        raw = cluster["sign"](cluster["build"](report_no=f"RPT-C{i}"))
        with httpx.Client(timeout=30) as c:
            return c.post(f"{urls[i % 2]}/v1/ingest", content=raw,
                          headers=cluster["headers"])

    def revoke():
        with httpx.Client(timeout=30) as c:
            return c.post(f"{urls[0]}/v1/admin/labs/LAB-001/revoke",
                          headers=cluster["admin_headers"])

    with ThreadPoolExecutor(max_workers=6) as pool:
        ing_futs = [pool.submit(ingest, i) for i in range(6)]
        rev_fut = pool.submit(revoke)
        ing_responses = [f.result() for f in ing_futs]
        rev = rev_fut.result()

    assert rev.status_code == 200
    for r in ing_responses:
        assert r.status_code in (201, 403), r.text

    conn = cluster["db"].get_conn()
    rows = conn.execute("SELECT report_no FROM reports ORDER BY report_no").fetchall()
    # 每个成功入仓的报告都必须有完整 2 条测值和 1 条接收记录（无半份）
    for row in rows:
        assert conn.execute(
            "SELECT COUNT(*) c FROM measurements WHERE report_no=?",
            (row["report_no"],),
        ).fetchone()["c"] == 2
        assert conn.execute(
            "SELECT COUNT(*) c FROM receipts WHERE report_no=?",
            (row["report_no"],),
        ).fetchone()["c"] == 1

    # 撤销后两个实例都不可再入仓
    raw = cluster["sign"](cluster["build"](report_no="RPT-AFTER"))
    with httpx.Client(timeout=30) as c:
        for url in urls:
            r = c.post(f"{url}/v1/ingest", content=raw, headers=cluster["headers"])
            assert r.status_code == 403 and r.json()["error"]["code"] == "LAB_REVOKED"
