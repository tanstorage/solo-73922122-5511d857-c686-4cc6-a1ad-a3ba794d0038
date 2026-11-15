"""pytest 夹具：隔离的临时 DB/证书目录 + ASGI 异步测试客户端 + 签章工具。"""
from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from lxml import etree
from signxml import SignatureConstructionMethod, XMLSigner


@pytest_asyncio.fixture
async def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("APP_BASE_DIR", str(tmp_path))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "data" / "warehouse.db"))
    monkeypatch.setenv("CERT_DIR", str(tmp_path / "certs"))
    monkeypatch.setenv("ADMIN_TOKEN", "test-admin-token")

    import app
    import app.config
    import app.db as db_mod
    old_conn = getattr(db_mod._local, "conn", None)
    if old_conn is not None:
        old_conn.close()
        db_mod._local.conn = None
    importlib.reload(app.config)
    importlib.reload(db_mod)
    import app.trust
    importlib.reload(app.trust)
    import app.security
    importlib.reload(app.security)
    import app.main
    importlib.reload(app.main)
    assert app.trust.db is db_mod and app.main.db is db_mod

    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    def make_lab(lab_id: str):
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
        return key, cert

    keys = {lab: make_lab(lab) for lab in ("LAB-001", "LAB-002")}

    db_mod.init_db()
    registered = app.trust.sync_labs()
    assert set(registered) == {"LAB-001", "LAB-002"}

    NS = "https://lab.example.com/report/1"

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

    # 通过 LifespanManager 触发 FastAPI lifespan（init_db / sync_labs）
    from asgi_lifespan import LifespanManager

    async with LifespanManager(app.main.app) as managed:
        async with AsyncClient(
            transport=ASGITransport(app=managed.app), base_url="http://test"
        ) as client:
            yield {
                "client": client,
                "build": build,
                "sign": sign,
                "keys": keys,
                "tmp": tmp_path,
                "NS": NS,
                "DS": "http://www.w3.org/2000/09/xmldsig#",
                "modules": {
                    "config": app.config, "db": db_mod,
                    "security": app.security, "main": app.main,
                },
            }
