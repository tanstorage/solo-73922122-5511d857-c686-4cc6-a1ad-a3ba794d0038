#!/usr/bin/env python3
"""生成两个合作实验室的 RSA 密钥与自签证书（仅用于本地演示/测试）。

输出：
  examples/keys/LAB-001.key.pem, LAB-001.cert.pem
  examples/keys/LAB-002.key.pem, LAB-002.cert.pem
  certs/LAB-001.pem, certs/LAB-002.pem   （本地信任库，服务只信任这里）
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent.parent
KEY_DIR = ROOT / "examples" / "keys"
CERT_DIR = ROOT / "certs"

LABS = ["LAB-001", "LAB-002"]


def make_lab(lab_id: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, lab_id),
         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Partner Lab")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        # signxml 的证书有效性策略要求数字签名型终端证书具备 Key Usage
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    KEY_DIR.mkdir(parents=True, exist_ok=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key_path = KEY_DIR / f"{lab_id}.key.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    (KEY_DIR / f"{lab_id}.cert.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    # 信任库里只放证书，永远不放私钥
    (CERT_DIR / f"{lab_id}.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    print(f"[ok] {lab_id}: {key_path.relative_to(ROOT)} + certs/{lab_id}.pem")


def main() -> int:
    for lab_id in LABS:
        make_lab(lab_id)
    print(f"\n本地信任库目录: {CERT_DIR}")
    print("服务启动时会把 certs/*.pem 登记为可信实验室（私钥仅保存在 examples/keys/）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
