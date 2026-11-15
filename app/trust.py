"""实验室本地信任库：certs/<实验室号>.pem -> DB 登记。"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from . import config, db


def cert_fingerprint(cert: x509.Certificate) -> str:
    return "sha256:" + cert.fingerprint(hashes.SHA256()).hex()


def load_local_certs() -> dict[str, str]:
    """扫描证书目录，返回 {lab_id: pem}。文件名（去 .pem）即实验室号。"""
    out: dict[str, str] = {}
    if not config.CERT_DIR.exists():
        return out
    for path in sorted(config.CERT_DIR.glob("*.pem")):
        lab_id = path.stem.strip()
        if not lab_id:
            continue
        pem = path.read_text(encoding="ascii")
        # 提前校验证书可解析且为 RSA，避免坏证书进入信任库
        cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        if not isinstance(cert.public_key(), rsa.RSAPublicKey):
            raise RuntimeError(f"{path.name} 不是 RSA 证书，本系统仅接受 RSA-SHA256")
        out[lab_id] = pem
    return out


def sync_labs() -> list[str]:
    """启动时把本地证书登记到 DB（撤销状态永久保留，刷新证书不会解除撤销）。"""
    registered: list[str] = []
    with db.write_tx() as tx:
        for lab_id, pem in load_local_certs().items():
            cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
            db.upsert_lab(tx, lab_id, pem, cert_fingerprint(cert))
            registered.append(lab_id)
    return registered
