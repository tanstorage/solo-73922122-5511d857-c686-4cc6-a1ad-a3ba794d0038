"""运行期配置：全部可通过环境变量覆盖。"""
from __future__ import annotations

import os
from pathlib import Path

# 单件 XML 上限：256 KiB（262144 字节）
MAX_BODY_BYTES = int(os.environ.get("MAX_BODY_BYTES", 256 * 1024))

BASE_DIR = Path(os.environ.get("APP_BASE_DIR", Path(__file__).resolve().parent.parent))
# 本地配置的实验室证书目录（信任根），文件名形如 <实验室号>.pem
CERT_DIR = Path(os.environ.get("CERT_DIR", BASE_DIR / "certs"))
# SQLite 数据文件（两个实例共享同一文件 + 命名卷）
DB_PATH = Path(os.environ.get("DB_PATH", BASE_DIR / "data" / "warehouse.db"))
# 管理接口令牌；为空则管理接口仅限本机回环访问
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
# 写事务抢锁的等待参数（毫秒）与重试次数
BUSY_TIMEOUT_MS = int(os.environ.get("BUSY_TIMEOUT_MS", 10_000))
WRITE_RETRIES = int(os.environ.get("WRITE_RETRIES", 20))

# 业务 XML 命名空间
NS = "https://lab.example.com/report/1"
NSMAP = {"lr": NS, "ds": "http://www.w3.org/2000/09/xmldsig#"}

DS_NS = "http://www.w3.org/2000/09/xmldsig#"
ENVELOPED_SIG_URI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
C14N_INCLUSIVE_10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_EXCLUSIVE_10 = "http://www.w3.org/2001/10/xml-exc-c14n#"
C14N_11 = "http://www.w3.org/2006/12/xml-c14n11"
RSA_SHA256_SIG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
SHA256_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256"
ALLOWED_C14N = frozenset({C14N_INCLUSIVE_10, C14N_EXCLUSIVE_10, C14N_11})
