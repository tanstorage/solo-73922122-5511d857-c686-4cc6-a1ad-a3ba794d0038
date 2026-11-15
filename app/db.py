"""SQLite 持久层：WAL 多实例共享、即时事务保证原子提交。"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

from . import config

_local = threading.local()


def _connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(config.DB_PATH),
        timeout=config.BUSY_TIMEOUT_MS / 1000.0,
        isolation_level=None,  # 手动事务
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={config.BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_conn() -> sqlite3.Connection:
    """每线程一个连接（请求处理为同步端点）。"""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


@contextmanager
def write_tx() -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE 立即取写锁；报告头/测值/接收记录同一事务提交。"""
    conn = get_conn()
    last_err: sqlite3.Error | None = None
    for _ in range(config.WRITE_RETRIES):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as exc:  # database is locked
            last_err = exc
    else:
        raise RuntimeError("写锁获取超时") from last_err
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


SCHEMA = """
CREATE TABLE IF NOT EXISTS labs (
    lab_id       TEXT PRIMARY KEY,
    cert_pem     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    revoked_at   TEXT
);
CREATE TABLE IF NOT EXISTS reports (
    report_no    TEXT PRIMARY KEY,
    lab_id       TEXT NOT NULL,
    sample_no    TEXT NOT NULL,
    raw_xml      BLOB NOT NULL,
    sha256       TEXT NOT NULL,
    received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE IF NOT EXISTS measurements (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    report_no    TEXT NOT NULL REFERENCES reports(report_no),
    analyte      TEXT NOT NULL,
    value        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_meas_report ON measurements(report_no);
CREATE TABLE IF NOT EXISTS receipts (
    report_no    TEXT PRIMARY KEY,
    outcome      TEXT NOT NULL,
    detail       TEXT NOT NULL,
    recorded_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)


def is_revoked(conn: sqlite3.Connection, lab_id: str) -> bool:
    row = conn.execute(
        "SELECT revoked FROM labs WHERE lab_id=?", (lab_id,)
    ).fetchone()
    return row is not None and bool(row["revoked"])


def get_lab_cert(conn: sqlite3.Connection, lab_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT lab_id, cert_pem, fingerprint, revoked FROM labs WHERE lab_id=?",
        (lab_id,),
    ).fetchone()


def upsert_lab(conn: sqlite3.Connection, lab_id: str, cert_pem: str, fingerprint: str) -> None:
    """登记/刷新本地证书；已撤销的实验室不会因证书刷新而恢复授权。"""
    conn.execute(
        """
        INSERT INTO labs(lab_id, cert_pem, fingerprint) VALUES(?,?,?)
        ON CONFLICT(lab_id) DO UPDATE SET
            cert_pem=excluded.cert_pem,
            fingerprint=excluded.fingerprint
        """,
        (lab_id, cert_pem, fingerprint),
    )


def revoke_lab(conn: sqlite3.Connection, lab_id: str) -> bool:
    """永久撤销；返回 False 表示实验室不存在。"""
    cur = conn.execute(
        """
        UPDATE labs SET revoked=1,
               revoked_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE lab_id=? AND revoked=0
        """,
        (lab_id,),
    )
    if cur.rowcount == 1:
        return True
    # 已撤销仍视为成功（幂等），不存在则 False
    return conn.execute(
        "SELECT 1 FROM labs WHERE lab_id=?", (lab_id,)
    ).fetchone() is not None


def find_report(conn: sqlite3.Connection, report_no: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM reports WHERE report_no=?", (report_no,)
    ).fetchone()


def insert_report(
    conn: sqlite3.Connection,
    *,
    report_no: str,
    lab_id: str,
    sample_no: str,
    raw_xml: bytes,
    sha256: str,
    measurements: list[tuple[str, str]],
    outcome: str,
    detail: str,
) -> None:
    conn.execute(
        "INSERT INTO reports(report_no, lab_id, sample_no, raw_xml, sha256) VALUES(?,?,?,?,?)",
        (report_no, lab_id, sample_no, raw_xml, sha256),
    )
    conn.executemany(
        "INSERT INTO measurements(report_no, analyte, value) VALUES(?,?,?)",
        [(report_no, a, v) for a, v in measurements],
    )
    conn.execute(
        "INSERT INTO receipts(report_no, outcome, detail) VALUES(?,?,?)",
        (report_no, outcome, detail),
    )
# 说明：receipts 与报告/测值在同一事务内写入，保证“原文、测值和接收结果一起生效”。
# 验签失败、格式非法等拒收路径整体回滚，不产生任何半份报告或残留接收记录。
