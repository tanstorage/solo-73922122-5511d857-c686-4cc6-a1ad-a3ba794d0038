#!/usr/bin/env python3
"""端到端演示：对本地运行的两个实例执行 合法入仓 -> 重试复用 -> 篡改/攻击拒收 ->
撤销授权 -> 撤销后拒收 -> 历史可查 的完整流程。

前提: 已运行 generate_certs.py、sign_report.py。
用法:
  python examples/demo_client.py                 # 默认 127.0.0.1:8001 / :8002
  python examples/demo_client.py --a 8003 --b 8004
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "dev-admin-token"


def show(title: str, resp: httpx.Response) -> None:
    print(f"\n== {title} [{resp.status_code}] ==")
    print(resp.json())


def main() -> int:
    ap = argparse.ArgumentParser(description="入仓服务端到端演示")
    ap.add_argument("--a", type=int, default=8001, help="实例 A 端口")
    ap.add_argument("--b", type=int, default=8002, help="实例 B 端口")
    args = ap.parse_args()
    base_a = f"http://127.0.0.1:{args.a}"
    base_b = f"http://127.0.0.1:{args.b}"

    valid = ROOT / "examples" / "out" / "report-valid.xml"
    if not valid.exists():
        print("请先运行: python examples/generate_certs.py && "
              "python examples/sign_report.py LAB-001 RPT-2026-0001 SAMPLE-77 "
              "Pb=0.12 Cd=0.03 --out examples/out/report-valid.xml")
        return 1
    raw = valid.read_bytes()
    headers = {"X-Lab-ID": "LAB-001", "Content-Type": "application/xml"}

    with httpx.Client(timeout=10) as c:
        # 1) 合法报告送实例 A
        show("1. 合法报告 -> 实例 A", c.post(f"{base_a}/v1/ingest", content=raw, headers=headers))
        # 2) 同原文重试送实例 B（幂等复用）
        show("2. 同原文重试 -> 实例 B（应 reused=true）",
             c.post(f"{base_b}/v1/ingest", content=raw, headers=headers))
        # 3) 查询
        show("3. 查询报告", c.get(f"{base_a}/v1/reports/RPT-2026-0001"))
        # 4) 各类攻击样例逐个拒收
        attack_dir = ROOT / "examples" / "out" / "attacks"
        for attack in sorted(attack_dir.glob("*.xml")):
            show(f"4. 攻击样例 {attack.name} -> 应拒收",
                 c.post(f"{base_a}/v1/ingest", content=attack.read_bytes(), headers=headers))
        # 5) 撤销 LAB-001（在实例 B 上操作）
        show("5. 撤销 LAB-001（实例 B）",
             c.post(f"{base_b}/v1/admin/labs/LAB-001/revoke",
                    headers={"X-Admin-Token": TOKEN}))
        # 6) 撤销后再送合法件（实例 A 也必须拒收，证明在途/跨实例生效）
        show("6. 撤销后重送 -> 实例 A 应拒收",
             c.post(f"{base_a}/v1/ingest", content=raw, headers=headers))
        # 7) 历史报告仍可查
        show("7. 撤销后历史报告仍可查", c.get(f"{base_b}/v1/reports/RPT-2026-0001"))
        # 8) 授权状态
        show("8. 实验室状态", c.get(f"{base_a}/v1/labs"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
