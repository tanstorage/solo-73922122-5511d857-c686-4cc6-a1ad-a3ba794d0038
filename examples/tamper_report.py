#!/usr/bin/env python3
"""基于一份合法签章报告，构造多种被篡改/越权的变体，用于验证服务拒收行为。

用法:
  python examples/tamper_report.py examples/out/report-valid.xml --outdir examples/out/attacks

产出:
  tampered-value.xml        改动已签的测值（摘要失配）
  unsigned-injection.xml    在签名后追加未签的同名 Measurement（根摘要失配/结构拒收）
  external-reference.xml    Reference URI 改成外部 http 地址（外部引用拒收）
  duplicate-id.xml          制造重复 XML Id（拒收）
  multi-report.xml          放入两份 Report（拒收）
  foreign-signature.xml     用另一个实验室的私钥重签（本地证书验签失败）
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from lxml import etree
from signxml import SignatureConstructionMethod, XMLSigner

ROOT = Path(__file__).resolve().parent.parent
DS = "http://www.w3.org/2000/09/xmldsig#"
LR = "{https://lab.example.com/report/1}"


def write(outdir: Path, name: str, doc: etree._Element) -> Path:
    p = outdir / name
    # 不使用 pretty_print：重排空白会改变已签负载，掩盖各攻击样例本身的语义
    p.write_bytes(
        etree.tostring(doc, xml_declaration=True, encoding="UTF-8")
    )
    print(f"[ok] {p.relative_to(ROOT)}")
    return p


def main() -> int:
    ap = argparse.ArgumentParser(description="构造篡改/攻击 XML 示例")
    ap.add_argument("source", help="合法签章报告路径")
    ap.add_argument("--outdir", default="examples/out/attacks")
    args = ap.parse_args()

    src = Path(args.source)
    if not src.is_absolute():
        src = ROOT / src
    raw = src.read_bytes()
    outdir = Path(args.outdir)
    if not outdir.is_absolute():
        outdir = ROOT / outdir
    outdir.mkdir(parents=True, exist_ok=True)

    # 1) 直接改文本：0.12 -> 9.99
    if b"0.12" in raw:
        p = outdir / "tampered-value.xml"
        p.write_bytes(raw.replace(b"0.12", b"9.99", 1))
        print(f"[ok] {p.relative_to(ROOT)}")

    # 2) 签名后追加未签同名元素
    doc = etree.fromstring(raw)
    extra = etree.SubElement(doc, f"{LR}Measurement")
    etree.SubElement(extra, f"{LR}Analyte").text = "Hg"
    etree.SubElement(extra, f"{LR}Value").text = "55.5"
    write(outdir, "unsigned-injection.xml", doc)

    # 3) 外部引用
    doc = etree.fromstring(raw)
    ref = doc.find(f".//{{{DS}}}Reference")
    ref.set("URI", "http://attacker.example/evil.xml")
    write(outdir, "external-reference.xml", doc)

    # 4) 重复 XML Id
    doc = etree.fromstring(raw)
    doc.find(f"{LR}Measurement").set("Id", doc.get("Id"))
    write(outdir, "duplicate-id.xml", doc)

    # 5) 多份报告
    doc = etree.fromstring(raw)
    batch = etree.Element(f"{LR}Batch", nsmap={"lr": "https://lab.example.com/report/1"})
    batch.append(doc)
    second = etree.fromstring(etree.tostring(doc))
    second.set("Id", "report-second")
    second.find(f"{LR}ReportNo").text = "RPT-EVIL-SECOND"
    batch.append(second)
    write(outdir, "multi-report.xml", batch)

    # 6) 用 LAB-002 的私钥重签 LAB-001 的报告（若存在该私钥）
    foreign_key = ROOT / "examples" / "keys" / "LAB-002.key.pem"
    foreign_cert = ROOT / "examples" / "keys" / "LAB-002.cert.pem"
    if foreign_key.exists():
        doc = etree.fromstring(raw)
        for sig in doc.findall(f"{{{DS}}}Signature"):
            doc.remove(sig)
        key = serialization.load_pem_private_key(foreign_key.read_bytes(), password=None)
        re_signed = XMLSigner(method=SignatureConstructionMethod.enveloped).sign(
            doc, key=key, cert=foreign_cert.read_bytes().decode("ascii")
        )
        write(outdir, "foreign-signature.xml", re_signed)
    else:
        print("[skip] foreign-signature.xml：缺少 LAB-002 私钥，请先运行 generate_certs.py")

    print(f"\n所有攻击样例已写入 {outdir}，可逐个 POST 到 /v1/ingest 观察拒收。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
