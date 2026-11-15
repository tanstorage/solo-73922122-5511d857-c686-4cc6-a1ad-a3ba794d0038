#!/usr/bin/env python3
"""构造并用实验室私钥签署检验报告 XML（enveloped RSA-SHA256）。

用法:
  python examples/sign_report.py LAB-001 RPT-2026-0001 SAMPLE-77 \
      "Pb=0.12" "Cd=0.03" --out examples/out/report-valid.xml

生成的文档结构:
  <lr:Report Id="...">
    <lr:ReportNo/> <lr:LabId/> <lr:SampleNo/>
    <lr:Measurement><lr:Analyte/><lr:Value/></lr:Measurement> ...
    <ds:Signature> ... </ds:Signature>   (enveloped, rsa-sha256, sha256)
  </lr:Report>
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from lxml import etree
from signxml import (
    CanonicalizationMethod,
    DigestAlgorithm,
    SignatureConstructionMethod,
    SignatureMethod,
    XMLSigner,
)

ROOT = Path(__file__).resolve().parent.parent
NS = "https://lab.example.com/report/1"
LR = f"{{{NS}}}"


def build_report(lab_id: str, report_no: str, sample_no: str,
                 measurements: list[tuple[str, str]]) -> etree._Element:
    root = etree.Element(
        f"{LR}Report",
        Id=f"report-{report_no}",
        nsmap={"lr": NS},
    )
    for tag, text in (("ReportNo", report_no), ("LabId", lab_id), ("SampleNo", sample_no)):
        el = etree.SubElement(root, f"{LR}{tag}")
        el.text = text
    for analyte, value in measurements:
        m = etree.SubElement(root, f"{LR}Measurement")
        a = etree.SubElement(m, f"{LR}Analyte")
        a.text = analyte
        v = etree.SubElement(m, f"{LR}Value")
        v.text = value
    return root


def sign(root: etree._Element, key_pem: bytes, cert_pem: bytes) -> bytes:
    key = serialization.load_pem_private_key(key_pem, password=None)
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA256,
        digest_algorithm=DigestAlgorithm.SHA256,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    signed = signer.sign(root, key=key, cert=cert_pem.decode("ascii"))
    # 注意：不得使用 pretty_print —— 签名后插入缩进空白会改变已签负载的规范化字节，
    # 导致验签失败（本仓库测试已覆盖该陷阱）。
    return etree.tostring(signed, xml_declaration=True, encoding="UTF-8")


def parse_measurements(items: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for item in items:
        if "=" not in item:
            raise SystemExit(f"测值参数格式应为 项目=数值，收到: {item}")
        analyte, value = item.split("=", 1)
        float(value)  # 校验数值
        out.append((analyte.strip(), value.strip()))
    if not out:
        raise SystemExit("至少提供一个测值，例如 Pb=0.12")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="签署检验报告 XML")
    ap.add_argument("lab_id")
    ap.add_argument("report_no")
    ap.add_argument("sample_no")
    ap.add_argument("measurements", nargs="+", help="形如 Pb=0.12 的测值，可多个")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    key_path = ROOT / "examples" / "keys" / f"{args.lab_id}.key.pem"
    cert_path = ROOT / "examples" / "keys" / f"{args.lab_id}.cert.pem"
    if not key_path.exists():
        raise SystemExit(f"缺少私钥 {key_path}，请先运行 examples/generate_certs.py")

    root = build_report(
        args.lab_id, args.report_no, args.sample_no,
        parse_measurements(args.measurements),
    )
    raw = sign(root, key_path.read_bytes(), cert_path.read_bytes())

    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(raw)
    print(f"[ok] 已生成签章报告: {out} ({len(raw)} 字节)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
