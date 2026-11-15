"""XML 安全解析与 enveloped RSA-SHA256 验签。

信任原则：
1. 验签证书只来自本地配置（DB 中由 certs/ 目录登记），签名自带 KeyInfo 证书一律不参与信任决策。
2. 业务数据只从 signxml 返回的 signed_xml（由已验摘要的规范化负载重建）提取，
   文档中任何未签名的同名元素都不可能进入结果。
3. 重复 XML ID、外部引用、XPointer、多份报告/多个签名一律拒收。
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

from cryptography import x509
from lxml import etree
from signxml import (
    DigestAlgorithm,
    InvalidCertificate,
    InvalidInput,
    InvalidSignature,
    SignatureConfiguration,
    SignatureMethod,
    XMLVerifier,
)
from signxml.exceptions import InvalidDigest

from . import config

DS = config.DS_NS


class RejectError(Exception):
    """业务可预期的拒收，携带 HTTP 状态码与错误码。"""

    def __init__(self, status_code: int, code: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SignedReport:
    report_no: str
    lab_id: str
    sample_no: str
    measurements: list[tuple[str, str]]
    signed_root: etree._Element


# 关闭一切外部资源加载的安全解析器
_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    dtd_validation=False,
    huge_tree=False,
    collect_ids=False,  # 自行检测重复 ID，不依赖解析器 ID 表
    remove_comments=False,
)


def _qn(local: str) -> str:
    return f"{{{config.NS}}}{local}"


def parse_hardened(raw: bytes) -> etree._Element:
    """解析并执行结构层拒收检查，全部在验签之前完成。"""
    if not raw or raw[0:1] != b"<":
        raise RejectError(400, "NOT_XML", "请求体不是 XML 文档")
    try:
        tree = etree.fromstring(raw, parser=_PARSER)
    except etree.XMLSyntaxError as exc:
        raise RejectError(400, "XML_PARSE_ERROR", f"XML 解析失败: {exc.msg}") from exc

    # 1) 禁 DOCTYPE / 实体（解析器已不加载 DTD，这里再显式拦截声明）
    for prolog in tree.itersiblings(preceding=True):
        if isinstance(prolog, etree._Element) and prolog.tag == etree.DTD:
            raise RejectError(400, "DOCTYPE_FORBIDDEN", "禁止携带 DTD/DOCTYPE")
    if tree.getroottree().docinfo.doctype:
        raise RejectError(400, "DOCTYPE_FORBIDDEN", "禁止携带 DTD/DOCTYPE")
    if tree.xpath("//comment()"):
        raise RejectError(400, "COMMENT_FORBIDDEN", "文档不得包含 XML 注释")

    # 2) 重复 XML ID：Id/id/xml:id 等属性值在全文档内必须唯一
    seen_ids: dict[str, str] = {}
    for el in tree.iter():
        for attr_name, attr_val in el.attrib.items():
            local = etree.QName(attr_name).localname if "}" in attr_name else attr_name
            if local in ("Id", "id"):
                if attr_val in seen_ids:
                    raise RejectError(
                        400,
                        "DUPLICATE_ID",
                        f"重复 XML ID: {attr_val}",
                    )
                seen_ids[attr_val] = etree.QName(el).localname

    # 3) 根元素必须是业务报告
    if tree.tag != _qn("Report"):
        raise RejectError(400, "UNEXPECTED_ROOT", "根元素必须是 lr:Report")

    # 4) 文档内有且仅有一份报告（根元素已是 Report；检查内部不得再嵌套 Report）
    nested_reports = tree.findall(f".//{_qn('Report')}")
    if nested_reports:
        raise RejectError(400, "MULTIPLE_REPORTS", "文档必须只包含一份报告")

    # 5) 有且仅有一个 ds:Signature，且必须是 enveloped（位于 Report 内部）
    sigs = tree.findall(f".//{{{DS}}}Signature")
    if len(sigs) != 1:
        raise RejectError(400, "SIGNATURE_COUNT", "文档必须包含且仅包含一个签名")
    if sigs[0].getparent() is not tree:
        raise RejectError(400, "NOT_ENVELOPED", "签名必须是 Report 的直接子元素（enveloped）")

    # 6) 签名结构白名单检查（算法、变换、引用）
    _check_signature_structure(sigs[0], seen_ids)
    return tree


def _check_signature_structure(sig: etree._Element, seen_ids: dict[str, str]) -> None:
    def find(path: str):
        node = sig.find(path, namespaces=config.NSMAP)
        if node is None:
            raise RejectError(400, "SIGNATURE_STRUCTURE", f"签名缺少 {path}")
        return node

    signed_info = find("ds:SignedInfo")

    sig_method = find("ds:SignedInfo/ds:SignatureMethod")
    if sig_method.get("Algorithm") != config.RSA_SHA256_SIG:
        raise RejectError(400, "ALGORITHM_FORBIDDEN", "仅接受 RSA-SHA256 签名算法")

    c14n_method = find("ds:SignedInfo/ds:CanonicalizationMethod")
    if c14n_method.get("Algorithm") not in config.ALLOWED_C14N:
        raise RejectError(400, "ALGORITHM_FORBIDDEN", "不允许的规范化算法")

    refs = signed_info.findall("ds:Reference", namespaces=config.NSMAP)
    if len(refs) != 1:
        raise RejectError(400, "REFERENCE_COUNT", "签名必须恰好包含一个 Reference")
    ref = refs[0]
    digest_method = ref.find("ds:DigestMethod", namespaces=config.NSMAP)
    if digest_method is None:
        raise RejectError(400, "SIGNATURE_STRUCTURE", "Reference 缺少 DigestMethod")
    if digest_method.get("Algorithm") != config.SHA256_DIGEST:
        raise RejectError(400, "ALGORITHM_FORBIDDEN", "摘要算法必须为 SHA256")

    uri = ref.get("URI") or ""
    if not uri.startswith("#") or uri.startswith("#xpointer"):
        raise RejectError(400, "EXTERNAL_REFERENCE", "仅允许同文档 #id 片段引用，禁止外部引用/XPointer")
    target_id = uri[1:]
    if target_id not in seen_ids:
        raise RejectError(400, "BROKEN_REFERENCE", f"引用的 ID 不存在: {target_id}")

    transforms = ref.find("ds:Transforms", namespaces=config.NSMAP)
    if transforms is None:
        raise RejectError(400, "SIGNATURE_STRUCTURE", "Reference 缺少 Transforms")
    algos = [t.get("Algorithm") for t in transforms.findall("ds:Transform", namespaces=config.NSMAP)]
    # 必须包含 enveloped transform；其余只允许标准 C14N；禁止 XSLT/XPath 等可执行变换
    if config.ENVELOPED_SIG_URI not in algos:
        raise RejectError(400, "NOT_ENVELOPED", "Reference 必须使用 enveloped-signature 变换")
    for algo in algos:
        if algo != config.ENVELOPED_SIG_URI and algo not in config.ALLOWED_C14N:
            raise RejectError(400, "TRANSFORM_FORBIDDEN", f"禁止的 Transform: {algo}")


def verify_report(raw: bytes, trusted_cert_pem: str) -> SignedReport:
    """用本地证书验签并只从已签负载提取业务数据。"""
    tree = parse_hardened(raw)
    target_id = (
        tree.find(".//ds:Signature/ds:SignedInfo/ds:Reference", namespaces=config.NSMAP)
        .get("URI")[1:]
    )

    cfg = SignatureConfiguration(
        require_x509=True,
        location=".//",
        expect_references=1,
        signature_methods=frozenset({SignatureMethod.RSA_SHA256}),
        digest_algorithms=frozenset({DigestAlgorithm.SHA256}),
    )

    def deny_external(uri: str):
        # 正常情况下外部 URI 在结构检查阶段已被拒，这里做纵深防御
        raise RejectError(400, "EXTERNAL_REFERENCE", f"禁止外部引用: {uri}")

    try:
        cert = x509.load_pem_x509_certificate(trusted_cert_pem.encode("ascii"))
        result = XMLVerifier().verify(
            tree,
            x509_cert=cert,  # 给定本地证书后，signxml 不会信任文件内嵌证书
            expect_config=cfg,
            id_attribute="Id",
            uri_resolver=deny_external,
            validate_schema=True,
        )
    except RejectError:
        raise
    except InvalidDigest as exc:
        raise RejectError(400, "DIGEST_MISMATCH", "摘要不一致：报告内容与签名不匹配（疑似被篡改）") from exc
    except InvalidSignature as exc:
        raise RejectError(400, "BAD_SIGNATURE", f"签名验签失败: {exc}") from exc
    except InvalidCertificate as exc:
        raise RejectError(400, "CERT_INVALID", f"本地验签证书无效: {exc}") from exc
    except InvalidInput as exc:
        raise RejectError(400, "SIGNATURE_STRUCTURE", f"签名结构不合法: {exc}") from exc
    except Exception as exc:  # 验签库的其它异常统一按拒收处理
        raise RejectError(400, "VERIFY_FAILED", f"验签失败: {exc}") from exc

    # 签名必须覆盖完整 Report 根元素
    if result.signed_xml is None or result.signed_xml.tag != _qn("Report"):
        raise RejectError(400, "SIGNATURE_SCOPE", "签名必须覆盖完整 Report 元素")
    if result.signed_xml.get("Id") != target_id:
        raise RejectError(400, "SIGNATURE_SCOPE", "签名引用未指向报告根元素")

    return _extract(result.signed_xml)


def _extract(signed_root: etree._Element) -> SignedReport:
    """只遍历已验签的报告子树，缺字段/空值/非法字符均拒收。"""

    def text_of(local: str, *, required: bool = True) -> str:
        node = signed_root.find(_qn(local))
        if node is None or node.text is None or not node.text.strip():
            if required:
                raise RejectError(400, "FIELD_MISSING", f"已签报告缺少必填字段: {local}")
            return ""
        return node.text.strip()

    report_no = text_of("ReportNo")
    lab_id = text_of("LabId")
    sample_no = text_of("SampleNo")

    meas_nodes = signed_root.findall(_qn("Measurement"))
    if not meas_nodes:
        raise RejectError(400, "FIELD_MISSING", "报告至少需要一个 Measurement")
    measurements: list[tuple[str, str]] = []
    seen_analytes: set[str] = set()
    for node in meas_nodes:
        analyte_el = node.find(_qn("Analyte"))
        value_el = node.find(_qn("Value"))
        if analyte_el is None or analyte_el.text is None or not analyte_el.text.strip():
            raise RejectError(400, "FIELD_MISSING", "Measurement 缺少 Analyte")
        if value_el is None or value_el.text is None or not value_el.text.strip():
            raise RejectError(400, "FIELD_MISSING", "Measurement 缺少 Value")
        analyte = analyte_el.text.strip()
        value = value_el.text.strip()
        if analyte in seen_analytes:
            raise RejectError(400, "DUPLICATE_ANALYTE", f"重复检测项目: {analyte}")
        seen_analytes.add(analyte)
        # 数值字段须为有限十进制数（拒绝 NaN / Infinity / 科学写法以外的非法值）
        try:
            numeric = float(value)
        except ValueError as exc:
            raise RejectError(400, "BAD_VALUE", f"测值不是数值: {analyte}={value}") from exc
        if not math.isfinite(numeric):
            raise RejectError(400, "BAD_VALUE", f"测值必须为有限数值: {analyte}={value}")
        measurements.append((analyte, value))

    return SignedReport(
        report_no=report_no,
        lab_id=lab_id,
        sample_no=sample_no,
        measurements=measurements,
        signed_root=signed_root,
    )


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
