"""验签安全：篡改、未签同名元素、重复 ID、外部引用、多报告、算法白名单等。"""
from __future__ import annotations

import copy
from lxml import etree


async def _post(env, raw, lab="LAB-001"):
    return await env["client"].post(
        "/v1/ingest", content=raw, headers={"X-Lab-ID": lab}
    )


async def test_tampered_value_digest_mismatch(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    tampered = raw.replace(b"0.12", b"9.99", 1)
    r = await _post(env, tampered)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "DIGEST_MISMATCH"


async def test_unsigned_same_name_element_not_mixed_in(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    extra = etree.SubElement(doc, f"{{{env['NS']}}}Measurement")
    etree.SubElement(extra, f"{{{env['NS']}}}Analyte").text = "Hg"
    etree.SubElement(extra, f"{{{env['NS']}}}Value").text = "55.5"
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    # 签名覆盖完整根元素，任何事后追加都导致根摘要失配
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "DIGEST_MISMATCH"


async def test_foreign_lab_resign_rejected(app_env):
    env = app_env
    # LAB-002 私钥重签 LAB-001 的报告；服务端用 LAB-001 本地证书验签
    doc = env["build"](lab_id="LAB-001")
    raw = env["sign"](doc, lab_id="LAB-002")
    r = await _post(env, raw, lab="LAB-001")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "BAD_SIGNATURE"


async def test_embedded_cert_never_trusted(app_env):
    """文件里带的证书与本地信任库不同：仍以本地证书为准，必须拒收。"""
    env = app_env
    raw = env["sign"](env["build"](), lab_id="LAB-002")  # 内含 LAB-002 证书
    # 声明 LAB-001 时服务取 LAB-001 本地证书验签 -> 失败
    r = await _post(env, raw, lab="LAB-001")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "BAD_SIGNATURE"


async def test_duplicate_xml_id_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    doc.find(f"{{{env['NS']}}}Measurement").set("Id", doc.get("Id"))
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "DUPLICATE_ID"


async def test_external_reference_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    ref = doc.find(f".//{{{env['DS']}}}Reference")
    ref.set("URI", "http://attacker.example/evil.xml")
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "EXTERNAL_REFERENCE"


async def test_xpointer_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    ref = doc.find(f".//{{{env['DS']}}}Reference")
    ref.set("URI", "#xpointer(//*[@Id])")
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "EXTERNAL_REFERENCE"


async def test_multiple_reports_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    batch = etree.Element(f"{{{env['NS']}}}Batch",
                          nsmap={"lr": "https://lab.example.com/report/1"})
    batch.append(doc)
    second = etree.fromstring(etree.tostring(doc))
    second.set("Id", "report-second")
    second.find(f"{{{env['NS']}}}ReportNo").text = "RPT-EVIL"
    batch.append(second)
    r = await _post(env, etree.tostring(batch, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] in ("UNEXPECTED_ROOT", "MULTIPLE_REPORTS")


async def test_two_signatures_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    sig = doc.find(f"{{{env['DS']}}}Signature")
    clone = copy.deepcopy(sig)
    doc.append(clone)
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "SIGNATURE_COUNT"


async def test_doctype_and_entity_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    with_dtd = (
        b'<?xml version="1.0" encoding="UTF-8"?>\n'
        b'<!DOCTYPE lr:Report [<!ENTITY x "boom">]>\n' + raw.split(b"?>", 1)[1]
    )
    r = await _post(env, with_dtd)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "DOCTYPE_FORBIDDEN"


async def test_xslt_transform_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    transforms = doc.find(f".//{{{env['DS']}}}Transforms")
    t = etree.SubElement(transforms, f"{{{env['DS']}}}Transform")
    t.set("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116")
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "TRANSFORM_FORBIDDEN"


async def test_non_rsa_signature_algorithm_rejected(app_env):
    env = app_env
    raw = env["sign"](env["build"]())
    doc = etree.fromstring(raw)
    sm = doc.find(f".//{{{env['DS']}}}SignatureMethod")
    sm.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    r = await _post(env, etree.tostring(doc, xml_declaration=True, encoding="UTF-8"))
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "ALGORITHM_FORBIDDEN"


async def test_missing_field_and_bad_value_rejected(app_env):
    env = app_env
    root = env["build"]()
    root.find(f"{{{env['NS']}}}SampleNo").text = "  "
    raw = env["sign"](root)
    r = await _post(env, raw)
    assert r.status_code == 400 and r.json()["error"]["code"] == "FIELD_MISSING"

    root2 = env["build"](measurements=(("Pb", "not-a-number"),))
    r2 = await _post(env, env["sign"](root2))
    assert r2.status_code == 400 and r2.json()["error"]["code"] == "BAD_VALUE"

    root3 = env["build"](measurements=(("Pb", "NaN"),))
    r3 = await _post(env, env["sign"](root3))
    assert r3.status_code == 400 and r3.json()["error"]["code"] == "BAD_VALUE"

    root4 = env["build"](measurements=(("Pb", "Infinity"),))
    r4 = await _post(env, env["sign"](root4))
    assert r4.status_code == 400 and r4.json()["error"]["code"] == "BAD_VALUE"
