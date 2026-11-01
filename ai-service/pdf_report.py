"""ANISAS SOC Evidence & Telemetry PDF Report generator.

Presentation-layer helper: renders the consolidated scan telemetry as a
polished, printable PDF report using ReportLab. Purely additive -- it only
reads the export data dict and returns PDF bytes.
"""

from io import BytesIO

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from xml.sax.saxutils import escape

NAVY = HexColor("#0B1B2A")
NAVY_DEEP = HexColor("#060D18")
CYAN = HexColor("#0891B2")
SLATE = HexColor("#334155")
TEXT_DARK = HexColor("#0F172A")
MUTED = HexColor("#64748B")
PALE_ROW = HexColor("#F1F7FB")
WHITE = colors.white

ACCENTS = {
    "m1": HexColor("#0891B2"),
    "m2": HexColor("#2563EB"),
    "m3": HexColor("#059669"),
    "m4": HexColor("#D97706"),
    "m5": HexColor("#E11D48"),
}


def _safe(value, max_len=None):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    out = []
    for ch in value:
        try:
            ch.encode("cp1252")
            out.append(ch)
        except (UnicodeEncodeError, UnicodeDecodeError):
            out.append("?")
    s = "".join(out)
    if max_len and len(s) > max_len:
        s = s[: max_len] + "..."
    return s


def _P(text, style):
    return Paragraph(escape(_safe(text)), style)


def _d(v, *keys, default="\u2014"):
    cur = v
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _join(values, limit=12):
    if not isinstance(values, (list, tuple)):
        return _safe(values)
    vals = [_safe(x) for x in values if x not in (None, "")]
    if len(vals) > limit:
        vals = vals[:limit] + ["+%d more" % (len(vals) - limit)]
    return ", ".join(vals)


def _score_color(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return CYAN
    if s < 30:
        return HexColor("#059669")
    if s < 60:
        return HexColor("#D97706")
    return HexColor("#DC2626")


PAGE = A4
PAGE_W, PAGE_H = PAGE
MARGIN_X = 36
AVAIL_W = PAGE_W - 2 * MARGIN_X

CTX = {"target": "", "scan_id": "", "ts": ""}


def _styles():
    return {
        "band_title": ParagraphStyle(
            "band_title", fontName="Helvetica-Bold", fontSize=10.5, textColor=WHITE, leading=14, alignment=TA_LEFT
        ),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8, textColor=SLATE, leading=11),
        "value": ParagraphStyle("value", fontName="Courier", fontSize=8.2, textColor=TEXT_DARK, leading=11),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=8.8, textColor=TEXT_DARK, leading=12),
        "cell": ParagraphStyle("cell", fontName="Courier", fontSize=7.6, textColor=TEXT_DARK, leading=10),
        "cell_h": ParagraphStyle(
            "cell_h", fontName="Helvetica-Bold", fontSize=7.4, textColor=WHITE, leading=10
        ),
        "metric_num": ParagraphStyle("metric_num", fontName="Courier-Bold", fontSize=17, textColor=NAVY, leading=20),
        "metric_lbl": ParagraphStyle("metric_lbl", fontName="Helvetica-Bold", fontSize=6.6, textColor=MUTED, leading=9),
    }


def _section_band(tag, num, title, S):
    color = ACCENTS.get(tag, CYAN)
    t = Table(
        [[_P("MODULE %s \u2022 %s" % (num, title), S["band_title"])]],
        colWidths=[AVAIL_W],
    )
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBEFORE", (0, 0), (0, -1), 4, NAVY),
                ("LINEBELOW", (0, -1), (-1, -1), 1, HexColor("#0B1B2A")),
            ]
        )
    )
    return [t, Spacer(1, 6)]


def _kv_table(pairs, S, label_w=160):
    rows = []
    for k, v in pairs:
        if v in (None, ""):
            continue
        rows.append([_P(k, S["label"]), _P(v, S["value"])])
    if not rows:
        return []
    t = Table(rows, colWidths=[label_w, AVAIL_W - label_w])
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, PALE_ROW]),
                ("LINEBELOW", (0, -1), (-1, -1), 0.5, HexColor("#D7E4EC")),
            ]
        )
    )
    return [t, Spacer(1, 8)]


def _data_table(headers, rows, S, color=None):
    if not rows:
        return []
    color = color or CYAN
    col_w = AVAIL_W / max(len(headers), 1)
    data = [[_P(h, S["cell_h"]) for h in headers]]
    for r in rows:
        data.append([_P(c, S["cell"]) for c in r])
    t = Table(data, colWidths=[col_w] * len(headers), repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), color),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE_ROW]),
                ("GRID", (0, 0), (-1, -1), 0.4, HexColor("#C9DAE4")),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return [t, Spacer(1, 8)]


def _bullet(text, S):
    return Paragraph("\u2022  " + escape(_safe(text)), S["body"])


def _bullets(texts, S):
    out = []
    for t in texts:
        out.append(_bullet(t, S))
        out.append(Spacer(1, 2))
    return out


def _exec_summary(data, S):
    ai = _d(data, "aiEngine", "aiDeviceClassifier", default={}) or {}
    risk_score = ai.get("overallRiskScore")
    if risk_score in (None, ""):
        risk_score = _d(data, "aiEvaluation", "risk_score")
    risk_level = ai.get("overallRiskRating") or _d(data, "aiEvaluation", "risk_level")
    iot = data.get("surveillanceIot") or {}
    recon = data.get("networkRecon") or {}
    open_ports = _d(recon, "module03Payload", "openPorts")
    port_count = len(open_ports) if isinstance(open_ports, list) else _safe(_d(recon, "module03Payload", "openPorts"))

    metrics = [
        ("RISK SCORE", _safe(risk_score), _score_color(risk_score)),
        ("RISK LEVEL", _safe(risk_level), _score_color(risk_score)),
        ("IOT ASSETS", _safe(_d(iot, "totalAssetsCount", default=0)), ACCENTS["m4"]),
        ("OPEN PORTS", _safe(port_count), ACCENTS["m2"]),
    ]
    cells = []
    inner_w = (AVAIL_W - 3 * 8) / 4
    for lbl, val, color in metrics:
        inner = Table(
            [[_P(val, S["metric_num"])], [_P(lbl, S["metric_lbl"])]],
            colWidths=[inner_w],
        )
        inner.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("BACKGROUND", (0, 0), (-1, -1), WHITE),
                    ("LINEBEFORE", (0, 0), (0, -1), 3, color),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("LINEABOVE", (0, 0), (-1, 0), 0.5, HexColor("#E2ECF2")),
                    ("LINEBELOW", (0, -1), (-1, -1), 0.5, HexColor("#E2ECF2")),
                ]
            )
        )
        cells.append(inner)
    row = Table([cells], colWidths=[inner_w] * 4)
    row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 8)]))
    return [row, Spacer(1, 10)]


def _section_m01(data, S):
    asn = data.get("asn") or {}
    t = _d(data, "threatIntel")
    prefixes = _d(asn, "prefixes", default=[])
    pairs = [
        ("AS Number", _d(asn, "asnNumber")),
        ("AS Name", _d(asn, "asnName")),
        ("Organization", _d(asn, "organization") or _d(asn, "org")),
        ("Country / Registry", "%s / %s" % (_safe(_d(asn, "countryCode")), _safe(_d(asn, "registry")))),
        ("CIDR / Subnet", _d(asn, "cidr") or _d(asn, "subnetCidr")),
        ("Description", _d(asn, "description")),
        ("Threat Score", _d(t, "abuseScore") or _d(data, "module02Payload", "threatScore")),
        ("Threat Risk", _d(t, "riskLevel") or _d(data, "module02Payload", "riskLevel")),
        ("Primary Hostname", _d(data, "module02Payload", "primaryHostName")),
        ("BGP Prefixes", len(prefixes) if isinstance(prefixes, list) else _safe(prefixes)),
        ("Allocation Date", _d(asn, "allocationDate")),
    ]
    return _kv_table(pairs, S)


def _section_m02(data, S):
    recon = data.get("networkRecon") or {}
    hosts = recon.get("hosts") or []
    ports = recon.get("portServices") or []
    rows = []
    for p in ports[:14]:
        rows.append(
            [_safe(p.get("port")), _safe(p.get("serviceName")), _safe(p.get("protocol")), _safe(p.get("status", "OPEN"))]
        )
    pairs = []
    if hosts:
        h = hosts[0]
        pairs = [
            ("Hostname", _safe(h.get("hostname"))),
            ("OS", _safe(h.get("osName"))),
            ("MAC", _safe(h.get("macAddress") or h.get("mac"))),
            ("Status", _safe(h.get("status"))),
        ]
    cert = (recon.get("certificates") or [None])[0] if recon.get("certificates") else None
    cert_pairs = []
    if cert:
        cert_pairs = [
            ("TLS Subject", _safe(cert.get("subject") or cert.get("commonName"))),
            ("TLS Issuer", _safe(cert.get("issuer"))),
            ("Validity", "%s -> %s" % (_safe(cert.get("notBefore")), _safe(cert.get("notAfter")))),
        ]
    pairs = (
        pairs
        + [
            ("Live Hosts", len(hosts)),
            ("DNS Records", len(recon.get("dnsRecords") or [])),
            ("Subdomains", len(recon.get("subdomains") or [])),
            ("Open Ports", _join(_d(recon, "module03Payload", "openPorts"))),
            ("Exposed Services", _join([p.get("serviceName") for p in ports])),
        ]
        + cert_pairs
    )
    return _kv_table(pairs, S) + _data_table(["PORT", "SERVICE", "PROTOCOL", "STATUS"], rows, S, ACCENTS["m2"])


def _section_m03(data, S):
    per = data.get("securityPerimeter") or {}
    fw = per.get("firewall") or {}
    waf = per.get("waf") or {}
    ids = per.get("ids") or {}
    dmz = per.get("dmz") or {}
    posture = per.get("securityPostureScore") or {}
    score = posture.get("overallScore") or posture.get("score") or _d(per, "module04Payload", "postureScore")
    pairs = [
        ("Branch Classification", per.get("branchClassification")),
        ("Asset Classification", per.get("assetClassification")),
        ("Firewall Vendor", _d(fw, "vendor") or _d(per, "module04Payload", "firewallVendor")),
        ("WAF Vendor", _d(waf, "vendor") or _d(per, "module04Payload", "wafVendor")),
        ("WAF Enabled", _d(waf, "enabled", default="N/A")),
        ("IDS / IPS Engine", _d(ids, "engine") or _d(ids, "vendor")),
        ("DMZ Segment Type", _d(dmz, "segmentType") or _d(per, "module04Payload", "perimeterStatus")),
        ("Security Posture Score", score),
        ("Posture Rating", posture.get("rating")),
        ("Scan Detection Chance", _d(per, "module04Payload", "scanDetectionChance")),
    ]
    recs = []
    for r in (per.get("recommendations") or []):
        if isinstance(r, dict):
            recs.append(" ".join(str(v) for v in r.values() if isinstance(v, str)))
        else:
            recs.append(r)
    return _kv_table(pairs, S) + _bullets(recs, S)


def _section_m04(data, S):
    iot = data.get("surveillanceIot") or {}
    assets = iot.get("discoveredAssets") or []
    default_cred = iot.get("defaultCredentialRisk") or {}
    sources = iot.get("iotDataSources") or []
    subnet = iot.get("subnetScan") or {}
    is_subnet = bool(subnet)
    asset_rows = []
    for a in assets[:14]:
        if is_subnet:
            asset_rows.append(
                [
                    _safe(a.get("ipAddress") or a.get("ip")),
                    _safe(a.get("hardwareVendor")),
                    _safe(a.get("deviceType")),
                    _safe(", ".join(str(p) for p in (a.get("openPorts") or [])[:6])),
                    _safe(a.get("riskLevel") or a.get("riskScore")),
                    _safe(a.get("cveCount")),
                ]
            )
        else:
            asset_rows.append(
                [
                    _safe(a.get("deviceType")),
                    _safe(a.get("hardwareVendor")),
                    _safe(a.get("deviceCategory")),
                    _safe(a.get("deviceTypeConfidence")),
                    _safe(a.get("riskLevel") or a.get("riskScore")),
                ]
            )
    ranges = iot.get("predicted_surveillance_ranges") or []
    range_rows = []
    for r in ranges[:10]:
        range_rows.append(
            [_safe(r.get("vlan")), _safe(r.get("predictedRange") or r.get("range")), "%s%%" % _safe(r.get("probability"))]
        )
    dc_detail = ""
    if default_cred.get("detail"):
        dc_detail = " \u2014 " + _safe(default_cred.get("detail"))
    pairs = [
        ("Device Type", iot.get("deviceType")),
        ("Type Confidence", "%s%%" % _safe(iot.get("deviceTypeConfidence"))),
        ("Hardware Vendor", iot.get("hardwareVendor")),
        ("Vendor Confidence", "%s%%" % _safe(iot.get("hardwareVendorConfidence"))),
        ("Vendor Source", iot.get("vendorSource")),
        ("Detection Method", iot.get("detectionMethod")),
        ("Network Owner", iot.get("networkOwner")),
        ("Cloud Asset", iot.get("isCloudAsset")),
        ("Total IoT Assets", iot.get("totalAssetsCount")),
        ("Intel Data Sources", _join(sources)),
        ("Internet Noise (GreyNoise)", "YES" if iot.get("isInternetNoise") else "No"),
        ("Critical CVE Count", iot.get("criticalCveCount")),
        ("Service CVEs", iot.get("serviceCveCount")),
        ("Total CVEs Available", iot.get("totalCveAvailable")),
        ("Default Credential Risk", _safe(default_cred.get("status")) + dc_detail),
        ("CVE Details", _join(iot.get("cveDetails"), limit=5)),
    ]
    if is_subnet:
        sev = subnet.get("severityBreakdown") or {}
        subnet_pairs = [
            ("Scan Mode", subnet.get("mode")),
            ("CIDR Scope", subnet.get("cidr")),
            ("Total IPs", subnet.get("totalIps")),
            ("Live Hosts", subnet.get("aliveHosts")),
            ("Hosts Swept", subnet.get("scannedHosts")),
            ("IoT Devices", subnet.get("iotHosts")),
            ("Total CVE Matches", subnet.get("totalCveCount")),
            ("Unique CVEs", subnet.get("uniqueCveCount")),
            ("KEV Catalog CVEs", subnet.get("kevCount")),
            ("Severity Breakdown", ", ".join("%s=%s" % (k, v) for k, v in sev.items()) if sev else None),
            ("Scan Duration",
             "%d ms" % subnet.get("scanDurationMs") if isinstance(subnet.get("scanDurationMs"), (int, float)) else None),
            ("Status", subnet.get("status")),
        ]
        pairs = subnet_pairs + pairs
    corr = iot.get("cveCorrelation") or {}
    if corr.get("used"):
        pairs.append(("CVE Correlation", "NVD service-banner correlation (%d CVEs via %s)"
                      % (corr.get("count", 0), ", ".join(corr.get("products") or []))))
    recs = []
    for r in (iot.get("recommendations") or []):
        if isinstance(r, dict):
            recs.append(" ".join(str(v) for v in r.values() if isinstance(v, str)))
        else:
            recs.append(r)
    asset_headers = ["IP ADDRESS", "VENDOR", "DEVICE", "PORTS", "RISK", "CVES"] if is_subnet else \
        ["DEVICE", "VENDOR", "CATEGORY", "CONF.", "RISK"]
    return (
        _kv_table(pairs, S)
        + _data_table(asset_headers, asset_rows, S, ACCENTS["m4"])
        + _data_table(["VLAN SEGMENT", "PREDICTED RANGE", "PROBABILITY"], range_rows, S, ACCENTS["m4"])
        + _bullets(recs, S)
    )


def _section_m05(data, S):
    ai = data.get("aiEngine") or {}
    cls = ai.get("aiDeviceClassifier") or {}
    nl = ai.get("nlReport") or {}
    topo = ai.get("topologyInference") or {}
    pairs = [
        ("Predicted Device Type", cls.get("predictedDeviceType")),
        ("Confidence Score", cls.get("confidenceScore")),
        ("Overall Risk Rating", cls.get("overallRiskRating")),
        ("Overall Risk Score", cls.get("overallRiskScore")),
        ("OS Fingerprint", _safe(ai.get("osFingerprint"))),
        ("Topology Inference", _safe(topo.get("summary") if isinstance(topo, dict) else topo)),
        ("LLM Model", nl.get("llmModelUsed")),
    ]
    out = _kv_table(pairs, S)
    summary = nl.get("executiveSummary")
    if isinstance(summary, str):
        out += _bullets([summary], S)
    elif isinstance(summary, list):
        out += _bullets(summary, S)
    threats = nl.get("keyThreats") or []
    if threats:
        out.append(_P("KEY THREATS", S["label"]))
        out.append(Spacer(1, 2))
        out += _bullets(threats, S)
    plan = nl.get("actionPlan") or []
    if plan:
        out.append(_P("RECOMMENDED ACTION PLAN", S["label"]))
        out.append(Spacer(1, 2))
        out += _bullets(plan, S)
    return out


def _draw_page_bg(canvas, doc):
    canvas.saveState()
    width, height = PAGE
    canvas.setFillColor(CYAN)
    canvas.rect(0, height - 3, width, 3, stroke=0, fill=1)
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, width, 34, stroke=0, fill=1)
    canvas.setStrokeColor(HexColor("#22D3EE"))
    canvas.setLineWidth(1)
    canvas.line(0, 34, width, 34)
    canvas.setFont("Helvetica", 6.4)
    canvas.setFillColor(HexColor("#93A4B4"))
    canvas.drawString(MARGIN_X, 14, "ANISAS CYBER INTELLIGENCE ENGINE \u2022 AUTHORIZED DEFENSIVE ASSESSMENT")
    canvas.drawRightString(width - MARGIN_X, 14, "Page %d" % canvas.getPageNumber())
    canvas.restoreState()


def _draw_cover(canvas):
    canvas.saveState()
    width, height = PAGE
    canvas.setFillColor(NAVY_DEEP)
    canvas.rect(0, height - 132, width, 132, stroke=0, fill=1)
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 128, width, 96, stroke=0, fill=1)
    canvas.setFillColor(CYAN)
    canvas.rect(0, height - 132, width, 3, stroke=0, fill=1)
    canvas.setFillColor(HexColor("#22D3EE"))
    canvas.setFont("Helvetica-Bold", 21)
    canvas.drawString(MARGIN_X, height - 58, "ANISAS CYBER INTELLIGENCE ENGINE")
    canvas.setFont("Helvetica-Bold", 10.5)
    canvas.setFillColor(HexColor("#7DD3FC"))
    canvas.drawString(MARGIN_X, height - 76, "SOC EVIDENCE & TELEMETRY REPORT")
    canvas.setFont("Courier-Bold", 9)
    canvas.setFillColor(WHITE)
    canvas.drawString(MARGIN_X, height - 108, "TARGET:  %s" % _safe(CTX["target"]))
    canvas.drawRightString(width - MARGIN_X, height - 108, "SCAN: %s" % _safe(CTX["scan_id"]))
    canvas.setFont("Courier", 8)
    canvas.setFillColor(HexColor("#9FB6C8"))
    canvas.drawString(MARGIN_X, height - 122, "GENERATED: %s UTC" % _safe(CTX["ts"]))
    canvas.drawRightString(width - MARGIN_X, height - 122, "CLASSIFICATION: RESTRICTED")
    canvas.restoreState()


def build_soc_report_pdf(data) -> bytes:
    """Render the consolidated telemetry dict to a styled PDF and return bytes."""
    data = data or {}
    CTX["target"] = _safe(data.get("targetIp"))
    CTX["scan_id"] = _safe(data.get("scanId"))
    CTX["ts"] = _safe(data.get("createdAt"))

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=PAGE,
        leftMargin=MARGIN_X,
        rightMargin=MARGIN_X,
        topMargin=64,
        bottomMargin=56,
        title="ANISAS SOC Evidence & Telemetry Report",
        author="ANISAS Cyber Intelligence Engine",
    )
    S = _styles()
    story = []

    def first_page(canvas, d):
        _draw_cover(canvas)
        _draw_page_bg(canvas, d)

    def later_pages(canvas, d):
        _draw_page_bg(canvas, d)

    story.append(Spacer(1, 40))
    story.append(KeepTogether(_exec_summary(data, S)))

    sections = []
    if data.get("asn"):
        sections.append(("m1", "01", "ASN & ISP INTELLIGENCE", _section_m01(data, S)))
    if data.get("networkRecon"):
        sections.append(("m2", "02", "NETWORK RECONNAISSANCE", _section_m02(data, S)))
    if data.get("securityPerimeter"):
        sections.append(("m3", "03", "SECURITY PERIMETER DETECTION", _section_m03(data, S)))
    if data.get("surveillanceIot"):
        sections.append(("m4", "04", "SURVEILLANCE & IOT ASSET INTELLIGENCE", _section_m04(data, S)))
    if data.get("aiEngine"):
        sections.append(("m5", "05", "AI RISK ENGINE & DECISION SUPPORT", _section_m05(data, S)))

    for tag, num, title, items in sections:
        story.append(KeepTogether(_section_band(tag, num, title, S) + items))

    doc.build(story, onFirstPage=first_page, onLaterPages=later_pages)
    return buf.getvalue()
