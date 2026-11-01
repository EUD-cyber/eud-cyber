"""Read-only report projections shared by HTML and server-generated PDF exports.

No HTML renderer, browser, network requests, or report writes are involved.
ReportLab is imported lazily so JSON/HTML remain available without PDF support.
"""
from html import escape
from io import BytesIO
import json
import os
import re

from reports import PHASE_GUIDANCE, PHASE_ORDER, mitre_url, redact_environment

VIEWS = {"investigation": "Investigation View", "ground-truth": "Ground Truth View"}


def safe_report(report):
    """Defence in depth for historical structured and free-form credentials.

    Omit credential containers and wordlists entirely. Key/value credentials,
    authorization headers, CLI arguments and URL userinfo are also scrubbed.
    Unlabelled arbitrary text cannot reliably be identified as a credential;
    capture must never record secrets in the first place.
    """
    def clean(value):
        if isinstance(value, dict):
            return {str(k): clean(v) for k, v in value.items()
                    if str(k) == "credential_method" or not re.search(r"passw|passwd|secret|token|credential|wordlist|candidate|contents|authorization|api.?key|private.?key", str(k), re.I)}
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, str):
            value = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=._~-]+", "[REDACTED]", value)
            value = re.sub(r'''(?ix)\b[\w-]*(?:password|passwd|secret|token|credential|api[_-]?key|wordlist[_-]?(?:contents|entries))[\w-]*["']?\s*(?:=|:)\s*(?:"[^"]*"|'[^']*'|[^\r\n,;]+)''', "[REDACTED]", value)
            value = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED]", value, flags=re.S)
            # Remove control characters invalid in XML/HTML while preserving lines.
            return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
        return value
    return clean(redact_environment(report, os.environ))


def array(value):
    return value if isinstance(value, list) else []


def obj(value):
    return value if isinstance(value, dict) else {}


def text(value):
    if value is None or value == "":
        return "Unavailable"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def report_document(report, view="investigation"):
    """Return text-only blocks plus validated MITRE URLs, never host HTML."""
    if view not in VIEWS:
        raise ValueError("Unknown report view")
    report = safe_report(report)
    incident = obj(report.get("incident"))
    phases = [p for p in array(report.get("phases")) if isinstance(p, dict)]
    phases.sort(key=lambda p: (PHASE_ORDER.index(p.get("id")) if p.get("id") in PHASE_ORDER else len(PHASE_ORDER)))
    full = view == "ground-truth"
    blocks = []
    def add(kind, content, url=None):
        blocks.append((kind, text(content), url))
    def heading(title):
        add("h2", title)
    def dump(value):
        # One paragraph per JSON line allows long appendices to split across pages.
        for line in json.dumps(value, ensure_ascii=False, indent=2).splitlines():
            add("code", line)
    report_type = ("Standalone phase " + text(report.get("phase_id"))) if report.get("report_type") == "standalone_phase" else "Full Incident"
    add("h1", "MrNobody Incident Report")
    add("p", incident.get("id"))
    add("p", f"{report_type} | {VIEWS[view]}")
    heading("Incident overview")
    execution = obj(report.get("execution"))
    timing_profile = obj(execution.get("profile"))
    for label, value in [("Scenario", incident.get("scenario_name") or incident.get("scenario")),
                         ("Scenario ID", incident.get("scenario")),
                         ("Execution profile", timing_profile.get("mode", "normal")),
                         ("Target duration (seconds)", timing_profile.get("duration", 0)),
                         ("Status", incident.get("status")),
                         ("Start", incident.get("started")), ("End", incident.get("ended"))]:
        add("p", f"{label}: {text(value)}")
    add("p", "Recorded phase status describes the run, not proof that every action succeeded. Missing evidence is not proof of an unaffected asset.")
    heading("Summary metrics")
    summary = obj(report.get("summary"))
    for key, label in [("hosts", "Hosts discovered"), ("compromised", "Compromised hosts"),
                       ("exfiltration", "Exfiltration transfers recorded"), ("impact", "Impacted hosts")]:
        add("p", f"{label}: {text(summary.get(key))}")
    heading("Attack timeline")
    for phase in phases:
        add("p", f"{text(phase.get('id'))} - {text(phase.get('name'))} | {text(phase.get('status'))} | {text(phase.get('started'))} to {text(phase.get('ended'))}")
    if not phases:
        add("p", "No phase records available.")
    heading("MITRE ATT&CK summary")
    add("p", "Mappings describe phase metadata, not proof that every technique executed or succeeded.")
    techniques = {}
    for entry in array(report.get("mitre_summary")) + [t for p in phases for t in array(obj(p.get("mitre")).get("techniques"))]:
        entry = entry if isinstance(entry, dict) else {"id": entry}
        tid = entry.get("id")
        url = mitre_url(tid) if isinstance(tid, str) else None
        if url:
            techniques[tid] = (entry, url)
    for tid, (entry, url) in sorted(techniques.items()):
        add("link", f"{tid} - {text(entry.get('name'))}", url)
    if not techniques:
        add("p", "No technique mappings recorded.")
    heading("Affected assets")
    evidence = obj(report.get("evidence"))
    inventory = obj(report.get("inventory") or evidence.get("inventory"))
    add("p", "Discovered inventory is an investigation starting point; determine affected assets by correlating logs.")
    for host in array(inventory.get("hosts")):
        if isinstance(host, dict):
            add("p", f"Host: {text(host.get('ip') or host.get('host'))} | Hostname: {text(host.get('hostname'))}")
    if not array(inventory.get("hosts")):
        add("p", "No recorded inventory available.")
    if full:
        add("h3", "Actual compromised hosts")
        dump(report.get("compromised_hosts") or evidence.get("compromised") or "Unavailable")
    heading("Phase-by-phase analysis")
    recommendations = []
    for phase in phases:
        add("h3", f"{text(phase.get('id'))} - {text(phase.get('name'))}")
        add("p", f"Phase status: {text(phase.get('status'))}")
        analysis = obj(phase.get("analysis"))
        add("p", analysis.get("what_happened") if full else "Establish source, target, method and outcome from independent host and network evidence.")
        add("h3", "Findings")
        for finding in (array(analysis.get("findings")) if full else ["Compare host and network evidence before concluding which actions succeeded."]):
            add("p", finding)
        fallback = PHASE_GUIDANCE.get(phase.get("id"), ("Correlate host and network logs.", "Validate each outcome independently.", "Apply least privilege, segmentation and monitoring."))
        for index, (key, label) in enumerate([("detection", "Detection guidance"), ("investigation_tasks", "Investigation tasks / questions"), ("prevention", "Prevention / Mitigation")]):
            add("h3", label)
            for item in array(analysis.get(key)) or [fallback[index]]:
                add("p", item)
                if key == "prevention" and item not in recommendations:
                    recommendations.append(item)
        add("p", analysis.get("guidance_notice") or "Educational recommendations, not evidence that a sensor detected or a control prevented this activity.")
        for entry in array(obj(phase.get("mitre")).get("techniques")):
            tid = entry.get("id") if isinstance(entry, dict) else entry
            if isinstance(tid, str) and mitre_url(tid):
                add("link", tid, mitre_url(tid))
    heading("Recommendations")
    for item in recommendations or ["Review evidence coverage, apply least privilege and test recovery procedures."]:
        add("p", item)
    if full:
        add("break", "")
        heading("Technical evidence / ground-truth appendix")
        add("p", "Recorded evidence and exact outcomes, with credentials and wordlist material omitted. Missing fields mean unavailable evidence.")
        for phase in phases:
            add("h3", f"Phase {text(phase.get('id'))}: events, outcomes and evidence references")
            dump({key: phase.get(key, "Unavailable") for key in ("started", "ended", "outcomes", "events")})
            dump(obj(phase.get("analysis")).get("evidence", []))
        for key in ("inventory", "compromised_hosts", "evidence", "events", "sources", "campaign"):
            add("h3", key)
            dump(report.get(key, "Unavailable"))
    else:
        heading("Ground-truth appendix")
        add("p", "Choose Ground Truth View and export again to include recorded answers, exact action outcomes and technical evidence.")
    if array(report.get("warnings")):
        heading("Evidence availability")
        for warning in report["warnings"]:
            add("p", warning)
    return incident, blocks


def export_html(report, view="investigation"):
    incident, blocks = report_document(report, view)
    parts = []
    for kind, content, url in blocks:
        safe = escape(content)
        if kind == "break":
            parts.append('<div class="page-break"></div>')
        elif kind == "link":
            parts.append(f'<p><a href="{escape(url, quote=True)}">{safe}</a></p>')
        elif kind == "code":
            parts.append(f'<div class="evidence">{safe}</div>')
        else:
            parts.append(f'<{kind}>{safe}</{kind}>')
    title = escape(text(incident.get("id")))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident report - {title}</title><style>
body{{font:15px/1.55 system-ui,sans-serif;color:#182b3a;background:#fff;max-width:960px;margin:40px auto;padding:0 28px}}
h1{{font-size:32px;color:#153f60;border-bottom:4px solid #247c9c;padding-bottom:12px}}
h2{{color:#153f60;border-bottom:1px solid #ccd8df;padding:18px 0 8px;break-after:avoid}}
h3{{color:#245b73;break-after:avoid}}p{{overflow-wrap:anywhere}}a{{color:#07598a}}
.evidence{{font:11px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f7;padding:0 8px}}
footer{{margin-top:28px;border-top:1px solid #ccd8df;font-size:11px;color:#456}}
@page{{size:A4;margin:18mm}}@media print{{body{{margin:0;padding:0;font-size:10pt}}.page-break{{break-before:page}}a{{text-decoration:underline}}}}
</style></head><body>{''.join(parts)}<footer>MrNobody Incident Platform | {title} | {VIEWS[view]}</footer></body></html>'''


def export_pdf(report, view="investigation"):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak

    incident, blocks = report_document(report, view)
    output = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Evidence", fontName="Courier", fontSize=7, leading=10,
                              spaceAfter=1, wordWrap="CJK", alignment=TA_LEFT))
    styles["BodyText"].fontSize = 9
    styles["BodyText"].leading = 13
    styles["BodyText"].splitLongWords = True
    for name in ("Title", "Heading2", "Heading3"):
        styles[name].textColor = colors.HexColor("#153f60")
    story = []
    for kind, content, url in blocks:
        if kind == "break":
            story.append(PageBreak())
            continue
        # Chunk individual extreme log lines so a single flowable cannot exhaust a page.
        chunks = [content[i:i + 1800] for i in range(0, len(content), 1800)] or [" "]
        for chunk in chunks:
            markup = escape(chunk).replace("\n", "<br/>")
            if kind == "link":
                markup = f'<a href="{escape(url, quote=True)}" color="#07598a">{markup}</a>'
            style = styles[{"h1": "Title", "h2": "Heading2", "h3": "Heading3", "code": "Evidence"}.get(kind, "BodyText")]
            story.append(Paragraph(markup, style))
    title = text(incident.get("id"))
    def page_footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#ccd8df"))
        canvas.line(42, 38, A4[0] - 42, 38)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(42, 25, "MrNobody Incident Platform | " + VIEWS[view])
        canvas.drawRightString(A4[0] - 42, 25, f"Page {doc.page}")
        canvas.restoreState()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=42, leftMargin=42,
                            topMargin=40, bottomMargin=52, title="Incident report - " + title,
                            author="MrNobody Incident Platform")
    doc.build(story, onFirstPage=page_footer, onLaterPages=page_footer)
    return output.getvalue()
