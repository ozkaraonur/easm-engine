from html import escape

from easm.core.models import SEVERITY_ORDER, ScanResult
from easm.reporting.remediation import remediation_for
from easm.reporting.summary import assets, summarize

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--ink:#1c2430;--mute:#66707e;--line:#e2e6ec;
--critical:#c62828;--high:#e65100;--medium:#f9a825;--low:#0277bd;--info:#78909c;--none:#2e7d32}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px}
h1{margin:0 0 4px}h2{margin:32px 0 12px;font-size:1.15rem}
.mute{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:16px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.stat b{display:block;font-size:1.8rem}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;color:#fff;
font-size:.75rem;font-weight:700;text-transform:uppercase}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}
.badge.medium{background:var(--medium);color:#222}.badge.low{background:var(--low)}
.badge.info{background:var(--info)}.badge.none{background:var(--none)}
a{color:#1565c0}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);
vertical-align:top;word-break:break-word}
th{background:#eef1f5;font-size:.8rem;text-transform:uppercase;color:var(--mute)}
code{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:.9em}
.finding{border-left:5px solid var(--info)}
.finding.critical{border-color:var(--critical)}.finding.high{border-color:var(--high)}
.finding.medium{border-color:var(--medium)}.finding.low{border-color:var(--low)}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b222b;--ink:#e6eaf0;
--mute:#93a0b0;--line:#2b3542}a{color:#64b5f6}th,code{background:#252e3a}}
"""


def _badge(severity: str) -> str:
    return f'<span class="badge {escape(severity)}">{escape(severity)}</span>'


def render_html(result: ScanResult) -> str:
    """Render a scan as one self-contained HTML page (embedded CSS, no external assets)."""
    s = summarize(result)
    stats = [
        ("Subdomains", s.subdomains),
        ("Active", s.active_subdomains),
        ("Web services", s.services),
        ("Findings", s.total_findings),
    ]
    body = [
        f"<h1>EASM Report: {escape(s.domain)}</h1>",
        (
            f'<div class="mute">Scan started {escape(s.started_at)}, duration '
            f"{s.duration_seconds}s</div>"
        ),
        "<h2>Executive Summary</h2>",
        f'<div class="card">Overall risk: {_badge(s.risk)}</div>',
        '<div class="grid">',
        *(
            f'<div class="card stat"><b>{v}</b><span class="mute">{k}</span></div>'
            for k, v in stats
        ),
        "</div>",
        '<div class="grid">',
        *(
            f'<div class="card stat"><b>{s.severity_counts[n]}</b>{_badge(n)}</div>'
            for n in SEVERITY_ORDER
        ),
        "</div>",
        "<h2>Discovered Assets</h2>",
        (
            "<table><tr><th>Host</th><th>Active</th><th>IPs</th><th>Open ports</th>"
            "<th>Web services</th></tr>"
        ),
    ]
    for h in assets(result):
        state = {True: "yes", False: "no", None: "-"}[h.is_active]
        urls = "<br>".join(escape(sv.url) for sv in h.services) or "-"
        body.append(
            f"<tr><td>{escape(h.name)}</td><td>{state}</td>"
            f"<td>{escape(', '.join(h.ips) or '-')}</td>"
            f"<td>{', '.join(map(str, h.open_ports)) or '-'}</td><td>{urls}</td></tr>"
        )
    body += ["</table>", "<h2>Findings</h2>"]
    if not result.findings:
        body.append('<div class="card">No exposures were found.</div>')
    for f in result.findings:
        body.append(
            f'<div class="card finding {escape(f.severity)}">{_badge(f.severity)} '
            f"<strong>{escape(f.check)}</strong>"
            f'<div><a href="{escape(f.url)}" rel="noopener noreferrer">{escape(f.url)}</a> '
            f'<span class="mute">{f"HTTP {f.status_code}" if f.status_code else "TCP"}</span></div>'
            f"<p><b>Evidence:</b> <code>{escape(f.evidence)}</code></p>"
            f"<p><b>Remediation:</b> {escape(remediation_for(f.check))}</p></div>"
        )
    if result.errors:
        body += [
            "<h2>Errors</h2>",
            *(f'<div class="card">{escape(e)}</div>' for e in result.errors),
        ]
    return (
        '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>EASM Report: {escape(s.domain)}</title><style>{CSS}</style></head>"
        f"<body><main>{''.join(body)}</main></body></html>\n"
    )
