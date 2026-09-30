"""Streamlit dashboard; launched via `easm web`."""

import asyncio

import streamlit as st

from easm.core.config import Settings
from easm.core.models import ScanResult
from easm.core.utils import normalize_domain
from easm.reporting import render_html
from easm.web.demo import DEMO_DOMAIN
from easm.web.logic import (
    ScanOptions,
    finding_rows,
    open_port_count,
    port_rows,
    risk_label,
    risk_score,
    run_scan,
)


def _run(domain: str, options: ScanOptions) -> ScanResult:
    bar = st.progress(0.0, text="Starting")

    def progress(fraction: float, message: str) -> None:
        bar.progress(fraction, text=message)

    result = asyncio.run(run_scan(domain, options, Settings(), progress))
    bar.empty()
    return result


def _render_results(result: ScanResult) -> None:
    score = risk_score(result)
    cols = st.columns(4)
    cols[0].metric("Assets", len(result.subdomains))
    cols[1].metric("Active", result.active_count)
    cols[2].metric("Open ports", open_port_count(result))
    cols[3].metric("Risk score", f"{score}/100", risk_label(score), delta_color="off")

    findings = finding_rows(result)
    if any(f["Severity"] != "INFO" for f in findings):
        st.error("Sensitive file exposure detected!")
    elif findings:
        st.info("Only informational files found (robots.txt / security.txt).")
    else:
        st.success("No sensitive file exposures found.")
    if findings:
        st.dataframe(findings, hide_index=True)

    st.subheader("Open ports and services")
    ports = port_rows(result)
    if ports:
        st.dataframe(ports, hide_index=True)
    else:
        st.caption("No open ports (or port scan not selected).")

    st.subheader("Subdomains")
    st.dataframe(
        [
            {"Subdomain": s.name, "Active": s.is_active, "IPs": ", ".join(s.ips)}
            for s in result.subdomains
        ],
        hide_index=True,
    )
    for err in result.errors:
        st.warning(err)

    st.download_button(
        "HTML Güvenlik Raporu İndir",
        data=render_html(result),
        file_name=f"{result.domain}-easm-report.html",
        mime="text/html",
    )


def main() -> None:
    st.set_page_config(page_title="EASM Engine", page_icon="🛰️", layout="wide")
    st.title("🛰️ EASM Engine")
    st.caption("Only scan assets you own or are explicitly authorized to test.")

    left, right = st.columns([4, 1], vertical_alignment="bottom")
    if right.button("Demo Hedef Yükle"):
        st.session_state["domain"] = DEMO_DOMAIN
    domain_input = left.text_input("Hedef domain", key="domain", placeholder="example.com")

    subs = st.checkbox("Subdomain enumeration", value=True)
    ports = st.checkbox("Port scan", value=True)
    files = st.checkbox("Sensitive file probing", value=True)
    if domain_input == DEMO_DOMAIN:
        st.caption("Offline demo: scans deliberately leaky local servers, no real network scan.")
    if files and not ports:
        st.caption("Sensitive file probing needs web services, so ports are scanned too.")

    if st.button("Taramayı Başlat", type="primary"):
        try:
            domain = normalize_domain(domain_input)
        except ValueError as exc:
            st.error(str(exc))
        else:
            if not (subs or ports or files):
                st.error("Select at least one module.")
            else:
                options = ScanOptions(subdomains=subs, ports=ports, exposures=files)
                st.session_state["result"] = _run(domain, options)

    result = st.session_state.get("result")
    if isinstance(result, ScanResult):
        _render_results(result)


main()
