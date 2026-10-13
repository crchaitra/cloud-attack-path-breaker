
import streamlit as st

from main import load_environment, build_graph
from security_report import generate_security_report
from report_export import build_export_report, report_to_json
from cloud_map import show_cloud_map, show_before_after_maps
from remediation_panel import show_remediation_panel
from validated_remediation import (
    find_validated_multi_edge_remediation,
)
from misconfiguration_checks import check_misconfigurations


st.set_page_config(
    page_title="Cloud Attack-Path Breaker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Cloud Attack-Path Breaker")

st.write(
    "Find dangerous routes through a cloud environment "
    "and identify potentially risky resource configurations."
)

st.info(
    "This is a local simulation using a sample cloud "
    "environment. It does not connect to a real cloud account."
)

try:
    environment = load_environment("cloud_environment.json")
    cloud = build_graph(environment)

    entry_point = environment["entry_point"]
    protected_asset = environment["protected_asset"]
    legitimate_paths = environment.get("legitimate_paths", [])

    report = generate_security_report(
        cloud,
        entry_point,
        protected_asset,
    )

    # Environment overview
    st.subheader("Cloud Environment Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Resources", report["resource_count"])
    col2.metric("Connections", report["connection_count"])
    col3.metric("Attack Paths", report["attack_path_count"])

    # Day 26: Misconfiguration findings
    st.divider()
    st.header("🔎 Cloud Misconfiguration Checks")
    st.write(
        "Checks for potentially risky resource settings using "
        "the project's illustrative detection rules."
    )

    findings = check_misconfigurations(cloud)

    if findings:
        high_count = sum(
            finding["severity"] == "HIGH"
            for finding in findings
        )

        finding_col1, finding_col2 = st.columns(2)
        finding_col1.metric("Findings", len(findings))
        finding_col2.metric("High-severity findings", high_count)

        for number, finding in enumerate(findings, start=1):
            with st.expander(
                f"⚠️ Finding {number}: {finding['rule']} "
                f"— {finding['resource_name']}"
            ):
                st.write(f"**Severity:** {finding['severity']}")
                st.write(
                    f"**Resource:** `{finding['resource_id']}`"
                )
                st.write(f"**Issue:** {finding['message']}")
                st.write(
                    f"**Recommended action:** "
                    f"{finding['recommendation']}"
                )
    else:
        st.success(
            "No misconfigurations were detected by the current rules."
        )

    st.caption(
        "These findings are rule-based warnings, not proof of "
        "exploitation or a complete cloud security audit."
    )

    # Protected asset reachability
    st.divider()
    st.subheader("Protected Asset — Original Environment")
    st.write(f"**Entry point:** `{entry_point}`")
    st.write(f"**Protected asset:** `{protected_asset}`")

    if report["protected_asset_reachable"]:
        st.error(
            "The protected asset is reachable through at least "
            "one discovered attack path in the original environment."
        )
    else:
        st.success(
            "No attack path was found from the configured entry "
            "point to the protected asset."
        )

    # Original network map
    st.subheader("Original Cloud Network Map")
    show_cloud_map(
        cloud,
        report["attack_paths"],
        title="Original Environment — Attack Paths",
    )

    # Attack paths
    st.subheader("Discovered Attack Paths")

    if report["attack_paths"]:
        for number, item in enumerate(report["attack_paths"], start=1):
            with st.expander(
                f"Path {number} — Score: {item['risk_score']}/100"
            ):
                st.write(f"**Route:** {' → '.join(item['path'])}")
                st.write("**Why it received this score:**")

                for reason in item["reasons"]:
                    st.write(f"- {reason}")
    else:
        st.write("No attack paths were discovered.")

    # Single-edge remediation panel
    st.divider()

    show_remediation_panel(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths,
    )

    # Multi-edge remediation simulation
    st.divider()
    st.header("🔬 Before-and-After Remediation Simulation")
    st.write(
        "Compare the original environment with a simulated "
        "remediated environment. No real cloud resources are changed."
    )

    remediation_result = None

    try:
        remediation_result = find_validated_multi_edge_remediation(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths=legitimate_paths,
            max_removals=3,
        )

        if remediation_result is None:
            st.warning(
                "No safe remediation solution was found within "
                "the current search limit."
            )
        else:
            simulated_graph = remediation_result["graph"]
            paths_before = remediation_result["paths_before"]
            paths_after = remediation_result["paths_after"]

            before_col, after_col, change_col = st.columns(3)

            before_col.metric(
                "Attack paths before", len(paths_before)
            )
            after_col.metric(
                "Attack paths after",
                len(paths_after),
                delta=len(paths_after) - len(paths_before),
                delta_color="inverse",
            )
            change_col.metric(
                "Connections removed",
                remediation_result["removals_count"],
            )

            if paths_after:
                st.warning(
                    "Some attack paths remain after remediation."
                )
            else:
                st.success(
                    "No discovered attack paths remain in the "
                    "simulated environment."
                )

            with st.expander("View proposed connection removals"):
                for connection in remediation_result[
                    "removed_connections"
                ]:
                    st.write(
                        f"- `{connection['source']}` → "
                        f"`{connection['target']}` "
                        f"(Type: {connection['type']})"
                    )

            st.subheader("Compare Network Maps")
            show_before_after_maps(
                original_graph=cloud,
                remediated_graph=simulated_graph,
                original_attack_paths=paths_before,
                remaining_attack_paths=paths_after,
            )

    except ValueError as error:
        st.error(f"Remediation validation failed: {error}")

    # Day 27: Export the full assessment, including misconfigurations.
    st.divider()
    st.header("📄 Export Security Assessment")
    st.write(
        "Download the assessment, misconfiguration findings, and "
        "simulated remediation results as a JSON report."
    )

    export_report = build_export_report(
        report,
        remediation_result=remediation_result,
        misconfiguration_findings=findings,
    )

    report_json = report_to_json(export_report)

    st.download_button(
        label="⬇️ Download Security Report (JSON)",
        data=report_json,
        file_name="cloud_security_assessment.json",
        mime="application/json",
    )

    st.caption(
        "The report contains illustrative risk scores and local "
        "simulation results. It does not certify real-world security."
    )

except Exception as error:
    st.error(f"Could not load the cloud environment: {error}")
    st.info(
        "Check that cloud_environment.json exists and that "
        "its configuration is valid."
    )
