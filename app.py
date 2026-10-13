
import streamlit as st
import networkx as nx

from main import load_environment, build_graph
from security_report import generate_security_report
from cloud_map import show_cloud_map, show_before_after_maps
from remediation_panel import show_remediation_panel
from validated_remediation import (
    find_validated_multi_edge_remediation,
)


st.set_page_config(
    page_title="Cloud Attack-Path Breaker",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Cloud Attack-Path Breaker")

st.write(
    "Find dangerous routes through a cloud environment "
    "and understand what needs protection."
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

    st.subheader("Cloud Environment Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Resources", report["resource_count"])
    col2.metric("Connections", report["connection_count"])
    col3.metric("Attack Paths", report["attack_path_count"])

    st.subheader("Protected Asset — Original Environment")

    st.write(f"**Entry point:** `{entry_point}`")
    st.write(f"**Protected asset:** `{protected_asset}`")

    if report["protected_asset_reachable"]:
        st.error(
            "The protected asset is reachable through "
            "at least one discovered attack path in the "
            "original environment."
        )
    else:
        st.success(
            "No attack path was found from the configured "
            "entry point to the protected asset."
        )

    st.subheader("Original Cloud Network Map")

    show_cloud_map(
        cloud,
        report["attack_paths"],
        title="Original Environment — Attack Paths",
    )

    st.subheader("Discovered Attack Paths")

    if report["attack_paths"]:
        for number, item in enumerate(
            report["attack_paths"],
            start=1,
        ):
            path_text = " → ".join(item["path"])

            with st.expander(
                f"Path {number} — Score: {item['risk_score']}/100"
            ):
                st.write(f"**Route:** {path_text}")
                st.write("**Why it received this score:**")

                for reason in item["reasons"]:
                    st.write(f"- {reason}")
    else:
        st.write("No attack paths were discovered.")

    st.divider()

    # Show the existing remediation recommendations.
    show_remediation_panel(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths,
    )

    # Day 19: Before-and-after remediation comparison.
    st.divider()
    st.header("🔬 Before-and-After Remediation Simulation")

    st.write(
        "Compare the original environment with a simulated "
        "environment after applying the multi-connection "
        "remediation recommendation. No real cloud resources "
        "are changed."
    )

    try:
        result = find_validated_multi_edge_remediation(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths=legitimate_paths,
            max_removals=3,
        )

        if result is None:
            st.warning(
                "No safe remediation solution was found within "
                "the current search limit. The comparison cannot "
                "show a successful fix."
            )
        else:
            simulated_graph = result["graph"]
            removed_connections = result["removed_connections"]
            paths_before = result["paths_before"]
            paths_after = result["paths_after"]

            st.subheader("Remediation Summary")

            before_col, after_col, change_col = st.columns(3)

            before_col.metric(
                "Attack paths before",
                len(paths_before),
            )

            after_col.metric(
                "Attack paths after",
                len(paths_after),
                delta=len(paths_after) - len(paths_before),
                delta_color="inverse",
            )

            change_col.metric(
                "Connections removed",
                result["removals_count"],
            )

            if paths_after:
                st.warning(
                    "Some attack paths remain after the simulated "
                    "remediation."
                )
            else:
                st.success(
                    "The simulated remediation blocks all discovered "
                    "attack paths while preserving configured access."
                )

            if removed_connections:
                with st.expander("View proposed connection removals"):
                    for connection in removed_connections:
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

except Exception as error:
    st.error(f"Could not load the cloud environment: {error}")
    st.info(
        "Check that cloud_environment.json exists "
        "and that its configuration is valid."
    )
