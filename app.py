
import streamlit as st

from main import load_environment, build_graph
from security_report import generate_security_report
from cloud_map import show_cloud_map
from remediation_panel import show_remediation_panel


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

    st.subheader("Protected Asset")

    st.write(f"**Entry point:** `{entry_point}`")
    st.write(f"**Protected asset:** `{protected_asset}`")

    if report["protected_asset_reachable"]:
        st.error(
            "The protected asset is reachable through "
            "at least one discovered attack path."
        )
    else:
        st.success(
            "No attack path was found from the configured "
            "entry point to the protected asset."
        )

    st.subheader("Cloud Network Map")

    show_cloud_map(cloud, report["attack_paths"])

    st.subheader("Discovered Attack Paths")

    if report["attack_paths"]:
        for number, item in enumerate(
            report["attack_paths"], start=1
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

    show_remediation_panel(
        cloud,
        entry_point,
        protected_asset,
        legitimate_paths,
    )

except Exception as error:
    st.error(f"Could not load the cloud environment: {error}")
    st.info(
        "Check that cloud_environment.json exists "
        "and that its configuration is valid."
    )
