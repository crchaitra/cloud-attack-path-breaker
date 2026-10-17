import json
from html import escape

import streamlit as st

from cloud_map import show_cloud_map, show_before_after_maps
from dashboard_ui import (
    inject_dashboard_styles,
    render_attack_path_card,
    render_finding_card,
    render_metric_card,
    render_status_card,
)
from main import (
    build_graph,
    find_attack_paths,
    legitimate_access_preserved,
    load_environment,
    recommend_remediations,
)
from misconfiguration_checks import check_misconfigurations
from report_export import build_export_report, report_to_json
from security_report import generate_security_report
from validated_remediation import (
    find_validated_multi_edge_remediation,
)


def render_graph_selection(selection, graph, blocked_connections=None):
    """Show details for a node or connection selected in Cytoscape."""
    if not isinstance(selection, dict):
        return None

    data = selection.get("data")
    if not isinstance(data, dict):
        return None

    target_id = data.get("target_id")
    action = selection.get("action")

    if action == "node_selected" and isinstance(target_id, str):
        if target_id not in graph:
            st.warning("The selected resource is no longer in this graph.")
            return None
        resource = graph.nodes[target_id]
        with st.container(border=True):
            st.markdown(f"**Selected resource · {resource.get('name', target_id)}**")
            st.code(target_id)
            st.write(f"Type: {resource.get('type', 'unknown')}")
            st.write(f"Public: {'Yes' if resource.get('public') else 'No'}")
            st.write(f"Sensitivity: {resource.get('sensitivity', 'unknown')}")
        return {"kind": "node", "id": target_id}

    if action != "edge_selected" or not isinstance(target_id, str):
        return None

    edge_prefix, separator, encoded_edge = target_id.partition(":")
    if not separator or edge_prefix not in {"edge", "blocked"}:
        st.error("The selected connection returned an invalid graph identifier.")
        return None

    try:
        edge = json.loads(encoded_edge)
    except json.JSONDecodeError:
        st.error("The selected connection returned an invalid graph identifier.")
        return None

    if (
        not isinstance(edge, list)
        or len(edge) != 2
        or not all(isinstance(resource_id, str) for resource_id in edge)
    ):
        st.error("The selected connection returned an invalid graph identifier.")
        return None

    source, target = edge
    if graph.has_edge(source, target):
        connection_type = graph.edges[source, target].get("type", "unknown")
        status = "Configured connection"
    else:
        connection_type = "unknown"
        for blocked in blocked_connections or []:
            if blocked["source"] == source and blocked["target"] == target:
                connection_type = blocked.get("type", "unknown")
                break
        status = "Simulated blocked connection"

    with st.container(border=True):
        st.markdown(f"**Selected connection · {status}**")
        st.code(f"{source} → {target}")
        st.write(f"Connection type: {connection_type}")
    return {
        "kind": "edge",
        "source": source,
        "target": target,
        "connection_type": connection_type,
        "present": graph.has_edge(source, target),
    }


st.set_page_config(
    page_title="CLOUD//BREAKER | Attack Path Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_dashboard_styles()

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
    findings = check_misconfigurations(cloud)

    remediation_result = None
    remediation_error = None
    try:
        remediation_result = find_validated_multi_edge_remediation(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths=legitimate_paths,
            max_removals=3,
        )
    except ValueError as error:
        remediation_error = error

    export_report = build_export_report(
        report,
        remediation_result=remediation_result,
        misconfiguration_findings=findings,
    )
    report_json = report_to_json(export_report)

    with st.sidebar:
        st.markdown(
            """
            <div class="cb-brand">
                <div class="cb-brand-mark">
                    <span class="cb-brand-glyph">⌁</span>
                    <span>CLOUD//BREAKER</span>
                </div>
                <div class="cb-micro" style="margin-top:.55rem;">Attack path intelligence</div>
            </div>
            <div class="cb-micro" style="margin:0 0 .55rem .5rem;">Workspace</div>
            """,
            unsafe_allow_html=True,
        )
        page = st.radio(
            "Dashboard navigation",
            [
                "Overview",
                "Attack map",
                "Remediation lab",
                "Findings",
                "Security report",
            ],
            label_visibility="collapsed",
        )
        st.markdown(
            f"""
            <div class="cb-panel" style="margin-top:1.2rem;padding:.9rem;">
                <div class="cb-micro">Environment status</div>
                <div style="margin:.5rem 0;color:#39ff88;font-weight:800;">● &nbsp;LOCAL SIMULATION</div>
                <div class="cb-micro">{report["resource_count"]} resources · {report["connection_count"]} connections</div>
            </div>
            <div class="cb-micro" style="margin:1rem .35rem;">
                No real cloud account is connected.
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        """
        <div class="cb-hero">
            <div>
                <div class="cb-micro">Threat surface / local analysis</div>
                <h1>CLOUD<span>//</span>BREAKER</h1>
                <div class="cb-hero-subtitle">ATTACK PATH INTELLIGENCE</div>
            </div>
            <div class="cb-local-badge"><span class="cb-local-dot"></span>LOCAL SIMULATION</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if page == "Overview":
        st.markdown('<div class="cb-section-kicker">01 / System overview</div>', unsafe_allow_html=True)
        st.subheader("Cloud exposure at a glance")
        st.caption("A local analysis of configured resources, connections, and illustrative attack paths.")

        metric_columns = st.columns(4)
        metric_data = [
            ("Cloud resources", report["resource_count"], "Nodes in the environment graph", "#A855F7"),
            ("Connections", report["connection_count"], "Directed access relationships", "#FF3CAC"),
            ("Attack paths", report["attack_path_count"], "Routes to the protected asset", "#FF3355"),
            (
                "Asset exposure",
                "EXPOSED" if report["protected_asset_reachable"] else "CLEAR",
                "Protected asset reachability",
                "#FF3355" if report["protected_asset_reachable"] else "#39FF88",
            ),
        ]
        for column, (label, value, detail, accent) in zip(metric_columns, metric_data):
            with column:
                render_metric_card(label, value, detail, accent)

        st.markdown("")
        render_status_card(
            report["protected_asset_reachable"],
            protected_asset,
            entry_point,
        )

        st.markdown("")
        map_column, path_column = st.columns([1.55, 1], gap="large")
        with map_column:
            st.markdown('<div class="cb-section-kicker">Attack surface</div>', unsafe_allow_html=True)
            st.subheader("Network attack map")
            graph_selection = show_cloud_map(
                cloud,
                report["attack_paths"],
                title="RESOURCE ACCESS GRAPH",
                entry_point=entry_point,
                protected_asset=protected_asset,
                legitimate_paths=legitimate_paths,
                key="overview-network-map",
            )
            render_graph_selection(graph_selection, cloud)
        with path_column:
            st.markdown('<div class="cb-section-kicker">Highest priority</div>', unsafe_allow_html=True)
            st.subheader("Discovered paths")
            if report["attack_paths"]:
                for number, item in enumerate(report["attack_paths"][:3], start=1):
                    render_attack_path_card(item, number)
                    with st.expander(f"Why path {number} received this score"):
                        for reason in item["reasons"]:
                            st.write(f"• {reason}")
                st.caption(report["risk_score_note"])
            else:
                st.markdown(
                    '<div class="cb-empty">No route to the protected asset was found from the configured entry point.</div>',
                    unsafe_allow_html=True,
                )

        st.markdown("")
        summary_column, finding_column = st.columns(2, gap="large")
        with summary_column:
            st.markdown('<div class="cb-section-kicker">Assessment scope</div>', unsafe_allow_html=True)
            st.markdown(
                f"""
                <div class="cb-panel">
                    <div class="cb-micro">Entry point</div>
                    <div class="cb-code" style="margin:.35rem 0 1rem;">{escape(str(entry_point))}</div>
                    <div class="cb-micro">Protected asset</div>
                    <div class="cb-code" style="margin-top:.35rem;">{escape(str(protected_asset))}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with finding_column:
            high_findings = sum(
                finding["severity"].upper() == "HIGH"
                for finding in findings
            )
            st.markdown('<div class="cb-section-kicker">Configuration checks</div>', unsafe_allow_html=True)
            st.markdown(
                f"""
                <div class="cb-panel">
                    <div style="font-size:1.45rem;font-weight:800;">{len(findings)} <span style="color:#a09aaf;font-size:.88rem;font-weight:500;">detected finding(s)</span></div>
                    <div class="cb-micro" style="margin-top:.35rem;">{high_findings} high severity · rule-based checks</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    elif page == "Attack map":
        st.markdown('<div class="cb-section-kicker">02 / Path intelligence</div>', unsafe_allow_html=True)
        st.subheader("Attack map")
        st.caption("Red edges belong to discovered routes. Purple edges are ordinary connections; green edges are configured legitimate access.")

        selected_paths = report["attack_paths"]
        if report["attack_paths"]:
            overlay_options = ["All discovered paths"] + [
                f"Path {number}: {' → '.join(item['path'])}"
                for number, item in enumerate(report["attack_paths"], start=1)
            ]
            selected_overlay = st.selectbox("Attack path overlay", overlay_options)
            if selected_overlay != overlay_options[0]:
                selected_index = overlay_options.index(selected_overlay) - 1
                selected_paths = [report["attack_paths"][selected_index]]

        graph_selection = show_cloud_map(
            cloud,
            selected_paths,
            title="RESOURCE ACCESS GRAPH",
            entry_point=entry_point,
            protected_asset=protected_asset,
            legitimate_paths=legitimate_paths,
            key="attack-path-network-map",
        )
        render_graph_selection(graph_selection, cloud)
        st.caption("Node shapes indicate resource type; outlined nodes identify the entry point and protected asset. Risk scores are illustrative project heuristics, not validated real-world ratings.")

        st.markdown('<div class="cb-section-kicker">Route analysis</div>', unsafe_allow_html=True)
        st.subheader("Risk assessment")
        if report["attack_paths"]:
            for number, item in enumerate(report["attack_paths"], start=1):
                render_attack_path_card(item, number)
                with st.expander(f"Path {number} · route context and scoring rationale"):
                    st.markdown("**Traversed resources**")
                    for resource_id in item["path"]:
                        resource = cloud.nodes[resource_id]
                        st.write(
                            f"`{resource_id}` · {resource.get('name', resource_id)} "
                            f"— {resource.get('type', 'unknown')} / "
                            f"{resource.get('sensitivity', 'unknown')} sensitivity"
                        )
                    st.markdown("**Why this score**")
                    for reason in item["reasons"]:
                        st.write(f"• {reason}")
                    st.markdown(f"**Reachable sensitive asset:** `{protected_asset}`")
            st.info(report["risk_score_note"])
        else:
            st.success("No attack paths were discovered for this environment.")

    elif page == "Remediation lab":
        st.markdown('<div class="cb-section-kicker">03 / Response operations</div>', unsafe_allow_html=True)
        st.subheader("Remediation lab")
        st.warning("SIMULATION ONLY · Proposed changes are evaluated on a local graph copy and do not modify real cloud infrastructure.")

        if remediation_error:
            st.error(f"Remediation validation failed: {remediation_error}")

        recommendations, _, _ = recommend_remediations(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths,
        )

        st.markdown('<div class="cb-section-kicker">Attack / defend exercise</div>', unsafe_allow_html=True)
        st.write(
            "Focus an exposed route, choose a safe connection on that route, "
            "and evaluate the proposed block on a local graph copy."
        )

        simulated_edge = st.session_state.get("attack_defend_removed_edge")
        simulated_connections = []
        if simulated_edge is not None and cloud.has_edge(*simulated_edge):
            simulated_connections = [{
                "source": simulated_edge[0],
                "target": simulated_edge[1],
                "type": cloud.edges[simulated_edge].get("type", "unknown"),
            }]

        graph_selection = show_cloud_map(
            cloud,
            report["attack_paths"],
            title="CLICK A RESOURCE OR CONNECTION",
            entry_point=entry_point,
            protected_asset=protected_asset,
            legitimate_paths=legitimate_paths,
            removed_connections=simulated_connections,
            key="remediation-interactive-map",
        )
        selected_element = render_graph_selection(
            graph_selection,
            cloud,
            blocked_connections=simulated_connections,
        )
        if not report["attack_paths"]:
            st.success("No attack route was discovered. You can still inspect the resources and connections.")
        else:
            st.caption("Select a resource or a red attack-path connection directly on the graph.")

        recommendation_by_edge = {
            (item["source"], item["target"]): item
            for item in recommendations
        }
        selected_edge = None
        if selected_element and selected_element["kind"] == "edge":
            selected_edge = (
                selected_element["source"],
                selected_element["target"],
            )
        selected_recommendation = recommendation_by_edge.get(selected_edge)

        if selected_edge and selected_recommendation is None:
            st.warning(
                "This connection can be inspected, but it is not a safe "
                "single-connection remediation candidate. The configured "
                "legitimate-access validation or path-impact check excludes it."
            )
        elif selected_recommendation:
            st.success(
                f"This connection is a safe candidate: it eliminates "
                f"{selected_recommendation['paths_eliminated']} attack path(s), "
                f"with {selected_recommendation['paths_remaining']} remaining. "
                "Configured legitimate access is preserved."
            )
        else:
            st.info("Click an attack-path connection to inspect it and enable a safe simulation.")

        simulate_column, reset_column = st.columns(2)
        with simulate_column:
            simulate_clicked = st.button(
                "Simulate selected connection block",
                key="simulate_selected_block",
                type="primary",
                disabled=selected_recommendation is None,
            )
        with reset_column:
            reset_clicked = st.button(
                "Reset simulation",
                key="reset_selected_block",
                disabled=simulated_edge is None,
            )

        if simulate_clicked and selected_recommendation:
            st.session_state["attack_defend_removed_edge"] = selected_edge
            st.rerun()
        if reset_clicked:
            st.session_state.pop("attack_defend_removed_edge", None)
            st.rerun()

        simulated_edge = st.session_state.get("attack_defend_removed_edge")
        if simulated_edge is not None:
            source, target = simulated_edge
            if selected_edge is not None and selected_edge != simulated_edge:
                st.info(
                    f"The selected connection {selected_edge[0]} → "
                    f"{selected_edge[1]} has not been simulated yet. "
                    f"Current results still reflect blocking "
                    f"{source} → {target}."
                )
            if not cloud.has_edge(source, target):
                st.error(
                    "The selected connection is not present in the current "
                    "environment. Reset the simulation and choose another."
                )
            else:
                simulated_graph = cloud.copy()
                simulated_graph.remove_edge(source, target)
                access_preserved = legitimate_access_preserved(
                    cloud,
                    simulated_graph,
                    legitimate_paths,
                )
                if not access_preserved:
                    st.error(
                        "This block would break configured legitimate access; "
                        "it is not accepted as a safe simulation."
                    )
                else:
                    remaining_paths = find_attack_paths(
                        simulated_graph,
                        entry_point,
                        protected_asset,
                    )
                    before_column, after_column, access_column = st.columns(3)
                    with before_column:
                        render_metric_card(
                            "Paths before",
                            len(report["attack_paths"]),
                            "Original environment",
                            "#FF3355",
                        )
                    with after_column:
                        render_metric_card(
                            "Paths after",
                            len(remaining_paths),
                            f"After blocking {source} → {target}",
                            "#39FF88" if not remaining_paths else "#FF3CAC",
                        )
                    with access_column:
                        render_metric_card(
                            "Required access",
                            "PRESERVED",
                            "Existing validation passed",
                            "#39FF88",
                        )
                    st.caption(
                        f"Simulated removal: {source} → {target}. "
                        "The original graph and environment file are unchanged."
                    )
                    if remaining_paths:
                        st.warning(
                            f"{len(remaining_paths)} attack path(s) remain "
                            "after this single simulated block."
                        )
                        with st.expander(
                            "Inspect remaining attack path(s)",
                            expanded=True,
                        ):
                            for path in remaining_paths:
                                st.code(" → ".join(path))
                    else:
                        st.success(
                            "No discovered attack paths remain after this "
                            "simulated block."
                        )
                    comparison_selections = show_before_after_maps(
                        original_graph=cloud,
                        remediated_graph=simulated_graph,
                        original_attack_paths=report["attack_paths"],
                        remaining_attack_paths=remaining_paths,
                        entry_point=entry_point,
                        protected_asset=protected_asset,
                        legitimate_paths=legitimate_paths,
                        removed_connections=simulated_connections,
                        key_prefix="selected-edge-simulation",
                    )
                    render_graph_selection(
                        comparison_selections["before"],
                        cloud,
                    )
                    render_graph_selection(
                        comparison_selections["after"],
                        simulated_graph,
                        blocked_connections=simulated_connections,
                    )

        st.markdown('<div class="cb-section-kicker">Single-connection recommendations</div>', unsafe_allow_html=True)
        if recommendations:
            for recommendation in recommendations:
                with st.container(border=True):
                    st.markdown(
                        f"**Block candidate {recommendation['rank']}** · "
                        f"`{recommendation['source']}` → `{recommendation['target']}`"
                    )
                    st.caption(
                        f"{recommendation['connection_type']} · "
                        f"eliminates {recommendation['paths_eliminated']} path(s), "
                        f"{recommendation['paths_remaining']} remain"
                    )
                    st.write(recommendation["reason"])
                    st.success("Configured legitimate access is preserved.")
        else:
            st.info("No safe, beneficial single-connection fix was found.")

        st.markdown('<div class="cb-section-kicker">Validated multi-connection simulation</div>', unsafe_allow_html=True)
        st.subheader("Before / after")
        if remediation_result is None:
            st.warning("No safe remediation solution was found within the current search limit.")
        else:
            paths_before = remediation_result["paths_before"]
            paths_after = remediation_result["paths_after"]
            preserved = remediation_result["legitimate_access_preserved"]
            before_column, after_column, changes_column, access_column = st.columns(4)
            with before_column:
                render_metric_card("Paths before", len(paths_before), "Original environment", "#FF3355")
            with after_column:
                render_metric_card("Paths after", len(paths_after), "Simulated environment", "#39FF88")
            with changes_column:
                render_metric_card(
                    "Connections removed",
                    remediation_result["removals_count"],
                    "Selected for simulated removal",
                    "#A855F7",
                )
            with access_column:
                render_metric_card(
                    "Required access",
                    "PRESERVED" if preserved else "NOT PRESERVED",
                    "Validation result",
                    "#39FF88" if preserved else "#FF3355",
                )

            removed = remediation_result["removed_connections"]
            with st.expander("Inspect proposed connection removals", expanded=True):
                if removed:
                    for connection in removed:
                        st.markdown(
                            f"`{connection['source']}` → `{connection['target']}` "
                            f"<span class=\"cb-pill\" style=\"--finding-accent:#a855f7;--finding-border:rgba(168,85,247,.35);\">{connection['type']}</span>",
                            unsafe_allow_html=True,
                        )
                else:
                    st.write("No connection removals are needed.")

            if paths_after:
                st.warning("Some discovered attack paths remain after the proposed changes.")
            else:
                st.success("All discovered attack paths are blocked in the simulation.")
            if preserved:
                st.success("Configured legitimate access remains preserved.")
            else:
                st.error("The proposed changes do not preserve required access.")

            comparison_selections = show_before_after_maps(
                original_graph=cloud,
                remediated_graph=remediation_result["graph"],
                original_attack_paths=paths_before,
                remaining_attack_paths=paths_after,
                entry_point=entry_point,
                protected_asset=protected_asset,
                legitimate_paths=legitimate_paths,
                removed_connections=remediation_result["removed_connections"],
                key_prefix="validated-remediation",
            )
            render_graph_selection(
                comparison_selections["before"],
                cloud,
            )
            render_graph_selection(
                comparison_selections["after"],
                remediation_result["graph"],
                blocked_connections=remediation_result["removed_connections"],
            )

    elif page == "Findings":
        st.markdown('<div class="cb-section-kicker">04 / Configuration signals</div>', unsafe_allow_html=True)
        st.subheader("Misconfiguration findings")
        st.caption("Rule-based warnings from this simulated environment. Findings are not proof of exploitation or a complete cloud security audit.")
        high_count = sum(
            finding["severity"].upper() == "HIGH"
            for finding in findings
        )
        finding_col, high_col = st.columns(2)
        with finding_col:
            render_metric_card("Findings", len(findings), "Detected by configured rules", "#FF3CAC")
        with high_col:
            render_metric_card("High severity", high_count, "Prioritize exposure review", "#FF3355")

        if findings:
            for finding in findings:
                render_finding_card(finding)
        else:
            st.markdown(
                '<div class="cb-empty">✓ &nbsp; No misconfigurations were detected by the current rules.</div>',
                unsafe_allow_html=True,
            )

    else:
        st.markdown('<div class="cb-section-kicker">05 / Evidence export</div>', unsafe_allow_html=True)
        st.subheader("Security report")
        st.caption("Export the assessment, findings, illustrative risk scores, and any validated simulation results.")
        report_column, facts_column = st.columns([1.35, 1], gap="large")
        with report_column:
            st.markdown(
                """
                <div class="cb-panel">
                    <div class="cb-micro">Assessment package</div>
                    <div style="margin:.45rem 0;font-size:1.12rem;font-weight:800;">Cloud security assessment</div>
                    <div class="cb-finding-copy">Structured JSON · UTF-8 · generated locally</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.download_button(
                label="↓  Download security report (.json)",
                data=report_json,
                file_name="cloud_security_assessment.json",
                mime="application/json",
                width="stretch",
            )
            st.success("Report content is ready for download.")
        with facts_column:
            st.markdown('<div class="cb-section-kicker">Included in export</div>', unsafe_allow_html=True)
            st.write(f"• {report['resource_count']} resources and {report['connection_count']} connections")
            st.write(f"• {report['attack_path_count']} discovered attack path(s)")
            st.write(f"• {len(findings)} rule-based finding(s)")
            st.write(f"• {'Validated simulation result' if remediation_result else 'No remediation result'}")
            st.caption("Scores are illustrative project heuristics and the remediation output is simulation-only.")
        with st.expander("Preview JSON report"):
            st.json(export_report, expanded=True)

except Exception as error:
    st.error(f"Could not load the cloud environment: {error}")
    st.info(
        "Check that cloud_environment.json exists and that "
        "its configuration is valid."
    )
