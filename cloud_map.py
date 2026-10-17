import json

import streamlit as st
from streamlit_cytoscape import EdgeStyle, Event, NodeStyle, streamlit_cytoscape


_COLORS = {
    "purple": "#A855F7",
    "pink": "#FF3CAC",
    "red": "#FF3355",
    "green": "#39FF88",
}

def _extract_path(item):
    """Accept either a report dictionary or a raw path list."""
    if isinstance(item, dict):
        return item["path"]
    return item


def show_cloud_map(
    cloud,
    attack_paths=None,
    title="Cloud Environment — Attack Paths Highlighted",
    removed_connections=None,
    entry_point=None,
    protected_asset=None,
    legitimate_paths=None,
    key="cloud-network-graph",
):
    """Render an interactive, type-aware graph and return the last selection."""
    if attack_paths is None:
        attack_paths = []
    if legitimate_paths is None:
        legitimate_paths = []
    if removed_connections is None:
        removed_connections = []

    dangerous_edges = set()
    for item in attack_paths:
        path = _extract_path(item)
        dangerous_edges.update(zip(path, path[1:]))

    legitimate_edges = set()
    for path in legitimate_paths:
        legitimate_edges.update(zip(path, path[1:]))

    blocked_edges = {
        (connection["source"], connection["target"])
        for connection in removed_connections
    }

    elements = {"nodes": [], "edges": []}
    node_style_data = {}
    for resource_id, resource in cloud.nodes(data=True):
        is_entry = resource_id == entry_point or resource.get("type") == "entry_point"
        resource_type = resource.get("type", "unknown")
        shape = {
            "entry_point": "triangle",
            "compute": "ellipse",
            "storage": "round-rectangle",
            "identity": "diamond",
            "logging": "hexagon",
        }.get(resource_type, "ellipse")
        if is_entry:
            posture = "entry"
            fill = "#31224B"
            border = _COLORS["purple"]
        elif resource_id == protected_asset:
            posture = "protected"
            fill = "#4A1D32"
            border = _COLORS["red"]
        elif resource.get("public"):
            posture = "public"
            fill = "#482132"
            border = _COLORS["red"]
        elif resource.get("sensitivity") == "critical":
            posture = "critical"
            fill = "#48213D"
            border = _COLORS["pink"]
        elif resource.get("sensitivity") == "high":
            posture = "high"
            fill = "#302344"
            border = _COLORS["purple"]
        elif resource.get("sensitivity") == "low":
            posture = "low"
            fill = "#183629"
            border = _COLORS["green"]
        else:
            posture = "standard"
            fill = "#24233D"
            border = "#8D78B8"

        style_type = (
            resource_type
            if resource_type in {
                "entry_point",
                "compute",
                "storage",
                "identity",
                "logging",
            }
            else "resource"
        )
        style_label = f"node_{style_type}_{posture}"
        node_style_data[style_label] = {
            "fill": fill,
            "shape": shape,
            "border": border,
        }
        elements["nodes"].append({
            "data": {
                "id": str(resource_id),
                "label": style_label,
                "display_label": resource.get("name", resource_id),
                "name": resource.get("name", resource_id),
                "resource_type": resource.get("type", "unknown"),
                "public": bool(resource.get("public", False)),
                "sensitivity": resource.get("sensitivity", "unknown"),
            }
        })

    for source, target, attributes in cloud.edges(data=True):
        edge = (source, target)
        if edge in blocked_edges:
            style_label = "simulated_block"
        elif edge in dangerous_edges:
            style_label = "attack_path"
        elif edge in legitimate_edges:
            style_label = "legitimate_access"
        else:
            style_label = "ordinary_connection"
        elements["edges"].append({
            "data": {
                "id": f"edge:{json.dumps([source, target], separators=(',', ':'))}",
                "source": str(source),
                "target": str(target),
                "label": style_label,
                "connection_type": attributes.get("type", "unknown"),
            }
        })

    for connection in removed_connections:
        source = connection["source"]
        target = connection["target"]
        if source not in cloud or target not in cloud or cloud.has_edge(source, target):
            continue
        elements["edges"].append({
            "data": {
                "id": f"blocked:{json.dumps([source, target], separators=(',', ':'))}",
                "source": str(source),
                "target": str(target),
                "label": "simulated_block",
                "connection_type": connection.get("type", "unknown"),
            }
        })

    node_styles = [
        NodeStyle(
            label=style_label,
            color=style["fill"],
            caption="display_label",
            custom_styles={
                "shape": style["shape"],
                "width": 54,
                "height": 54,
                "border-width": 2.5,
                "border-color": style["border"],
                "font-size": 10,
                "font-weight": "bold",
                "color": "#F5F3FF",
                "text-wrap": "wrap",
                "text-max-width": 115,
                "text-outline-width": 2,
                "text-outline-color": "#10101C",
            },
        )
        for style_label, style in sorted(node_style_data.items())
    ]

    edge_style_data = {
        "attack_path": (_COLORS["red"], "solid", 4),
        "ordinary_connection": ("#756A88", "solid", 2),
        "legitimate_access": (_COLORS["green"], "solid", 3),
        "simulated_block": (_COLORS["pink"], "dashed", 4),
    }
    edge_styles = [
        EdgeStyle(
            label=style_label,
            color=color,
            caption="connection_type",
            directed=True,
            curve_style="bezier",
            custom_styles={
                "width": width,
                "line-style": line_style,
                "target-arrow-shape": "triangle",
                "target-arrow-color": color,
                "arrow-scale": 1.2,
                "font-size": 8,
                "color": "#F5F3FF",
                "text-background-color": "#10101C",
                "text-background-opacity": .9,
                "text-background-padding": 2,
            },
        )
        for style_label, (color, line_style, width) in edge_style_data.items()
        if any(edge["data"]["label"] == style_label for edge in elements["edges"])
    ]

    st.markdown(f"**{title}**")
    selection = streamlit_cytoscape(
        elements=elements,
        layout={
            "name": "cose",
            "animate": False,
            "padding": 40,
            "nodeRepulsion": 9000,
            "idealEdgeLength": 110,
            "componentSpacing": 100,
        },
        node_styles=node_styles,
        edge_styles=edge_styles,
        height=540,
        key=key,
        events=[
            Event("node_selected", "tap", "node"),
            Event("edge_selected", "tap", "edge"),
        ],
    )
    st.caption(
        "Purple node = entry point · red node = protected asset · "
        "red edge = discovered attack path · purple edge = ordinary connection · "
        "green edge = legitimate access · pink dashed edge = simulated block. "
        "Click a node or connection to inspect it."
    )
    return selection


def show_before_after_maps(
    original_graph,
    remediated_graph,
    original_attack_paths,
    remaining_attack_paths=None,
    entry_point=None,
    protected_asset=None,
    legitimate_paths=None,
    removed_connections=None,
    key_prefix="before-after",
):
    """Display original and simulated remediated network maps."""
    if remaining_attack_paths is None:
        remaining_attack_paths = []

    before_column, after_column = st.columns(2)
    selections = {}

    with before_column:
        st.markdown("### Before remediation")
        st.caption(
            f"{original_graph.number_of_edges()} connections · "
            f"{len(original_attack_paths)} attack paths"
        )
        selections["before"] = show_cloud_map(
            original_graph,
            attack_paths=original_attack_paths,
            title="ORIGINAL ENVIRONMENT",
            entry_point=entry_point,
            protected_asset=protected_asset,
            legitimate_paths=legitimate_paths,
            key=f"{key_prefix}-before",
        )

    with after_column:
        st.markdown("### After simulated remediation")
        st.caption(
            f"{remediated_graph.number_of_edges()} connections · "
            f"{len(remaining_attack_paths)} attack paths remaining"
        )
        selections["after"] = show_cloud_map(
            remediated_graph,
            attack_paths=remaining_attack_paths,
            title="SIMULATED ENVIRONMENT",
            entry_point=entry_point,
            protected_asset=protected_asset,
            legitimate_paths=legitimate_paths,
            removed_connections=removed_connections,
            key=f"{key_prefix}-after",
        )

        if remaining_attack_paths:
            st.warning(
                "The protected asset remains reachable in this simulation."
            )
        else:
            st.success(
                "No attack paths were found in the simulated environment."
            )
    return selections
