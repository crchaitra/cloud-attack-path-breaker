
import matplotlib.pyplot as plt
import networkx as nx
import streamlit as st


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
):
    """Draw resources and highlight discovered attack-path connections."""

    if attack_paths is None:
        attack_paths = []

    dangerous_edges = set()

    for item in attack_paths:
        path = _extract_path(item)

        for source, target in zip(path, path[1:]):
            dangerous_edges.add((source, target))

    positions = nx.spring_layout(cloud, seed=42, k=1.5)
    figure, axis = plt.subplots(figsize=(10, 4.5))

    node_colors = []

    for resource_id in cloud.nodes:
        resource = cloud.nodes[resource_id]

        if resource.get("type") == "entry_point":
            node_colors.append("#F4A261")
        elif resource.get("sensitivity") == "critical":
            node_colors.append("#E76F51")
        else:
            node_colors.append("#78C6A3")

    nx.draw_networkx_nodes(
        cloud, positions, node_color=node_colors,
        node_size=1800, ax=axis,
    )

    nx.draw_networkx_labels(
        cloud, positions, font_size=8,
        font_weight="bold", ax=axis,
    )

    ordinary_edges = [
        edge for edge in cloud.edges()
        if edge not in dangerous_edges
    ]

    highlighted_edges = [
        edge for edge in cloud.edges()
        if edge in dangerous_edges
    ]

    nx.draw_networkx_edges(
        cloud, positions, edgelist=ordinary_edges,
        edge_color="#64748B", width=1.8,
        arrows=True, arrowsize=18,
        connectionstyle="arc3,rad=0.08", ax=axis,
    )

    nx.draw_networkx_edges(
        cloud, positions, edgelist=highlighted_edges,
        edge_color="#E63946", width=3,
        arrows=True, arrowsize=22,
        connectionstyle="arc3,rad=0.08", ax=axis,
    )

    axis.set_title(title, fontsize=13)
    axis.axis("off")
    figure.tight_layout()

    st.pyplot(figure)
    plt.close(figure)

    st.caption(
        "Red = connection on a discovered attack path. "
        "Grey = other connection. This is a local simulation."
    )


def show_before_after_maps(
    original_graph,
    remediated_graph,
    original_attack_paths,
    remaining_attack_paths=None,
):
    """Display original and simulated remediated network maps."""

    if remaining_attack_paths is None:
        remaining_attack_paths = []

    before_column, after_column = st.columns(2)

    with before_column:
        st.markdown("### 🔴 Before remediation")
        st.write(f"Connections: {original_graph.number_of_edges()}")
        st.write(f"Attack paths: {len(original_attack_paths)}")

        show_cloud_map(
            original_graph,
            attack_paths=original_attack_paths,
            title="Original Environment",
        )

    with after_column:
        st.markdown("### 🛡️ After simulated remediation")
        st.write(f"Connections: {remediated_graph.number_of_edges()}")
        st.write(f"Attack paths remaining: {len(remaining_attack_paths)}")

        show_cloud_map(
            remediated_graph,
            attack_paths=remaining_attack_paths,
            title="Simulated Remediated Environment",
        )

        if remaining_attack_paths:
            st.warning(
                "The protected asset remains reachable in this simulation."
            )
        else:
            st.success(
                "No attack paths were found in the simulated environment."
            )
