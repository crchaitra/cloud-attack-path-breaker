
import matplotlib.pyplot as plt
import networkx as nx
import streamlit as st


def show_cloud_map(cloud, attack_paths=None):
    """
    Draw cloud resources and highlight connections
    that belong to discovered attack paths.
    """

    if attack_paths is None:
        attack_paths = []

    # Collect every connection used by an attack path.
    dangerous_edges = set()

    for item in attack_paths:
        path = item["path"]

        for source, target in zip(path, path[1:]):
            dangerous_edges.add((source, target))

    # Arrange the resources on the map.
    positions = nx.spring_layout(
        cloud,
        seed=42,
        k=1.5,
    )

    figure, axis = plt.subplots(figsize=(10, 4.5))

    # Choose a colour for each resource.
    node_colors = []

    for resource_id in cloud.nodes:
        resource = cloud.nodes[resource_id]

        if resource.get("type") == "entry_point":
            node_colors.append("#F4A261")
        elif resource.get("sensitivity") == "critical":
            node_colors.append("#E76F51")
        else:
            node_colors.append("#78C6A3")

    # Draw the resources.
    nx.draw_networkx_nodes(
        cloud,
        positions,
        node_color=node_colors,
        node_size=1800,
        ax=axis,
    )

    # Draw the resource names.
    nx.draw_networkx_labels(
        cloud,
        positions,
        font_size=8,
        font_weight="bold",
        ax=axis,
    )

    # Separate ordinary connections from dangerous ones.
    ordinary_edges = [
        (source, target)
        for source, target in cloud.edges()
        if (source, target) not in dangerous_edges
    ]

    highlighted_edges = [
        (source, target)
        for source, target in cloud.edges()
        if (source, target) in dangerous_edges
    ]

    # Draw ordinary connections in grey.
    nx.draw_networkx_edges(
        cloud,
        positions,
        edgelist=ordinary_edges,
        edge_color="#64748B",
        width=1.8,
        arrows=True,
        arrowsize=18,
        connectionstyle="arc3,rad=0.08",
        ax=axis,
    )

    # Draw attack-path connections in red.
    nx.draw_networkx_edges(
        cloud,
        positions,
        edgelist=highlighted_edges,
        edge_color="#E63946",
        width=3,
        arrows=True,
        arrowsize=22,
        connectionstyle="arc3,rad=0.08",
        ax=axis,
    )

    axis.set_title(
        "Cloud Environment — Attack Paths Highlighted",
        fontsize=13,
    )

    axis.axis("off")
    figure.tight_layout()

    st.pyplot(figure)
    plt.close(figure)

    st.caption(
        "Red = connection on a discovered attack path. "
        "Grey = other connection. "
        "This is a local simulation."
    )
