
from itertools import combinations

from main import (
    find_attack_paths,
    legitimate_access_preserved,
)


def find_multi_edge_remediation(
    cloud,
    entry_point,
    protected_asset,
    legitimate_paths=None,
    max_removals=3,
):
    """
    Find the smallest tested set of connection removals that blocks
    every attack path while preserving configured legitimate connections.

    The search is bounded by max_removals.
    Returns a result dictionary, or None if no solution is found
    within the search limit.
    """

    if legitimate_paths is None:
        legitimate_paths = []

    if max_removals < 1:
        raise ValueError("max_removals must be at least 1.")

    original_paths = find_attack_paths(
        cloud, entry_point, protected_asset
    )

    if not original_paths:
        return {
            "removed_connections": [],
            "graph": cloud.copy(),
            "paths_before": [],
            "paths_after": [],
            "legitimate_access_preserved": True,
            "removals_count": 0,
        }

    edges = list(cloud.edges(data=True))

    # Try smaller combinations before larger combinations.
    for number_to_remove in range(
        1, min(max_removals, len(edges)) + 1
    ):
        for selected_edges in combinations(edges, number_to_remove):
            simulated_graph = cloud.copy()

            removed_connections = [
                {
                    "source": source,
                    "target": target,
                    "type": attributes.get("type", "unknown"),
                }
                for source, target, attributes in selected_edges
            ]

            for connection in removed_connections:
                simulated_graph.remove_edge(
                    connection["source"],
                    connection["target"],
                )

            if not legitimate_access_preserved(
                cloud,
                simulated_graph,
                legitimate_paths,
            ):
                continue

            remaining_paths = find_attack_paths(
                simulated_graph,
                entry_point,
                protected_asset,
            )

            if not remaining_paths:
                return {
                    "removed_connections": removed_connections,
                    "graph": simulated_graph,
                    "paths_before": original_paths,
                    "paths_after": remaining_paths,
                    "legitimate_access_preserved": True,
                    "removals_count": len(removed_connections),
                }

    return None


def print_multi_remediation(result):
    """Print the result of the multi-connection search."""

    print("\n=== Multi-Connection Remediation ===")

    if result is None:
        print(
            "No safe solution found within the configured "
            "search limit."
        )
        print(
            "A larger search limit or a different remediation "
            "strategy may be needed."
        )
        return

    print(f"Attack paths before: {len(result['paths_before'])}")
    print(f"Attack paths after: {len(result['paths_after'])}")
    print(f"Connections to review: {result['removals_count']}")

    if result["removed_connections"]:
        for connection in result["removed_connections"]:
            print(
                f"- {connection['source']} -> "
                f"{connection['target']} "
                f"({connection['type']})"
            )
    else:
        print("No removals needed.")

    print(
        "Legitimate access preserved: "
        f"{result['legitimate_access_preserved']}"
    )
