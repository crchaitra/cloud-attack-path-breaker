
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
    Find the smallest set of connection removals that blocks
    all attack paths while preserving required legitimate access.

    Returns a dictionary containing the proposed changes,
    or None if no safe solution is found.
    """

    if legitimate_paths is None:
        legitimate_paths = []

    if max_removals < 1:
        raise ValueError("max_removals must be at least 1.")

    original_paths = find_attack_paths(
        cloud,
        entry_point,
        protected_asset,
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

    # Try removing one connection first, then two, then three.
    for number_to_remove in range(
        1,
        min(max_removals, len(edges)) + 1,
    ):
        for selected_edges in combinations(
            edges,
            number_to_remove,
        ):
            simulated_graph = cloud.copy()

            removed_connections = [
                {
                    "source": source,
                    "target": target,
                    "type": attributes.get("type", "unknown"),
                }
                for source, target, attributes in selected_edges
            ]

            # Apply the proposed removals only to the copy.
            for connection in removed_connections:
                simulated_graph.remove_edge(
                    connection["source"],
                    connection["target"],
                )

            # Never accept a change that breaks required access.
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

            # A solution is successful only when no attack path remains.
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
    """Print the multi-connection remediation result."""

    print("\n=== Multi-Connection Remediation ===")

    if result is None:
        print(
            "No safe solution found within the configured "
            "search limit."
        )
        print(
            "Try a larger search limit or another remediation strategy."
        )
        return

    print(f"Attack paths before: {len(result['paths_before'])}")
    print(f"Attack paths after: {len(result['paths_after'])}")
    print(f"Connections to review: {result['removals_count']}")

    for connection in result["removed_connections"]:
        print(
            f"- {connection['source']} -> "
            f"{connection['target']} "
            f"({connection['type']})"
        )

    if not result["removed_connections"]:
        print("No removals needed.")

    print(
        "Legitimate access preserved: "
        f"{result['legitimate_access_preserved']}"
    )
