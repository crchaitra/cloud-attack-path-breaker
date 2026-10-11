
import json
from pathlib import Path

import networkx as nx


def load_environment(file_path="cloud_environment.json"):
    """Load the cloud environment configuration from a JSON file."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path.resolve()}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def build_graph(environment):
    """Build and validate a directed graph of cloud resources."""
    resources = environment.get("resources", [])
    connections = environment.get("connections", [])

    if not isinstance(resources, list) or not isinstance(connections, list):
        raise ValueError("Resources and connections must be lists.")

    graph = nx.DiGraph()
    resource_ids = set()

    for resource in resources:
        resource_id = resource.get("id")

        if not resource_id:
            raise ValueError("Every resource must have an ID.")

        if resource_id in resource_ids:
            raise ValueError(f"Duplicate resource ID: {resource_id}")

        resource_ids.add(resource_id)
        graph.add_node(resource_id, **resource)

    for connection in connections:
        source = connection.get("source")
        target = connection.get("target")

        if source not in resource_ids or target not in resource_ids:
            raise ValueError(
                f"Connection references an unknown resource: "
                f"{source} -> {target}"
            )

        graph.add_edge(
            source,
            target,
            **{
                key: value
                for key, value in connection.items()
                if key not in ("source", "target")
            },
        )

    entry_point = environment.get("entry_point")
    protected_asset = environment.get("protected_asset")

    if entry_point not in resource_ids:
        raise ValueError("Entry point is missing or does not exist.")

    if protected_asset not in resource_ids:
        raise ValueError("Protected asset is missing or does not exist.")

    return graph


def find_attack_paths(cloud, entry_point, protected_asset):
    """Find all simple directed paths to the protected asset."""
    if entry_point not in cloud or protected_asset not in cloud:
        return []

    try:
        return list(
            nx.all_simple_paths(cloud, entry_point, protected_asset)
        )
    except nx.NetworkXNoPath:
        return []


def score_path(cloud, path):
    """Calculate an illustrative risk score from 0 to 100."""
    if not path:
        return 0, ["No resources in path"]

    score = 0
    reasons = []

    # Public exposure increases risk.
    if cloud.nodes[path[0]].get("public", False):
        score += 25
        reasons.append("Public entry point (+25)")

    # Longer paths involve more opportunities for misconfiguration.
    if len(path) > 2:
        score += 10
        reasons.append("Multiple steps in attack path (+10)")

    sensitivity_values = {
        "low": 5,
        "medium": 10,
        "high": 20,
        "critical": 30,
    }

    highest_sensitivity = "low"
    highest_value = 5

    for node in path:
        sensitivity = cloud.nodes[node].get("sensitivity", "low")
        value = sensitivity_values.get(sensitivity, 5)

        if value > highest_value:
            highest_value = value
            highest_sensitivity = sensitivity

    score += highest_value
    reasons.append(
        f"Highest resource sensitivity: "
        f"{highest_sensitivity} (+{highest_value})"
    )

    score = min(score, 100)
    return score, reasons


def recommend_remediations(cloud, entry_point, protected_asset):
    """
    Simulate removing individual connections and select the removal
    that eliminates the most attack paths without modifying the original.
    """
    original_paths = find_attack_paths(
        cloud, entry_point, protected_asset
    )

    if not original_paths:
        return [], cloud.copy(), original_paths

    candidates = []

    for source, target, attributes in list(cloud.edges(data=True)):
        simulated_graph = cloud.copy()
        simulated_graph.remove_edge(source, target)

        remaining_paths = find_attack_paths(
            simulated_graph, entry_point, protected_asset
        )

        eliminated_count = len(original_paths) - len(remaining_paths)

        if eliminated_count > 0:
            candidates.append(
                {
                    "source": source,
                    "target": target,
                    "connection_type": attributes.get("type", "unknown"),
                    "paths_eliminated": eliminated_count,
                    "paths_remaining": len(remaining_paths),
                    "graph": simulated_graph,
                }
            )

    # Prefer eliminating more paths, leaving fewer paths, and then
    # prioritizing direct-access connections when results are tied.
    candidates.sort(
        key=lambda item: (
            -item["paths_eliminated"],
            item["paths_remaining"],
            0 if item["connection_type"] == "direct_access" else 1,
            item["source"],
            item["target"],
        )
    )

    if not candidates:
        return [], cloud.copy(), original_paths

    best = candidates[0]

    recommendation = {
        "source": best["source"],
        "target": best["target"],
        "connection_type": best["connection_type"],
        "paths_eliminated": best["paths_eliminated"],
        "paths_remaining": best["paths_remaining"],
        "action": (
            f"Review and restrict the connection from "
            f"{best['source']} to {best['target']}"
        ),
    }

    return [recommendation], best["graph"], original_paths


def main():
    """Run the cloud attack-path analysis from the terminal."""
    try:
        environment = load_environment()
        cloud = build_graph(environment)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Could not load cloud environment: {error}")
        return

    entry_point = environment["entry_point"]
    protected_asset = environment["protected_asset"]

    print("=== Cloud Attack-Path Breaker ===")
    print(f"Resources: {cloud.number_of_nodes()}")
    print(f"Connections: {cloud.number_of_edges()}")
    print(f"Entry point: {entry_point}")
    print(f"Protected asset: {protected_asset}")

    original_edges = set(cloud.edges())
    original_paths = find_attack_paths(
        cloud, entry_point, protected_asset
    )

    print(f"\nAttack paths found: {len(original_paths)}")

    for index, path in enumerate(original_paths, start=1):
        score, reasons = score_path(cloud, path)

        print(f"\nPath {index}: {' -> '.join(path)}")
        print(f"Risk score: {score}/100")

        for reason in reasons:
            print(f"  - {reason}")

    print("\n=== Remediation Simulation ===")

    recommendations, simulated_graph, _ = recommend_remediations(
        cloud, entry_point, protected_asset
    )

    if not recommendations:
        print("No single-connection remediation was identified.")
    else:
        for recommendation in recommendations:
            print(f"Recommendation: {recommendation['action']}")
            print(
                f"Connection type: "
                f"{recommendation['connection_type']}"
            )
            print(
                f"Attack paths eliminated: "
                f"{recommendation['paths_eliminated']}"
            )

    remaining_paths = find_attack_paths(
        simulated_graph, entry_point, protected_asset
    )

    print(f"Attack paths before: {len(original_paths)}")
    print(f"Attack paths after: {len(remaining_paths)}")
    print(f"Original graph unchanged: {set(cloud.edges()) == original_edges}")

    if remaining_paths:
        print("\nRemaining attack paths:")
        for path in remaining_paths:
            print(" -> ".join(path))

    print(
        "\nNote: This is a simulated risk-reduction exercise. "
        "Fewer attack paths do not by themselves prove that legitimate "
        "access has been preserved."
    )


if __name__ == "__main__":
    main()
