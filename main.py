
import json
from pathlib import Path

import networkx as nx


def load_environment(file_path="cloud_environment.json"):
    """Load the simulated cloud environment."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path.resolve()}"
        )

    with path.open("r", encoding="utf-8") as file:
        try:
            environment = json.load(file)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid JSON in configuration file: {error}"
            ) from error

    if not isinstance(environment, dict):
        raise ValueError(
            "Environment configuration must be a JSON object."
        )

    return environment


def build_graph(environment):
    """Build and validate a directed cloud-resource graph."""

    if not isinstance(environment, dict):
        raise ValueError("Environment configuration must be an object.")

    resources = environment.get("resources", [])
    connections = environment.get("connections", [])

    if not isinstance(resources, list):
        raise ValueError("Resources must be a list.")

    if not isinstance(connections, list):
        raise ValueError("Connections must be a list.")

    graph = nx.DiGraph()
    resource_ids = set()

    # Validate and add resources.
    for resource in resources:
        if not isinstance(resource, dict):
            raise ValueError("Every resource must be an object.")

        resource_id = resource.get("id")

        if not isinstance(resource_id, str) or not resource_id.strip():
            raise ValueError(
                "Every resource must have a non-empty string ID."
            )

        if resource_id in resource_ids:
            raise ValueError(f"Duplicate resource ID: {resource_id}")

        resource_ids.add(resource_id)
        graph.add_node(resource_id, **resource)

    # Validate and add connections.
    for connection in connections:
        if not isinstance(connection, dict):
            raise ValueError("Every connection must be an object.")

        source = connection.get("source")
        target = connection.get("target")

        if not isinstance(source, str) or not source.strip():
            raise ValueError(
                "Every connection must have a valid source ID."
            )

        if not isinstance(target, str) or not target.strip():
            raise ValueError(
                "Every connection must have a valid target ID."
            )

        if source not in resource_ids or target not in resource_ids:
            raise ValueError(
                f"Connection references an unknown resource: "
                f"{source} -> {target}"
            )

        if graph.has_edge(source, target):
            raise ValueError(
                f"Duplicate connection: {source} -> {target}"
            )

        edge_attributes = {
            key: value
            for key, value in connection.items()
            if key not in ("source", "target")
        }

        graph.add_edge(source, target, **edge_attributes)

    # Validate entry point and protected asset.
    entry_point = environment.get("entry_point")
    protected_asset = environment.get("protected_asset")

    if not isinstance(entry_point, str) or entry_point not in resource_ids:
        raise ValueError("Entry point is missing or does not exist.")

    if (
        not isinstance(protected_asset, str)
        or protected_asset not in resource_ids
    ):
        raise ValueError("Protected asset is missing or does not exist.")

    # Validate legitimate paths.
    legitimate_paths = environment.get("legitimate_paths", [])

    if not isinstance(legitimate_paths, list):
        raise ValueError("Legitimate paths must be a list.")

    for path in legitimate_paths:
        if not isinstance(path, list) or len(path) < 2:
            raise ValueError(
                "Every legitimate path must contain at least two resource IDs."
            )

        if any(
            not isinstance(node, str) or node not in resource_ids
            for node in path
        ):
            raise ValueError(
                f"Legitimate path contains an unknown or invalid resource: "
                f"{path}"
            )

    return graph


def find_attack_paths(cloud, entry_point, protected_asset):
    """Find all simple paths from the entry point to the protected asset."""
    if entry_point not in cloud or protected_asset not in cloud:
        return []

    return list(nx.all_simple_paths(cloud, entry_point, protected_asset))


def score_path(cloud, path):
    """Calculate an illustrative risk score between 0 and 100."""
    if not path:
        return 0, ["No resources in path"]

    score = 0
    reasons = []

    if cloud.nodes[path[0]].get("public", False):
        score += 25
        reasons.append("Public entry point (+25)")

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

    return min(score, 100), reasons


def legitimate_access_preserved(
    cloud, simulated_graph, legitimate_paths
):
    """Check that every required path remains connected in order."""
    for path in legitimate_paths:
        for source, target in zip(path, path[1:]):
            if not simulated_graph.has_edge(source, target):
                return False

    return True


def recommend_remediations(
    cloud,
    entry_point,
    protected_asset,
    legitimate_paths=None,
):
    """
    Compare single-edge removals, rejecting those that break required access.

    Return:
        recommendations, best_simulated_graph, original_attack_paths
    """
    if legitimate_paths is None:
        legitimate_paths = []

    original_paths = find_attack_paths(
        cloud, entry_point, protected_asset
    )

    candidates = []

    for source, target, attributes in list(cloud.edges(data=True)):
        simulated_graph = cloud.copy()
        simulated_graph.remove_edge(source, target)

        access_preserved = legitimate_access_preserved(
            cloud, simulated_graph, legitimate_paths
        )

        remaining_paths = find_attack_paths(
            simulated_graph, entry_point, protected_asset
        )

        eliminated_count = len(original_paths) - len(remaining_paths)

        if not access_preserved or eliminated_count <= 0:
            continue

        candidates.append(
            {
                "source": source,
                "target": target,
                "connection_type": attributes.get("type", "unknown"),
                "paths_eliminated": eliminated_count,
                "paths_remaining": len(remaining_paths),
                "legitimate_access_preserved": True,
                "graph": simulated_graph,
            }
        )

    candidates.sort(
        key=lambda item: (
            -item["paths_eliminated"],
            item["paths_remaining"],
            0 if item["connection_type"] == "direct_access" else 1,
            item["source"],
            item["target"],
        )
    )

    recommendations = []

    for rank, candidate in enumerate(candidates, start=1):
        recommendations.append(
            {
                "rank": rank,
                "source": candidate["source"],
                "target": candidate["target"],
                "connection_type": candidate["connection_type"],
                "paths_eliminated": candidate["paths_eliminated"],
                "paths_remaining": candidate["paths_remaining"],
                "legitimate_access_preserved": candidate[
                    "legitimate_access_preserved"
                ],
                "action": (
                    f"Review and restrict the connection from "
                    f"{candidate['source']} to {candidate['target']}"
                ),
                "reason": (
                    f"Eliminates {candidate['paths_eliminated']} attack "
                    f"path(s), leaves {candidate['paths_remaining']} "
                    f"remaining, and preserves all defined legitimate paths."
                ),
            }
        )

    if not candidates:
        return recommendations, cloud.copy(), original_paths

    return recommendations, candidates[0]["graph"], original_paths


def main():
    """Run the attack-path analysis and remediation comparison."""
    try:
        environment = load_environment()
        cloud = build_graph(environment)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Could not load cloud environment: {error}")
        return

    entry_point = environment["entry_point"]
    protected_asset = environment["protected_asset"]
    legitimate_paths = environment.get("legitimate_paths", [])

    original_edges = set(cloud.edges())

    attack_paths = find_attack_paths(
        cloud, entry_point, protected_asset
    )

    print("=== Cloud Attack-Path Breaker ===")
    print(f"Resources: {cloud.number_of_nodes()}")
    print(f"Connections: {cloud.number_of_edges()}")
    print(f"Entry point: {entry_point}")
    print(f"Protected asset: {protected_asset}")

    print(f"\n=== Attack Paths: {len(attack_paths)} ===")

    for index, path in enumerate(attack_paths, start=1):
        score, reasons = score_path(cloud, path)

        print(f"\nPath {index}: {' -> '.join(path)}")
        print(f"Risk score: {score}/100")

        for reason in reasons:
            print(f"  - {reason}")

    print("\n=== Required Legitimate Access ===")

    if legitimate_paths:
        for path in legitimate_paths:
            available = all(
                cloud.has_edge(source, target)
                for source, target in zip(path, path[1:])
            )
            status = "AVAILABLE" if available else "MISSING"
            print(f"{' -> '.join(path)}: {status}")
    else:
        print("No legitimate paths configured.")

    recommendations, best_graph, original_paths = (
        recommend_remediations(
            cloud,
            entry_point,
            protected_asset,
            legitimate_paths,
        )
    )

    print("\n=== Ranked Remediation Options ===")

    if not recommendations:
        print(
            "No single-connection fix reduces attack paths "
            "while preserving all required legitimate paths."
        )
    else:
        for recommendation in recommendations:
            print(
                f"\nOption {recommendation['rank']}: "
                f"{recommendation['source']} -> "
                f"{recommendation['target']}"
            )
            print(
                f"  Connection type: "
                f"{recommendation['connection_type']}"
            )
            print(
                f"  Attack paths eliminated: "
                f"{recommendation['paths_eliminated']}"
            )
            print(
                f"  Attack paths remaining: "
                f"{recommendation['paths_remaining']}"
            )
            print(
                f"  Legitimate access preserved: "
                f"{recommendation['legitimate_access_preserved']}"
            )
            print(f"  Action: {recommendation['action']}")
            print(f"  Reason: {recommendation['reason']}")

    remaining_paths = find_attack_paths(
        best_graph, entry_point, protected_asset
    )

    print("\n=== Best Option Simulation ===")
    print(f"Attack paths before: {len(original_paths)}")
    print(f"Attack paths after: {len(remaining_paths)}")
    print(
        "Original graph unchanged: "
        f"{set(cloud.edges()) == original_edges}"
    )
    print(
        "Required access preserved: "
        f"{legitimate_access_preserved(cloud, best_graph, legitimate_paths)}"
    )

    print(
        "\nNote: This is a local simulation. Required access is checked "
        "against explicitly defined paths; this does not prove that every "
        "real-world permission or application behavior remains functional."
    )


if __name__ == "__main__":
    main()
