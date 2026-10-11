
import json
import networkx as nx


SENSITIVITY_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


def load_environment(file_path="cloud_environment.json"):
    """Load the simulated cloud environment."""
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_graph(environment):
    """Validate the environment and build the directed graph."""
    required_keys = {
        "resources",
        "connections",
        "entry_point",
        "protected_asset",
    }

    if not required_keys.issubset(environment):
        raise ValueError("Environment is missing required keys.")

    resources = environment["resources"]
    connections = environment["connections"]
    entry_point = environment["entry_point"]
    protected_asset = environment["protected_asset"]

    resource_ids = [resource.get("id") for resource in resources]

    if None in resource_ids:
        raise ValueError("Every resource must have an ID.")

    if len(resource_ids) != len(set(resource_ids)):
        raise ValueError("Duplicate resource IDs found.")

    if entry_point not in resource_ids:
        raise ValueError("Entry point does not exist in resources.")

    if protected_asset not in resource_ids:
        raise ValueError("Protected asset does not exist in resources.")

    cloud = nx.DiGraph()

    for resource in resources:
        resource_id = resource["id"]

        if "public" not in resource or "sensitivity" not in resource:
            raise ValueError(
                f"Resource {resource_id} is missing security attributes."
            )

        if not isinstance(resource["public"], bool):
            raise ValueError(
                f"Resource {resource_id} must have a Boolean public value."
            )

        if resource["sensitivity"] not in SENSITIVITY_POINTS:
            raise ValueError(
                f"Invalid sensitivity for resource {resource_id}."
            )

        cloud.add_node(
            resource_id,
            name=resource["name"],
            type=resource["type"],
            public=resource["public"],
            sensitivity=resource["sensitivity"],
        )

    for connection in connections:
        source = connection.get("source")
        target = connection.get("target")
        connection_type = connection.get("type")

        if source not in resource_ids or target not in resource_ids:
            raise ValueError(
                f"Unknown resource in connection: {source} -> {target}"
            )

        if not connection_type:
            raise ValueError(
                f"Connection {source} -> {target} has no type."
            )

        cloud.add_edge(source, target, type=connection_type)

    return cloud


def find_attack_paths(cloud, entry_point, protected_asset):
    """Find all simple paths to the protected asset."""
    if entry_point not in cloud:
        raise ValueError("Entry point does not exist in the graph.")

    if protected_asset not in cloud:
        raise ValueError("Protected asset does not exist in the graph.")

    return list(
        nx.all_simple_paths(
            cloud,
            source=entry_point,
            target=protected_asset,
        )
    )


def score_path(cloud, path):
    """Calculate a simple illustrative risk score."""
    score = 0
    reasons = []

    public_nodes = [
        node for node in path
        if cloud.nodes[node]["public"]
    ]

    if public_nodes:
        score += 25
        reasons.append("Contains publicly exposed resources (+25)")

    identity_steps = sum(
        1
        for source, target in zip(path, path[1:])
        if cloud.edges[source, target]["type"] == "assume_role"
    )

    if identity_steps:
        points = min(identity_steps * 20, 40)
        score += points
        reasons.append(
            f"Identity permission transitions (+{points})"
        )

    most_sensitive = max(
        (cloud.nodes[node]["sensitivity"] for node in path),
        key=lambda value: SENSITIVITY_POINTS[value],
    )

    points = SENSITIVITY_POINTS[most_sensitive]
    score += points
    reasons.append(
        f"Highest resource sensitivity: {most_sensitive} (+{points})"
    )

    return min(score, 100), reasons


def recommend_remediations(cloud, protected_asset):
    """Recommend and simulate restricting direct access to protected storage."""
    if protected_asset not in cloud:
        raise ValueError("Protected asset does not exist in the graph.")

    # Copy the graph so the original environment is not changed.
    simulated_graph = cloud.copy()
    recommendations = []

    direct_sources = list(
        simulated_graph.predecessors(protected_asset)
    )

    for source in direct_sources:
        edge_type = simulated_graph.edges[
            source, protected_asset
        ]["type"]

        if edge_type == "direct_access":
            recommendations.append({
                "source": source,
                "target": protected_asset,
                "connection_type": edge_type,
                "action": (
                    f"Remove or restrict direct access from "
                    f"{source} to {protected_asset}"
                ),
            })

            simulated_graph.remove_edge(source, protected_asset)

    return recommendations, simulated_graph


def main():
    """Run the Cloud Attack-Path Breaker."""
    environment = load_environment()
    cloud = build_graph(environment)

    entry_point = environment["entry_point"]
    protected_asset = environment["protected_asset"]

    print("CLOUD ATTACK-PATH BREAKER")
    print("=" * 40)
    print("Configuration validation passed.")
    print(f"Resources: {cloud.number_of_nodes()}")
    print(f"Connections: {cloud.number_of_edges()}")

    print("\nResources:")
    for node, attributes in cloud.nodes(data=True):
        print(
            f"- {attributes['name']} "
            f"({attributes['type']}, ID: {node})"
        )

    paths = find_attack_paths(cloud, entry_point, protected_asset)

    print(f"\nFound {len(paths)} attack path(s):")

    scored_paths = []

    for path in paths:
        score, reasons = score_path(cloud, path)
        scored_paths.append((score, path, reasons))

    scored_paths.sort(key=lambda item: item[0], reverse=True)

    for number, (score, path, reasons) in enumerate(
        scored_paths, start=1
    ):
        names = [cloud.nodes[node]["name"] for node in path]

        print(f"\nPath {number}: {' -> '.join(names)}")
        print(f"Risk score: {score}/100")

        for reason in reasons:
            print(f"  - {reason}")

    # Recommend and simulate remediation.
    print("\n" + "=" * 40)
    print("REMEDIATION RECOMMENDATIONS")
    print("=" * 40)

    recommendations, simulated_graph = recommend_remediations(
        cloud, protected_asset
    )

    if not recommendations:
        print("No direct-access remediation recommendations found.")
    else:
        for number, recommendation in enumerate(
            recommendations, start=1
        ):
            print(f"\nRecommendation {number}:")
            print(f"  Action: {recommendation['action']}")
            print(
                f"  Connection: {recommendation['source']} -> "
                f"{recommendation['target']}"
            )

    # Verify whether the simulated change removes attack paths.
    remaining_paths = find_attack_paths(
        simulated_graph, entry_point, protected_asset
    )

    print("\nSIMULATION RESULTS")
    print("-" * 40)
    print(f"Attack paths before remediation: {len(paths)}")
    print(f"Attack paths after remediation: {len(remaining_paths)}")

    if len(remaining_paths) < len(paths):
        print("Result: The simulation reduced the number of attack paths.")
    else:
        print("Result: No reduction in attack paths was achieved.")

    if remaining_paths:
        print("\nRemaining attack paths:")
        for path in remaining_paths:
            names = [
                simulated_graph.nodes[node]["name"]
                for node in path
            ]
            print(f"- {' -> '.join(names)}")
    else:
        print("No attack paths to the protected asset remain.")

    print("\nOriginal graph unchanged:", cloud.number_of_edges() == 7)


if __name__ == "__main__":
    main()
