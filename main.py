
import json
import networkx as nx


SENSITIVITY_POINTS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


def load_environment(file_path="cloud_environment.json"):
    """Load the simulated cloud environment from a JSON file."""
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_graph(environment):
    """Validate the environment and build its directed graph."""
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
    """Return all simple paths from the entry point to the protected asset."""
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
    """Calculate a simple heuristic risk score for an attack path."""
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


def main():
    """Run the Cloud Attack-Path Breaker command-line program."""
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

    if not paths:
        print("\nNo path to the protected asset was found.")
        return

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


if __name__ == "__main__":
    main()
