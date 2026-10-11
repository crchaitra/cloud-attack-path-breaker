
import json
import networkx as nx

# Load the simulated cloud environment
with open("cloud_environment.json", "r", encoding="utf-8") as file:
    environment = json.load(file)

resources = environment["resources"]
connections = environment["connections"]
entry_point = environment["entry_point"]
protected_asset = environment["protected_asset"]

# Validate resource IDs
resource_ids = [resource["id"] for resource in resources]

if len(resource_ids) != len(set(resource_ids)):
    raise ValueError("Duplicate resource IDs found.")

if entry_point not in resource_ids:
    raise ValueError("Entry point does not exist in resources.")

if protected_asset not in resource_ids:
    raise ValueError("Protected asset does not exist in resources.")

# Build the cloud graph with security attributes
cloud = nx.DiGraph()

for resource in resources:
    if "public" not in resource or "sensitivity" not in resource:
        raise ValueError(
            f"Resource {resource['id']} is missing security attributes."
        )

    if resource["sensitivity"] not in {
        "low", "medium", "high", "critical"
    }:
        raise ValueError(
            f"Invalid sensitivity for resource {resource['id']}."
        )

    cloud.add_node(
        resource["id"],
        name=resource["name"],
        type=resource["type"],
        public=resource["public"],
        sensitivity=resource["sensitivity"]
    )

# Validate and add connections
for connection in connections:
    source = connection["source"]
    target = connection["target"]

    if source not in resource_ids or target not in resource_ids:
        raise ValueError(
            f"Unknown resource in connection: {source} -> {target}"
        )

    cloud.add_edge(
        source,
        target,
        type=connection["type"]
    )

print("CLOUD ATTACK-PATH BREAKER")
print("=" * 40)
print("Configuration validation passed.")
print(f"Resources: {cloud.number_of_nodes()}")
print(f"Connections: {cloud.number_of_edges()}")

# Risk weights for resource sensitivity
sensitivity_points = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30
}

def score_path(path):
    score = 0
    reasons = []

    # Score public resources along the path
    public_nodes = [
        node for node in path
        if cloud.nodes[node]["public"]
    ]

    if public_nodes:
        score += 25
        reasons.append("Contains publicly exposed resources (+25)")

    # Score identity permission transitions
    identity_steps = sum(
        1
        for source, target in zip(path, path[1:])
        if cloud.edges[source, target]["type"] == "assume_role"
    )

    if identity_steps:
        points = min(identity_steps * 20, 40)
        score += points
        reasons.append(f"Identity permission transitions (+{points})")

    # Score the most sensitive resource on the path
    most_sensitive = max(
        (cloud.nodes[node]["sensitivity"] for node in path),
        key=lambda value: sensitivity_points[value]
    )

    points = sensitivity_points[most_sensitive]
    score += points
    reasons.append(
        f"Highest resource sensitivity: {most_sensitive} (+{points})"
    )

    return min(score, 100), reasons


# Find every simple path to the protected asset
paths = list(
    nx.all_simple_paths(
        cloud,
        source=entry_point,
        target=protected_asset
    )
)

if paths:
    print(f"\nFound {len(paths)} attack path(s):")

    scored_paths = []

    for path in paths:
        score, reasons = score_path(path)
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
else:
    print("\nNo path to the protected asset was found.")
