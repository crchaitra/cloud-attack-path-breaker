
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

# Build the cloud graph
cloud = nx.DiGraph()

for resource in resources:
    cloud.add_node(
        resource["id"],
        name=resource["name"],
        type=resource["type"]
    )

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

# Find all simple paths to the protected asset
paths = list(
    nx.all_simple_paths(
        cloud,
        source=entry_point,
        target=protected_asset
    )
)

# Explainable prototype risk scoring
def score_path(path):
    score = 0
    reasons = []

    # Public entry point
    if path[0] == entry_point:
        score += 30
        reasons.append("Starts at the external entry point (+30)")

    # Identity and permission transitions
    identity_steps = 0

    for source, target in zip(path, path[1:]):
        connection_type = cloud.edges[source, target]["type"]

        if connection_type == "assume_role":
            identity_steps += 1

    if identity_steps:
        points = min(identity_steps * 20, 40)
        score += points
        reasons.append(f"Identity permission transitions (+{points})")

    # Sensitive destination
    if path[-1] == protected_asset:
        score += 30
        reasons.append("Reaches sensitive storage (+30)")

    return min(score, 100), reasons


if paths:
    print(f"\nFound {len(paths)} attack path(s):")

    scored_paths = []

    for path in paths:
        score, reasons = score_path(path)
        scored_paths.append((score, path, reasons))

    # Show highest-scoring paths first
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
