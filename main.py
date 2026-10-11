
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

# Validate entry point and protected asset
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

# Validate connections and add edges
for connection in connections:
    source = connection["source"]
    target = connection["target"]

    if source not in resource_ids or target not in resource_ids:
        raise ValueError(
            f"Connection references an unknown resource: {source} -> {target}"
        )

    cloud.add_edge(
        source,
        target,
        type=connection["type"]
    )

print("CLOUD ATTACK-PATH BREAKER")
print("=" * 35)
print("Configuration validation passed.")
print(f"Resources: {cloud.number_of_nodes()}")
print(f"Connections: {cloud.number_of_edges()}")
print("\nCLOUD RESOURCES")

for node, details in cloud.nodes(data=True):
    print(f"- {details['name']} ({details['type']})")

# Find all simple attack paths
paths = list(
    nx.all_simple_paths(
        cloud,
        source=entry_point,
        target=protected_asset
    )
)

if paths:
    print(f"\nFound {len(paths)} attack path(s):")

    for number, path in enumerate(paths, start=1):
        names = [cloud.nodes[node]["name"] for node in path]
        print(f"\nPath {number}:")
        print(" -> ".join(names))
else:
    print("\nNo path to the protected asset was found.")
