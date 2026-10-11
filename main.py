
import networkx as nx

# Create a simulated cloud environment
cloud = nx.DiGraph()

# Add the longer route
cloud.add_edge("Internet", "Web Server")
cloud.add_edge("Web Server", "App Role")
cloud.add_edge("App Role", "Sensitive Storage")

# Add a second, direct route
cloud.add_edge("Internet", "Sensitive Storage")

entry_point = "Internet"
protected_asset = "Sensitive Storage"

print("CLOUD ATTACK-PATH BREAKER")
print("=" * 35)

# Find all simple paths to the protected asset
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
        print(f"\nPath {number}:")
        print(" -> ".join(path))
else:
    print("\nNo path to sensitive storage was found.")
