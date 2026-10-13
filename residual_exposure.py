
import networkx as nx

from main import find_attack_paths, score_path


def analyze_residual_exposure(
    simulated_graph,
    entry_point,
    protected_asset,
):
    """
    Identify attack paths and sensitive resources that remain reachable
    after a simulated security fix.
    """

    remaining_paths = find_attack_paths(
        simulated_graph,
        entry_point,
        protected_asset,
    )

    # Find every resource reachable from the entry point.
    reachable_resources = set()

    if entry_point in simulated_graph:
        reachable_resources.add(entry_point)
        reachable_resources.update(
            nx.descendants(simulated_graph, entry_point)
        )

    # Flag resources marked high or critical in the configuration.
    sensitive_resources = []

    for resource_id in sorted(reachable_resources):
        sensitivity = simulated_graph.nodes[resource_id].get(
            "sensitivity", "low"
        )

        if sensitivity in ("high", "critical"):
            sensitive_resources.append(
                {
                    "id": resource_id,
                    "name": simulated_graph.nodes[resource_id].get(
                        "name", resource_id
                    ),
                    "sensitivity": sensitivity,
                }
            )

    # Explain the remaining paths and their illustrative scores.
    path_details = []

    for path in remaining_paths:
        score, reasons = score_path(simulated_graph, path)

        critical_resources_on_path = [
            resource_id
            for resource_id in path
            if simulated_graph.nodes[resource_id].get(
                "sensitivity", "low"
            ) == "critical"
        ]

        path_details.append(
            {
                "path": path,
                "score": score,
                "reasons": reasons,
                "critical_resources": critical_resources_on_path,
            }
        )

    return {
        "remaining_paths": remaining_paths,
        "remaining_path_count": len(remaining_paths),
        "reachable_sensitive_resources": sensitive_resources,
        "path_details": path_details,
        "protected_asset_reachable": (
            protected_asset in reachable_resources
        ),
    }


def print_residual_exposure(report):
    """Print a readable residual-exposure report."""

    print("\n=== Residual Exposure Report ===")

    print(
        f"Attack paths remaining: "
        f"{report['remaining_path_count']}"
    )

    if report["remaining_paths"]:
        for index, details in enumerate(
            report["path_details"], start=1
        ):
            print(
                f"\nPath {index}: "
                f"{' -> '.join(details['path'])}"
            )
            print(
                f"Illustrative risk score: {details['score']}/100"
            )

            if details["critical_resources"]:
                print(
                    "Critical resources on path: "
                    + ", ".join(details["critical_resources"])
                )

            for reason in details["reasons"]:
                print(f"  - {reason}")
    else:
        print("No paths to the protected asset remain.")

    print("\nReachable high/critical resources:")

    if report["reachable_sensitive_resources"]:
        for resource in report["reachable_sensitive_resources"]:
            print(
                f"- {resource['name']} "
                f"({resource['sensitivity']})"
            )
    else:
        print("None found.")

    if report["protected_asset_reachable"]:
        print(
            "\nWARNING: The protected asset is still reachable "
            "from the entry point."
        )
    else:
        print(
            "\nThe protected asset is not reachable from the "
            "entry point in this simulation."
        )
