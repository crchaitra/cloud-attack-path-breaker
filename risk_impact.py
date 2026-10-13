
from main import find_attack_paths, score_path


def measure_remediation_impact(
    original_graph,
    simulated_graph,
    entry_point,
    protected_asset,
):
    """
    Compare illustrative attack-path scores before and after a fix.

    This is a project-specific metric, not a validated risk standard.
    """

    paths_before = find_attack_paths(
        original_graph,
        entry_point,
        protected_asset,
    )

    paths_after = find_attack_paths(
        simulated_graph,
        entry_point,
        protected_asset,
    )

    scores_before = [
        score_path(original_graph, path)[0]
        for path in paths_before
    ]

    scores_after = [
        score_path(simulated_graph, path)[0]
        for path in paths_after
    ]

    total_before = sum(scores_before)
    total_after = sum(scores_after)

    reduction = total_before - total_after

    if total_before > 0:
        reduction_percent = (reduction / total_before) * 100
    else:
        reduction_percent = 0.0

    return {
        "paths_before": len(paths_before),
        "paths_after": len(paths_after),
        "scores_before": scores_before,
        "scores_after": scores_after,
        "total_score_before": total_before,
        "total_score_after": total_after,
        "score_reduction": reduction,
        "reduction_percent": round(reduction_percent, 1),
    }


def print_remediation_impact(impact):
    """Print a readable summary of remediation impact."""

    print("\n=== Remediation Impact ===")

    print(f"Attack paths before: {impact['paths_before']}")
    print(f"Attack paths after: {impact['paths_after']}")

    print(
        "Combined path-risk score before: "
        f"{impact['total_score_before']}"
    )

    print(
        "Combined path-risk score after: "
        f"{impact['total_score_after']}"
    )

    print(f"Illustrative score reduction: {impact['score_reduction']}")

    print(
        "Illustrative percentage reduction: "
        f"{impact['reduction_percent']}%"
    )

    if impact["paths_after"] > 0:
        print("Warning: Attack paths still reach the protected asset.")
    else:
        print("No attack paths remain in this simulation.")
