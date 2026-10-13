
from main import find_attack_paths, score_path


def generate_security_report(
    cloud,
    entry_point,
    protected_asset,
):
    """
    Generate a structured security assessment report.

    Risk scores are illustrative project heuristics,
    not validated real-world risk measurements.
    """

    paths = find_attack_paths(
        cloud,
        entry_point,
        protected_asset,
    )

    path_reports = []

    for path in paths:
        score, reasons = score_path(cloud, path)

        path_reports.append({
            "path": path,
            "risk_score": score,
            "reasons": reasons,
        })

    path_reports.sort(
        key=lambda item: item["risk_score"],
        reverse=True,
    )

    return {
        "report_type": "Cloud Attack-Path Security Assessment",
        "entry_point": entry_point,
        "protected_asset": protected_asset,
        "resource_count": cloud.number_of_nodes(),
        "connection_count": cloud.number_of_edges(),
        "attack_path_count": len(path_reports),
        "protected_asset_reachable": len(path_reports) > 0,
        "attack_paths": path_reports,
        "risk_score_note": (
            "Scores are illustrative project heuristics, "
            "not validated real-world risk ratings."
        ),
    }
