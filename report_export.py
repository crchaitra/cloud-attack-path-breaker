
import json
from datetime import datetime, timezone


def build_export_report(
    security_report,
    remediation_result=None,
):
    """
    Combine the security assessment and optional remediation
    results into a JSON-serializable export report.
    """

    report = {
        "report_type": security_report["report_type"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "entry_point": security_report["entry_point"],
        "protected_asset": security_report["protected_asset"],
        "resource_count": security_report["resource_count"],
        "connection_count": security_report["connection_count"],
        "attack_path_count": security_report["attack_path_count"],
        "protected_asset_reachable": security_report[
            "protected_asset_reachable"
        ],
        "attack_paths": security_report["attack_paths"],
        "risk_score_note": security_report["risk_score_note"],
        "remediation": None,
    }

    if remediation_result is not None:
        report["remediation"] = {
            "connections_removed": remediation_result[
                "removed_connections"
            ],
            "attack_paths_before": len(
                remediation_result["paths_before"]
            ),
            "attack_paths_after": len(
                remediation_result["paths_after"]
            ),
            "removals_count": remediation_result["removals_count"],
            "legitimate_access_preserved": remediation_result[
                "legitimate_access_preserved"
            ],
            "simulation_only": True,
        }

    return report


def report_to_json(report):
    """Convert the report dictionary into readable JSON text."""

    return json.dumps(
        report,
        indent=4,
        ensure_ascii=False,
    )
