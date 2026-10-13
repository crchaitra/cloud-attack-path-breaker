
import json
import unittest

from main import build_graph
from security_report import generate_security_report


class TestSecurityReport(unittest.TestCase):

    def setUp(self):
        environment = {
            "resources": [
                {
                    "id": "internet",
                    "name": "Internet",
                    "type": "entry_point",
                    "public": True,
                    "sensitivity": "low",
                },
                {
                    "id": "server",
                    "name": "Application Server",
                    "type": "compute",
                    "public": False,
                    "sensitivity": "medium",
                },
                {
                    "id": "storage",
                    "name": "Sensitive Storage",
                    "type": "storage",
                    "public": False,
                    "sensitivity": "critical",
                },
            ],
            "connections": [
                {
                    "source": "internet",
                    "target": "storage",
                    "type": "direct_access",
                },
                {
                    "source": "internet",
                    "target": "server",
                    "type": "network_access",
                },
                {
                    "source": "server",
                    "target": "storage",
                    "type": "storage_access",
                },
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [],
        }

        self.graph = build_graph(environment)

    def test_report_contains_basic_information(self):
        report = generate_security_report(
            self.graph, "internet", "storage"
        )

        self.assertEqual(report["entry_point"], "internet")
        self.assertEqual(report["protected_asset"], "storage")
        self.assertEqual(report["resource_count"], 3)
        self.assertEqual(report["connection_count"], 3)

    def test_report_finds_both_attack_paths(self):
        report = generate_security_report(
            self.graph, "internet", "storage"
        )

        self.assertEqual(report["attack_path_count"], 2)
        self.assertTrue(report["protected_asset_reachable"])

    def test_paths_are_sorted_by_risk_score(self):
        report = generate_security_report(
            self.graph, "internet", "storage"
        )

        scores = [
            item["risk_score"]
            for item in report["attack_paths"]
        ]

        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_report_can_be_converted_to_json(self):
        report = generate_security_report(
            self.graph, "internet", "storage"
        )

        json_text = json.dumps(report)
        restored_report = json.loads(json_text)

        self.assertEqual(
            restored_report["attack_path_count"], 2
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

