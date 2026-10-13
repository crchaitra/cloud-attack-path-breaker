
import unittest

from main import build_graph
from residual_exposure import analyze_residual_exposure


class TestResidualExposure(unittest.TestCase):

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
                {
                    "id": "backup",
                    "name": "Backup Storage",
                    "type": "storage",
                    "public": False,
                    "sensitivity": "high",
                },
            ],
            "connections": [
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
                {
                    "source": "internet",
                    "target": "storage",
                    "type": "direct_access",
                },
                {
                    "source": "server",
                    "target": "backup",
                    "type": "storage_access",
                },
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [],
        }

        self.graph = build_graph(environment)

        # Simulate blocking only direct access.
        self.fixed_graph = self.graph.copy()
        self.fixed_graph.remove_edge("internet", "storage")

    def test_detects_remaining_attack_path(self):
        report = analyze_residual_exposure(
            self.fixed_graph, "internet", "storage"
        )

        self.assertEqual(report["remaining_path_count"], 1)
        self.assertEqual(
            report["remaining_paths"][0],
            ["internet", "server", "storage"],
        )

    def test_flags_reachable_critical_storage(self):
        report = analyze_residual_exposure(
            self.fixed_graph, "internet", "storage"
        )

        resource_ids = [
            resource["id"]
            for resource in report["reachable_sensitive_resources"]
        ]

        self.assertIn("storage", resource_ids)
        self.assertTrue(report["protected_asset_reachable"])

    def test_reports_score_for_remaining_path(self):
        report = analyze_residual_exposure(
            self.fixed_graph, "internet", "storage"
        )

        self.assertEqual(len(report["path_details"]), 1)
        self.assertEqual(report["path_details"][0]["score"], 65)
        self.assertIn(
            "storage",
            report["path_details"][0]["critical_resources"],
        )

    def test_reports_no_exposure_after_all_routes_are_blocked(self):
        safe_graph = self.graph.copy()
        safe_graph.remove_edge("internet", "storage")
        safe_graph.remove_edge("server", "storage")

        report = analyze_residual_exposure(
            safe_graph, "internet", "storage"
        )

        self.assertEqual(report["remaining_path_count"], 0)
        self.assertFalse(report["protected_asset_reachable"])

        resource_ids = [
            resource["id"]
            for resource in report["reachable_sensitive_resources"]
        ]

        self.assertNotIn("storage", resource_ids)

    def test_does_not_modify_the_supplied_graph(self):
        original_edges = set(self.fixed_graph.edges())

        analyze_residual_exposure(
            self.fixed_graph, "internet", "storage"
        )

        self.assertEqual(
            set(self.fixed_graph.edges()),
            original_edges,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
