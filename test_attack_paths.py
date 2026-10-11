
import unittest

from main import (
    build_graph,
    find_attack_paths,
    score_path,
    recommend_remediations,
)


class TestAttackPaths(unittest.TestCase):

    def setUp(self):
        self.environment = {
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
        }

        self.graph = build_graph(self.environment)

    def test_finds_attack_path(self):
        paths = find_attack_paths(
            self.graph, "internet", "storage"
        )
        self.assertIn(["internet", "storage"], paths)

    def test_finds_multiple_attack_paths(self):
        paths = find_attack_paths(
            self.graph, "internet", "storage"
        )
        self.assertEqual(len(paths), 2)

    def test_returns_no_path_when_unreachable(self):
        graph = build_graph(self.environment)
        graph.remove_edge("internet", "storage")
        graph.remove_edge("server", "storage")

        paths = find_attack_paths(
            graph, "internet", "storage"
        )
        self.assertEqual(paths, [])

    def test_invalid_configuration_is_rejected(self):
        invalid_environment = {
            **self.environment,
            "resources": (
                self.environment["resources"]
                + [self.environment["resources"][0]]
            ),
        }

        with self.assertRaises(ValueError):
            build_graph(invalid_environment)

    def test_critical_asset_increases_risk_score(self):
        score, reasons = score_path(
            self.graph, ["internet", "storage"]
        )

        self.assertEqual(score, 55)
        self.assertIn(
            "Highest resource sensitivity: critical (+30)",
            reasons,
        )

    def test_remediation_removes_direct_access(self):
        recommendations, simulated_graph, original_paths = (
            recommend_remediations(
                self.graph, "internet", "storage"
            )
        )

        remaining_paths = find_attack_paths(
            simulated_graph, "internet", "storage"
        )

        self.assertEqual(len(original_paths), 2)
        self.assertEqual(len(recommendations), 1)
        self.assertEqual(len(remaining_paths), 1)
        self.assertNotIn(
            ["internet", "storage"],
            remaining_paths,
        )

        self.assertEqual(
            recommendations[0]["connection_type"],
            "direct_access",
        )

    def test_remediation_preserves_original_graph(self):
        original_edges = set(self.graph.edges())
        original_paths = find_attack_paths(
            self.graph, "internet", "storage"
        )

        recommend_remediations(
            self.graph, "internet", "storage"
        )

        self.assertEqual(set(self.graph.edges()), original_edges)
        self.assertEqual(
            find_attack_paths(
                self.graph, "internet", "storage"
            ),
            original_paths,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
