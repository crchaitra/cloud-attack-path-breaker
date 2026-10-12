
import unittest

from main import (
    build_graph,
    find_attack_paths,
    score_path,
    recommend_remediations,
    legitimate_access_preserved,
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
                {
                    "id": "logging",
                    "name": "Logging Service",
                    "type": "logging",
                    "public": False,
                    "sensitivity": "low",
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
                {
                    "source": "server",
                    "target": "logging",
                    "type": "log_access",
                },
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [["server", "logging"]],
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
        graph = self.graph.copy()
        graph.remove_edge("internet", "storage")
        graph.remove_edge("server", "storage")

        paths = find_attack_paths(graph, "internet", "storage")
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
                self.graph,
                "internet",
                "storage",
                self.environment["legitimate_paths"],
            )
        )

        remaining_paths = find_attack_paths(
            simulated_graph, "internet", "storage"
        )

        self.assertEqual(len(original_paths), 2)
        self.assertGreaterEqual(len(recommendations), 1)
        self.assertEqual(len(remaining_paths), 1)
        self.assertNotIn(["internet", "storage"], remaining_paths)
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
            self.graph,
            "internet",
            "storage",
            self.environment["legitimate_paths"],
        )

        self.assertEqual(set(self.graph.edges()), original_edges)
        self.assertEqual(
            find_attack_paths(self.graph, "internet", "storage"),
            original_paths,
        )

    def test_remediation_preserves_legitimate_access(self):
        recommendations, simulated_graph, _ = recommend_remediations(
            self.graph,
            "internet",
            "storage",
            self.environment["legitimate_paths"],
        )

        self.assertTrue(recommendations)
        self.assertTrue(
            legitimate_access_preserved(
                self.graph,
                simulated_graph,
                self.environment["legitimate_paths"],
            )
        )
        self.assertTrue(simulated_graph.has_edge("server", "logging"))

    def test_remediation_options_are_ranked(self):
        recommendations, _, _ = recommend_remediations(
            self.graph,
            "internet",
            "storage",
            self.environment["legitimate_paths"],
        )

        self.assertTrue(recommendations)

        ranks = [item["rank"] for item in recommendations]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))

        eliminated_counts = [
            item["paths_eliminated"] for item in recommendations
        ]
        self.assertEqual(
            eliminated_counts,
            sorted(eliminated_counts, reverse=True),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

