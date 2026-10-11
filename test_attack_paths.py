
import unittest

from main import build_graph, find_attack_paths, score_path


class TestAttackPaths(unittest.TestCase):

    def setUp(self):
        """Create a small test environment for each test."""
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
        """Check that a route to sensitive storage is discovered."""
        paths = find_attack_paths(
            self.graph, "internet", "storage"
        )

        self.assertIn(
            ["internet", "storage"],
            paths,
        )

    def test_finds_multiple_attack_paths(self):
        """Check that both routes to storage are discovered."""
        paths = find_attack_paths(
            self.graph, "internet", "storage"
        )

        self.assertEqual(len(paths), 2)

    def test_returns_no_path_when_unreachable(self):
        """Check that disconnected storage has no attack path."""
        graph = build_graph(self.environment)

        graph.remove_edge("internet", "storage")
        graph.remove_edge("server", "storage")

        paths = find_attack_paths(
            graph, "internet", "storage"
        )

        self.assertEqual(paths, [])

    def test_invalid_configuration_is_rejected(self):
        """Check that duplicate resource IDs are rejected."""
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
        """Check that critical sensitivity contributes 30 points."""
        score, reasons = score_path(
            self.graph,
            ["internet", "storage"],
        )

        self.assertEqual(score, 55)
        self.assertIn(
            "Highest resource sensitivity: critical (+30)",
            reasons,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
