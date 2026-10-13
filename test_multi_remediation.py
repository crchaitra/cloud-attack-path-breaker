
import unittest

from main import build_graph, find_attack_paths
from multi_remediation import find_multi_edge_remediation


class TestMultiRemediation(unittest.TestCase):

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
                    "target": "logging",
                    "type": "log_access",
                },
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [["server", "logging"]],
        }

        self.graph = build_graph(environment)
        self.legitimate_paths = environment["legitimate_paths"]

    def test_finds_combination_that_blocks_all_attack_paths(self):
        result = find_multi_edge_remediation(
            self.graph,
            "internet",
            "storage",
            self.legitimate_paths,
            max_removals=2,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["paths_after"], [])
        self.assertEqual(result["removals_count"], 2)

    def test_preserves_legitimate_access(self):
        result = find_multi_edge_remediation(
            self.graph,
            "internet",
            "storage",
            self.legitimate_paths,
            max_removals=2,
        )

        self.assertIsNotNone(result)
        self.assertTrue(result["legitimate_access_preserved"])
        self.assertTrue(
            result["graph"].has_edge("server", "logging")
        )

    def test_does_not_modify_original_graph(self):
        original_edges = set(self.graph.edges())

        find_multi_edge_remediation(
            self.graph,
            "internet",
            "storage",
            self.legitimate_paths,
            max_removals=2,
        )

        self.assertEqual(set(self.graph.edges()), original_edges)

    def test_returns_none_when_no_safe_solution_exists(self):
        # The only attack connection is also required for legitimate access.
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
                }
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [["internet", "storage"]],
        }

        graph = build_graph(environment)

        result = find_multi_edge_remediation(
            graph,
            "internet",
            "storage",
            environment["legitimate_paths"],
            max_removals=1,
        )

        self.assertIsNone(result)

    def test_rejects_invalid_search_limit(self):
        with self.assertRaises(ValueError):
            find_multi_edge_remediation(
                self.graph,
                "internet",
                "storage",
                self.legitimate_paths,
                max_removals=0,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
