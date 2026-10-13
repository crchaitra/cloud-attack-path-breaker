
import unittest

from main import build_graph
from validated_remediation import (
    find_validated_multi_edge_remediation,
)


class TestValidatedRemediation(unittest.TestCase):

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
                    "id": "logging",
                    "name": "Logging Service",
                    "type": "logging",
                    "public": False,
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
                    "target": "server",
                    "type": "network_access",
                },
                {
                    "source": "server",
                    "target": "logging",
                    "type": "log_access",
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
        self.required_paths = [
            ["internet", "server", "logging"]
        ]

    def test_valid_path_allows_remediation_search(self):
        result = find_validated_multi_edge_remediation(
            self.graph,
            "internet",
            "storage",
            legitimate_paths=self.required_paths,
            max_removals=2,
        )

        self.assertIsNotNone(result)

    def test_invalid_path_stops_remediation_search(self):
        invalid_paths = [
            ["internet", "logging"]
        ]

        with self.assertRaisesRegex(
            ValueError, "missing connection"
        ):
            find_validated_multi_edge_remediation(
                self.graph,
                "internet",
                "storage",
                legitimate_paths=invalid_paths,
                max_removals=2,
            )

    def test_unknown_resource_stops_remediation_search(self):
        invalid_paths = [
            ["internet", "unknown_resource"]
        ]

        with self.assertRaisesRegex(
            ValueError, "unknown resource"
        ):
            find_validated_multi_edge_remediation(
                self.graph,
                "internet",
                "storage",
                legitimate_paths=invalid_paths,
                max_removals=2,
            )

    def test_original_graph_remains_unchanged(self):
        original_edges = set(self.graph.edges())

        find_validated_multi_edge_remediation(
            self.graph,
            "internet",
            "storage",
            legitimate_paths=self.required_paths,
            max_removals=2,
        )

        self.assertEqual(
            set(self.graph.edges()),
            original_edges,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
