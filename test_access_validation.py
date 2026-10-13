
import unittest

from main import build_graph
from access_validation import (
    validate_legitimate_paths,
    legitimate_access_preserved_strict,
)


class TestAccessValidation(unittest.TestCase):

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
        self.required_path = ["internet", "server", "logging"]

    def test_accepts_valid_multi_step_path(self):
        self.assertTrue(
            validate_legitimate_paths(
                self.graph, [self.required_path]
            )
        )

    def test_rejects_missing_connection(self):
        impossible_path = [
            "internet",
            "server",
            "storage",
            "logging",
        ]

        with self.assertRaisesRegex(
            ValueError, "missing connection"
        ):
            validate_legitimate_paths(
                self.graph, [impossible_path]
            )

    def test_rejects_unknown_resource(self):
        invalid_path = ["internet", "missing_server"]

        with self.assertRaisesRegex(
            ValueError, "unknown resource"
        ):
            validate_legitimate_paths(
                self.graph, [invalid_path]
            )

    def test_detects_broken_required_access_after_fix(self):
        simulated_graph = self.graph.copy()
        simulated_graph.remove_edge("server", "logging")

        self.assertFalse(
            legitimate_access_preserved_strict(
                self.graph,
                simulated_graph,
                [self.required_path],
            )
        )

    def test_accepts_preserved_required_access(self):
        simulated_graph = self.graph.copy()
        simulated_graph.remove_edge("server", "storage")

        self.assertTrue(
            legitimate_access_preserved_strict(
                self.graph,
                simulated_graph,
                [self.required_path],
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
