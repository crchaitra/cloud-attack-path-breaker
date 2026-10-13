
import unittest

from main import build_graph
from risk_impact import measure_remediation_impact


class TestRemediationImpact(unittest.TestCase):

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
            ],
            "entry_point": "internet",
            "protected_asset": "storage",
            "legitimate_paths": [],
        }

        self.graph = build_graph(environment)
        self.fixed_graph = self.graph.copy()
        self.fixed_graph.remove_edge("internet", "storage")

    def test_measures_score_before_and_after(self):
        impact = measure_remediation_impact(
            self.graph,
            self.fixed_graph,
            "internet",
            "storage",
        )

        self.assertEqual(impact["total_score_before"], 120)
        self.assertEqual(impact["total_score_after"], 65)

    def test_calculates_score_reduction(self):
        impact = measure_remediation_impact(
            self.graph,
            self.fixed_graph,
            "internet",
            "storage",
        )

        self.assertEqual(impact["score_reduction"], 55)
        self.assertEqual(impact["reduction_percent"], 45.8)

    def test_reports_remaining_attack_path(self):
        impact = measure_remediation_impact(
            self.graph,
            self.fixed_graph,
            "internet",
            "storage",
        )

        self.assertEqual(impact["paths_before"], 2)
        self.assertEqual(impact["paths_after"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
