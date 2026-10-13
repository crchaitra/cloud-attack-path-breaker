
import unittest
import networkx as nx

from misconfiguration_checks import check_misconfigurations


class TestMisconfigurationChecks(unittest.TestCase):

    def test_detects_public_critical_resource(self):
        graph = nx.DiGraph()
        graph.add_node(
            "storage",
            name="Sensitive Storage",
            type="storage",
            public=True,
            sensitivity="critical",
        )

        findings = check_misconfigurations(graph)

        self.assertTrue(
            any(
                finding["rule"] == "Public sensitive resource"
                for finding in findings
            )
        )

    def test_detects_public_storage(self):
        graph = nx.DiGraph()
        graph.add_node(
            "bucket",
            name="Public Bucket",
            type="storage",
            public=True,
            sensitivity="low",
        )

        findings = check_misconfigurations(graph)

        self.assertTrue(
            any(
                finding["rule"] == "Public storage"
                for finding in findings
            )
        )

    def test_ignores_private_critical_storage(self):
        graph = nx.DiGraph()
        graph.add_node(
            "storage",
            name="Private Storage",
            type="storage",
            public=False,
            sensitivity="critical",
        )

        findings = check_misconfigurations(graph)

        self.assertEqual(findings, [])

    def test_ignores_public_low_sensitivity_compute(self):
        graph = nx.DiGraph()
        graph.add_node(
            "server",
            name="Public Web Server",
            type="compute",
            public=True,
            sensitivity="low",
        )

        findings = check_misconfigurations(graph)

        self.assertEqual(findings, [])

    def test_empty_graph_has_no_findings(self):
        graph = nx.DiGraph()

        self.assertEqual(check_misconfigurations(graph), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
