import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "nrich_nmap_orchestrator.py"
SPEC = importlib.util.spec_from_file_location("nrich_nmap_orchestrator", MODULE_PATH)
orchestrator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(orchestrator)


class NrichParserTests(unittest.TestCase):
    def test_parses_supported_host_shapes(self):
        raw = """[
          {"ip":"192.0.2.10","ports":[443,80],"hostnames":["demo.example"]},
          {"address":"198.51.100.20","services":[{"port":53}]}
        ]"""

        findings = orchestrator.parse_nrich_json(raw)

        self.assertEqual(findings["192.0.2.10"].ports_tcp, {80, 443})
        self.assertEqual(findings["192.0.2.10"].domain, "demo.example")
        self.assertEqual(findings["198.51.100.20"].ports_tcp, {53})

    def test_parses_only_definitive_open_nmap_ports(self):
        output = (
            "Host: 192.0.2.10 ()\tPorts: "
            "22/open/tcp//ssh///, 53/open|filtered/udp//domain///, 443/closed/tcp//https///"
        )

        parsed = orchestrator.parse_nmap_grepable(output)

        self.assertEqual(parsed["192.0.2.10"], {"tcp": [22], "udp": []})

    def test_builds_stable_three_column_rows(self):
        finding = orchestrator.HostFinding(
            ip="192.0.2.10",
            ports_tcp={443, 80},
            ports_udp={53},
            domain="demo.example",
        )

        rows = orchestrator.build_rows_single_cell({finding.ip: finding})

        self.assertEqual(
            rows,
            [{
                "ip": "192.0.2.10",
                "ports/protocol": "53/udp, 80/tcp, 443/tcp",
                "dns": "demo.example",
            }],
        )


if __name__ == "__main__":
    unittest.main()
