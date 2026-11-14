"""Offline tests for dry-run cleanup decisions. Never operate on real services."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pqp_cleanup", ROOT / "cleanup.py")
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)


class CleanupTests(unittest.TestCase):
    def test_server_rules(self):
        rules = cleanup.firewall_specs({"role": "server", "port": "29999"})
        self.assertEqual(len(rules), 3)
        self.assertIn(("raw", "PREROUTING", ("-p", "tcp", "--dport", "29999", "-j", "NOTRACK")), rules)

    def test_client_rules(self):
        rules = cleanup.firewall_specs({"role": "client", "port": "29999", "ip": "203.0.113.2"})
        self.assertIn(("raw", "OUTPUT", ("-p", "tcp", "-d", "203.0.113.2", "--dport", "29999", "-j", "NOTRACK")), rules)

    def test_unknown_service_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, units, opt = (root / x for x in ("config", "units", "manager"))
            for d in (base, units, opt):
                d.mkdir()
            (units / "paqet-plus-server-turkey.service").write_text("[Service]\nExecStart=/usr/bin/unknown\n")
            with mock.patch.object(cleanup, "BASE", base), mock.patch.object(cleanup, "UNITDIR", units), mock.patch.object(cleanup, "OPT", opt):
                with self.assertRaises(RuntimeError):
                    cleanup.discover()

    def test_known_service_discovered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            base, units, opt = (root / x for x in ("config", "units", "manager"))
            for d in (base, units, opt):
                d.mkdir()
            cfg = base / "turkey-server.yaml"
            cfg.write_text("role: server\n")
            (units / "paqet-plus-server-turkey.service").write_text("[Service]\nExecStart=/usr/local/bin/paqet run -c " + str(cfg) + "\n")
            (base / "paqet-plus-server-turkey.meta").write_text("ROLE=server\nTUNNEL_NAME=turkey\nPAQET_PORT=29999\nCONFIG=" + str(cfg) + "\n")
            with mock.patch.object(cleanup, "BASE", base), mock.patch.object(cleanup, "UNITDIR", units), mock.patch.object(cleanup, "OPT", opt):
                found = cleanup.discover()
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0]["service"], "paqet-plus-server-turkey")

    def test_saved_rules_remove_only_matching_port(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.v4"
            path.write_text("*raw\n:PREROUTING ACCEPT [0:0]\n"
                            "-A PREROUTING -p tcp -m tcp --dport 29999 -j NOTRACK\n"
                            "-A PREROUTING -p tcp -m tcp --dport 5555 -j NOTRACK\n"
                            "COMMIT\n*mangle\n"
                            "-A OUTPUT -p tcp -m tcp --sport 29999 --tcp-flags RST RST -j DROP\n"
                            "COMMIT\n")
            with mock.patch.object(cleanup, "PERSIST", path):
                self.assertEqual(cleanup.strip_persisted(cleanup.firewall_specs({"role": "server", "port": "29999"})), 2)
                saved = path.read_text()
            self.assertIn("5555", saved)
            self.assertNotIn("29999", saved)

    def test_client_persisted_rules_normalized_without_touching_other_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.v4"
            path.write_text("*raw\n:PREROUTING ACCEPT [0:0]\n"
                            "-A PREROUTING -s 206.1.101.169/32 -p tcp -m tcp --sport 29999 -j NOTRACK\n"
                            "-A OUTPUT -d 206.1.101.169/32 -p tcp -m tcp --dport 29999 -j NOTRACK\n"
                            "-A OUTPUT -d 192.0.2.77/32 -p tcp -m tcp --dport 29999 -j NOTRACK\n"
                            "COMMIT\n*mangle\n"
                            "-A OUTPUT -d 206.1.101.169/32 -p tcp -m tcp --dport 29999 --tcp-flags RST RST -j DROP\n"
                            "-A OUTPUT -d 206.1.101.169/32 -p tcp -m tcp --dport 29999 -m comment --comment other -j NOTRACK\n"
                            "COMMIT\n")
            with mock.patch.object(cleanup, "PERSIST", path):
                count = cleanup.strip_persisted(cleanup.firewall_specs({
                    "role": "client", "port": "29999", "ip": "206.1.101.169"
                }))
                saved = path.read_text()
            self.assertEqual(count, 3)
            self.assertIn("192.0.2.77/32", saved)
            self.assertIn("--comment other", saved)
            self.assertEqual(saved.count("206.1.101.169"), 1)

    def test_no_plaintext_metadata_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.meta"
            path.write_text("ROLE=server\nROLE=client\n")
            with self.assertRaises(RuntimeError):
                cleanup.meta_values(path)


if __name__ == "__main__":
    unittest.main()
