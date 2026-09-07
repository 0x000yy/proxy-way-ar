"""اختبارات محلية لا تفتح اتصالات خارجية ولا تتصل بعقد Tor."""
import builtins
import importlib.util
import socket
import unittest
from pathlib import Path

FILE = Path(__file__).parents[1] / "PROXY-WAY.py"
spec = importlib.util.spec_from_file_location("proxy_way", FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# منع بدء اكتشاف خارجي أثناء الاختبار.
mod.NodeDiscovery.start_discovery = lambda self: None
mod.NodeDiscovery.stop_discovery = lambda self: None


class اختبار_الأداة(unittest.TestCase):
    def test_crypto_round_trip(self):
        crypto = mod.SecureCrypto()
        crypto.generate_session_key()
        payload = "بيانات اختبار عربية".encode("utf-8")
        encrypted = crypto.encrypt(payload)
        self.assertNotEqual(encrypted, payload)
        self.assertEqual(crypto.decrypt(encrypted), payload)

    def test_discovery_defaults_and_parser(self):
        discovery = mod.NodeDiscovery()
        self.assertEqual(len(discovery.known_nodes), len(mod.DEFAULT_NODES))
        data = "IP PORT\n127.0.0.1 9050\n"
        nodes = discovery.parse_external_nodes(data, "https://api.dan.me.uk/tornodes")
        self.assertTrue(nodes)
        self.assertEqual(nodes[0]["ip"], "127.0.0.1")

    def test_memory_manager(self):
        manager = mod.MemoryManager()
        left, right = socket.socketpair()
        try:
            manager.add_connection("اختبار", left)
            self.assertEqual(manager.get_stats()["total_connections"], 1)
            manager.remove_connection("اختبار")
            self.assertEqual(manager.get_stats()["total_connections"], 0)
        finally:
            right.close()

    def test_menu_exits_in_arabic_mode(self):
        answers = iter(["0"])
        original = builtins.input
        builtins.input = lambda prompt="": next(answers)
        try:
            app = mod.ProxyApp()
            app.main_menu()
        finally:
            builtins.input = original

    def test_proxy_initializes_without_tor(self):
        proxy = mod.ProxyTunnel(listen_port=0, use_encryption=True, use_tor=True)
        try:
            self.assertFalse(proxy.use_tor)
            self.assertFalse(proxy.tor_available)
        finally:
            proxy.stop()


if __name__ == "__main__":
    unittest.main()
