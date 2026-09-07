"""اختبارات محلية لا تفتح اتصالات خارجية ولا تتصل بعقد Tor."""
import builtins
import importlib.util
import socket
from pathlib import Path

FILE = Path(__file__).parents[1] / "PROXY-WAY.py"
spec = importlib.util.spec_from_file_location("proxy_way", FILE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# منع بدء اكتشاف خارجي أثناء الاختبار.
mod.NodeDiscovery.start_discovery = lambda self: None
mod.NodeDiscovery.stop_discovery = lambda self: None


def test_crypto_round_trip():
    crypto = mod.SecureCrypto()
    crypto.generate_session_key()
    payload = b"بيانات اختبار عربية"
    encrypted = crypto.encrypt(payload)
    assert encrypted != payload
    assert crypto.decrypt(encrypted) == payload


def test_discovery_defaults_and_parser():
    discovery = mod.NodeDiscovery()
    assert len(discovery.known_nodes) == len(mod.DEFAULT_NODES)
    data = "IP PORT\\n127.0.0.1 9050\\n"
    nodes = discovery.parse_external_nodes(data, "https://api.dan.me.uk/tornodes")
    assert nodes and nodes[0]["ip"] == "127.0.0.1"


def test_memory_manager():
    manager = mod.MemoryManager()
    left, right = socket.socketpair()
    try:
        manager.add_connection("اختبار", left)
        assert manager.get_stats()["total_connections"] == 1
        manager.remove_connection("اختبار")
        assert manager.get_stats()["total_connections"] == 0
    finally:
        right.close()


def test_menu_exits_in_arabic_mode():
    answers = iter(["0"])
    original = builtins.input
    builtins.input = lambda prompt="": next(answers)
    try:
        app = mod.ProxyApp()
        app.main_menu()
    finally:
        builtins.input = original


def test_proxy_initializes_without_tor():
    proxy = mod.ProxyTunnel(listen_port=0, use_encryption=True, use_tor=True)
    try:
        assert proxy.use_tor is False
        assert proxy.tor_available is False
    finally:
        proxy.stop()
