#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
# PROXY TUNNEL v3.0 - الإصدار المتكامل النهائي
# ================================================================
# [عقد افتراضية + اكتشاف تلقائي + إدارة ذاكرة متقدمة]
# ================================================================

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import random
import socket
import threading
import subprocess
import hashlib
import base64
import struct
import logging
import signal
import gc
import queue
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import urlparse
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ================================================================
# 1. العقد الافتراضية
# ================================================================

DEFAULT_NODES = [
    # عقد Tor العامة (مثال)
    {'id': 'tor_node_001', 'ip': '185.220.101.1', 'port': 9050, 'type': 'entry', 'country': 'DE', 'status': 'active'},
    {'id': 'tor_node_002', 'ip': '185.220.101.2', 'port': 9051, 'type': 'middle', 'country': 'NL', 'status': 'active'},
    {'id': 'tor_node_003', 'ip': '185.220.101.3', 'port': 9052, 'type': 'exit', 'country': 'FR', 'status': 'active'},
    
    # عقد إضافية
    {'id': 'tor_node_004', 'ip': '193.218.118.1', 'port': 9050, 'type': 'entry', 'country': 'US', 'status': 'active'},
    {'id': 'tor_node_005', 'ip': '193.218.118.2', 'port': 9051, 'type': 'middle', 'country': 'CA', 'status': 'active'},
    {'id': 'tor_node_006', 'ip': '193.218.118.3', 'port': 9052, 'type': 'exit', 'country': 'UK', 'status': 'active'},
    
    # عقد محلية (للتطوير)
    {'id': 'local_node_001', 'ip': '127.0.0.1', 'port': 9050, 'type': 'entry', 'country': 'Local', 'status': 'active'},
    {'id': 'local_node_002', 'ip': '127.0.0.1', 'port': 9051, 'type': 'middle', 'country': 'Local', 'status': 'active'},
    {'id': 'local_node_003', 'ip': '127.0.0.1', 'port': 9052, 'type': 'exit', 'country': 'Local', 'status': 'active'},
]

# ================================================================
# 2. نظام التشفير المتقدم
# ================================================================

class SecureCrypto:
    """نظام تشفير مع تبادل مفاتيح RSA + AES"""
    
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.session_key = None
        self.cipher = None
        self.peer_public_keys = {}
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def load_peer_public_key(self, peer_id, pem_key):
        try:
            key = serialization.load_pem_public_key(
                pem_key.encode(),
                backend=default_backend()
            )
            self.peer_public_keys[peer_id] = key
            return True
        except:
            return False
    
    def generate_session_key(self):
        self.session_key = base64.urlsafe_b64encode(os.urandom(32))
        self.cipher = Fernet(self.session_key)
        return self.session_key
    
    def encrypt_session_key(self, peer_id):
        if peer_id not in self.peer_public_keys:
            return None
        peer_key = self.peer_public_keys[peer_id]
        encrypted = peer_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    def decrypt_session_key(self, encrypted_key):
        try:
            data = base64.b64decode(encrypted_key)
            decrypted = self.private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.session_key = decrypted
            self.cipher = Fernet(self.session_key)
            return True
        except:
            return False
    
    def encrypt(self, data):
        if not self.cipher:
            return data
        if isinstance(data, str):
            data = data.encode()
        return self.cipher.encrypt(data)
    
    def decrypt(self, data):
        if not self.cipher:
            return data
        try:
            return self.cipher.decrypt(data)
        except:
            return data
    
    def sign_data(self, data):
        if isinstance(data, str):
            data = data.encode()
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, data, signature, peer_id):
        if peer_id not in self.peer_public_keys:
            return False
        try:
            self.peer_public_keys[peer_id].verify(
                base64.b64decode(signature),
                data.encode() if isinstance(data, str) else data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

# ================================================================
# 3. نظام إدارة الذاكرة المتقدم
# ================================================================

class MemoryManager:
    """إدارة الذاكرة المتقدمة مع تنظيف تلقائي"""
    
    def __init__(self):
        self.logger = self._get_logger()
        self.connections = {}
        self.lock = threading.Lock()
        self.last_cleanup = datetime.now()
        self.cleanup_interval = 60  # ثانية
    
    def _get_logger(self):
        class Logger:
            def info(self, msg): print(f"[Memory] {msg}")
            def warning(self, msg): print(f"[!] {msg}")
            def debug(self, msg): print(f"[*] {msg}")
        return Logger()
    
    def add_connection(self, conn_id, sock):
        """إضافة اتصال للإدارة"""
        with self.lock:
            self.connections[conn_id] = {
                'sock': sock,
                'created': datetime.now(),
                'last_activity': datetime.now(),
                'active': True
            }
            self.check_cleanup()
    
    def update_activity(self, conn_id):
        """تحديث وقت آخر نشاط"""
        with self.lock:
            if conn_id in self.connections:
                self.connections[conn_id]['last_activity'] = datetime.now()
    
    def remove_connection(self, conn_id):
        """إزالة اتصال"""
        with self.lock:
            if conn_id in self.connections:
                try:
                    self.connections[conn_id]['sock'].close()
                except:
                    pass
                del self.connections[conn_id]
    
    def check_cleanup(self):
        """التحقق من الحاجة للتنظيف"""
        if (datetime.now() - self.last_cleanup).seconds > self.cleanup_interval:
            self.cleanup()
            self.last_cleanup = datetime.now()
    
    def cleanup(self):
        """تنظيف الاتصالات الميتة"""
        with self.lock:
            to_remove = []
            for conn_id, conn in self.connections.items():
                # إزالة الاتصالات القديمة (أكثر من 5 دقائق بدون نشاط)
                if (datetime.now() - conn['last_activity']).seconds > 300:
                    to_remove.append(conn_id)
                # إزالة الاتصالات المغلقة
                try:
                    if not conn['active']:
                        to_remove.append(conn_id)
                except:
                    to_remove.append(conn_id)
            
            for conn_id in to_remove:
                try:
                    self.connections[conn_id]['sock'].close()
                except:
                    pass
                del self.connections[conn_id]
            
            # إجبار جمع القمامة
            if len(to_remove) > 10:
                gc.collect()
            
            self.logger.debug(f"Cleaned {len(to_remove)} connections")
    
    def get_stats(self):
        """الحصول على إحصائيات الذاكرة"""
        with self.lock:
            return {
                'total_connections': len(self.connections),
                'active_connections': len([c for c in self.connections.values() if c['active']]),
                'last_cleanup': self.last_cleanup.isoformat()
            }

# ================================================================
# 4. نظام اكتشاف العقد التلقائي (P2P Discovery)
# ================================================================

class NodeDiscovery:
    """اكتشاف العقد التلقائي في الشبكة"""
    
    def __init__(self):
        self.logger = self._get_logger()
        self.known_nodes = {}
        self.discovery_interval = 300  # 5 دقائق
        self.running = False
        self.discovery_thread = None
        
        # تحميل العقد الافتراضية
        self.load_default_nodes()
    
    def _get_logger(self):
        class Logger:
            def info(self, msg): print(f"[Discovery] {msg}")
            def warning(self, msg): print(f"[!] {msg}")
            def debug(self, msg): print(f"[*] {msg}")
        return Logger()
    
    def load_default_nodes(self):
        """تحميل العقد الافتراضية"""
        for node in DEFAULT_NODES:
            self.known_nodes[node['id']] = node
        self.logger.info(f"Loaded {len(DEFAULT_NODES)} default nodes")
    
    def start_discovery(self):
        """بدء اكتشاف العقد"""
        if self.running:
            return
        self.running = True
        self.discovery_thread = threading.Thread(target=self.discovery_loop, daemon=True)
        self.discovery_thread.start()
        self.logger.info("Node discovery started")
    
    def stop_discovery(self):
        """إيقاف اكتشاف العقد"""
        self.running = False
        if self.discovery_thread:
            self.discovery_thread.join(timeout=2)
        self.logger.info("Node discovery stopped")
    
    def discovery_loop(self):
        """حلقة اكتشاف العقد"""
        while self.running:
            try:
                self.discover_nodes()
                time.sleep(self.discovery_interval)
            except Exception as e:
                self.logger.warning(f"Discovery error: {e}")
                time.sleep(30)
    
    def discover_nodes(self):
        """اكتشاف عقد جديدة"""
        self.logger.debug("Discovering new nodes...")
        
        # 1. طلب قائمة العقد من العقد المعروفة
        for node_id, node in list(self.known_nodes.items()):
            if node.get('status') != 'active':
                continue
            try:
                new_nodes = self.query_node_for_peers(node)
                if new_nodes:
                    for n in new_nodes:
                        if n['id'] not in self.known_nodes:
                            self.known_nodes[n['id']] = n
                            self.logger.info(f"Discovered new node: {n['id']} at {n['ip']}:{n['port']}")
            except Exception as e:
                self.logger.debug(f"Failed to query {node_id}: {e}")
        
        # 2. البحث عن عقد من مصادر خارجية
        self.discover_from_external()
        
        self.logger.debug(f"Total known nodes: {len(self.known_nodes)}")
    
    def query_node_for_peers(self, node):
        """سؤال عقدة عن العقد الأخرى التي تعرفها"""
        try:
            # محاولة الاتصال بالعقدة وطلب قائمة العقد
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((node['ip'], node['port']))
            
            # إرسال طلب قائمة العقد
            sock.send(b"LIST_NODES")
            
            # استقبال الرد
            data = sock.recv(4096)
            sock.close()
            
            # تحليل البيانات
            try:
                nodes = json.loads(data.decode())
                return nodes
            except:
                return None
                
        except Exception as e:
            self.logger.debug(f"Query failed: {e}")
            return None
    
    def discover_from_external(self):
        """اكتشاف عقد من مصادر خارجية"""
        try:
            # مصادر خارجية للعقد
            sources = [
                "https://api.dan.me.uk/tornodes",
                "https://onionoo.torproject.org/summary",
                "https://torstatus.blutmagie.de/query_exit.php"
            ]
            
            for source in sources:
                try:
                    response = requests.get(source, timeout=10)
                    if response.status_code == 200:
                        # معالجة البيانات حسب المصدر
                        nodes = self.parse_external_nodes(response.text, source)
                        for node in nodes:
                            if node['id'] not in self.known_nodes:
                                self.known_nodes[node['id']] = node
                                self.logger.info(f"Discovered external node: {node['id']}")
                except:
                    pass
                    
        except Exception as e:
            self.logger.warning(f"External discovery error: {e}")
    
    def parse_external_nodes(self, data, source):
        """تحليل بيانات العقد من مصادر خارجية"""
        nodes = []
        try:
            if 'torproject' in source:
                # بيانات من Tor Project
                json_data = json.loads(data)
                for item in json_data.get('relays', []):
                    nodes.append({
                        'id': item.get('fingerprint', 'unknown')[:8],
                        'ip': item.get('or_addresses', ['0.0.0.0'])[0].split(':')[0],
                        'port': 9050,
                        'type': 'middle',
                        'country': item.get('country', 'Unknown'),
                        'status': 'active'
                    })
            elif 'dan.me.uk' in source:
                # بيانات من dan.me.uk
                lines = data.strip().split('\n')
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        nodes.append({
                            'id': f"external_{hashlib.md5(line.encode()).hexdigest()[:8]}",
                            'ip': parts[0],
                            'port': int(parts[1]) if parts[1].isdigit() else 9050,
                            'type': 'middle',
                            'country': 'Unknown',
                            'status': 'active'
                        })
        except:
            pass
        return nodes[:10]  # حد أقصى 10 عقد
    
    def get_active_nodes(self):
        """الحصول على العقد النشطة"""
        return [n for n in self.known_nodes.values() if n.get('status') == 'active']
    
    def get_random_nodes(self, count=3):
        """الحصول على عقد عشوائية"""
        active = self.get_active_nodes()
        if len(active) < count:
            return active
        return random.sample(active, count)

# ================================================================
# 5. خادم العقدة المتقدم
# ================================================================

class ProxyNode:
    """خادم عقدة متقدم مع دعم اكتشاف العقد"""
    
    def __init__(self, listen_port=9050, node_type='middle', node_id=None):
        self.listen_port = listen_port
        self.node_type = node_type
        self.node_id = node_id or f"node_{random.randint(1000, 9999)}"
        self.running = False
        self.logger = self._get_logger()
        self.crypto = SecureCrypto()
        self.memory_manager = MemoryManager()
        self.discovery = NodeDiscovery()
        self.connections = {}
        self.lock = threading.Lock()
        self.server = None
        
        # بدء اكتشاف العقد
        self.discovery.start_discovery()
    
    def _get_logger(self):
        class Logger:
            def info(self, msg): print(f"[+] [{self.node_id}] {msg}")
            def error(self, msg): print(f"[-] [{self.node_id}] {msg}")
            def warning(self, msg): print(f"[!] [{self.node_id}] {msg}")
            def debug(self, msg): print(f"[*] [{self.node_id}] {msg}")
        return Logger()
    
    def start(self):
        """تشغيل خادم العقدة"""
        self.logger.info(f"Starting {self.node_type} node on port {self.listen_port}")
        self.logger.info(f"Node ID: {self.node_id}")
        self.logger.info(f"Public Key: {self.crypto.get_public_key_pem()[:50]}...")
        
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server.bind(('0.0.0.0', self.listen_port))
            self.server.listen(100)
            self.logger.info(f"Node running on 0.0.0.0:{self.listen_port}")
            
            while self.running:
                try:
                    client_sock, client_addr = self.server.accept()
                    conn_id = f"{client_addr[0]}:{client_addr[1]}_{int(time.time())}"
                    self.memory_manager.add_connection(conn_id, client_sock)
                    threading.Thread(
                        target=self.handle_connection,
                        args=(client_sock, client_addr, conn_id),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Accept error: {e}")
                    
        except Exception as e:
            self.logger.error(f"Node error: {e}")
        finally:
            if self.server:
                self.server.close()
    
    def handle_connection(self, client_sock, client_addr, conn_id):
        """معالجة اتصال وارد"""
        try:
            data = client_sock.recv(4096)
            if not data:
                self.memory_manager.remove_connection(conn_id)
                client_sock.close()
                return
            
            # تحديث وقت النشاط
            self.memory_manager.update_activity(conn_id)
            
            # معالجة الطلب
            data_str = data.decode('utf-8', errors='ignore')
            
            if data_str.startswith('LIST_NODES'):
                # طلب قائمة العقد
                self.handle_list_nodes(client_sock)
            elif data_str.startswith('KEY_EXCHANGE'):
                # تبادل المفاتيح
                self.handle_key_exchange(client_sock, data_str)
            elif data_str.startswith('HTTP') or ':' in data_str:
                # طلب HTTP أو اتصال TCP
                self.handle_forward(client_sock, data_str)
            else:
                # بيانات مشفرة
                self.handle_encrypted(client_sock, data_str)
                
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        finally:
            self.memory_manager.remove_connection(conn_id)
            client_sock.close()
    
    def handle_list_nodes(self, client_sock):
        """معالجة طلب قائمة العقد"""
        try:
            # إرسال قائمة العقد المعروفة
            nodes = self.discovery.get_active_nodes()
            response = json.dumps(nodes[:20])  # حد أقصى 20 عقدة
            client_sock.send(response.encode())
        except Exception as e:
            self.logger.error(f"List nodes error: {e}")
    
    def handle_key_exchange(self, client_sock, data_str):
        """معالجة تبادل المفاتيح"""
        try:
            parts = data_str.split('::')
            if len(parts) < 3:
                return
            
            peer_id = parts[1]
            public_key_pem = parts[2]
            
            if self.crypto.load_peer_public_key(peer_id, public_key_pem):
                self.logger.info(f"Loaded public key from peer: {peer_id}")
                self.crypto.generate_session_key()
                encrypted_key = self.crypto.encrypt_session_key(peer_id)
                
                response = f"KEY_EXCHANGE::{self.node_id}::{self.crypto.get_public_key_pem()}::{encrypted_key}"
                client_sock.send(response.encode())
                self.logger.info(f"Key exchange completed with {peer_id}")
            else:
                self.logger.error(f"Failed to load public key from {peer_id}")
                
        except Exception as e:
            self.logger.error(f"Key exchange error: {e}")
    
    def handle_forward(self, client_sock, data_str):
        """معالجة التوجيه"""
        try:
            if data_str.startswith('HTTP'):
                parts = data_str.split('::')
                if len(parts) >= 4:
                    _, host, port, request = parts[0], parts[1], parts[2], '::'.join(parts[3:])
                    port = int(port)
                    self.handle_http(client_sock, host, port, request)
            else:
                if ':' in data_str:
                    host, port = data_str.split(':')
                    port = int(port)
                    self.handle_tunnel(client_sock, host, port)
        except Exception as e:
            self.logger.error(f"Forward error: {e}")
    
    def handle_tunnel(self, client_sock, host, port):
        """معالجة اتصال TCP"""
        try:
            if self.node_type == 'exit':
                self.logger.debug(f"Exit node connecting to {host}:{port}")
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(10)
                target_sock.connect((host, port))
                self.bridge_connections(client_sock, target_sock)
            else:
                self.logger.debug(f"Forwarding to next hop")
                self.forward_to_next(client_sock, host, port)
                
        except Exception as e:
            self.logger.error(f"Tunnel error: {e}")
    
    def handle_http(self, client_sock, host, port, request):
        """معالجة طلب HTTP"""
        try:
            if self.node_type == 'exit':
                self.logger.debug(f"Exit node requesting {host}:{port}")
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(10)
                target_sock.connect((host, port))
                target_sock.send(request.encode())
                
                response = target_sock.recv(8192)
                if self.crypto.cipher:
                    response = self.crypto.encrypt(response)
                
                client_sock.send(response)
                target_sock.close()
            else:
                self.logger.debug("Forwarding HTTP to next hop")
                self.forward_http_next(client_sock, host, port, request)
                
        except Exception as e:
            self.logger.error(f"HTTP error: {e}")
    
    def forward_to_next(self, client_sock, host, port):
        """تمرير الاتصال إلى العقدة التالية"""
        try:
            # استخدام اكتشاف العقد للحصول على عقدة
            peers = self.discovery.get_random_nodes(1)
            if not peers:
                self.logger.warning("No peers available, using direct connection")
                self.handle_tunnel_direct(client_sock, host, port)
                return
            
            next_node = peers[0]
            self.logger.debug(f"Forwarding to {next_node['id']} at {next_node['ip']}:{next_node['port']}")
            
            next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_sock.settimeout(10)
            next_sock.connect((next_node['ip'], next_node['port']))
            
            # تبادل المفاتيح
            self.perform_key_exchange(next_sock, next_node['id'])
            
            # إرسال البيانات المشفرة
            data = f"{host}:{port}".encode()
            encrypted = self.crypto.encrypt(data)
            next_sock.send(encrypted)
            
            self.bridge_connections(client_sock, next_sock)
            
        except Exception as e:
            self.logger.error(f"Forward error: {e}")
    
    def forward_http_next(self, client_sock, host, port, request):
        """تمرير طلب HTTP إلى العقدة التالية"""
        try:
            peers = self.discovery.get_random_nodes(1)
            if not peers:
                self.handle_http_direct(client_sock, host, port, request)
                return
            
            next_node = peers[0]
            next_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            next_sock.settimeout(10)
            next_sock.connect((next_node['ip'], next_node['port']))
            
            self.perform_key_exchange(next_sock, next_node['id'])
            
            data = f"HTTP::{host}::{port}::{request}".encode()
            encrypted = self.crypto.encrypt(data)
            next_sock.send(encrypted)
            
            response = next_sock.recv(8192)
            decrypted = self.crypto.decrypt(response)
            
            client_sock.send(decrypted)
            next_sock.close()
            
        except Exception as e:
            self.logger.error(f"HTTP forward error: {e}")
    
    def perform_key_exchange(self, sock, peer_id):
        """تبادل المفاتيح مع عقدة أخرى"""
        try:
            key_data = f"KEY_EXCHANGE::{self.node_id}::{self.crypto.get_public_key_pem()}"
            sock.send(key_data.encode())
            
            response = sock.recv(4096)
            response_str = response.decode('utf-8', errors='ignore')
            
            if response_str.startswith('KEY_EXCHANGE'):
                parts = response_str.split('::')
                if len(parts) >= 4:
                    peer_id = parts[1]
                    peer_public_key = parts[2]
                    encrypted_session_key = parts[3]
                    
                    if self.crypto.load_peer_public_key(peer_id, peer_public_key):
                        if self.crypto.decrypt_session_key(encrypted_session_key):
                            self.logger.info(f"Key exchange successful with {peer_id}")
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Key exchange failed: {e}")
            return False
    
    def bridge_connections(self, sock1, sock2):
        """ربط اتصالين معاً"""
        try:
            sock1.setblocking(True)
            sock2.setblocking(True)
            
            while self.running:
                try:
                    data = sock1.recv(4096)
                    if not data:
                        break
                    
                    if self.crypto.cipher:
                        data = self.crypto.encrypt(data)
                    
                    sock2.send(data)
                    
                    data = sock2.recv(4096)
                    if not data:
                        break
                    
                    if self.crypto.cipher:
                        data = self.crypto.decrypt(data)
                    
                    sock1.send(data)
                    
                except socket.timeout:
                    continue
                except:
                    break
                    
        except:
            pass
        finally:
            try:
                sock1.close()
            except:
                pass
            try:
                sock2.close()
            except:
                pass
    
    def handle_tunnel_direct(self, client_sock, host, port):
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(10)
            target_sock.connect((host, port))
            self.bridge_connections(client_sock, target_sock)
        except:
            pass
    
    def handle_http_direct(self, client_sock, host, port, request):
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(10)
            target_sock.connect((host, port))
            target_sock.send(request.encode())
            response = target_sock.recv(8192)
            client_sock.send(response)
            target_sock.close()
        except:
            pass
    
    def handle_encrypted(self, client_sock, data_str):
        try:
            decrypted = self.crypto.decrypt(data_str.encode())
            data_str = decrypted.decode('utf-8', errors='ignore')
            if data_str.startswith('HTTP'):
                self.handle_forward(client_sock, data_str)
        except:
            pass
    
    def stop(self):
        self.running = False
        self.discovery.stop_discovery()
        if self.server:
            try:
                self.server.close()
            except:
                pass
        self.memory_manager.cleanup()
        self.logger.info("Node stopped")

# ================================================================
# 6. خادم البروكسي المتقدم
# ================================================================

class ProxyTunnel:
    """خادم بروكسي متقدم مع اكتشاف تلقائي للعقد"""
    
    def __init__(self, listen_port=8080, use_encryption=True, use_tor=False):
        self.listen_port = listen_port
        self.use_encryption = use_encryption
        self.use_tor = use_tor
        self.running = False
        self.logger = self._get_logger()
        self.crypto = SecureCrypto()
        self.discovery = NodeDiscovery()
        self.memory_manager = MemoryManager()
        
        # بدء اكتشاف العقد
        self.discovery.start_discovery()
        
        # التحقق من Tor
        self.tor_available = self.check_tor()
        if use_tor and not self.tor_available:
            self.logger.warning("Tor not available, falling back to proxy mode")
            self.use_tor = False
    
    def _get_logger(self):
        class Logger:
            def info(self, msg): print(f"[+] {msg}")
            def error(self, msg): print(f"[-] {msg}")
            def warning(self, msg): print(f"[!] {msg}")
            def success(self, msg): print(f"[✓] {msg}")
            def debug(self, msg): print(f"[*] {msg}")
            def section(self, msg): print(f"\n{'='*60}\n{msg}\n{'='*60}")
        return Logger()
    
    def check_tor(self):
        try:
            import stem
            from stem.control import Controller
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                return True
        except:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(('127.0.0.1', 9050))
                return True
            except:
                return False
            finally:
                if sock is not None:
                    sock.close()
    
    def start(self):
        self.logger.section("🚀 Starting Proxy Tunnel v3.0")
        self.logger.info(f"Listening on port: {self.listen_port}")
        self.logger.info(f"Encryption: {'Enabled' if self.use_encryption else 'Disabled'}")
        self.logger.info(f"Tor Integration: {'Enabled' if self.use_tor else 'Disabled'}")
        self.logger.info(f"Known nodes: {len(self.discovery.known_nodes)}")
        
        self.running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', self.listen_port))
            server.listen(100)
            self.logger.success(f"Proxy server running on 0.0.0.0:{self.listen_port}")
            
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    conn_id = f"{client_addr[0]}:{client_addr[1]}_{int(time.time())}"
                    self.memory_manager.add_connection(conn_id, client_sock)
                    threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr, conn_id),
                        daemon=True
                    ).start()
                except Exception as e:
                    self.logger.error(f"Accept error: {e}")
                    
        except Exception as e:
            self.logger.error(f"Server error: {e}")
        finally:
            server.close()
    
    def handle_client(self, client_sock, client_addr, conn_id):
        try:
            data = client_sock.recv(4096)
            if not data:
                self.memory_manager.remove_connection(conn_id)
                client_sock.close()
                return
            
            self.memory_manager.update_activity(conn_id)
            
            if self.use_encryption:
                try:
                    data = self.crypto.decrypt(data)
                except:
                    pass
            
            request = data.decode('utf-8', errors='ignore')
            lines = request.split('\r\n')
            
            if not lines:
                client_sock.close()
                return
            
            first_line = lines[0]
            parts = first_line.split(' ')
            
            if len(parts) < 2:
                client_sock.close()
                return
            
            method = parts[0]
            url = parts[1]
            
            if method == 'CONNECT':
                self.handle_connect(client_sock, url)
            else:
                self.handle_http(client_sock, data, url, request)
                
        except Exception as e:
            self.logger.error(f"Client handler error: {e}")
            try:
                client_sock.close()
            except:
                pass
        finally:
            self.memory_manager.remove_connection(conn_id)
    
    def handle_connect(self, client_sock, url):
        try:
            host, port = url.split(':')
            port = int(port)
            
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            
            if self.use_tor:
                self.forward_via_tor(client_sock, host, port)
            else:
                self.forward_via_proxy(client_sock, host, port)
            
        except Exception as e:
            self.logger.error(f"CONNECT error: {e}")
            client_sock.close()
    
    def handle_http(self, client_sock, data, url, request):
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc
            port = parsed.port or 80
            
            if not host:
                client_sock.close()
                return
            
            lines = request.split('\r\n')
            new_first = f"GET {parsed.path or '/'} HTTP/1.1"
            if parsed.query:
                new_first += f"?{parsed.query}"
            
            lines[0] = new_first
            new_request = '\r\n'.join(lines)
            
            if self.use_tor:
                self.http_via_tor(client_sock, host, port, new_request)
            else:
                self.http_via_proxy(client_sock, host, port, new_request)
            
        except Exception as e:
            self.logger.error(f"HTTP error: {e}")
            client_sock.close()
    
    def forward_via_tor(self, client_sock, host, port):
        try:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            sock.settimeout(10)
            sock.connect((host, port))
            self.bridge_connections(client_sock, sock)
        except Exception as e:
            self.logger.error(f"Tor forward error: {e}")
            client_sock.close()
    
    def forward_via_proxy(self, client_sock, host, port):
        try:
            # استخدام اكتشاف العقد للحصول على عقدة
            nodes = self.discovery.get_active_nodes()
            if not nodes:
                self.logger.warning("No nodes available, using direct connection")
                self.direct_tunnel(client_sock, host, port)
                return
            
            node = random.choice(nodes)
            self.logger.debug(f"Forwarding via node: {node['id']}")
            
            node_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            node_sock.settimeout(10)
            node_sock.connect((node['ip'], node['port']))
            
            # تبادل المفاتيح
            self.perform_key_exchange(node_sock, node['id'])
            
            data = f"{host}:{port}".encode()
            if self.use_encryption:
                data = self.crypto.encrypt(data)
            node_sock.send(data)
            
            self.bridge_connections(client_sock, node_sock)
            
        except Exception as e:
            self.logger.error(f"Proxy forward error: {e}")
            client_sock.close()
    
    def http_via_tor(self, client_sock, host, port, request):
        try:
            import socks
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            sock.settimeout(10)
            sock.connect((host, port))
            sock.send(request.encode())
            
            response = sock.recv(8192)
            client_sock.send(response)
            sock.close()
            client_sock.close()
            
        except Exception as e:
            self.logger.error(f"Tor HTTP error: {e}")
            client_sock.close()
    
    def http_via_proxy(self, client_sock, host, port, request):
        try:
            nodes = self.discovery.get_active_nodes()
            if not nodes:
                self.direct_http(client_sock, host, port, request)
                return
            
            node = random.choice(nodes)
            node_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            node_sock.settimeout(10)
            node_sock.connect((node['ip'], node['port']))
            
            self.perform_key_exchange(node_sock, node['id'])
            
            data = f"HTTP::{host}::{port}::{request}".encode()
            if self.use_encryption:
                data = self.crypto.encrypt(data)
            node_sock.send(data)
            
            response = node_sock.recv(8192)
            if self.use_encryption:
                response = self.crypto.decrypt(response)
            
            client_sock.send(response)
            node_sock.close()
            client_sock.close()
            
        except Exception as e:
            self.logger.error(f"Proxy HTTP error: {e}")
            client_sock.close()
    
    def perform_key_exchange(self, sock, peer_id):
        try:
            key_data = f"KEY_EXCHANGE::proxy::{self.crypto.get_public_key_pem()}"
            sock.send(key_data.encode())
            
            response = sock.recv(4096)
            response_str = response.decode('utf-8', errors='ignore')
            
            if response_str.startswith('KEY_EXCHANGE'):
                parts = response_str.split('::')
                if len(parts) >= 4:
                    peer_id = parts[1]
                    peer_public_key = parts[2]
                    encrypted_session_key = parts[3]
                    
                    if self.crypto.load_peer_public_key(peer_id, peer_public_key):
                        if self.crypto.decrypt_session_key(encrypted_session_key):
                            self.logger.debug(f"Key exchange successful with {peer_id}")
                            return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Key exchange failed: {e}")
            return False
    
    def bridge_connections(self, sock1, sock2):
        try:
            sock1.setblocking(True)
            sock2.setblocking(True)
            
            while self.running:
                try:
                    data = sock1.recv(4096)
                    if not data:
                        break
                    if self.use_encryption:
                        data = self.crypto.encrypt(data)
                    sock2.send(data)
                    
                    data = sock2.recv(4096)
                    if not data:
                        break
                    if self.use_encryption:
                        data = self.crypto.decrypt(data)
                    sock1.send(data)
                    
                except socket.timeout:
                    continue
                except:
                    break
                    
        except:
            pass
        finally:
            try:
                sock1.close()
            except:
                pass
            try:
                sock2.close()
            except:
                pass
    
    def direct_tunnel(self, client_sock, host, port):
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(10)
            target_sock.connect((host, port))
            self.bridge_connections(client_sock, target_sock)
        except:
            client_sock.close()
    
    def direct_http(self, client_sock, host, port, request):
        try:
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(10)
            target_sock.connect((host, port))
            target_sock.send(request.encode())
            response = target_sock.recv(8192)
            client_sock.send(response)
            target_sock.close()
            client_sock.close()
        except:
            client_sock.close()
    
    def stop(self):
        self.running = False
        self.discovery.stop_discovery()
        self.memory_manager.cleanup()
        self.logger.info("Proxy stopped")

# ================================================================
# 7. الواجهة الرئيسية
# ================================================================

class ProxyApp:
    def __init__(self):
        self.logger = self._get_logger()
        self.proxy = None
        self.nodes = []
    
    def _get_logger(self):
        class Logger:
            def info(self, msg): print(f"[+] {msg}")
            def error(self, msg): print(f"[-] {msg}")
            def success(self, msg): print(f"[✓] {msg}")
            def section(self, msg): print(f"\n{'='*60}\n{msg}\n{'='*60}")
        return Logger()
    
    def show_banner(self):
        print("""
╔═══════════════════════════════════════════════════════════════════╗
║  PROXY TUNNEL v3.0 - الإصدار المتكامل النهائي                   ║
║  [عقد افتراضية + اكتشاف تلقائي + إدارة ذاكرة متقدمة]           ║
╚═══════════════════════════════════════════════════════════════════╝
        """)
    
    def main_menu(self):
        while True:
            print("\n" + "="*50)
            print("PROXY TUNNEL v3.0 - القائمة الرئيسية")
            print("-"*50)
            print("  1 - تشغيل خادم البروكسي")
            print("  2 - تشغيل عقدة")
            print("  3 - عرض العقد المكتشفة")
            print("  4 - اختبار الاتصال")
            print("  5 - إحصائيات الذاكرة")
            print("  6 - تفعيل/تعطيل Tor")
            print("  0 - خروج")
            print("="*50)
            
            choice = input("[>] اختر: ").strip()
            
            if choice == '0':
                self.cleanup()
                break
            elif choice == '1':
                self.run_proxy()
            elif choice == '2':
                self.run_node()
            elif choice == '3':
                self.show_nodes()
            elif choice == '4':
                self.test_connection()
            elif choice == '5':
                self.show_memory_stats()
            elif choice == '6':
                self.toggle_tor()
            else:
                print("[-] خيار غير صحيح")
    
    def run_proxy(self):
        port = input("[>] المنفذ (الافتراضي 8080): ").strip()
        port = int(port) if port else 8080
        
        use_encryption = input("[>] تشفير؟ (نعم/لا، الافتراضي نعم): ").strip().lower() not in ('لا', 'ل', 'n', 'no')
        use_tor = input("[>] استخدام Tor؟ (نعم/لا، الافتراضي لا): ").strip().lower() in ('نعم', 'ن', 'y', 'yes')
        
        self.proxy = ProxyTunnel(port, use_encryption, use_tor)
        
        try:
            self.proxy.start()
        except KeyboardInterrupt:
            self.proxy.stop()
            self.logger.info("Proxy stopped")
    
    def run_node(self):
        port = input("[>] المنفذ (الافتراضي 9050): ").strip()
        port = int(port) if port else 9050
        
        node_type = input("[>] النوع (دخول/وسيط/خروج، الافتراضي وسيط): ").strip()
        node_type = {'دخول': 'entry', 'وسيط': 'middle', 'خروج': 'exit'}.get(node_type, node_type)
        node_type = node_type if node_type in ['entry', 'middle', 'exit'] else 'middle'
        
        node = ProxyNode(port, node_type)
        self.nodes.append(node)
        
        try:
            node.start()
        except KeyboardInterrupt:
            node.stop()
    
    def show_nodes(self):
        nodes = self.proxy.discovery.known_nodes if self.proxy else {}
        
        if not nodes:
            print("[-] لا توجد عقد")
            return
        
        print("\n[+] العقد المكتشفة:")
        print("-"*60)
        active = 0
        for node_id, node in nodes.items():
            status = "🟢" if node.get('status') == 'active' else "🔴"
            if node.get('status') == 'active':
                active += 1
            print(f"  {status} {node_id} - {node.get('ip')}:{node.get('port')} ({node.get('type', 'unknown')}) - {node.get('country', 'Unknown')}")
        print("-"*60)
        print(f"  الإجمالي: {len(nodes)} | النشطة: {active}")
        print("-"*60)
    
    def test_connection(self):
        if not self.proxy:
            self.logger.warning("Proxy not running")
            return
        
        url = input("[>] رابط الاختبار (الافتراضي https://httpbin.org/ip): ").strip()
        if not url:
            url = "https://httpbin.org/ip"
        
        self.logger.info(f"Testing connection to {url}...")
        
        try:
            proxies = {'http': f'http://127.0.0.1:{self.proxy.listen_port}',
                      'https': f'http://127.0.0.1:{self.proxy.listen_port}'}
            
            response = requests.get(url, proxies=proxies, timeout=15)
            self.logger.success("Connection successful!")
            self.logger.info(f"Status: {response.status_code}")
            self.logger.info(f"Response: {response.text[:200]}")
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
    
    def show_memory_stats(self):
        if self.proxy:
            stats = self.proxy.memory_manager.get_stats()
            print("\n[+] إحصائيات الذاكرة:")
            print("-"*40)
            print(f"  إجمالي الاتصالات: {stats['total_connections']}")
            print(f"  الاتصالات النشطة: {stats['active_connections']}")
            print(f"  آخر تنظيف: {stats['last_cleanup']}")
        else:
            self.logger.warning("Proxy not running")
    
    def toggle_tor(self):
        if self.proxy:
            self.proxy.use_tor = not self.proxy.use_tor
            self.logger.info(f"Tor: {'Enabled' if self.proxy.use_tor else 'Disabled'}")
        else:
            self.logger.warning("Proxy not running")
    
    def cleanup(self):
        self.logger.info("Cleaning up...")
        if self.proxy:
            self.proxy.stop()
        for node in self.nodes:
            node.stop()
        self.logger.success("Goodbye!")

# ================================================================
# 8. الدالة الرئيسية
# ================================================================

def main():
    try:
        import cryptography
        import requests
    except ImportError:
        print("[-] يرجى تثبيت المتطلبات:")
        print("    pip install cryptography requests")
        sys.exit(1)
    
    app = ProxyApp()
    app.show_banner()
    app.main_menu()

if __name__ == "__main__":
    main()
